"""Composition root for the local D1 approval UI."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import AbstractContextManager, asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from incidentgate.contracts import (
    IncidentIdentity,
    IncidentState,
    MonitorVerdict,
    PolicyConfiguration,
)
from incidentgate.control import (
    AnthropicAdvisoryMonitor,
    FixtureMonitor,
    is_known_model,
    model_accepts_sampling,
)
from incidentgate.control.model_proposal import ModelAgentProposer
from incidentgate.control.ports import ProposalGenerator
from incidentgate.control.response_cache import CacheBackedCompletionClient, ResponseCache
from incidentgate.integration import IncidentRuntime
from incidentgate.lab.repository import LabRepository
from incidentgate.scenario_registry import RUNNABLE_SCENARIOS, validate_scenario_registry
from incidentgate.telemetry import TelemetryConfig
from incidentgate.ui import create_ui_app


@dataclass(frozen=True)
class HostSettings:
    """Named host configuration; provider access is opt-in and secret repr-safe."""

    database_url: str
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = field(default=None, repr=False)
    langfuse_base_url: str | None = None
    bind_host: str = "127.0.0.1"
    bind_port: int = 8090
    monitor_provider: str = "fixture"
    anthropic_api_key: str | None = field(default=None, repr=False)
    anthropic_model: str | None = None
    anthropic_timeout_seconds: float = 10.0
    proposal_provider: str = "deterministic"
    proposal_model: str | None = None
    proposal_cache_dir: str | None = None

    def __post_init__(self) -> None:
        if self.monitor_provider not in {"fixture", "anthropic"}:
            raise ValueError("ADVISORY_MONITOR_PROVIDER must be fixture or anthropic")
        if self.proposal_provider not in {"deterministic", "model"}:
            raise ValueError("PROPOSAL_PROVIDER must be deterministic or model")
        if self.proposal_provider == "model" and not self.proposal_model:
            raise ValueError("model proposals require PROPOSAL_MODEL")
        if self.proposal_model is not None and not is_known_model(self.proposal_model):
            # Same reasoning as ANTHROPIC_MODEL below: the proposer is built per
            # incident, so its own guard would first fire mid-incident. The value is
            # not echoed, because a mis-set PROPOSAL_MODEL could hold a credential.
            raise ValueError("PROPOSAL_MODEL is not in the model capability table")
        if self.proposal_provider == "model" and not self.proposal_cache_dir:
            # Host-selectable model proposals are replay-only, deliberately. A live
            # provider call must record its cost against a named pricing snapshot,
            # and this host has no price list to name. Rather than invent prices or
            # record a call whose cost is silently absent, the host refuses. The
            # live client stays available to callers that supply their own snapshot.
            raise ValueError(
                "model proposals require PROPOSAL_CACHE_DIR; the host has no pricing "
                "snapshot with which to record a live provider call honestly"
            )
        # The same relaxation as in ``settings_from_env``, and for the same reason:
        # with a committed default the model is always present, so a strict pairing
        # would refuse every host that has no Anthropic credentials. The
        # provider-conditional check below is what carries the property.
        if self.monitor_provider == "anthropic" and not (
            self.anthropic_api_key and self.anthropic_model
        ):
            raise ValueError("Anthropic provider requires ANTHROPIC_API_KEY and ANTHROPIC_MODEL")
        if self.anthropic_model is not None and not is_known_model(self.anthropic_model):
            # The monitor is built per request, so its own guard would first fire mid-incident.
            # Checking here makes a typo'd model id a startup failure instead, before any
            # incident sees a monitor that could only ever return BLOCK. The value is not
            # echoed: a mis-set ANTHROPIC_MODEL could hold a credential.
            raise ValueError("ANTHROPIC_MODEL is not in the advisory monitor capability table")
        if self.monitor_provider == "anthropic" and not self.anthropic_api_key:
            raise ValueError("Anthropic provider requires ANTHROPIC_API_KEY and ANTHROPIC_MODEL")
        if not 0 < self.anthropic_timeout_seconds <= 60:
            raise ValueError("ANTHROPIC_TIMEOUT_SECONDS must be between 0 and 60")


#: Settings that live in a committed file because they are the same for everyone.
HOST_SETTINGS_PATH = Path(__file__).resolve().parents[3] / "config" / "host-settings.json"

#: Names that must never appear in the committed file. Credentials for the obvious
#: reason, and ``INCIDENTGATE_ALLOW_PROVIDER_SPEND`` for a less obvious one: it is
#: an authorisation rather than a setting, and committing it would turn a
#: deliberate act in one shell into a standing property of the repository.
_NEVER_COMMITTED = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "LANGFUSE_PUBLIC_KEY",
        "LANGFUSE_SECRET_KEY",
        "DATABASE_URL",
        "INCIDENTGATE_ALLOW_PROVIDER_SPEND",
    }
)


def committed_host_settings(path: Path | None = None) -> dict[str, str]:
    """The committed non-credential settings, refusing any file that carries a secret.

    Read as defaults that an environment variable of the same name overrides, so a
    one-off port change or a CI tweak needs no edit to a committed file.

    The refusal is not decoration. This file is in version control and a secret
    written here would be published by the act of committing it, which is exactly
    the mistake that is easy to make when a settings file already exists and looks
    like the place configuration goes. Refusing at load time makes it a startup
    failure rather than something noticed later.

    Keys beginning with an underscore are commentary. JSON has no comment syntax
    and the alternative -- an undocumented settings file -- is worse.
    """
    location = HOST_SETTINGS_PATH if path is None else path
    if not location.is_file():
        return {}
    payload = json.loads(location.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("committed host settings must be a JSON object")
    forbidden = sorted(_NEVER_COMMITTED & set(payload))
    if forbidden:
        raise ValueError(
            "committed host settings must not contain credentials or spend "
            f"authorisation: {', '.join(forbidden)}"
        )
    return {
        name: str(value)
        for name, value in payload.items()
        if not name.startswith("_") and value is not None
    }


def settings_from_env(env: Mapping[str, str] | None = None) -> HostSettings:
    """Read host-owned settings: committed defaults, overridden by the environment.

    Credentials and ``DATABASE_URL`` are read from the environment only and are
    never sourced from the committed file, which :func:`committed_host_settings`
    refuses to load if it names one.
    """
    environment = os.environ if env is None else env
    values: dict[str, str] = {**committed_host_settings(), **dict(environment)}
    database_url = values.get("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL is required")
    langfuse = tuple(
        values.get(name) or None
        for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_BASE_URL")
    )
    # Keyed on the two *credentials*, not on all three. LANGFUSE_BASE_URL now has a
    # committed default, so an all-three ``any`` would fire for everyone who has no
    # Langfuse keys -- the same failure the Anthropic pairing had, from the same
    # cause. What the check is for is unchanged: tracing must not be half
    # configured, and it is the keys that turn it on.
    if any(langfuse[:2]) and not all(langfuse):
        raise ValueError(
            "Langfuse configuration must provide public key, secret key, and base URL together"
        )
    try:
        bind_port = int(values.get("INCIDENTGATE_UI_PORT", "8090"))
    except ValueError as error:
        raise ValueError("INCIDENTGATE_UI_PORT must be an integer") from error
    if not 1 <= bind_port <= 65535:
        raise ValueError("INCIDENTGATE_UI_PORT must be between 1 and 65535")
    provider = values.get("ADVISORY_MONITOR_PROVIDER", "fixture").lower()
    if provider not in {"fixture", "anthropic"}:
        raise ValueError("ADVISORY_MONITOR_PROVIDER must be fixture or anthropic")
    api_key, model = values.get("ANTHROPIC_API_KEY") or None, values.get("ANTHROPIC_MODEL") or None
    if provider == "anthropic" and not (api_key and model):
        raise ValueError("Anthropic provider requires ANTHROPIC_API_KEY and ANTHROPIC_MODEL")
    # RELAXED DELIBERATELY, AND NOT SLIPPED IN.
    #
    # This used to be ``if bool(api_key) != bool(model): raise`` -- set one, set
    # both. That was right while ANTHROPIC_MODEL had no default: a model without a
    # key, or a key without a model, was someone's half-finished edit.
    #
    # ANTHROPIC_MODEL now has a committed default, so the model is *always* set and
    # the key is absent for everyone without credentials -- which is every
    # contributor running the deterministic host and CI. The strict pairing would
    # refuse all of them at startup, for a configuration that is complete and
    # correct.
    #
    # What the check was actually protecting is the line above: the anthropic
    # provider needs both. That is provider-conditional and unchanged. A key with
    # no model can no longer occur, because a model always exists; a model with no
    # key is now the ordinary case and is inert, since the provider defaults to
    # ``fixture`` and nothing reaches Anthropic without ``ADVISORY_MONITOR_PROVIDER``
    # naming it.
    proposal_provider = values.get("PROPOSAL_PROVIDER", "deterministic").lower()
    if proposal_provider not in {"deterministic", "model"}:
        raise ValueError("PROPOSAL_PROVIDER must be deterministic or model")
    proposal_model = values.get("PROPOSAL_MODEL") or None
    proposal_cache_dir = values.get("PROPOSAL_CACHE_DIR") or None
    try:
        anthropic_timeout = float(values.get("ANTHROPIC_TIMEOUT_SECONDS", "10"))
    except ValueError as error:
        raise ValueError("ANTHROPIC_TIMEOUT_SECONDS must be a number") from error
    if not 0 < anthropic_timeout <= 60:
        raise ValueError("ANTHROPIC_TIMEOUT_SECONDS must be between 0 and 60")
    public_key, secret_key, base_url = langfuse
    return HostSettings(
        database_url=database_url,
        langfuse_public_key=public_key,
        langfuse_secret_key=secret_key,
        langfuse_base_url=base_url,
        bind_host=values.get("INCIDENTGATE_UI_BIND_HOST", "127.0.0.1"),
        bind_port=bind_port,
        monitor_provider=provider,
        anthropic_api_key=api_key,
        anthropic_model=model,
        anthropic_timeout_seconds=anthropic_timeout,
        proposal_provider=proposal_provider,
        proposal_model=proposal_model,
        proposal_cache_dir=proposal_cache_dir,
    )


def telemetry_config(settings: HostSettings) -> TelemetryConfig:
    """Use isolated local tracing unless complete explicit export configuration exists."""
    values = (
        settings.langfuse_public_key,
        settings.langfuse_secret_key,
        settings.langfuse_base_url,
    )
    # Keyed on the two credentials, matching ``settings_from_env``. The base URL
    # has a committed default, so an all-three ``any`` fires for every host with no
    # Langfuse keys. ``external`` still requires all three, so tracing is exported
    # only when it is fully configured -- which is the property, and it is
    # unchanged.
    if any(values[:2]) and not all(values):
        raise ValueError(
            "Langfuse configuration must provide public key, secret key, and base URL together"
        )
    return TelemetryConfig(
        service_name="incidentgate-ui",
        external=all(values),
        langfuse_public_key=settings.langfuse_public_key,
        langfuse_secret_key=settings.langfuse_secret_key,
        langfuse_base_url=settings.langfuse_base_url,
    )


class LabScenarioController:
    """Explicit destructive lab preparation boundary, guarded by the UI."""

    def __init__(self, repository: LabRepository) -> None:
        self._repository = repository

    def prepare(self, scenario_id: str, thread_id: str, correlation_id: str) -> IncidentIdentity:
        if scenario_id not in RUNNABLE_SCENARIOS:
            raise ValueError("unsupported checkpoint scenario")
        self._repository.migrate()
        if scenario_id == "D1":
            self._repository.reset_d1()
            self._repository.inject_d1()
        else:
            self._repository.reset_checkpoint(scenario_id)
            self._repository.inject_checkpoint(scenario_id)
        return IncidentIdentity(
            incident_id=f"INC-{scenario_id}",
            scenario_id=scenario_id,
            thread_id=thread_id,
            correlation_id=correlation_id,
            state=IncidentState.OPEN,
        )


RuntimeBuilder = Callable[
    [HostSettings, TelemetryConfig], Callable[[], AbstractContextManager[Any]]
]


def build_proposer_factory(settings: HostSettings) -> Callable[[], ProposalGenerator] | None:
    """Return the proposer seam for this configuration, or None for the default.

    None means every scenario keeps its deterministic proposer, which is what the
    default configuration and every existing deployment get. The model path is
    replay-only by construction: it is wired to the response cache and never holds
    a network client, so selecting it cannot start making provider calls.
    """
    if settings.proposal_provider != "model":
        return None
    model, cache_dir = settings.proposal_model, settings.proposal_cache_dir
    # Both are guaranteed by HostSettings.__post_init__; asserting keeps the types
    # honest without duplicating the error messages.
    assert model is not None and cache_dir is not None
    client = CacheBackedCompletionClient(ResponseCache(Path(cache_dir)))
    temperature = 0.0 if model_accepts_sampling(model) else None

    def factory() -> ProposalGenerator:
        return ModelAgentProposer(client=client, model=model, temperature=temperature)

    return factory


def build_runtime_factory(
    settings: HostSettings, config: TelemetryConfig
) -> Callable[[], AbstractContextManager[IncidentRuntime]]:
    """Return a per-request runtime context manager so durable resources are closed."""

    @contextmanager
    def factory() -> Any:
        if settings.monitor_provider == "anthropic":
            assert settings.anthropic_api_key is not None and settings.anthropic_model is not None
            api_key, model = settings.anthropic_api_key, settings.anthropic_model
            monitor_factory: Callable[[], Any] = lambda: AnthropicAdvisoryMonitor(
                api_key=api_key,
                model=model,
                timeout_seconds=settings.anthropic_timeout_seconds,
            )
        elif settings.monitor_provider == "fixture":
            monitor_factory = lambda: FixtureMonitor(MonitorVerdict.ALLOW)
        else:
            raise ValueError("unknown advisory monitor provider")
        with IncidentRuntime(
            settings.database_url,
            telemetry_config=config,
            monitor_factory=monitor_factory,
            proposer_factory=build_proposer_factory(settings),
        ) as runtime:
            yield runtime

    return factory


def create_host_app(
    settings: HostSettings | None = None,
    *,
    env: Mapping[str, str] | None = None,
    repository_factory: Callable[[str], LabRepository] = LabRepository,
    runtime_builder: RuntimeBuilder = build_runtime_factory,
) -> FastAPI:
    """Build the local UI and initialize only non-destructive checkpoint baseline state."""
    configured = settings or settings_from_env(env)
    repository = repository_factory(configured.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        policy = PolicyConfiguration.model_validate(
            json.loads((Path(__file__).parents[3] / "config" / "policy.example.json").read_text())
        )
        validate_scenario_registry(policy)
        repository.migrate()
        repository.initialize_d1_if_absent()
        # No-action fixtures are initialized lazily by their explicit prepare
        # endpoint; retain the established non-destructive startup footprint.
        for scenario_id in ("D2", "D3", "D4", "D7"):
            repository.initialize_checkpoint_if_absent(scenario_id)
        yield

    app = create_ui_app(
        runtime_builder(configured, telemetry_config(configured)),
        LabScenarioController(repository),
        lifespan=lifespan,
    )

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
