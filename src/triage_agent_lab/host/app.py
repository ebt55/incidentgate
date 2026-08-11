"""Composition root for the local D1 approval UI."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI

from triage_agent_lab.contracts import IncidentIdentity, IncidentState, MonitorVerdict
from triage_agent_lab.control import AnthropicAdvisoryMonitor, FixtureMonitor
from triage_agent_lab.integration import IncidentRuntime
from triage_agent_lab.lab.repository import D1Repository
from triage_agent_lab.scenario_registry import RUNNABLE_SCENARIOS
from triage_agent_lab.telemetry import TelemetryConfig
from triage_agent_lab.ui import create_ui_app


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

    def __post_init__(self) -> None:
        if self.monitor_provider not in {"fixture", "anthropic"}:
            raise ValueError("ADVISORY_MONITOR_PROVIDER must be fixture or anthropic")
        if bool(self.anthropic_api_key) != bool(self.anthropic_model):
            raise ValueError("Anthropic configuration must provide API key and model together")
        if self.monitor_provider == "anthropic" and not self.anthropic_api_key:
            raise ValueError("Anthropic provider requires ANTHROPIC_API_KEY and ANTHROPIC_MODEL")
        if not 0 < self.anthropic_timeout_seconds <= 60:
            raise ValueError("ANTHROPIC_TIMEOUT_SECONDS must be between 0 and 60")


def settings_from_env(env: Mapping[str, str] | None = None) -> HostSettings:
    """Read only host-owned named environment values; reject partial tracing config."""
    values = os.environ if env is None else env
    database_url = values.get("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL is required")
    langfuse = tuple(
        values.get(name) or None
        for name in ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_BASE_URL")
    )
    if any(langfuse) and not all(langfuse):
        raise ValueError("Langfuse configuration must provide public key, secret key, and base URL together")
    try:
        bind_port = int(values.get("D1_UI_PORT", "8090"))
    except ValueError as error:
        raise ValueError("D1_UI_PORT must be an integer") from error
    if not 1 <= bind_port <= 65535:
        raise ValueError("D1_UI_PORT must be between 1 and 65535")
    provider = values.get("ADVISORY_MONITOR_PROVIDER", "fixture").lower()
    if provider not in {"fixture", "anthropic"}:
        raise ValueError("ADVISORY_MONITOR_PROVIDER must be fixture or anthropic")
    api_key, model = values.get("ANTHROPIC_API_KEY") or None, values.get("ANTHROPIC_MODEL") or None
    if provider == "anthropic" and not (api_key and model):
        raise ValueError("Anthropic provider requires ANTHROPIC_API_KEY and ANTHROPIC_MODEL")
    if bool(api_key) != bool(model):
        # Credentials do not activate external behavior, but partial configuration is still invalid.
        raise ValueError("Anthropic configuration must provide API key and model together")
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
        bind_host=values.get("D1_UI_BIND_HOST", "127.0.0.1"),
        bind_port=bind_port,
        monitor_provider=provider,
        anthropic_api_key=api_key,
        anthropic_model=model,
        anthropic_timeout_seconds=anthropic_timeout,
    )


def telemetry_config(settings: HostSettings) -> TelemetryConfig:
    """Use isolated local tracing unless complete explicit export configuration exists."""
    values = (
        settings.langfuse_public_key,
        settings.langfuse_secret_key,
        settings.langfuse_base_url,
    )
    if any(values) and not all(values):
        raise ValueError("Langfuse configuration must provide public key, secret key, and base URL together")
    return TelemetryConfig(
        service_name="triage-agent-lab-ui",
        external=all(values),
        langfuse_public_key=settings.langfuse_public_key,
        langfuse_secret_key=settings.langfuse_secret_key,
        langfuse_base_url=settings.langfuse_base_url,
    )


class D1ScenarioController:
    """Explicit destructive lab preparation boundary, guarded by the UI."""

    def __init__(self, repository: D1Repository) -> None:
        self._repository = repository

    def prepare_d1(self) -> None:
        self.prepare("D1", "d1-legacy", "ui-d1-legacy")

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
        return IncidentIdentity(incident_id=f"INC-{scenario_id}", scenario_id=scenario_id,
                                thread_id=thread_id, correlation_id=correlation_id,
                                state=IncidentState.OPEN)


RuntimeBuilder = Callable[[HostSettings, TelemetryConfig], Callable[[], AbstractContextManager[Any]]]


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
        with IncidentRuntime(settings.database_url, telemetry_config=config, monitor_factory=monitor_factory) as runtime:
            yield runtime

    return factory


def create_host_app(
    settings: HostSettings | None = None,
    *,
    env: Mapping[str, str] | None = None,
    repository_factory: Callable[[str], D1Repository] = D1Repository,
    runtime_builder: RuntimeBuilder = build_runtime_factory,
) -> FastAPI:
    """Build the local UI and initialize only non-destructive checkpoint baseline state."""
    configured = settings or settings_from_env(env)
    repository = repository_factory(configured.database_url)
    app = create_ui_app(runtime_builder(configured, telemetry_config(configured)), D1ScenarioController(repository))

    @app.on_event("startup")
    def initialize_host() -> None:
        repository.migrate()
        repository.initialize_d1_if_absent()
        # No-action fixtures are initialized lazily by their explicit prepare
        # endpoint; retain the established non-destructive startup footprint.
        for scenario_id in ("D2", "D3", "D4", "D7"):
            repository.initialize_checkpoint_if_absent(scenario_id)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
