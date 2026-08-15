from __future__ import annotations

from pathlib import Path
from typing import Self

import pytest
from fastapi.testclient import TestClient

from incidentgate.control.model_proposal import ModelAgentProposer
from incidentgate.host.app import (
    HostSettings,
    build_proposer_factory,
    build_runtime_factory,
    settings_from_env,
    telemetry_config,
)

MONITOR_MODEL = "claude-haiku-4-5-20251001"


class RecordingRepository:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def migrate(self) -> None:
        self.calls.append("migrate")

    def initialize_d1_if_absent(self) -> None:
        self.calls.append("initialize_d1")

    def initialize_checkpoint_if_absent(self, scenario_id: str) -> None:
        self.calls.append(f"initialize_{scenario_id.lower()}")

    def reset_d1(self) -> None:
        self.calls.append("reset")

    def inject_d1(self) -> None:
        self.calls.append("inject")


OPUS = "claude-opus-5"
CACHE_DIR = str(Path(__file__).resolve().parents[1] / "fixtures" / "model_cache")


def _model_env(**overrides: str) -> dict[str, str]:
    values = {
        "DATABASE_URL": "postgresql://example",
        "PROPOSAL_PROVIDER": "model",
        "PROPOSAL_MODEL": OPUS,
        "PROPOSAL_CACHE_DIR": CACHE_DIR,
    }
    values.update(overrides)
    return values


def test_the_default_is_deterministic_with_no_model_configuration_present() -> None:
    """The seam must be opt-in: an unconfigured host behaves exactly as before."""
    settings = settings_from_env({"DATABASE_URL": "postgresql://example"})
    assert settings.proposal_provider == "deterministic"
    assert settings.proposal_model is None and settings.proposal_cache_dir is None
    assert build_proposer_factory(settings) is None


def test_unknown_proposal_provider_fails_at_construction() -> None:
    with pytest.raises(ValueError, match="PROPOSAL_PROVIDER must be deterministic or model"):
        settings_from_env({"DATABASE_URL": "postgresql://example", "PROPOSAL_PROVIDER": "magic"})
    with pytest.raises(ValueError, match="PROPOSAL_PROVIDER must be deterministic or model"):
        HostSettings(database_url="postgresql://example", proposal_provider="magic")


def test_model_provider_without_a_model_fails_loud() -> None:
    with pytest.raises(ValueError, match="model proposals require PROPOSAL_MODEL"):
        settings_from_env({"DATABASE_URL": "postgresql://example", "PROPOSAL_PROVIDER": "model"})


def test_unknown_proposal_model_fails_loud_without_echoing_the_value() -> None:
    """A mis-set PROPOSAL_MODEL could hold a credential, so it must not appear in the error."""
    secret = "sk-ant-not-a-model-id"
    with pytest.raises(ValueError) as raised:
        settings_from_env(_model_env(PROPOSAL_MODEL=secret))
    assert "capability table" in str(raised.value)
    assert secret not in str(raised.value)


def test_model_provider_without_a_cache_directory_fails_loud() -> None:
    """Host-selectable model proposals are replay-only; there is no pricing snapshot."""
    env = _model_env()
    del env["PROPOSAL_CACHE_DIR"]
    with pytest.raises(ValueError, match="PROPOSAL_CACHE_DIR"):
        settings_from_env(env)


def test_model_provider_builds_a_replay_only_proposer() -> None:
    settings = settings_from_env(_model_env())
    factory = build_proposer_factory(settings)
    assert factory is not None
    proposer = factory()
    assert isinstance(proposer, ModelAgentProposer)
    # Selecting the model path must not put a network client anywhere in the seam.
    assert "CacheBackedCompletionClient" in repr(proposer._client)


def test_settings_never_echo_secrets_in_their_repr() -> None:
    settings = HostSettings(
        database_url="postgresql://example",
        anthropic_api_key="sk-ant-secret",
        anthropic_model=MONITOR_MODEL,
        langfuse_secret_key="langfuse-secret",
    )
    rendered = repr(settings)
    assert "sk-ant-secret" not in rendered and "langfuse-secret" not in rendered


def test_partial_langfuse_settings_are_rejected() -> None:
    with pytest.raises(ValueError, match="Langfuse configuration"):
        settings_from_env({"DATABASE_URL": "postgresql://example", "LANGFUSE_PUBLIC_KEY": "pk"})


def test_complete_langfuse_settings_build_external_config_without_network() -> None:
    settings = settings_from_env(
        {
            "DATABASE_URL": "postgresql://example",
            "LANGFUSE_PUBLIC_KEY": "pk",
            "LANGFUSE_SECRET_KEY": "sk",
            "LANGFUSE_BASE_URL": "https://langfuse.example",
        }
    )
    config = telemetry_config(settings)
    assert config.external is True
    assert config.langfuse_public_key == "pk"
    assert config.langfuse_secret_key == "sk"


def test_local_telemetry_is_explicit_when_langfuse_is_absent() -> None:
    assert telemetry_config(HostSettings(database_url="postgresql://example")).external is False


def test_direct_partial_settings_do_not_enable_external_telemetry() -> None:
    with pytest.raises(ValueError, match="Langfuse configuration"):
        telemetry_config(
            HostSettings(database_url="postgresql://example", langfuse_public_key="pk")
        )


def test_runtime_factory_defers_runtime_construction() -> None:
    settings = HostSettings(database_url="postgresql://invalid")
    assert callable(build_runtime_factory(settings, telemetry_config(settings)))


def test_anthropic_settings_are_explicit_complete_and_repr_safe() -> None:
    with pytest.raises(ValueError, match="Anthropic provider"):
        settings_from_env(
            {
                "DATABASE_URL": "postgresql://example",
                "ADVISORY_MONITOR_PROVIDER": "anthropic",
                "ANTHROPIC_API_KEY": "secret",
            }
        )
    with pytest.raises(ValueError, match="ADVISORY_MONITOR_PROVIDER"):
        settings_from_env(
            {"DATABASE_URL": "postgresql://example", "ADVISORY_MONITOR_PROVIDER": "unknown"}
        )
    settings = settings_from_env(
        {
            "DATABASE_URL": "postgresql://example",
            "ADVISORY_MONITOR_PROVIDER": "anthropic",
            "ANTHROPIC_API_KEY": "secret",
            "ANTHROPIC_MODEL": MONITOR_MODEL,
        }
    )
    assert settings.monitor_provider == "anthropic"
    assert "secret" not in repr(settings)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"anthropic_api_key": "secret"},
        {"anthropic_model": MONITOR_MODEL},
    ],
)
def test_direct_partial_anthropic_settings_are_rejected_consistently(
    kwargs: dict[str, str],
) -> None:
    with pytest.raises(ValueError, match="Anthropic configuration"):
        HostSettings(database_url="postgresql://example", **kwargs)


def test_unknown_anthropic_model_is_rejected_at_settings_construction() -> None:
    """The monitor is built per request, so a typo'd model id must fail at startup instead.

    Without this the process starts happily and every incident receives a monitor that can only
    ever return the generic BLOCK, which is indistinguishable from a real block verdict.
    """
    env = {
        "DATABASE_URL": "postgresql://example",
        "ADVISORY_MONITOR_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "secret",
        "ANTHROPIC_MODEL": "claude-opus-5-20260801",  # a plausible but unlisted id
    }
    with pytest.raises(ValueError, match="capability table"):
        settings_from_env(env)
    with pytest.raises(ValueError, match="capability table") as raised:
        HostSettings(
            database_url="postgresql://example",
            anthropic_api_key="secret",
            anthropic_model="sk-ant-pasted-into-the-wrong-variable",
        )
    assert "sk-ant" not in str(raised.value)  # the rejected value is never echoed
    # A listed id is accepted, so the check gates only ids the capability table cannot shape.
    assert (
        settings_from_env({**env, "ANTHROPIC_MODEL": MONITOR_MODEL}).anthropic_model
        == MONITOR_MODEL
    )


def test_anthropic_runtime_factory_selects_provider_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import incidentgate.host.app as host_app

    captured: list[object] = []

    class Runtime:
        def __init__(self, *args: object, monitor_factory: object, **kwargs: object) -> None:
            captured.append(monitor_factory)

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(host_app, "IncidentRuntime", Runtime)
    settings = HostSettings(
        database_url="postgresql://example",
        monitor_provider="anthropic",
        anthropic_api_key="secret",
        anthropic_model=MONITOR_MODEL,
    )
    with build_runtime_factory(settings, telemetry_config(settings))():
        pass
    assert len(captured) == 1
    assert captured[0]().__class__.__name__ == "AnthropicAdvisoryMonitor"  # type: ignore[operator]


def test_host_startup_initializes_without_destructive_reset() -> None:
    from contextlib import nullcontext

    from incidentgate.host.app import create_host_app

    repository = RecordingRepository()
    app = create_host_app(
        HostSettings(database_url="postgresql://example"),
        repository_factory=lambda _: repository,  # type: ignore[arg-type]
        runtime_builder=lambda _settings, _config: lambda: nullcontext(),
    )
    with TestClient(app) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
    assert repository.calls == [
        "migrate",
        "initialize_d1",
        "initialize_d2",
        "initialize_d3",
        "initialize_d4",
        "initialize_d7",
    ]


def test_host_registry_validation_precedes_migration(monkeypatch: pytest.MonkeyPatch) -> None:
    from contextlib import nullcontext

    import incidentgate.host.app as host_app

    repository = RecordingRepository()
    monkeypatch.setattr(
        host_app,
        "validate_scenario_registry",
        lambda _policy: (_ for _ in ()).throw(ValueError("scenario registry invalid: test")),
    )
    app = host_app.create_host_app(
        HostSettings(database_url="postgresql://example"),
        repository_factory=lambda _: repository,  # type: ignore[arg-type]
        runtime_builder=lambda _settings, _config: lambda: nullcontext(),
    )
    with pytest.raises(ValueError, match="scenario registry invalid"), TestClient(app):
        pass
    assert repository.calls == []
