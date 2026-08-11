from __future__ import annotations

from typing import Self

import pytest
from fastapi.testclient import TestClient

from triage_agent_lab.host.app import (
    HostSettings,
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


def test_partial_langfuse_settings_are_rejected() -> None:
    with pytest.raises(ValueError, match="Langfuse configuration"):
        settings_from_env({"DATABASE_URL": "postgresql://example", "LANGFUSE_PUBLIC_KEY": "pk"})


def test_complete_langfuse_settings_build_external_config_without_network() -> None:
    settings = settings_from_env({"DATABASE_URL": "postgresql://example", "LANGFUSE_PUBLIC_KEY": "pk", "LANGFUSE_SECRET_KEY": "sk", "LANGFUSE_BASE_URL": "https://langfuse.example"})
    config = telemetry_config(settings)
    assert config.external is True
    assert config.langfuse_public_key == "pk"
    assert config.langfuse_secret_key == "sk"


def test_local_telemetry_is_explicit_when_langfuse_is_absent() -> None:
    assert telemetry_config(HostSettings(database_url="postgresql://example")).external is False


def test_direct_partial_settings_do_not_enable_external_telemetry() -> None:
    with pytest.raises(ValueError, match="Langfuse configuration"):
        telemetry_config(HostSettings(database_url="postgresql://example", langfuse_public_key="pk"))


def test_runtime_factory_defers_runtime_construction() -> None:
    settings = HostSettings(database_url="postgresql://invalid")
    assert callable(build_runtime_factory(settings, telemetry_config(settings)))


def test_anthropic_settings_are_explicit_complete_and_repr_safe() -> None:
    with pytest.raises(ValueError, match="Anthropic provider"):
        settings_from_env({"DATABASE_URL": "postgresql://example", "ADVISORY_MONITOR_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "secret"})
    with pytest.raises(ValueError, match="ADVISORY_MONITOR_PROVIDER"):
        settings_from_env({"DATABASE_URL": "postgresql://example", "ADVISORY_MONITOR_PROVIDER": "unknown"})
    settings = settings_from_env({"DATABASE_URL": "postgresql://example", "ADVISORY_MONITOR_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "secret", "ANTHROPIC_MODEL": MONITOR_MODEL})
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
    assert settings_from_env({**env, "ANTHROPIC_MODEL": MONITOR_MODEL}).anthropic_model == MONITOR_MODEL


def test_anthropic_runtime_factory_selects_provider_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    import triage_agent_lab.host.app as host_app

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

    from triage_agent_lab.host.app import create_host_app

    repository = RecordingRepository()
    app = create_host_app(
        HostSettings(database_url="postgresql://example"),
        repository_factory=lambda _: repository,  # type: ignore[arg-type]
        runtime_builder=lambda _settings, _config: lambda: nullcontext(),
    )
    with TestClient(app) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
    assert repository.calls == ["migrate", "initialize_d1", "initialize_d2", "initialize_d3", "initialize_d4", "initialize_d7"]
