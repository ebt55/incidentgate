"""Settings are committed; credentials and authorisations are not.

The split is only worth anything if the boundary is enforced rather than
described. A settings file that already exists is exactly where someone will
reasonably put the next value, so the file that must never hold a secret has to
refuse one at load time rather than rely on everybody knowing.

Two consequences of giving settings committed defaults are load-bearing and both
are tested here: a value that used to be absent for most hosts is now always
present, so every check written as "these two must be set together" would start
refusing correct configurations. Two such checks existed and both were relaxed to
the provider-conditional form they were really protecting.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from incidentgate.host.app import (
    HOST_SETTINGS_PATH,
    HostSettings,
    committed_host_settings,
    settings_from_env,
)

DSN = "postgresql://incidentgate:x@127.0.0.1:5432/incidentgate"


# --------------------------------------------------------------------------
# The boundary.
# --------------------------------------------------------------------------


def test_the_committed_file_exists_and_is_read() -> None:
    assert HOST_SETTINGS_PATH.is_file()
    assert committed_host_settings() != {}


@pytest.mark.parametrize(
    "secret",
    [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "LANGFUSE_PUBLIC_KEY",
        "LANGFUSE_SECRET_KEY",
        "DATABASE_URL",
        "INCIDENTGATE_ALLOW_PROVIDER_SPEND",
    ],
)
def test_a_committed_file_naming_a_secret_is_refused(secret: str, tmp_path: Path) -> None:
    """Refused at load, so it is a startup failure and not a later discovery."""
    path = tmp_path / "host-settings.json"
    path.write_text(json.dumps({secret: "value"}), encoding="utf-8")
    with pytest.raises(ValueError, match="must not contain credentials"):
        committed_host_settings(path)


def test_the_real_committed_file_names_none_of_them() -> None:
    """The property asserted against the file actually in the repository."""
    payload = json.loads(HOST_SETTINGS_PATH.read_text(encoding="utf-8"))
    for secret in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "LANGFUSE_PUBLIC_KEY",
        "LANGFUSE_SECRET_KEY",
        "DATABASE_URL",
        "INCIDENTGATE_ALLOW_PROVIDER_SPEND",
    ):
        assert secret not in payload


def test_the_spend_authorisation_is_absent_for_a_stated_reason() -> None:
    """It is an authorisation, not a setting.

    Committing it would turn a deliberate act in one shell into a standing
    property of the repository, which is the opposite of what the spend gate is
    for -- and the gate's own tests require both halves in one invocation.
    """
    payload = json.loads(HOST_SETTINGS_PATH.read_text(encoding="utf-8"))
    assert "INCIDENTGATE_ALLOW_PROVIDER_SPEND" not in payload
    commentary = " ".join(
        " ".join(value) if isinstance(value, list) else str(value)
        for key, value in payload.items()
        if key.startswith("_")
    )
    assert "authorisation" in commentary


def test_credentials_still_come_from_the_environment() -> None:
    settings = settings_from_env({"DATABASE_URL": DSN, "ANTHROPIC_API_KEY": "k"})
    assert settings.anthropic_api_key == "k"
    assert settings.database_url == DSN


def test_the_environment_overrides_a_committed_default() -> None:
    """So a one-off port change needs no edit to a committed file."""
    assert settings_from_env({"DATABASE_URL": DSN}).bind_port == 8090
    overridden = settings_from_env({"DATABASE_URL": DSN, "INCIDENTGATE_UI_PORT": "9111"})
    assert overridden.bind_port == 9111


def test_underscore_keys_are_commentary_and_never_settings() -> None:
    """JSON has no comment syntax, and an undocumented settings file is worse."""
    payload = json.loads(HOST_SETTINGS_PATH.read_text(encoding="utf-8"))
    assert any(key.startswith("_") for key in payload)
    assert not any(key.startswith("_") for key in committed_host_settings())


def test_a_null_value_is_a_known_setting_with_no_value() -> None:
    """Not the same as a key nobody has heard of, and not an empty string either."""
    payload = json.loads(HOST_SETTINGS_PATH.read_text(encoding="utf-8"))
    assert payload["PROPOSAL_MODEL"] is None
    assert "PROPOSAL_MODEL" not in committed_host_settings()
    assert settings_from_env({"DATABASE_URL": DSN}).proposal_model is None


# --------------------------------------------------------------------------
# The two relaxations, each with the case that forced it.
# --------------------------------------------------------------------------


def test_a_host_with_a_committed_model_and_no_key_starts() -> None:
    """The case the old strict pairing refused: every contributor and CI.

    ``ANTHROPIC_MODEL`` now always has a value, so ``bool(key) != bool(model)``
    was true for everyone without Anthropic credentials.
    """
    settings = settings_from_env({"DATABASE_URL": DSN})
    assert settings.anthropic_model == "claude-opus-5"
    assert settings.anthropic_api_key is None
    assert settings.monitor_provider == "fixture"


def test_the_provider_conditional_check_still_refuses_a_half_configured_provider() -> None:
    """What the strict pairing was actually protecting, and it is unchanged."""
    with pytest.raises(ValueError, match="Anthropic provider requires"):
        settings_from_env({"DATABASE_URL": DSN, "ADVISORY_MONITOR_PROVIDER": "anthropic"})


def test_the_same_refusal_holds_when_settings_are_constructed_directly() -> None:
    """Both call sites were relaxed, so both have to keep the property."""
    with pytest.raises(ValueError, match="Anthropic provider requires"):
        HostSettings(
            database_url=DSN, monitor_provider="anthropic", anthropic_model="claude-opus-5"
        )


def test_a_key_with_no_provider_is_inert_rather_than_refused() -> None:
    """Credentials do not activate external behaviour; the provider selects it."""
    settings = HostSettings(
        database_url=DSN, anthropic_api_key="k", anthropic_model="claude-opus-5"
    )
    assert settings.monitor_provider == "fixture"


def test_tracing_is_turned_on_by_its_keys_and_not_by_its_base_url() -> None:
    """``LANGFUSE_BASE_URL`` has a committed default, so an all-three check would
    have fired for every host with no Langfuse keys -- the same failure as the
    Anthropic pairing, from the same cause."""
    settings = settings_from_env({"DATABASE_URL": DSN})
    assert settings.langfuse_base_url is not None
    assert settings.langfuse_public_key is None


def test_half_configured_tracing_is_still_refused() -> None:
    """The property the all-three check was for, kept."""
    with pytest.raises(ValueError, match="Langfuse configuration"):
        settings_from_env(
            {"DATABASE_URL": DSN, "LANGFUSE_PUBLIC_KEY": "p", "LANGFUSE_BASE_URL": ""}
        )
    with pytest.raises(ValueError, match="Langfuse configuration"):
        settings_from_env({"DATABASE_URL": DSN, "LANGFUSE_PUBLIC_KEY": "p"})


def test_tracing_is_not_exported_without_its_keys() -> None:
    """The third copy of the all-three check lived in ``telemetry_config``.

    Fixing only ``settings_from_env`` left it refusing every host with a committed
    base URL and no Langfuse keys -- caught by the gate, not by reading. ``external``
    still requires all three, so a committed base URL does not switch exporting on.
    """
    from incidentgate.host.app import telemetry_config

    config = telemetry_config(settings_from_env({"DATABASE_URL": DSN}))
    assert config.external is False
    assert config.langfuse_base_url is not None


def test_tracing_is_exported_when_all_three_are_present() -> None:
    config_settings = settings_from_env(
        {
            "DATABASE_URL": DSN,
            "LANGFUSE_PUBLIC_KEY": "p",
            "LANGFUSE_SECRET_KEY": "s",
        }
    )
    from incidentgate.host.app import telemetry_config

    assert telemetry_config(config_settings).external is True
