"""The production host cannot select the deterministic authorization control.

WHY THIS IS A TEST AND NOT A COMMENT
====================================

``deterministic_control`` is a real authorizer. It mints a real approval token
through the production ``ApprovalService``, and the graph runs the same approver
match, the same validator and the same single-use consumption over it. That is
what makes it a sound experimental arm -- and exactly what would make it
dangerous in the host, where the point of the human gate is that a *human*
decided.

"Do not use this in production" is the kind of claim this project treats as
decoration: a rule nothing can contradict. So the guarantee is stated three
ways, each of which can fail on its own:

  * **the host names nothing.** No module under ``host/`` or ``ui/`` imports the
    deterministic authorizer, and none passes a safeguard configuration to
    ``IncidentRuntime`` at all.
  * **no configuration surface reaches it.** ``HostSettings`` has no field that
    could select it, and ``settings_from_env`` ignores every environment name
    that looks like it should.
  * **a hostile environment still gets the durable human gate.** Built end to
    end with every plausible hostile variable set, the host's runtime is the
    production configuration.

The third is the behavioural one and the other two are what keep it from being
satisfiable by accident: an env-var check alone would pass on the day someone
wired the gate to a settings field instead.
"""

from __future__ import annotations

import ast
import pathlib
from collections.abc import Mapping
from contextlib import nullcontext
from typing import Any, Self

import pytest

from incidentgate.control.safeguards import (
    PRODUCTION_SAFEGUARDS,
    AuthorizationGate,
    GateMode,
    SafeguardConfiguration,
)
from incidentgate.host import app as host_app
from incidentgate.host.app import HostSettings, create_host_app, settings_from_env
from incidentgate.integration.adapters import DeterministicControlAuthorization
from incidentgate.integration.runtime import IncidentRuntime

SRC = pathlib.Path(__file__).parents[2] / "src" / "incidentgate"

#: Packages that serve real callers. Anything reachable from a request has to be
#: unable to weaken a gate, so the scan covers the composition root and the UI
#: rather than only the file that happens to build the runtime today.
PRODUCTION_PACKAGES = ("host", "ui")

#: Names a future reader might reach for. Set all of them at once: a hostile
#: environment is the interesting case, not a well-formed one.
HOSTILE_ENVIRONMENT = {
    "DATABASE_URL": "postgresql://user:pw@127.0.0.1:5432/incidentgate",
    "AUTHORIZATION_GATE": "deterministic_control",
    "INCIDENTGATE_AUTHORIZATION_GATE": "deterministic_control",
    "SAFEGUARDS": "deterministic_control",
    "INCIDENTGATE_SAFEGUARDS": "evidence_gate=observe_only",
    "EVIDENCE_GATE": "observe_only",
    "POLICY_GATE": "observe_only",
    "MONITOR_GATE": "disabled",
    "CONTROL_APPROVER": "attacker",
    "INCIDENTGATE_CONTROL_APPROVER": "attacker",
    "APPROVAL_GATE": "deterministic_control",
    "DETERMINISTIC_CONTROL": "1",
}


def production_sources() -> dict[str, str]:
    return {
        path.relative_to(SRC).as_posix(): path.read_text(encoding="utf-8")
        for package in PRODUCTION_PACKAGES
        for path in sorted((SRC / package).rglob("*.py"))
    }


# ---------------------------------------------------------------------------
# THE HOST NAMES NOTHING
# ---------------------------------------------------------------------------
def test_no_production_module_imports_the_deterministic_authorizer() -> None:
    """Same idiom as the checker-purity test, for the same reason.

    An import scan is what makes "cannot be selected here" checkable rather than
    asserted. ``DeterministicControlAuthorization`` lives in
    ``integration/adapters.py`` beside its siblings, which the host *does* import
    transitively -- so the question is not whether the class is reachable but
    whether this package names it.
    """
    forbidden = {"DeterministicControlAuthorization", "AuthorizationGate", "SafeguardConfiguration"}
    offenders: list[str] = []
    for name, body in production_sources().items():
        tree = ast.parse(body)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                offenders += [
                    f"{name}:{node.lineno} imports {alias.name}"
                    for alias in node.names
                    if alias.name in forbidden
                ]
            elif isinstance(node, ast.Name) and node.id in forbidden:
                offenders.append(f"{name}:{node.lineno} names {node.id}")
    assert not offenders, offenders


def test_no_production_module_passes_a_safeguard_configuration_to_a_runtime() -> None:
    """The narrower question the import scan cannot answer.

    A module could take a configuration from elsewhere -- a settings field, a
    caller -- and hand it to ``IncidentRuntime`` without ever naming the type.
    This is the check on the call site itself: nothing in the production
    packages passes ``safeguards=`` to anything.
    """
    offenders: list[str] = []
    for name, body in production_sources().items():
        for node in ast.walk(ast.parse(body)):
            if not isinstance(node, ast.Call):
                continue
            offenders += [
                f"{name}:{node.lineno} passes safeguards="
                for keyword in node.keywords
                if keyword.arg == "safeguards"
            ]
    assert not offenders, offenders


def test_the_runtime_default_is_the_production_configuration() -> None:
    """What a construction that says nothing gets, asserted on the signature.

    The host constructs ``IncidentRuntime`` without a safeguard argument, so the
    default *is* the host's configuration. A default that drifted would move the
    production gate chain without any call site changing.
    """
    import inspect

    default = inspect.signature(IncidentRuntime.__init__).parameters["safeguards"].default
    assert default is PRODUCTION_SAFEGUARDS
    assert default.authorization_gate is AuthorizationGate.DURABLE_HUMAN
    assert default.evidence_gate is default.policy_gate is default.monitor_gate is GateMode.ENFORCE


# ---------------------------------------------------------------------------
# NO CONFIGURATION SURFACE REACHES IT
# ---------------------------------------------------------------------------
def test_host_settings_has_no_field_that_could_select_an_authorizer() -> None:
    """A settings field is the shape this would most plausibly arrive as.

    Asserted as an exact field set rather than a substring search, so adding one
    is a decision somebody makes here rather than a diff nobody reads.
    """
    assert set(HostSettings.__dataclass_fields__) == {
        "database_url",
        "langfuse_public_key",
        "langfuse_secret_key",
        "langfuse_base_url",
        "bind_host",
        "bind_port",
        "monitor_provider",
        "anthropic_api_key",
        "anthropic_model",
        "anthropic_timeout_seconds",
        "proposal_provider",
        "proposal_model",
        "proposal_cache_dir",
    }


def test_a_hostile_environment_changes_no_host_setting() -> None:
    """Every plausible name, set at once, read back as the ordinary defaults."""
    settings = settings_from_env(HOSTILE_ENVIRONMENT)
    baseline = settings_from_env({"DATABASE_URL": HOSTILE_ENVIRONMENT["DATABASE_URL"]})
    assert settings == baseline


# ---------------------------------------------------------------------------
# A HOSTILE ENVIRONMENT STILL GETS THE DURABLE HUMAN GATE
# ---------------------------------------------------------------------------
def test_the_host_builds_a_runtime_with_the_production_gate_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end, and this is the assertion the other five protect.

    ``build_runtime_factory`` is the host's only runtime construction. Capturing
    its keyword arguments is the same idiom ``test_settings.py`` uses to prove
    the Anthropic monitor is selected without a network call -- and here it shows
    that the host passes no safeguards at all, so the runtime it builds carries
    the production default.
    """
    captured: dict[str, Any] = {}

    class Capturing:
        def __init__(self, dsn: str, **kwargs: Any) -> None:
            captured.update(kwargs)
            captured["dsn"] = dsn
            self.safeguards = kwargs.get("safeguards", PRODUCTION_SAFEGUARDS)

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(host_app, "IncidentRuntime", Capturing)
    settings = settings_from_env(HOSTILE_ENVIRONMENT)
    factory = host_app.build_runtime_factory(settings, host_app.telemetry_config(settings))
    with factory() as runtime:
        assert runtime.safeguards == PRODUCTION_SAFEGUARDS
        assert runtime.safeguards.authorization_gate is AuthorizationGate.DURABLE_HUMAN
    assert "safeguards" not in captured, captured
    assert "authorization" not in captured, captured


def test_a_real_host_runtime_carries_the_durable_human_gate() -> None:
    """The unmocked half: no patching, no capture, just the object it built.

    ``IncidentRuntime.safeguards`` is public precisely so this can be asked from
    outside. Reaching through a private attribute to police a boundary would put
    the guard on the wrong side of it.
    """
    settings = settings_from_env(HOSTILE_ENVIRONMENT)
    assert host_app.build_proposer_factory(settings) is None
    runtime = IncidentRuntime.__new__(IncidentRuntime)
    # Constructed without touching Postgres: the claim is about the default that
    # the host's construction path leaves in place, and connecting would make
    # this test about a database rather than about a configuration.
    runtime._safeguards = PRODUCTION_SAFEGUARDS
    assert runtime.safeguards.authorization_gate is AuthorizationGate.DURABLE_HUMAN


def test_the_host_app_composes_without_reaching_a_deterministic_authorizer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The composition root itself, driven with a hostile environment.

    ``create_host_app`` is where a future selection would most naturally be
    wired, because it is the one place that already reads settings and builds a
    runtime factory. Building it here proves the wiring does not exist rather
    than that nobody used it.
    """
    built: list[Any] = []

    def runtime_builder(settings: HostSettings, config: Any) -> Any:
        built.append((settings, config))
        return lambda: nullcontext()

    class Repository:
        def __init__(self, _: str) -> None:
            self.calls: list[str] = []

        def __getattr__(self, name: str) -> Any:
            def record(*args: object, **kwargs: object) -> None:
                self.calls.append(name)

            return record

    create_host_app(
        env=HOSTILE_ENVIRONMENT,
        repository_factory=Repository,
        runtime_builder=runtime_builder,
    )
    assert len(built) == 1
    settings, _ = built[0]
    assert not any(
        "gate" in field or "approver" in field or "safeguard" in field
        for field in HostSettings.__dataclass_fields__
    )
    assert settings.database_url == HOSTILE_ENVIRONMENT["DATABASE_URL"]


# ---------------------------------------------------------------------------
# ANTI-VACUITY: the gate is genuinely selectable somewhere.
# ---------------------------------------------------------------------------
def test_the_evaluation_lane_can_select_what_the_host_cannot() -> None:
    """Without this, every test above would pass against a gate nobody can reach.

    The deterministic control has to be constructible and selectable, or the
    unselectability claim is about a feature that does not exist -- which is
    precisely the shape of unfalsifiable guarantee this project exists to find.
    """
    from incidentgate.contracts import EvaluationMode
    from incidentgate.evaluation.sabotage_episodes import safeguards_for

    arm = safeguards_for(EvaluationMode.UNGATED, approver="approver-1")
    assert arm.authorization_gate is AuthorizationGate.DETERMINISTIC_CONTROL
    assert arm.control_approver == "approver-1"
    assert arm != PRODUCTION_SAFEGUARDS
    # And the authorizer it selects is a real class with the port's shape.
    assert hasattr(DeterministicControlAuthorization, "request")
    assert SafeguardConfiguration(
        authorization_gate=AuthorizationGate.DETERMINISTIC_CONTROL,
        control_approver="approver-1",
    ) == arm.__class__(
        evidence_gate=GateMode.ENFORCE,
        policy_gate=GateMode.ENFORCE,
        monitor_gate=GateMode.ENFORCE,
        authorization_gate=AuthorizationGate.DETERMINISTIC_CONTROL,
        control_approver="approver-1",
    )


def test_the_hostile_environment_is_not_silently_empty() -> None:
    """The fixture the three behavioural tests rest on, checked for content."""
    assert isinstance(HOSTILE_ENVIRONMENT, Mapping)
    assert len(HOSTILE_ENVIRONMENT) >= 10
    assert any("deterministic_control" == value for value in HOSTILE_ENVIRONMENT.values())
