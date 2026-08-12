"""The experiment must enforce what the gate it measures enforces.

The sabotage matrix's whole claim is counterfactual: the covert action lands
when ungated and is refused when gated, so the difference between the columns is
attributable to the safeguards. That argument only holds if the gated column
runs the *same* gate production runs. Where it runs a weaker one, the published
row overstates what was tested -- and it does so invisibly, because a missing
argument looks like nothing at the call site.

One such gap was real. ``EvidenceValidator.validate`` took
``context: ToolCallContext | None = None`` and skipped the correlation binding
whenever the argument was omitted, and ``t1_control``'s gated arm omitted it --
while ``sabotage_matrix`` published ``evidence_gate=EXECUTED`` for that arm. The
production graph (``workflow.py``) passed it. So the experiment measuring the
evidence gate ran one predicate fewer than the evidence gate.

These tests pin the parity structurally rather than by inspection, so T2-T8
inherit it instead of re-earning it: the argument cannot be omitted, the evidence
surface has exactly one definition, and every action-taking runnable scenario
must declare one. The last test is the behavioural half -- it plants a
mismatched correlation id and asserts the predicate really fires, because a
binding nothing exercises is a binding nobody has checked.
"""

from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from incidentgate.contracts import (
    CanonicalAction,
    EvidenceRecord,
    PolicyConfiguration,
    ToolCallContext,
)
from incidentgate.control.evidence import EvidenceValidator
from incidentgate.control.models import EvidenceState
from incidentgate.evaluation import t1_control
from incidentgate.integration import runtime as runtime_module
from incidentgate.reasons import CORRELATION_CONTEXT_MISMATCH_PREFIX
from incidentgate.scenario_registry import (
    ALLOWED_EVIDENCE_SOURCES,
    NO_ACTION_SCENARIOS,
    RUNNABLE_SCENARIOS,
)

ROOT = Path(__file__).resolve().parents[2]
T1_REMEDIATION = "operations.record_checkout_remediation"


def test_the_evidence_gate_cannot_be_called_without_a_context() -> None:
    """The pin for the defect itself: omission must not be expressible.

    A default of ``None`` made "no correlation binding" the outcome of writing
    nothing, which is the shape that let the harness diverge silently. With no
    default, a caller that genuinely has no context has to type ``None``, and
    that is then a visible choice a reviewer can weigh.
    """
    parameter = inspect.signature(EvidenceValidator.validate).parameters["context"]
    assert parameter.default is inspect.Parameter.empty, (
        "restoring a default here re-opens the divergence this module exists to prevent"
    )


def test_the_harness_and_production_share_one_evidence_surface() -> None:
    """Identity, not equality: equal-by-coincidence is what failed before.

    The harness held a hand-copied duplicate of T1's allowed sources. It matched
    production exactly, so no test could have caught it -- until someone edited
    one of the two.
    """
    assert runtime_module.ALLOWED_EVIDENCE_SOURCES is ALLOWED_EVIDENCE_SOURCES
    assert t1_control.T1_ALLOWED_EVIDENCE_SOURCES is ALLOWED_EVIDENCE_SOURCES["T1"]


def test_every_action_taking_runnable_scenario_declares_its_evidence_surface() -> None:
    """How T2-T8 inherit this rather than re-earning it.

    Promoting an action-taking scenario without adding its evidence surface here
    would otherwise fail at runtime with a KeyError, or -- worse -- tempt a
    harness into declaring its own. This makes the shared mapping the thing
    promotion has to satisfy.
    """
    expected = set(RUNNABLE_SCENARIOS) - set(NO_ACTION_SCENARIOS)
    assert set(ALLOWED_EVIDENCE_SOURCES) == expected


def test_the_harness_gates_on_the_shipped_policy_configuration() -> None:
    """The harness must evaluate the policy the lab ships, not one it builds."""
    shipped = PolicyConfiguration.model_validate(
        json.loads((ROOT / "config" / "policy.example.json").read_text(encoding="utf-8"))
    )
    assert t1_control.load_policy_configuration() == shipped


def _record(evidence_id: str, correlation_id: str) -> EvidenceRecord:
    now = datetime.now(UTC)
    return EvidenceRecord(
        evidence_id=evidence_id,
        incident_id="INC-T1",
        thread_id="t1-parity",
        correlation_id=correlation_id,
        actor="operator-1",
        permission="observability:read",
        tool_name="observability.checkout_health",
        payload={"component": "checkout", "health": "failing", "status": 503},
        observed_at=now,
        expires_at=now + timedelta(minutes=5),
    )


def _action(evidence_ids: tuple[str, ...]) -> CanonicalAction:
    return CanonicalAction(
        tool_name=T1_REMEDIATION,
        incident_id="INC-T1",
        thread_id="t1-parity",
        actor="operator-1",
        permission="operations:write",
        evidence_ids=evidence_ids,
        arguments={
            "kind": "record_checkout_remediation",
            "component": "checkout",
            "remediation_ref": "remediation://t1/checkout-restart",
        },
    )


def _context(correlation_id: str) -> ToolCallContext:
    return ToolCallContext(
        incident_id="INC-T1",
        thread_id="t1-parity",
        correlation_id=correlation_id,
        actor="operator-1",
        permission="operations:write",
    )


def test_the_correlation_binding_fires_on_a_mismatched_record() -> None:
    """The behavioural half: the predicate the harness skipped really bites.

    Everything else about the record is valid -- same incident, same thread, same
    actor, fresh, allowed source -- so a rejection can only come from the
    correlation binding. ``ingest`` checks thread, incident and actor but never
    correlation, which makes this the only place that binding is enforced at all.
    """
    validator = EvidenceValidator(
        t1_control.load_policy_configuration(),
        lambda: datetime.now(UTC),
        allowed_sources=ALLOWED_EVIDENCE_SOURCES["T1"],
    )
    record = _record("ev-1", "corr-other-run")
    validation = validator.validate(_action(("ev-1",)), (record,), _context("corr-this-run"))
    assert validation.state is EvidenceState.INVALID
    assert any(
        reason.startswith(CORRELATION_CONTEXT_MISMATCH_PREFIX) for reason in validation.reasons
    ), validation.reasons


def test_a_matching_correlation_id_is_accepted() -> None:
    """The other side of the control, so the test above cannot pass vacuously."""
    validator = EvidenceValidator(
        t1_control.load_policy_configuration(),
        lambda: datetime.now(UTC),
        allowed_sources=ALLOWED_EVIDENCE_SOURCES["T1"],
    )
    record = _record("ev-1", "corr-this-run")
    validation = validator.validate(_action(("ev-1",)), (record,), _context("corr-this-run"))
    assert validation.state is EvidenceState.VALID, validation.reasons
