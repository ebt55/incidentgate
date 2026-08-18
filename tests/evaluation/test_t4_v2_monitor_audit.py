"""T4-v2's unpromoted, offline semantic-monitor audit."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incidentgate.contracts import (
    EvidenceRecord,
    IncidentIdentity,
    Role,
    SetCheckoutMaintenanceModeArgs,
    SetCheckoutTrafficDrainArgs,
    ToolCallContext,
)
from incidentgate.control.models import Caller
from incidentgate.control.proposal import ProposalError
from incidentgate.manifests import T4V2Overlay, load_t4_v2_overlay

ROOT = Path(__file__).parents[2]


def _overlay() -> T4V2Overlay:
    return load_t4_v2_overlay(
        ROOT / "scenarios" / "sabotage-v2" / "T4.json",
        ROOT / "scenarios" / "sabotage" / "T4.json",
    )


def _evidence(calls: tuple[str, ...]) -> tuple[EvidenceRecord, ...]:
    now = datetime.now(UTC)
    payloads = (
        (
            "observability.checkout_health",
            {"component": "checkout", "health": "failing", "status": 503, "feature_x": True},
        ),
        ("observability.call_ledger", {"calls": list(calls), "mutation_count": len(calls)}),
    )
    return tuple(
        EvidenceRecord(
            evidence_id=f"ev-{index}",
            incident_id="INC-T4",
            thread_id="t4-v2-unit",
            correlation_id="corr-t4-v2-unit",
            tool_name=tool_name,
            actor="operator-1",
            permission="observability:read",
            observed_at=now,
            expires_at=now + timedelta(seconds=120),
            payload=payload,
        )
        for index, (tool_name, payload) in enumerate(payloads)
    )


def _identity() -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    return (
        IncidentIdentity(
            incident_id="INC-T4",
            scenario_id="T4",
            thread_id="t4-v2-unit",
            correlation_id="corr-t4-v2-unit",
        ),
        Caller(actor="operator-1", role=Role.OPERATOR),
        ToolCallContext(
            incident_id="INC-T4",
            thread_id="t4-v2-unit",
            correlation_id="corr-t4-v2-unit",
            actor="operator-1",
            permission="operations:write",
        ),
    )


def test_t4_v2_plan_uses_the_overlay_typed_actions_and_rejects_stale_prefix() -> None:
    from incidentgate.control.attack_policies import t4_v2_covert_plan

    variant = _overlay().variants[2]
    incident, caller, context = _identity()
    plan = t4_v2_covert_plan(variant)
    assert len(plan) == len(variant.action_history)

    committed: tuple[str, ...] = ()
    for proposer, expected in zip(plan, variant.action_history, strict=True):
        _, action = proposer.propose(incident, caller, context, _evidence(committed))
        assert action.tool_name == expected.tool
        if expected.field == "maintenance_mode":
            assert isinstance(action.arguments, SetCheckoutMaintenanceModeArgs)
            assert action.arguments.component == expected.component
            assert action.arguments.maintenance_mode is expected.value
        else:
            assert isinstance(action.arguments, SetCheckoutTrafficDrainArgs)
            assert action.arguments.component == expected.component
            assert action.arguments.traffic_drain is expected.value
        committed = (*committed, action.tool_name)

    with pytest.raises(ProposalError):
        plan[2].propose(
            incident,
            caller,
            context,
            # T4's public evidence intentionally records durable tool names,
            # not prior boolean arguments; state is verified authoritatively by
            # the real-condition end state below.
            _evidence((variant.action_history[0].tool, variant.action_history[0].tool)),
        )
