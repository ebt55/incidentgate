from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incidentgate.contracts import (
    EvidenceRecord,
    IncidentIdentity,
    PolicyConfiguration,
    Role,
    ToolCallContext,
)
from incidentgate.control import (
    Caller,
    DeterministicD2Proposer,
    DeterministicD3Proposer,
    DeterministicPolicyEngine,
    ProposalError,
)
from incidentgate.control.models import EvidenceState, EvidenceValidation

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def record(
    evidence_id: str, tool_name: str, payload: dict[str, object], *, incident: str, thread: str
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        incident_id=incident,
        thread_id=thread,
        correlation_id="corr",
        tool_name=tool_name,
        actor="observer",
        permission="observability:read",
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
        payload=payload,
    )


def inputs(scenario: str) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    incident = IncidentIdentity(
        incident_id=f"INC-{scenario}",
        scenario_id=scenario,
        thread_id="thread",
        correlation_id="corr",
    )
    return (
        incident,
        Caller(actor="operator", role=Role.OPERATOR),
        ToolCallContext(
            incident_id=incident.incident_id,
            thread_id="thread",
            correlation_id="corr",
            actor="operator",
            permission="operations:write",
        ),
    )


def policy() -> PolicyConfiguration:
    return PolicyConfiguration.model_validate(
        json.loads((Path(__file__).parents[2] / "config" / "policy.example.json").read_text())
    )


def test_d2_proposes_exact_typed_restore_and_policy_allows() -> None:
    incident, caller, context = inputs("D2")
    records = (
        record(
            "h",
            "observability.health",
            {"component": "api", "status": 500},
            incident=incident.incident_id,
            thread="thread",
        ),
        record(
            "c",
            "observability.config_diff",
            {
                "component": "api",
                "variable_name": "REQUIRED_API_URL",
                "present": False,
                "approved_value_ref": "config://approved/REQUIRED_API_URL",
            },
            incident=incident.incident_id,
            thread="thread",
        ),
        record(
            "l",
            "observability.logs",
            {"message": "missing config"},
            incident=incident.incident_id,
            thread="thread",
        ),
    )
    _, action = DeterministicD2Proposer().propose(incident, caller, context, records)
    assert action.tool_name == "operations.restore_config"
    assert action.arguments.approved_value_ref == "config://approved/REQUIRED_API_URL"
    outcome = DeterministicPolicyEngine(policy()).evaluate(
        action,
        Role.OPERATOR,
        EvidenceValidation(
            state=EvidenceState.VALID,
            reasons=("evidence_valid",),
            evidence_ids=action.evidence_ids,
            digest=(),
        ),
    )
    assert outcome.decision.value == "require_approval"


@pytest.mark.parametrize(
    "payload,reason",
    [
        (
            {
                "component": "api",
                "variable_name": "REQUIRED_API_URL",
                "present": True,
                "approved_value_ref": "config://approved/REQUIRED_API_URL",
            },
            "proposal_wrong_config",
        ),
        (
            {
                "component": "api",
                "variable_name": "REQUIRED_API_URL",
                "present": False,
                "approved_value_ref": "config://unapproved/value",
            },
            "proposal_wrong_config",
        ),
    ],
)
def test_d2_rejects_unsafe_config(payload: dict[str, object], reason: str) -> None:
    incident, caller, context = inputs("D2")
    records = (
        record(
            "h",
            "observability.health",
            {"component": "api", "status": 500},
            incident=incident.incident_id,
            thread="thread",
        ),
        record(
            "c",
            "observability.config_diff",
            payload,
            incident=incident.incident_id,
            thread="thread",
        ),
        record("l", "observability.logs", {}, incident=incident.incident_id, thread="thread"),
    )
    with pytest.raises(ProposalError, match=reason):
        DeterministicD2Proposer().propose(incident, caller, context, records)


def test_d3_requires_exhausted_pool() -> None:
    incident, caller, context = inputs("D3")
    records = (
        record(
            "h",
            "observability.health",
            {"component": "api", "status": 503},
            incident=incident.incident_id,
            thread="thread",
        ),
        record(
            "m",
            "metrics.db_pool",
            {"component": "api", "used": 10, "capacity": 10},
            incident=incident.incident_id,
            thread="thread",
        ),
        record("l", "observability.logs", {}, incident=incident.incident_id, thread="thread"),
    )
    _, action = DeterministicD3Proposer().propose(incident, caller, context, records)
    assert action.tool_name == "operations.restart" and action.arguments.component == "api"
    outcome = DeterministicPolicyEngine(policy()).evaluate(
        action,
        Role.OPERATOR,
        EvidenceValidation(
            state=EvidenceState.VALID,
            reasons=("evidence_valid",),
            evidence_ids=action.evidence_ids,
            digest=(),
        ),
    )
    assert outcome.decision.value == "require_approval"
    bad = (
        records[:1]
        + (
            records[1].model_copy(
                update={"payload": {"component": "api", "used": 9, "capacity": 10}}
            ),
        )
        + records[2:]
    )
    with pytest.raises(ProposalError, match="proposal_below_threshold"):
        DeterministicD3Proposer().propose(incident, caller, context, bad)
