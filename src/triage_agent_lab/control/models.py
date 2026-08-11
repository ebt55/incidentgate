"""Private control-plane models. Postgres durability is deliberately not asserted here."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import Field

from triage_agent_lab.contracts import (
    ApprovalToken,
    ContractModel,
    Hypothesis,
    IncidentReport,
    MonitorResult,
    OperationLedgerResult,
    PolicyOutcome,
    Role,
    VerificationResult,
)


class EvidenceState(StrEnum):
    VALID = "valid"
    INVALID = "invalid"


class EvidenceValidation(ContractModel):
    state: EvidenceState
    reasons: tuple[str, ...] = Field(min_length=1)
    evidence_ids: tuple[str, ...] = ()
    digest: tuple[dict[str, Any], ...] = ()


class Caller(ContractModel):
    """Authenticated principal supplied by the host, never inferred from a display name."""

    actor: str = Field(min_length=1)
    role: Role


class HumanDecision(ContractModel):
    decision: str = Field(pattern=r"^(approve|reject)$")
    approver: str = Field(min_length=1)
    reason: str | None = Field(default=None, max_length=1000)
    token: ApprovalToken | None = None


class ControlAuditEvent(ContractModel):
    transition: str
    incident_id: str
    thread_id: str
    action_hash: str | None = None
    reason: str | None = None
    at: datetime


class D1Result(ContractModel):
    final_state: str
    reasons: tuple[str, ...] = Field(min_length=1)
    action_hash: str | None = None
    evidence_ids: tuple[str, ...] = ()
    policy: PolicyOutcome | None = None
    monitor: MonitorResult | None = None
    operation: OperationLedgerResult | None = None
    verification: VerificationResult | None = None
    hypothesis: Hypothesis | None = None
    idempotency_key: UUID | None = None
    approval: HumanDecision | None = None
    report: IncidentReport | None = None


def audit_event(
    transition: str,
    *,
    incident_id: str,
    thread_id: str,
    now: datetime,
    action_hash: str | None = None,
    reason: str | None = None,
) -> ControlAuditEvent:
    return ControlAuditEvent(
        transition=transition,
        incident_id=incident_id,
        thread_id=thread_id,
        action_hash=action_hash,
        reason=reason,
        at=now,
    )
