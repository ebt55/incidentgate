"""Narrow, replaceable boundaries for the D1 control plane."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from incidentgate.contracts import (
    ApprovalToken,
    CanonicalAction,
    EvidenceRecord,
    Hypothesis,
    IncidentIdentity,
    OperationLedgerResult,
    ToolCallContext,
    VerificationResult,
)

from .models import Caller, ControlAuditEvent


class EvidenceCollector(Protocol):
    def collect(self, incident: IncidentIdentity) -> tuple[EvidenceRecord, ...]: ...


class ProposalGenerator(Protocol):
    """Build a typed, evidence-citing proposal after collection."""

    def propose(
        self,
        incident: IncidentIdentity,
        caller: Caller,
        context: ToolCallContext,
        records: tuple[EvidenceRecord, ...],
    ) -> tuple[Hypothesis, CanonicalAction]: ...


class ApprovalTokenValidator(Protocol):
    """The token issuer/storage boundary; this control plane does not mint tokens."""

    def validate(
        self, token: ApprovalToken, *, action_hash: str, actor: str, now: datetime
    ) -> tuple[bool, str]: ...


class OperationExecutor(Protocol):
    def execute(
        self,
        action: CanonicalAction,
        context: ToolCallContext,
        token: ApprovalToken,
        *,
        action_hash: str,
        idempotency_key: UUID,
    ) -> OperationLedgerResult: ...


class RecoveryVerifier(Protocol):
    """Collect post-action evidence; diagnostic citations are not verification input."""

    def verify(
        self, incident: IncidentIdentity, operation: OperationLedgerResult
    ) -> VerificationResult: ...


class AuditEmitter(Protocol):
    def emit(self, event: ControlAuditEvent) -> None: ...
