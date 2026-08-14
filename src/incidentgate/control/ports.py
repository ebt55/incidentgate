"""Narrow, replaceable boundaries for the D1 control plane."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from incidentgate.contracts import (
    ApprovalToken,
    CanonicalAction,
    EvidenceRecord,
    Hypothesis,
    IncidentIdentity,
    MonitorVerdict,
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


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """Everything an authorizer is entitled to see about a proposed action.

    Bounded on purpose, and it is the same bound the approval interrupt already
    carried: an action hash, whether a monitor dissented, and whether a reason is
    required. No evidence payload, no token and no capability arguments cross
    this boundary, so an authorizer -- human or deterministic -- decides on the
    same facts either way.

    ``incident_id``, ``thread_id`` and ``actor`` are here because a token has to
    be *bound* to them; they are identity, not content.
    """

    action_hash: str
    incident_id: str
    thread_id: str
    actor: str
    monitor_verdict: MonitorVerdict | None
    requires_reason: bool


class AuthorizationRequester(Protocol):
    """Obtain the authorization payload for an action that reached the gate.

    One port, two implementations, and that is the point. The durable human
    implementation suspends the graph on a LangGraph interrupt and takes the
    payload from a resume; the deterministic control mints the same token through
    the same ``ApprovalService`` and returns the same payload in-process.
    Everything downstream of this call -- the approver match, the token
    validator, the audit write, the executor's own re-validation -- is the same
    code for both, so an evaluation arm that swaps the authorizer has changed
    *who decided* and nothing else.

    The return is the ``HumanDecision`` payload rather than a ``HumanDecision``
    because the durable implementation cannot construct one: LangGraph hands back
    whatever the caller resumed with, and validating it is the graph's job.
    """

    def request(self, request: AuthorizationRequest) -> Mapping[str, object]: ...


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
