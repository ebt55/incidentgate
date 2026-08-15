"""Private control-plane models. Postgres durability is deliberately not asserted here."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, model_validator

from incidentgate.contracts import (
    ApprovalToken,
    ContractModel,
    Hypothesis,
    IncidentReport,
    ModelInvocationRecord,
    MonitorResult,
    MonitorVerdict,
    OperationLedgerResult,
    OperationStatus,
    PolicyDecision,
    PolicyOutcome,
    Role,
    VerificationResult,
)
from incidentgate.control.safeguards import AuthorizationGate, GateMode

EvaluationAuthorization = Literal[
    "automatic_evaluation_capability", "deterministic_approver_simulation"
]


def evaluation_authorization_label(gate: AuthorizationGate) -> EvaluationAuthorization:
    """The stable evaluation label for the public authorization implementation."""
    if gate is AuthorizationGate.DETERMINISTIC_CONTROL:
        return "automatic_evaluation_capability"
    return "deterministic_approver_simulation"


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


class WorkflowResult(ContractModel):
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


class EpisodeCheckpointIdentity(ContractModel):
    """A transcript-local action identity within one business incident thread.

    The root graph has exactly one LangGraph storage thread, so this identity
    deliberately is *not* a checkpointer namespace.  It is the durable
    sequence used to bind a started event to its terminal observation.
    """

    episode_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,120}$")
    sequence: int = Field(ge=0)


class EpisodeSafeguardIdentity(ContractModel):
    """The root-bound safeguard configuration used to resume an episode."""

    evidence_gate: GateMode
    policy_gate: GateMode
    monitor_gate: GateMode
    authorization_gate: AuthorizationGate
    control_approver: str | None = Field(default=None, min_length=1, max_length=200)


class EpisodeAuthorizationSelection(ContractModel):
    """A prompt-free, per-attempt authorization dependency identity."""

    leg: Literal["covert", "incident"]
    leg_index: int = Field(ge=0)
    sequence: int = Field(ge=0)
    selection_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,120}$")


class EpisodeStepSnapshot(ContractModel):
    """Secret-free terminal fact set recorded by an evaluation transcript."""

    thread_id: str = Field(min_length=1, max_length=128)
    #: A strategy can select a bounded attempt whose proposer declines to emit a
    #: canonical action.  That is an attempted/not-produced outcome, not a
    #: policy/monitor/human/repository catch, and it must not invent call facts.
    proposal_produced: bool = True
    tool_name: str | None = Field(default=None, min_length=1, max_length=128)
    arguments_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=32)
    policy_decision: PolicyDecision | None = None
    evidence_state: EvidenceState | None = None
    monitor_verdict: MonitorVerdict | None = None
    monitor_error_kind: str | None = Field(default=None, max_length=64)
    monitor_invocation: ModelInvocationRecord | None = None
    monitor_input_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    authorization: EvaluationAuthorization | None = None
    executed: bool
    operation_id: str | None = Field(default=None, max_length=200)
    operation_status: OperationStatus | None = None
    redelivered: bool
    terminal_state: str = Field(min_length=1, max_length=32)
    refusal_causes: tuple[str, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def proposal_shape_matches_production(self) -> EpisodeStepSnapshot:
        if self.proposal_produced:
            if self.tool_name is None or self.arguments_digest is None or not self.evidence_ids:
                raise ValueError(
                    "a produced proposal requires tool, arguments digest, and evidence ids"
                )
            if self.monitor_verdict is not None and self.monitor_error_kind is not None:
                raise ValueError("a monitor cannot have both a verdict and an error")
            if self.monitor_invocation is not None and self.monitor_input_hash is None:
                raise ValueError("a monitor invocation requires its input hash")
            operation_pair = (self.operation_id is not None, self.operation_status is not None)
            if operation_pair[0] != operation_pair[1]:
                raise ValueError("operation id and status must either both be present or absent")
            has_operation = self.operation_id is not None and self.operation_status is not None
            if self.executed != has_operation:
                raise ValueError("execution facts require both operation id and status")
            if self.redelivered != (self.operation_status is OperationStatus.DUPLICATE):
                raise ValueError("redelivery is exactly a duplicate operation")
            return self
        if (
            self.tool_name is not None
            or self.arguments_digest is not None
            or self.evidence_ids
            or self.policy_decision is not None
            or self.evidence_state is not None
            or self.monitor_verdict is not None
            or self.monitor_error_kind is not None
            or self.monitor_invocation is not None
            or self.monitor_input_hash is not None
            or self.authorization is not None
            or self.executed
            or self.operation_id is not None
            or self.operation_status is not None
            or self.redelivered
        ):
            raise ValueError("a not-produced proposal cannot carry action or gate facts")
        return self


class EpisodeTranscriptEvent(ContractModel):
    """One immutable observation in a resumable evaluation episode."""

    identity: EpisodeCheckpointIdentity
    leg: Literal["covert", "incident"]
    action_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,120}$")
    phase: Literal["started", "terminal"]
    at: datetime
    #: A typed prompt-free snapshot of the step observation.  It is populated only
    #: for terminal events; the matching ``started`` event is the durable claim
    #: that an action with this exact checkpoint identity may be redelivered.
    step: EpisodeStepSnapshot | None = None

    @model_validator(mode="after")
    def phase_has_only_its_legal_payload(self) -> EpisodeTranscriptEvent:
        if self.at.tzinfo is None or self.at.utcoffset() is None:
            raise ValueError("episode transcript timestamps must be timezone-aware")
        if (self.phase == "started") != (self.step is None):
            raise ValueError("started events have no snapshot and terminal events require one")
        return self


class EpisodeTranscript(ContractModel):
    """Append-only event stream for one business incident/thread episode."""

    incident_id: str = Field(min_length=1)
    thread_id: str = Field(min_length=1)
    episode_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,120}$")
    events: tuple[EpisodeTranscriptEvent, ...] = ()

    @model_validator(mode="after")
    def is_ordered_single_thread_history(self) -> EpisodeTranscript:
        open_event: EpisodeTranscriptEvent | None = None
        next_sequence = 0
        for event in self.events:
            if event.identity.episode_id != self.episode_id:
                raise ValueError("transcript event belongs to another episode")
            if event.identity.sequence != next_sequence:
                raise ValueError("transcript sequences must be contiguous and monotonic")
            if event.phase == "started":
                if open_event is not None:
                    raise ValueError("a transcript cannot start two actions at once")
                open_event = event
                continue
            if (
                open_event is None
                or open_event.identity.sequence != event.identity.sequence
                or open_event.leg != event.leg
                or open_event.action_id != event.action_id
                or event.step is None
            ):
                raise ValueError("terminal event must close its matching started event")
            if event.step.thread_id != self.thread_id:
                raise ValueError("snapshot thread does not match transcript business thread")
            open_event = None
            next_sequence += 1
        return self


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
