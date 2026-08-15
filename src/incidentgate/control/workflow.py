"""Replay-safe-before-approval D1 LangGraph workflow.

The builder accepts any LangGraph checkpointer. Unit tests use ``MemorySaver``; this
module does not claim Postgres durability or crash-safe external exactly-once effects.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypedDict, cast, runtime_checkable
from uuid import NAMESPACE_URL, UUID, uuid5

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from incidentgate.contracts import (
    CanonicalAction,
    EvidenceRecord,
    Hypothesis,
    IncidentIdentity,
    IncidentReport,
    IncidentState,
    ModelInvocationRecord,
    MonitorVerdict,
    OperationLedgerResult,
    OperationStatus,
    PolicyDecision,
    ToolCallContext,
    canonical_arguments_digest,
)
from incidentgate.reasons import (
    APPROVAL_TOKEN_REQUIRED,
    AUDIT_APPROVED,
    AUDIT_EXECUTED,
    AUDIT_FAILED,
    AUDIT_PASSED,
    AUDIT_REJECTED,
    AUDIT_TOKEN_REQUIRED,
    CALLER_ACTOR_MISMATCH,
    COLLECTION_CONTEXT_MISMATCH,
    DEFER_REASON_REQUIRED,
    EVIDENCE_VALID,
    HUMAN_REJECTED,
    INCIDENT_CONTEXT_MISMATCH,
    MONITOR_ACTION_HASH_MISMATCH,
    MONITOR_BLOCK,
    MONITOR_ERROR,
    NO_ACTION_EVIDENCE_VALIDATION_FAILED,
    POLICY_VALID,
    RECOVERY_FAILED,
    RECOVERY_VERIFIED,
    THREAD_CONTEXT_MISMATCH,
    TIME_BUDGET_EXHAUSTED,
    TOKEN_APPROVER_MISMATCH,
    approval_invalid,
    monitor_error,
    monitor_verdict,
)
from incidentgate.scenario_registry import (
    ACTION_TAKING_SCENARIOS,
    NO_ACTION_CATALOG,
    validate_no_action_evidence,
)
from incidentgate.telemetry import TelemetryRuntime

from .evidence import EvidenceValidator
from .models import (
    Caller,
    EpisodeAuthorizationSelection,
    EpisodeCheckpointIdentity,
    EpisodeSafeguardIdentity,
    EpisodeStepSnapshot,
    EpisodeTranscript,
    EpisodeTranscriptEvent,
    EvidenceState,
    EvidenceValidation,
    HumanDecision,
    WorkflowResult,
    audit_event,
    evaluation_authorization_label,
)
from .monitor import AdvisoryMonitor
from .policy import DeterministicPolicyEngine
from .ports import (
    ApprovalTokenValidator,
    AuditEmitter,
    AuthorizationRequest,
    AuthorizationRequester,
    EvidenceCollector,
    MonitorConsultationFactory,
    OperationExecutor,
    ProposalGenerator,
    RecoveryVerifier,
)
from .proposal import ProposalError
from .safeguards import PRODUCTION_SAFEGUARDS, SafeguardConfiguration

if TYPE_CHECKING:
    from .monitor_decision import MonitorThresholds
    from .monitor_v2 import AdvisoryMonitorV2


class WorkflowState(TypedDict, total=False):
    incident: IncidentIdentity
    action: CanonicalAction
    context: ToolCallContext
    caller: Caller
    records: tuple[Any, ...]
    evidence: EvidenceValidation
    hypothesis: Hypothesis
    policy: Any
    monitor: Any
    monitor_error: str
    monitor_input_hash: str | None
    monitor_invocation: ModelInvocationRecord | None
    idempotency_key: UUID
    human: HumanDecision
    operation: Any
    verification: Any
    result: WorkflowResult
    trace_carrier: dict[str, str]


class EpisodeWorkflowState(TypedDict, total=False):
    """One root graph's durable episode facts plus the shared action state.

    Action-local workflow channels are deliberately overwritten by
    ``episode_clear`` between iterations.  The transcript, sequence and bound
    are root-state facts: unlike the prior prototype they do not live in a
    separate manually-written checkpoint chain.
    """

    incident: IncidentIdentity
    context: ToolCallContext
    caller: Caller
    records: tuple[EvidenceRecord, ...] | None
    evidence: EvidenceValidation | None
    hypothesis: Hypothesis | None
    action: CanonicalAction | None
    policy: Any | None
    monitor: Any | None
    monitor_error: str | None
    monitor_input_hash: str | None
    monitor_invocation: ModelInvocationRecord | None
    idempotency_key: UUID | None
    human: HumanDecision | None
    operation: Any | None
    verification: Any | None
    result: WorkflowResult | None
    trace_carrier: dict[str, str]
    episode_transcript: EpisodeTranscript
    episode_max_actions: int
    episode_sequence: int
    episode_termination: Literal["strategy_complete", "max_actions"]
    episode_safeguards: EpisodeSafeguardIdentity
    episode_current_leg: Literal["covert", "incident"] | None
    episode_current_action_id: str | None
    episode_authorization_selection: EpisodeAuthorizationSelection | None


@dataclass(frozen=True)
class EpisodeStrategyObservation:
    """Read-only, prompt-free input for adaptive episode selection.

    The strategy is a process-local dependency.  This observation and its
    return value never enter checkpoint state; the selected identifiers and the
    proposal output are written by ``episode_propose`` in one root checkpoint.
    """

    transcript: EpisodeTranscript
    incident: IncidentIdentity
    caller: Caller
    context: ToolCallContext
    records: tuple[EvidenceRecord, ...]


@dataclass(frozen=True)
class EpisodeActionSelection:
    """An in-memory choice to make a fresh shared-pipeline proposal."""

    leg: Literal["covert", "incident"]
    action_id: str
    proposer: ProposalGenerator


@dataclass(frozen=True)
class EpisodeAuthorizationChoice:
    """One explicit, replay-checkable authorization implementation choice.

    ``selection_id`` is a trusted, versioned semantic identity supplied by the
    evaluation host.  It must change whenever the factory or requester behavior
    changes.  Reusing an id for different behavior violates the episode replay
    contract, even if the callable happens to share a type or qualified name.
    """

    selection_id: str
    factory: Callable[[], AuthorizationRequester]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", self.selection_id):
            raise ValueError("episode authorization selection_id must be a bounded identifier")
        if not callable(self.factory):
            raise TypeError("episode authorization choice factory must be callable")


EpisodeStrategy = Callable[[EpisodeStrategyObservation], EpisodeActionSelection | None]
EpisodeAuthorizationFactorySelector = Callable[
    [Literal["covert", "incident"], int], EpisodeAuthorizationChoice | None
]
EpisodePostDeliveryHook = Callable[
    [Literal["covert", "incident"], int, OperationLedgerResult], None
]


def resolve_episode_authorization(
    *,
    fallback: AuthorizationRequester,
    selector: EpisodeAuthorizationFactorySelector | None,
    leg: Literal["covert", "incident"],
    leg_index: int,
    sequence: int,
) -> tuple[EpisodeAuthorizationSelection, AuthorizationRequester]:
    """Construct one requester and its durable, replay-checkable identity."""
    choice: EpisodeAuthorizationChoice | None = None
    requester = fallback
    if selector is not None:
        choice = selector(leg, leg_index)
        if choice is not None:
            if not isinstance(choice, EpisodeAuthorizationChoice):
                raise TypeError("episode authorization selector must return an explicit choice")
            requester = choice.factory()
            if not callable(getattr(requester, "request", None)):
                raise TypeError("episode authorization factory returned an invalid requester")
    return (
        EpisodeAuthorizationSelection(
            leg=leg,
            leg_index=leg_index,
            sequence=sequence,
            selection_id="safeguard_default" if choice is None else choice.selection_id,
        ),
        requester,
    )


@runtime_checkable
class _SemanticMonitorObservation(Protocol):
    @property
    def last_input_hash(self) -> str | None: ...

    @property
    def last_invocation(self) -> ModelInvocationRecord | None: ...


class WorkflowDependencies:
    def __init__(
        self,
        *,
        collector: EvidenceCollector,
        proposer: ProposalGenerator,
        evidence_validator: EvidenceValidator,
        policy: DeterministicPolicyEngine,
        monitor: AdvisoryMonitor | None,
        token_validator: ApprovalTokenValidator,
        executor: OperationExecutor,
        verifier: RecoveryVerifier,
        audit: AuditEmitter,
        clock: Callable[[], datetime],
        telemetry: TelemetryRuntime | None = None,
        # Which gates enforce and who authorizes. Defaults to production's, so
        # every existing construction site keeps the behaviour it had: with
        # PRODUCTION_SAFEGUARDS the branches below reduce to the unconditional
        # code they replaced, term for term.
        safeguards: SafeguardConfiguration = PRODUCTION_SAFEGUARDS,
        # The authorization port. ``None`` selects the durable human interrupt,
        # which is the only authorizer the production host can reach.
        authorization: AuthorizationRequester | None = None,
        monitor_v2: AdvisoryMonitorV2 | None = None,
        monitor_consultation_factory: MonitorConsultationFactory | None = None,
        monitor_thresholds: MonitorThresholds | None = None,
    ) -> None:
        v2_bundle = (monitor_v2, monitor_consultation_factory, monitor_thresholds)
        has_v1, has_any_v2 = monitor is not None, any(item is not None for item in v2_bundle)
        has_complete_v2 = all(item is not None for item in v2_bundle)
        if (has_v1 and has_any_v2) or (not has_v1 and not has_complete_v2):
            raise ValueError(
                "configure exactly one monitor: v1 monitor or complete v2 monitor bundle"
            )
        self.collector = collector
        self.proposer = proposer
        self.evidence_validator = evidence_validator
        self.policy = policy
        self.monitor = monitor
        self.monitor_v2 = monitor_v2
        self.monitor_consultation_factory = monitor_consultation_factory
        self.monitor_thresholds = monitor_thresholds
        self.token_validator = token_validator
        self.executor = executor
        self.verifier = verifier
        self.audit = audit
        self.clock = clock
        self.telemetry = telemetry
        self.safeguards = safeguards
        self.authorization = authorization or DurableHumanAuthorization()


class DurableHumanAuthorization:
    """The production authorizer: suspend the graph and wait for a human.

    Holds no state and takes no arguments, because everything it needs is in the
    request and everything it produces comes back through the resume. The
    interrupt payload is exactly the three keys it has always carried -- a
    checkpointed value is a wire format, and adding a field here would rewrite
    the durable representation of every pending approval.
    """

    def request(self, request: AuthorizationRequest) -> Any:
        return interrupt(
            {
                "action_hash": request.action_hash,
                "monitor_verdict": request.monitor_verdict,
                "requires_reason": request.requires_reason,
            }
        )


@dataclass(frozen=True)
class WorkflowNodeBundle:
    """The action pipeline's bound nodes and route selectors.

    Topologies own only edges.  This keeps an episode loop from recreating a
    policy, approval, executor, or audit implementation beside the legacy path.
    """

    nodes: dict[str, Callable[[WorkflowState], WorkflowState]]
    propose_with: Callable[[ProposalGenerator, WorkflowState], WorkflowState]
    approval_with: Callable[[AuthorizationRequester, WorkflowState], WorkflowState]
    execute_with: Callable[
        [Callable[[WorkflowState, OperationLedgerResult], None] | None, WorkflowState],
        WorkflowState,
    ]
    after_monitor: Callable[[WorkflowState], str]
    after_approval: Callable[[WorkflowState], str]


def build_deferred_graph(
    collector: EvidenceCollector,
    audit: AuditEmitter,
    clock: Callable[[], datetime],
    *,
    checkpointer: Any = None,
    telemetry: TelemetryRuntime | None = None,
) -> Any:
    """A collection-only graph for fixed no-action scenarios D4/D7."""

    def collect(state: WorkflowState) -> WorkflowState:
        incident, context = state["incident"], state["context"]
        caller = state["caller"]
        if (
            context.incident_id != incident.incident_id
            or context.thread_id != incident.thread_id
            or context.correlation_id != incident.correlation_id
            or context.actor != caller.actor
            or context.permission != "observability:read"
            or context.idempotency_key is not None
        ):
            return {
                "result": WorkflowResult(
                    final_state="blocked", reasons=(COLLECTION_CONTEXT_MISMATCH,)
                )
            }
        span = f"{incident.scenario_id.lower()}.collection"
        with (
            telemetry.start_as_current_span(
                span,
                attributes={
                    "incident_id": incident.incident_id,
                    "thread_id": incident.thread_id,
                    "correlation_id": incident.correlation_id,
                    "actor": context.actor,
                    "permission": context.permission,
                },
            )
            if telemetry
            else nullcontext()
        ):
            records = collector.collect(incident)
        if not validate_no_action_evidence(incident.scenario_id, records):
            reason = str(
                getattr(collector, "deferred_reason", NO_ACTION_EVIDENCE_VALIDATION_FAILED)
            )
            final_state = str(getattr(collector, "final_state", "blocked"))
            if final_state != "blocked" and reason == TIME_BUDGET_EXHAUSTED:
                # IncidentState has no "failed" member, so this conversion would
                # raise on one of the four TerminalOutcome values.  It cannot
                # reach here: final_state comes only from the no-action
                # collector, which assigns "deferred" or NO_ACTION_CATALOG's
                # state, and every catalog state is resolved/deferred/blocked.
                # "failed" is produced only by the evaluation's counterfactual
                # path, which never drives this graph.  Pinned by
                # test_terminal_outcomes_reaching_the_enum_are_all_members.
                terminal = IncidentState(final_state)
                audit.emit(
                    audit_event(
                        "collection_deferred",
                        incident_id=incident.incident_id,
                        thread_id=incident.thread_id,
                        now=clock(),
                        reason=reason,
                    )
                )
                return {
                    "records": records,
                    "result": WorkflowResult(
                        final_state=final_state,
                        reasons=(reason,),
                        evidence_ids=tuple(record.evidence_id for record in records),
                        report=IncidentReport(
                            incident=incident.model_copy(update={"state": terminal}),
                            diagnosis="stale health evidence",
                            hypotheses=(),
                            evidence_ids=tuple(record.evidence_id for record in records),
                            final_state=terminal,
                        ),
                    ),
                }
            return {
                "records": records,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=(NO_ACTION_EVIDENCE_VALIDATION_FAILED,),
                    evidence_ids=tuple(record.evidence_id for record in records),
                ),
            }
        metadata = NO_ACTION_CATALOG[incident.scenario_id]
        diagnosis = str(getattr(collector, "diagnosis", metadata["diagnosis"]))
        reason = str(getattr(collector, "deferred_reason", metadata["reason"]))
        final_state = str(getattr(collector, "final_state", metadata["state"]))
        # Same reasoning as the conversion above: this domain is the no-action
        # catalog's state values, none of which is "failed".
        terminal = IncidentState(final_state)
        audit.emit(
            audit_event(
                str(metadata["audit"]),
                incident_id=incident.incident_id,
                thread_id=incident.thread_id,
                now=clock(),
                reason=reason,
            )
        )
        confidence = metadata["confidence"]
        assert isinstance(confidence, float)
        hypothesis = Hypothesis(
            hypothesis_id=f"{incident.scenario_id.lower()}-deferred",
            statement=diagnosis,
            confidence=confidence,
            evidence_ids=tuple(record.evidence_id for record in records),
        )
        report = IncidentReport(
            incident=incident.model_copy(update={"state": terminal}),
            diagnosis=diagnosis,
            hypotheses=(hypothesis,),
            evidence_ids=hypothesis.evidence_ids,
            final_state=terminal,
        )
        return {
            "records": records,
            "result": WorkflowResult(
                final_state=final_state,
                reasons=(reason,),
                evidence_ids=hypothesis.evidence_ids,
                hypothesis=hypothesis,
                report=report,
            ),
        }

    graph = StateGraph(WorkflowState)
    graph.add_node("collect", collect)
    graph.add_edge(START, "collect")
    graph.add_edge("collect", END)
    return graph.compile(checkpointer=checkpointer)


# FROZEN WIRE VALUE. This prefix is seeded into every idempotency key: the derived
# uuid5 is persisted in operation_ledger.idempotency_key and compared for exact
# equality by chaos/enddiff.py. It deliberately does NOT track the project or package
# name (renamed to incidentgate) and deliberately does NOT track the scenario -- the
# ":d1:" segment is baked in for D2/D3/D5/D8 and every R-tier scenario too. Uniqueness
# comes from thread_id + action_hash, which follow it. Changing any byte here silently
# converts invariant-2 exactly-once crash replay into duplicate mutation against any
# existing durable state, because replayed keys would no longer match stored rows.
# Wire values are forever; display names are not.
_IDEMPOTENCY_KEY_PREFIX = "triage-agent-lab:d1:"


def _idempotency_key(action_hash: str, thread_id: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"{_IDEMPOTENCY_KEY_PREFIX}{thread_id}:{action_hash}")


def _episode_idempotency_key(
    action_hash: str, thread_id: str, episode_id: str, sequence: int
) -> UUID:
    """Bind one root-episode attempt without changing frozen legacy keys."""
    legacy_name = f"{_IDEMPOTENCY_KEY_PREFIX}{thread_id}:{action_hash}"
    return uuid5(
        NAMESPACE_URL,
        f"{legacy_name}:episode:{episode_id}:sequence:{sequence}",
    )


def episode_safeguard_identity(
    safeguards: SafeguardConfiguration,
) -> EpisodeSafeguardIdentity:
    """Serialize only the configuration facts that may alter a resumed gate."""
    return EpisodeSafeguardIdentity(
        evidence_gate=safeguards.evidence_gate,
        policy_gate=safeguards.policy_gate,
        monitor_gate=safeguards.monitor_gate,
        authorization_gate=safeguards.authorization_gate,
        control_approver=safeguards.control_approver,
    )


def _observed_only(evidence: EvidenceValidation) -> EvidenceValidation:
    """What an observing evidence gate hands the policy instead of its verdict.

    The citations and the digest are carried through unchanged, because those are
    facts about the run rather than the gate's opinion of it -- the monitor still
    has to see what was cited, and the action still has to name it. Only the
    verdict is replaced, so an observing gate withholds its *decision* and
    nothing else.

    The real verdict is still what lands in ``state["evidence"]``, so nothing is
    lost: an arm running this gate in observe-only mode records exactly what it
    would have refused.
    """
    return EvidenceValidation(
        state=EvidenceState.VALID,
        reasons=(EVIDENCE_VALID,),
        evidence_ids=evidence.evidence_ids,
        digest=evidence.digest,
    )


def build_workflow_builder(dependencies: WorkflowDependencies) -> Any:
    """Build the one action pipeline without choosing its root topology.

    Both the legacy one-action graph and the future episode root graph must use
    these exact node functions and routes.  The caller alone decides where the
    pipeline starts/ends and which checkpointer owns the root state.
    """

    def _attributes(state: WorkflowState) -> dict[str, object]:
        incident, context, caller = state.get("incident"), state.get("context"), state.get("caller")
        action = state.get("action")
        attributes: dict[str, object] = {}
        if incident is not None:
            attributes.update(
                incident_id=incident.incident_id,
                thread_id=incident.thread_id,
                correlation_id=incident.correlation_id,
            )
        if caller is not None:
            attributes["actor"] = caller.actor
        if context is not None:
            attributes["permission"] = context.permission
        if action is not None:
            attributes["action_hash"] = getattr(state.get("policy"), "action_hash", None)
        if state.get("idempotency_key") is not None:
            attributes["idempotency_key"] = str(state["idempotency_key"])
        return attributes

    def _span(name: str, state: WorkflowState) -> Any:
        if dependencies.telemetry is None:
            return nullcontext()
        return dependencies.telemetry.start_as_current_span(name, attributes=_attributes(state))

    def _scenario_span(phase: str, state: WorkflowState) -> str:
        """Map only the supported fixed identities to telemetry names.

        This used to be "the scenarios ``IncidentRuntime._build_graph`` builds
        an action-taking workflow for", written out a second time by hand, and
        the duplication had already bitten: adding T4's branch to
        ``_build_graph`` without adding it here failed every T4 run inside the
        policy node, at a point far from the cause. Both are now projections of
        one field, so there is nothing left to keep in step.

        Still not the acceptance gate, and deliberately so. That is
        ``RUNNABLE_SCENARIOS``, checked in ``_invoke_phase``, and the two answer
        different questions: a scenario has a graph before it is promoted, and
        that window is where every T-tier scenario is measured from.
        """
        incident = state.get("incident")
        scenario_id = getattr(incident, "scenario_id", None)
        if scenario_id not in ACTION_TAKING_SCENARIOS:
            raise ValueError("unsupported checkpoint scenario")
        return f"{scenario_id.lower()}.{phase}"

    def ingest(state: WorkflowState) -> WorkflowState:
        incident, context, caller = state["incident"], state["context"], state["caller"]
        if incident.thread_id != context.thread_id:
            return {
                "result": WorkflowResult(final_state="blocked", reasons=(THREAD_CONTEXT_MISMATCH,))
            }
        if incident.incident_id != context.incident_id:
            return {
                "result": WorkflowResult(
                    final_state="blocked", reasons=(INCIDENT_CONTEXT_MISMATCH,)
                )
            }
        if caller.actor != context.actor:
            return {
                "result": WorkflowResult(final_state="blocked", reasons=(CALLER_ACTOR_MISMATCH,))
            }
        return {}

    def collect(state: WorkflowState) -> WorkflowState:
        with _span("mcp.observability", state):
            return {"records": dependencies.collector.collect(state["incident"])}

    def propose_with(proposer: ProposalGenerator, state: WorkflowState) -> WorkflowState:
        try:
            hypothesis, action = proposer.propose(
                state["incident"], state["caller"], state["context"], state["records"]
            )
        except ProposalError as error:
            _audit(state, "proposal", error.reason)
            return {"result": WorkflowResult(final_state="blocked", reasons=(error.reason,))}
        return {"hypothesis": hypothesis, "action": action}

    def propose(state: WorkflowState) -> WorkflowState:
        return propose_with(dependencies.proposer, state)

    def validate(state: WorkflowState) -> WorkflowState:
        # The validator always runs against the real records, and what it says is
        # always what lands in state. What the evidence *gate* decides is whether
        # the policy is allowed to act on it: an observing gate hands the policy
        # a valid stand-in carrying the same citations and the same digest, so a
        # stale or unallowed citation is recorded without becoming a denial the
        # policy gate would then be credited with.
        evidence = dependencies.evidence_validator.validate(
            state["action"], state["records"], state["context"]
        )
        judged = evidence if dependencies.safeguards.enforces_evidence else _observed_only(evidence)
        with _span(_scenario_span("policy", state), state):
            policy = dependencies.policy.evaluate(state["action"], state["caller"].role, judged)
        return {
            "evidence": evidence,
            "policy": policy,
            "idempotency_key": _idempotency_key(policy.action_hash, state["incident"].thread_id),
        }

    def _semantic_observation() -> WorkflowState:
        monitor = dependencies.monitor_v2
        if monitor is None or not isinstance(monitor, _SemanticMonitorObservation):
            return {}
        input_hash, invocation = monitor.last_input_hash, monitor.last_invocation
        if input_hash is not None and not re.fullmatch(r"[a-f0-9]{64}", input_hash):
            raise TypeError("semantic monitor exposed an invalid input hash")
        if invocation is not None and not isinstance(invocation, ModelInvocationRecord):
            raise TypeError("semantic monitor exposed an invalid invocation record")
        return {"monitor_input_hash": input_hash, "monitor_invocation": invocation}

    def monitor(state: WorkflowState) -> WorkflowState:
        evidence, policy = state["evidence"], state["policy"]
        if not dependencies.safeguards.consults_monitor:
            return {}
        # Skipped after a denial that actually stops the run, never after one the
        # policy gate only observed: an action still on its way to the executor
        # is exactly the action a monitor exists to see.
        if policy.decision is PolicyDecision.DENY and dependencies.safeguards.enforces_policy:
            return {}
        with _span(_scenario_span("monitor", state), state):
            if dependencies.monitor is not None:
                return {"monitor": dependencies.monitor.assess(state["action"], evidence.digest)}
            assert (
                dependencies.monitor_v2 is not None
                and dependencies.monitor_consultation_factory is not None
                and dependencies.monitor_thresholds is not None
            )
            try:
                consultation = dependencies.monitor_consultation_factory.build(
                    incident=state["incident"],
                    action=state["action"],
                    records=state["records"],
                    evidence=evidence,
                    policy=policy,
                    safeguards=dependencies.safeguards,
                )
            except (TypeError, ValueError):
                return {"monitor_error": "input_unrenderable"}
            outcome = dependencies.monitor_v2.assess_consultation(consultation)
            if outcome.outcome == "error":
                assert outcome.error_kind is not None
                return {"monitor_error": outcome.error_kind.value, **_semantic_observation()}
            assert outcome.assessment is not None
            try:
                from .monitor_v2 import bind_assessment

                result = bind_assessment(
                    outcome.assessment, state["action"], dependencies.monitor_thresholds
                )
            except ValueError:
                # A mismatched assessment is a failed consultation, never a
                # verdict that can be counted as a monitor catch.
                return {"monitor_error": "echo_mismatch", **_semantic_observation()}
            return {"monitor": result, **_semantic_observation()}

    def after_monitor(state: WorkflowState) -> str:
        # Episode loops explicitly clear an attempt before recollecting.  A
        # cleared ``result`` is represented by ``None`` in the durable root
        # state, not by removing a channel, so presence alone is not a terminal
        # fact.  The legacy graph never writes ``None`` and therefore retains
        # its original routing behaviour.
        if state.get("result") is not None:
            return "finish"
        if state["policy"].decision is PolicyDecision.DENY and (
            dependencies.safeguards.enforces_policy
        ):
            return "deny"
        monitor_result = state.get("monitor")
        # Not a safeguard and so not configurable: a monitor whose verdict names
        # a different action than the one under decision is a broken consultation
        # rather than a lenient one, and it fails closed in every arm.
        if monitor_result and monitor_result.evaluated_action_hash != state["policy"].action_hash:
            return "monitor_mismatch"
        if state.get("monitor_error") and dependencies.safeguards.enforces_monitor:
            return "monitor_error"
        return (
            "block"
            if monitor_result
            and monitor_result.verdict is MonitorVerdict.BLOCK
            and dependencies.safeguards.enforces_monitor
            else "approve"
        )

    def _audit(state: WorkflowState, transition: str, reason: str | None = None) -> None:
        policy = state.get("policy")
        action_hash = policy.action_hash if policy is not None else None
        dependencies.audit.emit(
            audit_event(
                transition,
                incident_id=state["incident"].incident_id,
                thread_id=state["incident"].thread_id,
                action_hash=action_hash,
                now=dependencies.clock(),
                reason=reason,
            )
        )

    def _report(state: WorkflowState, final_state: IncidentState) -> IncidentReport:
        action, incident = state["action"], state["incident"]
        return IncidentReport(
            incident=incident.model_copy(update={"state": final_state}),
            diagnosis=state["hypothesis"].statement,
            hypotheses=(state["hypothesis"],),
            evidence_ids=action.evidence_ids,
            action_hash=state["policy"].action_hash,
            policy=state["policy"],
            monitor=state.get("monitor"),
            verification=state.get("verification"),
            final_state=final_state,
        )

    def deny(state: WorkflowState) -> WorkflowState:
        policy = state["policy"]
        _audit(state, "policy", ";".join(policy.reasons))
        return {
            "result": WorkflowResult(
                final_state="blocked",
                reasons=policy.reasons,
                action_hash=policy.action_hash,
                evidence_ids=state["action"].evidence_ids,
                policy=policy,
                hypothesis=state["hypothesis"],
                idempotency_key=state["idempotency_key"],
                report=_report(state, IncidentState.BLOCKED),
            )
        }

    def blocked(state: WorkflowState) -> WorkflowState:
        monitor_result, policy = state["monitor"], state["policy"]
        _audit(state, "policy", POLICY_VALID)
        _audit(state, "monitor", MONITOR_BLOCK)
        return {
            "result": WorkflowResult(
                final_state="blocked",
                reasons=(MONITOR_BLOCK,),
                action_hash=policy.action_hash,
                evidence_ids=state["action"].evidence_ids,
                policy=policy,
                monitor=monitor_result,
                hypothesis=state["hypothesis"],
                idempotency_key=state["idempotency_key"],
                report=_report(state, IncidentState.BLOCKED),
            )
        }

    def monitor_mismatch(state: WorkflowState) -> WorkflowState:
        policy = state["policy"]
        _audit(state, "policy", POLICY_VALID)
        _audit(state, "monitor", MONITOR_ACTION_HASH_MISMATCH)
        return {
            "result": WorkflowResult(
                final_state="blocked",
                reasons=(MONITOR_ACTION_HASH_MISMATCH,),
                action_hash=policy.action_hash,
                evidence_ids=state["action"].evidence_ids,
                policy=policy,
                monitor=state.get("monitor"),
                hypothesis=state["hypothesis"],
                idempotency_key=state["idempotency_key"],
                report=_report(state, IncidentState.BLOCKED),
            )
        }

    def monitor_error_terminal(state: WorkflowState) -> WorkflowState:
        policy = state["policy"]
        _audit(state, "policy", POLICY_VALID)
        _audit(state, "monitor", monitor_error(state["monitor_error"]))
        return {
            "result": WorkflowResult(
                final_state="blocked",
                reasons=(MONITOR_ERROR,),
                action_hash=policy.action_hash,
                evidence_ids=state["action"].evidence_ids,
                policy=policy,
                hypothesis=state["hypothesis"],
                idempotency_key=state["idempotency_key"],
                report=_report(state, IncidentState.BLOCKED),
            )
        }

    def preapproval_audit(state: WorkflowState) -> WorkflowState:
        """Persist the decision chain before yielding control to a human.

        This node is deliberately separate from ``approval``: an interrupt does
        not checkpoint a node's work until it resumes.  The repository gives
        these append attempts stable identities, so a crash after an append but
        before LangGraph checkpoints this node is safe to replay.
        """
        _audit(state, "policy", POLICY_VALID)
        monitor_result = state.get("monitor")
        if monitor_result:
            _audit(state, "monitor", monitor_verdict(monitor_result.verdict))
        elif state.get("monitor_error"):
            _audit(state, "monitor", monitor_error(state["monitor_error"]))
        return {}

    def approval_with(requester: AuthorizationRequester, state: WorkflowState) -> WorkflowState:
        with _span(_scenario_span("approval", state), state):
            payload = requester.request(
                AuthorizationRequest(
                    action_hash=state["policy"].action_hash,
                    incident_id=state["incident"].incident_id,
                    thread_id=state["incident"].thread_id,
                    actor=state["action"].actor,
                    monitor_verdict=(state["monitor"].verdict if state.get("monitor") else None),
                    requires_reason=bool(
                        state.get("monitor") and state["monitor"].verdict is MonitorVerdict.DEFER
                    ),
                )
            )
        # Validated here rather than by the authorizer, and for both of them:
        # the durable implementation cannot validate what a caller resumed with,
        # so the graph is the only place the check can be shared.
        human = HumanDecision.model_validate(payload)
        policy, monitor_result = state["policy"], state.get("monitor")
        if human.decision == "reject":
            _audit(state, "approval", AUDIT_REJECTED)
            return {
                "human": human,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=(HUMAN_REJECTED,),
                    action_hash=policy.action_hash,
                    evidence_ids=state["action"].evidence_ids,
                    policy=policy,
                    monitor=monitor_result,
                    hypothesis=state["hypothesis"],
                    idempotency_key=state["idempotency_key"],
                    approval=human,
                    report=_report(state, IncidentState.BLOCKED),
                ),
            }
        if (
            monitor_result
            and monitor_result.verdict is MonitorVerdict.DEFER
            and not (human.reason or "").strip()
        ):
            _audit(state, "approval", DEFER_REASON_REQUIRED)
            return {
                "human": human,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=(DEFER_REASON_REQUIRED,),
                    action_hash=policy.action_hash,
                    evidence_ids=state["action"].evidence_ids,
                    policy=policy,
                    monitor=monitor_result,
                    hypothesis=state["hypothesis"],
                    idempotency_key=state["idempotency_key"],
                    approval=human,
                    report=_report(state, IncidentState.BLOCKED),
                ),
            }
        if human.token is None:
            _audit(state, "approval", AUDIT_TOKEN_REQUIRED)
            return {
                "human": human,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=(APPROVAL_TOKEN_REQUIRED,),
                    action_hash=policy.action_hash,
                    evidence_ids=state["action"].evidence_ids,
                    policy=policy,
                    monitor=monitor_result,
                    hypothesis=state["hypothesis"],
                    idempotency_key=state["idempotency_key"],
                    approval=human,
                    report=_report(state, IncidentState.BLOCKED),
                ),
            }
        if human.approver != human.token.approver:
            # A distinct check from the token validator's own approver_mismatch:
            # this compares the principal presenting the approval against the one
            # the token names, which the validator never sees. Same reported
            # string, deliberately, because to an approver it is the same fact.
            _audit(state, "approval", approval_invalid(TOKEN_APPROVER_MISMATCH))
            return {
                "human": human,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=(approval_invalid(TOKEN_APPROVER_MISMATCH),),
                    action_hash=policy.action_hash,
                    evidence_ids=state["action"].evidence_ids,
                    policy=policy,
                    monitor=monitor_result,
                    hypothesis=state["hypothesis"],
                    idempotency_key=state["idempotency_key"],
                    approval=human,
                    report=_report(state, IncidentState.BLOCKED),
                ),
            }
        valid, reason = dependencies.token_validator.validate(
            human.token,
            action_hash=policy.action_hash,
            actor=state["action"].actor,
            now=dependencies.clock(),
        )
        if not valid:
            _audit(state, "approval", approval_invalid(reason))
            return {
                "human": human,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=(approval_invalid(reason),),
                    action_hash=policy.action_hash,
                    evidence_ids=state["action"].evidence_ids,
                    policy=policy,
                    monitor=monitor_result,
                    hypothesis=state["hypothesis"],
                    idempotency_key=state["idempotency_key"],
                    approval=human,
                    report=_report(state, IncidentState.BLOCKED),
                ),
            }
        _audit(state, "approval", AUDIT_APPROVED)
        return {"human": human}

    def approval(state: WorkflowState) -> WorkflowState:
        return approval_with(dependencies.authorization, state)

    def after_approval(state: WorkflowState) -> str:
        return "finish" if state.get("result") is not None else "execute"

    def execute_with(
        post_delivery: Callable[[WorkflowState, OperationLedgerResult], None] | None,
        state: WorkflowState,
    ) -> WorkflowState:
        action, policy, human = state["action"], state["policy"], state["human"]
        context = state["context"].model_copy(update={"idempotency_key": state["idempotency_key"]})
        token = human.token
        assert token is not None
        with _span("mcp.operations", state):
            operation = dependencies.executor.execute(
                action,
                context,
                token,
                action_hash=policy.action_hash,
                idempotency_key=state["idempotency_key"],
            )
        if post_delivery is not None:
            post_delivery(state, operation)
        dependencies.audit.emit(
            audit_event(
                "execution",
                incident_id=action.incident_id,
                thread_id=action.thread_id,
                action_hash=policy.action_hash,
                now=dependencies.clock(),
                reason=AUDIT_EXECUTED,
            )
        )
        return {"operation": operation}

    def execute(state: WorkflowState) -> WorkflowState:
        return execute_with(None, state)

    def verify(state: WorkflowState) -> WorkflowState:
        action, policy = state["action"], state["policy"]
        with _span(_scenario_span("verification", state), state):
            verification = dependencies.verifier.verify(state["incident"], state["operation"])
        dependencies.audit.emit(
            audit_event(
                "verification",
                incident_id=action.incident_id,
                thread_id=action.thread_id,
                action_hash=policy.action_hash,
                now=dependencies.clock(),
                reason=AUDIT_PASSED if verification.passed else AUDIT_FAILED,
            )
        )
        final_state = "resolved" if verification.passed else "blocked"
        incident_state = IncidentState.RESOLVED if verification.passed else IncidentState.BLOCKED
        return {
            "verification": verification,
            "result": WorkflowResult(
                final_state=final_state,
                reasons=(RECOVERY_VERIFIED if verification.passed else RECOVERY_FAILED,),
                action_hash=policy.action_hash,
                evidence_ids=action.evidence_ids,
                policy=policy,
                monitor=state.get("monitor"),
                operation=state["operation"],
                verification=verification,
                hypothesis=state["hypothesis"],
                idempotency_key=state["idempotency_key"],
                approval=state["human"],
                report=_report({**state, "verification": verification}, incident_state),
            ),
        }

    return WorkflowNodeBundle(
        nodes={
            "ingest": ingest,
            "collect": collect,
            "propose": propose,
            "validate": validate,
            "monitor": monitor,
            "deny": deny,
            "blocked": blocked,
            "monitor_mismatch": monitor_mismatch,
            "monitor_error": monitor_error_terminal,
            "preapproval_audit": preapproval_audit,
            "approval": approval,
            "execute": execute,
            "verify": verify,
        },
        propose_with=propose_with,
        approval_with=approval_with,
        execute_with=execute_with,
        after_monitor=after_monitor,
        after_approval=after_approval,
    )


def build_workflow_graph(dependencies: WorkflowDependencies, *, checkpointer: Any = None) -> Any:
    """Compile the legacy one-action root graph unchanged."""
    bundle = build_workflow_builder(dependencies)
    graph = StateGraph(WorkflowState)
    for name, node in bundle.nodes.items():
        graph.add_node(name, node)
    graph.add_edge(START, "ingest")
    graph.add_conditional_edges(
        "ingest",
        lambda state: "finish" if state.get("result") is not None else "collect",
        {"finish": END, "collect": "collect"},
    )
    graph.add_edge("collect", "propose")
    graph.add_conditional_edges(
        "propose",
        lambda state: "finish" if state.get("result") is not None else "validate",
        {"finish": END, "validate": "validate"},
    )
    graph.add_edge("validate", "monitor")
    graph.add_conditional_edges(
        "monitor",
        bundle.after_monitor,
        {
            "finish": END,
            "deny": "deny",
            "block": "blocked",
            "monitor_mismatch": "monitor_mismatch",
            "monitor_error": "monitor_error",
            "approve": "preapproval_audit",
        },
    )
    graph.add_edge("deny", END)
    graph.add_edge("blocked", END)
    graph.add_edge("monitor_mismatch", END)
    graph.add_edge("monitor_error", END)
    graph.add_edge("preapproval_audit", "approval")
    graph.add_conditional_edges(
        "approval", bundle.after_approval, {"finish": END, "execute": "execute"}
    )
    graph.add_edge("execute", "verify")
    graph.add_edge("verify", END)
    return graph.compile(checkpointer=checkpointer)


def build_episode_workflow_graph(
    dependencies: WorkflowDependencies,
    *,
    strategy: EpisodeStrategy,
    authorization_factory_selector: EpisodeAuthorizationFactorySelector | None = None,
    preselected_requesters: dict[int, AuthorizationRequester] | None = None,
    post_delivery_hook: EpisodePostDeliveryHook | None = None,
    interrupt_after: tuple[Literal["episode_propose", "monitor", "execute"], ...] = (),
    checkpointer: Any = None,
) -> Any:
    """Compile the adaptive evaluation loop on one LangGraph root thread.

    The loop owns sequencing and the transcript, but not control-plane policy:
    every action-taking node below is a bound callable from
    :func:`build_workflow_builder`.  In particular, a denial reaches the same
    policy/monitor/authorization implementation as it does in the legacy
    one-action graph; only its terminal edge returns to ``episode_record``
    rather than ``END``.
    """

    bundle = build_workflow_builder(dependencies)
    requester_cache = {} if preselected_requesters is None else dict(preselected_requesters)
    expected_safeguards = episode_safeguard_identity(dependencies.safeguards)

    def transcript_from(state: EpisodeWorkflowState) -> EpisodeTranscript:
        raw = state["episode_transcript"]
        payload = raw.model_dump(mode="python") if isinstance(raw, EpisodeTranscript) else raw
        return EpisodeTranscript.model_validate(payload)

    def ensure_safeguards(state: EpisodeWorkflowState) -> None:
        raw = state.get("episode_safeguards")
        persisted = (
            raw
            if isinstance(raw, EpisodeSafeguardIdentity)
            else EpisodeSafeguardIdentity.model_validate(raw)
        )
        if persisted != expected_safeguards:
            raise ValueError("episode safeguards do not match the durable root configuration")

    def select_requester(
        *,
        leg: Literal["covert", "incident"],
        leg_index: int,
        sequence: int,
    ) -> tuple[EpisodeAuthorizationSelection, AuthorizationRequester]:
        return resolve_episode_authorization(
            fallback=dependencies.authorization,
            selector=authorization_factory_selector,
            leg=leg,
            leg_index=leg_index,
            sequence=sequence,
        )

    def episode_propose(state: EpisodeWorkflowState) -> EpisodeWorkflowState:
        ensure_safeguards(state)
        transcript = transcript_from(state)
        raw_records = state["records"]
        if raw_records is None:
            raise ValueError("episode collection did not produce evidence records")
        records = raw_records
        selection = strategy(
            EpisodeStrategyObservation(
                transcript=transcript,
                incident=state["incident"],
                caller=state["caller"],
                context=state["context"],
                records=records,
            )
        )
        if selection is None:
            return {"episode_termination": "strategy_complete"}
        if not selection.action_id or len(selection.action_id) > 120:
            raise ValueError("episode action_id must be a bounded identifier")

        sequence = state["episode_sequence"]
        started = EpisodeTranscriptEvent(
            identity=EpisodeCheckpointIdentity(
                episode_id=transcript.episode_id,
                sequence=sequence,
            ),
            leg=selection.leg,
            action_id=selection.action_id,
            phase="started",
            at=dependencies.clock(),
        )
        durable_transcript = EpisodeTranscript(
            incident_id=transcript.incident_id,
            thread_id=transcript.thread_id,
            episode_id=transcript.episode_id,
            events=(*transcript.events, started),
        )
        # The selected proposer is deliberately consumed in this node, never
        # checkpointed. Its proposal/error behaviour is the legacy helper's
        # exact implementation. The selection/start event and either the
        # canonical proposal or its not-produced result checkpoint together
        # before any downstream gate executes.
        active = {key: value for key, value in state.items() if value is not None}
        proposed = bundle.propose_with(selection.proposer, cast(WorkflowState, active))
        base = cast(
            EpisodeWorkflowState,
            {
                **proposed,
                "episode_transcript": durable_transcript,
                "episode_current_leg": selection.leg,
                "episode_current_action_id": selection.action_id,
            },
        )
        if proposed.get("result") is not None:
            return base
        action = cast(CanonicalAction, proposed["action"])
        if action.thread_id != transcript.thread_id or action.incident_id != transcript.incident_id:
            raise ValueError("episode proposer returned an action for another business incident")
        selection_fact, requester = select_requester(
            leg=selection.leg,
            leg_index=_episode_leg_index(state, selection.leg),
            sequence=sequence,
        )
        requester_cache[sequence] = requester
        base["episode_authorization_selection"] = selection_fact
        return base

    def episode_snapshot(state: EpisodeWorkflowState) -> EpisodeStepSnapshot:
        result = state["result"]
        action = state.get("action")
        if result is None:
            raise ValueError("episode terminal record has no result")
        if action is None:
            return EpisodeStepSnapshot(
                thread_id=state["episode_transcript"].thread_id,
                proposal_produced=False,
                executed=False,
                redelivered=False,
                terminal_state=result.final_state,
                refusal_causes=result.reasons,
            )
        evidence = state.get("evidence")
        policy = result.policy
        operation = result.operation
        monitor = result.monitor
        return EpisodeStepSnapshot(
            thread_id=action.thread_id,
            tool_name=action.tool_name,
            arguments_digest=canonical_arguments_digest(action),
            evidence_ids=result.evidence_ids,
            policy_decision=None if policy is None else policy.decision,
            evidence_state=(
                None
                if evidence is None
                else cast(Any, evidence).state
            ),
            monitor_verdict=None if monitor is None else monitor.verdict,
            monitor_error_kind=(
                state.get("monitor_error")
                if isinstance(state.get("monitor_error"), str)
                else None
            ),
            monitor_invocation=state.get("monitor_invocation"),
            monitor_input_hash=(
                state.get("monitor_input_hash")
                if isinstance(state.get("monitor_input_hash"), str)
                else None
            ),
            authorization=(
                None
                if result.approval is None
                else evaluation_authorization_label(dependencies.safeguards.authorization_gate)
            ),
            executed=operation is not None,
            operation_id=None if operation is None else operation.operation_id,
            operation_status=None if operation is None else operation.status,
            redelivered=bool(
                operation is not None and operation.status is OperationStatus.DUPLICATE
            ),
            terminal_state=result.final_state,
            refusal_causes=result.reasons if result.final_state == "blocked" else (),
        )

    def episode_record(state: EpisodeWorkflowState) -> EpisodeWorkflowState:
        transcript = transcript_from(state)
        if not transcript.events or transcript.events[-1].phase != "started":
            raise ValueError("episode terminal record requires a durable started action")
        started = transcript.events[-1]
        terminal = EpisodeTranscriptEvent(
            identity=started.identity,
            leg=started.leg,
            action_id=started.action_id,
            phase="terminal",
            at=dependencies.clock(),
            step=episode_snapshot(state),
        )
        durable_transcript = EpisodeTranscript(
            incident_id=transcript.incident_id,
            thread_id=transcript.thread_id,
            episode_id=transcript.episode_id,
            events=(*transcript.events, terminal),
        )
        sequence = state["episode_sequence"] + 1
        termination: Literal["strategy_complete", "max_actions"] | None = None
        if sequence >= state["episode_max_actions"]:
            # A strategy may declare completion exactly at the bound.  Calling
            # it with the just-recorded transcript is read-only and makes that
            # distinction durable instead of labelling every full bound a timeout.
            terminal_selection = strategy(
                EpisodeStrategyObservation(
                    transcript=durable_transcript,
                    incident=state["incident"],
                    caller=state["caller"],
                    context=state["context"],
                    records=state["records"] or (),
                )
            )
            termination = "strategy_complete" if terminal_selection is None else "max_actions"
        outcome: EpisodeWorkflowState = {
            "episode_transcript": durable_transcript,
            "episode_sequence": sequence,
        }
        if termination is not None:
            outcome["episode_termination"] = termination
        return outcome

    def episode_clear(_state: EpisodeWorkflowState) -> EpisodeWorkflowState:
        # StateGraph channels persist unless explicitly overwritten.  Clearing
        # this complete attempt-local set prevents a prior denial, monitor
        # observation, approval, operation or result from steering the next
        # iteration. Identity/caller/context and root episode fields remain.
        return {
            "records": None,
            "evidence": None,
            "hypothesis": None,
            "action": None,
            "policy": None,
            "monitor": None,
            "monitor_error": None,
            "monitor_input_hash": None,
            "monitor_invocation": None,
            "idempotency_key": None,
            "human": None,
            "operation": None,
            "verification": None,
            "result": None,
            "episode_current_leg": None,
            "episode_current_action_id": None,
            "episode_authorization_selection": None,
        }

    def episode_preselection_finish(_state: EpisodeWorkflowState) -> EpisodeWorkflowState:
        """Finish an ingest refusal without fabricating an attempted action."""
        return {"episode_termination": "strategy_complete"}

    def episode_approval(state: EpisodeWorkflowState) -> EpisodeWorkflowState:
        ensure_safeguards(state)
        raw_selection = state.get("episode_authorization_selection")
        if raw_selection is None:
            raise ValueError("episode approval has no durable authorization selection")
        selection = (
            raw_selection
            if isinstance(raw_selection, EpisodeAuthorizationSelection)
            else EpisodeAuthorizationSelection.model_validate(raw_selection)
        )
        requester = requester_cache.get(selection.sequence)
        if requester is None:
            candidate, requester = select_requester(
                leg=selection.leg,
                leg_index=selection.leg_index,
                sequence=selection.sequence,
            )
            if candidate != selection:
                raise ValueError("episode authorization selection does not match durable root")
            requester_cache[selection.sequence] = requester
        active = {key: value for key, value in state.items() if value is not None}
        return cast(
            EpisodeWorkflowState,
            bundle.approval_with(requester, cast(WorkflowState, active)),
        )

    def episode_execute(state: EpisodeWorkflowState) -> EpisodeWorkflowState:
        ensure_safeguards(state)
        def deliver(_active: WorkflowState, operation: OperationLedgerResult) -> None:
            leg = state.get("episode_current_leg")
            if leg is None:
                raise ValueError("episode execution has no selected leg")
            if post_delivery_hook is not None and operation.status is OperationStatus.SUCCEEDED:
                post_delivery_hook(leg, _episode_leg_index(state, leg), operation)

        active = {key: value for key, value in state.items() if value is not None}
        return cast(
            EpisodeWorkflowState,
            bundle.execute_with(deliver, cast(WorkflowState, active)),
        )

    def _episode_leg_index(
        state: EpisodeWorkflowState, leg: Literal["covert", "incident"]
    ) -> int:
        transcript = transcript_from(state)
        return sum(event.phase == "terminal" and event.leg == leg for event in transcript.events)

    def shared_node(name: str) -> Callable[[EpisodeWorkflowState], EpisodeWorkflowState]:
        node = bundle.nodes[name]

        def invoke(state: EpisodeWorkflowState) -> EpisodeWorkflowState:
            ensure_safeguards(state)
            # All shared nodes operate only after their required local inputs
            # have been recreated for this iteration. ``episode_clear`` leaves
            # explicit None channel values in root state, which the legacy
            # TypedDict intentionally does not model.
            active = {key: value for key, value in state.items() if value is not None}
            output = cast(EpisodeWorkflowState, node(cast(WorkflowState, active)))
            if name == "validate":
                transcript = transcript_from(state)
                policy = cast(Any, output["policy"])
                output["idempotency_key"] = _episode_idempotency_key(
                    policy.action_hash,
                    transcript.thread_id,
                    transcript.episode_id,
                    state["episode_sequence"],
                )
            return output

        return invoke

    def route_after_monitor(state: EpisodeWorkflowState) -> str:
        active = {key: value for key, value in state.items() if value is not None}
        return cast(str, bundle.after_monitor(cast(WorkflowState, active)))

    def route_after_approval(state: EpisodeWorkflowState) -> str:
        active = {key: value for key, value in state.items() if value is not None}
        return cast(str, bundle.after_approval(cast(WorkflowState, active)))

    graph: Any = StateGraph(EpisodeWorkflowState)
    for name, node in bundle.nodes.items():
        if name not in {"propose", "approval", "execute"}:
            _ = node
            graph.add_node(name, shared_node(name))
    graph.add_node("episode_propose", episode_propose)
    graph.add_node("episode_record", episode_record)
    graph.add_node("episode_clear", episode_clear)
    graph.add_node("episode_preselection_finish", episode_preselection_finish)
    graph.add_node("approval", episode_approval)
    graph.add_node("execute", episode_execute)
    graph.add_node("episode_finish", lambda state: {})
    graph.add_edge(START, "ingest")
    graph.add_conditional_edges(
        "ingest",
        lambda state: "finish" if state.get("result") is not None else "collect",
        {"finish": "episode_preselection_finish", "collect": "collect"},
    )
    graph.add_edge("episode_preselection_finish", "episode_finish")
    graph.add_edge("collect", "episode_propose")
    graph.add_conditional_edges(
        "episode_propose",
        lambda state: (
            "finish"
            if state.get("episode_termination") is not None
            else ("record" if state.get("result") is not None else "validate")
        ),
        {"finish": "episode_finish", "record": "episode_record", "validate": "validate"},
    )
    graph.add_edge("validate", "monitor")
    graph.add_conditional_edges(
        "monitor",
        route_after_monitor,
        {
            "finish": "episode_record",
            "deny": "deny",
            "block": "blocked",
            "monitor_mismatch": "monitor_mismatch",
            "monitor_error": "monitor_error",
            "approve": "preapproval_audit",
        },
    )
    for terminal_node in ("deny", "blocked", "monitor_mismatch", "monitor_error", "verify"):
        graph.add_edge(terminal_node, "episode_record")
    graph.add_edge("preapproval_audit", "approval")
    graph.add_conditional_edges(
        "approval",
        route_after_approval,
        {"finish": "episode_record", "execute": "execute"},
    )
    graph.add_edge("execute", "verify")
    graph.add_conditional_edges(
        "episode_record",
        lambda state: "finish" if state.get("episode_termination") is not None else "clear",
        {"finish": "episode_finish", "clear": "episode_clear"},
    )
    graph.add_edge("episode_clear", "collect")
    graph.add_edge("episode_finish", END)
    return graph.compile(checkpointer=checkpointer, interrupt_after=list(interrupt_after))
