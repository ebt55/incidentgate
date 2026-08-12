"""Replay-safe-before-approval D1 LangGraph workflow.

The builder accepts any LangGraph checkpointer. Unit tests use ``MemorySaver``; this
module does not claim Postgres durability or crash-safe external exactly-once effects.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from datetime import datetime
from typing import Any, TypedDict
from uuid import NAMESPACE_URL, UUID, uuid5

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from incidentgate.contracts import (
    CanonicalAction,
    Hypothesis,
    IncidentIdentity,
    IncidentReport,
    IncidentState,
    MonitorVerdict,
    PolicyDecision,
    ToolCallContext,
)
from incidentgate.scenario_registry import NO_ACTION_CATALOG, validate_no_action_evidence
from incidentgate.telemetry import TelemetryRuntime

from .evidence import EvidenceValidator
from .models import Caller, EvidenceValidation, HumanDecision, WorkflowResult, audit_event
from .monitor import AdvisoryMonitor
from .policy import DeterministicPolicyEngine
from .ports import (
    ApprovalTokenValidator,
    AuditEmitter,
    EvidenceCollector,
    OperationExecutor,
    ProposalGenerator,
    RecoveryVerifier,
)
from .proposal import ProposalError


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
    idempotency_key: UUID
    human: HumanDecision
    operation: Any
    verification: Any
    result: WorkflowResult
    trace_carrier: dict[str, str]


class WorkflowDependencies:
    def __init__(
        self,
        *,
        collector: EvidenceCollector,
        proposer: ProposalGenerator,
        evidence_validator: EvidenceValidator,
        policy: DeterministicPolicyEngine,
        monitor: AdvisoryMonitor,
        token_validator: ApprovalTokenValidator,
        executor: OperationExecutor,
        verifier: RecoveryVerifier,
        audit: AuditEmitter,
        clock: Callable[[], datetime],
        telemetry: TelemetryRuntime | None = None,
    ) -> None:
        self.collector = collector
        self.proposer = proposer
        self.evidence_validator = evidence_validator
        self.policy = policy
        self.monitor = monitor
        self.token_validator = token_validator
        self.executor = executor
        self.verifier = verifier
        self.audit = audit
        self.clock = clock
        self.telemetry = telemetry


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
                    final_state="blocked", reasons=("collection_context_mismatch",)
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
                getattr(collector, "deferred_reason", "no_action_evidence_validation_failed")
            )
            final_state = str(getattr(collector, "final_state", "blocked"))
            if final_state != "blocked" and reason == "time_budget_exhausted":
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
                    reasons=("no_action_evidence_validation_failed",),
                    evidence_ids=tuple(record.evidence_id for record in records),
                ),
            }
        metadata = NO_ACTION_CATALOG[incident.scenario_id]
        diagnosis = str(getattr(collector, "diagnosis", metadata["diagnosis"]))
        reason = str(getattr(collector, "deferred_reason", metadata["reason"]))
        final_state = str(getattr(collector, "final_state", metadata["state"]))
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


def build_workflow_graph(dependencies: WorkflowDependencies, *, checkpointer: Any = None) -> Any:
    """Compile the approval-gated workflow graph shared by every action-taking scenario.

    Invoke/resume with one caller-owned configurable ``thread_id``.
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
        """Map only the three supported fixed identities to telemetry names."""
        incident = state.get("incident")
        scenario_id = getattr(incident, "scenario_id", None)
        if scenario_id not in {
            "D1",
            "D2",
            "D3",
            "D5",
            "D8",
            "R01",
            "R02",
            "R03",
            "R04",
            "R06",
            "R07",
            "R08",
            "R09",
            "R12",
        }:
            raise ValueError("unsupported checkpoint scenario")
        return f"{scenario_id.lower()}.{phase}"

    def ingest(state: WorkflowState) -> WorkflowState:
        incident, context, caller = state["incident"], state["context"], state["caller"]
        if incident.thread_id != context.thread_id:
            return {
                "result": WorkflowResult(
                    final_state="blocked", reasons=("thread_context_mismatch",)
                )
            }
        if incident.incident_id != context.incident_id:
            return {
                "result": WorkflowResult(
                    final_state="blocked", reasons=("incident_context_mismatch",)
                )
            }
        if caller.actor != context.actor:
            return {
                "result": WorkflowResult(final_state="blocked", reasons=("caller_actor_mismatch",))
            }
        return {}

    def collect(state: WorkflowState) -> WorkflowState:
        with _span("mcp.observability", state):
            return {"records": dependencies.collector.collect(state["incident"])}

    def propose(state: WorkflowState) -> WorkflowState:
        try:
            hypothesis, action = dependencies.proposer.propose(
                state["incident"], state["caller"], state["context"], state["records"]
            )
        except ProposalError as error:
            _audit(state, "proposal", error.reason)
            return {"result": WorkflowResult(final_state="blocked", reasons=(error.reason,))}
        return {"hypothesis": hypothesis, "action": action}

    def validate(state: WorkflowState) -> WorkflowState:
        evidence = dependencies.evidence_validator.validate(
            state["action"], state["records"], state["context"]
        )
        with _span(_scenario_span("policy", state), state):
            policy = dependencies.policy.evaluate(state["action"], state["caller"].role, evidence)
        return {
            "evidence": evidence,
            "policy": policy,
            "idempotency_key": _idempotency_key(policy.action_hash, state["incident"].thread_id),
        }

    def monitor(state: WorkflowState) -> WorkflowState:
        evidence, policy = state["evidence"], state["policy"]
        if policy.decision is PolicyDecision.DENY:
            return {}
        with _span(_scenario_span("monitor", state), state):
            return {"monitor": dependencies.monitor.assess(state["action"], evidence.digest)}

    def after_monitor(state: WorkflowState) -> str:
        if "result" in state:
            return "finish"
        if state["policy"].decision is PolicyDecision.DENY:
            return "deny"
        monitor_result = state.get("monitor")
        if monitor_result and monitor_result.evaluated_action_hash != state["policy"].action_hash:
            return "monitor_mismatch"
        return (
            "block"
            if monitor_result and monitor_result.verdict is MonitorVerdict.BLOCK
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
        _audit(state, "policy", "policy_valid")
        _audit(state, "monitor", "monitor_block")
        return {
            "result": WorkflowResult(
                final_state="blocked",
                reasons=("monitor_block",),
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
        _audit(state, "policy", "policy_valid")
        _audit(state, "monitor", "action_hash_mismatch")
        return {
            "result": WorkflowResult(
                final_state="blocked",
                reasons=("monitor_action_hash_mismatch",),
                action_hash=policy.action_hash,
                evidence_ids=state["action"].evidence_ids,
                policy=policy,
                monitor=state.get("monitor"),
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
        _audit(state, "policy", "policy_valid")
        monitor_result = state.get("monitor")
        if monitor_result:
            _audit(state, "monitor", str(monitor_result.verdict))
        return {}

    def approval(state: WorkflowState) -> WorkflowState:
        with _span(_scenario_span("approval", state), state):
            payload = interrupt(
                {
                    "action_hash": state["policy"].action_hash,
                    "monitor_verdict": state["monitor"].verdict if state.get("monitor") else None,
                    "requires_reason": bool(
                        state.get("monitor") and state["monitor"].verdict is MonitorVerdict.DEFER
                    ),
                }
            )
        human = HumanDecision.model_validate(payload)
        policy, monitor_result = state["policy"], state.get("monitor")
        if human.decision == "reject":
            _audit(state, "approval", "rejected")
            return {
                "human": human,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=("human_rejected",),
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
            _audit(state, "approval", "defer_reason_required")
            return {
                "human": human,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=("defer_reason_required",),
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
            _audit(state, "approval", "token_required")
            return {
                "human": human,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=("approval_token_required",),
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
            _audit(state, "approval", "approver_mismatch")
            return {
                "human": human,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=("approval_invalid:approver_mismatch",),
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
            _audit(state, "approval", f"invalid:{reason}")
            return {
                "human": human,
                "result": WorkflowResult(
                    final_state="blocked",
                    reasons=(f"approval_invalid:{reason}",),
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
        _audit(state, "approval", "approved")
        return {"human": human}

    def after_approval(state: WorkflowState) -> str:
        return "finish" if "result" in state else "execute"

    def execute(state: WorkflowState) -> WorkflowState:
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
        dependencies.audit.emit(
            audit_event(
                "execution",
                incident_id=action.incident_id,
                thread_id=action.thread_id,
                action_hash=policy.action_hash,
                now=dependencies.clock(),
                reason="executed",
            )
        )
        return {"operation": operation}

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
                reason="passed" if verification.passed else "failed",
            )
        )
        final_state = "resolved" if verification.passed else "blocked"
        incident_state = IncidentState.RESOLVED if verification.passed else IncidentState.BLOCKED
        return {
            "verification": verification,
            "result": WorkflowResult(
                final_state=final_state,
                reasons=("recovery_verified" if verification.passed else "recovery_failed",),
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

    graph = StateGraph(WorkflowState)
    graph.add_node("ingest", ingest)
    graph.add_node("collect", collect)
    graph.add_node("propose", propose)
    graph.add_node("validate", validate)
    graph.add_node("monitor", monitor)
    graph.add_node("deny", deny)
    graph.add_node("blocked", blocked)
    graph.add_node("monitor_mismatch", monitor_mismatch)
    graph.add_node("preapproval_audit", preapproval_audit)
    graph.add_node("approval", approval)
    graph.add_node("execute", execute)
    graph.add_node("verify", verify)
    graph.add_edge(START, "ingest")
    graph.add_conditional_edges(
        "ingest",
        lambda state: "finish" if "result" in state else "collect",
        {"finish": END, "collect": "collect"},
    )
    graph.add_edge("collect", "propose")
    graph.add_conditional_edges(
        "propose",
        lambda state: "finish" if "result" in state else "validate",
        {"finish": END, "validate": "validate"},
    )
    graph.add_edge("validate", "monitor")
    graph.add_conditional_edges(
        "monitor",
        after_monitor,
        {
            "finish": END,
            "deny": "deny",
            "block": "blocked",
            "monitor_mismatch": "monitor_mismatch",
            "approve": "preapproval_audit",
        },
    )
    graph.add_edge("deny", END)
    graph.add_edge("blocked", END)
    graph.add_edge("monitor_mismatch", END)
    graph.add_edge("preapproval_audit", "approval")
    graph.add_conditional_edges("approval", after_approval, {"finish": END, "execute": "execute"})
    graph.add_edge("execute", "verify")
    graph.add_edge("verify", END)
    return graph.compile(checkpointer=checkpointer)
