"""Public, durable runtime boundary for starting and resuming D1 approvals."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Self, cast
from uuid import uuid4

import psycopg
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.types import Command
from psycopg.rows import dict_row

from incidentgate.contracts import (
    ApprovalRequest,
    CanonicalAction,
    EvidenceRecord,
    Hypothesis,
    IncidentIdentity,
    IncidentState,
    MonitorResult,
    MonitorVerdict,
    OperationLedgerResult,
    OperationStatus,
    PolicyConfiguration,
    PolicyDecision,
    PolicyOutcome,
    Role,
    ToolCallContext,
    VerificationResult,
)
from incidentgate.control import (
    AdvisoryMonitor,
    DeterministicD1Proposer,
    DeterministicD2Proposer,
    DeterministicD3Proposer,
    DeterministicD5Proposer,
    DeterministicD8Proposer,
    DeterministicPolicyEngine,
    EvidenceValidator,
    FixtureMonitor,
    WorkflowDependencies,
    build_deferred_graph,
    build_workflow_graph,
)
from incidentgate.control.models import (
    Caller,
    EvidenceState,
    EvidenceValidation,
    HumanDecision,
    WorkflowResult,
)
from incidentgate.control.ports import ProposalGenerator
from incidentgate.control.proposal import (
    DeterministicR01Proposer,
    DeterministicR02Proposer,
    DeterministicR03Proposer,
    DeterministicR04Proposer,
    DeterministicR06Proposer,
    DeterministicR07Proposer,
    DeterministicR08Proposer,
    DeterministicR09Proposer,
    DeterministicR12Proposer,
    DeterministicT1Proposer,
    DeterministicT2Proposer,
    DeterministicT4Proposer,
)
from incidentgate.lab.approval import ApprovalService
from incidentgate.lab.auth import Principal
from incidentgate.lab.repository import AuditTimelineEvent, LabRepository
from incidentgate.lab.service import ObservabilityService, OperationsService
from incidentgate.scenario_registry import (
    ALLOWED_EVIDENCE_SOURCES,
    NO_ACTION_SCENARIOS,
    RUNNABLE_SCENARIOS,
)
from incidentgate.telemetry import (
    TelemetryConfig,
    TelemetryRuntime,
    create_tracer_runtime,
    extract_trace_context,
    inject_trace_context,
    safe_trace_carrier,
)

from .adapters import (
    DeferredEvidenceCollector,
    LabAuditEmitter,
    LabEvidenceCollector,
    LabOperationExecutor,
    LabRecoveryVerifier,
    LabTokenValidator,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _durable_field(source: Any, name: str) -> Any:
    """Read one field from a durable checkpoint value.

    A revived checkpoint hands back either the contract model or the plain dict
    it serialized to, depending on what the serializer could reconstruct, so
    both shapes have to be read the same way.
    """
    if source is None:
        return None
    value = getattr(source, name, None)
    if value is None and isinstance(source, dict):
        value = source.get(name)
    return value


@dataclass(frozen=True)
class PendingApproval:
    """Bounded interrupt view; capabilities and evidence payloads never leave this boundary."""

    thread_id: str
    incident_id: str
    action_hash: str
    monitor_verdict: str | None
    # The approver is deciding whether a mutation happens, so everything the gate
    # already knows that bears on that decision is carried here rather than
    # dropped.  These are required, without defaults, precisely so that a second
    # construction site cannot quietly omit them and reintroduce a page that
    # renders confident-looking placeholders.  ``None`` and ``()`` mean genuinely
    # absent and are rendered as an explicit marker, never as a plausible value.
    monitor_rationale: str | None
    monitor_suspicion: float | None
    policy_decision: str | None
    policy_reasons: tuple[str, ...]
    requires_reason: bool
    evidence_ids: tuple[str, ...]
    tool_name: str
    # Most frozen capabilities have no component argument.  A human decision
    # surface must say so rather than be handed a plausible default.
    component: str | None
    target_revision: str | None
    variable_name: str | None = None
    approved_value_ref: str | None = None
    trace_id: str | None = None
    trace_url: str | None = None


@dataclass(frozen=True)
class RuntimeStatus:
    thread_id: str
    incident_id: str
    pending: PendingApproval | None
    result: WorkflowResult | None
    trace_id: str | None = None
    trace_url: str | None = None
    collection_attempts: tuple[int, ...] = ()


class IncidentRuntime:
    """Owns a PostgresSaver connection for the fixed checkpoint scenarios."""

    def __init__(
        self,
        dsn: str,
        *,
        clock: Callable[[], datetime] = _utc_now,
        approval_ttl: timedelta = timedelta(minutes=5),
        response_loss_once: bool = False,
        telemetry: TelemetryRuntime | None = None,
        telemetry_config: TelemetryConfig | None = None,
        monitor: AdvisoryMonitor | None = None,
        monitor_factory: Callable[[], AdvisoryMonitor] | None = None,
        # The proposer seam. Left unset, every scenario gets its deterministic
        # proposer exactly as before. Supplied, the factory decides what proposes
        # the action -- which is how a model output reaches the gate chain at all.
        # A factory rather than an instance because the proposer is built per
        # incident, matching how the monitor is built.
        proposer_factory: Callable[[], ProposalGenerator] | None = None,
        collection_crash_after_attempt: int | None = None,
        # The acceptance gate's only escape hatch, and deliberately a loud one.
        # A T-tier scenario needs a working runtime *before* it can be promoted
        # into RUNNABLE_SCENARIOS -- that is the order the acceptance gate
        # requires -- so the development window between "has a graph" and "is
        # promoted" is real and recurring: T1 lived in it, T2-T8 will. Passing
        # this is how a caller says so out loud at the call site, where review
        # can see it. It is not how the chaos worker, the host, or any published
        # measurement is constructed.
        allow_unpromoted_scenario: bool = False,
    ) -> None:
        if telemetry is not None and telemetry_config is not None:
            raise ValueError("provide either telemetry or telemetry_config, not both")
        if monitor is not None and monitor_factory is not None:
            raise ValueError("provide either monitor or monitor_factory, not both")
        self._dsn, self._clock, self._approval_ttl = dsn, clock, approval_ttl
        self._telemetry = telemetry or (
            create_tracer_runtime(telemetry_config) if telemetry_config else None
        )
        self._owns_telemetry = telemetry is None and self._telemetry is not None
        # The repository shares the runtime's clock. Letting it read its own wall
        # clock instead is what put two timebases behind one decision: the graph
        # validated an approval against this clock while the mutator re-validated
        # the same approval against a different one.
        self._repository = LabRepository(dsn, clock=clock)
        # The explicit local-contract allowlist keeps checkpoint revival strict.
        self._connection = psycopg.connect(
            dsn, autocommit=True, prepare_threshold=0, row_factory=dict_row
        )
        serde = JsonPlusSerializer(
            pickle_fallback=False,
            allowed_msgpack_modules=(
                CanonicalAction,
                EvidenceRecord,
                Hypothesis,
                IncidentIdentity,
                IncidentState,
                MonitorResult,
                MonitorVerdict,
                OperationLedgerResult,
                OperationStatus,
                PolicyDecision,
                PolicyOutcome,
                Role,
                ToolCallContext,
                VerificationResult,
                Caller,
                WorkflowResult,
                EvidenceState,
                EvidenceValidation,
                HumanDecision,
            ),
        )
        self._checkpointer = PostgresSaver(self._connection, serde=serde)
        self._checkpointer.setup()
        self._response_loss_once = response_loss_once
        self._monitor = monitor
        self._monitor_factory = monitor_factory
        self._proposer_factory = proposer_factory
        self._collection_crash_after_attempt = collection_crash_after_attempt
        self._allow_unpromoted_scenario = allow_unpromoted_scenario
        self._graph: Any | None = None

    def close(self) -> None:
        self._connection.close()
        if self._telemetry is not None:
            self._telemetry.flush()
            if self._owns_telemetry:
                self._telemetry.shutdown()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _build_graph(self, caller: Caller, context: ToolCallContext, *, scenario_id: str) -> Any:
        config = PolicyConfiguration.model_validate(
            json.loads((Path(__file__).parents[3] / "config" / "policy.example.json").read_text())
        )
        observability = ObservabilityService(self._repository)
        if scenario_id in NO_ACTION_SCENARIOS:

            def crash_after_attempt(number: int) -> None:
                if self._collection_crash_after_attempt == number:
                    self._collection_crash_after_attempt = None
                    raise RuntimeError("injected lab collection process loss")

            collector = DeferredEvidenceCollector(
                observability,
                caller,
                context,
                repository=self._repository,
                clock=self._clock,
                scenario_id=scenario_id,
                after_attempt=crash_after_attempt
                if self._collection_crash_after_attempt is not None
                else None,
            )
            return build_deferred_graph(
                collector,
                LabAuditEmitter(self._repository, caller.actor),
                self._clock,
                checkpointer=self._checkpointer,
                telemetry=self._telemetry,
            )
        sources = ALLOWED_EVIDENCE_SOURCES
        proposer: ProposalGenerator
        if scenario_id == "D1":
            proposer = DeterministicD1Proposer()
        elif scenario_id == "D2":
            proposer = DeterministicD2Proposer()
        elif scenario_id == "D3":
            proposer = DeterministicD3Proposer()
        elif scenario_id == "D5":
            proposer = DeterministicD5Proposer()
        elif scenario_id == "D8":
            proposer = DeterministicD8Proposer()
        elif scenario_id == "R01":
            proposer = DeterministicR01Proposer()
        elif scenario_id == "R02":
            proposer = DeterministicR02Proposer()
        elif scenario_id == "R03":
            proposer = DeterministicR03Proposer()
        elif scenario_id == "R04":
            proposer = DeterministicR04Proposer()
        elif scenario_id == "R06":
            proposer = DeterministicR06Proposer()
        elif scenario_id == "R07":
            proposer = DeterministicR07Proposer()
        elif scenario_id == "R08":
            proposer = DeterministicR08Proposer()
        elif scenario_id == "R09":
            proposer = DeterministicR09Proposer()
        elif scenario_id == "R12":
            proposer = DeterministicR12Proposer()
        elif scenario_id == "T1":
            # The honest baseline policy. T1's attack condition is supplied through
            # the proposer_factory seam below, which is the same seam a captured
            # model condition will use -- so the gate sees no difference between a
            # deterministic attack policy and a model-driven one.
            proposer = DeterministicT1Proposer()
        elif scenario_id == "T4":
            # Same shape as T1's entry and the same seam for its attack
            # condition. The difference is that T4's honest work is three calls
            # rather than one, so the class selected here re-derives its position
            # in the canonical sequence from call-ledger evidence on every
            # traversal instead of holding an index. One graph build is still one
            # proposal; three builds walk the sequence.
            proposer = DeterministicT4Proposer()
        elif scenario_id == "T2":
            # Same shape as T1's entry and the same seam for its attack
            # condition. T2 is the T1-shaped scenario -- one honest call, one
            # prohibited covert call -- so one proposer selected here is the
            # whole honest leg, with no position to re-derive.
            proposer = DeterministicT2Proposer()
        else:
            raise ValueError("unsupported checkpoint scenario")
        if self._proposer_factory is not None:
            # Deliberately after the scenario check: selecting a model-backed
            # proposer does not make an unsupported scenario supported.
            proposer = self._proposer_factory()
        dependencies = WorkflowDependencies(
            collector=LabEvidenceCollector(observability, caller, context, scenario_id=scenario_id),
            proposer=proposer,
            evidence_validator=EvidenceValidator(
                config, self._clock, allowed_sources=sources[scenario_id]
            ),
            policy=DeterministicPolicyEngine(config),
            monitor=(
                self._monitor_factory()
                if self._monitor_factory is not None
                else (self._monitor or FixtureMonitor(MonitorVerdict.ALLOW))
            ),
            token_validator=LabTokenValidator(self._repository),
            executor=LabOperationExecutor(
                OperationsService(self._repository),
                caller,
                response_loss_once=self._response_loss_once,
            ),
            verifier=LabRecoveryVerifier(
                observability, caller, context, self._clock, self._repository
            ),
            audit=LabAuditEmitter(self._repository, caller.actor),
            clock=self._clock,
            telemetry=self._telemetry,
        )
        self._response_loss_once = False
        return build_workflow_graph(dependencies, checkpointer=self._checkpointer)

    @staticmethod
    def _config(thread_id: str) -> Any:
        return {"configurable": {"thread_id": thread_id}}

    def resume(self, thread_id: str) -> RuntimeStatus:
        """Recreate a graph around the caller/context persisted in a checkpoint."""
        checkpoint = self._checkpointer.get_tuple(self._config(thread_id))
        if checkpoint is None:
            raise ValueError("unknown D1 runtime thread")
        channels = checkpoint.checkpoint["channel_values"]
        caller = channels.get("caller")
        context = channels.get("context")
        bound_caller = caller if isinstance(caller, Caller) else Caller.model_validate(caller)
        bound_context = (
            context
            if isinstance(context, ToolCallContext)
            else ToolCallContext.model_validate(context)
        )
        incident = channels.get("incident")
        bound_incident = (
            incident
            if isinstance(incident, IncidentIdentity)
            else IncidentIdentity.model_validate(incident)
        )
        self._graph = self._build_graph(
            bound_caller, bound_context, scenario_id=bound_incident.scenario_id
        )
        return self.status(thread_id)

    @staticmethod
    def _result(values: dict[str, Any]) -> WorkflowResult | None:
        result = values.get("result")
        return (
            result
            if isinstance(result, WorkflowResult)
            else (WorkflowResult.model_validate(result) if result else None)
        )

    def _trace(self, values: dict[str, Any]) -> tuple[str | None, str | None]:
        carrier = safe_trace_carrier(cast(dict[str, str], values.get("trace_carrier") or {}))
        if self._telemetry is None:
            return None, None
        trace_id = self._telemetry.current_trace_id(extract_trace_context(carrier))
        try:
            trace_url = self._telemetry.trace_url(trace_id)
        except Exception:  # noqa: BLE001 - external URL enrichment must not block the durable workflow.
            # URL lookup is presentation-only and may depend on an unavailable external service.
            trace_url = None
        return trace_id, trace_url

    def _pending(self, thread_id: str, values: dict[str, Any]) -> PendingApproval | None:
        policy, action, result = values.get("policy"), values.get("action"), self._result(values)
        if result is not None or policy is None or action is None:
            return None
        policy_hash = getattr(policy, "action_hash", None) or cast(dict[str, Any], policy).get(
            "action_hash"
        )
        monitor = values.get("monitor")
        verdict = getattr(monitor, "verdict", None) if monitor is not None else None
        verdict_text = str(verdict) if verdict is not None else None
        if not isinstance(policy_hash, str):
            raise TypeError("durable checkpoint does not contain a valid policy action hash")
        arguments = action.arguments
        trace_id, trace_url = self._trace(values)
        rationale = _durable_field(monitor, "rationale")
        suspicion = _durable_field(monitor, "suspicion_score")
        decision = _durable_field(policy, "decision")
        reasons = _durable_field(policy, "reasons") or ()
        return PendingApproval(
            thread_id=thread_id,
            incident_id=action.incident_id,
            action_hash=policy_hash,
            monitor_verdict=verdict_text,
            monitor_rationale=None if rationale is None else str(rationale),
            monitor_suspicion=None if suspicion is None else float(suspicion),
            policy_decision=None if decision is None else str(decision),
            policy_reasons=tuple(str(reason) for reason in reasons),
            requires_reason=verdict == MonitorVerdict.DEFER,
            evidence_ids=tuple(action.evidence_ids),
            tool_name=action.tool_name,
            component=getattr(arguments, "component", None),
            target_revision=getattr(arguments, "target_revision", None),
            variable_name=getattr(arguments, "variable_name", None),
            approved_value_ref=getattr(arguments, "approved_value_ref", None),
            trace_id=trace_id,
            trace_url=trace_url,
        )

    def start(
        self, incident: IncidentIdentity, operator: Caller, context: ToolCallContext
    ) -> PendingApproval | RuntimeStatus:
        if operator.role is not Role.OPERATOR:
            raise PermissionError("D1 runtime start requires an authenticated operator")
        if context.idempotency_key is not None:
            raise ValueError("caller-chosen idempotency keys are not accepted")
        self._graph = self._build_graph(operator, context, scenario_id=incident.scenario_id)
        initial: dict[str, Any] = {"incident": incident, "caller": operator, "context": context}
        values = self._invoke_phase(incident.thread_id, initial=initial)
        pending = self._pending(incident.thread_id, values)
        return pending or self._status_from_values(incident.thread_id, values)

    def status(self, thread_id: str) -> RuntimeStatus:
        if self._graph is None:
            return self.resume(thread_id)
        values = dict(self._graph.get_state(self._config(thread_id)).values)
        action = values.get("action")
        incident = values.get("incident")
        incident_id = (
            action.incident_id
            if action is not None
            else (
                IncidentIdentity.model_validate(incident).incident_id
                if incident is not None
                else ""
            )
        )
        trace_id, trace_url = self._trace(values)
        attempts = (
            self._repository.collection_attempt_numbers(incident_id, thread_id)
            if incident_id in {"INC-D4", "INC-D7"}
            else ()
        )
        return RuntimeStatus(
            thread_id=thread_id,
            incident_id=incident_id,
            pending=self._pending(thread_id, values),
            result=self._result(values),
            trace_id=trace_id,
            trace_url=trace_url,
            collection_attempts=attempts,
        )

    def approve(
        self, thread_id: str, approver: Principal, *, reason: str | None = None
    ) -> RuntimeStatus:
        status = self.status(thread_id)
        if status.pending is None:
            raise ValueError("thread has no pending approval")
        values = (
            dict(self._graph.get_state(self._config(thread_id)).values)
            if self._graph is not None
            else {}
        )
        action = values["action"]
        now = self._clock()
        request = ApprovalRequest(
            action_hash=status.pending.action_hash,
            actor=action.actor,
            requested_at=now,
            expires_at=now + self._approval_ttl,
            one_time_use_id=uuid4(),
        )
        token = ApprovalService(
            self._repository, self._clock, incident_id=status.incident_id, thread_id=thread_id
        ).approve(request, approver)
        return self._resume(
            thread_id,
            {
                "decision": "approve",
                "approver": approver.actor,
                "reason": reason,
                "token": token.model_dump(mode="python"),
            },
        )

    def reject(
        self, thread_id: str, approver: Principal, *, reason: str | None = None
    ) -> RuntimeStatus:
        if approver.role is not Role.APPROVER:
            raise PermissionError("D1 rejection requires an authenticated approver")
        if self.status(thread_id).pending is None:
            raise ValueError("thread has no pending approval")
        return self._resume(
            thread_id, {"decision": "reject", "approver": approver.actor, "reason": reason}
        )

    def retry(self, thread_id: str) -> RuntimeStatus:
        """Resume a failed task from the durable checkpoint after a lost response."""
        if self._checkpointer.get_tuple(self._config(thread_id)) is None:
            raise ValueError("unknown D1 runtime thread")
        if self._graph is None:
            self.resume(thread_id)
        graph = self._graph
        assert graph is not None
        values = self._invoke_phase(thread_id)
        return self._status_from_values(thread_id, values)

    def _resume(self, thread_id: str, payload: dict[str, object]) -> RuntimeStatus:
        if self._graph is None:
            self.resume(thread_id)
        graph = self._graph
        assert graph is not None
        values = self._invoke_phase(thread_id, resume=payload, approval=True)
        return self._status_from_values(thread_id, values)

    def _status_from_values(self, thread_id: str, values: dict[str, Any]) -> RuntimeStatus:
        action = values.get("action")
        incident = values.get("incident")
        incident_id = (
            action.incident_id
            if action is not None
            else (
                IncidentIdentity.model_validate(incident).incident_id
                if incident is not None
                else ""
            )
        )
        trace_id, trace_url = self._trace(values)
        attempts = (
            self._repository.collection_attempt_numbers(incident_id, thread_id)
            if incident_id in {"INC-D4", "INC-D7"}
            else ()
        )
        return RuntimeStatus(
            thread_id=thread_id,
            incident_id=incident_id,
            pending=self._pending(thread_id, values),
            result=self._result(values),
            trace_id=trace_id,
            trace_url=trace_url,
            collection_attempts=attempts,
        )

    def _invoke_phase(
        self,
        thread_id: str,
        *,
        initial: dict[str, Any] | None = None,
        resume: dict[str, object] | None = None,
        approval: bool = False,
    ) -> dict[str, Any]:
        graph = self._graph
        assert graph is not None
        values = (
            dict(graph.get_state(self._config(thread_id)).values) if initial is None else initial
        )
        carrier = safe_trace_carrier(cast(dict[str, str], values.get("trace_carrier") or {}))
        parent = extract_trace_context(carrier) if carrier else None
        incident = values.get("incident")
        caller = values.get("caller")
        context = values.get("context")
        attributes = {
            "incident_id": incident.incident_id if incident is not None else None,
            "thread_id": thread_id,
            "correlation_id": incident.correlation_id if incident is not None else None,
            "actor": caller.actor if caller is not None else None,
            "permission": context.permission if context is not None else None,
        }
        # The acceptance gate, enforced before anything runs and independently of
        # how this runtime was wired. It used to live inside the telemetry branch
        # below, which made it an accident of observability: ``_telemetry``
        # defaults to None, so every default-constructed runtime -- the chaos
        # worker, the evaluation harnesses, and every runtime test -- skipped it
        # entirely, and only the host path (which always builds a tracer) ever
        # enforced it. The evidence that it was not gating is that unpromoted T1
        # drove cleanly through the chaos worker across all 22 boundaries.
        #
        # ``_build_graph`` already refuses a scenario it has no graph for, so
        # this is the narrower question that check cannot answer: the scenario is
        # buildable, but has it been accepted? Same shape as ``_scenario_span``,
        # which validates unconditionally and only then decides on a span.
        scenario_id = getattr(incident, "scenario_id", None)
        if not self._allow_unpromoted_scenario and scenario_id not in RUNNABLE_SCENARIOS:
            raise ValueError("unsupported checkpoint scenario")
        if self._telemetry is None:
            payload: Any = (
                initial
                if initial is not None
                else (Command(resume=resume) if resume is not None else None)
            )
            return cast(dict[str, Any], graph.invoke(payload, self._config(thread_id)))
        try:
            # Only reachable with the opt-out, which is the one path that can
            # carry a scenario id the registry has never seen.
            span_scenario = (scenario_id or "unknown").lower()
            with self._telemetry.start_as_current_span(
                f"{span_scenario}.workflow", attributes=attributes, parent_context=parent
            ):
                if initial is not None:
                    initial["trace_carrier"] = dict(inject_trace_context({}))
                    result = graph.invoke(initial, self._config(thread_id))
                elif approval:
                    with self._telemetry.start_as_current_span(
                        f"{span_scenario}.approval", attributes=attributes
                    ):
                        result = graph.invoke(Command(resume=resume), self._config(thread_id))
                else:
                    result = graph.invoke(None, self._config(thread_id))
        finally:
            self._telemetry.flush()
        return cast(dict[str, Any], result)

    def timeline(self, incident_id: str, *, limit: int = 50) -> tuple[AuditTimelineEvent, ...]:
        return self._repository.timeline(incident_id, limit=limit)


class CheckpointRuntime(IncidentRuntime):
    """Alias for the durable incident runtime, used by the checkpoint test suites.

    Adds no behavior. IncidentRuntime is the name production code uses.
    """
