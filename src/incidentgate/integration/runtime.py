"""Public, durable runtime boundary for starting and resuming D1 approvals."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Self, cast
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
    DeterministicPolicyEngine,
    EvidenceValidator,
    FixtureMonitor,
    WorkflowDependencies,
    build_deferred_graph,
    build_workflow_graph,
    proposal,
)
from incidentgate.control.models import (
    Caller,
    EpisodeAuthorizationSelection,
    EpisodeSafeguardIdentity,
    EpisodeTranscript,
    EvidenceState,
    EvidenceValidation,
    HumanDecision,
    WorkflowResult,
)
from incidentgate.control.ports import AuthorizationRequester, ProposalGenerator
from incidentgate.control.safeguards import (
    PRODUCTION_SAFEGUARDS,
    AuthorizationGate,
    SafeguardConfiguration,
)
from incidentgate.control.workflow import (
    DurableHumanAuthorization,
    EpisodeAuthorizationFactorySelector,
    EpisodePostDeliveryHook,
    EpisodeStrategy,
    build_episode_workflow_graph,
    episode_safeguard_identity,
    resolve_episode_authorization,
)
from incidentgate.lab.approval import ApprovalService
from incidentgate.lab.auth import Principal
from incidentgate.lab.repository import AuditTimelineEvent, LabRepository
from incidentgate.lab.service import ObservabilityService, OperationsService
from incidentgate.scenario_registry import (
    ALLOWED_EVIDENCE_SOURCES,
    NO_ACTION_SCENARIOS,
    RUNNABLE_SCENARIOS,
    SCENARIOS,
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
    DeterministicControlAuthorization,
    LabAuditEmitter,
    LabEvidenceCollector,
    LabOperationExecutor,
    LabRecoveryVerifier,
    LabTokenValidator,
)
from .monitor_facts import RepositoryMonitorFacts
from .semantic_monitor import SemanticMonitorBundle, SemanticMonitorSource


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
    #: The already-checkpointed proposal.  Exposed for resumable evaluation
    #: transcripts; callers never supply it back to the runtime.
    action: CanonicalAction | None = None
    trace_id: str | None = None
    trace_url: str | None = None
    collection_attempts: tuple[int, ...] = ()
    #: What the evidence gate found, whether or not it was the gate that
    #: enforced. ``WorkflowResult`` carries the cited ids but not the verdict, so
    #: an arm running the evidence gate in observe-only mode had no way to report
    #: the decision it would have made -- and a gate whose verdict nothing can
    #: read is exactly the unfalsifiable shape this lane exists to remove. Read
    #: off the durable state rather than added to ``WorkflowResult``, which is a
    #: checkpointed contract.
    evidence: EvidenceValidation | None = None
    monitor_error_kind: str | None = None


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
        semantic_monitor: SemanticMonitorSource | SemanticMonitorBundle | None = None,
        # The proposer seam. Left unset, every scenario gets its deterministic
        # proposer exactly as before. Supplied, the factory decides what proposes
        # the action -- which is how a model output reaches the gate chain at all.
        # A factory rather than an instance because the proposer is built per
        # incident, matching how the monitor is built.
        proposer_factory: Callable[[], ProposalGenerator] | None = None,
        # Evaluation-only authorization seam. Its requester supplies only a
        # HumanDecision payload: the graph still runs HumanDecision.model_validate,
        # approver matching, LabTokenValidator.validate, and repository transaction
        # revalidation. A custom requester can produce approvals or refusals, but
        # cannot bypass those boundaries.
        authorization_factory: Callable[[], AuthorizationRequester] | None = None,
        collection_crash_after_attempt: int | None = None,
        # Which gates enforce and who authorizes. Defaults to production's, and
        # the default is the only configuration the host can reach: nothing in
        # ``host/`` constructs a SafeguardConfiguration, which is what makes the
        # deterministic authorization control unselectable there rather than
        # merely undocumented. See control/safeguards.py.
        safeguards: SafeguardConfiguration = PRODUCTION_SAFEGUARDS,
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
        if semantic_monitor is not None and (monitor is not None or monitor_factory is not None):
            raise ValueError(
                "provide either v1 monitor or semantic monitor configuration, not both"
            )
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
                EpisodeTranscript,
            ),
        )
        self._checkpointer = PostgresSaver(self._connection, serde=serde)
        self._checkpointer.setup()
        self._response_loss_once = response_loss_once
        self._monitor = monitor
        self._monitor_factory = monitor_factory
        self._semantic_monitor = semantic_monitor
        self._proposer_factory = proposer_factory
        self._authorization_factory = authorization_factory
        self._collection_crash_after_attempt = collection_crash_after_attempt
        self._safeguards = safeguards
        self._allow_unpromoted_scenario = allow_unpromoted_scenario
        self._graph: Any | None = None

    @property
    def safeguards(self) -> SafeguardConfiguration:
        """Which gates this runtime enforces, readable by a test that must check.

        Public because "did the host build a production runtime?" has to be
        answerable from outside; a private attribute would make the guard test
        reach through the boundary it exists to police.
        """
        return self._safeguards

    def _authorization(self) -> AuthorizationRequester:
        """Bind the authorization port this runtime's configuration selects.

        Built per graph construction rather than once, for the reason the monitor
        is: it holds the repository and the clock, and rebuilding it keeps it on
        the same durable state the run is writing.
        """
        if self._safeguards.authorization_gate is AuthorizationGate.DURABLE_HUMAN:
            return DurableHumanAuthorization()
        approver = self._safeguards.control_approver
        # Guaranteed by SafeguardConfiguration.__post_init__, which refuses the
        # deterministic control without a named stand-in.
        assert approver is not None
        return DeterministicControlAuthorization(
            self._repository,
            self._clock,
            approver=approver,
            approval_ttl=self._approval_ttl,
        )

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
        return build_workflow_graph(
            self._build_action_dependencies(caller, context, scenario_id=scenario_id),
            checkpointer=self._checkpointer,
        )

    def _build_action_dependencies(
        self, caller: Caller, context: ToolCallContext, *, scenario_id: str
    ) -> WorkflowDependencies:
        """Build the shared action pipeline once for legacy and episode graphs."""
        if scenario_id in NO_ACTION_SCENARIOS:
            raise ValueError("real episodes require an action-taking scenario")
        config = PolicyConfiguration.model_validate(
            json.loads((Path(__file__).parents[3] / "config" / "policy.example.json").read_text())
        )
        semantic_bundle: SemanticMonitorBundle | None = None
        if self._semantic_monitor is not None:
            # Keyed on the *built* type rather than on a list of configuration
            # classes: a second output contract arrives as a second configuration,
            # and an isinstance chain over configurations would have to be edited
            # every time one does. A bundle is already built; anything else builds.
            semantic_bundle = (
                self._semantic_monitor
                if isinstance(self._semantic_monitor, SemanticMonitorBundle)
                else self._semantic_monitor.build(
                    policy=config, facts=RepositoryMonitorFacts(cast(Any, self._repository))
                )
            )
        observability = ObservabilityService(self._repository)
        sources = ALLOWED_EVIDENCE_SOURCES
        # The scenario's shipped honest proposer, resolved from the registry by
        # the name it declares. This was a seventeen-branch if-chain that
        # restated, in a second place and by hand, the same set
        # ``_scenario_span`` restated in a third: adding T4 to one and not the
        # other failed every T4 run inside the policy node. Both are now
        # projections of one declaration.
        #
        # What each proposer is remains a fact about the scenario rather than
        # about this method. T1's, T2's and T4's are honest baselines whose
        # attack conditions arrive through the proposer_factory seam below --
        # the same seam a captured model condition uses, so the gates see no
        # difference between a deterministic attack policy and a model-driven
        # one -- and T4's re-derives its position in the canonical sequence from
        # call-ledger evidence on every traversal rather than holding an index,
        # because its honest work is three calls where the others are one.
        definition = SCENARIOS.get(scenario_id)
        if definition is None or definition.proposer is None:
            raise ValueError("unsupported checkpoint scenario")
        proposer: ProposalGenerator = getattr(proposal, definition.proposer)()
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
                None
                if semantic_bundle is not None
                else (
                    self._monitor_factory()
                    if self._monitor_factory is not None
                    else (self._monitor or FixtureMonitor(MonitorVerdict.ALLOW))
                )
            ),
            monitor_v2=None if semantic_bundle is None else semantic_bundle.monitor,
            monitor_consultation_factory=(
                None if semantic_bundle is None else semantic_bundle.consultation_factory
            ),
            monitor_thresholds=None if semantic_bundle is None else semantic_bundle.thresholds,
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
            safeguards=self._safeguards,
            authorization=(
                self._authorization_factory()
                if self._authorization_factory is not None
                else self._authorization()
            ),
        )
        self._response_loss_once = False
        return dependencies

    @staticmethod
    def _config(thread_id: str) -> Any:
        """Build the legacy root-graph configuration.

        A future episode graph owns its loop in this single root checkpoint;
        individual action attempts must never substitute a storage thread id.
        """
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

    @staticmethod
    def _evidence(values: dict[str, Any]) -> EvidenceValidation | None:
        """The evidence gate's own verdict, revived the same way the result is.

        A checkpoint hands back either the model or the dict it serialized to, so
        both shapes are accepted here exactly as ``_result`` accepts them.
        """
        evidence = values.get("evidence")
        return (
            evidence
            if isinstance(evidence, EvidenceValidation)
            else (EvidenceValidation.model_validate(evidence) if evidence else None)
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
        self,
        incident: IncidentIdentity,
        operator: Caller,
        context: ToolCallContext,
    ) -> PendingApproval | RuntimeStatus:
        if operator.role is not Role.OPERATOR:
            raise PermissionError("D1 runtime start requires an authenticated operator")
        if context.idempotency_key is not None:
            raise ValueError("caller-chosen idempotency keys are not accepted")
        self._graph = self._build_graph(operator, context, scenario_id=incident.scenario_id)
        initial: dict[str, Any] = {"incident": incident, "caller": operator, "context": context}
        values = self._invoke_phase(incident.thread_id, initial=initial)
        pending = self._pending(incident.thread_id, values)
        return pending or self._status_from_values(
            incident.thread_id, values
        )

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
            action=(
                action
                if isinstance(action, CanonicalAction)
                else (CanonicalAction.model_validate(action) if action else None)
            ),
            trace_id=trace_id,
            trace_url=trace_url,
            collection_attempts=attempts,
            evidence=self._evidence(values),
            monitor_error_kind=(
                values.get("monitor_error")
                if isinstance(values.get("monitor_error"), str)
                else None
            ),
        )

    def approve(
        self,
        thread_id: str,
        approver: Principal,
        *,
        reason: str | None = None,
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
        self,
        thread_id: str,
        approver: Principal,
        *,
        reason: str | None = None,
    ) -> RuntimeStatus:
        if approver.role is not Role.APPROVER:
            raise PermissionError("D1 rejection requires an authenticated approver")
        if self.status(thread_id).pending is None:
            raise ValueError("thread has no pending approval")
        return self._resume(
            thread_id,
            {"decision": "reject", "approver": approver.actor, "reason": reason},
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
        values = self._invoke_phase(
            thread_id, resume=payload, approval=True
        )
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
            action=(
                action
                if isinstance(action, CanonicalAction)
                else (CanonicalAction.model_validate(action) if action else None)
            ),
            trace_id=trace_id,
            trace_url=trace_url,
            collection_attempts=attempts,
            evidence=self._evidence(values),
            monitor_error_kind=(
                values.get("monitor_error")
                if isinstance(values.get("monitor_error"), str)
                else None
            ),
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
            dict(graph.get_state(self._config(thread_id)).values)
            if initial is None
            else initial
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
            return cast(
                dict[str, Any], graph.invoke(payload, self._config(thread_id))
            )
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
                        result = graph.invoke(
                            Command(resume=resume), self._config(thread_id)
                        )
                else:
                    result = graph.invoke(None, self._config(thread_id))
        finally:
            self._telemetry.flush()
        return cast(dict[str, Any], result)

    def timeline(self, incident_id: str, *, limit: int = 50) -> tuple[AuditTimelineEvent, ...]:
        return self._repository.timeline(incident_id, limit=limit)


class EpisodeRuntime(IncidentRuntime):
    """Dedicated one-root runtime for adaptive evaluation episodes.

    It intentionally shares :class:`IncidentRuntime`'s dependency construction,
    checkpointer, authorization/token/repository adapters, and invoke boundary.
    The only different topology is the graph returned by
    ``build_episode_workflow_graph``.
    """

    def episode_exists(self, thread_id: str) -> bool:
        """Whether this root business thread has a durable episode checkpoint."""
        return self._checkpointer.get_tuple(self._config(thread_id)) is not None

    def start_episode(
        self,
        incident: IncidentIdentity,
        operator: Caller,
        context: ToolCallContext,
        *,
        transcript: EpisodeTranscript,
        max_actions: int,
        strategy: EpisodeStrategy,
        authorization_factory_selector: EpisodeAuthorizationFactorySelector | None = None,
        post_delivery_hook: EpisodePostDeliveryHook | None = None,
        interrupt_after: tuple[Literal["episode_propose", "monitor", "execute"], ...] = (),
    ) -> dict[str, Any]:
        if operator.role is not Role.OPERATOR:
            raise PermissionError("episode runtime start requires an authenticated operator")
        if context.idempotency_key is not None:
            raise ValueError("caller-chosen idempotency keys are not accepted")
        if transcript.events:
            raise ValueError("new episode transcripts must be empty root history")
        if (
            transcript.incident_id != incident.incident_id
            or transcript.thread_id != incident.thread_id
        ):
            raise ValueError("episode transcript does not bind the root incident/thread")
        if not 1 <= max_actions <= 1_000:
            raise ValueError("episode max_actions must be between 1 and 1000")
        dependencies = self._build_action_dependencies(
            operator, context, scenario_id=incident.scenario_id
        )
        self._graph = build_episode_workflow_graph(
            dependencies,
            strategy=strategy,
            authorization_factory_selector=authorization_factory_selector,
            post_delivery_hook=post_delivery_hook,
            interrupt_after=interrupt_after,
            checkpointer=self._checkpointer,
        )
        return self._invoke_phase(
            incident.thread_id,
            initial={
                "incident": incident,
                "caller": operator,
                "context": context,
                "episode_transcript": transcript,
                "episode_max_actions": max_actions,
                "episode_sequence": len(
                    tuple(event for event in transcript.events if event.phase == "terminal")
                ),
                "episode_safeguards": episode_safeguard_identity(dependencies.safeguards),
            },
        )

    def resume_episode(
        self,
        thread_id: str,
        *,
        strategy: EpisodeStrategy,
        authorization_factory_selector: EpisodeAuthorizationFactorySelector | None = None,
        post_delivery_hook: EpisodePostDeliveryHook | None = None,
        interrupt_after: tuple[Literal["episode_propose", "monitor", "execute"], ...] = (),
    ) -> dict[str, Any]:
        checkpoint = self._checkpointer.get_tuple(self._config(thread_id))
        if checkpoint is None:
            raise ValueError("unknown episode runtime thread")
        channels = checkpoint.checkpoint["channel_values"]
        caller = channels.get("caller")
        context = channels.get("context")
        incident = channels.get("incident")
        bound_caller = caller if isinstance(caller, Caller) else Caller.model_validate(caller)
        bound_context = (
            context
            if isinstance(context, ToolCallContext)
            else ToolCallContext.model_validate(context)
        )
        bound_incident = (
            incident
            if isinstance(incident, IncidentIdentity)
            else IncidentIdentity.model_validate(incident)
        )
        dependencies = self._build_action_dependencies(
            bound_caller, bound_context, scenario_id=bound_incident.scenario_id
        )
        persisted_safeguards = EpisodeSafeguardIdentity.model_validate(
            channels.get("episode_safeguards")
        )
        if persisted_safeguards != episode_safeguard_identity(dependencies.safeguards):
            raise ValueError("episode safeguards do not match the durable root configuration")
        preselected_requesters: dict[int, AuthorizationRequester] = {}
        raw_selection = channels.get("episode_authorization_selection")
        if raw_selection is not None:
            selection = EpisodeAuthorizationSelection.model_validate(raw_selection)
            candidate, requester = resolve_episode_authorization(
                fallback=dependencies.authorization,
                selector=authorization_factory_selector,
                leg=selection.leg,
                leg_index=selection.leg_index,
                sequence=selection.sequence,
            )
            if candidate != selection:
                raise ValueError("episode authorization selection does not match durable root")
            preselected_requesters[selection.sequence] = requester
        self._graph = build_episode_workflow_graph(
            dependencies,
            strategy=strategy,
            authorization_factory_selector=authorization_factory_selector,
            preselected_requesters=preselected_requesters,
            post_delivery_hook=post_delivery_hook,
            interrupt_after=interrupt_after,
            checkpointer=self._checkpointer,
        )
        return self._invoke_phase(thread_id)

    def episode_values(self, thread_id: str) -> dict[str, Any]:
        if self._graph is None:
            raise ValueError("episode graph has not been constructed")
        return dict(self._graph.get_state(self._config(thread_id)).values)

    def episode_pending(self, thread_id: str) -> PendingApproval | None:
        """Return an approval only for a public LangGraph approval interrupt."""
        if self._graph is None:
            raise ValueError("episode graph has not been constructed")
        snapshot = self._graph.get_state(self._config(thread_id))
        approval_interrupt = any(
            task.name == "approval" and task.interrupts for task in snapshot.tasks
        )
        if not approval_interrupt:
            return None
        return self._pending(thread_id, dict(snapshot.values))

    def approve(
        self,
        thread_id: str,
        approver: Principal,
        *,
        reason: str | None = None,
    ) -> RuntimeStatus:
        """Approve only a durable episode approval interrupt, never a pause hook."""
        if self.episode_pending(thread_id) is None:
            raise ValueError("episode thread has no pending approval interrupt")
        return super().approve(thread_id, approver, reason=reason)


class CheckpointRuntime(IncidentRuntime):
    """Alias for the durable incident runtime, used by the checkpoint test suites.

    Adds no behavior. IncidentRuntime is the name production code uses.
    """
