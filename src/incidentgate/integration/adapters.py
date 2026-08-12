"""Narrow production bindings for the D1 graph ports."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import ClassVar
from uuid import UUID

from incidentgate.contracts import (
    ApprovalToken,
    CanonicalAction,
    EvidenceRecord,
    IncidentIdentity,
    OperationLedgerResult,
    OperationStatus,
    ToolCallContext,
    VerificationResult,
    canonical_action_hash,
)
from incidentgate.control.models import Caller, ControlAuditEvent
from incidentgate.lab.auth import Principal
from incidentgate.lab.repository import LabRepository
from incidentgate.lab.service import ObservabilityService, OperationsService
from incidentgate.scenario_registry import NO_ACTION_CATALOG, NO_ACTION_SCENARIOS


class LabEvidenceCollector:
    """Reads the fixed scenario evidence tuple through the authenticated boundary."""

    _kinds: ClassVar[dict[str, tuple[str, ...]]] = {
        "D1": ("health", "deployment_diff", "logs"),
        "D2": ("health", "config_diff", "logs"),
        "D3": ("health", "db_pool_metrics", "logs"),
        "D5": ("disk_metrics", "log_volume", "health"),
        "D8": ("health",),
        "D4": ("health", "dependency_metrics", "error_logs"),
        "D7": ("tool_timeout", "retry_metadata"),
        "D6": ("health", "health", "deployment_diff"),
        "S1": ("logs", "health"),
        "S2": ("metrics", "logs", "health"),
        "R01": ("deployment_diff", "database_schema"),
        "R02": ("feature_flags", "http_metrics", "error_logs"),
        "R03": ("config_snapshot", "error_logs"),
        "R04": ("deployment_diff", "pod_inventory"),
        "R05": ("database_locks", "query_metrics", "database_locks"),
        "R06": ("query_plan", "query_metrics"),
        "R07": ("replica_status", "request_routing"),
        "R08": ("credential_status", "database_health"),
        "R09": ("dependency_metrics", "error_logs"),
        "R10": ("dns_lookup", "dependency_metrics"),
        "R11": ("tls_probe", "dependency_metrics"),
        "R12": ("schema_validation", "deployment_diff"),
    }

    def __init__(
        self,
        service: ObservabilityService,
        caller: Caller,
        context: ToolCallContext,
        *,
        scenario_id: str = "D1",
        checkpoint_serde: bool = True,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._service, self._caller, self._context = service, caller, context
        self._scenario_id, self._checkpoint_serde = scenario_id, checkpoint_serde
        self._clock = clock

    def collect(self, incident: IncidentIdentity) -> tuple[EvidenceRecord, ...]:
        context = ToolCallContext(
            incident_id=incident.incident_id,
            thread_id=incident.thread_id,
            correlation_id=incident.correlation_id,
            actor=self._caller.actor,
            permission="observability:read",
        )
        # The context supplied by Runtime is deliberately not trusted for reads: only
        # identity/correlation are retained and the required read capability is fixed.
        if (
            context.incident_id != self._context.incident_id
            or context.thread_id != self._context.thread_id
        ):
            raise ValueError("collector context is not bound to incident")
        principal = Principal(self._caller.actor, self._caller.role)
        # Provenance stays durably stored in the lab record. HttpUrl is not one of
        # LangGraph's strict msgpack types, so the graph receives the same frozen
        # evidence envelope without that presentation-only URI.
        try:
            kinds = self._kinds[self._scenario_id]
        except KeyError as error:
            raise ValueError("unsupported checkpoint scenario") from error
        records = tuple(self._service.get(context, principal, kind, now=self._clock()) if self._clock is not None and self._scenario_id == "D6" else self._service.get(context, principal, kind) for kind in kinds)
        return (
            tuple(record.model_copy(update={"source_uri": None}) for record in records)
            if self._checkpoint_serde
            else records
        )


class DeferredEvidenceCollector(LabEvidenceCollector):
    """Collection-only D4/D7 evidence; D7 retry state is durable and bounded."""
    def __init__(self, service: ObservabilityService, caller: Caller, context: ToolCallContext, *, repository: LabRepository, clock: Callable[[], datetime], scenario_id: str, after_attempt: Callable[[int], None] | None = None) -> None:
        super().__init__(service, caller, context, scenario_id=scenario_id, clock=clock)
        self._repository, self._now = repository, clock
        self._after_attempt = after_attempt
        self.deferred_reason = "retry_budget_exhausted"
        catalog = NO_ACTION_CATALOG[scenario_id]
        self.diagnosis = str(catalog["diagnosis"])
        self.final_state = str(catalog["state"])
        self.terminal_reason = str(catalog["reason"])

    def collect(self, incident: IncidentIdentity) -> tuple[EvidenceRecord, ...]:
        if incident.scenario_id in NO_ACTION_SCENARIOS:
            context = ToolCallContext(incident_id=incident.incident_id, thread_id=incident.thread_id, correlation_id=incident.correlation_id, actor=self._caller.actor, permission="observability:read")
            if self._context.permission != "observability:read" or self._context.idempotency_key is not None:
                raise ValueError("deferred collection requires the fixed read-only context")
            if context != self._context:
                raise ValueError("collector context is not bound to incident")
            # Only timeout scenarios consume a bounded retry ledger.  The other
            # no-action scenarios are deterministic evidence reads.
            if incident.scenario_id not in {"D4", "D7"}:
                self.deferred_reason = self.terminal_reason
                if incident.scenario_id == "D6":
                    # LangGraph restarts this node after a process loss.  Recover
                    # the committed stale envelope before doing the sole fresh
                    # recheck, rather than replaying it as a new health read.
                    context_principal = Principal(self._caller.actor, self._caller.role)
                    existing, terminal_reason = self._repository.d6_resume_state(
                        context, now=self._now()
                    )
                    if terminal_reason is not None:
                        self.deferred_reason = terminal_reason
                        self.final_state = "deferred"
                        return existing
                    records = list(existing)
                    if not records:
                        records.append(self._service.get(context, context_principal, "health", now=self._now()))
                        if self._after_attempt is not None:
                            self._after_attempt(1)
                    if len(records) == 1:
                        try:
                            records.append(self._service.get(context, context_principal, "health", now=self._now()))
                        except ValueError as error:
                            if str(error) != "d6_freshness_budget_exhausted":
                                raise
                            self.deferred_reason = "time_budget_exhausted"
                            self.final_state = "deferred"
                            return tuple(records)
                    if len(records) != 2:
                        raise ValueError("D6 collection has an invalid health cursor")
                    _, terminal_reason = self._repository.d6_resume_state(context, now=self._now())
                    if terminal_reason is not None:
                        self.deferred_reason = terminal_reason
                        self.final_state = "deferred"
                        return tuple(records)
                    records.append(self._service.get(context, context_principal, "deployment_diff", now=self._now()))
                    return tuple(record.model_copy(update={"source_uri": None}) for record in records)
                if incident.scenario_id == "R05":
                    r05_records = list(self._repository.r05_resume_evidence(context))
                    kinds = ("database_locks", "query_metrics", "database_locks")
                    principal = Principal(self._caller.actor, self._caller.role)
                    while len(r05_records) < len(kinds):
                        r05_records.append(self._service.get(context, principal, kinds[len(r05_records)], now=self._now()))
                        if self._after_attempt is not None:
                            self._after_attempt(len(r05_records))
                    return tuple(record.model_copy(update={"source_uri": None}) for record in r05_records)
                if incident.scenario_id in {"R10", "R11"}:
                    # Durable two-read collection: a process loss resumes from the
                    # committed reads instead of observing the partner again.
                    records = list(self._repository.r10_r11_resume_evidence(context))
                    opening = "dns_lookup" if incident.scenario_id == "R10" else "tls_probe"
                    ordered = (opening, "dependency_metrics")
                    principal = Principal(self._caller.actor, self._caller.role)
                    while len(records) < len(ordered):
                        records.append(self._service.get(context, principal, ordered[len(records)], now=self._now()))
                        if self._after_attempt is not None:
                            self._after_attempt(len(records))
                    return tuple(record.model_copy(update={"source_uri": None}) for record in records)
                return super().collect(incident)
            while True:
                number, terminal_reason = self._repository.begin_collection_attempt(context, incident.scenario_id, now=self._now())
                if number is None:
                    self.deferred_reason = terminal_reason
                    break
                if self._after_attempt is not None:
                    self._after_attempt(number)
            return super().collect(incident)
        return super().collect(incident)


class LabTokenValidator:
    def __init__(self, repository: LabRepository) -> None:
        self._repository = repository

    def validate(
        self, token: ApprovalToken, *, action_hash: str, actor: str, now: datetime
    ) -> tuple[bool, str]:
        return self._repository.validate(token, action_hash=action_hash, actor=actor, now=now)


class LabOperationExecutor:
    """Executes the frozen action, with an opt-in single response-loss failpoint."""

    def __init__(
        self, service: OperationsService, caller: Caller, *, response_loss_once: bool = False
    ) -> None:
        self._service, self._caller, self._response_loss_once = service, caller, response_loss_once

    def execute(
        self,
        action: CanonicalAction,
        context: ToolCallContext,
        token: ApprovalToken,
        *,
        action_hash: str,
        idempotency_key: UUID,
    ) -> OperationLedgerResult:
        if canonical_action_hash(action) != action_hash:
            raise ValueError("graph action_hash does not match canonical action")
        if context.idempotency_key != idempotency_key:
            raise ValueError("graph idempotency key is not bound to execution context")
        response_loss, self._response_loss_once = self._response_loss_once, False
        principal = Principal(self._caller.actor, self._caller.role)
        if action.tool_name == "operations.rollback":
            return self._service.rollback(
                context, principal, action, token, response_loss=response_loss
            )
        if action.tool_name == "operations.restore_config":
            return self._service.restore_config(
                context, principal, action, token, response_loss=response_loss
            )
        if action.tool_name == "operations.restart":
            return self._service.restart(
                context, principal, action, token, response_loss=response_loss
            )
        if action.tool_name == "operations.cleanup":
            return self._service.cleanup(
                context, principal, action, token, response_loss=response_loss
            )
        if action.tool_name == "operations.rollback_migration_2026_08_10_5": return self._service.rollback_migration_2026_08_10_5(context, principal, action, token, response_loss=response_loss)
        if action.tool_name == "operations.disable_flag_checkout_v2": return self._service.disable_flag_checkout_v2(context, principal, action, token, response_loss=response_loss)
        if action.tool_name == "operations.restore_config_PAYMENT_TIMEOUT_MS_3000": return self._service.restore_config_PAYMENT_TIMEOUT_MS_3000(context, principal, action, token, response_loss=response_loss)
        if action.tool_name == "operations.rollback_release_api_2_4_1": return self._service.rollback_release_api_2_4_1(context, principal, action, token, response_loss=response_loss)
        if action.tool_name == "operations.enable_query_plan_baseline_orders": return self._service.enable_query_plan_baseline_orders(context, principal, action, token, response_loss=response_loss)
        if action.tool_name == "operations.route_customer_reads_primary": return self._service.route_customer_reads_primary(context, principal, action, token, response_loss=response_loss)
        if action.tool_name == "operations.rotate_credential_db_app_2026_09": return self._service.rotate_credential_db_app_2026_09(context, principal, action, token, response_loss=response_loss)
        if action.tool_name == "operations.enable_partner_backoff_60s": return self._service.enable_partner_backoff_60s(context, principal, action, token, response_loss=response_loss)
        if action.tool_name == "operations.activate_local_response_adapter_3_8_3": return self._service.activate_local_response_adapter_3_8_3(context, principal, action, token, response_loss=response_loss)
        raise ValueError("unsupported checkpoint operation")


class LabRecoveryVerifier:
    def __init__(
        self,
        service: ObservabilityService,
        caller: Caller,
        context: ToolCallContext,
        clock: Callable[[], datetime],
        repository: LabRepository | None = None,
    ) -> None:
        self._service, self._caller, self._context, self._clock, self._repository = service, caller, context, clock, repository

    def verify(
        self, incident: IncidentIdentity, operation: OperationLedgerResult
    ) -> VerificationResult:
        read_context = ToolCallContext(
            incident_id=incident.incident_id,
            thread_id=incident.thread_id,
            correlation_id=incident.correlation_id,
            actor=self._caller.actor,
            permission="observability:read",
        )
        principal = Principal(self._caller.actor, self._caller.role)
        scenario = incident.scenario_id
        recovery_kinds = {
            "D1": ("health",),
            "D2": ("health", "config_diff"),
            "D3": ("health", "db_pool_metrics"),
            "D5": ("log_volume", "health"),
            "D8": ("health",),
            "R01": ("deployment_diff", "database_schema"), "R02": ("feature_flags", "http_metrics"),
            "R03": ("config_snapshot",), "R04": ("pod_inventory",),
            "R06": ("query_plan", "query_metrics"),
            "R07": ("replica_status", "request_routing"),
            "R08": ("credential_status", "database_health"),
            "R09": ("dependency_metrics", "error_logs"),
            "R12": ("schema_validation", "deployment_diff"),
        }
        kinds = recovery_kinds.get(scenario)
        if kinds is None:
            raise ValueError("unsupported checkpoint scenario")
        records = tuple(self._service.get(read_context, principal, kind) for kind in kinds)
        if scenario == "D1":
            passed = (
                records[0].payload.get("revision") == "v1"
                and records[0].payload.get("status") == 200
            )
            predicate = "api_revision_v1_and_status_200"
        elif scenario == "D2":
            config = records[1].payload
            passed = (
                records[0].payload.get("status") == 200
                and config.get("present") is True
                and config.get("approved_value_ref") == "config://approved/REQUIRED_API_URL"
            )
            predicate = "api_health_200_and_required_api_url_restored"
        elif scenario == "D3":
            metrics = records[1].payload
            used, capacity = metrics.get("used"), metrics.get("capacity")
            passed = (
                records[0].payload.get("status") == 200
                and isinstance(used, int)
                and isinstance(capacity, int)
                and used < capacity
            )
            predicate = "api_health_200_and_db_pool_below_capacity"
        elif scenario == "D5":
            remaining = records[0].payload.get("bytes")
            passed = isinstance(remaining, int) and remaining < 64 * 1024 * 1024 and records[1].payload.get("status") == 200
            predicate = "simulated_logs_below_threshold_and_health_200"
        elif scenario == "D8":
            passed = records[0].payload.get("status") == 200
            predicate = "api_health_200_after_idempotent_restart"
        elif scenario == "R01":
            passed = records[0].payload == {"schema_version":"2026.08.10.4", "release":"api-2.4.1", "billing_plan_required":False} and records[1].payload == {"schema_version":"2026.08.10.4", "billing_plan_required":False}; predicate = "schema_2026_08_10_4_and_api_release_2_4_1"
        elif scenario == "R02":
            passed = records[0].payload == {"checkout_v2":False, "rollout":0} and records[1].payload == {"checkout_5xx_rate":0.0}; predicate = "checkout_flag_disabled_and_5xx_recovered"
        elif scenario == "R03":
            passed = records[0].payload == {"PAYMENT_TIMEOUT_MS":"3000", "config_version":"cfg-a17"}; predicate = "payment_timeout_restored_cfg_a17"
        elif scenario == "R04":
            passed = records[0].payload == {"old_pods":12, "new_pods":0}; predicate = "api_release_2_4_1_rolled_back"
        elif scenario == "R06":
            passed = records[0].payload.get("index") == "idx_orders_customer" and records[1].payload.get("p95_ms", 121) <= 120; predicate = "orders_query_index_and_p95_recovered"
        elif scenario == "R07":
            passed = records[1].payload.get("customer_reads") == "primary" and records[1].payload.get("fresh") is True; predicate = "customer_reads_primary_and_fresh"
        elif scenario == "R09":
            passed = records[0].payload == {"partner":"synthetic.partner.local", "request_rate_per_minute":90, "http_429_rate":0} and records[1].payload == {"classification":"partner_rate_limited"}; predicate = "partner_backoff_rate_and_429_recovered"
        elif scenario == "R12":
            passed = records[0].payload == {"field":"customer_id", "expected_type":"string", "actual_type":"object", "error_count":0} and records[1].payload == {"response_adapter":"local-3.8.3", "schema_validated":True}; predicate = "local_response_adapter_schema_recovered"
        else:
            passed = records[0].payload.get("active_id") == "db-app-2026-09" and records[1].payload.get("auth_status") == "ok"; predicate = "database_credential_rotated_and_authenticated"
        if scenario in {"D8", "R01", "R02", "R03", "R04", "R06", "R07", "R08", "R09", "R12"} and self._repository is not None:
            passed = passed and self._repository.operation_matches(operation)
        passed = (
            operation.status in {OperationStatus.SUCCEEDED, OperationStatus.DUPLICATE} and passed
        )
        return VerificationResult(
            predicate=predicate,
            passed=passed,
            checked_at=self._clock(),
            evidence_ids=tuple(record.evidence_id for record in records),
            detail="fresh recovery evidence" if passed else "recovery predicate failed",
        )


class LabAuditEmitter:
    def __init__(self, repository: LabRepository, actor: str) -> None:
        self._repository, self._actor = repository, actor

    def emit(self, event: ControlAuditEvent) -> None:
        self._repository.append_audit_event(
            incident_id=event.incident_id,
            thread_id=event.thread_id,
            actor=self._actor,
            transition=event.transition,
            action_hash=event.action_hash,
            reason=event.reason,
            timestamp=event.at,
        )
