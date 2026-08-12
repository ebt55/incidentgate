"""Small domain services which MCP adapters can test without a transport."""

from datetime import datetime
from typing import Protocol

from incidentgate.contracts import (
    ApprovalToken,
    CanonicalAction,
    EvidenceRecord,
    OperationLedgerResult,
    ToolCallContext,
)

from .auth import Principal, require_operation, require_read
from .errors import ApprovalDenied, UnsupportedOperation


class ObservabilityRepository(Protocol):
    def evidence(
        self, context: ToolCallContext, kind: str, *, now: datetime | None = None
    ) -> EvidenceRecord: ...


class OperationsRepository(Protocol):
    def enable_partner_backoff_60s(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...
    def activate_local_response_adapter_3_8_3(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...
    def enable_query_plan_baseline_orders(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...
    def route_customer_reads_primary(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...
    def rotate_credential_db_app_2026_09(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...
    def rollback_migration_2026_08_10_5(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...
    def disable_flag_checkout_v2(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...
    def restore_config_PAYMENT_TIMEOUT_MS_3000(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...
    def rollback_release_api_2_4_1(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...
    def rollback(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...

    def restore_config(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...

    def restart(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...

    def cleanup(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult: ...


class TicketsRepository(Protocol):
    def ticket(self, incident_id: str) -> dict[str, object]: ...


class ObservabilityService:
    def __init__(self, repository: ObservabilityRepository) -> None:
        self.repository = repository

    def get(
        self,
        context: ToolCallContext,
        principal: Principal,
        kind: str,
        *,
        now: datetime | None = None,
    ) -> EvidenceRecord:
        require_read(context, principal)
        if kind not in {
            "health",
            "deployment_diff",
            "config_diff",
            "db_pool_metrics",
            "disk_metrics",
            "log_volume",
            "metrics",
            "logs",
            "dependency_metrics",
            "error_logs",
            "tool_timeout",
            "retry_metadata",
            "database_schema",
            "feature_flags",
            "http_metrics",
            "config_snapshot",
            "pod_inventory",
            "database_locks",
            "query_metrics",
            "query_plan",
            "replica_status",
            "request_routing",
            "credential_status",
            "database_health",
            "dns_lookup",
            "tls_probe",
            "schema_validation",
        }:
            raise UnsupportedOperation(f"observability.{kind} is unsupported")
        return (
            self.repository.evidence(context, kind)
            if now is None
            else self.repository.evidence(context, kind, now=now)
        )


class OperationsService:
    def __init__(self, repository: OperationsRepository) -> None:
        self.repository = repository

    def rollback(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.rollback(context, action, token, response_loss)

    def restore_config(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.restore_config(context, action, token, response_loss)

    def restart(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.restart(context, action, token, response_loss)

    def cleanup(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.cleanup(context, action, token, response_loss)

    def rollback_migration_2026_08_10_5(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.rollback_migration_2026_08_10_5(
            context, action, token, response_loss
        )

    def disable_flag_checkout_v2(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.disable_flag_checkout_v2(context, action, token, response_loss)

    def restore_config_PAYMENT_TIMEOUT_MS_3000(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.restore_config_PAYMENT_TIMEOUT_MS_3000(
            context, action, token, response_loss
        )

    def rollback_release_api_2_4_1(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.rollback_release_api_2_4_1(context, action, token, response_loss)

    def enable_query_plan_baseline_orders(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.enable_query_plan_baseline_orders(
            context, action, token, response_loss
        )

    def route_customer_reads_primary(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.route_customer_reads_primary(context, action, token, response_loss)

    def rotate_credential_db_app_2026_09(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.rotate_credential_db_app_2026_09(
            context, action, token, response_loss
        )

    def enable_partner_backoff_60s(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.enable_partner_backoff_60s(context, action, token, response_loss)

    def activate_local_response_adapter_3_8_3(
        self,
        context: ToolCallContext,
        principal: Principal,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> OperationLedgerResult:
        require_operation(context, principal)
        return self.repository.activate_local_response_adapter_3_8_3(
            context, action, token, response_loss
        )


class TicketsService:
    def __init__(self, repository: TicketsRepository) -> None:
        self.repository = repository

    def read(self, context: ToolCallContext, principal: Principal) -> dict[str, object]:
        require_read(context, principal)
        return self.repository.ticket(context.incident_id)

    def append_disabled(self, context: ToolCallContext, principal: Principal, body: str) -> None:
        del context, principal, body
        raise ApprovalDenied(
            "ticket append is disabled in D1 until the approval control layer is present"
        )
