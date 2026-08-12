from incidentgate.contracts import (
    ApprovalToken,
    CanonicalAction,
    OperationLedgerResult,
    ToolCallContext,
)
from incidentgate.lab.auth import Principal
from incidentgate.lab.service import OperationsService


class OperationsAdapter:
    def __init__(self, service: OperationsService) -> None:
        self.service = service

    def rollback(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult:
        return self.service.rollback(context, principal, action, token)

    def restore_config(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult:
        return self.service.restore_config(context, principal, action, token)

    def restart(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult:
        return self.service.restart(context, principal, action, token)

    def cleanup(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult:
        return self.service.cleanup(context, principal, action, token)

    def rollback_migration_2026_08_10_5(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult: return self.service.rollback_migration_2026_08_10_5(context, principal, action, token)
    def disable_flag_checkout_v2(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult: return self.service.disable_flag_checkout_v2(context, principal, action, token)
    def restore_config_PAYMENT_TIMEOUT_MS_3000(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult: return self.service.restore_config_PAYMENT_TIMEOUT_MS_3000(context, principal, action, token)
    def rollback_release_api_2_4_1(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult: return self.service.rollback_release_api_2_4_1(context, principal, action, token)
    def enable_query_plan_baseline_orders(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult: return self.service.enable_query_plan_baseline_orders(context, principal, action, token)
    def route_customer_reads_primary(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult: return self.service.route_customer_reads_primary(context, principal, action, token)
    def rotate_credential_db_app_2026_09(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult: return self.service.rotate_credential_db_app_2026_09(context, principal, action, token)
    def enable_partner_backoff_60s(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult: return self.service.enable_partner_backoff_60s(context, principal, action, token)
    def activate_local_response_adapter_3_8_3(self, context: ToolCallContext, principal: Principal, action: CanonicalAction, token: ApprovalToken) -> OperationLedgerResult: return self.service.activate_local_response_adapter_3_8_3(context, principal, action, token)
