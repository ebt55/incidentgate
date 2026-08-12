"""Three localhost-only, stateless FastMCP entrypoint factories for the D1 lab."""

from typing import Any

from mcp.server.fastmcp import FastMCP

from incidentgate.contracts import ApprovalToken, CanonicalAction
from incidentgate.lab.auth import Principal
from incidentgate.lab.service import ObservabilityService, OperationsService, TicketsService

from .observability import ObservabilityAdapter
from .operations import OperationsAdapter
from .shared import LOCALHOST_HOST, context_from_payload
from .tickets import TicketsAdapter


def observability_server(service: ObservabilityService, principal: Principal) -> FastMCP:
    server = FastMCP("incidentgate-observability", host=LOCALHOST_HOST, stateless_http=True)
    adapter = ObservabilityAdapter(service)

    @server.tool()
    def health(context: dict[str, object]) -> dict[str, Any]:
        return adapter.health(context_from_payload(context), principal).model_dump(mode="json")

    @server.tool()
    def deployment_diff(context: dict[str, object]) -> dict[str, Any]:
        return adapter.deployment_diff(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def config_diff(context: dict[str, object]) -> dict[str, Any]:
        return adapter.config_diff(context_from_payload(context), principal).model_dump(mode="json")

    @server.tool()
    def db_pool_metrics(context: dict[str, object]) -> dict[str, Any]:
        return adapter.db_pool_metrics(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def disk_metrics(context: dict[str, object]) -> dict[str, Any]:
        return adapter.disk_metrics(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def log_volume(context: dict[str, object]) -> dict[str, Any]:
        return adapter.log_volume(context_from_payload(context), principal).model_dump(mode="json")

    @server.tool()
    def metrics(context: dict[str, object]) -> dict[str, Any]:
        return adapter.metrics(context_from_payload(context), principal).model_dump(mode="json")

    @server.tool()
    def logs(context: dict[str, object]) -> dict[str, Any]:
        return adapter.logs(context_from_payload(context), principal).model_dump(mode="json")

    @server.tool()
    def dependency_metrics(context: dict[str, object]) -> dict[str, Any]:
        return adapter.dependency_metrics(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def error_logs(context: dict[str, object]) -> dict[str, Any]:
        return adapter.error_logs(context_from_payload(context), principal).model_dump(mode="json")

    @server.tool()
    def tool_timeout(context: dict[str, object]) -> dict[str, Any]:
        return adapter.tool_timeout(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def retry_metadata(context: dict[str, object]) -> dict[str, Any]:
        return adapter.retry_metadata(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def database_schema(context: dict[str, object]) -> dict[str, Any]:
        return adapter.database_schema(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def feature_flags(context: dict[str, object]) -> dict[str, Any]:
        return adapter.feature_flags(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def http_metrics(context: dict[str, object]) -> dict[str, Any]:
        return adapter.http_metrics(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def config_snapshot(context: dict[str, object]) -> dict[str, Any]:
        return adapter.config_snapshot(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def pod_inventory(context: dict[str, object]) -> dict[str, Any]:
        return adapter.pod_inventory(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def database_locks(context: dict[str, object]) -> dict[str, Any]:
        return adapter.database_locks(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def query_metrics(context: dict[str, object]) -> dict[str, Any]:
        return adapter.query_metrics(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def query_plan(context: dict[str, object]) -> dict[str, Any]:
        return adapter.query_plan(context_from_payload(context), principal).model_dump(mode="json")

    @server.tool()
    def replica_status(context: dict[str, object]) -> dict[str, Any]:
        return adapter.replica_status(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def request_routing(context: dict[str, object]) -> dict[str, Any]:
        return adapter.request_routing(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def credential_status(context: dict[str, object]) -> dict[str, Any]:
        return adapter.credential_status(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool()
    def database_health(context: dict[str, object]) -> dict[str, Any]:
        return adapter.database_health(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    @server.tool(name="dns_lookup")
    def dns_lookup(context: dict[str, object]) -> dict[str, Any]:
        return adapter.dns_lookup(context_from_payload(context), principal).model_dump(mode="json")

    @server.tool(name="tls_probe")
    def tls_probe(context: dict[str, object]) -> dict[str, Any]:
        return adapter.tls_probe(context_from_payload(context), principal).model_dump(mode="json")

    @server.tool(name="schema_validation")
    def schema_validation(context: dict[str, object]) -> dict[str, Any]:
        return adapter.schema_validation(context_from_payload(context), principal).model_dump(
            mode="json"
        )

    return server


def operations_server(service: OperationsService, principal: Principal) -> FastMCP:
    server = FastMCP("incidentgate-operations", host=LOCALHOST_HOST, stateless_http=True)
    adapter = OperationsAdapter(service)

    @server.tool()
    def rollback(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        result = adapter.rollback(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        )
        return result.model_dump(mode="json")

    @server.tool()
    def restore_config(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        result = adapter.restore_config(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        )
        return result.model_dump(mode="json")

    @server.tool()
    def restart(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        result = adapter.restart(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        )
        return result.model_dump(mode="json")

    @server.tool()
    def cleanup(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        result = adapter.cleanup(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        )
        return result.model_dump(mode="json")

    # Registered exact capabilities; no operation-selector or alias is exposed.
    @server.tool(name="rollback_migration_2026_08_10_5")
    def rollback_migration_2026_08_10_5(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        return adapter.rollback_migration_2026_08_10_5(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        ).model_dump(mode="json")

    @server.tool(name="disable_flag_checkout_v2")
    def disable_flag_checkout_v2(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        return adapter.disable_flag_checkout_v2(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        ).model_dump(mode="json")

    @server.tool(name="restore_config_PAYMENT_TIMEOUT_MS_3000")
    def restore_config_PAYMENT_TIMEOUT_MS_3000(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        return adapter.restore_config_PAYMENT_TIMEOUT_MS_3000(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        ).model_dump(mode="json")

    @server.tool(name="rollback_release_api_2_4_1")
    def rollback_release_api_2_4_1(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        return adapter.rollback_release_api_2_4_1(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        ).model_dump(mode="json")

    @server.tool(name="enable_query_plan_baseline_orders")
    def enable_query_plan_baseline_orders(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        return adapter.enable_query_plan_baseline_orders(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        ).model_dump(mode="json")

    @server.tool(name="route_customer_reads_primary")
    def route_customer_reads_primary(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        return adapter.route_customer_reads_primary(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        ).model_dump(mode="json")

    @server.tool(name="rotate_credential_db_app_2026_09")
    def rotate_credential_db_app_2026_09(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        return adapter.rotate_credential_db_app_2026_09(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        ).model_dump(mode="json")

    @server.tool(name="enable_partner_backoff_60s")
    def enable_partner_backoff_60s(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        return adapter.enable_partner_backoff_60s(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        ).model_dump(mode="json")

    @server.tool(name="activate_local_response_adapter_3_8_3")
    def activate_local_response_adapter_3_8_3(
        context: dict[str, object], action: dict[str, object], token: dict[str, object]
    ) -> dict[str, Any]:
        return adapter.activate_local_response_adapter_3_8_3(
            context_from_payload(context),
            principal,
            CanonicalAction.model_validate(action),
            ApprovalToken.model_validate(token),
        ).model_dump(mode="json")

    return server


def tickets_server(service: TicketsService, principal: Principal) -> FastMCP:
    server = FastMCP("incidentgate-tickets", host=LOCALHOST_HOST, stateless_http=True)
    adapter = TicketsAdapter(service)

    @server.tool()
    def read_ticket(context: dict[str, object]) -> dict[str, object]:
        return adapter.read(context_from_payload(context), principal)

    @server.tool()
    def append_note(context: dict[str, object], body: str) -> None:
        adapter.append(context_from_payload(context), principal, body)

    return server
