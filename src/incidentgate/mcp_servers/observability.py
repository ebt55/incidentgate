from incidentgate.contracts import EvidenceRecord, ToolCallContext
from incidentgate.lab.auth import Principal
from incidentgate.lab.service import ObservabilityService


class ObservabilityAdapter:
    def __init__(self, service: ObservabilityService) -> None:
        self.service = service

    def health(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "health")

    def deployment_diff(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "deployment_diff")

    def config_diff(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "config_diff")

    def db_pool_metrics(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "db_pool_metrics")

    def disk_metrics(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "disk_metrics")

    def log_volume(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "log_volume")

    def metrics(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "metrics")

    def logs(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "logs")

    def dependency_metrics(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "dependency_metrics")

    def error_logs(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "error_logs")

    def tool_timeout(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "tool_timeout")

    def retry_metadata(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord:
        return self.service.get(context, principal, "retry_metadata")

    def database_schema(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "database_schema")
    def feature_flags(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "feature_flags")
    def http_metrics(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "http_metrics")
    def config_snapshot(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "config_snapshot")
    def pod_inventory(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "pod_inventory")
    def database_locks(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "database_locks")
    def query_metrics(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "query_metrics")
    def query_plan(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "query_plan")
    def replica_status(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "replica_status")
    def request_routing(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "request_routing")
    def credential_status(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "credential_status")
    def database_health(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "database_health")
    def dns_lookup(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "dns_lookup")
    def tls_probe(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "tls_probe")
    def schema_validation(self, context: ToolCallContext, principal: Principal) -> EvidenceRecord: return self.service.get(context, principal, "schema_validation")
