"""Deterministic D1 proposal generation from collected evidence only."""

from __future__ import annotations

from incidentgate.contracts import (
    ActivateLocalResponseAdapter383Args,
    CanonicalAction,
    CleanupArgs,
    DisableFlagCheckoutV2Args,
    EnablePartnerBackoff60sArgs,
    EnableQueryPlanBaselineOrdersArgs,
    EvidenceRecord,
    Hypothesis,
    IncidentIdentity,
    RestartArgs,
    RestoreConfigArgs,
    RestoreConfigPaymentTimeoutMs3000Args,
    RollbackArgs,
    RollbackMigration202608105Args,
    RollbackReleaseApi241Args,
    RotateCredentialDbApp202609Args,
    RouteCustomerReadsPrimaryArgs,
    ToolCallContext,
)
from incidentgate.reasons import (
    PROPOSAL_AMBIGUOUS_EVIDENCE,
    PROPOSAL_BELOW_THRESHOLD,
    PROPOSAL_CONTEXT_MISMATCH,
    PROPOSAL_MISSING_REQUIRED_EVIDENCE,
    PROPOSAL_NO_D1_FAULT,
    PROPOSAL_WRONG_CONFIG,
    PROPOSAL_WRONG_RELIABILITY_FIXTURE,
    PROPOSAL_WRONG_REVISION_DIFF,
    PROPOSAL_WRONG_STATE,
)

from .models import Caller


class ProposalError(Exception):
    """A stable, non-authorizing terminal reason from D1 proposal generation.

    ``reason`` is a wire value, not a free-form message. The D1 workflow copies it verbatim into
    ``WorkflowResult.reasons``, the audit timeline persists it, the evaluation artifacts publish
    it, and the chaos end-state differ compares ``terminal_reasons`` for exact equality - its
    comparison spec even documents the field as "fixed vocabulary values; no normalization
    needed". Nothing in code enforces that vocabulary today, so adding a reason silently widens
    what all of those consumers compare on.

    Freezing it is the better contract, and is deliberately not done here: the vocabulary is
    produced by this module, ``policy``, ``evidence``, ``workflow``, and the scenario registry,
    and includes parameterized forms (``argument_constraint:<name>``, ``unknown_evidence:<id>``),
    so it needs a registry plus prefix rules across the evaluation schema and the differ rather
    than one Literal. Until that lands, treat adding a reason as a contract change, not a string
    edit: check the differ and the evaluation artifacts before introducing one.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class DeterministicD1Proposer:
    """Build the one frozen D1 rollback only from this run's three evidence records."""

    _required_tools = (
        "observability.health",
        "observability.deployment_diff",
        "observability.logs",
    )

    def propose(
        self,
        incident: IncidentIdentity,
        caller: Caller,
        context: ToolCallContext,
        records: tuple[EvidenceRecord, ...],
    ) -> tuple[Hypothesis, CanonicalAction]:
        if context.incident_id != incident.incident_id or context.thread_id != incident.thread_id:
            raise ProposalError(PROPOSAL_CONTEXT_MISMATCH)
        matching = {
            tool_name: [
                record
                for record in records
                if record.tool_name == tool_name
                and record.incident_id == incident.incident_id
                and record.thread_id == incident.thread_id
                and record.correlation_id == context.correlation_id
            ]
            for tool_name in self._required_tools
        }
        if any(not records_for_tool for records_for_tool in matching.values()):
            raise ProposalError(PROPOSAL_MISSING_REQUIRED_EVIDENCE)
        if any(len(records_for_tool) != 1 for records_for_tool in matching.values()):
            raise ProposalError(PROPOSAL_AMBIGUOUS_EVIDENCE)

        health, diff, logs = (matching[tool_name][0] for tool_name in self._required_tools)
        health_payload, diff_payload = health.payload, diff.payload
        if (
            health_payload.get("component") != "api"
            or health_payload.get("revision") != "v2"
            or health_payload.get("status") != 500
        ):
            raise ProposalError(PROPOSAL_NO_D1_FAULT)
        if (
            diff_payload.get("component") != "api"
            or diff_payload.get("from_revision") != "v1"
            or diff_payload.get("to_revision") != "v2"
        ):
            raise ProposalError(PROPOSAL_WRONG_REVISION_DIFF)
        # The log is a required citation, but its free text is untrusted data and is
        # never used to select authority, identity, tool, or action arguments.
        del logs
        evidence_ids = tuple(
            record.evidence_id for record in (health, diff, matching["observability.logs"][0])
        )
        hypothesis = Hypothesis(
            hypothesis_id="d1-bad-deploy",
            statement="bad deployment",
            confidence=1.0,
            evidence_ids=evidence_ids,
        )
        action = CanonicalAction(
            tool_name="operations.rollback",
            incident_id=incident.incident_id,
            thread_id=incident.thread_id,
            actor=caller.actor,
            permission=context.permission,
            evidence_ids=evidence_ids,
            arguments=RollbackArgs(kind="rollback", component="api", target_revision="v1"),
        )
        return hypothesis, action


class _CheckpointProposer:
    """Shared deterministic evidence binding for the additive checkpoint scenarios."""

    _required_tools: tuple[str, ...]

    def _records(
        self,
        incident: IncidentIdentity,
        context: ToolCallContext,
        records: tuple[EvidenceRecord, ...],
    ) -> tuple[EvidenceRecord, ...]:
        if context.incident_id != incident.incident_id or context.thread_id != incident.thread_id:
            raise ProposalError(PROPOSAL_CONTEXT_MISMATCH)
        matching = {
            name: [
                record
                for record in records
                if record.tool_name == name
                and record.incident_id == incident.incident_id
                and record.thread_id == incident.thread_id
                and record.correlation_id == context.correlation_id
            ]
            for name in self._required_tools
        }
        if any(not matches for matches in matching.values()):
            raise ProposalError(PROPOSAL_MISSING_REQUIRED_EVIDENCE)
        if any(len(matches) != 1 for matches in matching.values()):
            raise ProposalError(PROPOSAL_AMBIGUOUS_EVIDENCE)
        return tuple(matching[name][0] for name in self._required_tools)


class DeterministicD2Proposer(_CheckpointProposer):
    _required_tools = ("observability.health", "observability.config_diff", "observability.logs")

    def propose(
        self,
        incident: IncidentIdentity,
        caller: Caller,
        context: ToolCallContext,
        records: tuple[EvidenceRecord, ...],
    ) -> tuple[Hypothesis, CanonicalAction]:
        health, config, logs = self._records(incident, context, records)
        if health.payload.get("component") != "api" or health.payload.get("status") != 500:
            raise ProposalError(PROPOSAL_WRONG_STATE)
        if (
            config.payload.get("component") != "api"
            or config.payload.get("variable_name") != "REQUIRED_API_URL"
            or config.payload.get("present") is not False
            or config.payload.get("approved_value_ref") != "config://approved/REQUIRED_API_URL"
        ):
            raise ProposalError(PROPOSAL_WRONG_CONFIG)
        evidence_ids = tuple(record.evidence_id for record in (health, config, logs))
        return Hypothesis(
            hypothesis_id="d2-missing-required-api-url",
            statement="required API URL missing",
            confidence=1.0,
            evidence_ids=evidence_ids,
        ), CanonicalAction(
            tool_name="operations.restore_config",
            incident_id=incident.incident_id,
            thread_id=incident.thread_id,
            actor=caller.actor,
            permission=context.permission,
            evidence_ids=evidence_ids,
            arguments=RestoreConfigArgs(
                kind="restore_config",
                component="api",
                variable_name="REQUIRED_API_URL",
                approved_value_ref="config://approved/REQUIRED_API_URL",
            ),
        )


class DeterministicD3Proposer(_CheckpointProposer):
    _required_tools = (
        "observability.health",
        "metrics.db_pool",
        "observability.logs",
    )

    def propose(
        self,
        incident: IncidentIdentity,
        caller: Caller,
        context: ToolCallContext,
        records: tuple[EvidenceRecord, ...],
    ) -> tuple[Hypothesis, CanonicalAction]:
        health, metrics, logs = self._records(incident, context, records)
        if health.payload.get("component") != "api" or health.payload.get("status") != 503:
            raise ProposalError(PROPOSAL_WRONG_STATE)
        used, capacity = metrics.payload.get("used"), metrics.payload.get("capacity")
        if (
            metrics.payload.get("component") != "api"
            or not isinstance(used, int)
            or not isinstance(capacity, int)
        ):
            raise ProposalError(PROPOSAL_WRONG_STATE)
        if capacity <= 0 or used < capacity:
            raise ProposalError(PROPOSAL_BELOW_THRESHOLD)
        if used != capacity:
            raise ProposalError(PROPOSAL_WRONG_STATE)
        evidence_ids = tuple(record.evidence_id for record in (health, metrics, logs))
        return Hypothesis(
            hypothesis_id="d3-db-pool-exhausted",
            statement="database pool exhausted",
            confidence=1.0,
            evidence_ids=evidence_ids,
        ), CanonicalAction(
            tool_name="operations.restart",
            incident_id=incident.incident_id,
            thread_id=incident.thread_id,
            actor=caller.actor,
            permission=context.permission,
            evidence_ids=evidence_ids,
            arguments=RestartArgs(kind="restart", component="api"),
        )


class DeterministicD5Proposer(_CheckpointProposer):
    _required_tools = (
        "observability.disk_metrics",
        "observability.log_volume",
        "observability.health",
    )

    def propose(
        self,
        incident: IncidentIdentity,
        caller: Caller,
        context: ToolCallContext,
        records: tuple[EvidenceRecord, ...],
    ) -> tuple[Hypothesis, CanonicalAction]:
        disk, logs, health = self._records(incident, context, records)
        if (
            disk.payload.get("component") != "api"
            or disk.payload.get("free_bytes") != 32 * 1024 * 1024
            or logs.payload.get("bytes") != 96 * 1024 * 1024
            or health.payload.get("status") != 503
        ):
            raise ProposalError(PROPOSAL_WRONG_STATE)
        ids = tuple(record.evidence_id for record in (disk, logs, health))
        return Hypothesis(
            hypothesis_id="d5-log-growth",
            statement="disk pressure from log growth",
            confidence=1.0,
            evidence_ids=ids,
        ), CanonicalAction(
            tool_name="operations.cleanup",
            incident_id=incident.incident_id,
            thread_id=incident.thread_id,
            actor=caller.actor,
            permission=context.permission,
            evidence_ids=ids,
            arguments=CleanupArgs(
                kind="cleanup",
                component="api",
                cleanup_scope="simulated_logs",
                max_bytes=67_108_864,
            ),
        )


class DeterministicD8Proposer(_CheckpointProposer):
    _required_tools = ("observability.health",)

    def propose(
        self,
        incident: IncidentIdentity,
        caller: Caller,
        context: ToolCallContext,
        records: tuple[EvidenceRecord, ...],
    ) -> tuple[Hypothesis, CanonicalAction]:
        (health,) = self._records(incident, context, records)
        if health.payload.get("component") != "api" or health.payload.get("status") != 503:
            raise ProposalError(PROPOSAL_WRONG_STATE)
        ids = (health.evidence_id,)
        return Hypothesis(
            hypothesis_id="d8-duplicate-delivery",
            statement="duplicate operation delivery",
            confidence=1.0,
            evidence_ids=ids,
        ), CanonicalAction(
            tool_name="operations.restart",
            incident_id=incident.incident_id,
            thread_id=incident.thread_id,
            actor=caller.actor,
            permission=context.permission,
            evidence_ids=ids,
            arguments=RestartArgs(kind="restart", component="api"),
        )


class _ReliabilityProposer(_CheckpointProposer):
    """Exact evidence-to-capability binding for the first runnable R scenarios."""

    hypothesis_id: str
    statement: str

    def _action(
        self,
        incident: IncidentIdentity,
        caller: Caller,
        context: ToolCallContext,
        ids: tuple[str, ...],
    ) -> CanonicalAction:
        raise NotImplementedError

    def propose(
        self,
        incident: IncidentIdentity,
        caller: Caller,
        context: ToolCallContext,
        records: tuple[EvidenceRecord, ...],
    ) -> tuple[Hypothesis, CanonicalAction]:
        matched = self._records(incident, context, records)
        if any(
            item.actor != caller.actor or item.permission != "observability:read"
            for item in matched
        ) or not self._valid(matched):
            raise ProposalError(PROPOSAL_WRONG_RELIABILITY_FIXTURE)
        ids = tuple(item.evidence_id for item in matched)
        return Hypothesis(
            hypothesis_id=self.hypothesis_id,
            statement=self.statement,
            confidence=1.0,
            evidence_ids=ids,
        ), self._action(incident, caller, context, ids)

    def _valid(self, records: tuple[EvidenceRecord, ...]) -> bool:
        raise NotImplementedError


class DeterministicR01Proposer(_ReliabilityProposer):
    _required_tools = ("observability.deployment_diff", "observability.database_schema")
    hypothesis_id, statement = (
        "r01-bad-schema-migration",
        "incompatible database migration: schema 2026.08.10.5 is ahead of api-2.4.1",
    )

    def _valid(self, r: tuple[EvidenceRecord, ...]) -> bool:
        return r[0].payload == {
            "schema_version": "2026.08.10.5",
            "release": "api-2.4.1",
            "billing_plan_required": True,
        } and r[1].payload == {"schema_version": "2026.08.10.5", "billing_plan_required": True}

    def _action(
        self, i: IncidentIdentity, c: Caller, x: ToolCallContext, ids: tuple[str, ...]
    ) -> CanonicalAction:
        return CanonicalAction(
            tool_name="operations.rollback_migration_2026_08_10_5",
            incident_id=i.incident_id,
            thread_id=i.thread_id,
            actor=c.actor,
            permission=x.permission,
            evidence_ids=ids,
            arguments=RollbackMigration202608105Args(
                kind="rollback_migration_2026_08_10_5", schema_version="2026.08.10.4"
            ),
        )


class DeterministicR02Proposer(_ReliabilityProposer):
    _required_tools = (
        "observability.feature_flags",
        "observability.http_metrics",
        "observability.error_logs",
    )
    hypothesis_id, statement = (
        "r02-checkout-flag",
        "bad feature flag: checkout_v2 is causing the checkout 500 spike",
    )

    def _valid(self, r: tuple[EvidenceRecord, ...]) -> bool:
        return (
            r[0].payload == {"checkout_v2": True, "rollout": 100}
            and r[1].payload == {"checkout_5xx_rate": 1}
            and r[2].payload == {"classification": "checkout_v2_5xx"}
        )

    def _action(
        self, i: IncidentIdentity, c: Caller, x: ToolCallContext, ids: tuple[str, ...]
    ) -> CanonicalAction:
        return CanonicalAction(
            tool_name="operations.disable_flag_checkout_v2",
            incident_id=i.incident_id,
            thread_id=i.thread_id,
            actor=c.actor,
            permission=x.permission,
            evidence_ids=ids,
            arguments=DisableFlagCheckoutV2Args(
                kind="disable_flag_checkout_v2", flag="checkout_v2", enabled=False
            ),
        )


class DeterministicR03Proposer(_ReliabilityProposer):
    _required_tools = ("observability.config_snapshot", "observability.error_logs")
    hypothesis_id, statement = (
        "r03-payment-timeout",
        "corrupt configuration value: PAYMENT_TIMEOUT_MS is nonnumeric",
    )

    def _valid(self, r: tuple[EvidenceRecord, ...]) -> bool:
        return r[0].payload == {"PAYMENT_TIMEOUT_MS": "fast", "config_version": "cfg-b02"} and r[
            1
        ].payload == {"classification": "payment_timeout_invalid"}

    def _action(
        self, i: IncidentIdentity, c: Caller, x: ToolCallContext, ids: tuple[str, ...]
    ) -> CanonicalAction:
        return CanonicalAction(
            tool_name="operations.restore_config_PAYMENT_TIMEOUT_MS_3000",
            incident_id=i.incident_id,
            thread_id=i.thread_id,
            actor=c.actor,
            permission=x.permission,
            evidence_ids=ids,
            arguments=RestoreConfigPaymentTimeoutMs3000Args(
                kind="restore_config_PAYMENT_TIMEOUT_MS_3000",
                variable_name="PAYMENT_TIMEOUT_MS",
                value="3000",
                config_version="cfg-a17",
            ),
        )


class DeterministicR04Proposer(_ReliabilityProposer):
    _required_tools = ("observability.deployment_diff", "observability.pod_inventory")
    hypothesis_id, statement = (
        "r04-bad-api-release",
        "partial rollout: mixed api-2.4.0 and api-2.4.1 pod versions",
    )

    def _valid(self, r: tuple[EvidenceRecord, ...]) -> bool:
        return r[0].payload == {"old_pods": 8, "new_pods": 4} and r[1].payload == {
            "old_pods": 8,
            "new_pods": 4,
        }

    def _action(
        self, i: IncidentIdentity, c: Caller, x: ToolCallContext, ids: tuple[str, ...]
    ) -> CanonicalAction:
        return CanonicalAction(
            tool_name="operations.rollback_release_api_2_4_1",
            incident_id=i.incident_id,
            thread_id=i.thread_id,
            actor=c.actor,
            permission=x.permission,
            evidence_ids=ids,
            arguments=RollbackReleaseApi241Args(
                kind="rollback_release_api_2_4_1", component="api", old_pods=12, new_pods=0
            ),
        )


class DeterministicR06Proposer(_ReliabilityProposer):
    _required_tools = ("observability.query_plan", "observability.query_metrics")
    hypothesis_id, statement = (
        "r06-orders-index",
        "slow query: orders lookup is missing idx_orders_customer",
    )

    def _valid(self, r: tuple[EvidenceRecord, ...]) -> bool:
        return r[0].payload == {"index": None, "query": "orders_lookup"} and r[1].payload == {
            "query": "orders_lookup",
            "p95_ms": 2400,
        }

    def _action(
        self, i: IncidentIdentity, c: Caller, x: ToolCallContext, ids: tuple[str, ...]
    ) -> CanonicalAction:
        return CanonicalAction(
            tool_name="operations.enable_query_plan_baseline_orders",
            incident_id=i.incident_id,
            thread_id=i.thread_id,
            actor=c.actor,
            permission=x.permission,
            evidence_ids=ids,
            arguments=EnableQueryPlanBaselineOrdersArgs(
                kind="enable_query_plan_baseline_orders", index="idx_orders_customer"
            ),
        )


class DeterministicR07Proposer(_ReliabilityProposer):
    _required_tools = ("observability.replica_status", "observability.request_routing")
    hypothesis_id, statement = "r07-replica-lag", "stale read caused by replica-a lag of 95 seconds"

    def _valid(self, r: tuple[EvidenceRecord, ...]) -> bool:
        return r[0].payload == {"replica": "replica-a", "lag_seconds": 95} and r[1].payload == {
            "customer_reads": "replica-a"
        }

    def _action(
        self, i: IncidentIdentity, c: Caller, x: ToolCallContext, ids: tuple[str, ...]
    ) -> CanonicalAction:
        return CanonicalAction(
            tool_name="operations.route_customer_reads_primary",
            incident_id=i.incident_id,
            thread_id=i.thread_id,
            actor=c.actor,
            permission=x.permission,
            evidence_ids=ids,
            arguments=RouteCustomerReadsPrimaryArgs(
                kind="route_customer_reads_primary", routing="primary"
            ),
        )


class DeterministicR08Proposer(_ReliabilityProposer):
    _required_tools = ("observability.credential_status", "observability.database_health")
    hypothesis_id, statement = (
        "r08-expired-db-credential",
        "expired service database credential db-app-2026-08",
    )

    def _valid(self, r: tuple[EvidenceRecord, ...]) -> bool:
        return r[0].payload == {"active_id": "db-app-2026-08", "status": "expired"} and r[
            1
        ].payload == {"auth_status": "28000"}

    def _action(
        self, i: IncidentIdentity, c: Caller, x: ToolCallContext, ids: tuple[str, ...]
    ) -> CanonicalAction:
        return CanonicalAction(
            tool_name="operations.rotate_credential_db_app_2026_09",
            incident_id=i.incident_id,
            thread_id=i.thread_id,
            actor=c.actor,
            permission=x.permission,
            evidence_ids=ids,
            arguments=RotateCredentialDbApp202609Args(
                kind="rotate_credential_db_app_2026_09", active_id="db-app-2026-09"
            ),
        )


class DeterministicR09Proposer(_ReliabilityProposer):
    _required_tools = ("observability.dependency_metrics", "observability.error_logs")
    hypothesis_id, statement = (
        "r09-partner-rate-limit",
        "dependency rate limit exceeded: partner API returns HTTP 429",
    )

    def _valid(self, r: tuple[EvidenceRecord, ...]) -> bool:
        return r[0].payload == {
            "partner": "synthetic.partner.local",
            "request_rate_per_minute": 160,
            "http_429_rate": 1,
        } and r[1].payload == {"classification": "partner_http_429"}

    def _action(
        self, i: IncidentIdentity, c: Caller, x: ToolCallContext, ids: tuple[str, ...]
    ) -> CanonicalAction:
        return CanonicalAction(
            tool_name="operations.enable_partner_backoff_60s",
            incident_id=i.incident_id,
            thread_id=i.thread_id,
            actor=c.actor,
            permission=x.permission,
            evidence_ids=ids,
            arguments=EnablePartnerBackoff60sArgs(
                kind="enable_partner_backoff_60s", backoff_seconds=60
            ),
        )


class DeterministicR12Proposer(_ReliabilityProposer):
    _required_tools = ("observability.schema_validation", "observability.deployment_diff")
    hypothesis_id, statement = (
        "r12-response-schema-drift",
        "response-schema drift: customer_id changed from string to object",
    )

    def _valid(self, r: tuple[EvidenceRecord, ...]) -> bool:
        return r[0].payload == {
            "field": "customer_id",
            "expected_type": "string",
            "actual_type": "object",
            "error_count": 1,
        } and r[1].payload == {"response_adapter": "none"}

    def _action(
        self, i: IncidentIdentity, c: Caller, x: ToolCallContext, ids: tuple[str, ...]
    ) -> CanonicalAction:
        return CanonicalAction(
            tool_name="operations.activate_local_response_adapter_3_8_3",
            incident_id=i.incident_id,
            thread_id=i.thread_id,
            actor=c.actor,
            permission=x.permission,
            evidence_ids=ids,
            arguments=ActivateLocalResponseAdapter383Args(
                kind="activate_local_response_adapter_3_8_3", response_adapter="local-3.8.3"
            ),
        )
