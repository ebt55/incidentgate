from datetime import UTC, datetime, timedelta
from typing import Never
from uuid import uuid4

import pytest

from triage_agent_lab.contracts import (
    ApprovalToken,
    CanonicalAction,
    EvidenceRecord,
    Role,
    ToolCallContext,
    canonical_action_hash,
)
from triage_agent_lab.lab.auth import Principal
from triage_agent_lab.lab.errors import ApprovalDenied, PermissionDenied
from triage_agent_lab.lab.service import ObservabilityService, OperationsService, TicketsService
from triage_agent_lab.mcp_servers.entrypoints import (
    observability_server,
    operations_server,
    tickets_server,
)
from triage_agent_lab.mcp_servers.observability import ObservabilityAdapter
from triage_agent_lab.mcp_servers.operations import OperationsAdapter
from triage_agent_lab.mcp_servers.tickets import TicketsAdapter


class FakeObservabilityRepository:
    def evidence(self, context: ToolCallContext, kind: str) -> EvidenceRecord:
        now = datetime.now(UTC)
        return EvidenceRecord(
            evidence_id="e-1",
            incident_id=context.incident_id,
            thread_id=context.thread_id,
            correlation_id=context.correlation_id,
            tool_name=f"observability.{kind}",
            actor=context.actor,
            permission=context.permission,
            observed_at=now,
            expires_at=now + timedelta(seconds=1),
            payload={"kind": kind},
        )


class FakeOperationsRepository:
    def rollback(
        self,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        response_loss: bool = False,
    ) -> Never:
        del context, action, token, response_loss
        raise AssertionError("not reached in this adapter boundary test")

    def restore_config(
        self, context: ToolCallContext, action: CanonicalAction, token: ApprovalToken,
        response_loss: bool = False,
    ) -> Never:
        del context, action, token, response_loss
        raise AssertionError("not reached in this adapter boundary test")

    def restart(
        self, context: ToolCallContext, action: CanonicalAction, token: ApprovalToken,
        response_loss: bool = False,
    ) -> Never:
        del context, action, token, response_loss
        raise AssertionError("not reached in this adapter boundary test")


class TicketRepository:
    def ticket(self, incident_id: str) -> dict[str, object]:
        return {"ticket_id": "D1-1", "incident_id": incident_id}


def read_context() -> ToolCallContext:
    return ToolCallContext(
        incident_id="INC-D1",
        thread_id="thread-d1",
        correlation_id="corr-d1",
        actor="observer-1",
        permission="observability:read",
    )


def test_observability_adapter_is_bound_and_unsupported_states_are_explicit() -> None:
    adapter = ObservabilityAdapter(ObservabilityService(FakeObservabilityRepository()))
    context = read_context()
    principal = Principal("observer-1", Role.OBSERVER)
    assert adapter.health(context, principal).payload == {"kind": "health"}
    assert adapter.config_diff(context, principal).payload == {"kind": "config_diff"}
    assert adapter.db_pool_metrics(context, principal).payload == {"kind": "db_pool_metrics"}
    assert ObservabilityService(FakeObservabilityRepository()).get(context, principal, "metrics").payload == {"kind": "metrics"}


def test_operations_adapter_keeps_auth_boundary() -> None:
    adapter = OperationsAdapter(OperationsService(FakeOperationsRepository()))
    context = read_context().model_copy(
        update={"actor": "operator-1", "permission": "operations:write", "idempotency_key": uuid4()}
    )
    action = CanonicalAction(
        tool_name="operations.rollback",
        incident_id="INC-D1",
        thread_id="thread-d1",
        actor="operator-1",
        permission="operations:write",
        evidence_ids=("e-1",),
        arguments={"kind": "rollback", "component": "api", "target_revision": "v1"},
    )
    now = datetime.now(UTC)
    token = ApprovalToken(
        action_hash=canonical_action_hash(action),
        actor="operator-1",
        approver="approver-1",
        one_time_use_id=uuid4(),
        requested_at=now,
        expires_at=now + timedelta(minutes=1),
        approved_at=now,
    )
    with pytest.raises(AssertionError):
        adapter.rollback(context, Principal("operator-1", Role.OPERATOR), action, token)
    with pytest.raises(PermissionDenied):
        adapter.rollback(context, Principal("operator-1", Role.OBSERVER), action, token)
    restart = action.model_copy(update={"tool_name": "operations.restart", "arguments": {"kind": "restart", "component": "api"}})
    with pytest.raises(AssertionError):
        adapter.restart(context, Principal("operator-1", Role.OPERATOR), restart, token)


def test_ticket_adapter_read_is_bounded_and_append_is_disabled() -> None:
    adapter = TicketsAdapter(TicketsService(TicketRepository()))
    context = read_context()
    principal = Principal("observer-1", Role.OBSERVER)
    assert adapter.read(context, principal) == {"ticket_id": "D1-1", "incident_id": "INC-D1"}
    with pytest.raises(ApprovalDenied):
        adapter.append(context.model_copy(update={"idempotency_key": uuid4()}), principal, "no bypass")


def test_fastmcp_factories_are_localhost_only_and_stateless() -> None:
    observer = Principal("observer-1", Role.OBSERVER)
    operator = Principal("operator-1", Role.OPERATOR)
    servers = (
        observability_server(ObservabilityService(FakeObservabilityRepository()), observer),
        operations_server(OperationsService(FakeOperationsRepository()), operator),
        tickets_server(TicketsService(TicketRepository()), observer),
    )
    assert [server.name for server in servers] == [
        "incidentgate-observability",
        "incidentgate-operations",
        "incidentgate-tickets",
    ]
    for server in servers:
        assert server.settings.host == "127.0.0.1"
        assert server.settings.stateless_http is True
