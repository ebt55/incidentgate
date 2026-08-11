"""Live durable checks for the public D1 runtime boundary."""

from __future__ import annotations

import os
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from triage_agent_lab.contracts import IncidentIdentity, Role, ToolCallContext
from triage_agent_lab.control.models import Caller
from triage_agent_lab.integration import D1Runtime, PendingApproval
from triage_agent_lab.lab.auth import Principal
from triage_agent_lab.lab.errors import ApprovalDenied, ResponseLost
from triage_agent_lab.lab.repository import D1Repository
from triage_agent_lab.telemetry import create_tracer_runtime


@pytest.fixture
def repository() -> D1Repository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("Postgres D1 integration requires DATABASE_URL")
    repository = D1Repository(dsn)
    repository.migrate()
    repository.reset_d1()
    repository.inject_d1()
    return repository


def inputs(thread_id: str) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    thread_id = f"{thread_id}-{uuid4().hex[:12]}"
    incident = IncidentIdentity(
        incident_id="INC-D1", scenario_id="D1", thread_id=thread_id, correlation_id=f"corr-{thread_id}"
    )
    caller = Caller(actor="operator-1", role=Role.OPERATOR)
    context = ToolCallContext(
        incident_id="INC-D1", thread_id=thread_id, correlation_id=f"corr-{thread_id}",
        actor="operator-1", permission="operations:write",
    )
    return incident, caller, context


def pickle_rows(repository: D1Repository, thread_id: str) -> int:
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) AS total FROM checkpoint_blobs WHERE thread_id = %s AND type = 'pickle'",
            (thread_id,),
        )
        return int(cursor.fetchone()["total"])


def ledger_rows(repository: D1Repository, thread_id: str, action_hash: str) -> int:
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) AS total FROM operation_ledger WHERE thread_id = %s AND action_hash = %s",
            (thread_id, action_hash),
        )
        return int(cursor.fetchone()["total"])


def test_start_interrupts_then_recreated_runtime_approves(repository: D1Repository) -> None:
    dsn = repository.dsn
    incident, caller, context = inputs("durable-approval")
    with D1Runtime(dsn) as first:
        pending = first.start(incident, caller, context)
        assert isinstance(pending, PendingApproval)
        assert (pending.tool_name, pending.component, pending.target_revision) == (
            "operations.rollback", "api", "v1"
        )
        assert repository.state() == {"revision": "v2", "health_status": 500, "mutation_count": 0}
        assert ledger_rows(repository, incident.thread_id, pending.action_hash) == 0
        assert pickle_rows(repository, incident.thread_id) == 0
        preapproval = first.timeline("INC-D1")
        assert [event.transition for event in preapproval] == ["policy", "monitor"]
    with D1Runtime(dsn) as second:
        status = second.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
        assert status.result is not None and status.result.final_state == "resolved"
        assert status.result.verification is not None
        assert status.result.verification.evidence_ids[0] not in pending.evidence_ids
        assert status.result.report is not None
        assert status.result.report.evidence_ids == pending.evidence_ids
        assert pickle_rows(repository, incident.thread_id) == 0
        timeline = second.timeline("INC-D1")
        transitions = [event.transition for event in timeline]
        assert [transitions.index(transition) for transition in ("policy", "monitor", "approval", "execution", "verification")] == sorted(
            transitions.index(transition) for transition in ("policy", "monitor", "approval", "execution", "verification")
        )
        assert "rollback_committed" in transitions
        assert "token" not in str([event.model_dump() for event in timeline]).lower()
        assert transitions.count("policy") == transitions.count("monitor") == 1
    assert repository.state() == {"revision": "v1", "health_status": 200, "mutation_count": 1}


def test_non_approver_cannot_approve_or_mutate(repository: D1Repository) -> None:
    incident, caller, context = inputs("role-denial")
    with D1Runtime(repository.dsn) as runtime:
        runtime.start(incident, caller, context)
        with pytest.raises(ApprovalDenied, match="approver role"):
            runtime.approve(incident.thread_id, Principal("operator-1", Role.OPERATOR))
        with pytest.raises(PermissionError, match="authenticated approver"):
            runtime.reject(incident.thread_id, Principal("operator-1", Role.OPERATOR))
        with pytest.raises(ValueError, match="no pending approval"):
            runtime.approve("unknown-thread", Principal("approver-1", Role.APPROVER))
        with pytest.raises(ValueError, match="unknown D1 runtime thread"):
            runtime.retry("unknown-thread")
    assert repository.state() == {"revision": "v2", "health_status": 500, "mutation_count": 0}


def test_trace_url_failure_keeps_pending_and_status_available(repository: D1Repository) -> None:
    class FailingTraceUrlClient:
        def get_trace_url(self, *, trace_id: str | None = None) -> str:
            raise RuntimeError("Langfuse is unavailable")

    telemetry = create_tracer_runtime()
    telemetry.client = FailingTraceUrlClient()
    incident, caller, context = inputs("trace-url-failure")
    try:
        with D1Runtime(repository.dsn, telemetry=telemetry) as runtime:
            pending = runtime.start(incident, caller, context)
            assert isinstance(pending, PendingApproval)
            assert pending.trace_id is not None
            assert pending.trace_url is None
            status = runtime.status(incident.thread_id)
            assert status.trace_id == pending.trace_id
            assert status.trace_url is None
            assert status.pending is not None
            assert repository.state() == {"revision": "v2", "health_status": 500, "mutation_count": 0}
            assert ledger_rows(repository, incident.thread_id, pending.action_hash) == 0
    finally:
        telemetry.shutdown()


def test_rejection_and_repeat_approval_never_create_extra_mutations(repository: D1Repository) -> None:
    rejected, caller, context = inputs("rejection")
    with D1Runtime(repository.dsn) as runtime:
        runtime.start(rejected, caller, context)
        status = runtime.reject(rejected.thread_id, Principal("approver-1", Role.APPROVER))
        assert status.result is not None and status.result.final_state == "blocked"
    assert repository.state()["mutation_count"] == 0

    repository.reset_d1()
    repository.inject_d1()
    approved, caller, context = inputs("double-approval")
    with D1Runtime(repository.dsn) as runtime:
        runtime.start(approved, caller, context)
        runtime.approve(approved.thread_id, Principal("approver-1", Role.APPROVER))
        with pytest.raises(ValueError, match="no pending approval"):
            runtime.approve(approved.thread_id, Principal("approver-1", Role.APPROVER))
        with pytest.raises(ValueError, match="no pending approval"):
            runtime.reject(approved.thread_id, Principal("approver-1", Role.APPROVER))
    assert repository.state()["mutation_count"] == 1


def test_zero_ttl_cannot_issue_or_execute(repository: D1Repository) -> None:
    incident, caller, context = inputs("expired-request")
    with D1Runtime(repository.dsn, approval_ttl=timedelta()) as runtime:
        runtime.start(incident, caller, context)
        with pytest.raises(ValidationError):
            runtime.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
    assert repository.state() == {"revision": "v2", "health_status": 500, "mutation_count": 0}


def test_response_loss_retries_from_durable_checkpoint_once(repository: D1Repository) -> None:
    dsn = repository.dsn
    incident, caller, context = inputs("durable-response-loss")
    with D1Runtime(dsn, response_loss_once=True) as first:
        first.start(incident, caller, context)
        pending = first.status(incident.thread_id).pending
        assert pending is not None
        assert [event.transition for event in first.timeline("INC-D1")] == ["policy", "monitor"]
        with pytest.raises(ResponseLost):
            first.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
    with D1Runtime(dsn) as second:
        status = second.retry(incident.thread_id)
        assert status.result is not None and status.result.operation is not None
        assert status.result.operation.status.value == "duplicate"
        assert status.result.operation.idempotency_key == status.result.idempotency_key
        assert status.result.operation.action_hash == pending.action_hash
        assert status.result.final_state == "resolved"
        assert ledger_rows(repository, incident.thread_id, pending.action_hash) == 1
        transitions = [event.transition for event in second.timeline("INC-D1")]
        assert transitions.count("policy") == transitions.count("monitor") == 1
    assert repository.state() == {"revision": "v1", "health_status": 200, "mutation_count": 1}
