"""Live Postgres acceptance coverage for the D5/D8 local fixture workflows."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from triage_agent_lab.contracts import IncidentIdentity, Role, ToolCallContext
from triage_agent_lab.control.models import Caller
from triage_agent_lab.host.app import HostSettings, create_host_app
from triage_agent_lab.integration import IncidentRuntime, PendingApproval
from triage_agent_lab.lab.auth import Principal
from triage_agent_lab.lab.errors import ResponseLost
from triage_agent_lab.lab.repository import D1Repository
from triage_agent_lab.telemetry import create_tracer_runtime


@pytest.fixture
def repository() -> D1Repository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("D5/D8 integration requires DATABASE_URL")
    repository = D1Repository(dsn)
    repository.migrate()
    return repository


def inputs(scenario: str) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    thread = f"{scenario.lower()}-{uuid4().hex[:12]}"
    incident = IncidentIdentity(incident_id=f"INC-{scenario}", scenario_id=scenario,
                                thread_id=thread, correlation_id=f"corr-{thread}")
    return incident, Caller(actor="operator-1", role=Role.OPERATOR), ToolCallContext(
        incident_id=incident.incident_id, thread_id=thread, correlation_id=incident.correlation_id,
        actor="operator-1", permission="operations:write")


def test_d5_approved_cleanup_is_exactly_bounded_and_reject_is_side_effect_free(repository: D1Repository) -> None:
    repository.reset_checkpoint("D5"); repository.inject_checkpoint("D5")
    incident, caller, context = inputs("D5")
    with IncidentRuntime(repository.dsn) as runtime:
        pending = runtime.start(incident, caller, context)
        assert isinstance(pending, PendingApproval)
        assert pending.tool_name == "operations.cleanup"
        assert pending.evidence_ids
        rejected = runtime.reject(incident.thread_id, Principal("approver-1", Role.APPROVER))
        assert rejected.result is not None and rejected.result.final_state == "blocked"
    assert repository.checkpoint_state("D5")["mutation_count"] == 0
    assert repository.operation_count("INC-D5") == 0
    repository.reset_checkpoint("D5"); repository.inject_checkpoint("D5")
    incident, caller, context = inputs("D5")
    with IncidentRuntime(repository.dsn) as runtime:
        assert isinstance(runtime.start(incident, caller, context), PendingApproval)
        complete = runtime.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
    assert complete.result is not None and complete.result.verification.passed
    assert complete.result.operation.result["removed_bytes"] == 64 * 1024 * 1024
    assert repository.approval_consumed(complete.result.operation.approval_token_id)
    state = repository.checkpoint_state("D5")
    assert state["log_bytes"] == 32 * 1024 * 1024 and state["free_bytes"] == 96 * 1024 * 1024 and state["mutation_count"] == 1
    assert repository.operation_count("INC-D5") == 1
    repository.reset_checkpoint("D5")


def test_d8_fresh_runtime_retry_replays_one_committed_restart(repository: D1Repository) -> None:
    repository.reset_checkpoint("D8"); repository.inject_checkpoint("D8")
    incident, caller, context = inputs("D8")
    with IncidentRuntime(repository.dsn, response_loss_once=True) as first:
        assert isinstance(first.start(incident, caller, context), PendingApproval)
        with pytest.raises(ResponseLost):
            first.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
    with IncidentRuntime(repository.dsn) as second:
        resumed = second.resume(incident.thread_id)
        assert resumed.thread_id == incident.thread_id
        replay = second.retry(incident.thread_id)
    assert replay.result is not None
    assert replay.result.operation.status.value == "duplicate"
    assert replay.result.verification.passed
    state = repository.checkpoint_state("D8")
    assert state["mutation_count"] == 1
    assert repository.operation_count("INC-D8") == 1
    assert repository.operation_matches(replay.result.operation)
    forged = replay.result.operation.model_copy(
        update={"context": replay.result.operation.context.model_copy(update={"correlation_id": "forged"})}
    )
    assert not repository.operation_matches(forged)
    repository.reset_checkpoint("D8")


@pytest.mark.parametrize("scenario", ("D5", "D8"))
def test_d5_d8_runtime_emits_one_safe_workflow_phase_trace(repository: D1Repository, scenario: str) -> None:
    repository.reset_checkpoint(scenario); repository.inject_checkpoint(scenario)
    incident, caller, context = inputs(scenario)
    exporter = InMemorySpanExporter()
    telemetry = create_tracer_runtime(processors=(SimpleSpanProcessor(exporter),))
    with IncidentRuntime(repository.dsn, telemetry=telemetry) as runtime:
        runtime.start(incident, caller, context)
        runtime.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
    prefix = scenario.lower()
    spans = [span for span in exporter.get_finished_spans() if span.name.startswith(f"{prefix}.")]
    assert {span.name for span in spans} >= {f"{prefix}.workflow", f"{prefix}.policy", f"{prefix}.monitor", f"{prefix}.approval", f"{prefix}.verification"}
    assert len({span.context.trace_id for span in spans}) == 1
    assert all("secret" not in str(span.attributes).lower() for span in spans)
    telemetry.shutdown(); repository.reset_checkpoint(scenario)


def _nonce(page: str, position: int = 0) -> str:
    return page.split("name='nonce' value='")[position + 1].split("'")[0]


@pytest.mark.parametrize(
    ("scenario", "proposed", "decision", "expected_operations"),
    (("D5", "bounded simulated-log cleanup (cap 64 MiB)", "approve", 1), ("D5", "bounded simulated-log cleanup (cap 64 MiB)", "reject", 0), ("D8", "operations.restart api", "approve", 1)),
)
def test_fresh_host_ui_resumes_d5_d8_pending_without_sensitive_action_material(
    repository: D1Repository, scenario: str, proposed: str, decision: str, expected_operations: int
) -> None:
    """A newly built host resumes each mutable checkpoint without secret material."""
    repository.reset_checkpoint(scenario)
    settings = HostSettings(database_url=repository.dsn)
    first = TestClient(create_host_app(settings))
    first.post("/mock-login", data={"actor": "operator-1"})
    home = first.get("/")
    scenario_nonce = home.text.split(f"action='/incidents/{scenario.lower()}/prepare'>")[1].split("value='")[1].split("'")[0]
    prepared = first.post(f"/incidents/{scenario.lower()}/prepare", data={"nonce": scenario_nonce}, follow_redirects=False)
    assert prepared.status_code == 303, prepared.text
    thread = prepared.headers["location"].split("/")[2]
    start = first.get(f"/incidents/{thread}/start")
    assert first.post(f"/incidents/{thread}/start", data={"nonce": _nonce(start.text)}, follow_redirects=False).status_code == 303

    second = TestClient(create_host_app(settings))
    second.post("/mock-login", data={"actor": "approver-1"})
    pending = second.get(f"/threads/{thread}")
    assert proposed in pending.text
    assert all(word not in pending.text.lower() for word in ("approval token", "token", "secret", "idempotency", "100663296", "33554432"))
    assert second.post(f"/threads/{thread}/approve", headers={"X-D1-Actor": "operator-1"}).status_code == 403
    assert second.post(f"/threads/{thread}/{decision}", data={"nonce": _nonce(pending.text, 0 if decision == "approve" else 1)}, follow_redirects=False).status_code == 303
    assert repository.operation_count(f"INC-{scenario}") == expected_operations
    repository.reset_checkpoint(scenario)
