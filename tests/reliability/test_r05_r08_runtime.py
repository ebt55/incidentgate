"""Durable public-runtime acceptance coverage for reliability R05--R08."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from mcp.server.fastmcp.exceptions import ToolError
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from incidentgate.contracts import (
    ApprovalRequest,
    EvidenceRecord,
    IncidentIdentity,
    Role,
    ToolCallContext,
    canonical_action_hash,
)
from incidentgate.control.models import Caller
from incidentgate.control.proposal import (
    DeterministicR06Proposer,
    DeterministicR07Proposer,
    DeterministicR08Proposer,
)
from incidentgate.host.app import HostSettings, create_host_app
from incidentgate.integration import IncidentRuntime, PendingApproval
from incidentgate.lab.approval import ApprovalService
from incidentgate.lab.auth import Principal
from incidentgate.lab.errors import ResponseLost
from incidentgate.lab.repository import LabRepository
from incidentgate.lab.service import ObservabilityService, OperationsService
from incidentgate.mcp_servers.entrypoints import observability_server, operations_server
from incidentgate.telemetry import create_tracer_runtime


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("R05-R08 integration requires DATABASE_URL")
    repository = LabRepository(dsn)
    repository.migrate()
    return repository


def _inputs(scenario: str) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    thread = f"{scenario.lower()}-{uuid4().hex[:12]}"
    incident = IncidentIdentity(
        incident_id=f"INC-{scenario}", scenario_id=scenario, thread_id=thread,
        correlation_id=f"corr-{thread}",
    )
    permission = "observability:read" if scenario == "R05" else "operations:write"
    return incident, Caller(actor="operator-1", role=Role.OPERATOR), ToolCallContext(
        incident_id=incident.incident_id, thread_id=thread,
        correlation_id=incident.correlation_id, actor="operator-1", permission=permission,
    )


def test_reliability_evidence_read_reports_its_own_source_not_a_later_one(
    repository: LabRepository,
) -> None:
    """A reliability read must never be re-selected from the incident's newest row."""
    repository.reset_checkpoint("R08")
    repository.inject_checkpoint("R08")
    _, _, context = _inputs("R08")
    read_context = context.model_copy(update={"permission": "observability:read"})
    base = datetime.now(UTC)
    try:
        thirty = base + timedelta(seconds=30)
        later = repository.evidence(read_context, "credential_status", now=thirty)
        earlier = repository.evidence(read_context, "credential_status", now=base)
        assert later.observed_at == thirty
        assert earlier.observed_at == base
        assert earlier.expires_at == base + timedelta(seconds=120)
        assert earlier.source_uri != later.source_uri
    finally:
        repository.reset_checkpoint("R08")


def test_r05_evidence_reads_are_not_corrupted_across_threads_on_one_incident(
    repository: LabRepository,
) -> None:
    """Two threads on one incident must not observe each other's read-cursor payloads."""
    repository.reset_checkpoint("R05")
    repository.inject_checkpoint("R05")
    _, _, first = _inputs("R05")
    _, _, second = _inputs("R05")
    base = datetime.now(UTC)
    try:
        repository.evidence(second, "database_locks", now=base + timedelta(seconds=10))
        repository.evidence(second, "query_metrics", now=base + timedelta(seconds=11))
        recheck = repository.evidence(second, "database_locks", now=base + timedelta(seconds=12))
        assert recheck.payload["auto_release_observed_at_seconds"] == 45
        opening = repository.evidence(first, "database_locks", now=base)
        assert opening.payload == {"blocking_transaction": "tx-4401", "virtual_elapsed_seconds": 0}
        assert opening.observed_at == base
    finally:
        repository.reset_checkpoint("R05")


@pytest.mark.parametrize("scenario", ("R06", "R07", "R08"))
def test_r06_r08_pending_approval_does_not_fabricate_a_component(
    repository: LabRepository, scenario: str
) -> None:
    """These capabilities have no component argument; the interrupt must not invent one."""
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = _inputs(scenario)
    try:
        with IncidentRuntime(repository.dsn) as runtime:
            pending = runtime.start(incident, caller, context)
        assert isinstance(pending, PendingApproval)
        assert pending.component is None
        assert pending.target_revision is None
        assert repository.operation_count(incident.incident_id) == 0
    finally:
        repository.reset_checkpoint(scenario)


def test_r05_no_action_recovers_ordered_durable_reads_after_process_loss(repository: LabRepository) -> None:
    repository.reset_checkpoint("R05")
    repository.inject_checkpoint("R05")
    incident, caller, context = _inputs("R05")
    try:
        with (
            IncidentRuntime(repository.dsn, collection_crash_after_attempt=1) as runtime,
            pytest.raises(RuntimeError, match="process loss"),
        ):
            runtime.start(incident, caller, context)
        with IncidentRuntime(repository.dsn) as runtime:
            runtime.resume(incident.thread_id)
            completed = runtime.retry(incident.thread_id)
        assert completed.result is not None
        assert completed.pending is None
        assert completed.result.final_state == "resolved"
        assert completed.result.report.diagnosis == "database lock contention: tx-4401 blocks orders writes"
        assert completed.result.reasons == ("lock_auto_release_observed_no_action",)
        public_result = completed.result.model_dump(mode="json", exclude_none=True)
        assert all(name not in public_result for name in ("policy", "monitor", "approval", "operation", "idempotency_key"))
        records = repository.r05_resume_evidence(context)
        assert [record.tool_name for record in records] == [
            "observability.database_locks", "observability.query_metrics", "observability.database_locks"
        ]
        assert records[-1].payload["virtual_time_fixture"] is True
        assert records[-1].payload["auto_release_observed_at_seconds"] >= 45
        assert repository.operation_count(incident.incident_id) == 0
        assert repository.checkpoint_state("R05")["mutation_count"] == 0
    finally:
        repository.reset_checkpoint("R05")


@pytest.mark.parametrize("scenario", ("R06", "R07", "R08"))
def test_r06_r08_approval_and_response_loss_replay_are_exact(repository: LabRepository, scenario: str) -> None:
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = _inputs(scenario)
    try:
        with IncidentRuntime(repository.dsn, response_loss_once=True) as runtime:
            assert isinstance(runtime.start(incident, caller, context), PendingApproval)
            with pytest.raises(ResponseLost):
                runtime.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
        with IncidentRuntime(repository.dsn) as runtime:
            runtime.resume(incident.thread_id)
            completed = runtime.retry(incident.thread_id)
        assert completed.result is not None and completed.result.verification is not None
        assert completed.result.operation is not None
        assert completed.result.operation.status.value == "duplicate"
        assert completed.result.verification.passed
        assert repository.operation_count(incident.incident_id) == 1
        if scenario == "R08":
            rendered = str(completed).lower()
            assert all(word not in rendered for word in ("secret", "credential_value", "password"))
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize("scenario", ("R05", "R06", "R07", "R08"))
def test_r05_r08_telemetry_uses_safe_workflow_trace(repository: LabRepository, scenario: str) -> None:
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = _inputs(scenario)
    exporter = InMemorySpanExporter()
    telemetry = create_tracer_runtime(processors=(SimpleSpanProcessor(exporter),))
    try:
        with IncidentRuntime(repository.dsn, telemetry=telemetry) as runtime:
            started = runtime.start(incident, caller, context)
            if scenario != "R05":
                assert isinstance(started, PendingApproval)
                runtime.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
        spans = [span for span in exporter.get_finished_spans() if span.name.startswith(scenario.lower())]
        assert spans and len({span.context.trace_id for span in spans}) == 1
        allowed = {"incident_id", "thread_id", "correlation_id", "actor", "permission", "action_hash", "idempotency_key"}
        assert all(set(span.attributes) <= allowed for span in spans)
    finally:
        telemetry.shutdown()
        repository.reset_checkpoint(scenario)


def test_r05_host_terminal_page_is_safe_and_describes_the_virtual_fixture(repository: LabRepository) -> None:
    repository.reset_checkpoint("R05")
    try:
        client = TestClient(create_host_app(HostSettings(database_url=repository.dsn)))
        client.post("/mock-login", data={"actor": "operator-1"})
        home = client.get("/")
        nonce = home.text.split("action='/incidents/r05/prepare'>")[1].split("value='")[1].split("'")[0]
        prepared = client.post("/incidents/r05/prepare", data={"nonce": nonce}, follow_redirects=False)
        thread = prepared.headers["location"].split("/")[2]
        prompt = client.get(f"/incidents/{thread}/start")
        start_nonce = prompt.text.split("name='nonce' value='")[1].split("'")[0]
        client.post(f"/incidents/{thread}/start", data={"nonce": start_nonce}, follow_redirects=False)
        fresh = TestClient(create_host_app(HostSettings(database_url=repository.dsn)))
        fresh.post("/mock-login", data={"actor": "approver-1"})
        page = fresh.get(f"/threads/{thread}").text.lower()
        assert "deterministic virtual fixture observation" in page and "auto-release" in page and "no-action" in page
        assert all(word not in page for word in ("policy:", "monitor:", "approval", "operation", "idempotency", "token"))
    finally:
        repository.reset_checkpoint("R05")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "reads", "operation", "proposer", "bad_argument"),
    (
        ("R06", ("query_plan", "query_metrics"), "enable_query_plan_baseline_orders", DeterministicR06Proposer, ("index", "wrong-index")),
        ("R07", ("replica_status", "request_routing"), "route_customer_reads_primary", DeterministicR07Proposer, ("routing", "replica-a")),
        ("R08", ("credential_status", "database_health"), "rotate_credential_db_app_2026_09", DeterministicR08Proposer, ("active_id", "db-app-2026-08")),
    ),
)
async def test_public_fastmcp_r05_r08_capabilities_and_safe_denials(
    repository: LabRepository, scenario: str, reads: tuple[str, ...], operation: str,
    proposer: type[object], bad_argument: tuple[str, object],
) -> None:
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, write_context = _inputs(scenario)
    read_context = write_context.model_copy(update={"permission": "observability:read"})
    observe = observability_server(ObservabilityService(repository), Principal("operator-1", Role.OPERATOR))
    execute = operations_server(OperationsService(repository), Principal("operator-1", Role.OPERATOR))
    try:
        assert set(reads) <= {tool.name for tool in await observe.list_tools()}
        assert operation in {tool.name for tool in await execute.list_tools()}
        records = [EvidenceRecord.model_validate((await observe.call_tool(name, {"context": read_context.model_dump(mode="json")}))[1]) for name in reads]
        _, action = proposer().propose(incident, caller, write_context, tuple(records))  # type: ignore[operator]
        now = datetime.now(UTC)
        token = ApprovalService(repository, lambda: now, incident_id=incident.incident_id, thread_id=incident.thread_id).approve(
            ApprovalRequest(action_hash=canonical_action_hash(action), actor=caller.actor, requested_at=now, expires_at=now + timedelta(minutes=5), one_time_use_id=uuid4()), Principal("approver-1", Role.APPROVER)
        )
        context = write_context.model_copy(update={"idempotency_key": uuid4()})
        payload = {"context": context.model_dump(mode="json"), "action": action.model_dump(mode="json"), "token": token.model_dump(mode="json")}
        denied = operations_server(OperationsService(repository), Principal("observer-1", Role.OBSERVER))
        with pytest.raises(ToolError):
            await denied.call_tool(operation, payload)
        malformed = action.model_dump(mode="json")
        malformed["arguments"][bad_argument[0]] = bad_argument[1]  # type: ignore[index]
        with pytest.raises(ToolError):
            await execute.call_tool(operation, {**payload, "action": malformed})
        with pytest.raises(ToolError):
            await execute.call_tool(operation, {**payload, "context": {**payload["context"], "thread_id": "forged-thread"}})
        assert repository.operation_count(incident.incident_id) == 0 and not repository.approval_consumed(token.token_id)
        reply = await execute.call_tool(operation, payload)
        assert "succeeded" in str(reply) and repository.operation_count(incident.incident_id) == 1
        if scenario == "R08":
            assert all(word not in str(reply).lower() for word in ("secret", "password", "credential_value"))
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.asyncio
async def test_r05_fastmcp_exposes_only_read_capabilities(repository: LabRepository) -> None:
    repository.reset_checkpoint("R05")
    repository.inject_checkpoint("R05")
    incident, _, context = _inputs("R05")
    server = observability_server(ObservabilityService(repository), Principal("operator-1", Role.OPERATOR))
    try:
        names = {tool.name for tool in await server.list_tools()}
        assert {"database_locks", "query_metrics"} <= names
        first = await server.call_tool("database_locks", {"context": context.model_dump(mode="json")})
        assert EvidenceRecord.model_validate(first[1]).incident_id == incident.incident_id
        with pytest.raises(ToolError):
            await server.call_tool("query_metrics", {"context": {**context.model_dump(mode="json"), "permission": "operations:write"}})
        assert repository.operation_count(incident.incident_id) == 0
    finally:
        repository.reset_checkpoint("R05")


@pytest.mark.parametrize(
    ("scenario", "proposed"),
    (
        (
            "R06",
            (
                "operations.enable_query_plan_baseline_orders: "
                "index idx_orders_customer for orders_lookup"
            ),
        ),
        ("R07", "operations.route_customer_reads_primary: customer reads routed to primary"),
        ("R08", "operations.rotate_credential_db_app_2026_09: activate identifier db-app-2026-09"),
    ),
)
def test_r06_r08_approval_page_states_the_real_proposed_action(
    repository: LabRepository, scenario: str, proposed: str
) -> None:
    """The approval surface must describe the frozen capability, not a D1-shaped rollback."""
    repository.reset_checkpoint(scenario)
    lower = scenario.lower()
    try:
        operator = TestClient(create_host_app(HostSettings(database_url=repository.dsn)))
        operator.post("/mock-login", data={"actor": "operator-1"})
        home = operator.get("/").text.split(f"action='/incidents/{lower}/prepare'>")[1]
        nonce = home.split("value='")[1].split("'")[0]
        prepared = operator.post(
            f"/incidents/{lower}/prepare", data={"nonce": nonce}, follow_redirects=False
        )
        thread = prepared.headers["location"].split("/")[2]
        prompt = operator.get(f"/incidents/{thread}/start")
        start_nonce = prompt.text.split("name='nonce' value='")[1].split("'")[0]
        started = operator.post(
            f"/incidents/{thread}/start", data={"nonce": start_nonce}, follow_redirects=False
        )
        assert started.status_code == 303
        fresh = TestClient(create_host_app(HostSettings(database_url=repository.dsn)))
        fresh.post("/mock-login", data={"actor": "approver-1"})
        page = fresh.get(f"/threads/{thread}").text
        assert f"Proposed action: {proposed};" in page
        assert "from v2 to" not in page
        assert "None" not in page.split("Proposed action:")[1].split("</p>")[0]
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize(
    ("scenario", "action_text", "decision"),
    (
        ("R06", "operations.enable_query_plan_baseline_orders", "approve"),
        ("R07", "operations.route_customer_reads_primary", "approve"),
        ("R08", "operations.rotate_credential_db_app_2026_09", "reject"),
    ),
)
def test_r06_r08_fresh_host_pending_role_nonce_and_safe_text(
    repository: LabRepository, scenario: str, action_text: str, decision: str
) -> None:
    repository.reset_checkpoint(scenario)
    try:
        operator = TestClient(create_host_app(HostSettings(database_url=repository.dsn)))
        operator.post("/mock-login", data={"actor": "operator-1"})
        nonce = operator.get("/").text.split(f"action='/incidents/{scenario.lower()}/prepare'>")[1].split("value='")[1].split("'")[0]
        prepared = operator.post(f"/incidents/{scenario.lower()}/prepare", data={"nonce": nonce}, follow_redirects=False)
        thread = prepared.headers["location"].split("/")[2]
        prompt = operator.get(f"/incidents/{thread}/start")
        start_nonce = prompt.text.split("name='nonce' value='")[1].split("'")[0]
        assert operator.post(f"/incidents/{thread}/start", data={"nonce": start_nonce}, follow_redirects=False).status_code == 303
        fresh = TestClient(create_host_app(HostSettings(database_url=repository.dsn)))
        fresh.post("/mock-login", data={"actor": "approver-1"})
        pending = fresh.get(f"/threads/{thread}")
        assert action_text in pending.text
        lowered = pending.text.lower()
        assert all(word not in lowered for word in ("approval token", "idempotency", "secret", "password", "raw fixture"))
        assert fresh.post(f"/threads/{thread}/{decision}", headers={"X-Incidentgate-Actor": "operator-1"}).status_code == 403
        form_nonce = pending.text.split("name='nonce' value='")[1 if decision == "approve" else 2].split("'")[0]
        assert fresh.post(f"/threads/{thread}/{decision}", data={"nonce": form_nonce}, follow_redirects=False).status_code == 303
        assert fresh.post(f"/threads/{thread}/{decision}", data={"nonce": form_nonce}).status_code == 403
        assert repository.operation_count(f"INC-{scenario}") == (1 if decision == "approve" else 0)
    finally:
        repository.reset_checkpoint(scenario)
