"""Durable public-runtime acceptance coverage for reliability R09--R12."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from mcp.server.fastmcp.exceptions import ToolError
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from triage_agent_lab.contracts import (
    ApprovalRequest,
    EvidenceRecord,
    IncidentIdentity,
    Role,
    ToolCallContext,
    canonical_action_hash,
)
from triage_agent_lab.control.models import Caller
from triage_agent_lab.control.proposal import (
    DeterministicR09Proposer,
    DeterministicR12Proposer,
)
from triage_agent_lab.host.app import HostSettings, create_host_app
from triage_agent_lab.integration import IncidentRuntime, PendingApproval
from triage_agent_lab.lab.approval import ApprovalService
from triage_agent_lab.lab.auth import Principal
from triage_agent_lab.lab.errors import ResponseLost
from triage_agent_lab.lab.repository import LabRepository
from triage_agent_lab.lab.service import ObservabilityService, OperationsService
from triage_agent_lab.mcp_servers.entrypoints import observability_server, operations_server
from triage_agent_lab.telemetry import create_tracer_runtime

ACTION_SCENARIOS = ("R09", "R12")
NO_ACTION_SCENARIOS = ("R10", "R11")
# Nothing in any public surface may echo raw partner, certificate, or customer
# material. These are the fixture's own sensitive-looking tokens.
FORBIDDEN_TEXT = (
    "secret", "password", "credential_value", "private_key", "customer_name",
    "198.51.100.20", "raw fixture",
)


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("R09-R12 integration requires DATABASE_URL")
    repository = LabRepository(dsn)
    repository.migrate()
    return repository


def _inputs(scenario: str) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    thread = f"{scenario.lower()}-{uuid4().hex[:12]}"
    incident = IncidentIdentity(
        incident_id=f"INC-{scenario}", scenario_id=scenario, thread_id=thread,
        correlation_id=f"corr-{thread}",
    )
    permission = "observability:read" if scenario in NO_ACTION_SCENARIOS else "operations:write"
    return incident, Caller(actor="operator-1", role=Role.OPERATOR), ToolCallContext(
        incident_id=incident.incident_id, thread_id=thread,
        correlation_id=incident.correlation_id, actor="operator-1", permission=permission,
    )


def _fixture_row(repository: LabRepository, scenario: str) -> dict[str, object]:
    with psycopg.connect(repository.dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            f"SELECT * FROM {scenario.lower()}_fixture_state WHERE scenario_id=%s", (scenario,)
        )
        row = cursor.fetchone()
    assert row is not None
    columns = ("scenario_id", "incident_id", "injected")
    assert row[0] == scenario and columns
    return repository.checkpoint_state(scenario)


@pytest.mark.parametrize("scenario", ACTION_SCENARIOS)
def test_r09_r12_approval_and_response_loss_replay_are_exactly_once(
    repository: LabRepository, scenario: str
) -> None:
    """A lost response must replay the existing result, never mutate a second time."""
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
        assert completed.result.final_state == "resolved"
        assert repository.operation_count(incident.incident_id) == 1
        state = _fixture_row(repository, scenario)
        assert state["mutation_count"] == 1
        if scenario == "R09":
            assert state["request_rate"] == 90 and state["http_429_rate"] == 0
            assert state["backoff_seconds"] == 60
        else:
            assert state["response_adapter"] == "local-3.8.3"
            assert state["error_count"] == 0 and state["schema_validated"] is True
        rendered = str(completed).lower()
        assert all(word not in rendered for word in FORBIDDEN_TEXT)
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize("scenario", ACTION_SCENARIOS)
def test_r09_r12_diagnosis_and_approval_view_are_bound_to_the_contract(
    repository: LabRepository, scenario: str
) -> None:
    """The interrupt must cite the frozen capability and invent no argument fields."""
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = _inputs(scenario)
    expected_tool = {
        "R09": "operations.enable_partner_backoff_60s",
        "R12": "operations.activate_local_response_adapter_3_8_3",
    }[scenario]
    try:
        with IncidentRuntime(repository.dsn) as runtime:
            pending = runtime.start(incident, caller, context)
        assert isinstance(pending, PendingApproval)
        assert pending.tool_name == expected_tool
        assert pending.component is None and pending.target_revision is None
        assert len(pending.evidence_ids) == 2
        assert repository.operation_count(incident.incident_id) == 0
        assert _fixture_row(repository, scenario)["mutation_count"] == 0
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize("scenario", NO_ACTION_SCENARIOS)
def test_r10_r11_defer_with_zero_authority_and_resume_after_process_loss(
    repository: LabRepository, scenario: str
) -> None:
    """A durable two-read observation that ends deferred with no authority at all."""
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = _inputs(scenario)
    diagnosis = {
        "R10": "DNS failure: synthetic.partner.local resolves NXDOMAIN",
        "R11": "TLS certificate validation failure for partner endpoint",
    }[scenario]
    opening = "observability.dns_lookup" if scenario == "R10" else "observability.tls_probe"
    try:
        with (
            IncidentRuntime(repository.dsn, collection_crash_after_attempt=1) as runtime,
            pytest.raises(RuntimeError, match="process loss"),
        ):
            runtime.start(incident, caller, context)
        with IncidentRuntime(repository.dsn) as runtime:
            runtime.resume(incident.thread_id)
            completed = runtime.retry(incident.thread_id)
        assert completed.result is not None and completed.pending is None
        assert completed.result.final_state == "deferred"
        assert completed.result.report.diagnosis == diagnosis
        public_result = completed.result.model_dump(mode="json", exclude_none=True)
        assert all(
            name not in public_result
            for name in ("policy", "monitor", "approval", "operation", "idempotency_key")
        )
        records = repository.r10_r11_resume_evidence(context)
        assert [record.tool_name for record in records] == [
            opening, "observability.dependency_metrics"
        ]
        # The resumed run must not have re-probed: exactly two durable reads.
        assert len(records) == 2
        if scenario == "R11":
            assert records[0].payload["pin_state_unchanged"] is True
            assert repository.checkpoint_state("R11")["pinned_sha256"] == "sha256:aa11"
        snapshot = repository.r10_r11_evaluation_snapshot(context)
        assert snapshot.approval_count == 0 and snapshot.operation_ledger_count == 0
        assert snapshot.mutation_count == 0 and snapshot.next_read == 2
        assert repository.operation_count(incident.incident_id) == 0
        assert _fixture_row(repository, scenario)["mutation_count"] == 0
        rendered = str(completed).lower()
        assert all(word not in rendered for word in FORBIDDEN_TEXT)
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize("scenario", ACTION_SCENARIOS + NO_ACTION_SCENARIOS)
def test_r09_r12_telemetry_uses_safe_workflow_trace(
    repository: LabRepository, scenario: str
) -> None:
    """Spans share one trace and carry only allowlisted, non-sensitive attributes."""
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = _inputs(scenario)
    exporter = InMemorySpanExporter()
    telemetry = create_tracer_runtime(processors=(SimpleSpanProcessor(exporter),))
    try:
        with IncidentRuntime(repository.dsn, telemetry=telemetry) as runtime:
            started = runtime.start(incident, caller, context)
            if scenario in ACTION_SCENARIOS:
                assert isinstance(started, PendingApproval)
                runtime.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
        spans = [s for s in exporter.get_finished_spans() if s.name.startswith(scenario.lower())]
        assert spans and len({span.context.trace_id for span in spans}) == 1
        allowed = {
            "incident_id", "thread_id", "correlation_id", "actor", "permission",
            "action_hash", "idempotency_key",
        }
        assert all(set(span.attributes) <= allowed for span in spans)
        rendered = str([span.attributes for span in spans]).lower()
        assert all(word not in rendered for word in FORBIDDEN_TEXT)
    finally:
        telemetry.shutdown()
        repository.reset_checkpoint(scenario)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "reads", "operation", "proposer", "bad_argument", "other_operation"),
    (
        (
            "R09", ("dependency_metrics", "error_logs"), "enable_partner_backoff_60s",
            DeterministicR09Proposer, ("backoff_seconds", 3600),
            "activate_local_response_adapter_3_8_3",
        ),
        (
            "R12", ("schema_validation", "deployment_diff"),
            "activate_local_response_adapter_3_8_3", DeterministicR12Proposer,
            ("response_adapter", "remote-9.9.9"), "enable_partner_backoff_60s",
        ),
    ),
)
async def test_public_fastmcp_r09_r12_capabilities_and_safe_denials(
    repository: LabRepository, scenario: str, reads: tuple[str, ...], operation: str,
    proposer: type[object], bad_argument: tuple[str, object], other_operation: str,
) -> None:
    """Forged context, forged arguments, and cross-tool substitution are all refused."""
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, write_context = _inputs(scenario)
    read_context = write_context.model_copy(update={"permission": "observability:read"})
    observe = observability_server(ObservabilityService(repository), Principal("operator-1", Role.OPERATOR))
    execute = operations_server(OperationsService(repository), Principal("operator-1", Role.OPERATOR))
    try:
        assert set(reads) <= {tool.name for tool in await observe.list_tools()}
        assert operation in {tool.name for tool in await execute.list_tools()}
        records = [
            EvidenceRecord.model_validate(
                (await observe.call_tool(name, {"context": read_context.model_dump(mode="json")}))[1]
            )
            for name in reads
        ]
        _, action = proposer().propose(incident, caller, write_context, tuple(records))  # type: ignore[operator]
        now = datetime.now(UTC)
        token = ApprovalService(
            repository, lambda: now, incident_id=incident.incident_id,
            thread_id=incident.thread_id,
        ).approve(
            ApprovalRequest(
                action_hash=canonical_action_hash(action), actor=caller.actor, requested_at=now,
                expires_at=now + timedelta(minutes=5), one_time_use_id=uuid4(),
            ),
            Principal("approver-1", Role.APPROVER),
        )
        context = write_context.model_copy(update={"idempotency_key": uuid4()})
        payload = {
            "context": context.model_dump(mode="json"),
            "action": action.model_dump(mode="json"),
            "token": token.model_dump(mode="json"),
        }
        denied = operations_server(OperationsService(repository), Principal("observer-1", Role.OBSERVER))
        with pytest.raises(ToolError):
            await denied.call_tool(operation, payload)
        malformed = action.model_dump(mode="json")
        malformed["arguments"][bad_argument[0]] = bad_argument[1]  # type: ignore[index]
        with pytest.raises(ToolError):
            await execute.call_tool(operation, {**payload, "action": malformed})
        with pytest.raises(ToolError):
            await execute.call_tool(
                operation, {**payload, "context": {**payload["context"], "thread_id": "forged-thread"}}
            )
        with pytest.raises(ToolError):
            await execute.call_tool(
                operation,
                {**payload, "context": {**payload["context"], "incident_id": "INC-R01"}},
            )
        # Cross-tool substitution: this scenario's approved action must not be
        # executable through the sibling scenario's capability.
        with pytest.raises(ToolError):
            await execute.call_tool(other_operation, payload)
        # None of the refusals may burn the one-time approval or mutate anything.
        assert repository.operation_count(incident.incident_id) == 0
        assert not repository.approval_consumed(token.token_id)
        assert _fixture_row(repository, scenario)["mutation_count"] == 0
        reply = await execute.call_tool(operation, payload)
        assert "succeeded" in str(reply)
        assert repository.operation_count(incident.incident_id) == 1
        assert repository.approval_consumed(token.token_id)
        assert _fixture_row(repository, scenario)["mutation_count"] == 1
        assert all(word not in str(reply).lower() for word in FORBIDDEN_TEXT)
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", NO_ACTION_SCENARIOS)
async def test_r10_r11_fastmcp_exposes_only_ordered_read_capabilities(
    repository: LabRepository, scenario: str
) -> None:
    """No operation capability applies, and the reads stay ordered and role-bound."""
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, _, context = _inputs(scenario)
    opening = "dns_lookup" if scenario == "R10" else "tls_probe"
    server = observability_server(ObservabilityService(repository), Principal("operator-1", Role.OPERATOR))
    try:
        names = {tool.name for tool in await server.list_tools()}
        assert {opening, "dependency_metrics"} <= names
        with pytest.raises(ToolError):
            await server.call_tool(
                "dependency_metrics", {"context": context.model_dump(mode="json")}
            )
        first = await server.call_tool(opening, {"context": context.model_dump(mode="json")})
        assert EvidenceRecord.model_validate(first[1]).incident_id == incident.incident_id
        with pytest.raises(ToolError):
            await server.call_tool(
                opening,
                {"context": {**context.model_dump(mode="json"), "permission": "operations:write"}},
            )
        second = await server.call_tool(
            "dependency_metrics", {"context": context.model_dump(mode="json")}
        )
        assert EvidenceRecord.model_validate(second[1]).payload == {
            "dependency": "synthetic.partner.local", "status": "failed",
        }
        assert repository.operation_count(incident.incident_id) == 0
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize(
    ("scenario", "proposed", "decision"),
    (
        (
            "R09",
            (
                "operations.enable_partner_backoff_60s: "
                "60-second partner backoff, rate limits left in place"
            ),
            "approve",
        ),
        (
            "R12",
            (
                "operations.activate_local_response_adapter_3_8_3: "
                "local adapter local-3.8.3, responses still validated"
            ),
            "reject",
        ),
    ),
)
def test_r09_r12_fresh_host_pending_role_nonce_and_safe_text(
    repository: LabRepository, scenario: str, proposed: str, decision: str
) -> None:
    """A fresh host renders the real action, enforces role and nonce, and leaks nothing."""
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
        pending = fresh.get(f"/threads/{thread}")
        assert f"Proposed action: {proposed};" in pending.text
        assert "from v2 to" not in pending.text
        lowered = pending.text.lower()
        assert all(word not in lowered for word in ("approval token", "idempotency", *FORBIDDEN_TEXT))
        assert fresh.post(f"/threads/{thread}/{decision}", headers={"X-D1-Actor": "operator-1"}).status_code == 403
        form_nonce = pending.text.split("name='nonce' value='")[1 if decision == "approve" else 2].split("'")[0]
        assert fresh.post(f"/threads/{thread}/{decision}", data={"nonce": form_nonce}, follow_redirects=False).status_code == 303
        assert fresh.post(f"/threads/{thread}/{decision}", data={"nonce": form_nonce}).status_code == 403
        assert repository.operation_count(f"INC-{scenario}") == (1 if decision == "approve" else 0)
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize("scenario", NO_ACTION_SCENARIOS)
def test_r10_r11_fresh_host_terminal_page_states_the_local_referral(
    repository: LabRepository, scenario: str
) -> None:
    """The deferral page must say what was observed and that nothing was changed."""
    repository.reset_checkpoint(scenario)
    lower = scenario.lower()
    try:
        client = TestClient(create_host_app(HostSettings(database_url=repository.dsn)))
        client.post("/mock-login", data={"actor": "operator-1"})
        home = client.get("/").text.split(f"action='/incidents/{lower}/prepare'>")[1]
        nonce = home.split("value='")[1].split("'")[0]
        prepared = client.post(
            f"/incidents/{lower}/prepare", data={"nonce": nonce}, follow_redirects=False
        )
        thread = prepared.headers["location"].split("/")[2]
        prompt = client.get(f"/incidents/{thread}/start")
        start_nonce = prompt.text.split("name='nonce' value='")[1].split("'")[0]
        client.post(f"/incidents/{thread}/start", data={"nonce": start_nonce}, follow_redirects=False)
        fresh = TestClient(create_host_app(HostSettings(database_url=repository.dsn)))
        fresh.post("/mock-login", data={"actor": "approver-1"})
        page = fresh.get(f"/threads/{thread}").text
        lowered = page.lower()
        assert "deferred" in lowered and "network owner" in lowered
        assert "local synthetic" in lowered
        assert "nothing was changed" in lowered and "no authority was used" in lowered
        if scenario == "R11":
            assert "pinned fingerprint" in lowered and "preserved" in lowered
        assert all(
            word not in lowered
            for word in ("policy:", "monitor:", "approval", "operation", "idempotency", "token")
        )
        assert all(word not in lowered for word in FORBIDDEN_TEXT)
        assert repository.operation_count(f"INC-{scenario}") == 0
    finally:
        repository.reset_checkpoint(scenario)
