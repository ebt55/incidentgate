"""Live, durable acceptance coverage for the first runnable reliability slice."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

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
    DeterministicR01Proposer,
    DeterministicR02Proposer,
    DeterministicR03Proposer,
    DeterministicR04Proposer,
)
from triage_agent_lab.host.app import HostSettings, create_host_app
from triage_agent_lab.integration import IncidentRuntime, PendingApproval
from triage_agent_lab.lab.approval import ApprovalService
from triage_agent_lab.lab.auth import Principal
from triage_agent_lab.lab.errors import ResponseLost
from triage_agent_lab.lab.repository import D1Repository
from triage_agent_lab.lab.service import ObservabilityService, OperationsService
from triage_agent_lab.mcp_servers.entrypoints import observability_server, operations_server
from triage_agent_lab.telemetry import create_tracer_runtime


@pytest.fixture
def repository() -> D1Repository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("R01-R04 integration requires DATABASE_URL")
    result = D1Repository(dsn)
    result.migrate()
    return result


def _inputs(scenario: str) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    thread = f"{scenario.lower()}-{uuid4().hex[:12]}"
    incident = IncidentIdentity(
        incident_id=f"INC-{scenario}",
        scenario_id=scenario,
        thread_id=thread,
        correlation_id=f"corr-{thread}",
    )
    return (
        incident,
        Caller(actor="operator-1", role=Role.OPERATOR),
        ToolCallContext(
            incident_id=incident.incident_id,
            thread_id=thread,
            correlation_id=incident.correlation_id,
            actor="operator-1",
            permission="operations:write",
        ),
    )


@pytest.mark.parametrize("scenario", ("R01", "R02", "R03", "R04"))
def test_reliability_action_requires_approval_and_fresh_verification(
    repository: D1Repository, scenario: str
) -> None:
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = _inputs(scenario)
    try:
        with IncidentRuntime(repository.dsn) as runtime:
            pending = runtime.start(incident, caller, context)
            assert isinstance(pending, PendingApproval)
            assert pending.tool_name.startswith("operations.")
            assert pending.evidence_ids
            rejected = runtime.reject(incident.thread_id, Principal("approver-1", Role.APPROVER))
        assert rejected.result is not None and rejected.result.final_state == "blocked"
        assert repository.operation_count(incident.incident_id) == 0

        repository.reset_checkpoint(scenario)
        repository.inject_checkpoint(scenario)
        incident, caller, context = _inputs(scenario)
        with IncidentRuntime(repository.dsn) as runtime:
            assert isinstance(runtime.start(incident, caller, context), PendingApproval)
            completed = runtime.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
        assert completed.result is not None and completed.result.verification is not None
        assert completed.result.verification.passed
        assert repository.operation_count(incident.incident_id) == 1
        expected = {
            "R01": {
                "schema_version": "2026.08.10.4",
                "release": "api-2.4.1",
                "billing_plan_required": False,
            },
            "R02": {"checkout_v2": False, "rollout": 0, "checkout_5xx_rate": 0},
            "R03": {"payment_timeout_ms": "3000", "config_version": "cfg-a17"},
            "R04": {"old_pods": 12, "new_pods": 0},
        }[scenario]
        state = repository.checkpoint_state(scenario)
        assert state["mutation_count"] == 1
        assert {key: state[key] for key in expected} == expected
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize("scenario", ("R01", "R02", "R03", "R04"))
def test_reliability_response_loss_replays_one_durable_operation(
    repository: D1Repository, scenario: str
) -> None:
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
            replay = runtime.retry(incident.thread_id)
        assert replay.result is not None and replay.result.operation is not None
        assert replay.result.operation.status.value == "duplicate"
        assert replay.result.verification is not None and replay.result.verification.passed
        assert repository.operation_count(incident.incident_id) == 1
        state = repository.checkpoint_state(scenario)
        assert state["mutation_count"] == 1
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize("scenario", ("R01", "R02", "R03", "R04"))
def test_reliability_phase_trace_is_one_safe_chain(repository: D1Repository, scenario: str) -> None:
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = _inputs(scenario)
    exporter = InMemorySpanExporter()
    telemetry = create_tracer_runtime(processors=(SimpleSpanProcessor(exporter),))
    try:
        with IncidentRuntime(repository.dsn, telemetry=telemetry) as runtime:
            runtime.start(incident, caller, context)
            runtime.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
        spans = [
            span for span in exporter.get_finished_spans() if span.name.startswith(scenario.lower())
        ]
        assert {span.name for span in spans} >= {
            f"{scenario.lower()}.{phase}"
            for phase in ("workflow", "policy", "monitor", "approval", "verification")
        }
        assert len({span.context.trace_id for span in spans}) == 1
        allowed = {
            "incident_id",
            "thread_id",
            "correlation_id",
            "actor",
            "permission",
            "action_hash",
            "idempotency_key",
        }
        assert all(set(span.attributes) <= allowed for span in spans)
        assert any(span.parent.span_id for span in spans)
        rendered = str([span.attributes for span in spans]).lower()
        assert all(
            value not in rendered for value in ("token", "approval_id", "secret", "fast", "cfg-b02")
        )
    finally:
        telemetry.shutdown()
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize(
    ("scenario", "safe_text"),
    (
        ("R01", "schema 2026.08.10.4"),
        ("R02", "checkout_v2 false"),
        ("R03", "PAYMENT_TIMEOUT_MS 3000"),
        ("R04", "old pods 12, new pods 0"),
    ),
)
def test_reliability_host_fresh_load_preserves_cookie_role_and_safe_action_text(
    repository: D1Repository, scenario: str, safe_text: str
) -> None:
    repository.reset_checkpoint(scenario)
    settings = HostSettings(database_url=repository.dsn)
    try:
        first = TestClient(create_host_app(settings))
        first.post("/mock-login", data={"actor": "operator-1"})
        home = first.get("/")
        nonce = (
            home.text.split(f"action='/incidents/{scenario.lower()}/prepare'>")[1]
            .split("value='")[1]
            .split("'")[0]
        )
        prepared = first.post(
            f"/incidents/{scenario.lower()}/prepare", data={"nonce": nonce}, follow_redirects=False
        )
        assert prepared.status_code == 303
        thread = prepared.headers["location"].split("/")[2]
        start = first.get(f"/incidents/{thread}/start")
        start_nonce = start.text.split("name='nonce' value='")[1].split("'")[0]
        assert (
            first.post(
                f"/incidents/{thread}/start", data={"nonce": start_nonce}, follow_redirects=False
            ).status_code
            == 303
        )
        second = TestClient(create_host_app(settings))
        second.post("/mock-login", data={"actor": "approver-1"})
        pending = second.get(f"/threads/{thread}")
        assert safe_text in pending.text
        assert all(
            word not in pending.text.lower() for word in ("approval token", "secret", "idempotency")
        )
        assert (
            second.post(
                f"/threads/{thread}/approve", headers={"X-D1-Actor": "operator-1"}
            ).status_code
            == 403
        )
        approve_nonce = pending.text.split("name='nonce' value='")[0 + 1].split("'")[0]
        assert (
            second.post(
                f"/threads/{thread}/approve", data={"nonce": approve_nonce}, follow_redirects=False
            ).status_code
            == 303
        )
        assert repository.operation_count(f"INC-{scenario}") == 1
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "reads", "operation", "proposer"),
    (
        (
            "R01",
            ("deployment_diff", "database_schema"),
            "rollback_migration_2026_08_10_5",
            DeterministicR01Proposer,
        ),
        (
            "R02",
            ("feature_flags", "http_metrics", "error_logs"),
            "disable_flag_checkout_v2",
            DeterministicR02Proposer,
        ),
        (
            "R03",
            ("config_snapshot", "error_logs"),
            "restore_config_PAYMENT_TIMEOUT_MS_3000",
            DeterministicR03Proposer,
        ),
        (
            "R04",
            ("deployment_diff", "pod_inventory"),
            "rollback_release_api_2_4_1",
            DeterministicR04Proposer,
        ),
    ),
)
async def test_public_fastmcp_exact_reliability_capabilities_and_role_denial(
    repository: D1Repository,
    scenario: str,
    reads: tuple[str, ...],
    operation: str,
    proposer: type[object],
) -> None:
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, write_context = _inputs(scenario)
    read_context = write_context.model_copy(update={"permission": "observability:read"})
    observe = observability_server(
        ObservabilityService(repository), Principal("operator-1", Role.OPERATOR)
    )
    operate = operations_server(
        OperationsService(repository), Principal("operator-1", Role.OPERATOR)
    )
    try:
        assert set(reads) <= {tool.name for tool in await observe.list_tools()}
        assert operation in {tool.name for tool in await operate.list_tools()}
        records = []
        for name in reads:
            reply = await observe.call_tool(name, {"context": read_context.model_dump(mode="json")})
            assert "INC-" in str(reply)
            records.append(EvidenceRecord.model_validate(reply[1]))
        _, action = proposer().propose(incident, caller, write_context, tuple(records))  # type: ignore[operator]
        now = datetime.now(UTC)
        token = ApprovalService(
            repository, lambda: now, incident_id=incident.incident_id, thread_id=incident.thread_id
        ).approve(
            ApprovalRequest(
                action_hash=canonical_action_hash(action),
                actor=caller.actor,
                requested_at=now,
                expires_at=now + timedelta(minutes=5),
                one_time_use_id=uuid4(),
            ),
            Principal("approver-1", Role.APPROVER),
        )
        execution_context = write_context.model_copy(update={"idempotency_key": uuid4()})
        denied = operations_server(
            OperationsService(repository), Principal("observer-1", Role.OBSERVER)
        )
        with pytest.raises(ToolError):
            await denied.call_tool(
                operation,
                {
                    "context": execution_context.model_dump(mode="json"),
                    "action": action.model_dump(mode="json"),
                    "token": token.model_dump(mode="json"),
                },
            )
        assert repository.operation_count(
            incident.incident_id
        ) == 0 and not repository.approval_consumed(token.token_id)
        for field, value in (
            ("incident_id", "INC-R99"),
            ("thread_id", "forged-thread"),
            ("correlation_id", "forged-correlation"),
            ("actor", "forged-actor"),
            ("permission", "forged:write"),
        ):
            with pytest.raises(ToolError):
                await operate.call_tool(
                    operation,
                    {
                        "context": {**execution_context.model_dump(mode="json"), field: value},
                        "action": action.model_dump(mode="json"),
                        "token": token.model_dump(mode="json"),
                    },
                )
            assert repository.operation_count(
                incident.incident_id
            ) == 0 and not repository.approval_consumed(token.token_id)
        if scenario == "R02":
            malformed = action.model_dump(mode="json")
            malformed["arguments"]["enabled"] = 0  # type: ignore[index]
            with pytest.raises(ToolError):
                await operate.call_tool(
                    operation,
                    {
                        "context": execution_context.model_dump(mode="json"),
                        "action": malformed,
                        "token": token.model_dump(mode="json"),
                    },
                )
            assert repository.operation_count(
                incident.incident_id
            ) == 0 and not repository.approval_consumed(token.token_id)
        if scenario == "R01":
            with pytest.raises(ToolError):
                await operate.call_tool(
                    "rollback_release_api_2_4_1",
                    {
                        "context": execution_context.model_dump(mode="json"),
                        "action": action.model_dump(mode="json"),
                        "token": token.model_dump(mode="json"),
                    },
                )
            assert repository.operation_count(
                incident.incident_id
            ) == 0 and not repository.approval_consumed(token.token_id)
        result = await operate.call_tool(
            operation,
            {
                "context": execution_context.model_dump(mode="json"),
                "action": action.model_dump(mode="json"),
                "token": token.model_dump(mode="json"),
            },
        )
        assert "succeeded" in str(result) and repository.operation_count(incident.incident_id) == 1
        assert repository.approval_consumed(token.token_id)
    finally:
        repository.reset_checkpoint(scenario)
