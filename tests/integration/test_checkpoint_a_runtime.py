"""Durable public-runtime coverage for the additive D2/D3 checkpoints."""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from incidentgate.contracts import (
    CanonicalAction,
    IncidentIdentity,
    MonitorResult,
    MonitorVerdict,
    Role,
    ToolCallContext,
    canonical_action_hash,
)
from incidentgate.control.models import Caller
from incidentgate.integration import IncidentRuntime, PendingApproval
from incidentgate.lab.auth import Principal
from incidentgate.lab.errors import ResponseLost
from incidentgate.lab.repository import APPROVED_API_URL_REF, LabRepository
from incidentgate.telemetry import create_tracer_runtime


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("Checkpoint A runtime integration requires DATABASE_URL")
    repo = LabRepository(dsn)
    repo.migrate()
    return repo


def inputs(scenario: str) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    thread = f"runtime-{scenario.lower()}-{uuid4().hex[:12]}"
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


def evidence_tools(repo: LabRepository, evidence_ids: tuple[str, ...]) -> set[str]:
    with repo._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT tool_name FROM evidence_records WHERE evidence_id = ANY(%s)",
            (list(evidence_ids),),
        )
        return {str(row["tool_name"]) for row in cursor.fetchall()}


class RecordingMonitor:
    def __init__(self, verdict: MonitorVerdict = MonitorVerdict.ALLOW) -> None:
        self.verdict, self.calls = verdict, 0

    def assess(self, action: CanonicalAction, evidence_digest: object) -> MonitorResult:
        self.calls += 1
        return MonitorResult(verdict=self.verdict, suspicion_score=0.0 if self.verdict is MonitorVerdict.ALLOW else 1.0,
                             rationale="configured_monitor", evaluated_action_hash=canonical_action_hash(action))


@pytest.mark.parametrize("scenario", ["D1", "D2", "D3"])
def test_configured_monitor_factory_reconstructs_after_reopen(repository: LabRepository, scenario: str) -> None:
    if scenario == "D1":
        repository.reset_d1()
        repository.inject_d1()
    else:
        repository.reset_checkpoint(scenario)
        repository.inject_checkpoint(scenario)
    incident, caller, context = inputs(scenario)
    monitors: list[RecordingMonitor] = []
    def factory() -> RecordingMonitor:
        monitor = RecordingMonitor()
        monitors.append(monitor)
        return monitor
    with IncidentRuntime(repository.dsn, monitor_factory=factory) as first:
        pending = first.start(incident, caller, context)
        assert isinstance(pending, PendingApproval) and monitors[-1].calls == 1
    with IncidentRuntime(repository.dsn, monitor_factory=factory) as second:
        status = second.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
        assert status.result is not None and status.result.final_state == "resolved"
        assert len(monitors) == 2
    state = repository.state() if scenario == "D1" else repository.checkpoint_state(scenario)
    assert state["mutation_count"] == 1


def test_d3_configured_monitor_block_is_terminal_across_reopen(repository: LabRepository) -> None:
    repository.reset_checkpoint("D3")
    repository.inject_checkpoint("D3")
    incident, caller, context = inputs("D3")
    with IncidentRuntime(repository.dsn, monitor_factory=lambda: RecordingMonitor(MonitorVerdict.BLOCK)) as first:
        status = first.start(incident, caller, context)
        assert not isinstance(status, PendingApproval) and status.result is not None
        assert status.result.final_state == "blocked"
        assert [event.transition for event in first.timeline(incident.incident_id)] == ["policy", "monitor"]
    with (
        IncidentRuntime(repository.dsn, monitor_factory=lambda: RecordingMonitor(MonitorVerdict.BLOCK)) as second,
        pytest.raises(ValueError, match="no pending approval"),
    ):
        second.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
    assert repository.checkpoint_state("D3")["mutation_count"] == 0


@pytest.mark.parametrize(
    ("scenario", "tool_name", "tools"),
    [
        (
            "D2",
            "operations.restore_config",
            {"observability.health", "observability.config_diff", "observability.logs"},
        ),
        (
            "D3",
            "operations.restart",
            {"observability.health", "metrics.db_pool", "observability.logs"},
        ),
    ],
)
def test_checkpoint_start_is_durable_and_reject_is_zero_mutation(
    repository: LabRepository, scenario: str, tool_name: str, tools: set[str]
) -> None:
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = inputs(scenario)
    with IncidentRuntime(repository.dsn) as runtime:
        pending = runtime.start(incident, caller, context)
        assert isinstance(pending, PendingApproval)
        assert pending.incident_id == f"INC-{scenario}" and pending.tool_name == tool_name
        assert pending.component == "api" and pending.target_revision is None
        assert evidence_tools(repository, pending.evidence_ids) == tools
        assert [event.transition for event in runtime.timeline(incident.incident_id)] == [
            "policy",
            "monitor",
        ]
        assert repository.checkpoint_state(scenario)["mutation_count"] == 0
        status = runtime.status(incident.thread_id)
        assert status.incident_id == incident.incident_id and status.pending == pending
        if scenario == "D2":
            assert pending.variable_name == "REQUIRED_API_URL"
            assert pending.approved_value_ref == APPROVED_API_URL_REF
        else:
            assert pending.variable_name is None and pending.approved_value_ref is None
        rejected = runtime.reject(incident.thread_id, Principal("approver-1", Role.APPROVER))
        assert rejected.result is not None and rejected.result.final_state == "blocked"
    assert repository.checkpoint_state(scenario)["mutation_count"] == 0


@pytest.mark.parametrize("scenario", ["D2", "D3"])
def test_checkpoint_approval_recreates_runtime_and_freshly_verifies(
    repository: LabRepository, scenario: str
) -> None:
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = inputs(scenario)
    with IncidentRuntime(repository.dsn) as first:
        pending = first.start(incident, caller, context)
        assert isinstance(pending, PendingApproval)
    with IncidentRuntime(repository.dsn) as second:
        status = second.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
        assert status.incident_id == incident.incident_id
        assert status.result is not None and status.result.final_state == "resolved"
        assert status.result.operation is not None and status.result.verification is not None
        assert set(status.result.verification.evidence_ids).isdisjoint(pending.evidence_ids)
        assert (
            status.result.report is not None
            and status.result.report.evidence_ids == pending.evidence_ids
        )
        if scenario == "D2":
            result = status.result.operation.result
            assert result is not None and result["config_reference"] == APPROVED_API_URL_REF
            assert "value" not in result and "secret" not in str(result).lower()
    assert repository.checkpoint_state(scenario)["mutation_count"] == 1


def test_d3_response_loss_retries_once_as_duplicate(repository: LabRepository) -> None:
    repository.reset_checkpoint("D3")
    repository.inject_checkpoint("D3")
    incident, caller, context = inputs("D3")
    with IncidentRuntime(repository.dsn, response_loss_once=True) as first:
        pending = first.start(incident, caller, context)
        assert isinstance(pending, PendingApproval)
        with pytest.raises(ResponseLost):
            first.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
    with IncidentRuntime(repository.dsn) as second:
        status = second.retry(incident.thread_id)
        assert status.incident_id == "INC-D3"
        assert status.result is not None and status.result.operation is not None
        assert status.result.operation.status.value == "duplicate"
        assert set(status.result.verification.evidence_ids).isdisjoint(pending.evidence_ids)  # type: ignore[union-attr]
    assert repository.checkpoint_state("D3")["mutation_count"] == 1


@pytest.mark.parametrize("scenario", ["D2", "D3"])
def test_checkpoint_trace_is_scenario_named_and_continues_after_reopen(
    repository: LabRepository, scenario: str
) -> None:
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    incident, caller, context = inputs(scenario)
    exporter = InMemorySpanExporter()
    telemetry = create_tracer_runtime(processors=(SimpleSpanProcessor(exporter),))
    try:
        with IncidentRuntime(repository.dsn, telemetry=telemetry) as first:
            pending = first.start(incident, caller, context)
            assert isinstance(pending, PendingApproval)
        with IncidentRuntime(repository.dsn, telemetry=telemetry) as second:
            second.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
        spans = exporter.get_finished_spans()
        names = {span.name for span in spans}
        prefix = scenario.lower()
        assert {f"{prefix}.{phase}" for phase in ("workflow", "policy", "monitor", "approval", "verification")} <= names
        assert {"mcp.observability", "mcp.operations"} <= names
        assert len({span.context.trace_id for span in spans}) == 1
        forbidden = {"raw_log", "token", "traceparent", "approved_value", "config_value"}
        assert all(not (set(span.attributes) & forbidden) for span in spans)
    finally:
        telemetry.shutdown()
