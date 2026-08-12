"""Focused negative contracts and trace safety for D5/D8."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import ValidationError

from incidentgate.contracts import (
    CanonicalAction,
    CleanupArgs,
    EvidenceRecord,
    IncidentIdentity,
    PolicyConfiguration,
    Role,
    ToolCallContext,
)
from incidentgate.control.models import Caller, EvidenceState, EvidenceValidation
from incidentgate.control.policy import DeterministicPolicyEngine
from incidentgate.control.proposal import (
    DeterministicD5Proposer,
    DeterministicD8Proposer,
    ProposalError,
)
from incidentgate.telemetry import create_tracer_runtime


def _record(tool: str, payload: dict[str, object], number: int) -> EvidenceRecord:
    now = datetime.now(UTC)
    return EvidenceRecord(evidence_id=f"ev-{number}", incident_id="INC-D5", thread_id="d5-thread",
        correlation_id="corr", tool_name=tool, actor="operator-1", permission="observability:read",
        observed_at=now, expires_at=now + timedelta(minutes=5), payload=payload)


def test_cleanup_contract_forbids_paths_extra_fields_and_unbounded_caps() -> None:
    valid = {"kind": "cleanup", "component": "api", "cleanup_scope": "simulated_logs", "max_bytes": 67_108_864}
    assert CleanupArgs.model_validate(valid).max_bytes == 67_108_864
    for invalid in ({**valid, "path": "/tmp"}, {**valid, "glob": "*"}, {**valid, "max_bytes": 67_108_865}):
        with pytest.raises(ValidationError):
            CleanupArgs.model_validate(invalid)


def test_d5_proposer_requires_exact_ordered_fixture_evidence() -> None:
    incident = IncidentIdentity(incident_id="INC-D5", scenario_id="D5", thread_id="d5-thread", correlation_id="corr")
    context = ToolCallContext(incident_id="INC-D5", thread_id="d5-thread", correlation_id="corr", actor="operator-1", permission="operations:write")
    records = (
        _record("observability.disk_metrics", {"component": "api", "free_bytes": 32 * 1024 * 1024}, 1),
        _record("observability.log_volume", {"component": "api", "bytes": 96 * 1024 * 1024}, 2),
        _record("observability.health", {"component": "api", "status": 503}, 3),
    )
    _, action = DeterministicD5Proposer().propose(incident, Caller(actor="operator-1", role=Role.OPERATOR), context, records)
    assert action.evidence_ids == ("ev-1", "ev-2", "ev-3") and action.arguments.max_bytes == 67_108_864
    with pytest.raises(ProposalError, match="missing_required_evidence"):
        DeterministicD5Proposer().propose(incident, Caller(actor="operator-1", role=Role.OPERATOR), context, records[:2])


def test_d8_proposal_cites_only_pre_action_health() -> None:
    incident = IncidentIdentity(incident_id="INC-D8", scenario_id="D8", thread_id="d8-thread", correlation_id="corr")
    context = ToolCallContext(incident_id="INC-D8", thread_id="d8-thread", correlation_id="corr", actor="operator-1", permission="operations:write")
    now = datetime.now(UTC)
    health = EvidenceRecord(evidence_id="health-only", incident_id="INC-D8", thread_id="d8-thread", correlation_id="corr", tool_name="observability.health", actor="operator-1", permission="observability:read", observed_at=now, expires_at=now + timedelta(minutes=5), payload={"component": "api", "status": 503})
    _, action = DeterministicD8Proposer().propose(incident, Caller(actor="operator-1", role=Role.OPERATOR), context, (health,))
    assert action.evidence_ids == ("health-only",)


def test_policy_denies_constructed_cleanup_scope_and_cap_bypass() -> None:
    config = PolicyConfiguration.model_validate(json.loads((Path(__file__).parents[1] / "config" / "policy.example.json").read_text()))
    evidence = EvidenceValidation(state=EvidenceState.VALID, reasons=("evidence_valid",), evidence_ids=("ev",), digest=())
    for arguments, reason in (
        (CleanupArgs.model_construct(kind="cleanup", component="api", cleanup_scope="other", max_bytes=67_108_864), "cleanup_scope"),
        (CleanupArgs.model_construct(kind="cleanup", component="other", cleanup_scope="simulated_logs", max_bytes=67_108_864), "component"),
        (CleanupArgs.model_construct(kind="cleanup", component="api", cleanup_scope="simulated_logs", max_bytes=67_108_863), "max_bytes"),
        (CleanupArgs.model_construct(kind="cleanup", component="api", cleanup_scope="simulated_logs", max_bytes=67_108_865), "max_bytes"),
    ):
        action = CanonicalAction.model_construct(tool_name="operations.cleanup", incident_id="INC-D5", thread_id="thread", actor="operator-1", permission="operations:write", evidence_ids=("ev",), arguments=arguments)
        outcome = DeterministicPolicyEngine(config).evaluate(action, Role.OPERATOR, evidence)
        assert outcome.decision.value == "deny" and f"argument_constraint:{reason}" in outcome.reasons


def test_d5_d8_telemetry_is_contiguous_and_denies_unknown_or_unsafe_attributes() -> None:
    exporter = InMemorySpanExporter()
    runtime = create_tracer_runtime(processors=(SimpleSpanProcessor(exporter),))
    for scenario in ("d5", "d8"):
        with (
            runtime.start_as_current_span(f"{scenario}.workflow", attributes={"incident_id": scenario, "secret": "no"}),
            runtime.start_as_current_span(f"{scenario}.approval", attributes={"thread_id": f"{scenario}-thread", "raw_log": "no"}),
        ):
            pass
    spans = exporter.get_finished_spans()
    assert all("secret" not in str(span.attributes).lower() and "raw_log" not in str(span.attributes).lower() for span in spans)
    assert spans[0].context.trace_id == spans[1].context.trace_id and spans[2].context.trace_id == spans[3].context.trace_id
    with pytest.raises(ValueError, match="unknown telemetry"):
        runtime.start_as_current_span("d5.unsafe")
    runtime.shutdown()
