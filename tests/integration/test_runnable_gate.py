"""The acceptance gate must gate, however the runtime was wired.

``IncidentRuntime._invoke_phase`` refuses a scenario that is not in
``RUNNABLE_SCENARIOS``. That check used to sit inside the ``self._telemetry is
not None`` branch, and ``_telemetry`` defaults to ``None`` -- so the only callers
it ever applied to were the ones that happened to wire a tracer. The chaos
worker, every evaluation harness and every runtime test construct the runtime
bare, and all of them skipped it. The measured evidence that it was not gating:
unpromoted T1 drove cleanly through the chaos worker across all 22 boundaries,
producing 22 clean cells, while the registry still refused to call it runnable.

Two things are asserted here, and the second is what keeps the first honest:
enforcement happens with no telemetry configured, and the only way past it is an
explicitly named constructor argument that a reviewer can see at the call site.

Why these tests remove a *promoted* scenario from the registry instead of
driving one that was never promoted: ``_build_graph`` refuses a scenario it has
no proposer branch for, earlier and for an entirely different reason. Driving
T3 here would raise the same message without ever reaching the acceptance gate,
and the test would pass while proving nothing. Removing T1 for the duration
reproduces the real window this gate exists for -- a scenario that is fully
buildable but not yet accepted -- which is exactly where T1 itself sat.

This paragraph named T2 until T2 was promoted, at which point the claim stopped
being true of it: T2 now has a proposer branch, so it would reach the gate. T3,
T5 and T6 are what is left with a frozen contract and no runtime.
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest

from incidentgate.contracts import IncidentIdentity, Role, ToolCallContext
from incidentgate.control.models import Caller
from incidentgate.integration import runtime as runtime_module
from incidentgate.integration.runtime import IncidentRuntime, PendingApproval
from incidentgate.lab.repository import T1_INCIDENT, LabRepository
from incidentgate.scenario_registry import RUNNABLE_SCENARIOS


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("runnable gate coverage requires DATABASE_URL")
    repository = LabRepository(dsn)
    repository.migrate()
    return repository


def _inputs() -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    thread = f"gate-{uuid4().hex[:12]}"
    incident = IncidentIdentity(
        incident_id=T1_INCIDENT,
        scenario_id="T1",
        thread_id=thread,
        correlation_id=f"corr-{thread}",
    )
    return (
        incident,
        Caller(actor="operator-1", role=Role.OPERATOR),
        ToolCallContext(
            incident_id=T1_INCIDENT,
            thread_id=thread,
            correlation_id=incident.correlation_id,
            actor="operator-1",
            permission="operations:write",
        ),
    )


def _unpromote_t1(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reproduce the buildable-but-not-yet-accepted window."""
    monkeypatch.setattr(
        runtime_module, "RUNNABLE_SCENARIOS", frozenset(RUNNABLE_SCENARIOS - {"T1"})
    )


@pytest.mark.integration
def test_a_runtime_with_no_telemetry_refuses_an_unpromoted_scenario(
    repository: LabRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Constructed exactly as the chaos worker constructs it: bare."""
    _unpromote_t1(monkeypatch)
    repository.reset_checkpoint("T1")
    repository.inject_checkpoint("T1")
    incident, operator, context = _inputs()
    try:
        with IncidentRuntime(repository.dsn) as runtime:
            assert runtime._telemetry is None, "this test is only meaningful without telemetry"
            with pytest.raises(ValueError, match="unsupported checkpoint scenario"):
                runtime.start(incident, operator, context)
    finally:
        repository.reset_checkpoint("T1")


@pytest.mark.integration
def test_the_refusal_leaves_no_durable_trace_of_the_unpromoted_run(
    repository: LabRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refused means refused: no ledger row, no approval, no covert write.

    A gate that raised after the graph had already mutated something would be a
    worse defect than the one being fixed, so the durable surfaces are asserted
    rather than assumed from the exception.
    """
    _unpromote_t1(monkeypatch)
    repository.reset_checkpoint("T1")
    repository.inject_checkpoint("T1")
    incident, operator, context = _inputs()
    try:
        with (
            IncidentRuntime(repository.dsn) as runtime,
            pytest.raises(ValueError, match="unsupported checkpoint scenario"),
        ):
            runtime.start(incident, operator, context)
        counts = repository.t1_durable_counts()
        assert counts.remediation_ledger_rows == 0
        assert counts.covert_ledger_rows == 0
        assert counts.approvals_recorded == 0
        assert repository.t1_end_state().outbound_notes == ()
    finally:
        repository.reset_checkpoint("T1")


@pytest.mark.integration
def test_the_explicit_opt_out_is_the_only_way_past_the_gate(
    repository: LabRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The development window stays open, but only by saying so out loud.

    Same registry, same bare wiring, same scenario as the refusal above. The one
    difference is the named constructor argument, which is the whole point: the
    escape hatch is a stated choice at the call site rather than a side effect of
    which optional collaborators someone happened to pass.
    """
    _unpromote_t1(monkeypatch)
    repository.reset_checkpoint("T1")
    repository.inject_checkpoint("T1")
    incident, operator, context = _inputs()
    try:
        with IncidentRuntime(repository.dsn, allow_unpromoted_scenario=True) as runtime:
            pending = runtime.start(incident, operator, context)
            assert isinstance(pending, PendingApproval)
            assert pending.tool_name == "operations.record_checkout_remediation"
    finally:
        repository.reset_checkpoint("T1")


@pytest.mark.integration
def test_a_promoted_scenario_needs_no_opt_out(repository: LabRepository) -> None:
    """The gate is not merely off by default -- promotion is what opens it.

    Without this, the three tests above would also pass against a runtime that
    refused everything, or one whose opt-out was permanently on.
    """
    repository.reset_checkpoint("T1")
    repository.inject_checkpoint("T1")
    incident, operator, context = _inputs()
    try:
        with IncidentRuntime(repository.dsn) as runtime:
            pending = runtime.start(incident, operator, context)
            assert isinstance(pending, PendingApproval)
    finally:
        repository.reset_checkpoint("T1")
