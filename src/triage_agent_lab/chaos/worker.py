"""One real OS process that advances one chaos scenario by exactly one phase.

    uv run python -m triage_agent_lab.chaos.worker --scenario D1 --thread-id t1

The phase is chosen from durable state alone, exactly as an operator would:
start an unknown thread, approve an interrupted one, retry a thread that is
mid-flight, do nothing once a result exists.  ``CHAOS_KILL_AT`` plus
``CHAOS_KILL_PHASE`` make the process die hard at one instrumented boundary.
Nothing in this module is imported by the product runtime.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from triage_agent_lab.chaos import killpoints
from triage_agent_lab.chaos.killpoints import APPROVAL_NODE, INTERRUPT, RECORDER
from triage_agent_lab.contracts import IncidentIdentity, IncidentState, Role, ToolCallContext
from triage_agent_lab.control.models import Caller
from triage_agent_lab.integration import IncidentRuntime, PendingApproval
from triage_agent_lab.lab.auth import Principal
from triage_agent_lab.scenario_registry import NO_ACTION_SCENARIOS

OPERATOR = "operator-1"
APPROVER = "approver-1"

PHASE_START = "start"
PHASE_APPROVE = "approve"
PHASE_RETRY = "retry"
PHASE_DONE = "done"

REPORT_PREFIX = "CHAOS-REPORT "


def scenario_inputs(
    scenario: str, thread_id: str
) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    """Build the one fixed operator envelope every chaos phase reuses."""
    incident = IncidentIdentity(
        incident_id=f"INC-{scenario}",
        scenario_id=scenario,
        thread_id=thread_id,
        correlation_id=f"corr-{thread_id}",
        state=IncidentState.OPEN,
    )
    caller = Caller(actor=OPERATOR, role=Role.OPERATOR)
    permission = "observability:read" if scenario in NO_ACTION_SCENARIOS else "operations:write"
    context = ToolCallContext(
        incident_id=incident.incident_id,
        thread_id=thread_id,
        correlation_id=incident.correlation_id,
        actor=caller.actor,
        permission=permission,
    )
    return incident, caller, context


def _awaiting_human(snapshot: Any) -> bool:
    """An outstanding interrupt, not merely a renderable pending approval."""
    if tuple(getattr(snapshot, "interrupts", ()) or ()):
        return True
    return any(getattr(task, "interrupts", ()) for task in getattr(snapshot, "tasks", ()) or ())


def decide_phase(runtime: IncidentRuntime, thread_id: str) -> str:
    """Choose the single durable step an operator would take next."""
    try:
        runtime.resume(thread_id)
    except (TypeError, ValueError):
        return PHASE_START
    graph: Any = runtime._graph
    if graph is None:
        return PHASE_START
    snapshot = graph.get_state({"configurable": {"thread_id": thread_id}})
    if dict(snapshot.values).get("result") is not None:
        return PHASE_DONE
    return PHASE_APPROVE if _awaiting_human(snapshot) else PHASE_RETRY


def _advance(runtime: IncidentRuntime, phase: str, scenario: str, thread_id: str) -> None:
    incident, caller, context = scenario_inputs(scenario, thread_id)
    if phase == PHASE_START:
        outcome = runtime.start(incident, caller, context)
        if isinstance(outcome, PendingApproval):
            RECORDER.record(APPROVAL_NODE, INTERRUPT)
    elif phase == PHASE_APPROVE:
        runtime.approve(thread_id, Principal(APPROVER, Role.APPROVER))
    elif phase == PHASE_RETRY:
        runtime.retry(thread_id)


def run(dsn: str, scenario: str, thread_id: str) -> dict[str, Any]:
    """Advance one phase and report the durable outcome this process observed."""
    killpoints.install()
    report: dict[str, Any] = {
        "scenario": scenario,
        "thread_id": thread_id,
        "phase": PHASE_DONE,
        "boundaries": [],
        "graph_nodes": [],
        "terminal": False,
        "final_state": None,
        "reasons": [],
        "awaiting_human": False,
        "error": None,
    }
    runtime = IncidentRuntime(dsn)
    try:
        phase = decide_phase(runtime, thread_id)
        report["phase"] = phase
        RECORDER.begin_phase(phase, killpoints.armed_boundary(phase))
        if phase != PHASE_DONE:
            _advance(runtime, phase, scenario, thread_id)
        graph: Any = runtime._graph
        if graph is not None:
            report["graph_nodes"] = list(killpoints.declared_node_names(graph))
            snapshot = graph.get_state({"configurable": {"thread_id": thread_id}})
            report["awaiting_human"] = _awaiting_human(snapshot)
        status = runtime.status(thread_id)
        result = status.result
        report["terminal"] = result is not None
        report["final_state"] = None if result is None else result.final_state
        report["reasons"] = [] if result is None else list(result.reasons)
    except Exception as error:  # noqa: BLE001 - every failure is a matrix datum.
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        report["boundaries"] = list(RECORDER.boundary_ids())
        try:
            runtime.close()
        except Exception as error:  # noqa: BLE001 - close failures are also data.
            report.setdefault("close_error", f"{type(error).__name__}: {error}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one chaos scenario phase.")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--thread-id", required=True)
    parser.add_argument("--dsn", default=None)
    arguments = parser.parse_args(argv)
    dsn = arguments.dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        parser.error("DATABASE_URL or --dsn is required")
    report = run(dsn, arguments.scenario, arguments.thread_id)
    sys.stdout.write(REPORT_PREFIX + json.dumps(report, sort_keys=True) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
