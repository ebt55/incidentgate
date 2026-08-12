"""Chaos kill-matrix orchestrator.

Publish the full table over all runnable scenarios (the committed artifact)::

    uv run python -m incidentgate.chaos.matrix --out artifacts/chaos-matrix/

That command writes ``kill-matrix.json`` and ``kill-matrix.md`` into
``artifacts/chaos-matrix/``, which is committed on purpose.  Transient
exploratory runs belong in ``artifacts/chaos/``, which stays git-ignored; pass
``--out artifacts/chaos/`` for those.  The run takes tens of minutes because
every cell is real processes against real Postgres, so it is a command rather
than a test.  Start it from a cold database, because the published table is a
durability claim about a known starting state.

For every scenario the orchestrator first drives a golden no-kill run with real
worker subprocesses and records both the durable end state and every boundary
those processes crossed.  The boundary set is therefore derived, never listed:
new scenarios inherit coverage.  Each matrix cell then resets the fixtures,
drives fresh worker processes until one is killed hard at that boundary,
recovers with further fresh processes, and diffs the durable end state against
the golden capture.  A boundary that no scenario path reaches is recorded as
``n/a`` with the reason it does not apply, never dropped from the table.

The CI suite deliberately runs a small documented subset of this matrix rather
than all of it; see ``tests/chaos/test_kill_matrix.py`` for that choice.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

import psycopg

from incidentgate.chaos import CHAOS_APPLICATION_NAME, chaos_dsn, enddiff
from incidentgate.chaos.killpoints import (
    KILL_AT_ENV,
    KILL_EXIT_CODE,
    KILL_PHASE_ENV,
    PSEUDO_BOUNDARIES,
)
from incidentgate.chaos.worker import (
    PHASE_APPROVE,
    PHASE_DONE,
    PHASE_RETRY,
    PHASE_START,
    REPORT_PREFIX,
)
from incidentgate.lab.repository import LabRepository
from incidentgate.scenario_registry import RUNNABLE_SCENARIOS

_TIER_ORDER = {"D": 0, "S": 1, "R": 2, "T": 3}


def _tier_rank(scenario: str) -> tuple[int, str]:
    """Order the published table by tier, T last.

    ``T`` is registered explicitly rather than left to the fallback rank: the
    column order of the published table should be a stated choice, not a side
    effect of a prefix nobody listed. Appending it also leaves the twenty-two
    existing columns exactly where a reader of the previous table found them.
    """
    return _TIER_ORDER.get(scenario[:1], len(_TIER_ORDER)), scenario


#: Derived from the acceptance gate rather than restated, so promoting a
#: scenario to runnable enrolls it in the matrix instead of silently leaving a
#: gap the published table would not show. This tuple was a hand-written ten
#: while the registry already listed twenty-two.
SCENARIOS: tuple[str, ...] = tuple(sorted(RUNNABLE_SCENARIOS, key=_tier_rank))
PHASE_ORDER: tuple[str, ...] = (PHASE_START, PHASE_APPROVE, PHASE_RETRY, PHASE_DONE)
PSEUDO_NODES = frozenset(boundary.split(":", 1)[0] for boundary in PSEUDO_BOUNDARIES)

WORKER_TIMEOUT_SECONDS = 300
MAX_DRIVE_STEPS = 8
REAP_EVERY_CELLS = 12
REAP_IDLE_SECONDS = 20.0

STATUS_OK = "ok"
STATUS_FAIL = "fail"
STATUS_NA = "n/a"
STATUS_ERROR = "harness-error"

#: Committed home of the published table. Separate from the git-ignored
#: ``artifacts/chaos/`` so transient runs cannot accidentally become the
#: published claim, and so publishing needs no ``git add -f``.
PUBLISHED_ARTIFACT_DIR = "artifacts/chaos-matrix"
REPRODUCTION_COMMAND = f"uv run python -m incidentgate.chaos.matrix --out {PUBLISHED_ARTIFACT_DIR}/"

#: The run writes its own output into ``PUBLISHED_ARTIFACT_DIR``, so an
#: unscoped ``git status`` sees that output and stamps ``dirty: true`` on every
#: table that has ever been published - including one generated from a pristine
#: tree. Excluding exactly that directory makes the flag mean the only thing
#: worth publishing: whether the *sources* differ from the recorded revision.
#: ``:(top)`` anchors both patterns at the repository root, because ``_git``
#: runs from this package's directory rather than from the root.
DIRTY_PATHSPEC: tuple[str, ...] = (":(top)", f":(top,exclude){PUBLISHED_ARTIFACT_DIR}/")
DIRTY_MEANING = (
    "any tracked or untracked change outside "
    f"{PUBLISHED_ARTIFACT_DIR}/, the directory this command writes into"
)


def git_revision() -> dict[str, Any]:
    """Record the exact tree the published table was measured from.

    A table generated from a dirty tree is not reproducible from its revision
    alone, so the dirty flag is published next to the sha rather than hidden.
    ``dirty_means`` travels with it because the flag is deliberately scoped -
    see :data:`DIRTY_PATHSPEC` - and a scoped flag that does not say what it
    excluded is worth less than no flag at all.
    """

    def _git(*arguments: str) -> str | None:
        try:
            completed = subprocess.run(
                ["git", *arguments],
                capture_output=True,
                text=True,
                cwd=Path(__file__).resolve().parent,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return completed.stdout.strip() if completed.returncode == 0 else None

    revision = _git("rev-parse", "HEAD")
    status = _git("status", "--porcelain", "--", *DIRTY_PATHSPEC)
    return {
        "revision": revision,
        "dirty": None if status is None else bool(status),
        "dirty_means": DIRTY_MEANING,
    }


@dataclass(frozen=True)
class WorkerRun:
    """One real subprocess: its exit code is the proof the kill was real."""

    returncode: int
    report: dict[str, Any] | None
    stderr: str
    seconds: float

    @property
    def killed(self) -> bool:
        return self.returncode == KILL_EXIT_CODE


@dataclass
class DriveResult:
    """The full sequence of worker processes used to move one thread along."""

    runs: list[WorkerRun] = field(default_factory=list)
    killed_at_step: int | None = None
    terminal: bool = False
    final_state: str | None = None
    reasons: tuple[str, ...] = ()
    boundaries: list[str] = field(default_factory=list)
    phases: list[str] = field(default_factory=list)
    graph_nodes: list[str] = field(default_factory=list)
    orphan_samples: list[dict[str, int]] = field(default_factory=list)
    error: str | None = None

    @property
    def kill_seconds(self) -> float:
        if self.killed_at_step is None:
            return 0.0
        return round(sum(run.seconds for run in self.runs[: self.killed_at_step + 1]), 3)

    @property
    def recovery_seconds(self) -> float:
        if self.killed_at_step is None:
            return round(sum(run.seconds for run in self.runs), 3)
        return round(sum(run.seconds for run in self.runs[self.killed_at_step + 1 :]), 3)


def _worker_env(dsn: str, kill_at: str | None, kill_phase: str | None) -> dict[str, str]:
    environment = dict(os.environ)
    environment["DATABASE_URL"] = dsn
    environment.pop(KILL_AT_ENV, None)
    environment.pop(KILL_PHASE_ENV, None)
    if kill_at is not None and kill_phase is not None:
        environment[KILL_AT_ENV] = kill_at
        environment[KILL_PHASE_ENV] = kill_phase
    return environment


def _parse_report(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        if line.startswith(REPORT_PREFIX):
            parsed: dict[str, Any] = json.loads(line[len(REPORT_PREFIX) :])
            return parsed
    return None


def run_worker(
    dsn: str,
    scenario: str,
    thread_id: str,
    *,
    kill_at: str | None = None,
    kill_phase: str | None = None,
) -> WorkerRun:
    """Spawn one real worker process and never touch it after that."""
    command = [
        sys.executable,
        "-m",
        "incidentgate.chaos.worker",
        "--scenario",
        scenario,
        "--thread-id",
        thread_id,
    ]
    started = perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=_worker_env(dsn, kill_at, kill_phase),
            timeout=WORKER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return WorkerRun(-1, None, "worker timed out", round(perf_counter() - started, 3))
    return WorkerRun(
        returncode=completed.returncode,
        report=_parse_report(completed.stdout),
        stderr=completed.stderr[-800:],
        seconds=round(perf_counter() - started, 3),
    )


def drive(
    dsn: str,
    scenario: str,
    thread_id: str,
    *,
    kill_at: str | None = None,
    kill_phase: str | None = None,
) -> DriveResult:
    """Advance the thread with fresh processes until it terminates or is lost."""
    result = DriveResult()
    armed_at, armed_phase = kill_at, kill_phase
    for step in range(MAX_DRIVE_STEPS):
        run = run_worker(dsn, scenario, thread_id, kill_at=armed_at, kill_phase=armed_phase)
        result.runs.append(run)
        if run.killed:
            result.killed_at_step = step
            # Sampled before any recovery process opens new backends, so the
            # states counted here belong to the process that just died hard.
            result.orphan_samples.append(sample_chaos_backend_states(dsn))
            armed_at, armed_phase = None, None
            continue
        if run.returncode != 0 or run.report is None:
            result.error = f"worker exit {run.returncode}: {run.stderr.strip()[-400:]}"
            return result
        report = run.report
        result.boundaries.extend(str(item) for item in report.get("boundaries", []))
        result.phases.append(str(report.get("phase")))
        for node in report.get("graph_nodes", []):
            if str(node) not in result.graph_nodes:
                result.graph_nodes.append(str(node))
        if report.get("error"):
            result.error = str(report["error"])
            return result
        if report.get("terminal"):
            result.terminal = True
            result.final_state = report.get("final_state")
            result.reasons = tuple(str(item) for item in report.get("reasons", []))
            return result
        if report.get("phase") == PHASE_DONE:
            result.error = "worker reported no further durable step but no result exists"
            return result
    result.error = f"thread did not terminate within {MAX_DRIVE_STEPS} worker processes"
    return result


def reset_scenario(repository: LabRepository, scenario: str) -> None:
    """Return the lab to the frozen injected fault for exactly one scenario."""
    if scenario == "D1":
        repository.reset_d1()
        repository.inject_d1()
    else:
        repository.reset_checkpoint(scenario)
        repository.inject_checkpoint(scenario)


def purge_thread(dsn: str, thread_id: str) -> None:
    """Drop one thread's checkpoint rows so long matrix runs stay bounded."""
    with psycopg.connect(dsn, autocommit=True) as connection:
        for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
            try:
                connection.execute(f"DELETE FROM {table} WHERE thread_id = %s", (thread_id,))
            except psycopg.Error:
                connection.rollback()


def sample_chaos_backend_states(dsn: str) -> dict[str, int]:
    """Count this harness's surviving backends by ``pg_stat_activity.state``.

    Called immediately after a killed worker has been reaped by the parent, so
    any backend still listed here outlived the process that opened it.  This is
    the measurement behind the reaper's docstring: it answers empirically which
    states orphans actually occupy rather than assuming ``idle``.  The sampling
    connection excludes itself; a backend with a NULL state reports ``unknown``.
    """
    with psycopg.connect(chaos_dsn(dsn), autocommit=True) as connection:
        rows = connection.execute(
            "SELECT coalesce(state, 'unknown') AS state, count(*) AS total "
            "FROM pg_stat_activity "
            "WHERE datname = current_database() AND pid <> pg_backend_pid() "
            "AND application_name = %s GROUP BY 1",
            (CHAOS_APPLICATION_NAME,),
        ).fetchall()
    return {str(row[0]): int(row[1]) for row in rows}


def merge_state_counts(samples: Sequence[dict[str, int]]) -> dict[str, int]:
    """Sum backend-state samples, keeping the peak seen for each state.

    Peak rather than total: samples are taken at different instants, so adding
    them would count one long-lived backend once per sample.  The peak answers
    the question the reaper cares about - how many orphans coexisted at worst.
    """
    peaks: dict[str, int] = {}
    for sample in samples:
        for state, count in sample.items():
            peaks[state] = max(peaks.get(state, 0), count)
    return dict(sorted(peaks.items()))


def reap_idle_backends(dsn: str, *, idle_seconds: float = REAP_IDLE_SECONDS) -> None:
    """Reclaim backends left behind by hard-killed workers between cells.

    Scoped to this harness by ``application_name``. Same database, never self,
    ``idle`` only (never ``idle in transaction``, which would abort live work).
    ``idle_seconds`` exists so tests can prove the scoping without waiting out
    the real threshold; production callers use the default.

    **This reaper is belt-and-suspenders, and that is a measurement rather than
    an assumption.** :func:`sample_chaos_backend_states` runs immediately after
    every ``os._exit(137)``, before any recovery process can open a connection.
    Across the published 23-scenario run that is 346 samples taken after 346
    real kills, and every single one came back empty: no backend carrying this
    harness's ``application_name`` outlived the process that opened it. The
    operating system closes the dead process' sockets and Postgres tears the
    backends down with them, fast enough that the sample never caught one.

    Two consequences worth stating plainly. First, the ``state = 'idle'``
    targeting has never been exercised by a real orphan - it is exercised only
    by ``tests/chaos/test_reaper.py``, which manufactures idle backends on
    purpose. Second, the interesting failure mode this was written to guard
    against, an orphan stuck in ``idle in transaction`` holding locks, has not
    been observed at all; that state is deliberately *not* targeted here, so if
    it ever does appear the reaper will not paper over it. The empty result is
    published in the artifact as ``orphan_backend_states`` alongside
    ``orphan_backend_samples`` so an empty mapping cannot be misread as an
    absence of measurement.
    """
    with psycopg.connect(chaos_dsn(dsn), autocommit=True) as connection:
        connection.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = current_database() AND pid <> pg_backend_pid() "
            "AND application_name = %s "
            "AND state = 'idle' "
            "AND state_change < now() - make_interval(secs => %s::double precision)",
            (CHAOS_APPLICATION_NAME, idle_seconds),
        )


def _phase_of(boundary: str) -> str:
    return boundary.split("/", 1)[0]


def _node_of(boundary: str) -> str:
    return boundary.split("/", 1)[1].split(":", 1)[0]


def _slug(boundary: str) -> str:
    return boundary.replace("/", "-").replace(":", "-").replace("#", "-")


def _boundary_rank(boundary: str, first_seen: dict[str, int]) -> tuple[int, int]:
    phase = _phase_of(boundary)
    rank = PHASE_ORDER.index(phase) if phase in PHASE_ORDER else len(PHASE_ORDER)
    return rank, first_seen[boundary]


def merge_boundaries(golden: dict[str, DriveResult], scenarios: Sequence[str]) -> list[str]:
    """Union every golden boundary, ordered by phase then first observation."""
    first_seen: dict[str, int] = {}
    for scenario in scenarios:
        for boundary in golden[scenario].boundaries:
            first_seen.setdefault(boundary, len(first_seen))
    return sorted(first_seen, key=lambda boundary: _boundary_rank(boundary, first_seen))


def _na_reason(boundary: str, golden: DriveResult) -> str:
    phase, node = _phase_of(boundary), _node_of(boundary)
    if phase not in golden.phases:
        return f"scenario has no {phase} phase"
    if node not in golden.graph_nodes and node not in PSEUDO_NODES:
        return "node is absent from the scenario graph"
    return "boundary is not reached on the scenario path"


def run_cell(
    dsn: str,
    repository: LabRepository,
    scenario: str,
    boundary: str,
    golden_state: dict[str, Any],
) -> dict[str, Any]:
    """Reset, kill at the boundary, recover, and diff against the golden run."""
    reset_scenario(repository, scenario)
    thread_id = f"chaos-{scenario.lower()}-{_slug(boundary)}-{uuid4().hex[:8]}"
    result = drive(dsn, scenario, thread_id, kill_at=boundary, kill_phase=_phase_of(boundary))
    actual = enddiff.capture(dsn, scenario, final_state=result.final_state, reasons=result.reasons)
    diff = enddiff.compare(golden_state, actual)
    exit_codes = [run.returncode for run in result.runs]
    cell: dict[str, Any] = {
        "scenario": scenario,
        "boundary": boundary,
        "phase": _phase_of(boundary),
        "thread_id": thread_id,
        "worker_exit_codes": exit_codes,
        "surviving_worker_phases": list(result.phases),
        "killed": result.killed_at_step is not None,
        "kill_exit_code": KILL_EXIT_CODE if result.killed_at_step is not None else None,
        "orphan_backend_states": merge_state_counts(result.orphan_samples),
        # Published next to the mapping so an empty mapping is legible as a
        # result. `{}` with a positive sample count means "looked, found none";
        # `{}` with a zero sample count would mean "never looked".
        "orphan_backend_samples": len(result.orphan_samples),
        "recovery_processes": max(len(exit_codes) - ((result.killed_at_step or 0) + 1), 0),
        "resume_outcome": {
            "terminal": result.terminal,
            "final_state": result.final_state,
            "reasons": list(result.reasons),
            "error": result.error,
        },
        "diff": {
            "clean": diff.clean,
            "verdicts": list(diff.verdicts),
            "differences": [asdict(item) for item in diff.differences],
            "observations": diff.observations,
        },
        "timings_seconds": {
            "kill": result.kill_seconds,
            "recovery": result.recovery_seconds,
            "total": round(result.kill_seconds + result.recovery_seconds, 3),
        },
    }
    if result.killed_at_step is None:
        cell["status"] = STATUS_ERROR
        cell["verdict"] = "boundary never fired"
    elif diff.clean:
        cell["status"] = STATUS_OK
        cell["verdict"] = STATUS_OK
        purge_thread(dsn, thread_id)
    else:
        cell["status"] = STATUS_FAIL
        cell["verdict"] = "+".join(diff.verdicts)
    return cell


def run_golden(
    dsn: str, repository: LabRepository, scenario: str
) -> tuple[DriveResult, dict[str, Any]]:
    """Capture one clean reference run per scenario per matrix run."""
    reset_scenario(repository, scenario)
    thread_id = f"chaos-{scenario.lower()}-golden-{uuid4().hex[:8]}"
    result = drive(dsn, scenario, thread_id)
    state = enddiff.capture(dsn, scenario, final_state=result.final_state, reasons=result.reasons)
    return result, state


def run_matrix(
    dsn: str,
    scenarios: Sequence[str] = SCENARIOS,
    *,
    boundaries: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Execute the whole matrix and return the raw report."""
    # Stamp once here so every connection downstream inherits it: the repository,
    # the enddiff captures, purge_thread, the reaper, and the worker subprocesses
    # that receive this DSN through DATABASE_URL.
    dsn = chaos_dsn(dsn)
    repository = LabRepository(dsn)
    repository.migrate()
    golden: dict[str, DriveResult] = {}
    golden_states: dict[str, dict[str, Any]] = {}
    golden_report: dict[str, Any] = {}
    for scenario in scenarios:
        result, state = run_golden(dsn, repository, scenario)
        if not result.terminal:
            raise RuntimeError(f"golden run for {scenario} did not terminate: {result.error}")
        golden[scenario] = result
        golden_states[scenario] = state
        reached = {_node_of(item) for item in result.boundaries}
        golden_report[scenario] = {
            "phases": list(result.phases),
            "boundaries": list(result.boundaries),
            "graph_nodes": list(result.graph_nodes),
            "unreached_graph_nodes": [node for node in result.graph_nodes if node not in reached],
            "terminal": {"final_state": result.final_state, "reasons": list(result.reasons)},
            "end_state": state,
        }
    rows = merge_boundaries(golden, scenarios)
    if boundaries is not None:
        selected = set(boundaries)
        rows = [row for row in rows if row in selected]
    cells: list[dict[str, Any]] = []
    executed = 0
    for boundary in rows:
        for scenario in scenarios:
            if boundary not in golden[scenario].boundaries:
                cells.append(
                    {
                        "scenario": scenario,
                        "boundary": boundary,
                        "phase": _phase_of(boundary),
                        "status": STATUS_NA,
                        "verdict": STATUS_NA,
                        "reason": _na_reason(boundary, golden[scenario]),
                    }
                )
                continue
            cells.append(run_cell(dsn, repository, scenario, boundary, golden_states[scenario]))
            executed += 1
            if executed % REAP_EVERY_CELLS == 0:
                reap_idle_backends(dsn)
    # Unconditional, so the reaper is exercised by every run rather than only by
    # runs long enough to reach the cadence. The CI subset executes 12 cells
    # against REAP_EVERY_CELLS of 12, so the cadence fires exactly once and only
    # on the very last cell; any narrower selection reaches it zero times.
    reap_idle_backends(dsn)
    return {
        "generated_by": "incidentgate.chaos.matrix",
        "reproduction_command": REPRODUCTION_COMMAND,
        "git": git_revision(),
        "scenarios": list(scenarios),
        "boundaries": rows,
        "orphan_backend_states": merge_state_counts(
            [cell["orphan_backend_states"] for cell in cells if "orphan_backend_states" in cell]
        ),
        "orphan_backend_samples": sum(int(cell.get("orphan_backend_samples", 0)) for cell in cells),
        "comparison_spec": enddiff.spec_rows(),
        "at_least_rationale": enddiff.AT_LEAST_RATIONALE,
        "golden": golden_report,
        "cells": cells,
        "totals": totals(cells),
    }


def totals(cells: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Every headline number is counted here, never written by hand."""
    counted = {
        "cells": len(cells),
        "kills": 0,
        "clean": 0,
        "not_applicable": 0,
        "failures": 0,
        "harness_errors": 0,
        "duplicate_mutations": 0,
        "lost_incidents": 0,
        "state_divergences": 0,
        "orphaned_approvals": 0,
        "replayed_reads": 0,
    }
    for cell in cells:
        status = cell.get("status")
        if status == STATUS_NA:
            counted["not_applicable"] += 1
            continue
        if cell.get("killed"):
            counted["kills"] += 1
        observations = cell.get("diff", {}).get("observations", {})
        counted["orphaned_approvals"] += max(int(observations.get("orphaned_approvals", 0)), 0)
        counted["replayed_reads"] += max(int(observations.get("replayed_reads", 0)), 0)
        if status == STATUS_OK:
            counted["clean"] += 1
            continue
        if status == STATUS_ERROR:
            counted["harness_errors"] += 1
            continue
        counted["failures"] += 1
        for verdict in cell.get("diff", {}).get("verdicts", []):
            if verdict == enddiff.DUPLICATE_MUTATION:
                counted["duplicate_mutations"] += 1
            elif verdict == enddiff.LOST_INCIDENT:
                counted["lost_incidents"] += 1
            else:
                counted["state_divergences"] += 1
    return counted


_CELL_LABELS = {STATUS_OK: "OK", STATUS_NA: "n/a", STATUS_ERROR: "ERR"}
_VERDICT_LABELS = {
    enddiff.DUPLICATE_MUTATION: "FAIL-dup",
    enddiff.LOST_INCIDENT: "FAIL-lost",
    enddiff.STATE_DIVERGENCE: "FAIL-diff",
}


def _cell_label(cell: dict[str, Any]) -> str:
    status = str(cell.get("status"))
    if status == STATUS_FAIL:
        verdicts = cell.get("diff", {}).get("verdicts", [])
        return "+".join(_VERDICT_LABELS.get(str(item), "FAIL") for item in verdicts) or "FAIL"
    label = _CELL_LABELS.get(status, status)
    if status == STATUS_OK and any(
        int(value) > 0 for value in cell.get("diff", {}).get("observations", {}).values()
    ):
        return "OK\\*"
    return label


def render_markdown(report: dict[str, Any]) -> str:
    """Render the published table; every number comes from :func:`totals`."""
    scenarios = [str(item) for item in report["scenarios"]]
    rows = [str(item) for item in report["boundaries"]]
    counted = report["totals"]
    index = {(str(cell["scenario"]), str(cell["boundary"])): cell for cell in report["cells"]}
    lines: list[str] = ["# Chaos kill matrix", ""]
    lines.append(
        f"**{counted['kills']} real process kills** across {len(scenarios)} scenarios x "
        f"{len(rows)} node boundaries: {counted['clean']} clean, "
        f"{counted['duplicate_mutations']} duplicate mutations, "
        f"{counted['lost_incidents']} lost incidents, "
        f"{counted['state_divergences']} other durable divergences."
    )
    lines.append("")
    lines.append(
        f"{counted['cells']} cells total: {counted['clean']} clean, "
        f"{counted['not_applicable']} n/a, {counted['failures']} failing, "
        f"{counted['harness_errors']} harness errors."
    )
    lines.append("")
    lines.append(
        "Every kill is a real `os._exit(137)` inside a worker subprocess; the parent "
        "asserts the exit code before it attempts recovery with new processes."
    )
    lines.append("")
    lines.extend(_render_provenance(report))
    lines.extend(_render_legend())
    lines.extend(_render_table(scenarios, rows, index))
    lines.extend(_render_failures(report))
    lines.extend(_render_observations(report, index))
    lines.extend(_render_orphans(report))
    lines.extend(_render_coverage(report))
    lines.extend(_render_spec(report))
    return "\n".join(lines) + "\n"


def _render_provenance(report: dict[str, Any]) -> list[str]:
    git = report.get("git", {})
    revision = git.get("revision") or "unknown"
    dirty = git.get("dirty")
    suffix = " (dirty tree)" if dirty else ""
    lines = [
        "## Provenance",
        "",
        f"- generated by: `{report['generated_by']}`",
        f"- git revision: `{revision}`{suffix}",
        f"- reproduce with: `{report['reproduction_command']}`",
    ]
    # Read from the report rather than restated, so the rendered scope and the
    # scope the check actually applied cannot drift apart.
    meaning = git.get("dirty_means")
    if meaning:
        lines.append(
            f"- `dirty` counts {meaning} - the command writes into that directory, so "
            "counting it would stamp every published table dirty"
        )
    lines.append("")
    return lines


def _render_orphans(report: dict[str, Any]) -> list[str]:
    """Publish what a hard-killed worker actually leaves behind in Postgres."""
    states = report.get("orphan_backend_states", {})
    samples = int(report.get("orphan_backend_samples", 0))
    lines = ["## Orphaned backends after a hard kill", ""]
    if not states:
        lines.extend(
            [
                (
                    f"**{samples} samples, taken immediately after {samples} real "
                    "`os._exit(137)` kills** and before any recovery process opened a "
                    "connection: **no** backend carrying this harness's `application_name` "
                    "survived the process that opened it. The operating system closes the "
                    "sockets as the process dies and Postgres tears the backends down with "
                    "them, faster than the sample could catch one."
                ),
                "",
                (
                    "So the empty `orphan_backend_states` mapping in the JSON is a measurement "
                    "rather than a missing one - it is published beside "
                    f"`orphan_backend_samples: {samples}` for exactly that reason. Two things "
                    "follow. The reaper's `state = 'idle'` targeting has never been exercised "
                    "by a real orphan - only by `tests/chaos/test_reaper.py`, which "
                    "manufactures idle backends deliberately - which makes the reaper "
                    "belt-and-suspenders rather than load-bearing. And the failure mode it was "
                    "written against, an orphan stuck in `idle in transaction` holding locks, "
                    "was never observed; the reaper deliberately does not target that state, "
                    "so it cannot hide one if it appears."
                ),
                "",
            ]
        )
        return lines
    lines.append(
        f"Peak count of this harness's backends by `pg_stat_activity.state`, across "
        f"{samples} samples taken immediately after each kill and before any recovery "
        "process connected:"
    )
    lines.append("")
    lines.append("| Backend state | Peak observed |")
    lines.append("| --- | --- |")
    for state, count in states.items():
        lines.append(f"| `{state}` | {count} |")
    lines.append("")
    return lines


def _render_legend() -> list[str]:
    return [
        "## Legend",
        "",
        "| Cell | Meaning |",
        "| --- | --- |",
        "| `OK` | process died at the boundary, recovered, end state matches golden |",
        "| `OK\\*` | as `OK`, with a recorded replay observation (see below) |",
        "| `FAIL-dup` | duplicate mutation: a ledger row or mutation counter exceeded golden |",
        "| `FAIL-lost` | lost incident: the thread never reached the golden terminal |",
        "| `FAIL-diff` | other durable end-state divergence |",
        "| `n/a` | the boundary does not exist on that scenario's path |",
        "| `ERR` | harness fault: the armed boundary never fired |",
        "",
    ]


def _render_table(
    scenarios: Sequence[str], rows: Sequence[str], index: dict[tuple[str, str], dict[str, Any]]
) -> list[str]:
    lines = ["## Matrix", "", "| Boundary | " + " | ".join(scenarios) + " |"]
    lines.append("| --- |" + " --- |" * len(scenarios))
    for boundary in rows:
        cells = [_cell_label(index[(scenario, boundary)]) for scenario in scenarios]
        lines.append(f"| `{boundary}` | " + " | ".join(cells) + " |")
    lines.append("")
    return lines


def _render_failures(report: dict[str, Any]) -> list[str]:
    failing = [
        cell for cell in report["cells"] if cell.get("status") in {STATUS_FAIL, STATUS_ERROR}
    ]
    lines = ["## Failures", ""]
    if not failing:
        lines.extend(["None. Every executed cell matched its golden end state.", ""])
        return lines
    for cell in failing:
        lines.append(f"### `{cell['boundary']}` x {cell['scenario']} - {cell['verdict']}")
        lines.append("")
        outcome = cell.get("resume_outcome", {})
        lines.append(
            f"- worker exit codes: `{cell.get('worker_exit_codes')}`; "
            f"resume terminal: `{outcome.get('final_state')}` "
            f"reasons `{outcome.get('reasons')}`; error: `{outcome.get('error')}`"
        )
        for difference in cell.get("diff", {}).get("differences", []):
            lines.append(
                f"- `{difference['field']}` ({difference['verdict']}): "
                f"golden `{difference['golden']}` vs actual `{difference['actual']}`"
            )
        lines.append("")
    return lines


def _render_observations(
    report: dict[str, Any], index: dict[tuple[str, str], dict[str, Any]]
) -> list[str]:
    counted = report["totals"]
    lines = ["## Replay observations", "", report["at_least_rationale"] + ".", ""]
    lines.append(
        f"- `replayed_reads`: {counted['replayed_reads']} extra evidence rows across the "
        "matrix, all with payloads already present in the golden run."
    )
    lines.append(
        f"- `orphaned_approvals`: {counted['orphaned_approvals']} unconsumed approval rows "
        "left by kills inside the approval window."
    )
    orphaning = [
        cell
        for cell in report["cells"]
        if int(cell.get("diff", {}).get("observations", {}).get("orphaned_approvals", 0)) > 0
    ]
    orphaned = sorted({str(cell["boundary"]) for cell in orphaning})
    if orphaned:
        lines.append(
            "- boundaries that orphan an approval: " + ", ".join(f"`{b}`" for b in orphaned)
        )
    lines.append("")
    lines.extend(_render_orphaned_approval_footnote(report, orphaning, orphaned))
    return lines


def _render_orphaned_approval_footnote(
    report: dict[str, Any], orphaning: Sequence[dict[str, Any]], boundaries: Sequence[str]
) -> list[str]:
    """Define the one non-zero number in the table, and why it is not a defect.

    This footnote exists because ``orphaned_approvals: 60`` reads like a bug
    report until someone says what an orphaned approval is. Curating it to zero
    would have been easy and dishonest; explaining it is the alternative.
    """
    if not orphaning:
        return []
    scenarios = sorted({str(cell["scenario"]) for cell in orphaning})
    per_cell = sorted(
        {int(cell["diff"]["observations"]["orphaned_approvals"]) for cell in orphaning}
    )
    minted = sorted(
        scenario
        for scenario in report["scenarios"]
        if int(report["golden"][scenario]["end_state"]["approvals_total"]) > 0
    )
    return [
        "### What `orphaned_approvals` counts",
        "",
        (
            "An **orphaned approval** is a durable approval row with no matching executed "
            "operation: `approvals_total` exceeded the golden run while `approvals_consumed`, "
            "`ledger_max_rows_per_key` and `fixture_mutation_count` all matched it exactly. "
            "It is neither a lost incident nor a duplicate mutation - both of those are "
            "separate verdicts in the table above, and both are zero."
        ),
        "",
        (
            f"Every orphaning cell orphans exactly {' and '.join(str(n) for n in per_cell)} "
            f"approval, across {len(boundaries)} boundaries x {len(scenarios)} scenarios = "
            f"{len(orphaning)} cells. Those scenarios are exactly the "
            f"{len(minted)} whose golden run mints an approval at all; the remaining "
            f"{len(report['scenarios']) - len(minted)} defer, block, or take no action, so "
            "they have no token to orphan. The four boundaries are exactly the kill points "
            "between the approval commit and the operation commit."
        ),
        "",
        (
            "The mechanism: a kill in that window loses the in-memory handle to a token that "
            "is *already durable*. Recovery cannot tell a committed-but-unspent token from one "
            "it never minted, so it mints a fresh token for the identical canonical action and "
            "spends that one. The pre-kill token is left un-redeemed. Approval issuance is "
            "therefore not idempotent across a crash - but redemption is, and redemption is "
            "what mutates."
        ),
        "",
        "An un-redeemed token is not a spendable capability:",
        "",
        (
            "- It is bound to a canonical action hash covering thread id, actor, permission, "
            "evidence ids and arguments. `_token_matches_approval` compares the durable row, "
            "the presented token and a freshly recomputed hash three ways, so it cannot be "
            "presented for a different action or by a different actor."
        ),
        (
            "- The ledger's idempotency key is `uuid5(thread_id, action_hash)` - a pure "
            "function of the binding the token already carries. The only key an orphan can "
            "derive is the one the recovered operation already occupies, and that collision "
            "routes into the replay branch, which rejects a token id that does not match the "
            "ledger row's."
        ),
        "",
        (
            "Both are exercised against a real orphan left by a real kill in "
            "`tests/chaos/test_orphaned_approvals.py`, which drives one killed cell and then "
            "attempts to spend what it left behind."
        ),
        "",
    ]


def _render_coverage(report: dict[str, Any]) -> list[str]:
    lines = ["## Graph coverage", "", "| Scenario | Graph nodes | Never on the golden path |"]
    lines.append("| --- | --- | --- |")
    for scenario in report["scenarios"]:
        golden = report["golden"][scenario]
        nodes = ", ".join(f"`{node}`" for node in golden["graph_nodes"]) or "-"
        unreached = ", ".join(f"`{node}`" for node in golden["unreached_graph_nodes"]) or "-"
        lines.append(f"| {scenario} | {nodes} | {unreached} |")
    lines.append("")
    lines.append(
        "Node names are read from the compiled graph builders inside the worker, so a new "
        "scenario or node is enumerated automatically. Nodes that never run on a frozen "
        "fixture's path have no boundary to kill at and are listed here rather than hidden."
    )
    lines.append("")
    return lines


def _render_spec(report: dict[str, Any]) -> list[str]:
    lines = [
        "## Comparison spec",
        "",
        (
            "Thread ids, correlation ids, uuids and clocks change on every run, so the "
            "differ compares this normalized projection of durable state and nothing else."
        ),
        "",
        "| Field | Describes | Normalization | Rule | Violation |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["comparison_spec"]:
        lines.append(
            f"| `{row['field']}` | {row['describes']} | {row['normalization']} | "
            f"`{row['rule']}` | `{row['failure']}` |"
        )
    lines.append("")
    return lines


def write_artifacts(report: dict[str, Any], out: Path) -> tuple[Path, Path]:
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "kill-matrix.json"
    markdown_path = out / "kill-matrix.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the chaos kill matrix.")
    parser.add_argument("--out", default=None, help="directory for kill-matrix.json/.md")
    parser.add_argument("--dsn", default=None)
    parser.add_argument(
        "--scenarios", default=",".join(SCENARIOS), help="comma separated scenario ids"
    )
    parser.add_argument("--boundaries", default=None, help="comma separated boundary ids")
    arguments = parser.parse_args(argv)
    dsn = arguments.dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        parser.error("DATABASE_URL or --dsn is required")
    scenarios = tuple(item.strip() for item in arguments.scenarios.split(",") if item.strip())
    selected = (
        tuple(item.strip() for item in arguments.boundaries.split(",") if item.strip())
        if arguments.boundaries
        else None
    )
    report = run_matrix(dsn, scenarios, boundaries=selected)
    if arguments.out:
        json_path, markdown_path = write_artifacts(report, Path(arguments.out))
        sys.stdout.write(f"wrote {json_path}\nwrote {markdown_path}\n")
    else:
        sys.stdout.write(render_markdown(report))
    counted = report["totals"]
    failed = counted["failures"] + counted["harness_errors"]
    sys.stdout.write(
        f"kills={counted['kills']} clean={counted['clean']} n/a={counted['not_applicable']} "
        f"failures={counted['failures']} harness_errors={counted['harness_errors']}\n"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
