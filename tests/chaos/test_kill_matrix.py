"""CI-sized slice of the chaos kill matrix plus unit cover for the differ.

The full matrix stays a command (``python -m incidentgate.chaos.matrix``).
The live tests here run a representative subset: D1 across the interesting
windows, and one no-action scenario, all against real killed subprocesses.

Known unresolved flake (observed 2026-08-12).
``test_every_executed_cell_reaches_the_golden_end_state`` failed once during a
full-suite run on a clean tree and has not reproduced since: it passed on an
immediate rerun of the same suite, in eight consecutive isolated runs of this
module, and in every full-suite run afterwards. It is recorded here rather than
hidden behind a retry, a sleep, or a skip, because those turn a real signal into
a silent one. Ruled out so far: cross-test mutation of Postgres between the
golden capture and a cell capture - pytest runs serially, this package collects
first, the module-scoped ``subset`` fixture runs the whole matrix in one call,
and every cell re-runs ``reset_scenario`` before driving workers. Not yet known:
which cell failed and with what verdict, because that run was not captured with
a traceback. Capture the next occurrence with ``--tb=long``; the assertion below
already reports the failing cell's verdict and diff differences, and the cell's
``resume_outcome.error`` distinguishes a lost worker from a state divergence.
"""

from __future__ import annotations

import os
from typing import Any

import psycopg
import pytest

from incidentgate.chaos import enddiff, matrix
from incidentgate.chaos.killpoints import BoundaryEvent, boundary_id
from incidentgate.lab.repository import LabRepository

SELECTED_BOUNDARIES = (
    "start/collect:entry",
    "start/collect:exit",
    "start/approval:interrupt",
    "approve/approval_token:committed",
    "approve/operation:committed",
)
SUBSET_SCENARIOS = ("D1", "S1")
NO_ACTION_BOUNDARIES = ("start/collect:entry", "start/collect:exit")


def _golden() -> dict[str, Any]:
    return {
        "terminal_final_state": "resolved",
        "terminal_reasons": ["recovery_verified"],
        "ledger_rows_by_scope": [["d1-api", 1]],
        "ledger_max_rows_per_key": 1,
        "fixture_mutation_count": 1,
        "fixture_generation": 0,
        "approvals_consumed": 1,
        "approvals_total": 1,
        "evidence_read_kinds": [["observability.health", "{}"]],
        "evidence_read_total": 4,
    }


def test_boundary_id_renders_phase_node_and_position() -> None:
    event = BoundaryEvent(node="execute", position="entry", occurrence=1)
    assert boundary_id("approve", event) == "approve/execute:entry"


def test_boundary_id_disambiguates_repeated_occurrences() -> None:
    event = BoundaryEvent(node="collect", position="exit", occurrence=2)
    assert boundary_id("start", event) == "start/collect:exit#2"


def test_comparison_spec_field_names_are_unique_and_typed() -> None:
    names = [spec.name for spec in enddiff.COMPARISON_SPEC]
    assert len(names) == len(set(names))
    assert {spec.rule for spec in enddiff.COMPARISON_SPEC} == {
        enddiff.RULE_EQUAL,
        enddiff.RULE_AT_LEAST,
    }


def test_compare_flags_a_duplicate_mutation() -> None:
    actual = {**_golden(), "fixture_mutation_count": 2, "ledger_rows_by_scope": [["d1-api", 2]]}
    diff = enddiff.compare(_golden(), actual)
    assert diff.verdicts == (enddiff.DUPLICATE_MUTATION,)
    assert {item.field for item in diff.differences} == {
        "fixture_mutation_count",
        "ledger_rows_by_scope",
    }


def test_compare_flags_a_lost_incident() -> None:
    actual = {**_golden(), "terminal_final_state": None, "terminal_reasons": []}
    diff = enddiff.compare(_golden(), actual)
    assert diff.verdicts == (enddiff.LOST_INCIDENT,)


def test_compare_allows_replayed_reads_but_not_different_reads() -> None:
    replayed = enddiff.compare(_golden(), {**_golden(), "evidence_read_total": 7})
    assert replayed.clean
    assert replayed.observations["replayed_reads"] == 3
    changed = enddiff.compare(
        _golden(), {**_golden(), "evidence_read_kinds": [["observability.logs", "{}"]]}
    )
    assert changed.verdicts == (enddiff.STATE_DIVERGENCE,)


def test_compare_treats_a_missing_durable_effect_as_a_lost_incident() -> None:
    diff = enddiff.compare(_golden(), {**_golden(), "approvals_total": 0})
    assert diff.verdicts == (enddiff.LOST_INCIDENT,)


@pytest.fixture(scope="module")
def subset() -> dict[str, Any]:
    """Run the representative matrix once for every live assertion below."""
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("chaos kill matrix requires DATABASE_URL")
    return matrix.run_matrix(dsn, SUBSET_SCENARIOS, boundaries=SELECTED_BOUNDARIES)


def _cells(report: dict[str, Any], scenario: str) -> dict[str, dict[str, Any]]:
    return {str(cell["boundary"]): cell for cell in report["cells"] if cell["scenario"] == scenario}


@pytest.mark.integration
def test_every_executed_cell_reaches_the_golden_end_state(subset: dict[str, Any]) -> None:
    failing = [
        (cell["scenario"], cell["boundary"], cell.get("verdict"), cell["diff"]["differences"])
        for cell in subset["cells"]
        if cell["status"] not in {matrix.STATUS_OK, matrix.STATUS_NA}
    ]
    assert failing == []
    assert subset["totals"]["duplicate_mutations"] == 0
    assert subset["totals"]["lost_incidents"] == 0


@pytest.mark.integration
def test_every_kill_is_a_real_process_exit(subset: dict[str, Any]) -> None:
    executed = [cell for cell in subset["cells"] if cell["status"] != matrix.STATUS_NA]
    assert executed
    for cell in executed:
        assert cell["killed"], cell["boundary"]
        assert matrix.KILL_EXIT_CODE in cell["worker_exit_codes"], cell["boundary"]
        assert cell["recovery_processes"] >= 1, cell["boundary"]


@pytest.mark.integration
def test_d1_covers_every_requested_window(subset: dict[str, Any]) -> None:
    assert set(_cells(subset, "D1")) == set(SELECTED_BOUNDARIES)


@pytest.mark.integration
def test_approval_window_kill_keeps_exactly_one_consumed_approval(
    subset: dict[str, Any],
) -> None:
    cell = _cells(subset, "D1")["approve/approval_token:committed"]
    assert cell["status"] == matrix.STATUS_OK
    assert cell["diff"]["observations"]["orphaned_approvals"] >= 0
    assert cell["resume_outcome"]["final_state"] == "resolved"


@pytest.mark.integration
def test_response_loss_window_kill_does_not_duplicate_the_mutation(
    subset: dict[str, Any],
) -> None:
    cell = _cells(subset, "D1")["approve/operation:committed"]
    assert cell["status"] == matrix.STATUS_OK
    assert enddiff.DUPLICATE_MUTATION not in cell["diff"]["verdicts"]
    assert cell["resume_outcome"]["terminal"] is True


@pytest.mark.integration
def test_no_action_scenario_marks_the_approval_windows_not_applicable(
    subset: dict[str, Any],
) -> None:
    cells = _cells(subset, "S1")
    executed = {name for name, cell in cells.items() if cell["status"] != matrix.STATUS_NA}
    assert executed == set(NO_ACTION_BOUNDARIES)
    for name in set(SELECTED_BOUNDARIES) - set(NO_ACTION_BOUNDARIES):
        assert cells[name]["status"] == matrix.STATUS_NA
        assert cells[name]["reason"]


@pytest.mark.integration
def test_boundaries_are_derived_from_the_compiled_graphs(subset: dict[str, Any]) -> None:
    d1_nodes = subset["golden"]["D1"]["graph_nodes"]
    assert {"ingest", "collect", "approval", "execute", "verify"} <= set(d1_nodes)
    assert subset["golden"]["S1"]["graph_nodes"] == ["collect"]
    assert set(subset["golden"]["D1"]["unreached_graph_nodes"]) == {
        "deny",
        "blocked",
        "monitor_mismatch",
    }


@pytest.mark.integration
def test_the_differ_catches_a_real_duplicate_mutation_in_postgres() -> None:
    """Negative control: a green matrix must be able to go red on real state."""
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("chaos kill matrix requires DATABASE_URL")
    repository = LabRepository(dsn)
    repository.migrate()
    matrix.reset_scenario(repository, "D1")
    baseline = enddiff.capture(dsn, "D1", final_state="resolved", reasons=("recovery_verified",))
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(
            "UPDATE target_state SET mutation_count = mutation_count + 1 WHERE component = 'api'"
        )
    try:
        tampered = enddiff.capture(
            dsn, "D1", final_state="resolved", reasons=("recovery_verified",)
        )
        diff = enddiff.compare(baseline, tampered)
        assert enddiff.DUPLICATE_MUTATION in diff.verdicts
        assert "fixture_mutation_count" in {item.field for item in diff.differences}
    finally:
        matrix.reset_scenario(repository, "D1")


@pytest.mark.integration
def test_rendered_artifact_headline_is_computed(subset: dict[str, Any]) -> None:
    counted = subset["totals"]
    rendered = matrix.render_markdown(subset)
    assert f"**{counted['kills']} real process kills**" in rendered
    assert f"{counted['duplicate_mutations']} duplicate mutations" in rendered
    assert f"{counted['lost_incidents']} lost incidents" in rendered
    assert "| Boundary |" in rendered
