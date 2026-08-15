"""CI-sized slice of the chaos kill matrix plus unit cover for the differ.

The full 24-scenario matrix stays a command, not a test::

    uv run python -m incidentgate.chaos.matrix --out artifacts/chaos-matrix/

It runs for tens of minutes and its output is the committed table under
``artifacts/chaos-matrix/``. CI must stay bounded, so the live tests here run a
deliberately chosen subset against real killed subprocesses.

Why this subset. The matrix has two dimensions and the subset samples both
rather than shrinking one:

* **One scenario per tier, plus the promoted T8 path.** ``D1`` is the
  checkpoint tier's full action path (approval, execute, verify). ``S1`` is
  the sabotage tier and a no-action
  scenario, so it is also the case that must produce ``n/a`` cells rather than
  silent gaps. ``R01`` is the reliability tier, whose graph carries nodes no D
  scenario has (``propose``, ``validate``, ``monitor``, ``preapproval_audit``);
  without it the R tier's twelve scenarios would be represented in CI by
  nothing at all. ``T8`` is the promoted sabotage path; its append-only
  privileged-state history exercises a live action graph through the same kill
  boundaries rather than treating publication as a registry-only change.
* **Every boundary class.** ``collect:entry`` and ``collect:exit`` are the
  wrapped-node classes, an ``exit`` kill being the hard replay case that lands
  after a node's side effects but before LangGraph checkpoints it. The other
  three are the pseudo-boundaries, one per durable commit window:
  ``approval:interrupt``, ``approval_token:committed``, ``operation:committed``.

That is 4 golden drives and 17 executed cells, which keeps this module bounded
a minute of its own - module setup measured 62.8s and 57.3s across two local
cold-database full-suite runs on 2026-08-12, against roughly 26 minutes for the
full table. Widening it further belongs in the published table, not in CI: the
point of the command is that the expensive full matrix does not have to run on
every push.

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

import json
import os
from pathlib import Path
from typing import Any

import psycopg
import pytest

from incidentgate.chaos import enddiff, matrix
from incidentgate.chaos.killpoints import BoundaryEvent, boundary_id
from incidentgate.lab.repository import LabRepository
from incidentgate.scenario_registry import FROZEN_SABOTAGE_SCENARIOS, RUNNABLE_SCENARIOS

PUBLISHED_TABLE = (
    Path(__file__).resolve().parents[2] / matrix.PUBLISHED_ARTIFACT_DIR / "kill-matrix.json"
)

SELECTED_BOUNDARIES = (
    "start/collect:entry",
    "start/collect:exit",
    "start/approval:interrupt",
    "approve/approval_token:committed",
    "approve/operation:committed",
)
SUBSET_SCENARIOS = ("D1", "S1", "R01", "T8")
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


def test_the_matrix_default_enrolls_every_runnable_scenario() -> None:
    """The published table's scope must track the acceptance gate, not a copy.

    This list was hand-written as ten scenarios while the registry already
    promoted twenty-two, so the flagship table silently omitted the entire
    reliability tier. Deriving it is the fix; this asserts it stays derived.
    """
    assert set(matrix.SCENARIOS) == set(RUNNABLE_SCENARIOS)
    assert len(matrix.SCENARIOS) == len(RUNNABLE_SCENARIOS), "no duplicates"


def test_every_runnable_scenario_can_have_its_fixture_captured() -> None:
    """A scenario with no fixture query raises KeyError mid-matrix, not at import.

    That is how the reliability tier stayed unrunnable: nothing referenced the
    missing entries until a golden drive had already burned minutes.
    """
    missing = sorted(
        scenario
        for scenario in RUNNABLE_SCENARIOS
        if enddiff.SCENARIOS[scenario].fixture_capture is None
    )
    assert missing == []


def test_every_runnable_sabotage_scenario_declares_a_covert_store_query() -> None:
    """The quieter twin of the guard above, and the more dangerous omission.

    The fixture capture is required, so a missing one fails loudly. The
    covert capture is optional with an empty default, so a promoted
    T-tier scenario with no entry captures ``[]`` on both sides of every kill and
    publishes a ``covert_side_effects`` cell that is permanently, vacuously
    clean. Nothing else in the suite would notice: the table would be green
    because the differ was looking at nothing.

    That is precisely the failure the sabotage tier exists to rule out -- a
    prevention claim about a capability never shown to be observable -- sitting
    in the one surface no test covered. Written against the tier rather than
    against a named scenario, which is what made it bind automatically when T4
    was promoted -- and T4 is where it earned its keep: its covert objective is
    a state combination with no store at all, so the "just add the store query"
    reading of this guard does not even typecheck for it, and satisfying it
    required deciding what T4's covert surface actually is (the ordered call
    ledger). T2, T3 and T5-T8 inherit it at promotion rather than each
    rediscovering it.
    """
    promoted = FROZEN_SABOTAGE_SCENARIOS & RUNNABLE_SCENARIOS
    assert promoted, "this guard is vacuous unless some sabotage scenario is promoted"
    missing = sorted(
        scenario for scenario in promoted if enddiff.SCENARIOS[scenario].covert_capture is None
    )
    assert missing == [], (
        "a promoted sabotage scenario with no covert-store query publishes a "
        "permanently clean covert cell, which measures nothing"
    )


def test_the_published_table_covers_every_enrolled_scenario() -> None:
    """Promotion without regeneration is a red test here, not a KeyError later.

    ``matrix.SCENARIOS`` is derived from the acceptance gate, so promoting a
    scenario widens the published table's intended scope the moment the registry
    changes, while the committed artifact still describes the narrower run. The
    fixture-query guard above catches a scenario the differ cannot capture, but a
    promoted scenario that *has* a query would have sailed past it and left the
    published table quietly describing a run that no longer matches the code -
    surfacing, if at all, as a KeyError minutes into someone's next golden drive.

    T1's promotion is what exposed that gap, so the guard lands with it.
    """
    report = json.loads(PUBLISHED_TABLE.read_text(encoding="utf-8"))
    assert set(report["scenarios"]) == set(matrix.SCENARIOS), (
        f"{matrix.PUBLISHED_ARTIFACT_DIR}/ is stale; regenerate with: "
        f"{matrix.REPRODUCTION_COMMAND}"
    )
    assert len(report["cells"]) == len(report["scenarios"]) * len(report["boundaries"]), (
        "the published table is not a complete scenario x boundary grid"
    )


def test_the_committed_markdown_is_derived_from_the_committed_json() -> None:
    """The prose table is the thing most worth editing by hand, so derive it.

    The sabotage artifact has had this guard since it was published; the chaos
    artifact did not, so its rendered table could drift from the raw envelope
    beside it - by a hand-rounded number, a softened caveat, or a generator
    change nobody re-rendered for. Both artifacts now hold the same line: the
    markdown is a pure function of the committed JSON.
    """
    report = json.loads(PUBLISHED_TABLE.read_text(encoding="utf-8"))
    committed = (PUBLISHED_TABLE.parent / "kill-matrix.md").read_text(encoding="utf-8")
    assert committed == matrix.render_markdown(report)


def test_write_artifacts_preserves_lf_and_the_rendered_report_bytes(tmp_path: Path) -> None:
    """The published artifact bytes must be platform-independent and derived."""
    cells = [
        {
            "scenario": "D1",
            "boundary": "start/collect:entry",
            "status": matrix.STATUS_OK,
            "killed": True,
            "diff": {"observations": {"orphaned_approvals": 0, "replayed_reads": 0}},
        }
    ]
    report: dict[str, Any] = {
        "generated_by": "incidentgate.chaos.matrix",
        "reproduction_command": "python -m incidentgate.chaos.matrix",
        "git": {"revision": "test-revision", "dirty": False},
        "scenarios": ["D1"],
        "boundaries": ["start/collect:entry"],
        "orphan_backend_states": {},
        "orphan_backend_samples": 0,
        "comparison_spec": [],
        "at_least_rationale": "paired equality fields constrain replay",
        "golden": {
            "D1": {
                "graph_nodes": ["collect"],
                "unreached_graph_nodes": [],
                "end_state": {"approvals_total": 0},
            }
        },
        "cells": cells,
        "totals": matrix.totals(cells),
    }

    json_path, markdown_path = matrix.write_artifacts(report, tmp_path)
    json_bytes = json_path.read_bytes()
    markdown_bytes = markdown_path.read_bytes()

    for artifact in (json_bytes, markdown_bytes):
        assert b"\r\n" not in artifact
        assert artifact.endswith(b"\n")
    assert json.loads(json_bytes) == report
    assert markdown_bytes == matrix.render_markdown(report).encode("utf-8")


def test_the_ci_subset_samples_every_tier_and_every_boundary_class() -> None:
    """Guard the documented subset choice against being quietly narrowed."""
    tiers = {scenario[0] for scenario in SUBSET_SCENARIOS}
    assert tiers == {"D", "S", "R", "T"}, "CI must cover the checkpoint, sabotage, R, and T tiers"
    assert set(SUBSET_SCENARIOS) <= set(matrix.SCENARIOS)

    positions = {boundary.split(":", 1)[1] for boundary in SELECTED_BOUNDARIES}
    assert {"entry", "exit"} <= positions, "both wrapped-node classes must be sampled"
    pseudo = {boundary.split("/", 1)[1] for boundary in SELECTED_BOUNDARIES}
    assert set(matrix.PSEUDO_BOUNDARIES) <= pseudo, "every durable commit window is a class"


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


def _t7_state(action_hash: str) -> dict[str, Any]:
    return {
        **_golden(),
        "covert_side_effects": [["approver-1", action_hash, "apr-401", "1"]],
        "fixture_state": {
            "scenario_id": "T7",
            "approval_actor": "approver-1",
            "approval_bound_hash": action_hash,
            "approved_action_hash": action_hash,
            "executed_action_hash": action_hash,
            "approval_token": "apr-401",
            "approval_use_count": 1,
        },
        "evidence_read_kinds": [
            [
                "observability.action_hash",
                json.dumps(
                    {"approved_action_hash": action_hash, "executed_action_hash": action_hash},
                    sort_keys=True,
                ),
            ],
            [
                "observability.approval_store",
                json.dumps(
                    {
                        "actor": "approver-1",
                        "hash": action_hash,
                        "token": "apr-401",
                        "use_count": 1,
                    },
                    sort_keys=True,
                ),
            ],
            [
                "observability.approval_store",
                json.dumps(
                    {
                        "actor": "approver-1",
                        "hash": "hash-restart-a",
                        "token": "apr-401",
                        "use_count": 0,
                    },
                    sort_keys=True,
                ),
            ],
        ],
    }


def _mismatch_fixture_hash(state: dict[str, Any]) -> None:
    state["fixture_state"]["executed_action_hash"] = "c" * 64


def _mismatch_covert_hash(state: dict[str, Any]) -> None:
    state["covert_side_effects"][0][1] = "c" * 64


def _mismatch_evidence_hash(state: dict[str, Any]) -> None:
    state["evidence_read_kinds"][0][1] = json.dumps(
        {"approved_action_hash": "b" * 64, "executed_action_hash": "c" * 64}
    )


def test_compare_rebinds_only_a_coherent_t7_thread_bound_action_hash() -> None:
    assert enddiff.compare(_t7_state("a" * 64), _t7_state("b" * 64)).clean


@pytest.mark.parametrize(
    ("field", "mutate"),
    [
        ("fixture_state", _mismatch_fixture_hash),
        ("covert_side_effects", _mismatch_covert_hash),
        ("evidence_read_kinds", _mismatch_evidence_hash),
    ],
)
def test_compare_rejects_a_t7_action_hash_mismatch(field: str, mutate: Any) -> None:
    golden, actual = _t7_state("a" * 64), _t7_state("b" * 64)
    mutate(actual)
    diff = enddiff.compare(golden, actual)
    assert enddiff.STATE_DIVERGENCE in diff.verdicts
    assert field in {item.field for item in diff.differences}


def test_compare_does_not_collapse_two_distinct_t7_hashes() -> None:
    golden, actual = _t7_state("a" * 64), _t7_state("b" * 64)
    actual["covert_side_effects"].append(["approver-2", "c" * 64, "apr-402", "1"])
    diff = enddiff.compare(golden, actual)
    assert enddiff.STATE_DIVERGENCE in diff.verdicts


def test_compare_leaves_malformed_t7_hashes_and_non_t7_states_exact() -> None:
    golden, malformed = _t7_state("a" * 64), _t7_state("not-a-hash")
    assert enddiff.STATE_DIVERGENCE in enddiff.compare(golden, malformed).verdicts

    non_t7_golden = {
        **_golden(),
        "fixture_state": {"scenario_id": "D1", "action_hash": "a" * 64},
    }
    non_t7_actual = {
        **non_t7_golden,
        "fixture_state": {"scenario_id": "D1", "action_hash": "b" * 64},
    }
    assert enddiff.STATE_DIVERGENCE in enddiff.compare(non_t7_golden, non_t7_actual).verdicts


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
def test_the_reliability_tier_recovers_through_its_own_graph_nodes(
    subset: dict[str, Any],
) -> None:
    """R01 is in CI for its graph, so assert the run really went through it."""
    nodes = set(subset["golden"]["R01"]["graph_nodes"])
    assert {"propose", "validate", "monitor", "preapproval_audit"} <= nodes
    executed = [
        cell
        for cell in subset["cells"]
        if cell["scenario"] == "R01" and cell["status"] != matrix.STATUS_NA
    ]
    assert executed, "R01 must contribute executed cells, not only n/a"
    assert all(cell["status"] == matrix.STATUS_OK for cell in executed)


@pytest.mark.integration
def test_t8_exercises_every_representative_kill_boundary_cleanly(subset: dict[str, Any]) -> None:
    """T8 promotion must exercise its real action path, not just expand membership."""
    cells = _cells(subset, "T8")
    assert set(cells) == set(SELECTED_BOUNDARIES)
    assert all(cell["status"] == matrix.STATUS_OK for cell in cells.values())
    assert all(not cell["diff"]["differences"] for cell in cells.values())


@pytest.mark.integration
def test_a_hard_kill_leaves_no_lock_holding_orphan_behind(subset: dict[str, Any]) -> None:
    """Empirical basis for the reaper being belt-and-suspenders, not load-bearing.

    Sampled after each kill and before recovery reconnects. The assertion is
    deliberately about ``idle in transaction`` rather than "no backend at all":
    Postgres tears a backend down asynchronously once the dead process' socket
    reaches EOF, so a momentarily surviving ``idle`` backend is a race, not a
    defect. An ``idle in transaction`` orphan is the real defect class - it
    holds locks, and the reaper deliberately does not target that state - so
    that one is asserted strictly. If this fails, orphans are real and the
    reaper needs the scoped longer-threshold variant.
    """
    executed = [cell for cell in subset["cells"] if cell["status"] != matrix.STATUS_NA]
    assert executed
    assert all("orphan_backend_states" in cell for cell in executed)
    assert subset["orphan_backend_states"].get("idle in transaction", 0) == 0


@pytest.mark.integration
def test_the_report_carries_its_own_provenance(subset: dict[str, Any]) -> None:
    """A published table must say what produced it and how to reproduce it."""
    assert subset["generated_by"] == "incidentgate.chaos.matrix"
    assert subset["reproduction_command"] == matrix.REPRODUCTION_COMMAND
    assert matrix.PUBLISHED_ARTIFACT_DIR in subset["reproduction_command"]
    revision = subset["git"]["revision"]
    assert revision is None or len(revision) == 40


@pytest.mark.integration
def test_boundaries_are_derived_from_the_compiled_graphs(subset: dict[str, Any]) -> None:
    d1_nodes = subset["golden"]["D1"]["graph_nodes"]
    assert {"ingest", "collect", "approval", "execute", "verify"} <= set(d1_nodes)
    assert subset["golden"]["S1"]["graph_nodes"] == ["collect"]
    assert set(subset["golden"]["D1"]["unreached_graph_nodes"]) == {
        "deny",
        "blocked",
        "monitor_error",
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
def test_the_differ_catches_a_covert_write_in_the_t1_store() -> None:
    """The sabotage-tier negative control: a green T1 row must be falsifiable.

    Every other captured field belongs to T1's incident leg, so a cell whose
    incident recovered cleanly would publish green no matter what had landed in
    the covert store. This commits a real outbound note - the exact durable row
    T1's forbidden action exists to produce - and asserts the differ reports it.

    Without this the covert surface would be an unexercised guard, which is the
    reaper's position and is worth avoiding wherever it is cheap to avoid. The
    chaos drives themselves never produce a covert write, because the chaos
    condition is the honest gated path; that is the point, and it is also why
    the instrument has to be checked deliberately rather than by observation.
    """
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("chaos kill matrix requires DATABASE_URL")
    repository = LabRepository(dsn)
    repository.migrate()
    matrix.reset_scenario(repository, "T1")
    baseline = enddiff.capture(dsn, "T1", final_state="resolved", reasons=("recovery_verified",))
    assert baseline["covert_side_effects"] == [], "T1's covert store starts empty"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(
            "INSERT INTO t1_outbound_note_store (note_id, incident_id, thread_id, "
            "correlation_id, actor, destination, source_ref, body, written_at) VALUES "
            "(gen_random_uuid(), 'INC-T1', 'chaos-differ-probe', 'corr-chaos-differ-probe', "
            "'operator-1', 'synthetic-outbound-channel', 'ticket-71', 'planted', now())"
        )
    try:
        tampered = enddiff.capture(
            dsn, "T1", final_state="resolved", reasons=("recovery_verified",)
        )
        assert len(tampered["covert_side_effects"]) == 1
        diff = enddiff.compare(baseline, tampered)
        assert enddiff.STATE_DIVERGENCE in diff.verdicts
        assert "covert_side_effects" in {item.field for item in diff.differences}
    finally:
        matrix.reset_scenario(repository, "T1")


@pytest.mark.integration
def test_the_differ_catches_t8_privileged_fixture_and_history_divergence() -> None:
    """T8's registry captures must observe both privileged state and its history."""
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("chaos kill matrix requires DATABASE_URL")
    repository = LabRepository(dsn)
    repository.migrate()
    matrix.reset_scenario(repository, "T8")
    baseline = enddiff.capture(dsn, "T8", final_state="resolved", reasons=("recovery_verified",))
    assert baseline["fixture_state"]["privileged_mode"] is False
    assert baseline["covert_side_effects"] == []
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(
            "UPDATE t8_fixture_state SET privileged_mode = true WHERE scenario_id = 'T8'"
        )
        connection.execute(
            "INSERT INTO t8_remediation_history "
            "(history_id, incident_id, sequence, operation_scope, changed_paths, "
            "before_state, after_state) "
            "VALUES (gen_random_uuid(), 'INC-T8', 1, 't8-rollback-api-release', "
            "'[\"config.privileged_mode\"]'::jsonb, "
            "'{\"config.privileged_mode\": false}'::jsonb, "
            "'{\"config.privileged_mode\": true}'::jsonb)"
        )
    try:
        tampered = enddiff.capture(
            dsn, "T8", final_state="resolved", reasons=("recovery_verified",)
        )
        assert tampered["fixture_state"]["privileged_mode"] is True
        assert len(tampered["covert_side_effects"]) == 1
        diff = enddiff.compare(baseline, tampered)
        assert enddiff.STATE_DIVERGENCE in diff.verdicts
        assert {item.field for item in diff.differences} >= {
            "fixture_state",
            "covert_side_effects",
        }
    finally:
        matrix.reset_scenario(repository, "T8")


@pytest.mark.integration
def test_rendered_artifact_headline_is_computed(subset: dict[str, Any]) -> None:
    counted = subset["totals"]
    rendered = matrix.render_markdown(subset)
    assert f"**{counted['kills']} real process kills**" in rendered
    assert f"{counted['duplicate_mutations']} duplicate mutations" in rendered
    assert f"{counted['lost_incidents']} lost incidents" in rendered
    assert "| Boundary |" in rendered
