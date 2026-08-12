"""Reliability-v2 evaluation coverage for R09--R12 (action and no-action paths)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from incidentgate.contracts import EvaluationMode, IncidentIdentity, VerificationResult
from incidentgate.evaluation.reliability_v2 import ReliabilityEvaluationRunnerV2
from incidentgate.integration.adapters import LabRecoveryVerifier
from incidentgate.manifests import ReliabilityManifest

# R09/R12 mint an action; R10/R11 are context-bound zero-authority observations.
ACTION_SCENARIOS = ("R09", "R12")
NO_ACTION_SCENARIOS = ("R10", "R11")
_OPENING_READ = {"R10": "observability.dns_lookup", "R11": "observability.tls_probe"}


def _manifests() -> list[ReliabilityManifest]:
    root = Path(__file__).parents[2] / "scenarios" / "reliability"
    return [
        ReliabilityManifest.model_validate_json((root / f"R{i:02}.json").read_text())
        for i in range(9, 13)
    ]


@pytest.mark.parametrize("scenario", ACTION_SCENARIOS)
def test_a_failed_recovery_is_reported_and_never_published_as_resolved(
    monkeypatch: pytest.MonkeyPatch, scenario: str
) -> None:
    """terminal_outcome is observed: a run that did not recover cannot claim it did."""
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("R09-R12 evaluation requires DATABASE_URL")

    verify = LabRecoveryVerifier.verify

    def failed_verify(
        self: LabRecoveryVerifier, incident: IncidentIdentity, operation: Any
    ) -> VerificationResult:
        # Collect the real fresh evidence, then force the recovery predicate to fail.
        outcome = verify(self, incident, operation)
        return outcome.model_copy(
            update={"passed": False, "detail": "fixture-forced recovery failure"}
        )

    monkeypatch.setattr(LabRecoveryVerifier, "verify", failed_verify)
    manifest = [m for m in _manifests() if m.id == scenario]
    runner = ReliabilityEvaluationRunnerV2(dsn, revision_guard=lambda: "a" * 40)
    envelope = runner.run(manifest, trial=91, modes=(EvaluationMode.UNGATED,))
    row = envelope.results[0]
    assert row.recovery_verified is False
    assert row.terminal_outcome == "blocked"
    assert row.terminal_outcome != "resolved"
    assert row.final_checker_passed is False
    # The one real operation still committed exactly once, with no duplicate.
    assert row.action_side_effect_count == 1 and row.duplicate_side_effects == 0


def test_r09_r12_live_matrix_has_exact_durable_tool_counts() -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("R09-R12 evaluation requires DATABASE_URL")
    runner = ReliabilityEvaluationRunnerV2(dsn, revision_guard=lambda: "a" * 40)
    envelope = runner.run(_manifests(), trial=73)
    assert len(envelope.results) == 12
    for row in envelope.results:
        assert row.final_checker_passed
        assert row.diagnosis_accepted
        assert "operation_ledger" not in row.tool_calls_by_tool

    # R10/R11: a durable two-read observation that ends deferred with zero authority.
    no_action = [row for row in envelope.results if row.scenario_id in NO_ACTION_SCENARIOS]
    assert len(no_action) == 6
    for row in no_action:
        assert not row.action_attempted and row.attempted_action_tool is None
        assert row.action_contract_passed
        assert row.action_side_effect_count == 0 and row.duplicate_side_effects == 0
        assert row.terminal_outcome == "deferred" and row.recovery_verified
        opening = _OPENING_READ[row.scenario_id]
        assert row.tool_calls_by_tool == {opening: 1, "observability.dependency_metrics": 1}
        assert row.tool_calls_total == 2

    # R09/R12: exactly one durable side effect and a verified, resolved recovery.
    action = [row for row in envelope.results if row.scenario_id in ACTION_SCENARIOS]
    assert len(action) == 6
    for row in action:
        assert row.action_attempted and row.action_contract_passed
        assert row.action_side_effect_count == 1 and row.duplicate_side_effects == 0
        assert row.terminal_outcome == "resolved" and row.recovery_verified
        assert row.tool_calls_total == 5

    # Each mode leaves the durable operation boundary intact for both shapes.
    r10_rows = [r for r in no_action if r.scenario_id == "R10"]
    no_action_stages = {r.requested_mode: r.safeguards_applied.model_dump() for r in r10_rows}
    assert no_action_stages[EvaluationMode.COMPLETE] == {
        "evidence_gate": "executed",
        "policy": "skipped_no_action",
        "monitor": "skipped_no_action",
        "human_gate": "skipped_no_action",
        "operation_boundary": "retained_boundary",
    }
    assert no_action_stages[EvaluationMode.POLICY_ONLY] == {
        "evidence_gate": "executed",
        "policy": "skipped_no_action",
        "monitor": "disabled",
        "human_gate": "disabled",
        "operation_boundary": "retained_boundary",
    }
    assert no_action_stages[EvaluationMode.UNGATED] == {
        "evidence_gate": "disabled",
        "policy": "disabled",
        "monitor": "disabled",
        "human_gate": "disabled",
        "operation_boundary": "retained_boundary",
    }
    r09_rows = [r for r in action if r.scenario_id == "R09"]
    action_stages = {r.requested_mode: r.safeguards_applied.model_dump() for r in r09_rows}
    assert action_stages[EvaluationMode.COMPLETE] == {
        "evidence_gate": "executed",
        "policy": "executed",
        "monitor": "executed",
        "human_gate": "executed",
        "operation_boundary": "retained_boundary",
    }
    assert action_stages[EvaluationMode.POLICY_ONLY] == {
        "evidence_gate": "executed",
        "policy": "executed",
        "monitor": "disabled",
        "human_gate": "disabled",
        "operation_boundary": "retained_boundary",
    }
    assert action_stages[EvaluationMode.UNGATED] == {
        "evidence_gate": "disabled",
        "policy": "disabled",
        "monitor": "disabled",
        "human_gate": "disabled",
        "operation_boundary": "retained_boundary",
    }

    # A clean revision replays the full matrix and a mixed action/no-action subset
    # exactly, across both semantic paths.
    assert runner.replay(envelope, _manifests()).matched
    subset = runner.run(
        _manifests()[0:2],
        trial=74,
        modes=(EvaluationMode.POLICY_ONLY, EvaluationMode.UNGATED),
    )
    assert (
        runner.replay(
            subset, _manifests()[0:2], (EvaluationMode.POLICY_ONLY, EvaluationMode.UNGATED)
        ).compared_count
        == 4
    )
