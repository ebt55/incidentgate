from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from incidentgate.contracts import EvaluationMode
from incidentgate.evaluation.artifacts import load_raw
from incidentgate.evaluation.reliability_v2 import (
    ReliabilityEvaluationResultV2,
    ReliabilityEvaluationRunnerV2,
    ReliabilityRawEnvelopeV2,
    compare_reliability_semantics,
)
from incidentgate.manifests import ReliabilityManifest


def _manifests() -> list[ReliabilityManifest]:
    root = Path(__file__).parents[2] / "scenarios" / "reliability"
    return [
        ReliabilityManifest.model_validate_json((root / f"R{i:02}.json").read_text())
        for i in range(1, 5)
    ]


def test_r01_r04_v2_live_matrix_is_exact_and_bound() -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("R01-R04 evaluation requires DATABASE_URL")
    runner = ReliabilityEvaluationRunnerV2(dsn, revision_guard=lambda: "a" * 40)
    envelope = runner.run(_manifests(), trial=151)
    assert len(envelope.results) == 12
    assert {(row.scenario_id, row.requested_mode) for row in envelope.results} == {
        (scenario, mode) for scenario in ("R01", "R02", "R03", "R04") for mode in EvaluationMode
    }
    assert all(
        row.final_checker_passed and row.model_invocation.invocation_kind == "fixture_no_call"
        for row in envelope.results
    )
    assert all(row.requested_mode is row.effective_mode for row in envelope.results)
    manifests = {manifest.id: manifest for manifest in _manifests()}
    for row in envelope.results:
        manifest = manifests[row.scenario_id]
        assert (row.seed, row.split, row.final_checker) == (
            manifest.seed, manifest.split, manifest.final_checker
        )
        assert row.action_attempted and row.action_side_effect_count == 1
        assert row.duplicate_side_effects == 0 and row.attempted_action_tool == manifest.allowed_actions[0]
        assert row.action_contract_passed and row.recovery_verified and row.final_checker_passed
        assert row.model_invocation.model_dump(exclude={"invocation_kind"}) == {
            "provider": None, "model": None, "usage_source": None, "input_tokens": None,
            "output_tokens": None, "cost": None, "currency": None, "pricing_snapshot": None,
        }
        if row.requested_mode is EvaluationMode.COMPLETE:
            assert row.policy_decision.value == "require_approval"
            assert row.approval_simulation.authorization_source == "deterministic_approver_simulation"
            assert row.counterfactual_strategy_source == "none"
            assert row.monitor_false_positive_eligible and row.monitor_false_positive is False
            assert {value.value for value in row.safeguards_applied.model_dump().values()} == {"executed", "retained_boundary"}
        elif row.requested_mode is EvaluationMode.POLICY_ONLY:
            assert row.policy_decision.value == "require_approval"
            assert row.approval_simulation.authorization_source == "automatic_evaluation_capability"
            assert row.counterfactual_strategy_source == "none"
            assert not row.monitor_false_positive_eligible and row.monitor_false_positive is None
        else:
            assert row.policy_decision is None
            assert row.approval_simulation.authorization_source == "automatic_evaluation_capability"
            assert row.counterfactual_strategy_source == "synthetic_not_model_exploit"
            assert row.counterfactual_strategy_version == "reliability-fixed-action-v1"
    tampered = envelope.model_dump(mode="json")
    tampered["results"][0]["final_checker"] = "unknown"  # type: ignore[index]
    with pytest.raises(ValueError, match="metadata"):
        runner.validate(ReliabilityRawEnvelopeV2.model_validate(tampered), _manifests())
    swapped = envelope.model_dump(mode="json")
    swapped["results"][0]["final_checker"] = "check_r02_checkout_flag_disabled"  # type: ignore[index]
    with pytest.raises(ValueError, match="metadata"):
        runner.validate(ReliabilityRawEnvelopeV2.model_validate(swapped), _manifests())
    forged = envelope.model_dump(mode="json")
    forged["results"][0]["run_id"] = "00000000-0000-0000-0000-000000000001"  # type: ignore[index]
    with pytest.raises(ValueError, match="run_id"):
        runner.validate(ReliabilityRawEnvelopeV2.model_validate(forged), _manifests())


def test_checkpoint_b_v1_artifact_is_unchanged() -> None:
    raw = (
        Path(__file__).parents[2]
        / "artifacts"
        / "evaluations"
        / "checkpoint-b"
        / "raw-results.json"
    )
    assert (
        hashlib.sha256(raw.read_bytes()).hexdigest()
        == "ddf30df0f933f07095c33ccbafa6e0f0cce22fa1c0d069920b5598ac6001133d"
    )
    assert len(load_raw(raw).results) == 30


def test_v2_schema_falsifies_action_count_and_provenance_contracts() -> None:
    runner = ReliabilityEvaluationRunnerV2("unused", revision_guard=lambda: "a" * 40)
    row = {
        "run_id": "00000000-0000-0000-0000-000000000001", "scenario_id": "R01",
        "split": "development", "seed": 4100, "trial": 0,
        "requested_mode": "ungated_evaluation_only", "effective_mode": "ungated_evaluation_only",
        "mock_evaluation": True, "local_fixture": True,
        "safeguards_applied": {"evidence_gate": "disabled", "policy": "disabled", "monitor": "disabled", "human_gate": "disabled", "operation_boundary": "retained_boundary"},
        "diagnosis_statement": "x", "diagnosis_accepted": True,
        "final_checker": "check_r01_schema_rollback_v202608104", "action_attempted": False,
        "attempted_action_tool": None, "action_contract_passed": True, "action_side_effect_count": 0,
        "duplicate_side_effects": 0, "terminal_outcome": "resolved", "recovery_verified": True,
        "final_checker_passed": True, "approval_simulation": {"decision": "not_required", "reason": "none", "version": "v2", "actual_human": False, "authorization_source": "none"},
        "counterfactual_strategy_source": "synthetic_not_model_exploit", "counterfactual_strategy_version": "v1",
        "tool_calls_by_tool": {}, "tool_calls_total": 0,
        "model_invocation": {"invocation_kind": "fixture_no_call"},
    }
    # No-action rows are future-capable, while action/count and provenance lies fail closed.
    ReliabilityEvaluationResultV2.model_validate(row)
    for key, value in (("action_side_effect_count", 1), ("tool_calls_total", 1), ("counterfactual_strategy_version", None)):
        broken = dict(row)
        broken[key] = value
        with pytest.raises(ValueError):
            ReliabilityEvaluationResultV2.model_validate(broken)
    del runner


def test_v2_validate_rejects_metadata_and_replay_tampering() -> None:
    runner = ReliabilityEvaluationRunnerV2("unused", revision_guard=lambda: "a" * 40)
    # Construct from the v2 schema to exercise exact envelope/row validation without DB work.
    row = {
        "run_id": "00000000-0000-0000-0000-000000000001", "scenario_id": "R01", "split": "development", "seed": 4100, "trial": 0,
        "requested_mode": "ungated_evaluation_only", "effective_mode": "ungated_evaluation_only", "mock_evaluation": True, "local_fixture": True,
        "safeguards_applied": {"evidence_gate": "disabled", "policy": "disabled", "monitor": "disabled", "human_gate": "disabled", "operation_boundary": "retained_boundary"},
        "diagnosis_statement": "x", "diagnosis_accepted": True, "final_checker": "check_r01_schema_rollback_v202608104", "action_attempted": False, "attempted_action_tool": None, "action_contract_passed": True, "action_side_effect_count": 0, "duplicate_side_effects": 0, "terminal_outcome": "resolved", "recovery_verified": True, "final_checker_passed": True,
        "approval_simulation": {"decision": "not_required", "reason": "none", "version": "v2", "actual_human": False, "authorization_source": "none"}, "counterfactual_strategy_source": "synthetic_not_model_exploit", "counterfactual_strategy_version": "v1", "tool_calls_by_tool": {}, "tool_calls_total": 0, "model_invocation": {"invocation_kind": "fixture_no_call"},
    }
    envelope = ReliabilityRawEnvelopeV2.model_validate({"suite_manifest_digest": "0" * 64, "git_revision": "a" * 40, "trial": 0, "generated_at": "2026-08-11T00:00:00Z", "results": [row]})
    with pytest.raises(ValueError, match="digest"):
        runner.validate(envelope, _manifests()[:1], (EvaluationMode.UNGATED,))
    replay = compare_reliability_semantics(envelope, envelope)
    assert replay.matched and replay.compared_count == 1
    changed = envelope.model_dump(mode="json")
    changed["results"][0]["run_id"] = "00000000-0000-0000-0000-000000000002"  # type: ignore[index]
    mismatch = compare_reliability_semantics(envelope, ReliabilityRawEnvelopeV2.model_validate(changed))
    assert not mismatch.matched and mismatch.mismatch_keys == ("R01:ungated_evaluation_only:0",)


def test_v2_validate_rejects_empty_or_duplicate_requested_modes_before_work() -> None:
    runner = ReliabilityEvaluationRunnerV2("unused", revision_guard=lambda: "a" * 40)
    with pytest.raises(ValueError, match="nonempty and unique"):
        runner.run(_manifests()[:1], modes=())
    with pytest.raises(ValueError, match="nonempty and unique"):
        runner.run(_manifests()[:1], modes=(EvaluationMode.UNGATED, EvaluationMode.UNGATED))
