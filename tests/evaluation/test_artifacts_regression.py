from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from incidentgate.evaluation.artifacts import load_raw, render_reports
from incidentgate.evaluation.regression import compare_semantics
from incidentgate.evaluation.runner import CheckpointBEvaluationRunner, run_checkpoint_b


@pytest.mark.integration
def test_checkpoint_b_artifacts_are_raw_bound_and_replayable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("local Postgres is required")
    revision = "a" * 40
    monkeypatch.setattr("incidentgate.evaluation.runner._revision", lambda value: value or revision)
    output = tmp_path / "checkpoint-b"
    raw_path = run_checkpoint_b(dsn, output=output, mock_evaluation=True, git_revision=revision)
    assert raw_path.name == "raw-results.json"
    assert {path.name for path in output.iterdir()} == {
        "raw-results.json", "preliminary.csv", "preliminary.md", "regression.json"
    }
    raw_bytes = raw_path.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    csv_text, markdown = (output / "preliminary.csv").read_text(encoding="utf-8"), (output / "preliminary.md").read_text(encoding="utf-8")
    assert f"raw_sha256={digest}" in csv_text and f"git_revision={revision}" in csv_text
    assert digest in markdown and revision in markdown
    rows = list(csv.DictReader(csv_text.splitlines()[1:]))
    fields = {"mode", "runs", "diagnosis_accepted", "action_contract_passed", "final_checker_passed", "safe_resolution", "unsafe_action", "unauthorized_action", "deferred_correctly", "policy_caught", "monitor_caught", "monitor_false_positive", "duplicate_delivery_observed", "duplicate_side_effects", "mean_tool_calls", "p50_latency_ms", "p95_latency_ms", "input_tokens", "output_tokens", "model_cost"}
    assert len(rows) == 3 and {row["mode"] for row in rows} == {"ungated_evaluation_only", "policy_only_evaluation_only", "policy_monitor_human"}
    assert set(rows[0]) == fields
    assert all(f"| {field} " in markdown for field in fields)
    assert all(row[key] == "N/A" for row in rows for key in ("input_tokens", "output_tokens", "model_cost"))
    assert all(row["policy_caught"] == "N/A" for row in rows)
    assert all(row["monitor_caught"] == "N/A" for row in rows[:2])
    assert all(row["deferred_correctly"] == "N/A" or "/" in row["deferred_correctly"] for row in rows)
    raw = load_raw(raw_path)
    for rendered in rows:
        latencies = sorted(row.latency_ms for row in raw.results if row.requested_mode.value == rendered["mode"])
        assert rendered["p50_latency_ms"] == str(latencies[(len(latencies) - 1) // 2])
        assert rendered["p95_latency_ms"] == str(latencies[(95 * len(latencies) + 99) // 100 - 1])
    report = json.loads((output / "regression.json").read_text(encoding="utf-8"))
    assert report["matched"] is True and report["compared"] == 30 and report["git_revision"] == revision
    assert report["suite_manifest_digest"] == load_raw(raw_path).suite_manifest_digest
    assert all(re.fullmatch(r"[0-9a-f]{64}", report[key]) for key in ("expected_semantic_hash", "actual_semantic_hash")) and report["expected_semantic_hash"] == report["actual_semantic_hash"]
    expected = CheckpointBEvaluationRunner(dsn, mock_evaluation=True, git_revision=revision).run()
    changed_row = expected.results[0].model_copy(update={"diagnosis_statement": "different diagnosis"})
    altered = expected.model_copy(update={"results": (changed_row, *expected.results[1:])})
    changed = compare_semantics(expected, altered)
    assert not changed.matched and changed.expected_semantic_hash != changed.actual_semantic_hash and "('D1', 'ungated_evaluation_only', 0)" in changed.mismatches
    assert "git_revision" in compare_semantics(expected, expected.model_copy(update={"git_revision": "b" * 40})).mismatches
    assert "suite_manifest_digest" in compare_semantics(expected, expected.model_copy(update={"suite_manifest_digest": "b" * 64})).mismatches
    raw_path.write_bytes(raw_bytes + b"\n")
    render_reports(raw_path, output)
    assert digest not in (output / "preliminary.csv").read_text(encoding="utf-8")


def test_raw_envelope_rejects_malformed_incomplete_duplicate_and_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_bytes(b"not JSON")
    with pytest.raises(ValidationError):
        load_raw(malformed)
    with pytest.raises(FileNotFoundError):
        load_raw(tmp_path / "missing.json")
    # Validation is deliberately exercised through JSON so report generation cannot bypass it.
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("local Postgres is required for frozen valid matrix fixture")
    monkeypatch.setattr("incidentgate.evaluation.runner._revision", lambda value: value or "a" * 40)
    raw = CheckpointBEvaluationRunner(dsn, mock_evaluation=True, git_revision="a" * 40).run()
    body = raw.model_dump(mode="json")
    variants = [
        {**body, "results": body["results"][:-1]},
        {**body, "results": [*body["results"][:-1], body["results"][0]]},
        {**body, "results": [{**body["results"][0], "seed": 999}, *body["results"][1:]]},
    ]
    for index, payload in enumerate(variants):
        path = tmp_path / f"bad-{index}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ValidationError):
            load_raw(path)
