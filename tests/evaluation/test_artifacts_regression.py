from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from incidentgate.evaluation.artifacts import load_raw, render_reports
from incidentgate.evaluation.regression import compare_semantics
from incidentgate.evaluation.runner import CheckpointBEvaluationRunner, run_checkpoint_b

COMMITTED_DIR = Path(__file__).resolve().parents[2] / "artifacts" / "evaluations" / "checkpoint-b"
COMMITTED_RAW = COMMITTED_DIR / "raw-results.json"


def test_the_committed_csv_stamp_matches_the_file_it_stamps() -> None:
    """A provenance stamp that does not match what it stamps is worse than no stamp.

    ``preliminary.csv`` and ``preliminary.md`` each carry the sha256 of ``raw-results.json``,
    and for the whole life of the published artifact they carried the wrong one: the digest of
    the CRLF bytes the file had before ``.gitattributes`` pinned the tree to LF. The byte gate
    in tests/reliability was updated when that was fixed; the derived artifacts were not, and
    nothing noticed because the only assertion on the stamp re-renders into tmp_path and
    compares the result with itself, which is true by construction whatever the committed files
    say. This reads the committed bytes instead, which is the only way the two can disagree.
    """
    actual = hashlib.sha256(COMMITTED_RAW.read_bytes()).hexdigest()
    csv_stamp = (COMMITTED_DIR / "preliminary.csv").read_text(encoding="utf-8").splitlines()[0]
    assert f"raw_sha256={actual}" in csv_stamp, (
        f"preliminary.csv stamps a digest that is not raw-results.json's ({actual}); "
        f"regenerate the artifacts. Stamp line: {csv_stamp}"
    )
    assert actual in (COMMITTED_DIR / "preliminary.md").read_text(encoding="utf-8"), (
        f"preliminary.md does not carry raw-results.json's digest {actual}"
    )


def test_the_committed_reproduction_command_names_a_module_that_resolves() -> None:
    """The published command must be runnable, which means naming a package that exists.

    It named ``triage_agent_lab.evaluation.runner`` long after the rename to ``incidentgate``.
    Nothing compared the field to anything, so nothing could fail; this compares it to the
    import system.
    """
    command = load_raw(COMMITTED_RAW).reproduction_command
    module = re.search(r"python -m ([\w.]+)", command)
    assert module is not None, f"no module in reproduction command: {command}"
    assert importlib.util.find_spec(module.group(1)) is not None, (
        f"the committed artifact tells readers to run {module.group(1)!r}, which does not "
        "resolve; regenerate the artifact"
    )


def _assert_matches_the_committed_baseline(fresh: object) -> None:
    """Compare a fresh derivation against the artifact this repo publishes.

    Nothing did this before, and the gap was invisible because two tests looked
    like they covered it. ``test_checkpoint_b_v1_artifact_is_unchanged`` only
    re-hashes the committed bytes, so it detects edits to the file and nothing
    about the code that produced it; the replay assertions in the caller compare
    one fresh run against another fresh run, which proves determinism and not
    fidelity. Between them a change to evaluation semantics could leave the
    published numbers stale with every test green -- which is exactly the
    situation the allowed-sources fix had to be checked against by hand.

    Semantic level, not byte level, on purpose: ``compare_semantics`` already
    excludes ``latency_ms`` and ``trace_id``, so this pins what the run *means*
    without pinning wall-clock noise. ``git_revision`` is the one expected
    difference -- the caller stamps a synthetic revision -- so it is required to
    be the *only* one rather than filtered out silently.

    The consequence is deliberate: a change that genuinely moves evaluation
    semantics now fails here until the artifact is regenerated honestly, which
    is this repo's discipline for published measurement anyway.
    """
    committed = load_raw(COMMITTED_RAW)
    report = compare_semantics(committed, fresh)  # type: ignore[arg-type]
    assert report.compared == 30, report.compared
    assert report.expected_semantic_hash == report.actual_semantic_hash, (
        "a fresh checkpoint-B derivation no longer matches the committed artifact; "
        f"regenerate it or explain the change: {report.mismatches}"
    )
    assert report.mismatches == ("git_revision",), report.mismatches


@pytest.mark.integration
def test_checkpoint_b_artifacts_are_raw_bound_and_replayable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("local Postgres is required")
    revision = "a" * 40
    monkeypatch.setattr("incidentgate.evaluation.runner._revision", lambda value: value or revision)
    output = tmp_path / "checkpoint-b"
    raw_path = run_checkpoint_b(dsn, output=output, mock_evaluation=True, git_revision=revision)
    assert raw_path.name == "raw-results.json"
    assert {path.name for path in output.iterdir()} == {
        "raw-results.json",
        "preliminary.csv",
        "preliminary.md",
        "regression.json",
    }
    raw_bytes = raw_path.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    csv_text, markdown = (
        (output / "preliminary.csv").read_text(encoding="utf-8"),
        (output / "preliminary.md").read_text(encoding="utf-8"),
    )
    assert f"raw_sha256={digest}" in csv_text and f"git_revision={revision}" in csv_text
    assert digest in markdown and revision in markdown
    rows = list(csv.DictReader(csv_text.splitlines()[1:]))
    fields = {
        "mode",
        "runs",
        "diagnosis_accepted",
        "action_contract_passed",
        "final_checker_passed",
        "safe_resolution",
        "unsafe_action",
        "unauthorized_action",
        "deferred_correctly",
        "policy_caught",
        "monitor_caught",
        "monitor_false_positive",
        "duplicate_delivery_observed",
        "duplicate_side_effects",
        "mean_tool_calls",
        "p50_latency_ms",
        "p95_latency_ms",
        "model_backed",
        "input_tokens",
        "output_tokens",
        "model_cost",
    }
    assert len(rows) == 3 and {row["mode"] for row in rows} == {
        "ungated_evaluation_only",
        "policy_only_evaluation_only",
        "policy_monitor_human",
    }
    assert set(rows[0]) == fields
    assert all(f"| {field} " in markdown for field in fields)
    assert all(
        row[key] == "N/A" for row in rows for key in ("input_tokens", "output_tokens", "model_cost")
    )
    assert all(row["policy_caught"] == "N/A" for row in rows)
    assert all(row["monitor_caught"] == "N/A" for row in rows[:2])
    assert all(
        row["deferred_correctly"] == "N/A" or "/" in row["deferred_correctly"] for row in rows
    )
    raw = load_raw(raw_path)
    _assert_matches_the_committed_baseline(raw)
    for rendered in rows:
        latencies = sorted(
            row.latency_ms for row in raw.results if row.requested_mode.value == rendered["mode"]
        )
        assert rendered["p50_latency_ms"] == str(latencies[(len(latencies) - 1) // 2])
        assert rendered["p95_latency_ms"] == str(latencies[(95 * len(latencies) + 99) // 100 - 1])
    report = json.loads((output / "regression.json").read_text(encoding="utf-8"))
    assert (
        report["matched"] is True
        and report["compared"] == 30
        and report["git_revision"] == revision
    )
    assert report["suite_manifest_digest"] == load_raw(raw_path).suite_manifest_digest
    assert (
        all(
            re.fullmatch(r"[0-9a-f]{64}", report[key])
            for key in ("expected_semantic_hash", "actual_semantic_hash")
        )
        and report["expected_semantic_hash"] == report["actual_semantic_hash"]
    )
    expected = CheckpointBEvaluationRunner(dsn, mock_evaluation=True, git_revision=revision).run()
    changed_row = expected.results[0].model_copy(
        update={"diagnosis_statement": "different diagnosis"}
    )
    altered = expected.model_copy(update={"results": (changed_row, *expected.results[1:])})
    changed = compare_semantics(expected, altered)
    assert (
        not changed.matched
        and changed.expected_semantic_hash != changed.actual_semantic_hash
        and "('D1', 'ungated_evaluation_only', 0)" in changed.mismatches
    )
    assert (
        "git_revision"
        in compare_semantics(
            expected, expected.model_copy(update={"git_revision": "b" * 40})
        ).mismatches
    )
    assert (
        "suite_manifest_digest"
        in compare_semantics(
            expected, expected.model_copy(update={"suite_manifest_digest": "b" * 64})
        ).mismatches
    )
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
