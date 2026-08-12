"""Semantic replay comparison with observational fields deliberately excluded."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from incidentgate.contracts import CheckpointBRawEnvelope, ContractModel


class RegressionReport(ContractModel):
    matched: bool
    compared: int
    expected_semantic_hash: str
    actual_semantic_hash: str
    suite_manifest_digest: str
    git_revision: str
    mismatches: tuple[str, ...] = ()


def compare_semantics(expected: CheckpointBRawEnvelope, actual: CheckpointBRawEnvelope) -> RegressionReport:
    ignored = {"latency_ms", "trace_id"}
    expected_rows = {(row.scenario_id, row.requested_mode.value, row.trial): row.model_dump(mode="json", exclude=ignored) for row in expected.results}
    actual_rows = {(row.scenario_id, row.requested_mode.value, row.trial): row.model_dump(mode="json", exclude=ignored) for row in actual.results}
    mismatches: list[str] = [str(key) for key in sorted(set(expected_rows) | set(actual_rows)) if expected_rows.get(key) != actual_rows.get(key)]
    if expected.git_revision != actual.git_revision:
        mismatches.append("git_revision")
    if expected.suite_manifest_digest != actual.suite_manifest_digest:
        mismatches.append("suite_manifest_digest")
    def semantic_hash(rows: Mapping[tuple[str, str, int], object]) -> str:
        body = [rows[key] for key in sorted(rows)]
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    return RegressionReport(matched=not mismatches, compared=len(expected_rows), mismatches=tuple(map(str, mismatches)), expected_semantic_hash=semantic_hash(expected_rows), actual_semantic_hash=semantic_hash(actual_rows), suite_manifest_digest=expected.suite_manifest_digest, git_revision=expected.git_revision)
