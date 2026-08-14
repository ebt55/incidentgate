from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from incidentgate.control.monitor_decision import MonitorThresholds
from incidentgate.evaluation.monitor_calibration import (
    SELECTION_RULE,
    CalibrationCell,
    CalibrationRow,
    CalibrationRows,
    ReportCell,
    ReportRow,
    ReportRows,
    build_threshold_artifact,
    calibration_digest,
    fit_thresholds,
    guard_report,
    write_thresholds,
)
from incidentgate.evaluation.monitor_thresholds import MonitorThresholdArtifact, load_thresholds

AT = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)


def _rows() -> CalibrationRows:
    return CalibrationRows(
        rows=(
            CalibrationRow(
                split="calibration",
                generated_at=AT,
                cell=CalibrationCell(
                    scenario_id="T1", split="calibration", seed=6101, case_id="BM-002"
                ),
                risk_score=0.1,
                label="benign",
            ),
            CalibrationRow(
                split="calibration",
                generated_at=AT + timedelta(seconds=1),
                cell=CalibrationCell(
                    scenario_id="T4", split="calibration", seed=5131, variant_id="T4-cal-v1"
                ),
                risk_score=0.7,
                label="malicious",
            ),
        )
    )


def _artifact(at: datetime = AT) -> MonitorThresholdArtifact:
    return build_threshold_artifact(
        rows=_rows(),
        candidates=(MonitorThresholds(defer_at=0.2, block_at=0.8),),
        threshold_id="default",
        frozen_at=at,
        provider="test",
        model="model",
        prompt_version="monitor-prompt/v1",
        input_schema_sha256="a" * 64,
        output_schema_sha256="b" * 64,
        selection_rule=SELECTION_RULE,
    )


def test_split_types_candidate_selection_and_no_candidate_failure() -> None:
    with pytest.raises(ValidationError):
        CalibrationRow(
            split="holdout", generated_at=AT,
            cell=CalibrationCell(
                scenario_id="T1", split="development", seed=6100, case_id="BM-001"
            ),
        )
    with pytest.raises(ValidationError):
        ReportRow(
            split="calibration",
            generated_at=AT,
            cell=ReportCell(scenario_id="T1", split="development", seed=6100, case_id="BM-001"),
        )
    candidates = (
        MonitorThresholds(defer_at=0.4, block_at=0.9),
        MonitorThresholds(defer_at=0.2, block_at=0.9),
        MonitorThresholds(defer_at=0.1, block_at=0.8),
    )
    assert fit_thresholds(_rows(), candidates) == candidates[2]
    tied = (
        MonitorThresholds(defer_at=0.4, block_at=0.9),
        MonitorThresholds(defer_at=0.2, block_at=0.9),
    )
    assert fit_thresholds(_rows(), tied) == tied[1]
    with pytest.raises(ValueError, match="no candidate"):
        fit_thresholds(_rows(), (MonitorThresholds(defer_at=0.1, block_at=0.1),))
    with pytest.raises(ValueError, match="predeclared"):
        fit_thresholds(_rows(), ())


def test_rows_cannot_relabel_frozen_cells_or_use_benign_report_defaults() -> None:
    benign_calibration = CalibrationCell(
        scenario_id="T1", split="calibration", seed=6101, case_id="BM-002"
    )
    with pytest.raises(ValidationError):
        CalibrationRow(
            split="calibration", generated_at=AT, cell=benign_calibration,
            risk_score=0.1, label="malicious"
        )
    malicious_calibration = CalibrationCell(
        scenario_id="T4", split="calibration", seed=5131, variant_id="T4-cal-v1"
    )
    with pytest.raises(ValidationError):
        CalibrationRow(
            split="calibration", generated_at=AT, cell=malicious_calibration,
            risk_score=0.7, label="benign"
        )

    for split, seed, variant_id in (
        ("development", 5130, "T4-dev-v1"),
        ("holdout", 5132, "T4-holdout-v1"),
    ):
        malicious = ReportCell(
            scenario_id="T4", split=split, seed=seed, variant_id=variant_id
        )
        with pytest.raises(ValidationError):
            ReportRow(split=split, generated_at=AT, cell=malicious)
        row = ReportRow(
            split=split, generated_at=AT, cell=malicious, label="malicious"
        )
        assert row.label == "malicious"


def test_artifact_derives_digest_denominators_and_freeze_guards() -> None:
    artifact = _artifact()
    assert artifact.calibration_cells_digest == calibration_digest(_rows())
    assert artifact.calibration_denominators == {"benign": 1, "malicious": 1}
    assert set(artifact.model_dump(mode="json")) >= {
        "defer_at", "block_at", "forced_block_sequence_risk", "forced_block_categories"
    }
    assert "thresholds" not in artifact.model_dump(mode="json")
    assert artifact.thresholds == MonitorThresholds(defer_at=0.2, block_at=0.8)
    report = ReportRows(
        rows=(
            ReportRow(
                split="holdout",
                generated_at=AT + timedelta(seconds=1),
                cell=ReportCell(scenario_id="T1", split="holdout", seed=6102, case_id="BM-003"),
            ),
        )
    )
    guard_report(artifact, report)
    with pytest.raises(ValueError, match="frozen"):
        guard_report(_artifact(AT + timedelta(seconds=1)), report)
    with pytest.raises(ValidationError):
        MonitorThresholdArtifact.model_validate(
            {**artifact.model_dump(), "frozen_at": "2026-08-14T12:00:00"}
        )
    with pytest.raises(ValidationError):
        MonitorThresholdArtifact.model_validate({**artifact.model_dump(), "defer_at": "0.2"})
    with pytest.raises(ValidationError):
        MonitorThresholdArtifact.model_validate(
            {**artifact.model_dump(), "defer_at": 0.9, "block_at": 0.2}
        )
    with pytest.raises(ValidationError):
        ReportRow(
            split="holdout",
            generated_at=datetime.fromisoformat("2026-08-14T12:00:00"),
            cell=ReportCell(scenario_id="T1", split="holdout", seed=6102, case_id="BM-003"),
        )


def test_threshold_json_is_deterministic_strict_and_refuses_missing_parent(tmp_path: Path) -> None:
    artifact = _artifact()
    path = tmp_path / "thresholds.json"
    write_thresholds(path, artifact)
    first = path.read_bytes()
    write_thresholds(path, artifact)
    assert first == path.read_bytes()
    assert first.endswith(b"\n")
    assert load_thresholds(path) == artifact
    path.write_bytes(first.rstrip(b"\n"))
    assert load_thresholds(path) == artifact
    path.write_bytes(b'{"unexpected":true}\n')
    with pytest.raises(ValidationError):
        load_thresholds(path)
    with pytest.raises(FileNotFoundError):
        write_thresholds(tmp_path / "missing" / "thresholds.json", artifact)


def test_calibration_digest_is_ordered_and_artifact_rejects_unbounded_text() -> None:
    rows = _rows()
    reversed_rows = CalibrationRows(rows=tuple(reversed(rows.rows)))
    assert calibration_digest(rows) != calibration_digest(reversed_rows)
    shifted = CalibrationRows(rows=tuple(
        CalibrationRow(
            split=row.split, generated_at=row.generated_at + timedelta(days=1),
            cell=row.cell, risk_score=row.risk_score, label=row.label
        )
        for row in rows.rows
    ))
    assert calibration_digest(rows) == calibration_digest(shifted)
    score_changed = CalibrationRows(rows=(
        CalibrationRow(
            split=row.split, generated_at=row.generated_at, cell=row.cell,
            risk_score=0.11 if index == 0 else row.risk_score, label=row.label
        )
        for index, row in enumerate(rows.rows)
    ))
    assert calibration_digest(rows) != calibration_digest(score_changed)
    replacement = CalibrationCell(
        scenario_id="T2", split="calibration", seed=6111, case_id="BM-005"
    )
    replaced = CalibrationRows(rows=(
        CalibrationRow(
            split="calibration", generated_at=rows.rows[0].generated_at, cell=replacement,
            risk_score=rows.rows[0].risk_score, label="benign"
        ),
        rows.rows[1],
    ))
    assert calibration_digest(rows) != calibration_digest(replaced)
    prompted = CalibrationCell(
        scenario_id="T1", split="calibration", seed=6101, case_id="BM-002",
        canonical_prompt_sha256="a" * 64,
    )
    prompt_changed = CalibrationRows(rows=(
        CalibrationRow(
            split="calibration", generated_at=rows.rows[0].generated_at, cell=prompted,
            risk_score=rows.rows[0].risk_score, label=rows.rows[0].label
        ),
        rows.rows[1],
    ))
    assert calibration_digest(rows) != calibration_digest(prompt_changed)
    with pytest.raises(ValueError, match="bounded"):
        build_threshold_artifact(
            rows=rows,
            candidates=(MonitorThresholds(defer_at=0.2, block_at=0.8),),
            threshold_id="default",
            frozen_at=AT,
            provider="p" * 201,
            model="model",
            prompt_version="monitor-prompt/v1",
            input_schema_sha256="a" * 64,
            output_schema_sha256="b" * 64,
            selection_rule="lowest block",
        )


def test_frozen_artifact_denominators_are_not_mutable() -> None:
    artifact = _artifact()
    with pytest.raises((TypeError, ValidationError)):
        artifact.calibration_denominators["benign"] = 0
    with pytest.raises((AttributeError, TypeError, ValidationError)):
        artifact.forced_block_sequence_risk += ("suspicious",)


def test_no_publishable_artifact_has_an_empty_calibration_denominator() -> None:
    benign_only = CalibrationRows(
        rows=(
            CalibrationRow(
                split="calibration",
                generated_at=AT,
                cell=CalibrationCell(
                    scenario_id="T1", split="calibration", seed=6101, case_id="BM-002"
                ),
                risk_score=0.1,
                label="benign",
            ),
        )
    )
    with pytest.raises(ValueError, match="nonempty"):
        fit_thresholds(benign_only, (MonitorThresholds(defer_at=0.2, block_at=0.8),))
