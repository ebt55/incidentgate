"""Calibration-only, deterministic threshold selection and artifact I/O."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from pydantic import Field, StrictFloat, StrictInt, field_serializer, field_validator

from incidentgate.contracts import ContractModel
from incidentgate.control.monitor_decision import MonitorThresholds
from incidentgate.control.monitor_v2 import RiskCategory


class _TimedRow(ContractModel):
    generated_at: datetime

    @field_validator("generated_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return value


class CalibrationRow(_TimedRow):
    split: Literal["calibration"]
    risk_score: StrictFloat = Field(ge=0, le=1)
    label: Literal["benign", "malicious"]


class ReportRow(_TimedRow):
    split: Literal["development", "holdout"]
    risk_score: StrictFloat = Field(default=0.0, ge=0, le=1)
    label: Literal["benign", "malicious"] = "benign"


class CalibrationRows(ContractModel):
    rows: tuple[CalibrationRow, ...] = Field(min_length=1)


class ReportRows(ContractModel):
    rows: tuple[ReportRow, ...] = Field(min_length=1)


class MonitorThresholdArtifact(ContractModel):
    schema_version: Literal["monitor-thresholds-v1"] = "monitor-thresholds-v1"
    threshold_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    frozen_at: datetime
    selected_on_split: Literal["calibration"] = "calibration"
    provider: str = Field(min_length=1, max_length=200)
    model: str = Field(min_length=1, max_length=200)
    prompt_version: str = Field(min_length=1, max_length=200)
    input_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    output_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    defer_at: StrictFloat = Field(gt=0, le=1)
    block_at: StrictFloat = Field(gt=0, le=1)
    forced_block_sequence_risk: tuple[Literal["none", "suspicious", "forbidden"], ...] = (
        "forbidden",
    )
    forced_block_categories: tuple[RiskCategory, ...] = ()
    calibration_cells_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    calibration_denominators: Mapping[Literal["benign", "malicious"], StrictInt]
    selection_rule: str = Field(min_length=1, max_length=200)

    @field_validator("frozen_at")
    @classmethod
    def frozen_at_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("frozen_at must be timezone-aware")
        return value

    def model_post_init(self, __context: object, /) -> None:
        # Validate ordering and the two forced-block collections at the artifact
        # boundary too; the convenience property must not be the first validator.
        _ = self.thresholds

    @field_validator("calibration_denominators")
    @classmethod
    def frozen_denominators(
        cls, value: Mapping[Literal["benign", "malicious"], StrictInt]
    ) -> Mapping[Literal["benign", "malicious"], StrictInt]:
        if set(value) != {"benign", "malicious"}:
            raise ValueError("calibration denominators require benign and malicious keys")
        if any(count < 0 for count in value.values()):
            raise ValueError("calibration denominators must be nonnegative")
        return MappingProxyType(dict(value))

    @field_serializer("calibration_denominators")
    def serialize_denominators(
        self, value: Mapping[Literal["benign", "malicious"], StrictInt]
    ) -> dict[Literal["benign", "malicious"], int]:
        return dict(value)

    @property
    def thresholds(self) -> MonitorThresholds:
        return MonitorThresholds(
            defer_at=self.defer_at,
            block_at=self.block_at,
            forced_block_sequence_risk=self.forced_block_sequence_risk,
            forced_block_categories=self.forced_block_categories,
        )


def fit_thresholds(
    rows: CalibrationRows, candidates: tuple[MonitorThresholds, ...]
) -> MonitorThresholds:
    """Choose only a declared candidate, never infer thresholds from report data."""
    if not candidates:
        raise ValueError("at least one predeclared candidate is required")
    eligible = [
        threshold
        for threshold in candidates
        if not any(
            row.label == "benign" and row.risk_score >= threshold.block_at for row in rows.rows
        )
    ]
    if not eligible:
        raise ValueError("no candidate blocks zero benign calibration rows")
    return min(eligible, key=lambda threshold: (threshold.block_at, threshold.defer_at))


def calibration_digest(rows: CalibrationRows) -> str:
    payload = [row.model_dump(mode="json") for row in rows.rows]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode("utf-8")).hexdigest()


def build_threshold_artifact(
    *,
    rows: CalibrationRows,
    candidates: tuple[MonitorThresholds, ...],
    threshold_id: str,
    frozen_at: datetime,
    provider: str,
    model: str,
    prompt_version: str,
    input_schema_sha256: str,
    output_schema_sha256: str,
    selection_rule: str,
) -> MonitorThresholdArtifact:
    """Bind artifact provenance and denominators directly to calibration rows."""
    if any(len(value) > 200 for value in (provider, model, prompt_version, selection_rule)):
        raise ValueError("artifact text fields are bounded")
    denominators: dict[Literal["benign", "malicious"], int] = {
        "benign": sum(row.label == "benign" for row in rows.rows),
        "malicious": sum(row.label == "malicious" for row in rows.rows),
    }
    return MonitorThresholdArtifact(
        threshold_id=threshold_id,
        frozen_at=frozen_at,
        provider=provider,
        model=model,
        prompt_version=prompt_version,
        input_schema_sha256=input_schema_sha256,
        output_schema_sha256=output_schema_sha256,
        **fit_thresholds(rows, candidates).model_dump(),
        calibration_cells_digest=calibration_digest(rows),
        calibration_denominators=denominators,
        selection_rule=selection_rule,
    )


def guard_report(thresholds: MonitorThresholdArtifact, rows: ReportRows) -> None:
    if any(str(thresholds.selected_on_split) == str(row.split) for row in rows.rows):
        raise ValueError("threshold split must differ from report split")
    if any(thresholds.frozen_at >= row.generated_at for row in rows.rows):
        raise ValueError("thresholds must be frozen before report rows")


def write_thresholds(path: Path, artifact: MonitorThresholdArtifact) -> None:
    if not path.parent.is_dir():
        raise FileNotFoundError(path.parent)
    payload = json.dumps(
        artifact.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    path.write_bytes((payload + "\n").encode("utf-8"))


def load_thresholds(path: Path) -> MonitorThresholdArtifact:
    return MonitorThresholdArtifact.model_validate_json(path.read_bytes())
