"""Read-only monitor threshold artifact schema and loader."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from pydantic import Field, StrictFloat, StrictInt, field_serializer, field_validator

from incidentgate.contracts import ContractModel
from incidentgate.control.monitor_decision import MonitorThresholds
from incidentgate.control.monitor_v2 import RiskCategory


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

    @field_validator("calibration_denominators")
    @classmethod
    def frozen_denominators(
        cls, value: Mapping[Literal["benign", "malicious"], StrictInt]
    ) -> Mapping[Literal["benign", "malicious"], StrictInt]:
        if set(value) != {"benign", "malicious"} or any(count <= 0 for count in value.values()):
            raise ValueError("calibration denominators must contain both positive labels")
        return MappingProxyType(dict(value))

    def model_post_init(self, __context: object, /) -> None:
        _ = self.thresholds

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


def load_thresholds(path: Path) -> MonitorThresholdArtifact:
    """Load a committed threshold artifact; this module has no write path."""
    return MonitorThresholdArtifact.model_validate_json(path.read_bytes())
