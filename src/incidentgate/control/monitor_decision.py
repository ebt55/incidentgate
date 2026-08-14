"""Pure threshold decision for v2 monitor assessments."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictFloat, model_validator

from incidentgate.contracts import ContractModel, MonitorResult, MonitorVerdict
from incidentgate.control.monitor_v2 import MonitorAssessmentV2, RiskCategory


class MonitorThresholds(ContractModel):
    defer_at: StrictFloat = Field(gt=0, le=1)
    block_at: StrictFloat = Field(gt=0, le=1)
    forced_block_sequence_risk: tuple[Literal["none", "suspicious", "forbidden"], ...] = (
        "forbidden",
    )
    forced_block_categories: tuple[RiskCategory, ...] = ()

    @model_validator(mode="after")
    def ordered(self) -> MonitorThresholds:
        if self.defer_at > self.block_at:
            raise ValueError("defer_at must be <= block_at")
        for values in (self.forced_block_sequence_risk, self.forced_block_categories):
            if values != tuple(sorted(values)) or len(set(values)) != len(values):
                raise ValueError("forced block values must be unique and sorted")
        return self


def decide(assessment: MonitorAssessmentV2, thresholds: MonitorThresholds) -> MonitorVerdict:
    if assessment.sequence_risk in thresholds.forced_block_sequence_risk:
        return MonitorVerdict.BLOCK
    if set(assessment.risk_categories) & set(thresholds.forced_block_categories):
        return MonitorVerdict.BLOCK
    if assessment.risk_score >= thresholds.block_at:
        return MonitorVerdict.BLOCK
    if assessment.risk_score >= thresholds.defer_at:
        return MonitorVerdict.DEFER
    return MonitorVerdict.ALLOW


def to_monitor_result(
    assessment: MonitorAssessmentV2, action_hash: str, thresholds: MonitorThresholds
) -> MonitorResult:
    return MonitorResult(
        verdict=decide(assessment, thresholds),
        suspicion_score=assessment.risk_score,
        rationale=assessment.rationale,
        evaluated_action_hash=action_hash,
    )
