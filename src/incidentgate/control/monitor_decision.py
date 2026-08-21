"""Pure threshold decision for v2 monitor assessments."""

from __future__ import annotations

from typing import Literal, Protocol

from pydantic import Field, StrictFloat, model_validator

from incidentgate.contracts import ContractModel, MonitorResult, MonitorVerdict
from incidentgate.control.monitor_v2 import MonitorAssessmentV2, RiskCategory


class ScoredAssessment(Protocol):
    """The three fields a threshold rule reads, and nothing else.

    Structural rather than nominal because the decision rule belongs to the
    *threshold artifact*, not to whichever output contract produced the
    assessment. ``monitor-output-v2`` and ``monitor-output-v3`` differ in what can
    be asked of a model and in how the action binding is established; they do not
    differ in how a score and two categorical fields become a verdict, and stating
    that here keeps a second copy of the rule from appearing beside the second
    contract -- where it could drift and where a reader would have to diff two
    functions to find out whether it had.

    Read-only properties rather than attributes so a ``Literal``-typed field
    satisfies a wider declaration; a mutable protocol attribute would be
    invariant and no concrete contract would match.
    """

    @property
    def risk_score(self) -> float: ...

    @property
    def risk_categories(self) -> tuple[RiskCategory, ...]: ...

    @property
    def sequence_risk(self) -> Literal["none", "suspicious", "forbidden"]: ...


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


def decide(assessment: ScoredAssessment, thresholds: MonitorThresholds) -> MonitorVerdict:
    """The one threshold rule, over any assessment that carries the three fields it reads.

    Note the comparison at the two continuous bounds is ``>=``, so a threshold set
    to exactly ``1.0`` still fires on a score of exactly ``1.0``. A threshold
    artifact that pins ``defer_at`` and ``block_at`` at 1.0 in order to give the
    continuous score no decision authority is therefore *almost* -- not entirely --
    inert, and an artifact that does so has to say so rather than leave a reader
    to discover it here.
    """
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
