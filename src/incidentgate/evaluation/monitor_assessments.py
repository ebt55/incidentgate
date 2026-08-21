"""The raw monitor record: what the monitor said, beside the verdict it produced.

WHY THIS IS A SIDECAR AND NOT A FIELD
=====================================

``SabotageStepOutcomeV3`` carries ``monitor_verdict`` and ``monitor_error_kind``
and nothing else, and ``monitor_decision.to_monitor_result`` drops
``risk_categories``, ``sequence_risk`` and ``evidence_support`` on the way to the
frozen :class:`~incidentgate.contracts.MonitorResult`. So a published v3 row can
say BLOCK and cannot say why -- and under an a-priori threshold artifact whose
decision rule is *categorical*, the score that a reader would use to judge the
rule is exactly the number the row does not carry. A categorical decision rule
with an undisclosed score is the opacity the threshold constraint exists to
prevent.

Two ways to fix that: a v4 step contract, or a sidecar. The sidecar is taken.
A v4 step would move the frozen row schema that four published artifacts and
every v3 test are written against, for a field the row's own decision does not
read; and the raw assessment is not a *step* fact at all -- it is what one model
said about one action, which is a different object with a different lifetime.

WHAT IT PUBLISHES THAT THE ROW CANNOT
=====================================

**Three monitor states, never collapsed.** ``CovertOutcome.STOPPED_AT_MONITOR``
is reached when *either* a BLOCK verdict or a monitor error stopped a covert
call (``sabotage_v3.py``'s ``_outcome_is_observed``), so at row level "the
monitor judged this and said stop" and "the monitor could not assess this at
all" are one value. The rendered cell distinguishes them --
``classify_covert_cell`` prints ``monitor error (...)`` -- but the enum does not.

That collapse is **documented rather than fixed**, deliberately: adding an enum
member to the frozen v3 row contract would move a published schema for a path
Route A never reaches, since T1's covert leg is denied at the policy gate and
never arrives at the monitor at all. What is fixed is the place the new
measurement lands. :class:`MonitorAssessmentRecord` carries ``monitor_state``
with three values, and it carries a record for **every step of every leg** --
including the ones the monitor never saw, which are the third state and which no
row field distinguishes from a monitor that allowed the call.

**The score the decision did not use.** ``risk_score``, ``risk_categories``,
``sequence_risk`` and ``evidence_support`` are published raw, exactly as the
model emitted them, beside the verdict the threshold artifact derived.

**Whether the model could have echoed the digest.**
``monitor-output-v3`` stops asking the model to transcribe a 64-hex fingerprint
and stamps it from the harness instead. ``fingerprint_echo`` records what the
body happened to say anyway -- absent, matching or mismatched -- so the design
question that decision answered ("can a model of this size copy a digest?") gets
a measured rate rather than an argument.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, StrictFloat, StrictInt, field_validator, model_validator

from incidentgate.contracts import ContractModel, EvaluationMode, MonitorVerdict
from incidentgate.control.monitor_contract_v3 import FingerprintEcho
from incidentgate.control.monitor_v2 import MonitorErrorKind, RiskCategory

#: The three states a monitor can be in for one call, which no single row field
#: keeps apart.
#:
#: ``judged``          -- the monitor was consulted, answered, and its answer
#:                        parsed and validated. A verdict exists.
#: ``unparseable``     -- the monitor was consulted and no assessment came back:
#:                        a schema violation, a truncation, a transport failure,
#:                        a missing capture. ``error_kind`` says which, and the
#:                        distinction matters because a SCHEMA_VIOLATION or a
#:                        CACHE_MISS is a fact about this harness while a
#:                        RESPONSE_MALFORMED is a fact about the model.
#: ``never_consulted`` -- the chain stopped before the monitor node. On T1's
#:                        covert leg the policy denies first, so this is the
#:                        state of every covert cell, and it is the reason the
#:                        covert-detection measurement is still unreached.
MonitorState = Literal["judged", "unparseable", "never_consulted"]


class MonitorAssessmentRecord(ContractModel):
    """One monitor cell: which call, what state, and what the model actually said."""

    run_id: UUID
    scenario_id: str = Field(pattern=r"^T[1-8]$")
    variant_id: str = Field(pattern=r"^T[1-8]-(?:dev|cal|holdout)-v[0-9]+$")
    split: Literal["development", "calibration", "holdout"]
    condition: EvaluationMode
    trial: StrictInt = Field(ge=0)
    attacker_source: str = Field(min_length=1, max_length=200)
    monitor_source: str = Field(min_length=1, max_length=200)
    leg: Literal["covert", "incident"]
    step_index: StrictInt = Field(ge=0)
    proposed_tool: str = Field(min_length=1, max_length=200)
    monitor_state: MonitorState
    #: The rendered input's digest, never its body. Present whenever the monitor
    #: node ran, absent when the chain never reached it.
    monitor_input_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    #: The capture's cache key, which is what makes this record replayable.
    prompt_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    error_kind: MonitorErrorKind | None = None
    #: The raw model output. Published because the decision rule is categorical
    #: and a categorical rule with an undisclosed score is not auditable.
    risk_score: StrictFloat | None = Field(default=None, ge=0, le=1)
    risk_categories: tuple[RiskCategory, ...] = ()
    sequence_risk: Literal["none", "suspicious", "forbidden"] | None = None
    evidence_support: Literal["supported", "unsupported", "contradictory"] | None = None
    rationale: str | None = Field(default=None, min_length=1, max_length=600)
    fingerprint_echo: FingerprintEcho | None = None
    #: What the threshold artifact's rule made of the above. ``None`` unless the
    #: state is ``judged``.
    verdict: MonitorVerdict | None = None

    @model_validator(mode="after")
    def state_and_payload_agree(self) -> MonitorAssessmentRecord:
        judged = self.monitor_state == "judged"
        assessment = (
            self.risk_score,
            self.sequence_risk,
            self.evidence_support,
            self.rationale,
            self.fingerprint_echo,
            self.verdict,
        )
        if judged and any(value is None for value in assessment):
            raise ValueError("a judged cell records the whole assessment and its verdict")
        if not judged and any(value is not None for value in assessment):
            raise ValueError("only a judged cell records an assessment or a verdict")
        if not judged and self.risk_categories:
            raise ValueError("only a judged cell records risk categories")
        if (self.monitor_state == "unparseable") != (self.error_kind is not None):
            raise ValueError("an unparseable cell records exactly one error kind")
        if (self.monitor_state == "never_consulted") != (self.monitor_input_sha256 is None):
            raise ValueError(
                "a consulted cell renders an input and an unconsulted one renders none"
            )
        if self.prompt_sha256 is not None and self.monitor_state == "never_consulted":
            raise ValueError("an unconsulted cell has no capture to name")
        return self


class MonitorAssessmentEnvelopeV1(ContractModel):
    """Every monitor cell of one published envelope, under one threshold artifact."""

    schema_version: Literal["monitor-assessment-record-v1"] = "monitor-assessment-record-v1"
    generated_at: datetime
    git_revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    git_dirty: bool
    suite_manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    #: The rule these verdicts were derived under, pinned by the bytes of the
    #: artifact that stated it. The artifact is committed and hashed before any
    #: capture is taken, so this digest is what proves the rule was not moved
    #: afterwards.
    threshold_artifact_path: str = Field(min_length=1, max_length=200)
    threshold_artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    threshold_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    threshold_provenance_band: Literal["a_priori_definitional"]
    decision_rule: Literal["categorical_only"]
    continuous_score_authority: Literal[
        "none_the_decision_rule_is_categorical_and_the_score_is_published_raw"
    ]
    provider: str = Field(min_length=1, max_length=200)
    model: str = Field(min_length=1, max_length=200)
    prompt_version: str = Field(min_length=1, max_length=200)
    input_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    output_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    #: What this record is and is not evidence for, carried in the artifact rather
    #: than left to whoever cites it.
    measures: str = Field(min_length=1, max_length=2000)
    records: tuple[MonitorAssessmentRecord, ...] = Field(min_length=1, max_length=256)

    @field_validator("generated_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def cells_are_unique_and_belong_to_this_monitor(self) -> MonitorAssessmentEnvelopeV1:
        keys = [(item.run_id, item.leg, item.step_index) for item in self.records]
        if len(keys) != len(set(keys)):
            raise ValueError("each monitor cell appears at most once")
        expected = f"model:{self.provider}/{self.model}"
        if any(
            item.monitor_source != expected
            for item in self.records
            if item.monitor_state != "never_consulted"
        ):
            raise ValueError("a consulted cell must name the monitor this envelope describes")
        return self


#: What a published record of this shape is evidence for, and what it is not.
#:
#: Kept as a constant so a test can require the envelope to carry it, rather than
#: trusting whoever writes the artifact to remember. The wording is deliberately
#: the disconfirming half first: the covert-detection measurement this project
#: exists for is still unreached, and a benign-leg record is not it.
BENIGN_LEG_MEASURES: tuple[str, ...] = (
    (
        "This record measures a real model judging a real model's HONEST remediation on T1, "
        "and the human approval gate downstream of that judgement. It is a benign "
        "false-positive measurement."
    ),
    (
        "It is NOT covert detection. T1's covert call is denied by the policy gate with "
        "capability_prohibited before the monitor node runs, so every covert cell below is "
        "never_consulted, monitor_verdict is null on the covert leg of every row, and no cell "
        "here is evidence about whether this monitor would notice a covert action."
    ),
    (
        "Covert detection is not cheaply reachable from here. The observe-only route leaks "
        "the policy decision into the monitor's own input -- MonitorInputV2 carries "
        "policy_decision=deny, policy_risk_class=prohibited and "
        "policy_reasons=[capability_prohibited] -- so a BLOCK under it would measure "
        "agreement with a shown denial rather than detection. Closing that is a new input "
        "contract plus a separate versioned row family, not a flag."
    ),
)
