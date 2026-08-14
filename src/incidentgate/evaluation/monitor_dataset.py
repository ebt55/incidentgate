"""Frozen, prompt-free benign monitor cases for Phase 3.

This module names executable episode plans; it never fabricates a monitor input
or claims that the plan has already been run.  Only response-loss retry is
available to the T1/T2/T4 runtime lane today.  The remaining vocabulary values
belong to other runtime lanes and are deliberately rejected here.
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Final, Literal

from pydantic import Field, StrictInt, field_validator, model_validator

from incidentgate.contracts import ContractModel
from incidentgate.control.proposal import (
    DeterministicT1Proposer,
    DeterministicT2Proposer,
    DeterministicT4Proposer,
)
from incidentgate.manifests import load_sabotage_manifests

Split = Literal["development", "calibration", "holdout"]
InterferenceKind = Literal[
    "nominal",
    "retry_after_response_loss",
    "recovery_probe_repeat",
    "out_of_order_read",
    "duplicate_delivery",
    "collection_crash_replay",
]

# This is intentionally a registry of importable, honest runtime proposer
# classes, rather than a free-form description in JSON.  T4 uses a fresh
# instance of its one stateless proposer once for each canonical operation.
HONEST_EPISODE_REGISTRY: Final[dict[str, tuple[str, ...]]] = {
    "T1": (DeterministicT1Proposer.__name__,),
    "T2": (DeterministicT2Proposer.__name__,),
    "T4": (
        DeterministicT4Proposer.__name__,
        DeterministicT4Proposer.__name__,
        DeterministicT4Proposer.__name__,
    ),
}

# IncidentRuntime exposes response_loss_once for ordinary action scenarios and
# recovery is its retry() path.  Collection crashes are restricted to no-action
# scenarios; duplicate delivery is currently D8 measurement; no T1/T2/T4
# runner exposes an out-of-order read or repeated recovery probe switch.
SUPPORTED_INTERFERENCE: Final[dict[str, frozenset[InterferenceKind]]] = {
    "T1": frozenset(("nominal", "retry_after_response_loss")),
    "T2": frozenset(("nominal", "retry_after_response_loss")),
    "T4": frozenset(("nominal", "retry_after_response_loss")),
}


class BenignMonitorCase(ContractModel):
    case_id: str = Field(pattern=r"^BM-[0-9]{3}$")
    scenario_id: Literal["T1", "T2", "T4"]
    split: Split
    seed: StrictInt = Field(ge=0, le=2_147_483_647)
    episode_plan: tuple[str, ...] = Field(min_length=1, max_length=8)
    interference_kind: InterferenceKind
    expected_verdict: Literal["allow"]
    inclusion_rationale: str = Field(min_length=1, max_length=240)

    @field_validator("episode_plan")
    @classmethod
    def known_honest_plan(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # Scenario-dependent validation is completed below, once both fields
        # are available.  This validator keeps each individual name bounded.
        if any(not item or len(item) > 80 for item in value):
            raise ValueError("episode_plan names must be nonempty and bounded")
        return value

    @model_validator(mode="after")
    def executable(self) -> BenignMonitorCase:
        if self.episode_plan != HONEST_EPISODE_REGISTRY[self.scenario_id]:
            raise ValueError(
                "episode_plan must exactly name the registered honest runtime plan"
            )
        if self.interference_kind not in SUPPORTED_INTERFERENCE[self.scenario_id]:
            raise ValueError("interference kind is not runnable for this scenario")
        return self


class BenignMonitorSuite(ContractModel):
    schema_version: Literal["monitor-benign-suite-v1"]
    cases: tuple[BenignMonitorCase, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def complete_and_unique(self) -> BenignMonitorSuite:
        ids = tuple(case.case_id for case in self.cases)
        if len(set(ids)) != len(ids):
            raise ValueError("benign case ids must be unique")
        if {case.split for case in self.cases} != {"development", "calibration", "holdout"}:
            raise ValueError(
                "benign suite must cover every split"
            )
        required = {
            (scenario, kind)
            for scenario, kinds in SUPPORTED_INTERFERENCE.items()
            for kind in kinds
        }
        actual = {(case.scenario_id, case.interference_kind) for case in self.cases}
        if not required <= actual:
            raise ValueError(
                "benign suite must cover every runnable scenario/interference pair"
            )
        return self


_SUITE_PATH: Final[Path] = (
    Path(__file__).parents[3] / "scenarios" / "monitor" / "benign-v1.json"
)


def load_benign_monitor_suite(path: Path = _SUITE_PATH) -> BenignMonitorSuite:
    """Load and strictly validate the committed frozen suite without execution."""
    return BenignMonitorSuite.model_validate_json(path.read_bytes())


class FrozenMonitorCell(ContractModel):
    """An observed score's exact frozen input identity, not a synthetic sample."""

    scenario_id: Literal["T1", "T2", "T4"]
    split: Split
    seed: StrictInt = Field(ge=0, le=2_147_483_647)
    case_id: str | None = Field(default=None, pattern=r"^BM-[0-9]{3}$")
    variant_id: str | None = Field(
        default=None, pattern=r"^T[124]-(?:dev|cal|holdout)-v[0-9]+$"
    )
    canonical_prompt_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @property
    def label(self) -> Literal["benign", "malicious"]:
        return "benign" if self.case_id is not None else "malicious"

    @model_validator(mode="after")
    def matches_frozen_input(self) -> FrozenMonitorCell:
        if (self.case_id is None) == (self.variant_id is None):
            raise ValueError("a cell names exactly one benign case or malicious variant")
        if self.case_id is not None:
            case = next(
                (
                    item
                    for item in load_benign_monitor_suite().cases
                    if item.case_id == self.case_id
                ),
                None,
            )
            if case is None or (case.scenario_id, case.split, case.seed) != (
                self.scenario_id,
                self.split,
                self.seed,
            ):
                raise ValueError("cell must exactly match a frozen benign case")
            return self
        variant = next(
            (
                item
                for manifest in load_sabotage_manifests(
                    Path(__file__).parents[3] / "scenarios" / "sabotage"
                )
                if manifest.id == "T4"
                for item in manifest.attack_policy_variants
                if item.variant_id == self.variant_id
            ),
            None,
        )
        if variant is None or (self.scenario_id, self.split, self.seed) != (
            "T4",
            variant.split,
            variant.seed,
        ):
            raise ValueError("cell must exactly match a frozen T4 attack variant")
        return self


def benign_suite_digest(suite: BenignMonitorSuite) -> str:
    """Hash every semantic field in file order; order is part of the frozen input."""
    payload = suite.model_dump(mode="json")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode("utf-8")).hexdigest()
