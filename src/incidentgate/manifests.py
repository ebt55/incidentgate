"""Schema for frozen Triage Agent Lab scenario-contract JSON files."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ScenarioManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1"]
    id: str = Field(pattern=r"^(D[1-8]|S[1-2])$")
    title: str
    status: Literal["frozen_contract"]
    initial_state: dict[str, str]
    injected_fault: dict[str, str]
    allowed_evidence: tuple[str, ...] = Field(min_length=1)
    acceptable_diagnoses: tuple[str, ...] = Field(min_length=1)
    allowed_actions: tuple[str, ...]
    forbidden_actions: tuple[str, ...] = Field(min_length=1)
    recovery_predicate: str
    final_checker: str
    retry_budget: int = Field(ge=0, le=5)
    time_budget_seconds: int = Field(gt=0, le=900)
    split: Literal["development", "calibration", "holdout"]
    seed: int

    @model_validator(mode="after")
    def actions_do_not_overlap(self) -> ScenarioManifest:
        if set(self.allowed_actions) & set(self.forbidden_actions):
            raise ValueError("allowed_actions and forbidden_actions must not overlap")
        return self


def load_checkpoint_manifests(directory: Path) -> list[ScenarioManifest]:
    return [ScenarioManifest.model_validate_json(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.json"))]


class ReliabilityManifest(ScenarioManifest):
    """Frozen, non-runnable reliability contract for the post-checkpoint suite."""

    id: str = Field(pattern=r"^R(?:0[1-9]|1[0-9]|20)$")

class AttackPolicyVariant(BaseModel):
    """A bounded synthetic policy prompt; it never carries credentials or exploit steps."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    variant_id: str = Field(pattern=r"^T[1-8]-(?:dev|cal|holdout)-v[0-9]+$")
    policy_version: str = Field(pattern=r"^attack-policy/T[1-8]/v[1-9][0-9]*$")
    split: Literal["development", "calibration", "holdout"]
    seed: int
    policy_text: str = Field(min_length=1, max_length=500)


class SabotageManifest(BaseModel):
    """Frozen control contract for a synthetic covert-side-effect test."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1"]
    id: str = Field(pattern=r"^T[1-8]$")
    title: str
    status: Literal["frozen_contract"]
    initial_state: dict[str, str]
    injected_fault: dict[str, str]
    allowed_evidence: tuple[str, ...] = Field(min_length=1)
    acceptable_diagnoses: tuple[str, ...] = Field(min_length=1)
    allowed_actions: tuple[str, ...]
    forbidden_actions: tuple[str, ...] = Field(min_length=1)
    required_path_binding: Literal["same_incident_thread"]
    allowed_behavior: tuple[str, ...] = Field(min_length=1)
    forbidden_behavior: tuple[str, ...] = Field(min_length=1)
    deterministic_incident_checker: str = Field(pattern=r"^check_t[1-8]_[a-z0-9_]+$")
    deterministic_covert_side_effect_checker: str = Field(pattern=r"^check_t[1-8]_[a-z0-9_]+$")
    canonical_allowed_call_sequence: tuple[str, ...] = ()
    forbidden_combined_transition: str | None = None
    baseline_configuration_digest: str | None = None
    baseline_permission_digest: str | None = None
    allowed_changed_paths: tuple[str, ...] = ()
    forbidden_privileged_paths: tuple[str, ...] = ()
    expected_full_diff_facts: tuple[str, ...] = ()
    attack_policy_variants: tuple[AttackPolicyVariant, ...] = Field(min_length=3)

    @model_validator(mode="after")
    def contract_is_complete(self) -> SabotageManifest:
        if set(self.allowed_behavior) & set(self.forbidden_behavior):
            raise ValueError("allowed_behavior and forbidden_behavior must not overlap")
        if set(self.allowed_actions) & set(self.forbidden_actions):
            raise ValueError("allowed_actions and forbidden_actions must not overlap")
        if self.id == "T4" and (not self.canonical_allowed_call_sequence or not self.forbidden_combined_transition):
            raise ValueError("T4 must declare canonical calls and forbidden transition")
        if self.id == "T8" and (
            not self.baseline_configuration_digest
            or not self.baseline_permission_digest
            or not self.allowed_changed_paths
            or not self.forbidden_privileged_paths
            or not self.expected_full_diff_facts
        ):
            raise ValueError("T8 must declare complete baseline and full-diff facts")
        variants = self.attack_policy_variants
        if {variant.split for variant in variants} != {"development", "calibration", "holdout"}:
            raise ValueError("attack-policy variants must cover development, calibration, and holdout")
        if len({variant.variant_id for variant in variants}) != len(variants):
            raise ValueError("attack-policy variant IDs must be unique")
        if len({variant.seed for variant in variants}) != len(variants):
            raise ValueError("attack-policy variant seeds must be unique")
        if len({variant.policy_version for variant in variants}) != len(variants):
            raise ValueError("attack-policy versions must be unique")
        if len({variant.policy_text for variant in variants}) != len(variants):
            raise ValueError("attack-policy texts must be unique")
        if any(not variant.variant_id.startswith(f"{self.id}-") for variant in variants):
            raise ValueError("attack-policy variant ID must be bound to its sabotage contract")
        if any(not variant.policy_version.startswith(f"attack-policy/{self.id}/") for variant in variants):
            raise ValueError("attack-policy version must be bound to its sabotage contract")
        prefix = f"check_{self.id.lower()}_"
        if not self.deterministic_incident_checker.startswith(prefix) or not self.deterministic_covert_side_effect_checker.startswith(prefix):
            raise ValueError("deterministic checker must be bound to its sabotage contract")
        return self


def load_reliability_manifests(directory: Path) -> list[ReliabilityManifest]:
    manifests = [
        ReliabilityManifest.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(directory.glob("*.json"))
    ]
    expected = {f"R{number:02d}" for number in range(1, 21)}
    if {manifest.id for manifest in manifests} != expected or len(manifests) != len(expected):
        raise ValueError("reliability contracts must contain exactly R01 through R20 once")
    return manifests


def load_sabotage_manifests(directory: Path) -> list[SabotageManifest]:
    manifests = [
        SabotageManifest.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(directory.glob("*.json"))
    ]
    expected = {f"T{number}" for number in range(1, 9)}
    if {manifest.id for manifest in manifests} != expected or len(manifests) != len(expected):
        raise ValueError("sabotage contracts must contain exactly T1 through T8 once")
    seeds = [variant.seed for manifest in manifests for variant in manifest.attack_policy_variants]
    variant_ids = [variant.variant_id for manifest in manifests for variant in manifest.attack_policy_variants]
    if len(set(seeds)) != len(seeds) or len(set(variant_ids)) != len(variant_ids):
        raise ValueError("sabotage attack-policy seeds and IDs must be globally unique")
    checkers = [
        checker
        for manifest in manifests
        for checker in (
            manifest.deterministic_incident_checker,
            manifest.deterministic_covert_side_effect_checker,
        )
    ]
    if len(set(checkers)) != len(checkers):
        raise ValueError("sabotage deterministic checker names must be globally unique")
    return manifests
