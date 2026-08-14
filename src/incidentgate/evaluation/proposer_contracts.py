"""Read-only schema and loader for frozen proposer holdout contracts."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from incidentgate.contracts import ContractModel

_SHA = re.compile(r"^[a-f0-9]{64}$")
_SCENARIO = re.compile(r"^(D[1-8]|S[1-2]|R[0-9]{2}|T[1-8])$")
_VARIANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


class ProposerPromptBinding(ContractModel):
    """An exact immutable mapping from a holdout source to its system prompt."""

    scenario_id: str = Field(pattern=r"^(D[1-8]|S[1-2]|R[0-9]{2}|T[1-8])$")
    variant_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
    split: Literal["holdout"]
    system_prompt_sha256: str
    action_profile_id: Literal["T1", "T2", "T4"] | None = None
    output_schema_sha256: str | None = None
    provider_schema_sha256: str | None = None

    @field_validator("system_prompt_sha256")
    @classmethod
    def _validate_sha(cls, value: str) -> str:
        if _SHA.fullmatch(value) is None:
            raise ValueError("system prompt hash must be lowercase sha256")
        return value


def validate_proposer_prompt_bindings(bindings: object) -> None:
    """Reject hand-built or serialized binding sets that are not canonical."""
    if not isinstance(bindings, tuple) or not 1 <= len(bindings) <= 64:
        raise ValueError("proposer prompt bindings must be a non-empty bounded tuple")
    if any(not isinstance(binding, ProposerPromptBinding) for binding in bindings):
        raise ValueError("proposer prompt bindings contain an invalid binding")
    source_keys = tuple(
        (binding.scenario_id, binding.variant_id, binding.split) for binding in bindings
    )
    if any(
        _SCENARIO.fullmatch(scenario_id) is None
        or _VARIANT.fullmatch(variant_id) is None
        or split != "holdout"
        for scenario_id, variant_id, split in source_keys
    ):
        raise ValueError("proposer prompt binding has invalid source identity")
    if len(set(source_keys)) != len(source_keys) or source_keys != tuple(sorted(source_keys)):
        raise ValueError("proposer prompt bindings must be unique and canonically sorted")
    if any(_SHA.fullmatch(binding.system_prompt_sha256) is None for binding in bindings):
        raise ValueError("proposer prompt binding has invalid system prompt hash")


class ProposerCaptureContractArtifact(ContractModel):
    """Frozen proposer surface admitted to a holdout capture; no writer lives here."""

    schema_version: Literal["proposer-capture-contract-v1", "proposer-capture-contract-v2"] = (
        "proposer-capture-contract-v1"
    )
    contract_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    frozen_at: datetime
    provider: Literal["anthropic"]
    model: str
    prompt_version: str
    prompt_bindings: tuple[ProposerPromptBinding, ...] = Field(min_length=1, max_length=64)
    input_schema_version: str
    input_schema_sha256: str
    output_schema_sha256: str | None = None
    provider_schema_sha256: str | None = None

    @field_validator("model", "prompt_version", "input_schema_version")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        if not value or len(value) > 200:
            raise ValueError("contract text must be a bounded non-empty string")
        return value

    @field_validator("input_schema_sha256")
    @classmethod
    def _validate_sha(cls, value: str) -> str:
        if _SHA.fullmatch(value) is None:
            raise ValueError("schema hash must be lowercase sha256")
        return value

    @field_validator("frozen_at")
    @classmethod
    def _validate_frozen_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("frozen_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _validate_prompt_bindings(self) -> ProposerCaptureContractArtifact:
        validate_proposer_prompt_bindings(self.prompt_bindings)
        if self.schema_version == "proposer-capture-contract-v1":
            if _SHA.fullmatch(self.output_schema_sha256 or "") is None or _SHA.fullmatch(
                self.provider_schema_sha256 or ""
            ) is None:
                raise ValueError("v1 proposer contract requires global schema hashes")
            if any(
                binding.action_profile_id is not None
                or binding.output_schema_sha256 is not None
                or binding.provider_schema_sha256 is not None
                for binding in self.prompt_bindings
            ):
                raise ValueError("v1 proposer bindings cannot carry scoped profile fields")
        else:
            if self.output_schema_sha256 is not None or self.provider_schema_sha256 is not None:
                raise ValueError("v2 proposer schema hashes belong to each source binding")
            if {binding.scenario_id for binding in self.prompt_bindings} != {"T1", "T2", "T4"}:
                raise ValueError("v2 proposer bindings must exactly cover T1, T2, and T4")
            if any(
                binding.scenario_id not in {"T1", "T2", "T4"}
                or binding.action_profile_id != binding.scenario_id
                or _SHA.fullmatch(binding.output_schema_sha256 or "") is None
                or _SHA.fullmatch(binding.provider_schema_sha256 or "") is None
                for binding in self.prompt_bindings
            ):
                raise ValueError("v2 proposer bindings require scoped profile and schema hashes")
        return self


def load_proposer_capture_contract(path: Path) -> ProposerCaptureContractArtifact:
    """Load a frozen contract.  This module intentionally has no write path."""
    return ProposerCaptureContractArtifact.model_validate_json(path.read_bytes())
