"""Bounded, replay-stable semantic input for the v2 advisory monitor."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from typing import Annotated, Literal, Protocol

from pydantic import Field, StrictBool, StrictFloat, StrictInt, StrictStr, field_validator

from incidentgate.contracts import (
    CanonicalAction,
    ContractModel,
    EvidenceRecord,
    IncidentIdentity,
    PolicyDecision,
    PolicyOutcome,
    canonical_arguments_digest,
)
from incidentgate.control.models import EvidenceValidation
from incidentgate.control.safeguards import SafeguardConfiguration
from incidentgate.manifests import ReliabilityManifest, SabotageManifest, ScenarioManifest
from incidentgate.reasons import expired_evidence, is_known_reason, stale_evidence

Sha256Hex = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
SafeName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
ToolName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")]
ChangedPath = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){0,4}$")]
_MAX_SCALAR = 512
_MAX_PROMPT_BYTES = 16_000


class EnumFact(ContractModel):
    kind: Literal["enum"]
    name: SafeName
    value: SafeName


class CountFact(ContractModel):
    kind: Literal["count"]
    name: SafeName
    value: StrictInt = Field(ge=0, le=1_000_000_000)


class HealthFact(ContractModel):
    kind: Literal["health"]
    name: SafeName
    value: Literal["healthy", "degraded", "unhealthy", "unknown"]


class FlagFact(ContractModel):
    kind: Literal["flag"]
    name: SafeName
    value: StrictBool


class ChangedPathFact(ContractModel):
    kind: Literal["changed_path"]
    name: SafeName
    value: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){0,4}$")


class ProbeFact(ContractModel):
    kind: Literal["probe"]
    name: SafeName
    value: Literal["pass", "fail", "inconclusive"]
    sequence: StrictInt = Field(ge=0, le=1_000_000_000)


class DigestFact(ContractModel):
    kind: Literal["digest"]
    name: SafeName
    value: Sha256Hex


SemanticFact = Annotated[
    EnumFact | CountFact | HealthFact | FlagFact | ChangedPathFact | ProbeFact | DigestFact,
    Field(discriminator="kind"),
]


class ProposedActionFacts(ContractModel):
    action_schema_version: Literal["1"]
    tool_name: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
    arguments: dict[str, StrictBool | StrictInt | StrictFloat | StrictStr] = Field(max_length=16)

    @field_validator("arguments")
    @classmethod
    def bounded_argument_names(
        cls, value: dict[str, StrictBool | StrictInt | StrictFloat | StrictStr]
    ) -> dict[str, StrictBool | StrictInt | StrictFloat | StrictStr]:
        if any(not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", key) for key in value):
            raise ValueError("argument names must be safe names")
        return value

    @field_validator("arguments", mode="after")
    @classmethod
    def bounded_scalars(
        cls, value: dict[str, StrictBool | StrictInt | StrictFloat | StrictStr]
    ) -> dict[str, StrictBool | StrictInt | StrictFloat | StrictStr]:
        if any(
            (isinstance(item, str) and len(item) > _MAX_SCALAR)
            or (isinstance(item, float) and not math.isfinite(item))
            for item in value.values()
        ):
            raise ValueError("arguments must be bounded finite scalars")
        return value

    def model_post_init(self, __context: object, /) -> None:
        kind = self.arguments.get("kind")
        if not isinstance(kind, str) or self.tool_name != f"operations.{kind}":
            raise ValueError("action kind must match operations tool name")


class EvidenceFact(ContractModel):
    citation: str = Field(pattern=r"^e[0-9]{1,2}$")
    source_tool: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
    source_digest: Sha256Hex
    freshness: Literal["fresh", "stale", "expired"]
    facts: tuple[SemanticFact, ...] = Field(max_length=8)


class CommittedCallFact(ContractModel):
    position: int = Field(ge=0, le=32)
    tool_name: str = Field(pattern=r"^(<unnamed>|[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)$")
    scope: str = Field(pattern=r"^[a-z][a-z0-9:_-]{0,63}$")
    status: SafeName


class CurrentStateFact(ContractModel):
    path: ChangedPath
    value: StrictStr | StrictInt | StrictFloat | StrictBool | None

    @field_validator("value")
    @classmethod
    def bounded_scalar(
        cls, value: StrictStr | StrictInt | StrictFloat | StrictBool | None
    ) -> StrictStr | StrictInt | StrictFloat | StrictBool | None:
        if (isinstance(value, str) and len(value) > _MAX_SCALAR) or (
            isinstance(value, float) and not math.isfinite(value)
        ):
            raise ValueError("state scalars must be bounded and finite")
        return value


class MonitorInputV2(ContractModel):
    input_schema_version: Literal["monitor-input-v2"] = "monitor-input-v2"
    prompt_version: Literal["monitor-prompt/v1"] = "monitor-prompt/v1"
    scenario_id: str = Field(pattern=r"^(D[1-8]|S[1-2]|R[0-9]{2}|T[1-8])$")
    incident_objective: str = Field(min_length=1, max_length=200)
    allowed_action_tools: tuple[ToolName, ...] = Field(max_length=16)
    forbidden_action_tools: tuple[ToolName, ...] = Field(max_length=16)
    allowed_changed_paths: tuple[ChangedPath, ...] = Field(max_length=32)
    action: ProposedActionFacts
    action_fingerprint: Sha256Hex
    policy_decision: PolicyDecision
    policy_risk_class: Literal["prohibited", "approval_required", "allowed"]
    policy_reasons: tuple[str, ...] = Field(min_length=1, max_length=16)
    evidence_support_state: Literal["valid", "invalid"]
    evidence_facts: tuple[EvidenceFact, ...] = Field(max_length=32)
    committed_calls: tuple[CommittedCallFact, ...] = Field(max_length=16)
    current_state_facts: tuple[CurrentStateFact, ...] = Field(max_length=32)
    authorization_required: StrictBool
    authorization_scope: str = Field(pattern=r"^[a-z][a-z0-9:_-]{0,63}$")

    @field_validator(
        "allowed_action_tools", "forbidden_action_tools", "allowed_changed_paths", "policy_reasons"
    )
    @classmethod
    def unique_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(value)) or len(set(value)) != len(value):
            raise ValueError("tuples must be unique and sorted")
        return value

    @field_validator("policy_reasons")
    @classmethod
    def frozen_reasons(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not all(is_known_reason(reason) for reason in value):
            raise ValueError("policy reasons must be frozen")
        return value

    def model_post_init(self, __context: object, /) -> None:
        encoded = json.dumps(
            self.action.arguments,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        if sha256(encoded.encode("utf-8")).hexdigest() != self.action_fingerprint:
            raise ValueError("action fingerprint must match action arguments")


class DurableFactReader(Protocol):
    """The only durable reads allowed to semantic-monitor adapters."""

    def ordered_operation_calls(self, incident_id: str) -> tuple[object, ...]: ...
    def checkpoint_state(self, scenario_id: str) -> dict[str, object]: ...


class ScenarioProjectionAdapter:
    """Reads only the manifest's public scenario policy fields."""

    def project(
        self, manifest: ScenarioManifest | ReliabilityManifest | SabotageManifest
    ) -> dict[str, object]:
        return {
            "incident_objective": manifest.title,
            "allowed_action_tools": tuple(sorted(manifest.allowed_actions)),
            "forbidden_action_tools": tuple(sorted(manifest.forbidden_actions)),
            "allowed_changed_paths": tuple(sorted(getattr(manifest, "allowed_changed_paths", ()))),
        }


def action_facts(action: CanonicalAction) -> ProposedActionFacts:
    """Project only the typed action arguments, never its run identity."""
    return ProposedActionFacts(
        action_schema_version=action.action_schema_version,
        tool_name=action.tool_name,
        arguments=action.arguments.model_dump(mode="json"),
    )


def action_fingerprint(action: CanonicalAction) -> str:
    return canonical_arguments_digest(action)


FactConverter = Callable[[bool | int | float | str], SemanticFact | None]


def project_evidence(
    scenario_id: str,
    validation: EvidenceValidation,
    records: tuple[object, ...],
    allowlist: dict[tuple[str, str], dict[str, FactConverter]],
) -> tuple[EvidenceFact, ...]:
    """Make a strict allowlist projection; unknown payload fields are omitted."""
    if len(records) > 32:
        raise ValueError("too many evidence records")
    result: list[EvidenceFact] = []
    for index, record in enumerate(records):
        tool = getattr(record, "tool_name", None)
        payload = getattr(record, "payload", None)
        if not isinstance(tool, str) or not isinstance(payload, dict):
            continue
        known = allowlist.get((scenario_id, tool), {})
        facts: list[SemanticFact] = []
        for key in sorted(known):
            value = payload.get(key)
            if isinstance(value, (bool, int, float, str)):
                fact = known[key](value)
                if fact is not None:
                    facts.append(fact)
        digest = sha256(
            json.dumps(
                {"tool": tool, "facts": [fact.model_dump(mode="json") for fact in facts]},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        evidence_id = getattr(record, "evidence_id", None)
        freshness: Literal["fresh", "stale", "expired"] = "fresh"
        if isinstance(evidence_id, str) and expired_evidence(evidence_id) in validation.reasons:
            freshness = "expired"
        elif isinstance(evidence_id, str) and stale_evidence(evidence_id) in validation.reasons:
            freshness = "stale"
        result.append(
            EvidenceFact(
                citation=f"e{index}",
                source_tool=tool,
                source_digest=digest,
                freshness=freshness,
                facts=tuple(facts),
            )
        )
    return tuple(result)


@dataclass(frozen=True, slots=True)
class MonitorConsultation:
    """Raw frozen graph boundary; projection to prompt input belongs to an adapter."""

    incident: IncidentIdentity
    action: CanonicalAction
    records: tuple[EvidenceRecord, ...]
    evidence: EvidenceValidation
    policy: PolicyOutcome
    safeguards: SafeguardConfiguration


def render_monitor_prompt(input_value: MonitorInputV2) -> str:
    """Stable data-only rendering. Deliberately contains no durable identity or oracle."""
    prompt = json.dumps(
        input_value.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    if len(prompt.encode("utf-8")) > _MAX_PROMPT_BYTES:
        raise ValueError("monitor prompt exceeds byte limit")
    return prompt


def monitor_input_schema_sha256() -> str:
    return sha256(
        json.dumps(
            MonitorInputV2.model_json_schema(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
