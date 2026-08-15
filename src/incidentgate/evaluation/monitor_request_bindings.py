"""Frozen, pre-provider binding of monitor requests to their runtime sources.

The response cache deliberately remains a one-request/one-capture store.  This
module records the distinct fact that a byte-identical monitor request can be
reached from more than one frozen runtime source.  It contains hashes and typed
metadata only; prompt text and model output stay out of this contract.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

from pydantic import Field, StrictBool, StrictFloat, StrictInt, field_validator, model_validator

from incidentgate.contracts import ContractModel

if TYPE_CHECKING:
    from incidentgate.evaluation.semantic_monitor_capture_plan import (
        MonitorAuditObservation,
        MonitorAuditSource,
        ReachedRequestIdentity,
    )

_SHA256 = r"^[a-f0-9]{64}$"
_MODEL = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_VERSION = r"^[a-z0-9][a-z0-9._/-]{0,79}$"
_VARIANT = r"^T[124]-(?:dev|cal|holdout)-v[0-9]+$"
_REVISION = r"^[a-f0-9]{40}$"
_MAX_WORKLIST_BYTES = 1_000_000


class MonitorRequestBindingRefusal(ValueError):
    """The no-call audit cannot become a frozen request/source worklist."""


class MonitorRequestIdentity(ContractModel):
    """Secret-free identity of one provider-targeted monitor request."""

    provider_target: Literal["anthropic"]
    model: str = Field(pattern=_MODEL)
    role: Literal["monitor"] = "monitor"
    prompt_sha256: str = Field(pattern=_SHA256)
    request_schema_sha256: str = Field(pattern=_SHA256)
    system_sha256: str = Field(pattern=_SHA256)
    user_content_sha256: str = Field(pattern=_SHA256)
    max_tokens: StrictInt = Field(gt=0, le=1_000_000)
    temperature: StrictFloat | None = Field(default=None, ge=0, le=2)
    thinking: tuple[tuple[str, str], ...] | None = Field(default=None, max_length=16)
    input_schema_version: Literal["monitor-input-v2"] = "monitor-input-v2"
    input_schema_sha256: str = Field(pattern=_SHA256)
    output_schema_sha256: str = Field(pattern=_SHA256)
    prompt_version: str = Field(pattern=_VERSION)

    @field_validator("thinking")
    @classmethod
    def bounded_thinking(
        cls, value: tuple[tuple[str, str], ...] | None
    ) -> tuple[tuple[str, str], ...] | None:
        if value is None:
            return value
        if tuple(sorted(value)) != value or any(
            not key or not item or len(key) > 80 or len(item) > 200 for key, item in value
        ):
            raise ValueError("thinking must be bounded and canonically sorted")
        return value

    @field_validator("temperature")
    @classmethod
    def finite_temperature(cls, value: StrictFloat | None) -> StrictFloat | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("temperature must be finite")
        return value


class MonitorSourceMembership(ContractModel):
    """One exact source which reached (or did not reach) a monitor request."""

    scenario_id: Literal["T1", "T2", "T4"]
    variant_id: str | None = Field(default=None, pattern=_VARIANT)
    case_id: str | None = Field(default=None, pattern=r"^BM-[0-9]{3}$")
    split: Literal["development", "calibration", "holdout"]
    seed: StrictInt = Field(ge=0, le=2_147_483_647)
    condition: Literal["complete"] = "complete"
    leg: Literal["covert", "incident"]
    step_index: StrictInt = Field(ge=0, le=63)
    redelivered: StrictBool = False

    @model_validator(mode="after")
    def one_source_kind(self) -> MonitorSourceMembership:
        if (self.variant_id is None) == (self.case_id is None):
            raise ValueError("source membership must name exactly one variant or benign case")
        return self

    @property
    def key(self) -> tuple[object, ...]:
        return (
            self.scenario_id,
            self.variant_id or "",
            self.case_id or "",
            self.split,
            self.seed,
            self.condition,
            self.leg,
            self.step_index,
            self.redelivered,
        )


CapturePhase = Literal["pre_threshold_development", "calibration_eligible", "post_threshold_freeze"]


class MonitorRequestBindingEntry(ContractModel):
    request: MonitorRequestIdentity
    request_identity_sha256: str = Field(pattern=_SHA256)
    sources: tuple[MonitorSourceMembership, ...] = Field(min_length=1, max_length=64)
    capture_witness: MonitorSourceMembership
    capture_phase: CapturePhase

    @model_validator(mode="after")
    def coherent(self) -> MonitorRequestBindingEntry:
        if self.request_identity_sha256 != request_identity_digest(self.request):
            raise ValueError("request identity digest disagrees with request fields")
        keys = tuple(source.key for source in self.sources)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise ValueError("request sources must be unique and canonically sorted")
        if self.capture_witness not in self.sources:
            raise ValueError("capture witness must be an exact request source member")
        if self.capture_witness != self.sources[0]:
            raise ValueError("capture witness must be the deterministic first source member")
        if self.capture_phase != derive_capture_phase(self.sources):
            raise ValueError("request capture phase disagrees with source memberships")
        return self


class MonitorNonConsultation(ContractModel):
    source: MonitorSourceMembership
    reason: Literal["policy_denied_before_monitor", "monitor_not_consulted"]


class MonitorRequestBindingWorklist(ContractModel):
    """Versioned, immutable in-memory contract suitable for later file freezing."""

    schema_version: Literal["monitor-request-binding-worklist/v1"] = (
        "monitor-request-binding-worklist/v1"
    )
    worklist_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    source_git_revision: str = Field(pattern=_REVISION)
    frozen_at: datetime
    audit_sha256: str = Field(pattern=_SHA256)
    entries: tuple[MonitorRequestBindingEntry, ...] = Field(min_length=1, max_length=256)
    non_consultations: tuple[MonitorNonConsultation, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def canonical_and_complete(self) -> MonitorRequestBindingWorklist:
        if self.frozen_at.tzinfo is None or self.frozen_at.utcoffset() is None:
            raise ValueError("worklist frozen_at must be timezone-aware")
        entry_keys = tuple(entry.request_identity_sha256 for entry in self.entries)
        if entry_keys != tuple(sorted(entry_keys)) or len(set(entry_keys)) != len(entry_keys):
            raise ValueError("worklist entries must be unique and canonically sorted")
        consulted = [source.key for entry in self.entries for source in entry.sources]
        missing = [row.source.key for row in self.non_consultations]
        if len(set(consulted)) != len(consulted) or len(set(missing)) != len(missing):
            raise ValueError("worklist source memberships must be globally unique")
        if set(consulted) & set(missing):
            raise ValueError("a source cannot be both consulted and non-consulted")
        if missing != sorted(missing):
            raise ValueError("non-consultations must be canonically sorted")
        if (
            len({entry.request.provider_target for entry in self.entries}) != 1
            or len({entry.request.model for entry in self.entries}) != 1
        ):
            raise ValueError("worklist entries must target one provider/model")
        return self


def request_identity_digest(identity: MonitorRequestIdentity) -> str:
    return sha256(_canonical_json(identity.model_dump(mode="json"))).hexdigest()


def worklist_json_bytes(worklist: MonitorRequestBindingWorklist) -> bytes:
    """Canonical bytes for a caller that later freezes the pre-provider contract."""
    return _canonical_json(worklist.model_dump(mode="json")) + b"\n"


def load_worklist(path: Path) -> MonitorRequestBindingWorklist:
    """Read a frozen worklist.  This module deliberately has no write path."""
    if not path.is_file():
        raise MonitorRequestBindingRefusal("worklist path must be a regular file")
    try:
        size = path.stat().st_size
    except OSError as error:
        raise MonitorRequestBindingRefusal("worklist path is not readable") from error
    if size <= 0 or size > _MAX_WORKLIST_BYTES:
        raise MonitorRequestBindingRefusal("worklist file has an invalid size")
    return MonitorRequestBindingWorklist.model_validate_json(path.read_bytes())


def build_verified_worklist(
    first: Iterable[MonitorAuditObservation],
    second: Iterable[MonitorAuditObservation],
    *,
    worklist_id: str,
    source_git_revision: str,
    frozen_at: datetime,
    provider_target: Literal["anthropic"] = "anthropic",
) -> MonitorRequestBindingWorklist:
    """Refuse unstable cold drives before deriving any provider-targeted work."""
    left, right = tuple(first), tuple(second)
    if left != right:
        raise MonitorRequestBindingRefusal("monitor request worklist cold audit is not stable")
    return build_worklist(
        left,
        worklist_id=worklist_id,
        source_git_revision=source_git_revision,
        frozen_at=frozen_at,
        provider_target=provider_target,
    )


def build_worklist(
    observations: Iterable[MonitorAuditObservation],
    *,
    worklist_id: str,
    source_git_revision: str,
    frozen_at: datetime,
    provider_target: Literal["anthropic"] = "anthropic",
) -> MonitorRequestBindingWorklist:
    """Group actual reached requests without treating collision members as independent."""
    from incidentgate.evaluation.semantic_monitor_capture_plan import MonitorAuditObservation

    rows = tuple(observations)
    groups: dict[ReachedRequestIdentity, list[MonitorSourceMembership]] = defaultdict(list)
    non_consultations: list[MonitorNonConsultation] = []
    seen_sources: set[tuple[object, ...]] = set()
    for row in rows:
        if not isinstance(row, MonitorAuditObservation):
            raise TypeError("worklist observations must use the semantic monitor audit type")
        source = source_membership(row.source, redelivered=row.redelivered)
        if source.key in seen_sources:
            raise MonitorRequestBindingRefusal("cold audit repeated a source membership")
        seen_sources.add(source.key)
        if row.consulted:
            if row.request is None or row.invocation_kind != "fixture_no_call":
                raise MonitorRequestBindingRefusal(
                    "consulted audit row lacks no-call request evidence"
                )
            groups[row.request].append(source)
        else:
            if row.request is not None or row.invocation_kind is not None:
                raise MonitorRequestBindingRefusal("non-consultation row carries a request")
            if row.non_consultation_reason not in {
                "policy_denied_before_monitor",
                "monitor_not_consulted",
            }:
                raise MonitorRequestBindingRefusal("non-consultation row has an unknown reason")
            non_consultations.append(
                MonitorNonConsultation(
                    source=source,
                    reason=cast(
                        Literal["policy_denied_before_monitor", "monitor_not_consulted"],
                        row.non_consultation_reason,
                    ),
                )
            )
    entries: list[MonitorRequestBindingEntry] = []
    for reached, sources in groups.items():
        identity = identity_from_reached(reached, provider_target=provider_target)
        canonical_sources = tuple(sorted(sources, key=lambda item: item.key))
        entries.append(
            MonitorRequestBindingEntry(
                request=identity,
                request_identity_sha256=request_identity_digest(identity),
                sources=canonical_sources,
                capture_witness=canonical_sources[0],
                capture_phase=derive_capture_phase(canonical_sources),
            )
        )
    canonical_entries = tuple(sorted(entries, key=lambda item: item.request_identity_sha256))
    canonical_non_consultations = tuple(sorted(non_consultations, key=lambda item: item.source.key))
    return MonitorRequestBindingWorklist(
        worklist_id=worklist_id,
        source_git_revision=source_git_revision,
        frozen_at=frozen_at,
        audit_sha256=observation_digest(rows),
        entries=canonical_entries,
        non_consultations=canonical_non_consultations,
    )


def derive_capture_phase(sources: Iterable[MonitorSourceMembership]) -> CapturePhase:
    values = tuple(sources)
    splits = {source.split for source in values}
    if not values:
        raise ValueError("capture phase requires at least one source")
    if "holdout" in splits or len(splits) > 1:
        return "post_threshold_freeze"
    if splits == {"calibration"}:
        return "calibration_eligible"
    if splits == {"development"}:
        return "pre_threshold_development"
    raise ValueError("source memberships have an unsupported split set")


def source_membership(source: MonitorAuditSource, *, redelivered: bool) -> MonitorSourceMembership:
    return MonitorSourceMembership(
        scenario_id=source.scenario_id,
        variant_id=source.variant_id,
        case_id=source.case_id,
        split=source.split,
        seed=source.seed,
        leg=source.leg,
        step_index=source.step_index,
        redelivered=redelivered,
    )


def identity_from_reached(
    reached: ReachedRequestIdentity, *, provider_target: Literal["anthropic"]
) -> MonitorRequestIdentity:
    if sha256(reached.canonical_prompt.encode()).hexdigest() != reached.canonical_prompt_sha256:
        raise MonitorRequestBindingRefusal(
            "reached request canonical prompt disagrees with its hash"
        )
    if reached.temperature is not None and (
        isinstance(reached.temperature, bool)
        or not isinstance(reached.temperature, (int, float))
        or not math.isfinite(reached.temperature)
    ):
        raise MonitorRequestBindingRefusal("reached request has an invalid temperature")
    try:
        envelope = json.loads(reached.canonical_prompt)
    except (TypeError, json.JSONDecodeError) as error:
        raise MonitorRequestBindingRefusal(
            "reached request lacks a canonical JSON envelope"
        ) from error
    if not isinstance(envelope, dict):
        raise MonitorRequestBindingRefusal("reached request envelope is not an object")
    expected = {
        "system",
        "user",
        "model",
        "max_tokens",
        "temperature",
        "thinking",
        "input_schema_sha256",
        "output_schema_sha256",
        "prompt_version",
    }
    system, user = envelope.get("system"), envelope.get("user")
    if (
        not isinstance(system, str)
        or not isinstance(user, str)
        or len(system.encode()) > 1_000_000
        or len(user.encode()) > 1_000_000
        or sha256(system.encode()).hexdigest() != reached.system_sha256
        or sha256(user.encode()).hexdigest() != reached.user_content_sha256
    ):
        raise MonitorRequestBindingRefusal("reached request text disagrees with its hashes")
    for key in ("input_schema_sha256", "output_schema_sha256", "prompt_version"):
        if not isinstance(envelope.get(key), str) or len(envelope[key]) > 80:
            raise MonitorRequestBindingRefusal("reached request envelope has invalid contract text")
    expected_thinking = None if reached.thinking is None else dict(reached.thinking)
    if set(envelope) != expected or (
        envelope["model"],
        envelope["max_tokens"],
        envelope["temperature"],
        envelope["thinking"],
    ) != (reached.model, reached.max_tokens, reached.temperature, expected_thinking):
        raise MonitorRequestBindingRefusal("reached request envelope disagrees with its identity")
    thinking = None if reached.thinking is None else tuple(sorted(reached.thinking))
    return MonitorRequestIdentity(
        provider_target=provider_target,
        model=reached.model,
        prompt_sha256=reached.canonical_prompt_sha256,
        request_schema_sha256=reached.request_schema_sha256,
        system_sha256=reached.system_sha256,
        user_content_sha256=reached.user_content_sha256,
        max_tokens=reached.max_tokens,
        temperature=None if reached.temperature is None else float(reached.temperature),
        thinking=thinking,
        input_schema_sha256=envelope["input_schema_sha256"],
        output_schema_sha256=envelope["output_schema_sha256"],
        prompt_version=envelope["prompt_version"],
    )


def observation_digest(observations: Iterable[MonitorAuditObservation]) -> str:
    """Digest audit metadata without serializing prompt or response text."""
    values: list[dict[str, object]] = []
    for row in observations:
        source = source_membership(row.source, redelivered=row.redelivered)
        request = None
        if row.request is not None:
            request = {
                "prompt_sha256": row.request.canonical_prompt_sha256,
                "request_schema_sha256": row.request.request_schema_sha256,
                "model": row.request.model,
                "system_sha256": row.request.system_sha256,
                "user_content_sha256": row.request.user_content_sha256,
                "max_tokens": row.request.max_tokens,
                "temperature": row.request.temperature,
                "thinking": row.request.thinking,
            }
        values.append(
            {
                "source": source.model_dump(mode="json"),
                "consulted": row.consulted,
                "request": request,
                "invocation_kind": row.invocation_kind,
                "non_consultation_reason": row.non_consultation_reason,
            }
        )
    return sha256(_canonical_json(values)).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
