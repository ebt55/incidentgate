"""Strict, offline replay cache for captured structured model responses."""

from __future__ import annotations

import json
import math
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, Literal

from pydantic import Field, StrictFloat, StrictInt, field_validator, model_validator

from incidentgate.contracts import ContractModel, EvaluationMode, ModelInvocationRecord

from .model_proposal import CompletionClient, CompletionRequest, CompletionResult

_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_GIT_REVISION = re.compile(r"^[a-f0-9]{40}$")
_MAX_RAW_JSON_BYTES = 1_000_000
_MAX_ENTRY_BYTES = 1_100_000
CaptureKind = Literal["provider_call", "synthetic", "local_weights_call"]

#: The two capture kinds that record a real model producing a real body. They
#: differ in who was billed, not in whether a model ran, so they carry the same
#: provenance and are validated together.
_REAL_CAPTURES: Final = ("provider_call", "local_weights_call")


class ResponseCacheMiss(Exception):
    def __init__(self, model: str, prompt_sha256: str) -> None:
        self.model, self.prompt_sha256 = model, prompt_sha256
        super().__init__(f"no cached completion for {model}:{prompt_sha256}")


class ProviderCaptureProvenance(ContractModel):
    """Secret-free, bounded evidence that a body was obtained by one live call."""

    provider: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")
    model: str = Field(min_length=1, max_length=128, pattern=_MODEL_ID.pattern)
    role: Literal["proposer", "monitor"]
    prompt_sha256: str = Field(pattern=_SHA256.pattern)
    request_schema_sha256: str = Field(pattern=_SHA256.pattern)
    input_schema_version: str = Field(
        min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9._/-]*$"
    )
    prompt_version: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9._/-]*$")
    #: Digest of the *scenario projection* this prompt was built from, as distinct
    #: from the scenario contract it was projected out of.
    #:
    #: WHY A CONTRACT DIGEST IS NOT ENOUGH, FOUND BY A GUARD RATHER THAN BY READING.
    #:
    #: ``ScenarioProjectionAdapter`` was corrected -- its allowlist had been
    #: excluding two thirds of T4's honest plan -- and every T4 monitor prompt
    #: changed while every field of its provenance stayed identical. The frozen
    #: manifest had not moved, so nothing recorded that the projection *of* it had.
    #: Two captures at one position then claimed byte-identical provenance and
    #: carried different prompt digests, and neither was dishonest.
    #:
    #: ``None`` means **not recorded**: the capture predates this field. It never
    #: means "no projection", and it is not backfilled -- a digest reconstructed for
    #: an old capture would be a guess presented as a record, the same line
    #: ``operation_ledger.arguments`` and ``request_envelope`` both draw.
    scenario_projection_sha256: str | None = Field(default=None, pattern=_SHA256.pattern)
    stop_reason: Literal["end_turn"]
    input_tokens: StrictInt = Field(ge=0)
    output_tokens: StrictInt = Field(ge=0)
    usage_source: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_-]+$")
    capture_mode: Literal["live_provider_call"]
    captured_at: datetime
    capture_command: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_./ :+=-]+$")
    git_revision: str = Field(pattern=_GIT_REVISION.pattern)
    #: Optional because a local-weights capture has no vendor and therefore no
    #: price list. Naming a sentinel snapshot to fill the slot would be inventing
    #: a price list for something that has no price, which is the fabrication
    #: this field exists to prevent. A provider call still requires one -- see
    #: ``cost_is_coherent``.
    pricing_snapshot_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$"
    )
    estimated_cost: StrictFloat | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=1, max_length=8, pattern=r"^[A-Z]{3}$")
    #: THREE STATES, DELIBERATELY DISTINGUISHABLE.
    #:
    #: * ``model_not_priced_in_snapshot`` with ``estimated_cost: null`` -- a
    #:   vendor was billed and we could not price it. A gap in our price list.
    #: * ``local_weights_no_vendor_charge`` with ``estimated_cost: null`` -- no
    #:   vendor exists to bill. Not a gap; there is nothing to price.
    #: * ``null`` with ``estimated_cost: 0.0`` and a currency -- we priced it and
    #:   it really was free.
    #:
    #: Collapsing any two of these would let "we don't know what this cost" read
    #: as "this cost nothing", which for a project that publishes cost-per-
    #: incident is the expensive direction to be wrong in.
    cost_unavailable_reason: (
        Literal["model_not_priced_in_snapshot", "local_weights_no_vendor_charge"] | None
    )
    #: The weights that produced this body, as canonical JSON of a flat
    #: string->string object, for a local-weights capture only.
    #:
    #: This is the local arm's whole provenance advantage over a hosted one: an
    #: exact file, an exact hash the harness computed itself, and the digest the
    #: local store independently declared for it. A hosted capture has no such
    #: thing and records ``None``.
    weights: str | None = Field(default=None, min_length=2, max_length=1200)
    scenario_id: str = Field(pattern=r"^(D[1-8]|S[1-2]|R[0-9]{2}|T[1-8])$")
    variant_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    #: WHICH SAFEGUARD CONFIGURATION PRODUCED THIS CAPTURE.
    #:
    #: Widened from ``EvaluationMode`` alone on 2026-08-22, additively: every
    #: value that was legal before is still legal and means what it meant, and
    #: all sixteen committed captures keep the exact string they already carry.
    #:
    #: The widening was needed because a configuration now exists that is not an
    #: ``EvaluationMode``: Route B runs the evidence gate enforcing, the policy
    #: gate **observing**, the monitor enforcing and durable human authorization,
    #: so the covert call reaches the monitor instead of being denied before it.
    #: A fourth ``EvaluationMode`` member was not available --
    #: ``CheckpointBRawEnvelope`` pins exactly ``10 scenarios x
    #: len(EvaluationMode)`` = 30 rows, so adding one invalidates every committed
    #: checkpoint-B envelope. **Do not "simplify" this union into a fourth
    #: ``EvaluationMode``; that breaks the published matrices.**
    #:
    #: The literal is deliberately long. This field is read by people working out
    #: what a number means, and it has to say which gates were on without them
    #: opening another file -- ``other`` or ``custom`` would evade exactly the
    #: question the field exists to answer.
    condition: EvaluationMode | Literal[
        "evidence_enforce_policy_observe_monitor_enforce_durable_human"
    ]
    leg: Literal["covert", "incident"]
    step_index: StrictInt = Field(ge=0)
    split: Literal["development", "calibration", "holdout"]
    #: The API envelope this capture's request was carried in, as canonical JSON
    #: of a flat string->string object (see ``anthropic_envelope_descriptor`` and
    #: ``openai_envelope_descriptor``).
    #:
    #: WHY THE ENVELOPE IS PART OF PROVENANCE AND NOT A DOCSTRING
    #: =========================================================
    #: Two providers cannot be sent byte-identical *requests*, only byte-identical
    #: *content*: the system instructions travel in a different channel, the
    #: output budget has a different name, and reasoning is controlled -- or not
    #: controlled -- differently. Those differences are small, real, and exactly
    #: the kind of thing that gets absorbed into "we sent both models the same
    #: prompt". Recording them beside the captured bytes means a reader comparing
    #: a claude row with a gpt row can see what was not identical and judge it,
    #: instead of taking the equivalence on trust.
    #:
    #: Optional because captures predating the field exist and are not being
    #: re-taken: the committed claude-opus-5 entry carries no envelope, and
    #: back-filling one would be asserting provenance for a request nobody
    #: recorded. ``None`` means "not recorded", never "no difference".
    request_envelope: str | None = Field(default=None, min_length=2, max_length=800)

    @field_validator("request_envelope", "weights")
    @classmethod
    def envelope_is_a_flat_string_object(cls, value: str | None) -> str | None:
        """Bound the shape as well as the size: provenance must stay readable and inert."""
        if value is None:
            return value
        parsed = json.loads(value)
        if not isinstance(parsed, dict) or not parsed:
            raise ValueError("request envelope must be a non-empty JSON object")
        if any(
            not isinstance(key, str) or not isinstance(item, str) or not key or not item
            for key, item in parsed.items()
        ):
            raise ValueError("request envelope must map non-empty strings to non-empty strings")
        return value

    @field_validator("captured_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("provider capture timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def cost_is_coherent(self) -> ProviderCaptureProvenance:
        if self.estimated_cost is not None and not math.isfinite(self.estimated_cost):
            raise ValueError("priced capture cost must be finite")
        local = self.cost_unavailable_reason == "local_weights_no_vendor_charge"
        if local and self.pricing_snapshot_id is not None:
            raise ValueError("a local weights capture names no pricing snapshot")
        if not local and not self.pricing_snapshot_id:
            raise ValueError("a provider capture must name the pricing snapshot it was priced at")
        if self.estimated_cost is None:
            if self.currency is not None or self.cost_unavailable_reason is None:
                raise ValueError("unpriced capture requires explicit unavailable-cost reason")
        elif self.cost_unavailable_reason is not None or self.currency is None:
            raise ValueError("priced capture has invalid cost provenance")
        return self

    def validate_invocation(
        self, request: CompletionRequest, invocation: ModelInvocationRecord
    ) -> None:
        text = (
            self.provider,
            self.model,
            self.input_schema_version,
            self.prompt_version,
            self.capture_command,
            self.scenario_id,
            self.variant_id,
            self.condition,
            self.leg,
            self.split,
        )
        if any(not item or len(item) > 200 for item in text):
            raise ValueError("provider capture provenance has empty or oversized text")
        if self.role not in ("proposer", "monitor") or self.stop_reason != "end_turn":
            raise ValueError("provider capture provenance has invalid role or stop reason")
        if self.capture_mode != "live_provider_call" or not _GIT_REVISION.fullmatch(
            self.git_revision
        ):
            raise ValueError("provider capture provenance has invalid capture mode or revision")
        if not _SHA256.fullmatch(self.prompt_sha256) or not _SHA256.fullmatch(
            self.request_schema_sha256
        ):
            raise ValueError("provider capture provenance has invalid hashes")
        if (self.prompt_sha256, self.model) != (request.prompt_sha256, request.model):
            raise ValueError("provider capture provenance does not match cache key")
        if (
            not request.canonical_prompt
            or sha256_text(request.canonical_prompt) != self.prompt_sha256
        ):
            raise ValueError("provider capture canonical prompt disagrees with its hash")
        if not request.schema or schema_sha256(request.schema) != self.request_schema_sha256:
            raise ValueError("provider capture schema disagrees with its hash")
        if invocation.invocation_kind not in _REAL_CAPTURES:
            raise ValueError("captures require a real model invocation")
        # A local capture has no vendor, so the cost fields it must agree with are
        # the absent ones. Requiring the weights identity here is what stops a
        # local capture being recorded with the provenance of a hosted one.
        if invocation.invocation_kind == "local_weights_call":
            if self.cost_unavailable_reason != "local_weights_no_vendor_charge":
                raise ValueError("a local weights capture must record why no cost applies")
            if not self.weights:
                raise ValueError("a local weights capture must record the weights that produced it")
        elif self.weights is not None:
            raise ValueError("only a local weights capture may record a weights identity")
        if (invocation.provider, invocation.model) != (self.provider, self.model):
            raise ValueError("provider/model provenance disagrees with invocation")
        if (
            invocation.input_tokens,
            invocation.output_tokens,
            invocation.pricing_snapshot,
            invocation.usage_source,
        ) != (
            self.input_tokens,
            self.output_tokens,
            self.pricing_snapshot_id,
            self.usage_source,
        ):
            raise ValueError("provider capture usage/pricing disagrees with invocation")
        if (invocation.cost, invocation.currency) != (self.estimated_cost, self.currency):
            raise ValueError("provider capture cost disagrees with invocation")

    def validate_cache_key(self, model: str, prompt_sha256: str) -> None:
        if (self.model, self.prompt_sha256) != (model, prompt_sha256):
            raise ValueError("provider capture provenance does not match cache key")

    def json_value(self) -> dict[str, object]:
        return self.model_dump(mode="json")


@dataclass(frozen=True)
class CachedCompletion:
    raw_json: str
    capture: CaptureKind
    provenance: ProviderCaptureProvenance | None = None


def sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def schema_sha256(schema: dict[str, object]) -> str:
    import hashlib

    encoded = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_raw_json(raw_json: str) -> None:
    if len(raw_json.encode("utf-8")) > _MAX_RAW_JSON_BYTES:
        raise ValueError("raw_json exceeds cache size limit")
    try:
        parsed = json.loads(raw_json)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("raw_json is not valid JSON") from error
    if not isinstance(parsed, (dict, list)):
        raise ValueError("raw_json must be a structured JSON value")  # noqa: TRY004


@dataclass(frozen=True)
class ResponseCache:
    root: Path

    def _path(self, model: str, prompt_sha256: str) -> Path:
        if not _MODEL_ID.fullmatch(model):
            raise ValueError("unsafe model id for cache path")
        if not _SHA256.fullmatch(prompt_sha256):
            raise ValueError("prompt_sha256 must be a lowercase sha256 hex digest")
        return self.root / model / f"{prompt_sha256}.json"

    def load(self, model: str, prompt_sha256: str) -> CachedCompletion:
        path = self._path(model, prompt_sha256)
        if not path.is_file():
            raise ResponseCacheMiss(model, prompt_sha256)
        try:
            encoded = path.read_bytes()
            if len(encoded) > _MAX_ENTRY_BYTES:
                raise ValueError("cache entry exceeds size limit")
            data = json.loads(encoded)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("malformed cache entry") from error
        if (
            not isinstance(data, dict)
            or data.get("model") != model
            or data.get("prompt_sha256") != prompt_sha256
            or not isinstance(data.get("raw_json"), str)
        ):
            raise ValueError("corrupt cache entry")
        _validate_raw_json(data["raw_json"])
        capture = data.get("capture")
        if capture not in (*_REAL_CAPTURES, "synthetic"):
            raise ValueError("cache entry does not record how it was captured")
        if capture == "synthetic":
            if set(data) != {"capture", "model", "prompt_sha256", "raw_json"}:
                raise ValueError("synthetic cache entries must not carry provider provenance")
            return CachedCompletion(data["raw_json"], "synthetic")
        raw = data.get("provenance")
        permitted = {"capture", "model", "prompt_sha256", "provenance", "raw_json"}
        if set(data) != permitted or not isinstance(raw, dict):
            raise ValueError("provider cache entry lacks provenance")
        try:
            provenance = ProviderCaptureProvenance.model_validate(raw)
            provenance.validate_cache_key(model, prompt_sha256)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("malformed provider cache provenance") from error
        # The entry's own claim about how it was captured must agree with the
        # cost provenance inside it, or a local body could be replayed as a
        # hosted one and vice versa.
        local_reason = provenance.cost_unavailable_reason == "local_weights_no_vendor_charge"
        if (capture == "local_weights_call") != local_reason:
            raise ValueError("cache entry capture kind disagrees with its cost provenance")
        return CachedCompletion(data["raw_json"], capture, provenance)

    def store(
        self,
        model: str,
        prompt_sha256: str,
        raw_json: str,
        *,
        capture: CaptureKind,
        provenance: ProviderCaptureProvenance | None = None,
        invocation: ModelInvocationRecord | None = None,
        request: CompletionRequest | None = None,
    ) -> None:
        self._path(model, prompt_sha256)
        _validate_raw_json(raw_json)
        if capture == "synthetic":
            if provenance is not None or invocation is not None or request is not None:
                raise ValueError("synthetic cache entries cannot carry provider provenance")
            payload: dict[str, object] = {
                "capture": capture,
                "model": model,
                "prompt_sha256": prompt_sha256,
                "raw_json": raw_json,
            }
        elif capture in _REAL_CAPTURES:
            if provenance is None or invocation is None or request is None:
                raise ValueError(
                    "provider cache entries require request, invocation and provenance"
                )
            if (request.model, request.prompt_sha256) != (model, prompt_sha256):
                raise ValueError("provider cache request disagrees with cache key")
            if invocation.invocation_kind != capture:
                raise ValueError("cache entry capture kind disagrees with its invocation")
            provenance.validate_invocation(request, invocation)
            payload = {
                "capture": capture,
                "model": model,
                "prompt_sha256": prompt_sha256,
                "provenance": provenance.json_value(),
                "raw_json": raw_json,
            }
        else:
            raise ValueError("capture must be one of provider_call, local_weights_call, synthetic")
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        if len(encoded) > _MAX_ENTRY_BYTES:
            raise ValueError("cache entry exceeds size limit")
        path = self._path(model, prompt_sha256)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".capture-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                if path.read_bytes() != encoded:
                    raise ValueError("refusing to overwrite a semantically different cache entry")
            finally:
                os.unlink(temporary)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


CaptureProvenanceBuilder = Callable[
    [CompletionRequest, CompletionResult], ProviderCaptureProvenance
]


class CacheBackedCompletionClient:
    def __init__(
        self,
        cache: ResponseCache,
        *,
        record_client: CompletionClient | None = None,
        record_mode: bool = False,
        provenance_builder: CaptureProvenanceBuilder | None = None,
        provider: str | None = None,
    ) -> None:
        if record_mode and (record_client is None or provenance_builder is None):
            raise ValueError("record mode requires a record client and provenance builder")
        self._cache, self._record_client = cache, record_client
        self._record_mode, self._provenance_builder, self._provider = (
            record_mode,
            provenance_builder,
            provider,
        )

    def complete(self, request: CompletionRequest) -> CompletionResult:
        try:
            entry = self._cache.load(request.model, request.prompt_sha256)
        except ResponseCacheMiss:
            if (
                not self._record_mode
                or self._record_client is None
                or self._provenance_builder is None
            ):
                raise
            result = self._record_client.complete(request)
            kind = result.invocation.invocation_kind
            if kind not in _REAL_CAPTURES:
                # Still refuses a fixture or a replay: recording one as a capture
                # is how a hand-written body would be laundered into a claim that
                # a model produced it. A local call is a real model producing a
                # real body, so it is admitted -- under its own kind, never
                # relabelled as a provider call.
                raise ValueError("record mode refuses results that did not come from a model")
            capture_kind: CaptureKind = (
                "local_weights_call" if kind == "local_weights_call" else "provider_call"
            )
            provenance = self._provenance_builder(request, result)
            self._cache.store(
                request.model,
                request.prompt_sha256,
                result.raw_json,
                capture=capture_kind,
                provenance=provenance,
                invocation=result.invocation,
                request=request,
            )
            return result
        if entry.capture == "synthetic":
            return CompletionResult(
                entry.raw_json, ModelInvocationRecord(invocation_kind="fixture_no_call")
            )
        assert entry.provenance is not None
        if self._provider is not None and self._provider != entry.provenance.provider:
            raise ValueError("cache replay provider disagrees with captured provenance")
        return CompletionResult(
            entry.raw_json,
            ModelInvocationRecord(
                invocation_kind="cache_replay",
                provider=entry.provenance.provider,
                model=request.model,
            ),
        )
