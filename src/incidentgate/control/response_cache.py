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
from typing import Literal

from pydantic import Field, StrictFloat, StrictInt, field_validator, model_validator

from incidentgate.contracts import ContractModel, EvaluationMode, ModelInvocationRecord

from .model_proposal import CompletionClient, CompletionRequest, CompletionResult

_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_GIT_REVISION = re.compile(r"^[a-f0-9]{40}$")
_MAX_RAW_JSON_BYTES = 1_000_000
_MAX_ENTRY_BYTES = 1_100_000
CaptureKind = Literal["provider_call", "synthetic"]


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
    stop_reason: Literal["end_turn"]
    input_tokens: StrictInt = Field(ge=0)
    output_tokens: StrictInt = Field(ge=0)
    usage_source: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_-]+$")
    capture_mode: Literal["live_provider_call"]
    captured_at: datetime
    capture_command: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_./ :+=-]+$")
    git_revision: str = Field(pattern=_GIT_REVISION.pattern)
    pricing_snapshot_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$"
    )
    estimated_cost: StrictFloat | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=1, max_length=8, pattern=r"^[A-Z]{3}$")
    cost_unavailable_reason: Literal["model_not_priced_in_snapshot"] | None
    scenario_id: str = Field(pattern=r"^(D[1-8]|S[1-2]|R[0-9]{2}|T[1-8])$")
    variant_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    condition: EvaluationMode
    leg: Literal["covert", "incident"]
    step_index: StrictInt = Field(ge=0)
    split: Literal["development", "calibration", "holdout"]

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
        if self.estimated_cost is None:
            if (
                self.currency is not None
                or self.cost_unavailable_reason != "model_not_priced_in_snapshot"
            ):
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
            self.pricing_snapshot_id,
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
        if invocation.invocation_kind != "provider_call":
            raise ValueError("provider captures require a real provider invocation")
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
        if capture not in ("provider_call", "synthetic"):
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
        return CachedCompletion(data["raw_json"], "provider_call", provenance)

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
        elif capture == "provider_call":
            if provenance is None or invocation is None or request is None:
                raise ValueError(
                    "provider cache entries require request, invocation and provenance"
                )
            if (request.model, request.prompt_sha256) != (model, prompt_sha256):
                raise ValueError("provider cache request disagrees with cache key")
            provenance.validate_invocation(request, invocation)
            payload = {
                "capture": capture,
                "model": model,
                "prompt_sha256": prompt_sha256,
                "provenance": provenance.json_value(),
                "raw_json": raw_json,
            }
        else:
            raise ValueError("capture must be one of provider_call or synthetic")
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
            if result.invocation.invocation_kind != "provider_call":
                raise ValueError("record mode refuses non-provider results")
            provenance = self._provenance_builder(request, result)
            self._cache.store(
                request.model,
                request.prompt_sha256,
                result.raw_json,
                capture="provider_call",
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
