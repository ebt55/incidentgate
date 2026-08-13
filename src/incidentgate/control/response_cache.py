"""Deterministic replay of model outputs, keyed by (model_id, canonical prompt hash).

Current flagship models reject temperature/top_p (see the per-model capability table in
``model_proposal``), so bit-level determinism cannot come from sampling params - it comes from
replaying a committed output for an identical prompt. This
module is that store. In CI a cache hit returns a ``cache_replay`` invocation naming the provider
and model whose output is being replayed; no provider was contacted, so no usage or cost may be
claimed. ``record_mode`` is the only path that contacts a real client, and it is off by default so
the default and CI paths never touch the network.

WHAT AN ENTRY MUST NOW RECORD, AND WHY. Every entry states how its body was obtained, in a
required ``capture`` field: ``provider_call`` for a body a real provider returned, ``synthetic``
for one authored locally. Without it the stored shape was ``{model, prompt_sha256, raw_json}``
and nothing else -- no capture time, no response id, no usage -- so a hand-written body and a
genuine capture were byte-indistinguishable, and the filename's model directory was the only
thing asserting whose output it was. A directory name is not provenance: this repository's one
committed fixture was re-attributed from ``claude-opus-4-8`` to ``claude-opus-5`` by renaming its
folder, which a real capture cannot survive. Replaying such an entry as ``cache_replay`` would
have published "anthropic/claude-opus-5 produced this" about text a developer typed, so the
kind is now *derived* from ``capture`` rather than assumed: only a ``provider_call`` capture
replays as ``cache_replay``, and a ``synthetic`` one replays as the ``fixture_no_call`` it is.
An entry missing ``capture`` is rejected rather than guessed at, because guessing is what this
field exists to stop.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from incidentgate.contracts import ModelInvocationRecord

from .model_proposal import CompletionClient, CompletionRequest, CompletionResult

_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")

#: How an entry's body was obtained. ``provider_call`` is the only value that licenses a
#: ``cache_replay`` replay, because it is the only one under which a model really produced
#: the body.
CaptureKind = Literal["provider_call", "synthetic"]
_CAPTURE_KINDS: frozenset[str] = frozenset(("provider_call", "synthetic"))


class ResponseCacheMiss(Exception):
    """Explicit, typed miss so callers choose between recording and failing closed."""

    def __init__(self, model: str, prompt_sha256: str) -> None:
        self.model = model
        self.prompt_sha256 = prompt_sha256
        super().__init__(f"no cached completion for {model}:{prompt_sha256}")


@dataclass(frozen=True)
class CachedCompletion:
    """A stored body together with the provenance that decides how it may be replayed."""

    raw_json: str
    capture: CaptureKind


@dataclass(frozen=True)
class ResponseCache:
    """A directory of ``<model>/<prompt_sha256>.json`` entries, each
    self-describing for integrity."""

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
        data = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(data, dict)
            or data.get("model") != model
            or data.get("prompt_sha256") != prompt_sha256
            or not isinstance(data.get("raw_json"), str)
        ):
            raise ValueError("corrupt cache entry")
        capture = data.get("capture")
        if capture not in _CAPTURE_KINDS:
            # Deliberately not defaulted. An entry with no recorded provenance is exactly the
            # ambiguity this field removes, and the safe-looking default -- treating it as
            # synthetic -- would quietly downgrade a real capture instead of being fixed.
            raise ValueError(
                "cache entry does not record how it was captured; re-record it so its "
                f"capture is one of {sorted(_CAPTURE_KINDS)}"
            )
        raw_json: str = data["raw_json"]
        return CachedCompletion(raw_json=raw_json, capture=capture)

    def store(
        self, model: str, prompt_sha256: str, raw_json: str, *, capture: CaptureKind
    ) -> None:
        # Keyword-only and unconditionally required: a default here would let the next
        # locally-authored body inherit whichever value looked convenient at the call site,
        # which is precisely how the committed fixture came to be replayed under a model name.
        if capture not in _CAPTURE_KINDS:
            raise ValueError(f"capture must be one of {sorted(_CAPTURE_KINDS)}")
        path = self._path(model, prompt_sha256)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "capture": capture,
            "model": model,
            "prompt_sha256": prompt_sha256,
            "raw_json": raw_json,
        }
        path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
            encoding="utf-8",
        )


class CacheBackedCompletionClient:
    """A ``CompletionClient`` that replays the cache; only ``record_mode`` contacts the network."""

    def __init__(
        self,
        cache: ResponseCache,
        *,
        record_client: CompletionClient | None = None,
        record_mode: bool = False,
        provider: str = "anthropic",
    ) -> None:
        if record_mode and record_client is None:
            raise ValueError("record mode requires a record client")
        if not provider:
            raise ValueError("a replay must name the provider whose output it replays")
        self._cache = cache
        self._record_client = record_client
        self._record_mode = record_mode
        # The cache entry stores the model and the prompt hash but not the provider, so the
        # caller states it. The default matches the only client implementation in the tree;
        # captures from a different provider must say so rather than be replayed under a
        # name that is not theirs.
        self._provider = provider

    def __repr__(self) -> str:
        return f"CacheBackedCompletionClient(record_mode={self._record_mode!r})"

    def complete(self, request: CompletionRequest) -> CompletionResult:
        try:
            entry = self._cache.load(request.model, request.prompt_sha256)
        except ResponseCacheMiss:
            if not self._record_mode or self._record_client is None:
                raise
            result = self._record_client.complete(request)
            # Provenance is derived from what the record client actually did, never asserted by
            # the caller. A recorder wired to a canned body therefore stores ``synthetic`` even
            # if it wanted otherwise, which is the property that keeps this field honest.
            self._cache.store(
                request.model,
                request.prompt_sha256,
                result.raw_json,
                capture=(
                    "provider_call"
                    if result.invocation.invocation_kind == "provider_call"
                    else "synthetic"
                ),
            )
            return result
        if entry.capture != "provider_call":
            # A locally-authored body replayed under a provider and model would assert that
            # this model produced this text. It did not. The honest record is the one that
            # describes what actually decided: a deterministic fixture, naming nobody.
            return CompletionResult(
                raw_json=entry.raw_json,
                invocation=ModelInvocationRecord(invocation_kind="fixture_no_call"),
            )
        # A replay contacted no provider, so it claims no usage or cost -- but it is a real
        # model's output, and recording it as fixture_no_call made it indistinguishable from a
        # deterministic fixture that never consulted a model at all.
        return CompletionResult(
            raw_json=entry.raw_json,
            invocation=ModelInvocationRecord(
                invocation_kind="cache_replay",
                provider=self._provider,
                model=request.model,
            ),
        )
