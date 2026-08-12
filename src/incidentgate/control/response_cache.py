"""Deterministic replay of model outputs, keyed by (model_id, canonical prompt hash).

Current flagship models reject temperature/top_p (see the per-model capability table in
``model_proposal``), so bit-level determinism cannot come from sampling params - it comes from
replaying a committed output for an identical prompt. This
module is that store. In CI a cache hit returns a ``cache_replay`` invocation naming the provider
and model whose output is being replayed; no provider was contacted, so no usage or cost may be
claimed. ``record_mode`` is the only path that contacts a real client, and it is off by default so
the default and CI paths never touch the network.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from incidentgate.contracts import ModelInvocationRecord

from .model_proposal import CompletionClient, CompletionRequest, CompletionResult

_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class ResponseCacheMiss(Exception):
    """Explicit, typed miss so callers choose between recording and failing closed."""

    def __init__(self, model: str, prompt_sha256: str) -> None:
        self.model = model
        self.prompt_sha256 = prompt_sha256
        super().__init__(f"no cached completion for {model}:{prompt_sha256}")


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

    def load(self, model: str, prompt_sha256: str) -> str:
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
        raw_json: str = data["raw_json"]
        return raw_json

    def store(self, model: str, prompt_sha256: str, raw_json: str) -> None:
        path = self._path(model, prompt_sha256)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"model": model, "prompt_sha256": prompt_sha256, "raw_json": raw_json}
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
            raw_json = self._cache.load(request.model, request.prompt_sha256)
        except ResponseCacheMiss:
            if not self._record_mode or self._record_client is None:
                raise
            result = self._record_client.complete(request)
            self._cache.store(request.model, request.prompt_sha256, result.raw_json)
            return result
        # A replay contacted no provider, so it claims no usage or cost -- but it is a real
        # model's output, and recording it as fixture_no_call made it indistinguishable from a
        # deterministic fixture that never consulted a model at all.
        return CompletionResult(
            raw_json=raw_json,
            invocation=ModelInvocationRecord(
                invocation_kind="cache_replay",
                provider=self._provider,
                model=request.model,
            ),
        )
