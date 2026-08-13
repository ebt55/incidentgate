"""Tests for the deterministic response cache and strong-tier offline replay.

The committed fixture under ``tests/fixtures/model_cache`` lets an opus proposer (which cannot
use temperature) reproduce a bit-identical action with no network. Its filename is the cache
key, which is a hash over the canonical prompt *including the proposer schema fingerprint*, so
any change to the prompt, to the citation-label scheme, or to ``_ProposerOutput`` re-keys it. To
regenerate it, run ``record_committed_fixture()`` at the bottom of this module: it rewrites the
committed directory in place from a canned output and needs no network and no API key.

The synthetic evidence in this module carries readable ids (``ev-health`` and friends) purely so
the assertions read well. They are no longer part of the key: the prompt cites evidence by
positional label, so what this fixture is really keyed to is the D1 *shape* -- three records, in
collection order, with those payloads. A lab-collected D1 incident produces that same shape and
therefore this same key, which is what
``tests/integration/test_model_backed_incident.py`` relies on.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from incidentgate.contracts import (
    EvidenceRecord,
    IncidentIdentity,
    ModelInvocationRecord,
    Role,
    ToolCallContext,
    canonical_action_hash,
)
from incidentgate.control.model_proposal import (
    CompletionRequest,
    CompletionResult,
    ModelAgentProposer,
)
from incidentgate.control.models import Caller
from incidentgate.control.proposal import ProposalError
from incidentgate.control.response_cache import (
    CacheBackedCompletionClient,
    ResponseCache,
    ResponseCacheMiss,
)

HAIKU = "claude-haiku-4-5-20251001"
OPUS = "claude-opus-5"
COMMITTED_CACHE = Path(__file__).resolve().parent.parent / "fixtures" / "model_cache"
OBSERVED = datetime(2026, 1, 1, tzinfo=UTC)
EXPIRES = OBSERVED + timedelta(hours=1)
HASH_A = sha256(b"prompt-a").hexdigest()
HASH_B = sha256(b"prompt-b").hexdigest()


def incident() -> IncidentIdentity:
    return IncidentIdentity(
        incident_id="INC-d1", scenario_id="D1", thread_id="thread-1", correlation_id="corr-1"
    )


def caller() -> Caller:
    return Caller(actor="agent-1", role=Role.OPERATOR)


def context() -> ToolCallContext:
    return ToolCallContext(
        incident_id="INC-d1",
        thread_id="thread-1",
        correlation_id="corr-1",
        actor="agent-1",
        permission="operations:write",
    )


def _evidence(evidence_id: str, tool_name: str, payload: dict[str, Any]) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        incident_id="INC-d1",
        thread_id="thread-1",
        correlation_id="corr-1",
        tool_name=tool_name,
        actor="agent-1",
        permission="observability:read",
        observed_at=OBSERVED,
        expires_at=EXPIRES,
        payload=payload,
    )


def records() -> tuple[EvidenceRecord, ...]:
    """D1's real evidence shape: the lab's payloads, in the lab's collection order.

    These payloads are transcribed from what ``LabEvidenceCollector`` actually serves for
    D1, not invented, and the order is ``_kinds["D1"]``. That correspondence is what lets a
    genuinely collected incident compute this module's key and replay the committed fixture;
    it is not decoration. The ids are readable rather than ``uuid4()`` only because these
    assertions read better that way -- ids are no longer part of the key at all.

    Kept DB-free deliberately, so ``record_committed_fixture()`` still needs no network and
    no Postgres. The cost of transcribing is that it can drift from the lab, so the drift is
    made loud rather than trusted: ``test_the_committed_fixture_is_keyed_to_real_lab_evidence``
    in tests/integration/test_model_backed_incident.py fails the moment these stop matching.
    """
    return (
        _evidence(
            "ev-health",
            "observability.health",
            {"component": "api", "revision": "v2", "status": 500},
        ),
        _evidence(
            "ev-diff",
            "observability.deployment_diff",
            {"component": "api", "from_revision": "v1", "to_revision": "v2"},
        ),
        _evidence(
            "ev-logs",
            "observability.logs",
            {"level": "ERROR", "message": "api revision v2 returns 500"},
        ),
    )


def model_output() -> str:
    return json.dumps(
        {
            "hypothesis_id": "d1-bad-deploy",
            "diagnosis": "bad deployment v2 rollback to v1",
            "confidence": 0.9,
            "tool_name": "operations.rollback",
            "arguments": {"kind": "rollback", "component": "api", "target_revision": "v1"},
            # Citation labels in the order records() supplies them, which is the order the
            # D1 collector reads: health, deployment_diff, logs.
            "citations": ["e0", "e1", "e2"],
        }
    )


class FakeClient:
    def __init__(self, raw_json: str, *, invocation: ModelInvocationRecord | None = None) -> None:
        self.raw_json = raw_json
        self.invocation = invocation or ModelInvocationRecord(invocation_kind="fixture_no_call")
        self.calls = 0
        self.requests: list[CompletionRequest] = []

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.calls += 1
        self.requests.append(request)
        return CompletionResult(raw_json=self.raw_json, invocation=self.invocation)


def committed_fixture_key() -> str:
    """The cache key the opus proposer computes today for the fixed synthetic D1 inputs."""
    client = FakeClient(model_output())
    ModelAgentProposer(client=client, model=OPUS, temperature=None).propose(
        incident(), caller(), context(), records()
    )
    return client.requests[0].prompt_sha256


def _request(model: str, prompt_sha256: str) -> CompletionRequest:
    return CompletionRequest(
        model=model,
        system="system",
        user_content="user",
        max_tokens=512,
        temperature=None,
        thinking=None,
        schema={},
        canonical_prompt="canonical",
        prompt_sha256=prompt_sha256,
    )


def _provider_invocation() -> ModelInvocationRecord:
    return ModelInvocationRecord(
        provider="anthropic",
        model=HAIKU,
        invocation_kind="provider_call",
        usage_source="anthropic_messages_usage",
        input_tokens=10,
        output_tokens=5,
        cost=0.0001,
        currency="USD",
        pricing_snapshot="snap-test",
    )


def test_cache_round_trips_same_key(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    cache.store(HAIKU, HASH_A, model_output())
    assert cache.load(HAIKU, HASH_A) == model_output()
    # A different prompt hash is a miss; a different model is a miss.
    with pytest.raises(ResponseCacheMiss):
        cache.load(HAIKU, HASH_B)
    with pytest.raises(ResponseCacheMiss):
        cache.load(OPUS, HASH_A)


def test_cache_miss_is_explicit(tmp_path: Path) -> None:
    client = CacheBackedCompletionClient(ResponseCache(tmp_path))
    with pytest.raises(ResponseCacheMiss) as raised:
        client.complete(_request(HAIKU, HASH_A))
    assert raised.value.model == HAIKU
    assert raised.value.prompt_sha256 == HASH_A


def test_cache_hit_is_recorded_as_a_named_replay_not_a_fixture(tmp_path: Path) -> None:
    """A replay is a real model's output; it must not look like a deterministic fixture."""
    cache = ResponseCache(tmp_path)
    cache.store(HAIKU, HASH_A, model_output())
    result = CacheBackedCompletionClient(cache).complete(_request(HAIKU, HASH_A))
    assert result.raw_json == model_output()
    assert result.invocation.invocation_kind == "cache_replay"
    assert result.invocation.provider == "anthropic"
    assert result.invocation.model == HAIKU
    # No provider was contacted, so no usage or cost exists to record.
    assert result.invocation.cost is None
    assert result.invocation.input_tokens is None
    assert result.invocation.usage_source is None


def test_a_replay_names_the_provider_the_caller_declared(tmp_path: Path) -> None:
    """Captures from another provider must not be replayed under Anthropic's name."""
    cache = ResponseCache(tmp_path)
    cache.store(HAIKU, HASH_A, model_output())
    client = CacheBackedCompletionClient(cache, provider="some-other-provider")
    assert client.complete(_request(HAIKU, HASH_A)).invocation.provider == "some-other-provider"
    with pytest.raises(ValueError, match="must name the provider"):
        CacheBackedCompletionClient(cache, provider="")


def test_record_mode_populates_then_replays(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    upstream = FakeClient(model_output(), invocation=_provider_invocation())
    recorder = CacheBackedCompletionClient(cache, record_client=upstream, record_mode=True)
    request = _request(HAIKU, HASH_A)

    first = recorder.complete(request)
    assert upstream.calls == 1
    assert first.raw_json == model_output()
    assert first.invocation.invocation_kind == "provider_call"  # a live call really happened

    # A plain (non-recording) client now replays the stored output with no upstream call.
    replay = CacheBackedCompletionClient(cache)
    second = replay.complete(request)
    assert second.raw_json == model_output()
    assert second.invocation.invocation_kind == "cache_replay"
    assert second.invocation.model == HAIKU
    assert upstream.calls == 1


def test_record_mode_requires_client(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="record mode requires a record client"):
        CacheBackedCompletionClient(ResponseCache(tmp_path), record_mode=True)


def test_corrupt_and_unsafe_entries_are_rejected(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    path = tmp_path / HAIKU / f"{HASH_A}.json"
    path.parent.mkdir(parents=True)
    # Stored hash does not match the file's key -> integrity failure.
    path.write_text(json.dumps({"model": HAIKU, "prompt_sha256": HASH_B, "raw_json": "{}"}))
    with pytest.raises(ValueError, match="corrupt cache entry"):
        cache.load(HAIKU, HASH_A)
    with pytest.raises(ValueError, match="unsafe model id"):
        cache.load("../escape", HASH_A)
    with pytest.raises(ValueError, match="sha256"):
        cache.load(HAIKU, "not-a-hash")


def test_committed_fixture_key_matches_the_current_prompt_and_schema() -> None:
    """Name the exact failure a re-keyed cache causes, instead of an opaque fail-closed error.

    A cache miss surfaces downstream only as ``proposal_model_unavailable``, so without this
    check a schema change that silently invalidates the fixture is very hard to diagnose.

    What re-keys this fixture is now exactly three things: ``_ProposerOutput``'s schema, the
    prompt serialization, and the citation-label scheme. What does *not* re-key it is the
    thing that used to: the evidence ids and ``observed_at`` this module happens to use. The
    prompt cites by position, so any three records read in D1's collection order with these
    payloads compute this key -- including the ``uuid4()``-identified ones a real lab
    collection mints, which is why ``tests/integration/test_model_backed_incident.py`` can now
    drive this fixture from a genuinely collected incident.
    """
    committed = {path.stem for path in (COMMITTED_CACHE / OPUS).glob("*.json")}
    assert committed_fixture_key() in committed, (
        f"the committed opus fixture is keyed {sorted(committed)} but the proposer now computes "
        f"{committed_fixture_key()}; the prompt or proposer schema changed - regenerate with "
        "record_committed_fixture() from this module"
    )


def test_strong_model_replays_committed_fixture_deterministically() -> None:
    """Opus cannot use temperature; determinism comes from the committed cache, offline."""
    entries = list((COMMITTED_CACHE / OPUS).glob("*.json"))
    assert entries, (
        "committed opus cache fixture is missing; regenerate it by running "
        "record_committed_fixture() from this module"
    )
    proposer = ModelAgentProposer(
        client=CacheBackedCompletionClient(ResponseCache(COMMITTED_CACHE)),
        model=OPUS,
        temperature=None,
    )
    hypothesis, action = proposer.propose(incident(), caller(), context(), records())
    assert action.tool_name == "operations.rollback"
    assert action.evidence_ids == ("ev-diff", "ev-health", "ev-logs")
    assert action.permission == "operations:write"
    assert hypothesis.hypothesis_id == "d1-bad-deploy"
    assert proposer.last_invocation is not None
    assert proposer.last_invocation.invocation_kind == "cache_replay"
    assert proposer.last_invocation.model == OPUS

    # Replaying the same committed output must produce a bit-identical action semantic hash.
    again_hypothesis, again_action = proposer.propose(incident(), caller(), context(), records())
    assert canonical_action_hash(again_action) == canonical_action_hash(action)
    assert again_hypothesis == hypothesis


def test_committed_cache_miss_fails_closed_in_proposer() -> None:
    """A proposer whose cache lacks this prompt must fail closed, never fabricate an action."""
    # What makes this a miss is the *evidence*: one record with one payload, where the
    # committed key covers D1's three. Identity is what makes it not a miss -- the differing
    # incident, correlation and evidence ids below never reach the prompt, which is the
    # point of citing by position, so they cannot re-key anything.
    mismatched = IncidentIdentity(
        incident_id="INC-d1", scenario_id="D1", thread_id="thread-1", correlation_id="corr-XYZ"
    )
    ctx = ToolCallContext(
        incident_id="INC-d1",
        thread_id="thread-1",
        correlation_id="corr-XYZ",
        actor="agent-1",
        permission="operations:write",
    )
    other = _evidence("ev-health", "observability.health", {"component": "api", "status": 500})
    mismatched_records = (
        EvidenceRecord(
            evidence_id="ev-health",
            incident_id="INC-d1",
            thread_id="thread-1",
            correlation_id="corr-XYZ",
            tool_name="observability.health",
            actor="agent-1",
            permission="observability:read",
            observed_at=OBSERVED,
            expires_at=EXPIRES,
            payload=other.payload,
        ),
    )
    proposer = ModelAgentProposer(
        client=CacheBackedCompletionClient(ResponseCache(COMMITTED_CACHE)),
        model=OPUS,
        temperature=None,
    )
    with pytest.raises(ProposalError) as raised:
        proposer.propose(mismatched, caller(), ctx, mismatched_records)
    assert raised.value.reason == "proposal_model_unavailable"


def record_committed_fixture() -> Path:
    """Populate the committed opus cache fixture from a canned model output (no network).

    Run this whenever the prompt serialization or schema fingerprint changes so the committed
    fixture key matches what the opus proposer computes for the fixed synthetic D1 inputs.
    From the repository root::

        uv run --extra dev python -c "from tests.control.test_response_cache import \\
            record_committed_fixture as r; print(r())"

    The recorded body is the canned ``model_output()`` above, not a live completion, so this
    needs no API key and no network. Entries under stale keys are removed so the committed
    directory holds exactly the one key the proposer computes today; re-running it when the
    key has not moved is a no-op.
    """
    cache = ResponseCache(COMMITTED_CACHE)
    upstream = FakeClient(model_output(), invocation=_provider_invocation())
    proposer = ModelAgentProposer(
        client=CacheBackedCompletionClient(cache, record_client=upstream, record_mode=True),
        model=OPUS,
        temperature=None,
    )
    proposer.propose(incident(), caller(), context(), records())
    current = committed_fixture_key()
    for stale in (COMMITTED_CACHE / OPUS).glob("*.json"):
        if stale.stem != current:
            stale.unlink()
    return COMMITTED_CACHE / OPUS / f"{current}.json"
