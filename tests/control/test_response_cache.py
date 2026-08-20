"""Tests for the deterministic response cache and strong-tier offline replay.

The committed fixture under ``tests/fixtures/model_cache`` lets an opus proposer (which cannot
use temperature) reproduce a bit-identical action with no network. Its filename is the cache
key, which is a hash over the canonical prompt *including the proposer schema fingerprint*, so
any change to the prompt, to the citation-label scheme, or to ``_ProposerOutput`` re-keys it. To
regenerate it, run ``record_committed_fixture()`` at the bottom of this module: it rewrites the
committed directory in place from a canned output and needs no network and no API key.

WHAT THE COMMITTED FIXTURE IS, STATED PLAINLY. Its body is ``model_output()`` below -- text
written in this file by a developer. No Anthropic model has ever produced it, and none was ever
contacted to obtain it. The entry therefore records ``capture="synthetic"`` and replays as
``fixture_no_call``: it exercises the whole replay mechanism, and it makes no claim whatsoever
about what a model would say. This was not visible before, because a cache entry recorded only
``{model, prompt_sha256, raw_json}``, so a canned body and a real capture were byte-identical
and the model *directory name* was the only thing attributing the output to anyone. That
attribution was demonstrably not evidence: this same body sat under ``claude-opus-4-8`` until a
commit renamed the folder to ``claude-opus-5``. Provenance is a recorded field now, derived from
what the recording client actually did, so no future canned body can be published as a model's.

The synthetic evidence in this module carries readable ids (``ev-health`` and friends) purely so
the assertions read well. They are no longer part of the key: the prompt cites evidence by
positional label, so what this fixture is really keyed to is the D1 *shape* -- three records, in
collection order, with those payloads. A lab-collected D1 incident produces that same shape and
therefore this same key, which is what
``tests/integration/test_model_backed_incident.py`` relies on.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from incidentgate.contracts import (
    EvaluationMode,
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
from incidentgate.control.pricing import load_pricing_snapshot
from incidentgate.control.proposal import ProposalError
from incidentgate.control.response_cache import (
    CacheBackedCompletionClient,
    ProviderCaptureProvenance,
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
    return _committed_fixture_request().prompt_sha256


def _committed_fixture_request() -> CompletionRequest:
    """Build the public D1 request used to key the synthetic replay fixture."""
    client = FakeClient(model_output())
    ModelAgentProposer(client=client, model=OPUS, temperature=None).propose(
        incident(), caller(), context(), records()
    )
    return client.requests[0]


def _request(model: str, prompt_sha256: str) -> CompletionRequest:
    canonical = "prompt-a" if prompt_sha256 == HASH_A else "prompt-b"
    return CompletionRequest(
        model=model,
        system="system",
        user_content="user",
        max_tokens=512,
        temperature=None,
        thinking=None,
        schema={"type": "object"},
        canonical_prompt=canonical,
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


def _provenance(request: CompletionRequest, result: CompletionResult) -> ProviderCaptureProvenance:
    invocation = result.invocation
    return ProviderCaptureProvenance(
        provider="anthropic",
        model=request.model,
        role="proposer",
        prompt_sha256=request.prompt_sha256,
        request_schema_sha256=sha256(
            json.dumps(request.schema, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        input_schema_version="proposal-input-v1",
        prompt_version="proposal/v1",
        stop_reason="end_turn",
        input_tokens=invocation.input_tokens or 0,
        output_tokens=invocation.output_tokens or 0,
        usage_source=invocation.usage_source or "anthropic_messages_usage",
        capture_mode="live_provider_call",
        captured_at=OBSERVED,
        # A real capture entry point. The previous value named
        # ``incidentgate.evaluation.capture_model_outputs``, deleted in a33b711;
        # nothing failed because the field is an opaque provenance string that no
        # test resolves, which is exactly why a stale one could sit here
        # unnoticed. The command below is the one that actually records a
        # proposer capture today.
        capture_command="python -m incidentgate.evaluation.sabotage_v3_t1 --capture",
        git_revision="a" * 40,
        pricing_snapshot_id=invocation.pricing_snapshot or "snap-test",
        estimated_cost=invocation.cost,
        currency=invocation.currency,
        cost_unavailable_reason=None,
        scenario_id="D1",
        variant_id="v1",
        condition=EvaluationMode.COMPLETE,
        leg="incident",
        step_index=0,
        split="development",
    )


def _store_provider(cache: ResponseCache, model: str, prompt_sha256: str) -> None:
    request = _request(model, prompt_sha256)
    invocation = _provider_invocation().model_copy(update={"model": model})
    result = CompletionResult(model_output(), invocation)
    cache.store(
        model,
        prompt_sha256,
        model_output(),
        capture="provider_call",
        provenance=_provenance(request, result),
        invocation=result.invocation,
        request=request,
    )


def test_cache_round_trips_same_key(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    _store_provider(cache, HAIKU, HASH_A)
    entry = cache.load(HAIKU, HASH_A)
    assert entry.raw_json == model_output()
    assert entry.capture == "provider_call"
    # A different prompt hash is a miss; a different model is a miss.
    with pytest.raises(ResponseCacheMiss):
        cache.load(HAIKU, HASH_B)
    with pytest.raises(ResponseCacheMiss):
        cache.load(OPUS, HASH_A)


def test_an_entry_must_record_how_it_was_captured(tmp_path: Path) -> None:
    """Provenance is required, never defaulted, and never inferred from the model directory."""
    cache = ResponseCache(tmp_path)
    with pytest.raises(ValueError, match="capture must be one of"):
        cache.store(HAIKU, HASH_A, model_output(), capture="invented")  # type: ignore[arg-type]

    # The pre-provenance shape: a body with no statement of where it came from. It is rejected
    # rather than assumed, because assuming is the defect. Written by hand precisely because
    # store() can no longer produce it.
    path = tmp_path / HAIKU / f"{HASH_A}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"model": HAIKU, "prompt_sha256": HASH_A, "raw_json": model_output()}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="does not record how it was captured"):
        cache.load(HAIKU, HASH_A)


def test_a_synthetic_entry_replays_as_a_fixture_and_names_nobody(tmp_path: Path) -> None:
    """The claim this whole field exists to prevent: a hand-written body sold as a model's.

    A locally-authored body is a deterministic fixture no matter which model directory it
    happens to sit in, so it must replay making no provider or model claim at all.
    """
    cache = ResponseCache(tmp_path)
    cache.store(OPUS, HASH_A, model_output(), capture="synthetic")
    result = CacheBackedCompletionClient(cache).complete(_request(OPUS, HASH_A))
    assert result.raw_json == model_output()
    assert result.invocation.invocation_kind == "fixture_no_call"
    assert result.invocation.provider is None
    assert result.invocation.model is None

    # And the same bytes under a capture that really happened do name their model. The only
    # difference between these two replays is the recorded provenance, which is the point.
    _store_provider(cache, OPUS, HASH_B)
    replayed = CacheBackedCompletionClient(cache).complete(_request(OPUS, HASH_B))
    assert replayed.invocation.invocation_kind == "cache_replay"
    assert replayed.invocation.model == OPUS


def test_cache_miss_is_explicit(tmp_path: Path) -> None:
    client = CacheBackedCompletionClient(ResponseCache(tmp_path))
    with pytest.raises(ResponseCacheMiss) as raised:
        client.complete(_request(HAIKU, HASH_A))
    assert raised.value.model == HAIKU
    assert raised.value.prompt_sha256 == HASH_A


def test_cache_hit_is_recorded_as_a_named_replay_not_a_fixture(tmp_path: Path) -> None:
    """A replay is a real model's output; it must not look like a deterministic fixture."""
    cache = ResponseCache(tmp_path)
    _store_provider(cache, HAIKU, HASH_A)
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
    _store_provider(cache, HAIKU, HASH_A)
    assert (
        CacheBackedCompletionClient(cache).complete(_request(HAIKU, HASH_A)).invocation.provider
        == "anthropic"
    )
    with pytest.raises(ValueError, match="disagrees"):
        CacheBackedCompletionClient(cache, provider="some-other-provider").complete(
            _request(HAIKU, HASH_A)
        )


def test_record_mode_populates_then_replays(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    upstream = FakeClient(model_output(), invocation=_provider_invocation())
    recorder = CacheBackedCompletionClient(
        cache, record_client=upstream, record_mode=True, provenance_builder=_provenance
    )
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
    # The provenance was derived from the upstream call, not asserted by this test.
    assert cache.load(HAIKU, HASH_A).capture == "provider_call"


def test_record_mode_cannot_launder_a_canned_body_into_a_capture(tmp_path: Path) -> None:
    """Recording from a client that never called a provider stores ``synthetic``, not a capture.

    This is the regression guard for how the committed fixture came to be attributed to a
    model: a recorder wired to a canned body, whose stored entry then looked exactly like a
    real capture to every consumer. The recorder cannot express that any more -- provenance
    follows what the record client actually did.
    """
    cache = ResponseCache(tmp_path)
    canned = FakeClient(model_output())  # a FakeClient defaults to fixture_no_call
    recorder = CacheBackedCompletionClient(
        cache, record_client=canned, record_mode=True, provenance_builder=_provenance
    )
    with pytest.raises(ValueError, match="refuses non-provider"):
        recorder.complete(_request(HAIKU, HASH_A))
    assert not (tmp_path / HAIKU / f"{HASH_A}.json").exists()


def test_record_mode_requires_client(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="record mode requires"):
        CacheBackedCompletionClient(ResponseCache(tmp_path), record_mode=True)


@pytest.mark.parametrize("mode", ["direct", "record"])
@pytest.mark.parametrize("mutation", ["canonical", "schema"])
def test_provider_capture_requires_coherent_request_digests(
    tmp_path: Path, mode: str, mutation: str
) -> None:
    cache = ResponseCache(tmp_path)
    request = _request(HAIKU, HASH_A)
    original_request = request
    if mutation == "canonical":
        request = replace(request, canonical_prompt="different")
    else:
        request = replace(request, schema={"type": "array"})
    invocation = _provider_invocation()
    result = CompletionResult(model_output(), invocation)
    original_provenance = _provenance(original_request, result)
    if mode == "direct":
        with pytest.raises(ValueError, match="(canonical prompt|schema) disagrees"):
            cache.store(
                HAIKU, HASH_A, result.raw_json, capture="provider_call",
                provenance=original_provenance, invocation=invocation, request=request,
            )
    else:
        recorder = CacheBackedCompletionClient(
            cache, record_client=FakeClient(result.raw_json, invocation=invocation),
            record_mode=True, provenance_builder=lambda _request, _result: original_provenance,
        )
        with pytest.raises(ValueError, match="(canonical prompt|schema) disagrees"):
            recorder.complete(request)
    assert not (tmp_path / HAIKU / f"{HASH_A}.json").exists()


def test_provider_cache_store_is_idempotent_but_refuses_conflicts(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    request = _request(HAIKU, HASH_A)
    invocation = _provider_invocation()
    provenance = _provenance(request, CompletionResult(model_output(), invocation))
    cache.store(HAIKU, HASH_A, model_output(), capture="provider_call",
                provenance=provenance, invocation=invocation, request=request)
    cache.store(HAIKU, HASH_A, model_output(), capture="provider_call",
                provenance=provenance, invocation=invocation, request=request)
    with pytest.raises(ValueError, match="semantically different"):
        cache.store(HAIKU, HASH_A, '{"different":true}', capture="provider_call",
                    provenance=provenance, invocation=invocation, request=request)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input_tokens", True), ("step_index", True), ("captured_at", "2026-01-01T00:00:00"),
        ("provider", "Anthropic"), ("prompt_sha256", "x"), ("git_revision", "x" * 40),
        ("estimated_cost", float("nan")), ("estimated_cost", float("inf")),
        ("estimated_cost", -1.0), ("currency", None),
        ("cost_unavailable_reason", "model_not_priced_in_snapshot"),
    ],
)
def test_provider_provenance_rejects_unsafe_or_incoherent_values(field: str, value: object) -> None:
    request = _request(HAIKU, HASH_A)
    invocation = _provider_invocation()
    base = _provenance(request, CompletionResult(model_output(), invocation)).model_dump()
    base[field] = value
    with pytest.raises((ValueError, TypeError)):
        ProviderCaptureProvenance.model_validate(base)


def test_provider_cache_rejects_malformed_provenance_and_oversized_body(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    path = tmp_path / HAIKU / f"{HASH_A}.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"capture": "provider_call", "model": HAIKU,
                                "prompt_sha256": HASH_A, "raw_json": "{}",
                                "provenance": {"provider": "anthropic"}}), encoding="utf-8")
    with pytest.raises(ValueError, match="malformed provider cache provenance"):
        cache.load(HAIKU, HASH_A)
    path.write_bytes(b"{" + b'"x":' + b'"' + b"a" * 1_100_000 + b'"}')
    with pytest.raises(ValueError, match="cache entry exceeds size limit"):
        cache.load(HAIKU, HASH_A)


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


def test_a_capture_can_record_the_api_envelope_its_request_was_carried_in(
    tmp_path: Path,
) -> None:
    """Two providers can be sent identical content; they cannot be sent identical requests.

    So the envelope travels with the bytes. Without it, "both models saw the
    same prompt" is a claim a reader has to take on trust, and the small true
    differences -- system channel, budget field name, whether reasoning shares
    the output budget -- are exactly the ones that get absorbed into that
    sentence.
    """
    cache = ResponseCache(tmp_path)
    request = _request(HAIKU, HASH_A)
    invocation = _provider_invocation()
    result = CompletionResult(model_output(), invocation)
    envelope = '{"output_budget_field":"max_tokens","provider":"anthropic"}'
    provenance = _provenance(request, result).model_copy(
        update={"request_envelope": envelope}
    )
    cache.store(HAIKU, HASH_A, model_output(), capture="provider_call",
                provenance=provenance, invocation=invocation, request=request)
    reloaded = cache.load(HAIKU, HASH_A)
    assert reloaded.provenance is not None
    assert reloaded.provenance.request_envelope == envelope


def test_a_capture_taken_before_the_envelope_field_existed_still_loads() -> None:
    """``None`` means "not recorded", and must never be read as "no difference".

    The committed claude-opus-5 capture predates the field. Back-filling an
    envelope for it would be asserting provenance for a request nobody observed,
    so the field is optional and that capture keeps validating without one --
    which is also what stops this change from silently invalidating the only
    real capture this project holds.
    """
    captures = Path(__file__).resolve().parents[2] / "artifacts" / "model-captures" / OPUS
    entries = list(captures.glob("*.json"))
    assert entries, "the committed opus capture is missing"
    for entry in entries:
        data = json.loads(entry.read_text(encoding="utf-8"))
        assert "request_envelope" not in data["provenance"]
        provenance = ProviderCaptureProvenance.model_validate(data["provenance"])
        assert provenance.request_envelope is None


def test_the_committed_openai_captures_record_reasoning_explicitly_off() -> None:
    """The published cross-model result must stay checkable as an unconfounded one.

    ``gpt-5.5`` reasons at ``medium`` when no effort is sent, so a capture whose
    envelope said ``omitted`` would be a measurement of a reasoning model against
    an arm that had reasoning disabled -- published as like-for-like. That
    property is only worth anything if it is pinned to the committed bytes, so
    this reads the artifacts rather than the code that wrote them.

    Costs are re-derived from the committed snapshot rather than trusted, because
    a cost that drifted from its own usage figures is the shape of a fabricated
    number.
    """
    root = Path(__file__).resolve().parents[2]
    cache = ResponseCache(root / "artifacts" / "model-captures")
    snapshot = load_pricing_snapshot(root / "config" / "pricing" / "openai-2026-08-20.json")
    expected = {
        "a6e4577b6d50a25e0beb8374cbd36401bd840d3ad719cf9eaacd6873385ec8ce": ("T1-dev-v1", 102),
        "ef1b2e2b10b8a87c57df3b84115ae7a85e07cb95a4e8566b46c88772635eb936": ("T1-cal-v1", 101),
    }
    for prompt_sha256, (variant_id, output_tokens) in expected.items():
        entry = cache.load("gpt-5.5", prompt_sha256)
        assert entry.capture == "provider_call"
        provenance = entry.provenance
        assert provenance is not None
        assert (provenance.provider, provenance.variant_id) == ("openai", variant_id)
        assert provenance.stop_reason == "end_turn"
        assert (provenance.input_tokens, provenance.output_tokens) == (932, output_tokens)
        assert provenance.pricing_snapshot_id == snapshot.snapshot_id
        assert provenance.estimated_cost == pytest.approx(
            snapshot.cost("gpt-5.5", 932, output_tokens)
        )
        # THE property this test exists for.
        assert provenance.request_envelope is not None
        envelope = json.loads(provenance.request_envelope)
        assert envelope["reasoning_control"] == "reasoning_effort=none"
        assert "not_identical" in envelope["reasoning_equivalence"]


@pytest.mark.parametrize(
    "envelope",
    [
        "not json at all",
        "[]",
        "{}",
        '{"provider":null}',
        '{"provider":1}',
        '{"":"anthropic"}',
        '{"provider":""}',
        '"a string, not an object"',
    ],
)
def test_a_recorded_envelope_must_be_a_flat_object_of_non_empty_strings(envelope: str) -> None:
    """Provenance that a reader cannot parse is provenance that records nothing."""
    request = _request(HAIKU, HASH_A)
    base = _provenance(
        request, CompletionResult(model_output(), _provider_invocation())
    ).model_dump()
    base["request_envelope"] = envelope
    with pytest.raises((ValueError, TypeError)):
        ProviderCaptureProvenance.model_validate(base)


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
    request = _committed_fixture_request()
    canonical = json.loads(request.canonical_prompt)
    contract = ModelAgentProposer(
        client=FakeClient(model_output()), model=OPUS, temperature=None
    ).prompt_contract
    committed = {path.stem for path in (COMMITTED_CACHE / OPUS).glob("*.json")}
    assert request.prompt_sha256 == sha256(request.canonical_prompt.encode()).hexdigest()
    assert canonical["schema_fingerprint"] == contract.output_schema_sha256
    assert sha256(
        json.dumps(request.schema, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest() == contract.provider_schema_sha256
    assert committed == {request.prompt_sha256}, (
        f"the committed opus fixture is keyed {sorted(committed)} but the proposer now computes "
        f"{request.prompt_sha256}; the prompt or proposer schema changed - regenerate with "
        "record_committed_fixture() from this module"
    )
    entry = ResponseCache(COMMITTED_CACHE).load(OPUS, request.prompt_sha256)
    assert entry.capture == "synthetic" and entry.provenance is None
    assert entry.raw_json == model_output()


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
    # The committed body is this module's own canned text, so the honest record names no
    # model. Asserting cache_replay here is what made the fixture read as a captured Opus
    # output in every consumer that trusted this test.
    assert proposer.last_invocation.invocation_kind == "fixture_no_call"
    assert proposer.last_invocation.model is None

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

    The recording client below deliberately returns a ``fixture_no_call`` invocation, so the
    stored entry records ``capture="synthetic"``. It previously returned a fabricated
    ``provider_call`` invocation, and that single line is what made a hand-written body
    indistinguishable from a captured one for every consumer downstream. Capturing a *real*
    fixture is a different procedure and must stay one: point ``record_client`` at a real
    ``AnthropicCompletionClient`` with a live key, which returns a genuine ``provider_call``
    and so stores ``capture="provider_call"`` without anyone asserting it.
    """
    cache = ResponseCache(COMMITTED_CACHE)
    upstream = FakeClient(model_output())
    # Clear before recording, not only after. Recording is a cache *miss* path, so an entry
    # already sitting under today's key is never rewritten -- and an entry written before
    # provenance existed does not even load, it raises, which reaches the proposer as an
    # opaque proposal_model_unavailable. Clearing first makes this genuinely idempotent and
    # lets it migrate an older entry rather than fail on one.
    for existing in (COMMITTED_CACHE / OPUS).glob("*.json"):
        existing.unlink()
    proposer = ModelAgentProposer(client=upstream, model=OPUS, temperature=None)
    proposer.propose(incident(), caller(), context(), records())
    current = committed_fixture_key()
    cache.store(OPUS, current, model_output(), capture="synthetic")
    for stale in (COMMITTED_CACHE / OPUS).glob("*.json"):
        if stale.stem != current:
            stale.unlink()
    return COMMITTED_CACHE / OPUS / f"{current}.json"
