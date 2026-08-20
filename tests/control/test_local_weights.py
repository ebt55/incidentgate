"""The local open-weight transport, exercised entirely against a fake server and store.

NO TEST HERE CONTACTS A SERVER OR READS A REAL MODEL. The Ollama blob store is
built in ``tmp_path`` from a few bytes, and the HTTP call is an injected
callable.

The load-bearing cases are the ones that make "local" mean something. A weights
hash the harness did not compute, an endpoint that is not loopback, or a server
answering as a different model than the one resolved would each turn this arm's
provenance back into a label -- which is the entire thing it exists to avoid.
"""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from incidentgate.control.local_weights import (
    DEFAULT_ENDPOINT,
    LOCAL_MODELS,
    OLLAMA_DEFAULT_SAMPLING,
    OLLAMA_TAGS,
    PROVIDER,
    LocalModelUnavailable,
    LocalWeightsError,
    OllamaWeightsCompletionClient,
    ServedModelMismatch,
    WeightsIdentityMismatch,
    effective_sampling,
    ollama_envelope_descriptor,
    resolve_ollama_weights,
)
from incidentgate.control.model_capabilities import (
    capability,
    is_known_model,
    reasoning_directive,
    sampling_directive,
    think_directive,
    thinking_directive,
)
from incidentgate.control.model_proposal import (
    CompletionRequest,
    anthropic_envelope_descriptor,
)
from incidentgate.control.openai_completion import openai_envelope_descriptor
from incidentgate.control.proposal import ProposalError

MODEL = "qwen3-14b"
TAG = "qwen3:14b"
NEMO = "mistral-nemo-12b"
#: What this lab sends on every local model, rather than inheriting.
SET = {"temperature": "1.0", "top_p": "1.0"}
WEIGHTS = b"not really 9GB of qwen3 weights, but hashed exactly the same way"


def build_store(tmp_path: Path, *, blob: bytes = WEIGHTS, declared: str | None = None) -> Path:
    """A minimal Ollama store: one manifest, one content-addressed blob."""
    root = tmp_path / "models"
    digest = declared or f"sha256:{sha256(blob).hexdigest()}"
    (root / "blobs").mkdir(parents=True)
    (root / "blobs" / digest.replace(":", "-")).write_bytes(blob)
    manifest_dir = root / "manifests" / "registry.ollama.ai" / "library" / "qwen3"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "14b").write_text(
        json.dumps({
            "layers": [
                {"mediaType": "application/vnd.ollama.image.template", "digest": "sha256:aa"},
                {"mediaType": "application/vnd.ollama.image.model", "digest": digest},
            ]
        }),
        encoding="utf-8",
    )
    return root


def body() -> str:
    return json.dumps({
        "hypothesis_id": "t1-checkout-outage",
        "diagnosis": "checkout outage",
        "confidence": 0.9,
        "citations": ["e0"],
        "tool_name": "operations.record_checkout_remediation",
        "arguments": {
            "kind": "record_checkout_remediation",
            "component": "checkout",
            "remediation_ref": "remediation://t1/checkout-restart",
        },
    })


def request() -> CompletionRequest:
    """Shaped exactly as ``ModelAgentProposer`` builds it for this model."""
    return CompletionRequest(
        model=MODEL,
        system="steering + base system prompt",
        user_content='{"evidence_digest":[]}',
        max_tokens=2048,
        temperature=None,
        thinking=None,
        reasoning=None,
        think=think_directive(MODEL),
        sampling=sampling_directive(MODEL),
        schema={"type": "object", "properties": {}},
        canonical_prompt="canonical",
        prompt_sha256="a" * 64,
    )


def response(
    *,
    content: str | None = None,
    done_reason: str = "stop",
    model: str = TAG,
    prompt_eval_count: int | None = 931,
    eval_count: int | None = 88,
    thinking: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    if error is not None:
        return {"error": error}
    message: dict[str, Any] = {"content": content}
    if thinking is not None:
        message["thinking"] = thinking
    payload: dict[str, Any] = {"model": model, "message": message, "done_reason": done_reason}
    if prompt_eval_count is not None:
        payload["prompt_eval_count"] = prompt_eval_count
    if eval_count is not None:
        payload["eval_count"] = eval_count
    return payload


class FakeServer:
    def __init__(self, reply: dict[str, Any]) -> None:
        self._reply = reply
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        self.calls.append((url, payload))
        return self._reply


def client_for(
    tmp_path: Path, reply: dict[str, Any]
) -> tuple[OllamaWeightsCompletionClient, FakeServer]:
    weights = resolve_ollama_weights(MODEL, store_root=build_store(tmp_path))
    server = FakeServer(reply)
    return OllamaWeightsCompletionClient(weights=weights, post_json=server), server


# ---------------------------------------------------------------------------
# The weights identity: computed here, never accepted as a claim
# ---------------------------------------------------------------------------


def test_the_harness_computes_the_hash_rather_than_being_told_it(tmp_path: Path) -> None:
    """The provenance anchor. A hash supplied by a caller would prove nothing."""
    weights = resolve_ollama_weights(MODEL, store_root=build_store(tmp_path))
    assert weights.weights_sha256 == sha256(WEIGHTS).hexdigest()
    assert weights.declared_digest == f"sha256:{weights.weights_sha256}"
    assert weights.server_model == TAG
    assert weights.harness_model == MODEL
    assert weights.size_bytes == len(WEIGHTS)
    assert weights.weights_path.read_bytes() == WEIGHTS
    recorded = weights.provenance()
    assert recorded["weights_sha256"] == weights.weights_sha256
    assert recorded["hash_verified_by"] == "incidentgate"


def test_a_blob_that_does_not_match_its_declared_digest_is_refused(tmp_path: Path) -> None:
    """The cross-check against the store's own manifest, which catches a swapped blob.

    Without it the harness would faithfully hash and record whatever bytes were
    sitting at that path, which is a fact about a file but not about the model
    the tag names.
    """
    root = build_store(tmp_path, declared="sha256:" + "0" * 64)
    with pytest.raises(WeightsIdentityMismatch, match="refusing to record a run"):
        resolve_ollama_weights(MODEL, store_root=root)


def test_a_missing_model_is_unavailable_rather_than_an_error_about_the_model(
    tmp_path: Path,
) -> None:
    """Not pulled yet is an environment fact, and must not read as a model failure."""
    with pytest.raises(LocalModelUnavailable, match="pull the model first"):
        resolve_ollama_weights(MODEL, store_root=tmp_path / "empty")
    root = build_store(tmp_path)
    next((root / "blobs").iterdir()).unlink()
    with pytest.raises(LocalModelUnavailable, match="missing from the Ollama store"):
        resolve_ollama_weights(MODEL, store_root=root)


def test_an_unmapped_model_is_refused_before_anything_is_hashed(tmp_path: Path) -> None:
    with pytest.raises(LocalWeightsError, match="is not in LOCAL_MODELS"):
        resolve_ollama_weights("some-model-nobody-mapped", store_root=build_store(tmp_path))


def test_the_tag_mapping_is_explicit_because_the_two_ids_cannot_be_the_same() -> None:
    """An Ollama tag contains a colon; a cache path and attacker_source do not."""
    assert OLLAMA_TAGS[MODEL] == TAG
    assert OLLAMA_TAGS[NEMO] == "mistral-nemo:12b"
    for harness_id, tag in OLLAMA_TAGS.items():
        assert ":" in tag and ":" not in harness_id


def test_every_local_model_is_in_the_capability_table() -> None:
    """A model the transport can resolve but the table cannot describe would run guessed."""
    for harness_id in LOCAL_MODELS:
        assert is_known_model(harness_id), f"{harness_id} has no capability row"


# ---------------------------------------------------------------------------
# Loopback: what stops "local" from being a label on an arbitrary URL
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://api.openai.com",
        "http://192.168.1.10:11434",
        "http://example.com:11434",
        "http://0.0.0.0:11434",
    ],
)
def test_a_non_loopback_endpoint_is_refused_outright(tmp_path: Path, endpoint: str) -> None:
    """THE check that makes a local claim mean something, and it has no override.

    Without it this is a general HTTP client wearing a provenance label: a real
    weights file could be hashed on disk while the answers came from a vendor
    across the network, and every recorded field would still look right.
    """
    weights = resolve_ollama_weights(MODEL, store_root=build_store(tmp_path))
    with pytest.raises(LocalWeightsError, match="must talk to loopback"):
        OllamaWeightsCompletionClient(weights=weights, endpoint=endpoint)


@pytest.mark.parametrize(
    "endpoint",
    ["http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434"],
)
def test_loopback_endpoints_are_accepted(tmp_path: Path, endpoint: str) -> None:
    weights = resolve_ollama_weights(MODEL, store_root=build_store(tmp_path))
    assert OllamaWeightsCompletionClient(weights=weights, endpoint=endpoint) is not None


def test_the_client_takes_no_api_key_at_all(tmp_path: Path) -> None:
    """Structural, and the property the spend-gate relaxation rests on.

    A transport with no credential parameter cannot authenticate to a paid API,
    whatever URL it is pointed at -- and it can only be pointed at loopback.
    """
    import inspect

    parameters = inspect.signature(OllamaWeightsCompletionClient.__init__).parameters
    assert "api_key" not in parameters
    assert "base_url" not in parameters
    weights = resolve_ollama_weights(MODEL, store_root=build_store(tmp_path))
    rendered = repr(OllamaWeightsCompletionClient(weights=weights))
    assert weights.weights_sha256[:12] in rendered


def test_the_default_endpoint_is_loopback() -> None:
    assert DEFAULT_ENDPOINT.startswith("http://127.0.0.1")


# ---------------------------------------------------------------------------
# The request: constrained decoding, reasoning off, sampling explicit
# ---------------------------------------------------------------------------


def test_the_request_constrains_decoding_and_switches_thinking_off(tmp_path: Path) -> None:
    client, server = client_for(tmp_path, response(content=body()))
    client.complete(request())
    url, payload = server.calls[0]
    assert url.endswith("/api/chat")
    assert payload["model"] == TAG
    assert payload["messages"][0] == {"role": "system", "content": "steering + base system prompt"}
    assert payload["messages"][1] == {"role": "user", "content": '{"evidence_digest":[]}'}
    # Constrained decoding, enforced by the sampler rather than requested.
    assert payload["format"] == request().schema
    assert payload["stream"] is False
    assert payload["options"]["num_predict"] == 2048
    # Reasoning off through the API parameter, not a `/no_think` prompt token --
    # a prompt token would change the bytes three arms hold identical.
    assert payload["think"] is False
    assert "/no_think" not in payload["messages"][0]["content"]
    assert "/no_think" not in payload["messages"][1]["content"]


def test_sampling_is_sent_explicitly_rather_than_inherited_from_the_modelfile(
    tmp_path: Path,
) -> None:
    """The third default confound.

    The modelfile bakes temperature 0.6. The Anthropic arm's documented default
    is 1.0. Sending nothing here would have run this arm at 0.6 while every
    envelope truthfully said "none_sent" -- true, and misleading in the one
    direction that matters.
    """
    assert LOCAL_MODELS[MODEL].modelfile_sampling["temperature"] == "0.6"
    client, server = client_for(tmp_path, response(content=body()))
    client.complete(request())
    options = server.calls[0][1]["options"]
    assert options["temperature"] == 1.0
    assert options["top_p"] == 1.0
    # Numbers on the wire, strings in the directive that travels through the
    # canonical prompt and the envelope.
    assert isinstance(options["temperature"], float)


def test_this_model_is_never_run_at_its_baked_in_defaults() -> None:
    assert is_known_model(MODEL)
    assert capability(MODEL).accepts_sampling is True
    assert capability(MODEL).thinking == "send_think_false"
    assert think_directive(MODEL) is False
    assert sampling_directive(MODEL) == {"temperature": "1.0", "top_p": "1.0"}
    # The other arms' accessors must not answer for this model, and vice versa.
    assert thinking_directive(MODEL) is None
    assert reasoning_directive(MODEL) is None
    assert think_directive("claude-opus-5") is None
    assert sampling_directive("gpt-5.5") is None


@pytest.mark.parametrize(
    "directive", [{"thinking": {"type": "disabled"}}, {"reasoning": {"effort": "none"}}]
)
def test_another_arms_reasoning_directive_fails_closed(
    tmp_path: Path, directive: dict[str, Any]
) -> None:
    """Ollama would ignore an unknown key and answer at its own default."""
    client, server = client_for(tmp_path, response(content=body()))
    with pytest.raises(ValueError, match="capability table entry for this model is wrong"):
        client.complete(replace(request(), **directive))
    assert server.calls == []


# ---------------------------------------------------------------------------
# The response: a real call that charged nobody
# ---------------------------------------------------------------------------


def test_a_complete_response_is_a_local_weights_call_with_usage_and_no_cost(
    tmp_path: Path,
) -> None:
    """The invocation kind that did not exist before this arm.

    Not ``provider_call``: that requires a named pricing snapshot, and inventing
    a zero-cost one would fabricate a price list for something with no price.
    Not ``fixture_no_call``: a model really ran, and claiming otherwise would be
    false in the direction that flatters us.
    """
    client, _ = client_for(tmp_path, response(content=body()))
    invocation = client.complete(request()).invocation
    assert invocation.invocation_kind == "local_weights_call"
    assert (invocation.provider, invocation.model) == (PROVIDER, MODEL)
    assert invocation.usage_source == "ollama_chat_usage"
    assert (invocation.input_tokens, invocation.output_tokens) == (931, 88)
    # cost null because no vendor exists to charge -- distinguishable from a
    # priced-at-zero call, which would carry a currency and a snapshot.
    assert invocation.cost is None
    assert invocation.currency is None
    assert invocation.pricing_snapshot is None


def test_a_server_answering_as_a_different_model_is_refused(tmp_path: Path) -> None:
    """A local server serves whatever it has loaded and owes the caller nothing.

    Silently measuring one model while the artifact names another is the exact
    failure this arm is supposed to be immune to, so the body is never parsed.
    """
    client, _ = client_for(tmp_path, response(content=body(), model="llama3:8b"))
    with pytest.raises(ServedModelMismatch, match="refusing to record output"):
        client.complete(request())


def test_a_model_that_cannot_load_is_an_environment_failure_not_a_decline(
    tmp_path: Path,
) -> None:
    """VRAM, most likely. A model that will not load has not chosen anything.

    The message must not read as a model outcome: the runner maps this to a
    transport failure, and the words that would let it be published as a decline
    must not appear.
    """
    client, _ = client_for(
        tmp_path,
        response(error="model requires more system memory (9.0 GiB) than is available (2.1 GiB)"),
    )
    with pytest.raises(LocalModelUnavailable) as raised:
        client.complete(request())
    rendered = str(raised.value)
    assert "more system memory" in rendered
    assert "declined" not in rendered and "not_produced" not in rendered
    assert not isinstance(raised.value, ProposalError)


def test_a_truncated_body_is_named_distinctly(tmp_path: Path) -> None:
    client, _ = client_for(tmp_path, response(content=body(), done_reason="length"))
    with pytest.raises(ProposalError) as error:
        client.complete(request())
    assert error.value.reason == "proposal_model_output_truncated"


def test_reasoning_content_despite_think_false_fails_closed(tmp_path: Path) -> None:
    """If the switch did not take, this run is not comparable and must not publish."""
    client, _ = client_for(
        tmp_path, response(content=body(), thinking="let me think about this...")
    )
    with pytest.raises(ValueError, match="not comparable"):
        client.complete(request())


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"content": body(), "done_reason": "tool_calls"}, "incomplete response"),
        ({"content": None}, "non-text response"),
        ({"content": body(), "prompt_eval_count": None}, "missing ollama usage"),
        ({"content": body(), "eval_count": None}, "missing ollama usage"),
    ],
)
def test_unexpected_response_shapes_fail_closed(
    tmp_path: Path, kwargs: dict[str, Any], match: str
) -> None:
    client, _ = client_for(tmp_path, response(**kwargs))
    with pytest.raises(ValueError, match=match):
        client.complete(request())


def test_construction_refuses_an_unsafe_timeout(tmp_path: Path) -> None:
    weights = resolve_ollama_weights(MODEL, store_root=build_store(tmp_path))
    for timeout in (0, 3601):
        with pytest.raises(ValueError, match="timeout must be within"):
            OllamaWeightsCompletionClient(weights=weights, timeout_seconds=timeout)


# ---------------------------------------------------------------------------
# The published envelope: three arms, comparable keys, honest sampling
# ---------------------------------------------------------------------------


def test_all_three_arms_describe_the_same_facts() -> None:
    """A key one arm states and another omits is a fact left to inference."""
    local = ollama_envelope_descriptor(False, SET, MODEL)
    openai = openai_envelope_descriptor({"effort": "none"})
    anthropic = anthropic_envelope_descriptor({"type": "disabled"})
    assert set(local) == set(openai) == set(anthropic)
    assert local["provider"] == PROVIDER
    assert local["reasoning_control"] == "think=false"
    assert "not_identical" in local["reasoning_equivalence"]
    # No vendor classifier sits between this caller and the weights, which is why
    # this arm can reach prompts the hosted arms cannot.
    assert local["refusal_surface"] == "none:no_provider_policy_layer"


def test_the_envelope_shows_effective_sampling_and_where_each_value_came_from() -> None:
    """``none_sent`` was true on every arm and meant something different on each.

    That made it read as equivalence, which is worse than useless. What replaces
    it is the effective value plus, per parameter, who decided it -- so a reader
    can tell a value we set from one that was applied to us.
    """
    local = ollama_envelope_descriptor(False, SET, MODEL)
    openai = openai_envelope_descriptor({"effort": "none"})
    anthropic = anthropic_envelope_descriptor({"type": "disabled"})

    assert anthropic["sampling"] == "temperature=1.0"
    assert anthropic["sampling_provenance"] == "provider_default_documented"
    # Not assumed to match the other arm just because that would look tidier.
    assert openai["sampling"] == "unknown"
    assert openai["sampling_provenance"] == "provider_default_undocumented"
    # Explicit where we set it, modelfile where qwen3 declared it.
    assert "temperature=1.0" in local["sampling"] and "top_p=1.0" in local["sampling"]
    assert "top_k=20" in local["sampling"] and "repeat_penalty=1" in local["sampling"]
    assert "explicit:temperature,top_p" in local["sampling_provenance"]
    assert "modelfile:repeat_penalty,top_k" in local["sampling_provenance"]
    # No arm claims a value it did not establish.
    assert "none_sent" not in json.dumps([local, openai, anthropic])


def test_omission_is_never_neutral_and_differs_between_the_two_local_models() -> None:
    """The finding that forced the descriptor to name a source per parameter.

    There is no configuration on this provider where sending nothing leaves
    sampling unset. Something always applies, and what applies is not even the
    same between two models on the same server: qwen3:14b would fall to its
    modelfile's 0.6, and mistral-nemo:12b -- whose modelfile declares only stop
    tokens -- to Ollama's documented 0.8.
    """
    assert LOCAL_MODELS[NEMO].modelfile_sampling == {}
    assert OLLAMA_DEFAULT_SAMPLING["temperature"] == "0.8"
    assert LOCAL_MODELS[MODEL].modelfile_sampling["temperature"] == "0.6"

    qwen_unset = effective_sampling(MODEL, None)
    nemo_unset = effective_sampling(NEMO, None)
    assert qwen_unset["temperature"] == ("0.6", "modelfile")
    assert nemo_unset["temperature"] == ("0.8", "ollama_default")
    # Two models, one server, two different temperatures from the same silence.
    assert qwen_unset["temperature"][0] != nemo_unset["temperature"][0]

    # Set explicitly, both land on the same value from the same source, and the
    # parameters nobody set still declare where they came from.
    for model in (MODEL, NEMO):
        resolved = effective_sampling(model, SET)
        assert resolved["temperature"] == ("1.0", "explicit")
        assert resolved["top_p"] == ("1.0", "explicit")
        assert resolved["top_k"][1] in ("modelfile", "ollama_default")
    assert effective_sampling(NEMO, SET)["top_k"] == ("40", "ollama_default")
    assert effective_sampling(MODEL, SET)["top_k"] == ("20", "modelfile")


def test_the_two_local_models_are_recorded_as_different_and_not_equated() -> None:
    """Different lineage, different quantisation. A shared arm is not a shared model."""
    assert LOCAL_MODELS[MODEL].quantisation == "Q4_K_M"
    assert LOCAL_MODELS[NEMO].quantisation == "Q4_0"
    assert LOCAL_MODELS[MODEL].quantisation != LOCAL_MODELS[NEMO].quantisation
    # Only one of them has a reasoning mode to switch off.
    assert think_directive(MODEL) is False
    assert think_directive(NEMO) is None
    assert capability(NEMO).thinking == "omit_is_off"
    # ...and both are still held to explicit sampling.
    assert sampling_directive(NEMO) == {"temperature": "1.0", "top_p": "1.0"}
