"""The OpenAI transport, exercised entirely against fakes.

NO TEST HERE CONTACTS A PROVIDER. The client takes an injected `client` exactly
as its Anthropic sibling does, and every case below supplies a SimpleNamespace
shaped like a real response.

The load-bearing case is the refusal one. OpenAI surfaces a refusal in two
places -- a `refusal` field on the message, and a `content_filter` finish reason
-- and neither may become `declined`. That is the same category error the
Anthropic arm already made once, and a second provider is exactly where it would
be made again by someone reading `refusal` as a synonym for "the model said no".
"""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from incidentgate.control.model_capabilities import (
    capability,
    is_known_model,
    reasoning_directive,
    thinking_directive,
)
from incidentgate.control.model_proposal import (
    CompletionRequest,
    PricingSnapshot,
    ProviderPolicyRefusal,
    anthropic_envelope_descriptor,
)
from incidentgate.control.openai_completion import (
    PROVIDER,
    OpenAICompletionClient,
    openai_envelope_descriptor,
)
from incidentgate.control.proposal import ProposalError

#: The exact id returned by ``models.list()`` against this project's credential
#: on 2026-08-20, not a family prefix and not a guess.
MODEL = "gpt-5.5"


def pricing() -> PricingSnapshot:
    return PricingSnapshot(
        snapshot_id="openai-2026-08-20",
        currency="USD",
        input_usd_per_token={MODEL: 0.000005},
        output_usd_per_token={MODEL: 0.00003},
    )


def request() -> CompletionRequest:
    """Shaped exactly as ``ModelAgentProposer`` builds it for this model.

    ``reasoning`` is set, not omitted, because omission is what the capability
    table now exists to prevent: on gpt-5.5 sending nothing means ``medium``.
    """
    return CompletionRequest(
        model=MODEL,
        system="steering + base system prompt",
        user_content='{"evidence_digest":[]}',
        max_tokens=2048,
        temperature=None,
        thinking=None,
        reasoning={"effort": "none"},
        schema={"type": "object", "properties": {}},
        canonical_prompt="canonical",
        prompt_sha256="a" * 64,
    )


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


class FakeOpenAI:
    """Shaped like the SDK surface the client actually touches."""

    def __init__(self, response: Any) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self._response


def response(
    *,
    content: str | None = None,
    refusal: str | None = None,
    finish_reason: str = "stop",
    prompt_tokens: int | None = 2110,
    completion_tokens: int | None = 224,
    request_id: str | None = "req_test_0001",
) -> Any:
    message = SimpleNamespace(content=content, refusal=refusal)
    usage = (
        None
        if prompt_tokens is None
        else SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens)
    )
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason=finish_reason)],
        usage=usage,
        _request_id=request_id,
    )


def client_for(resp: Any) -> tuple[OpenAICompletionClient, FakeOpenAI]:
    fake = FakeOpenAI(resp)
    return OpenAICompletionClient(api_key="sk-not-used", pricing=pricing(), client=fake), fake


# ---------------------------------------------------------------------------
# The happy path and its provenance
# ---------------------------------------------------------------------------


def test_a_complete_response_becomes_an_honest_provider_call_record() -> None:
    client, _ = client_for(response(content=body()))
    result = client.complete(request())
    invocation = result.invocation
    assert result.raw_json == body()
    assert invocation.invocation_kind == "provider_call"
    assert (invocation.provider, invocation.model) == (PROVIDER, MODEL)
    assert invocation.usage_source == "openai_chat_completions_usage"
    assert (invocation.input_tokens, invocation.output_tokens) == (2110, 224)
    assert invocation.pricing_snapshot == "openai-2026-08-20"
    assert invocation.currency == "USD"
    assert invocation.cost == pytest.approx(2110 * 0.000005 + 224 * 0.00003)


def test_the_request_carries_the_prompt_bytes_unchanged_in_openais_envelope() -> None:
    """The content must be identical to Anthropic's; only the carrier differs."""
    client, fake = client_for(response(content=body()))
    client.complete(request())
    call = fake.calls[0]
    assert call["model"] == MODEL
    assert call["max_completion_tokens"] == 2048
    # System instructions travel as a developer message, byte-for-byte.
    assert call["messages"][0] == {
        "role": "developer", "content": "steering + base system prompt"
    }
    assert call["messages"][1] == {"role": "user", "content": '{"evidence_digest":[]}'}
    # Structured output, deliberately non-strict; local re-validation stays strict.
    assert call["response_format"]["type"] == "json_schema"
    assert call["response_format"]["json_schema"]["strict"] is False
    assert call["response_format"]["json_schema"]["schema"] == request().schema
    # No sampling parameter, matching the Anthropic arm.
    assert "temperature" not in call and "top_p" not in call
    # And no Anthropic-shaped fields leaked across.
    assert "max_tokens" not in call and "system" not in call and "thinking" not in call
    # Reasoning off, sent explicitly, in the flat Chat Completions spelling --
    # not the Responses API's nested `reasoning: {effort: ...}` object.
    assert call["reasoning_effort"] == "none"
    assert "reasoning" not in call


def test_the_envelope_difference_is_published_rather_than_absorbed() -> None:
    """A reader comparing two arms must be able to see what was not identical."""
    descriptor = openai_envelope_descriptor({"effort": "none"})
    assert descriptor["provider"] == PROVIDER
    assert descriptor["system_channel"] == "developer_role_message"
    assert descriptor["output_budget_field"] == "max_completion_tokens"
    assert descriptor["structured_output_strict"] == "false"
    assert descriptor["usage_fields"] == "prompt_tokens,completion_tokens"


def test_both_arms_describe_the_same_facts_so_the_two_can_be_compared() -> None:
    """A descriptor published by only one arm leaves the comparison one-sided.

    The keys must match exactly. A key present on one side and absent on the
    other is a fact one arm stated and the other left to inference, which is the
    condition this pair of descriptors exists to remove.
    """
    openai = openai_envelope_descriptor({"effort": "none"})
    anthropic = anthropic_envelope_descriptor({"type": "disabled"})
    assert set(openai) == set(anthropic)
    assert anthropic["provider"] == "anthropic"


def test_the_recorded_envelope_names_the_exact_reasoning_setting_that_was_sent() -> None:
    """The record must distinguish "off" from "whatever the provider does by default".

    Those are the two outcomes the confound turned on, and on this model they
    look identical in every other field of the request.
    """
    assert (
        openai_envelope_descriptor({"effort": "none"})["reasoning_control"]
        == "reasoning_effort=none"
    )
    assert (
        anthropic_envelope_descriptor({"type": "disabled"})["reasoning_control"]
        == "thinking.type=disabled"
    )
    # And an arm that sent nothing must say so, rather than inheriting the
    # reassuring wording of one that did.
    omitted = openai_envelope_descriptor()["reasoning_control"]
    assert omitted == "reasoning_effort:omitted:provider_default_applies"


def test_the_two_arms_are_recorded_as_analogous_and_never_as_identical() -> None:
    """The weaker claim is the true one, and it is the one that gets published.

    Both arms switch reasoning off explicitly, which rules out the specific
    confound of one running at a provider default. It does not establish that
    ``thinking: disabled`` and ``reasoning_effort: none`` leave two different
    models in comparable internal states, and nothing in this project has
    measured that. A descriptor claiming equivalence would be asserting it.
    """
    for descriptor in (
        openai_envelope_descriptor({"effort": "none"}),
        anthropic_envelope_descriptor({"type": "disabled"}),
    ):
        equivalence = descriptor["reasoning_equivalence"]
        assert equivalence == "explicitly_off:analogous_to_the_other_arm_not_identical"
        assert "identical" in equivalence and "not_identical" in equivalence
    # An arm that set nothing makes no analogy claim at all.
    assert openai_envelope_descriptor()["reasoning_equivalence"] == (
        "not_set:provider_default_applies"
    )


def test_this_model_is_never_run_at_the_providers_reasoning_default() -> None:
    """The confound this row was rewritten to remove, asserted at its source.

    gpt-5.5 defaults to ``medium``. Omitting the parameter would have measured a
    reasoning model against ``claude-opus-5`` with thinking disabled and
    published it as like-for-like -- and it would have done so through a call
    that succeeded, so nothing downstream could have caught it.
    """
    assert is_known_model(MODEL)
    assert capability(MODEL).thinking == "send_effort_none"
    assert reasoning_directive(MODEL) == {"effort": "none"}
    # The Anthropic accessor must not answer for this model, and vice versa.
    assert thinking_directive(MODEL) is None
    assert reasoning_directive("claude-opus-5") is None
    assert thinking_directive("claude-opus-5") == {"type": "disabled"}


def test_an_anthropic_thinking_directive_fails_closed_instead_of_being_dropped() -> None:
    """A parameter this endpoint does not have must not be silently discarded.

    The capability table sends this model to ``reasoning_directive``, so this
    cannot fire on a correct table. If it ever does, the table is wrong, and a
    caller that asked for thinking to be disabled has to learn that the request
    went out without it -- otherwise two arms get compared on a parameter that
    held on only one of them.
    """
    client, fake = client_for(response(content=body()))
    thinking_request = replace(request(), thinking={"type": "disabled"})
    with pytest.raises(ValueError, match="capability table entry for this model is wrong"):
        client.complete(thinking_request)
    assert fake.calls == [], "the request must not reach the provider"


@pytest.mark.parametrize(
    "reasoning",
    [{}, {"effort": ""}, {"type": "disabled"}, {"effort": "none", "extra": "x"}],
)
def test_a_malformed_reasoning_directive_fails_closed_rather_than_degrading(
    reasoning: dict[str, str],
) -> None:
    """An unreadable setting must not quietly become an omitted one.

    Omission is ``medium`` on this model, so "we could not parse the directive"
    and "reason at the default" would otherwise collapse into the same request --
    and the resulting call would succeed.
    """
    client, fake = client_for(response(content=body()))
    with pytest.raises(ValueError, match="must be exactly"):
        client.complete(replace(request(), reasoning=reasoning))
    assert fake.calls == []


# ---------------------------------------------------------------------------
# Refusals: the case that must never become `declined`
# ---------------------------------------------------------------------------


def test_a_message_refusal_is_a_policy_refusal_and_carries_its_reason() -> None:
    client, _ = client_for(
        response(content=None, refusal="I can't help with exfiltrating data.")
    )
    with pytest.raises(ProviderPolicyRefusal) as error:
        client.complete(request())
    refusal = error.value
    assert refusal.stop_reason == "refusal"
    assert refusal.category == "message_refusal"
    assert refusal.explanation == "I can't help with exfiltrating data."
    assert refusal.request_id == "req_test_0001"
    # Billed, and priced from the refusal's own usage.
    assert (refusal.input_tokens, refusal.output_tokens) == (2110, 224)
    assert refusal.cost == pytest.approx(2110 * 0.000005 + 224 * 0.00003)
    assert refusal.pricing_snapshot == "openai-2026-08-20"


def test_a_content_filter_finish_reason_is_a_policy_refusal_too() -> None:
    """The input-classifier shape: the model may never have produced anything."""
    client, _ = client_for(response(content=None, finish_reason="content_filter"))
    with pytest.raises(ProviderPolicyRefusal) as error:
        client.complete(request())
    assert error.value.stop_reason == "content_filter"
    assert error.value.category == "content_filter"


def test_a_refusal_is_not_a_proposal_error_and_so_cannot_read_as_a_decline() -> None:
    """The distinction the whole lane rests on, asserted at the type level.

    ``ProposalError`` is the fail-closed proposal vocabulary; a refusal that
    arrived as one would be indistinguishable downstream from the model
    producing nothing usable, which is how a provider decision becomes a model
    observation.
    """
    client, _ = client_for(response(content=None, refusal="no"))
    with pytest.raises(ProviderPolicyRefusal) as error:
        client.complete(request())
    assert not isinstance(error.value, ProposalError)
    assert not isinstance(error.value, ValueError)


def test_the_refusal_message_never_renders_the_prompt() -> None:
    client, _ = client_for(response(content=None, refusal="policy text"))
    with pytest.raises(ProviderPolicyRefusal) as error:
        client.complete(request())
    rendered = str(error.value)
    assert "evidence_digest" not in rendered
    assert "steering" not in rendered


# ---------------------------------------------------------------------------
# Fail-closed discipline, mirroring the Anthropic client
# ---------------------------------------------------------------------------


def test_a_truncated_body_is_named_distinctly_rather_than_hidden() -> None:
    client, _ = client_for(response(content=body(), finish_reason="length"))
    with pytest.raises(ProposalError) as error:
        client.complete(request())
    assert error.value.reason == "proposal_model_output_truncated"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"content": body(), "finish_reason": "tool_calls"}, "incomplete response"),
        ({"content": None, "finish_reason": "stop"}, "non-text response"),
        ({"content": body(), "prompt_tokens": None}, "missing provider usage"),
    ],
)
def test_unexpected_response_shapes_fail_closed(kwargs: dict[str, Any], match: str) -> None:
    client, _ = client_for(response(**kwargs))
    with pytest.raises(ValueError, match=match):
        client.complete(request())


def test_an_unexpected_finish_reason_names_itself() -> None:
    """Diagnosability: the Anthropic arm lost three days to an unnamed stop reason."""
    client, _ = client_for(response(content=body(), finish_reason="tool_calls"))
    with pytest.raises(ValueError, match="tool_calls"):
        client.complete(request())


def test_the_client_never_renders_its_api_key() -> None:
    client, _ = client_for(response(content=body()))
    assert "sk-not-used" not in repr(client)
    assert "OpenAICompletionClient" in repr(client)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"api_key": ""}, "requires an API key"),
        ({"timeout_seconds": 0}, "timeout must be within"),
        ({"timeout_seconds": 61}, "timeout must be within"),
    ],
)
def test_construction_refuses_unsafe_configuration(kwargs: dict[str, Any], match: str) -> None:
    base: dict[str, Any] = {"api_key": "sk-x", "pricing": pricing(), "client": FakeOpenAI(None)}
    with pytest.raises(ValueError, match=match):
        OpenAICompletionClient(**{**base, **kwargs})


def test_an_unpriced_model_keeps_its_usage_rather_than_dropping_it() -> None:
    """A gap in our price list must not lose real spend from the record."""
    empty = PricingSnapshot(
        snapshot_id="openai-2026-08-20", currency="USD",
        input_usd_per_token={}, output_usd_per_token={},
    )
    fake = FakeOpenAI(response(content=body()))
    client = OpenAICompletionClient(api_key="sk-x", pricing=empty, client=fake)
    invocation = client.complete(request()).invocation
    assert (invocation.input_tokens, invocation.output_tokens) == (2110, 224)
    assert invocation.cost is None and invocation.currency is None
