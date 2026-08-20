"""The OpenAI transport, mirroring the Anthropic one rather than generalising it.

WHY A SIBLING MODULE AND NOT A REFACTOR
=======================================

This implements the existing ``CompletionClient`` protocol -- one method,
``complete(CompletionRequest) -> CompletionResult`` -- and nothing about that
seam changes to accommodate it. The protocol fit without widening, which is the
result worth recording: a second provider arriving is the moment a shared
abstraction either proves itself or quietly grows a special case, and this one
proved itself.

The Anthropic client stays where it is. Two small mirrored transports are easier
to read, and easier to tell apart when one of them misbehaves, than one client
carrying a provider switch through every branch.

WHAT DIFFERS, AND WHY IT IS THE ENVELOPE RATHER THAN THE CONTENT
================================================================

The whole value of the cross-model cell is that both providers saw the *same
prompt*. They did: the same frozen steering artifact, the same evidence digest,
the same output grammar. What necessarily differs is how those bytes are carried:

===================  =============================  ==============================
fact                 Anthropic                      OpenAI
===================  =============================  ==============================
system instructions  top-level ``system=``          a ``developer`` role message
output budget        ``max_tokens``                 ``max_completion_tokens``
structured output    ``output_config.format``       ``response_format.json_schema``
usage field names    ``input_tokens``/``output_``   ``prompt_tokens``/``completion_``
refusal surface      ``stop_reason="refusal"``      ``message.refusal`` or
                     + ``stop_details.category``    ``finish_reason``
reasoning            ``thinking={"type":            no parameter sent; the
                     "disabled"}`` -- off, so the   provider default applies, so
                     whole budget is the answer     the budget covers reasoning
                                                    *and* the answer
===================  =============================  ==============================

None of that is a content difference and none of it is hidden:
:func:`openai_envelope_descriptor` publishes it so a reader comparing the two
arms can see exactly what was not identical and judge for themselves, and
``sabotage_v3_t1`` writes that descriptor into the capture provenance so it
travels with the captured bytes rather than living only in this docstring.

THE REASONING ROW IS THE ONE THAT COSTS SOMETHING, AND IT IS NOT WORKED AROUND
=============================================================================

The Anthropic arm disables thinking outright, so its 2048-token budget is 2048
tokens of JSON. This arm sends no reasoning parameter, so a GPT-5-family model
reasons at the provider's default and those tokens are billed as output tokens
and drawn from the same ``max_completion_tokens``. The two budgets are the same
number and they do not buy the same thing.

Sending an effort parameter to close the gap was rejected: its accepted values
for this model are not verifiable without spending, and this project does not
put unverified values in a request whose whole purpose is provenance. Raising
the budget was rejected for the opposite reason -- the output budget is one of
the things held identical across the two arms on purpose.

So the gap is left open and published. If reasoning consumes the budget the
provider returns ``finish_reason: "length"``, which the branch below reports as
``proposal_model_output_truncated``: a named, billed failure that is visibly not
a decline and visibly not a short answer.

STRICT SCHEMA IS DELIBERATELY OFF
=================================

OpenAI's ``strict: true`` structured-output mode requires a schema subset --
``additionalProperties: false`` on every nested object, every property required
-- that the provider-facing schema this project already emits does not satisfy.
Sending it strict would be rejected with a 400 before the request was processed.

That is not worked around by rewriting the schema, because the schema is hashed
into the prompt contract and shared with the Anthropic arm; changing it for one
provider would end the comparison this client exists to enable. Strict is off,
and the guarantee is recovered where this project already keeps it: the response
is re-validated locally against the strict pydantic model in
``ModelAgentProposer._parse``, which fails closed on anything that does not
conform. The provider-facing schema is a hint here, exactly as
``_provider_schema``'s docstring says it is on the Anthropic side.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Final

from incidentgate.contracts import ModelInvocationRecord
from incidentgate.reasons import PROPOSAL_MODEL_OUTPUT_TRUNCATED

from .model_proposal import (
    CompletionRequest,
    CompletionResult,
    PricingSnapshot,
    ProviderPolicyRefusal,
)
from .proposal import ProposalError

PROVIDER: Final = "openai"

#: The response-format wrapper name. Required by the API and carried in the
#: published envelope descriptor because it is part of the request bytes.
_SCHEMA_NAME: Final = "incident_proposal"

#: ``finish_reason`` values that mean the provider stopped the response on policy
#: grounds rather than because the model finished. These are refusals, not
#: malformed bodies, and they must reach :class:`ProviderPolicyRefusal`.
_POLICY_FINISH_REASONS: Final = frozenset({"content_filter"})

#: The one value that means the model completed normally.
_COMPLETE_FINISH_REASON: Final = "stop"


def openai_envelope_descriptor() -> dict[str, str]:
    """Publish exactly how this provider's envelope differs from Anthropic's.

    Recorded rather than absorbed. A reader comparing a claude row against a gpt
    row is entitled to see what was not identical between them without reading
    two transports, and "the envelope differed but the content did not" is a
    claim that should be checkable rather than asserted.
    """
    return {
        "provider": PROVIDER,
        "system_channel": "developer_role_message",
        "output_budget_field": "max_completion_tokens",
        "structured_output": f"response_format.json_schema:{_SCHEMA_NAME}",
        "structured_output_strict": "false",
        "usage_fields": "prompt_tokens,completion_tokens",
        "refusal_surface": "message.refusal|finish_reason",
        # The one entry that is a limitation rather than a renaming. No
        # reasoning-effort parameter is sent, so the provider default applies and
        # the output budget is shared between reasoning and the answer -- unlike
        # the Anthropic arm, which disables thinking and spends the whole budget
        # on the answer. Recorded because a reader comparing token counts across
        # the two arms would otherwise be comparing two different quantities.
        "reasoning_control": "none_sent:provider_default_shares_output_budget",
        "sampling": "none_sent",
    }


class OpenAICompletionClient:
    """Real OpenAI transport: bounded, secret-free, and fail-closed like its sibling."""

    def __init__(
        self,
        *,
        api_key: str,
        pricing: PricingSnapshot,
        timeout_seconds: float = 30.0,
        client: Any | None = None,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("OpenAI completion client requires an API key")
        if not 0 < timeout_seconds <= 60:
            raise ValueError("timeout must be within (0, 60] seconds")
        if client is not None and client_factory is not None:
            raise ValueError("provide either client or client_factory, not both")
        self._api_key = api_key
        self._pricing = pricing
        self._timeout_seconds = timeout_seconds
        self._client = client
        self._client_factory = client_factory

    def __repr__(self) -> str:  # never render the API key
        return f"OpenAICompletionClient(timeout_seconds={self._timeout_seconds!r})"

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if self._client_factory is not None:
            return self._client_factory(
                api_key=self._api_key, timeout=self._timeout_seconds, max_retries=0
            )
        from openai import OpenAI

        return OpenAI(api_key=self._api_key, timeout=self._timeout_seconds, max_retries=0)

    def complete(self, request: CompletionRequest) -> CompletionResult:
        kwargs: dict[str, Any] = {
            "model": request.model,
            "max_completion_tokens": request.max_tokens,
            "messages": [
                # The steering and base system prompt travel as a developer
                # message: OpenAI's nearest equivalent to Anthropic's top-level
                # system channel. The bytes are identical, the channel is not.
                {"role": "developer", "content": request.system},
                {"role": "user", "content": request.user_content},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": _SCHEMA_NAME,
                    "schema": request.schema,
                    "strict": False,
                },
            },
        }
        if request.temperature is not None:
            kwargs["temperature"] = request.temperature
        if request.thinking is not None:
            # ``request.thinking`` is an Anthropic request shape with no OpenAI
            # equivalent, and there is no honest translation of it: the nearest
            # OpenAI control is a reasoning-effort value this project has not
            # verified for this model. So a set directive is a capability-table
            # error, and it fails closed and loudly rather than being dropped.
            #
            # Dropping it silently is the tempting version and the wrong one. A
            # caller that asked for thinking to be disabled and was not told the
            # request went out without that instruction would compare two arms
            # believing a parameter held on both.
            raise ValueError(
                "an Anthropic thinking directive cannot be sent to OpenAI; the capability "
                "table entry for this model is wrong"
            )
        response = self._get_client().chat.completions.create(**kwargs)
        request_id = getattr(response, "_request_id", None)
        choices = getattr(response, "choices", None)
        if not isinstance(choices, list) or len(choices) != 1:
            raise ValueError("non-single-choice response")
        choice = choices[0]
        message = getattr(choice, "message", None)
        finish_reason = getattr(choice, "finish_reason", None)

        # A refusal reaches us two ways, and both are policy decisions rather
        # than malformed bodies. See ProviderPolicyRefusal: publishing either as
        # a model decline would attribute a choice to a model that, in the
        # content-filter case, may never have produced one.
        refusal = getattr(message, "refusal", None)
        if isinstance(refusal, str) and refusal.strip():
            raise self._policy_refusal(
                response, request, stop_reason="refusal", explanation=refusal,
                category="message_refusal", request_id=request_id,
            )
        if finish_reason in _POLICY_FINISH_REASONS:
            raise self._policy_refusal(
                response, request, stop_reason=str(finish_reason), explanation=None,
                category=str(finish_reason), request_id=request_id,
            )
        if finish_reason == "length":
            # Mirrors the Anthropic client's distinct truncation path: a body cut
            # off by the output budget is a budget bug, not a parser failure. On
            # this provider it is also the expected shape of the reasoning gap
            # described in the module docstring -- reasoning tokens draw on the
            # same budget as the answer -- which is exactly why it must arrive
            # named rather than as a generic incomplete response.
            raise ProposalError(PROPOSAL_MODEL_OUTPUT_TRUNCATED)
        if finish_reason != _COMPLETE_FINISH_REASON:
            raise ValueError(f"incomplete response (finish_reason={finish_reason!r})")

        text = getattr(message, "content", None)
        if not isinstance(text, str) or not text:
            raise ValueError("non-text response")
        usage = getattr(response, "usage", None)
        input_tokens = getattr(usage, "prompt_tokens", None)
        output_tokens = getattr(usage, "completion_tokens", None)
        if usage is None or not isinstance(input_tokens, int) or not isinstance(output_tokens, int):
            raise ValueError("missing provider usage")
        # Same reasoning as the Anthropic client: the call is already billed, so a
        # snapshot that cannot price this model is a gap in our price list rather
        # than a reason to drop real usage from the record.
        priced = self._pricing.prices(request.model)
        invocation = ModelInvocationRecord(
            provider=PROVIDER,
            model=request.model,
            invocation_kind="provider_call",
            usage_source="openai_chat_completions_usage",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=self._pricing.cost(request.model, input_tokens, output_tokens) if priced else None,
            currency=self._pricing.currency if priced else None,
            pricing_snapshot=self._pricing.snapshot_id,
        )
        return CompletionResult(raw_json=text, invocation=invocation)

    def _policy_refusal(
        self,
        response: Any,
        request: CompletionRequest,
        *,
        stop_reason: str,
        category: str | None,
        explanation: str | None,
        request_id: str | None,
    ) -> ProviderPolicyRefusal:
        """Lift an OpenAI refusal into the same typed fact the Anthropic path raises.

        Usage is carried for the same reason it is there: a refused request is
        still read, and the provider bills for reading it. A refusal that dropped
        usage would hide a real cost.
        """
        usage = getattr(response, "usage", None)
        input_tokens = getattr(usage, "prompt_tokens", None)
        output_tokens = getattr(usage, "completion_tokens", None)
        input_tokens = input_tokens if isinstance(input_tokens, int) else 0
        output_tokens = output_tokens if isinstance(output_tokens, int) else 0
        priced = self._pricing.prices(request.model)
        return ProviderPolicyRefusal(
            stop_reason=stop_reason,
            category=category,
            explanation=explanation,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=(
                self._pricing.cost(request.model, input_tokens, output_tokens) if priced else None
            ),
            currency=self._pricing.currency if priced else None,
            pricing_snapshot=self._pricing.snapshot_id,
            request_id=request_id,
        )


def openai_envelope_json() -> str:
    """The envelope descriptor as canonical JSON, for recording in provenance."""
    return json.dumps(openai_envelope_descriptor(), sort_keys=True, separators=(",", ":"))
