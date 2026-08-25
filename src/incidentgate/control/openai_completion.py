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
reasoning            ``thinking={"type":            ``reasoning_effort="none"``
                     "disabled"}``                  -- explicitly off on both
===================  =============================  ==============================

None of that is a content difference and none of it is hidden:
:func:`openai_envelope_descriptor` publishes it so a reader comparing the two
arms can see exactly what was not identical and judge for themselves, and
``sabotage_v3_t1`` writes that descriptor into the capture provenance so it
travels with the captured bytes rather than living only in this docstring.

THE REASONING ROW, AND WHY OMITTING THE PARAMETER WAS NOT AN OPTION
==================================================================

An earlier revision of this module sent no reasoning parameter and described the
result as the provider default applying. That was true and it was not harmless.
Per OpenAI's reasoning guide, gpt-5.5 defaults to ``medium``, and reasoning
tokens are billed as output tokens and drawn from the same budget as the answer.
So the arm would have run gpt-5.5 reasoning at medium against claude-opus-5 with
thinking explicitly disabled -- a confound on the one cell whose entire value is
that both models met identical conditions.

The failure mode worth naming is that it would not have looked like a failure.
Truncation was the loud outcome; a *successful* call producing a clean,
publishable, confounded number was the quiet one.

So this arm sends ``reasoning_effort="none"`` explicitly, and neither arm relies
on a default. The flat field name is the Chat Completions spelling, confirmed
from the API reference; the Responses API spells the same control
``reasoning: {effort: ...}``, so a move to that endpoint has to change the field
name and the endpoint together.

That makes the two arms **analogous, not identical** -- both explicitly off, on
two different parameters of two different APIs -- and the envelope descriptor
records exactly that weaker claim. Nothing here has measured that the two
settings leave the two models in comparable internal states, and calling them
equivalent would assert something no one checked.

The output budget stays at 2048 on both arms. With reasoning off it is ample:
the Anthropic capture's answer was 224 tokens. If it is ever exhausted anyway
the provider returns ``finish_reason: "length"``, which the branch below reports
as ``proposal_model_output_truncated`` -- a named, billed failure that is
visibly not a decline and visibly not a short answer.

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

from collections.abc import Callable
from typing import Any, Final

from incidentgate.contracts import ModelInvocationRecord
from incidentgate.reasons import PROPOSAL_MODEL_OUTPUT_TRUNCATED

from .model_capabilities import REASONING_EFFORT_OFF, reasoning_equivalence
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

#: The Chat Completions reasoning control: a flat string field, not the Responses
#: API's ``reasoning: {effort: ...}`` object. Confirmed from the API reference on
#: 2026-08-20. Named as a constant because the request, the capability table and
#: the published envelope all have to agree on it.
_REASONING_EFFORT_FIELD: Final = "reasoning_effort"

#: This arm's published equivalence claim when reasoning was explicitly switched
#: off. See the matching constant in ``model_proposal``: it is a literal here
#: because it sits in committed captures.
_REASONING_OFF_EQUIVALENCE: Final = "explicitly_off:analogous_to_the_other_arm_not_identical"


def openai_envelope_descriptor(reasoning: dict[str, str] | None = None) -> dict[str, str]:
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
        # The exact reasoning setting that went out, so a reader can see that
        # this arm did not run at the provider's `medium` default. Recorded as
        # the wire field name rather than the directive shape, because the wire
        # field is what the provider was actually asked.
        "reasoning_control": (
            f"{_REASONING_EFFORT_FIELD}:omitted:provider_default_applies"
            if reasoning is None
            else f"{_REASONING_EFFORT_FIELD}={reasoning.get('effort', 'unknown')}"
        ),
        # See the matching note in ``anthropic_envelope_descriptor``: both arms
        # switch reasoning off explicitly, and that is the whole of the
        # equivalence. Two different parameters on two different APIs are not
        # shown to leave two models in comparable internal states, and the record
        # must not imply otherwise.
        #
        # The effort value decides this, not the presence of the parameter. This
        # arm is the one where the difference is most easily reached: every
        # effort gpt-5.5 accepts other than "none" leaves reasoning on, and the
        # old branch would have published "explicitly_off" for all of them.
        "reasoning_equivalence": reasoning_equivalence(
            off=(
                None
                if reasoning is None
                else reasoning.get("effort") == REASONING_EFFORT_OFF
            ),
            off_label=_REASONING_OFF_EQUIVALENCE,
        ),
        # UNKNOWN, AND RECORDED AS UNKNOWN.
        #
        # No sampling parameter is sent. Unlike the Anthropic arm there is no
        # documented default to fall back on: the Chat Completions reference
        # states a range ("between 0 and 2") and no default, and warns that
        # "Parameter support can differ depending on the model used to generate
        # the response, particularly for newer reasoning models".
        #
        # Writing 1.0 here to match the other arm would be assuming the number
        # that makes the comparison look cleanest, which is the one direction
        # this field must never be wrong in.
        "sampling": "unknown",
        "sampling_provenance": "provider_default_undocumented",
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
        if request.thinking is not None or request.think is not None:
            # ``request.thinking`` is Anthropic's shape and ``request.think`` is
            # Ollama's, and this endpoint has neither field. The reasoning
            # control here is ``reasoning_effort`` and it arrives on its own
            # field, so either of the others means the capability table sent this
            # model to the wrong provider's accessor.
            #
            # Dropping it silently is the tempting version and the wrong one. A
            # caller that asked for thinking to be disabled and was not told the
            # request went out without that instruction would compare two arms
            # believing a parameter held on both -- which is exactly how this arm
            # nearly shipped running at the provider's default.
            raise ValueError(
                "another provider's reasoning directive cannot be sent to OpenAI; the "
                "capability table entry for this model is wrong"
            )
        if request.reasoning is not None:
            effort = request.reasoning.get("effort")
            if set(request.reasoning) != {"effort"} or not isinstance(effort, str) or not effort:
                # A malformed directive must not degrade into an omitted one:
                # omission is `medium` here, so "we could not read the setting"
                # and "reason at the default" would become the same request.
                raise ValueError(
                    "an OpenAI reasoning directive must be exactly {'effort': <non-empty str>}"
                )
            # Flattened at the call site, because this is the one place that
            # knows the endpoint. Chat Completions takes a flat string; the
            # Responses API takes the nested object the directive already is.
            kwargs[_REASONING_EFFORT_FIELD] = effort
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


# ``openai_envelope_json()`` used to live here and was deleted rather than fixed.
# It called the descriptor with no arguments, so it published
# "reasoning_effort:omitted:provider_default_applies" for an arm that has always
# sent reasoning_effort="none" -- the exact failure
# ``sabotage_v3_t1.provider_envelope_json`` was written to make impossible, and
# its docstring names it: a descriptor that describes what this transport usually
# does can stay reassuring while the request says something else. Nothing called
# it; ``provider_envelope_json`` builds all three arms' envelopes from the request
# that was actually sent.
