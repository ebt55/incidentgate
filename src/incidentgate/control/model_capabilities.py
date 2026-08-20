"""One frozen, per-model statement of the provider facts this lab's model callers depend on.

Both the advisory monitor and the model proposer send bounded structured-output requests to
Anthropic, and both must get the same two facts right: whether the model accepts sampling
parameters, and how thinking has to be requested so a fixed ``max_tokens`` cannot silently
truncate the answer. Those facts are per exact model id, not per family prefix - Opus 4.6 and
Sonnet 4.6 still accept temperature/top_p while every Opus/Sonnet released after them rejects
them with an HTTP 400, and thinking flipped to on-by-default in the 5 generation. A prefix guess
is wrong in both directions: it forbids configurations the API accepts and hides ones it rejects.
Stating the facts once, here, keeps the two callers from drifting and makes adding a model a
deliberate edit rather than an accident of its name.

The thinking policies, and why the request shape differs per model:
  "omit_is_off"      - omitting the parameter means no thinking (Opus 4.8/4.7/4.6, Sonnet 4.6,
                       Haiku 4.5). Send nothing; max_tokens only has to cover the JSON object.
  "send_disabled"    - thinking is ON when the parameter is omitted, and an explicit
                       {"type": "disabled"} is accepted (Opus 5, Sonnet 5). Both callers emit one
                       small fixed JSON object, so deep reasoning is not the point and adaptive
                       thinking would silently consume the shared max_tokens budget.
  "send_effort_none" - the same fact on OpenAI, through a different parameter: reasoning is ON at
                       a provider default when nothing is sent, and an explicit effort of "none"
                       turns it off (gpt-5.5). See ``reasoning_directive``.
  "reserve_budget"   - thinking cannot be turned off: Fable 5 rejects {"type": "disabled"} at any
                       effort. Send nothing - omitting is the one setting no model rejects - and
                       size max_tokens to cover thinking *and* the JSON, because the cap bounds
                       them together.

WHY "send_effort_none" IS A FOURTH VALUE AND NOT A SECOND SPELLING OF "send_disabled"
=====================================================================================

The provider fact is the same shape - on by default, explicitly disableable - but the request
is not, and this enum exists to describe requests. Anthropic takes a ``thinking`` object whose
off value is ``{"type": "disabled"}``; OpenAI Chat Completions takes a flat ``reasoning_effort``
string whose off value is ``"none"``. A caller that read "send_disabled" and emitted an
Anthropic thinking block at an OpenAI endpoint would send a parameter the endpoint does not
have, and the two are dispatched by different accessors for exactly that reason:
``thinking_directive`` answers only for Anthropic, ``reasoning_directive`` only for OpenAI, and
both return None for a model that is not theirs.

Collapsing them would have kept the enum at three values by making one of them mean two
different wire shapes, which is the trade this table refuses. The whole point of stating
provider facts once is that the statement is exact.

"send_disabled" depends on callers never sending output_config.effort: on Opus 5 a
disabled-thinking request is a 400 at effort xhigh/max and accepted at the default high or below.
If an effort knob above high is ever added, those rows must move to "reserve_budget".

Sources for the OpenAI row, so the next reader can re-check rather than re-derive it
(retrieved 2026-08-20):
  - developers.openai.com/api/docs/api-reference/chat/create - the Chat Completions parameter is
    ``reasoning_effort``, a flat string: "Constrains effort on reasoning for reasoning models.
    Currently supported values are none, minimal, low, medium, high, xhigh, and max."
  - developers.openai.com/api/docs/guides/reasoning - gpt-5.5 defaults to ``medium``; supported
    values are model-dependent; reasoning tokens "are billed as output tokens" and count against
    the output token limit, reported under ``output_tokens_details.reasoning_tokens``.
  - The Responses API spells the same control ``reasoning: {effort: ...}``. This lab calls Chat
    Completions, so it sends the flat form; a move to Responses must change both together.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

ThinkingPolicy = Literal["omit_is_off", "send_disabled", "send_effort_none", "reserve_budget"]

#: The OpenAI Chat Completions off value, kept as a constant so the request, the capability
#: table and the published envelope descriptor cannot drift apart into three spellings.
REASONING_EFFORT_OFF = "none"


@dataclass(frozen=True)
class ModelCapability:
    """The two provider facts a bounded structured-output caller must get right, per model id."""

    accepts_sampling: bool
    thinking: ThinkingPolicy


MODEL_CAPABILITIES: Mapping[str, ModelCapability] = MappingProxyType(
    {
        "claude-opus-5": ModelCapability(accepts_sampling=False, thinking="send_disabled"),
        "claude-opus-4-8": ModelCapability(accepts_sampling=False, thinking="omit_is_off"),
        "claude-opus-4-7": ModelCapability(accepts_sampling=False, thinking="omit_is_off"),
        "claude-opus-4-6": ModelCapability(accepts_sampling=True, thinking="omit_is_off"),
        "claude-sonnet-5": ModelCapability(accepts_sampling=False, thinking="send_disabled"),
        "claude-sonnet-4-6": ModelCapability(accepts_sampling=True, thinking="omit_is_off"),
        "claude-haiku-4-5": ModelCapability(accepts_sampling=True, thinking="omit_is_off"),
        "claude-haiku-4-5-20251001": ModelCapability(accepts_sampling=True, thinking="omit_is_off"),
        "claude-fable-5": ModelCapability(accepts_sampling=False, thinking="reserve_budget"),
        # OpenAI. Both fields below are Anthropic-shaped questions, and this row
        # answers them as the *request shape this lab sends*, not as verified
        # claims about what the OpenAI API would accept -- which is a difference
        # worth stating rather than leaving a reader to assume this table means
        # the same thing for every provider.
        #
        # HOW THIS ID WAS OBTAINED. It is copied from a `models.list()` listing
        # taken against this project's OpenAI credential on 2026-08-20 -- a free
        # metadata call that sends no prompt content -- and not from memory. An
        # earlier revision of this row carried the same string as a *guess*, and
        # a guess that happens to be right is still a value nobody checked.
        #
        # `gpt-5.5` is the floating alias. The same listing also carries the
        # pinned snapshot `gpt-5.5-2026-04-23`, and the alias is expected to move
        # to a later snapshot eventually. The alias is nevertheless what is keyed
        # here, because it is the id OpenAI's published pricing page prices by
        # name: keying the dated snapshot instead would attach a retrieved rate
        # to an id no retrieved source names, which is the fabrication this
        # project's pricing contract exists to prevent. The cost of that choice
        # is disclosed rather than absorbed -- a capture taken through this row
        # is pinned by the recorded `captured_at`, `git_revision` and response
        # bytes, not by the model id, so a later alias move does not silently
        # rewrite what was measured, but it does mean the id alone does not name
        # a model version.
        #
        # accepts_sampling=False: the sabotage attacker sends no sampling
        # parameter at all, on either provider, because the two arms have to be
        # comparable and the Anthropic arm cannot send one. Recording False is
        # what makes ModelAgentProposer refuse a temperature here, so the
        # comparability is enforced rather than remembered.
        #
        # thinking="send_effort_none": reasoning is ON when nothing is sent.
        # Per OpenAI's reasoning guide, gpt-5.5 defaults to `medium`, reasoning
        # tokens are billed as output tokens, and they count against the same
        # output budget as the answer. So the request sends an explicit
        # `reasoning_effort="none"`; see `reasoning_directive`.
        #
        # TWO EARLIER REVISIONS OF THIS ROW WERE WRONG, IN THE SAME DIRECTION.
        #
        # The first claimed there is no reasoning parameter at all. The second
        # kept "omit_is_off" and claimed that omitting it made "no thinking"
        # true by construction. Both amount to trusting a default nobody looked
        # up, and the default is `medium`.
        #
        # The cost of leaving it there would not have been a broken run. It
        # would have been a *successful* one: gpt-5.5 reasoning at medium
        # measured against claude-opus-5 with thinking explicitly disabled,
        # published as a like-for-like comparison. The only thing this cell is
        # worth is that both models met identical conditions, and a confound
        # that produces a clean-looking number is the kind this table cannot
        # detect after the fact.
        #
        # So neither arm relies on a default now. Anthropic gets
        # {"type": "disabled"}, OpenAI gets reasoning_effort="none", and the
        # published envelope descriptor records both -- as *analogous*, which is
        # the true and weaker claim, never as identical.
        #
        # Zero headroom, keeping max_tokens at the same 2048 the Anthropic arm
        # used. With reasoning off that budget is ample: the Anthropic capture's
        # answer was 224 tokens.
        "gpt-5.5": ModelCapability(accepts_sampling=False, thinking="send_effort_none"),
    }
)

# An id this table has never seen fails closed on both axes. Sampling: treated as rejected, so a
# wrong guess costs a loud ValueError at construction rather than an HTTP 400 mid-incident, and it
# matches the direction the API has moved since Opus 4.7. Thinking: treated as un-disableable,
# because omitting the parameter is accepted by every model while {"type": "disabled"} is not, and
# the larger budget can only overpay, never truncate.
UNKNOWN_MODEL = ModelCapability(accepts_sampling=False, thinking="reserve_budget")

# Headroom a caller must add to its own output budget when thinking cannot be turned off, because
# max_tokens caps thinking and response text together.
THINKING_HEADROOM_TOKENS = 14_000


def capability(model: str) -> ModelCapability:
    """The stated capability for this exact model id, or the fail-closed unknown-model default."""
    return MODEL_CAPABILITIES.get(model, UNKNOWN_MODEL)


def is_known_model(model: str) -> bool:
    """Whether this table states the request shape for this exact model id, rather than guessing.

    Callers whose failures are invisible (see the advisory monitor) should refuse an unlisted id
    outright; callers whose failures are recorded may run on the fail-closed default instead.
    """
    return model in MODEL_CAPABILITIES


def model_accepts_sampling(model: str) -> bool:
    """May a request for this model id carry temperature/top_p at all?"""
    return capability(model).accepts_sampling


def thinking_directive(model: str) -> dict[str, str] | None:
    """The Anthropic ``thinking`` value for this model, or None when it must be omitted entirely.

    Answers only for Anthropic. A model whose reasoning is controlled by OpenAI's
    ``reasoning_effort`` returns None here and a directive from
    :func:`reasoning_directive` instead -- the two parameters are not
    interchangeable, and a caller that emitted this object at an OpenAI endpoint
    would be sending a field that endpoint does not have.
    """
    return {"type": "disabled"} if capability(model).thinking == "send_disabled" else None


def reasoning_directive(model: str) -> dict[str, str] | None:
    """The OpenAI reasoning control for this model, or None when it takes none.

    Returned as ``{"effort": ...}`` rather than a bare string so the directive is
    self-describing wherever it travels -- through ``CompletionRequest``, into the
    canonical prompt, and into the published envelope. The transport flattens it
    to the Chat Completions ``reasoning_effort`` field at the call site, which is
    the one place that knows which endpoint is being used.

    Sending this explicitly is the point. Omitting it does not mean "no
    reasoning"; on gpt-5.5 it means ``medium``, which would confound any
    comparison against an arm that switched reasoning off.
    """
    if capability(model).thinking != "send_effort_none":
        return None
    return {"effort": REASONING_EFFORT_OFF}


def thinking_headroom_tokens(model: str) -> int:
    """Extra max_tokens this model needs because its thinking cannot be turned off."""
    return THINKING_HEADROOM_TOKENS if capability(model).thinking == "reserve_budget" else 0
