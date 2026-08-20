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
  "omit_is_off"    - omitting the parameter means no thinking (Opus 4.8/4.7/4.6, Sonnet 4.6,
                     Haiku 4.5). Send nothing; max_tokens only has to cover the JSON object.
  "send_disabled"  - thinking is ON when the parameter is omitted, and an explicit
                     {"type": "disabled"} is accepted (Opus 5, Sonnet 5). Both callers emit one
                     small fixed JSON object, so deep reasoning is not the point and adaptive
                     thinking would silently consume the shared max_tokens budget.
  "reserve_budget" - thinking cannot be turned off: Fable 5 rejects {"type": "disabled"} at any
                     effort. Send nothing - omitting is the one setting no model rejects - and
                     size max_tokens to cover thinking *and* the JSON, because the cap bounds
                     them together.

"send_disabled" depends on callers never sending output_config.effort: on Opus 5 a
disabled-thinking request is a 400 at effort xhigh/max and accepted at the default high or below.
If an effort knob above high is ever added, those rows must move to "reserve_budget".
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

ThinkingPolicy = Literal["omit_is_off", "send_disabled", "reserve_budget"]


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
        # thinking="omit_is_off" is a statement about the REQUEST, and it is the
        # only one of the three policies that describes what this lab sends: no
        # reasoning parameter is emitted, and zero headroom keeps max_tokens at
        # the same 2048 the Anthropic arm used, since a different output budget
        # is a different experiment.
        #
        # It is NOT a claim that this model does no reasoning. An earlier
        # revision of this comment asserted that omitting the parameter made
        # "no thinking" true by construction; that is false for a GPT-5-family
        # model, which reasons at a provider default when no effort is
        # specified, bills those tokens as output tokens, and counts them
        # against `max_completion_tokens`. The Anthropic arm sends
        # {"type": "disabled"} and so really does get all 2048 tokens for the
        # JSON object; this arm does not, and the difference is published in
        # `openai_envelope_descriptor()` and recorded in every capture's
        # provenance rather than left for a reader to discover. The visible
        # consequence, if the budget is exhausted by reasoning, is a
        # `finish_reason: "length"` that the transport reports as
        # `proposal_model_output_truncated` -- a named, billed failure, never a
        # decline and never a silently short answer.
        "gpt-5.5": ModelCapability(accepts_sampling=False, thinking="omit_is_off"),
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
    """The ``thinking`` value to send for this model, or None when it must be omitted entirely."""
    return {"type": "disabled"} if capability(model).thinking == "send_disabled" else None


def thinking_headroom_tokens(model: str) -> int:
    """Extra max_tokens this model needs because its thinking cannot be turned off."""
    return THINKING_HEADROOM_TOKENS if capability(model).thinking == "reserve_budget" else 0
