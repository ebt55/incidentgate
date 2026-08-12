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
