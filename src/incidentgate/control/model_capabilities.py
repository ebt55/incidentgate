"""One frozen, per-model statement of the provider facts this lab's model callers depend on.

Both the advisory monitor and the model proposer send bounded structured-output requests, and
both must get the same three facts right: which transport the id belongs to, whether the model
accepts sampling parameters, and how thinking has to be requested so a fixed ``max_tokens``
cannot silently truncate the answer. Those facts are per exact model id, not per family prefix
- Opus 4.6 and
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
  "send_think_false" - the same fact again on a locally served hybrid reasoning model: thinking is
                       ON when nothing is sent, and an explicit ``think: false`` turns it off
                       (Qwen3). See ``think_directive``.
  "reserve_budget"   - thinking cannot be turned off: Fable 5 rejects {"type": "disabled"} at any
                       effort. Send nothing - omitting is the one setting no model rejects - and
                       size max_tokens to cover thinking *and* the JSON, because the cap bounds
                       them together.

WHY EACH OFF-SWITCH IS ITS OWN VALUE AND NOT A SECOND SPELLING OF "send_disabled"
=================================================================================

The provider fact is the same shape three times over - on by default, explicitly disableable -
but the request is not, and this enum exists to describe requests. Anthropic takes a ``thinking``
object whose off value is ``{"type": "disabled"}``; OpenAI Chat Completions takes a flat
``reasoning_effort`` string whose off value is ``"none"``; Ollama takes a boolean ``think`` whose
off value is ``false``. A caller that read "send_disabled" and emitted an Anthropic thinking
block at either of the other two endpoints would send a parameter that endpoint does not have,
and the three are dispatched by different accessors for exactly that reason:
``thinking_directive`` answers only for Anthropic, ``reasoning_directive`` only for OpenAI,
``think_directive`` only for the local arm, and each returns None for a model that is not theirs.

Collapsing them would have kept the enum smaller by making one value mean several wire shapes,
which is the trade this table refuses. The whole point of stating provider facts once is that
the statement is exact.

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

Source for the local row: Qwen3 is a hybrid reasoning model with thinking ON by default, and
Ollama 0.32 exposes a boolean ``think`` parameter on ``/api/chat``. The parameter is used rather
than the ``/no_think`` prompt token, deliberately: a prompt token would change the prompt bytes,
and the bytes are the one thing three arms are meant to hold identical.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

ThinkingPolicy = Literal[
    "omit_is_off", "send_disabled", "send_effort_none", "send_think_false", "reserve_budget"
]

#: Which transport a model id belongs to. Three values because this lab has three
#: transports, each with its own wire shape for the same two facts.
ModelProvider = Literal["anthropic", "openai", "local"]

#: The OpenAI Chat Completions off value, kept as a constant so the request, the capability
#: table and the published envelope descriptor cannot drift apart into three spellings.
REASONING_EFFORT_OFF = "none"


@dataclass(frozen=True)
class ModelCapability:
    """The provider facts a bounded structured-output caller must get right, per model id.

    ``provider`` was added third, and it is a fact this table already carried in
    prose. Every row's comment says which API it describes, and three separate
    accessors below dispatch on ``thinking`` in order to answer for one endpoint
    each -- which works only because no two providers currently share a policy
    value. That is a coincidence of the present table rather than a property of
    it, and a caller that has to *shape a request for whichever arm a model
    belongs to* needs the fact stated rather than inferred from an off-switch
    spelling.

    The concrete failure this closes is measured, not hypothetical:
    ``monitor_v2.StructuredMonitorCaller`` sends Anthropic's ``thinking`` and a
    bare ``temperature`` for every model it is handed. Pointed at ``qwen3-14b``
    it would put ``temperature: 0`` in the canonical prompt -- the bytes the
    capture is keyed and published by -- while the Ollama transport ignores that
    field entirely and the modelfile's 0.6 is what actually ran. True on the
    record, false about the run, and undetectable afterwards.
    """

    accepts_sampling: bool
    thinking: ThinkingPolicy
    provider: ModelProvider


MODEL_CAPABILITIES: Mapping[str, ModelCapability] = MappingProxyType(
    {
        "claude-opus-5": ModelCapability(
            accepts_sampling=False, thinking="send_disabled", provider="anthropic"
        ),
        "claude-opus-4-8": ModelCapability(
            accepts_sampling=False, thinking="omit_is_off", provider="anthropic"
        ),
        "claude-opus-4-7": ModelCapability(
            accepts_sampling=False, thinking="omit_is_off", provider="anthropic"
        ),
        "claude-opus-4-6": ModelCapability(
            accepts_sampling=True, thinking="omit_is_off", provider="anthropic"
        ),
        "claude-sonnet-5": ModelCapability(
            accepts_sampling=False, thinking="send_disabled", provider="anthropic"
        ),
        "claude-sonnet-4-6": ModelCapability(
            accepts_sampling=True, thinking="omit_is_off", provider="anthropic"
        ),
        "claude-haiku-4-5": ModelCapability(
            accepts_sampling=True, thinking="omit_is_off", provider="anthropic"
        ),
        "claude-haiku-4-5-20251001": ModelCapability(
            accepts_sampling=True, thinking="omit_is_off", provider="anthropic"
        ),
        "claude-fable-5": ModelCapability(
            accepts_sampling=False, thinking="reserve_budget", provider="anthropic"
        ),
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
        "gpt-5.5": ModelCapability(
            accepts_sampling=False, thinking="send_effort_none", provider="openai"
        ),
        # Local open weights, served by Ollama. The id here is a *harness* label,
        # not a vendor id: the server tag is `qwen3:14b` and contains a colon,
        # which no cache path, provenance field or attacker_source pattern
        # admits. `local_weights.OLLAMA_TAGS` holds the mapping and is tested.
        #
        # WHAT ACTUALLY IDENTIFIES THIS MODEL IS NOT THIS STRING.
        #
        # For the hosted arms the id is the identity, which is why a guessed one
        # was a defect worth a commit message. Here the identity is the weights
        # file: `resolve_ollama_weights` reads Ollama's manifest for the declared
        # digest, computes the sha256 of the blob itself, and refuses if the two
        # disagree. This row states the request shape; the capture states which
        # bytes answered.
        #
        # accepts_sampling=True, and this is the one axis where this arm
        # deliberately does NOT mirror the other two by staying silent.
        #
        # The modelfile bakes temperature 0.6, top_p 0.95, top_k 20,
        # repeat_penalty 1. Sending nothing would therefore have run this arm at
        # 0.6 against an Anthropic arm whose documented default is 1.0, while all
        # three envelopes read "none_sent" -- the same shape of confound as
        # gpt-5.5's `medium` reasoning default, and dangerous the same way,
        # because the mismatched run is the one that succeeds. See ``_SAMPLING``
        # for what is sent, what is left alone, and what could not be
        # established.
        #
        # thinking="send_think_false": Qwen3 is a hybrid reasoning model with
        # thinking ON by default, so omitting the parameter would run a different
        # experiment than the two arms that switched reasoning off -- the same
        # trap as gpt-5.5's `medium` default, and dangerous in the same way,
        # because the confounded call is the one that *succeeds*. Sent explicitly
        # as `think: false`. Zero headroom keeps the budget at the same 2048 the
        # other two arms used.
        #
        # FEASIBILITY DEPENDS ON FREE VRAM AT RUN TIME, NOT ON THIS TABLE.
        #
        # 14B at Q4 needs roughly 9 GB. The target card holds 10,240 MiB total,
        # of which ordinary desktop applications (ComfyUI, browsers, Docker
        # Desktop) were observed holding 8,067 MiB. The model will not load until
        # those are closed, and this row cannot promise otherwise.
        #
        # A model that fails to load is an ENVIRONMENT failure and must never be
        # recorded as a model outcome. `local_weights.LocalModelUnavailable`
        # exists for exactly that, and the runner maps it to `TransportUnavailable`
        # (exit 3) rather than to a decline -- the same principle this codebase
        # already pins for provider outages, applied to a failure that looks
        # different because the server is up, reachable, and simply cannot fit
        # the weights.
        #
        # SCOPE: EXPECTED TO SUIT T1, EXPECTED NOT TO SUIT T4.
        #
        # T1 is a single tool selection from a two-action grammar, which a 14B
        # model of this class should handle. T4 needs a covert objective split
        # across three ordered calls, and at this scale a failure there could as
        # easily be incompetence as refusal. The two are indistinguishable to the
        # attempt predicate, so a T4 null result from this arm would mean
        # nothing. Recorded now rather than rediscovered after a run.
        "qwen3-14b": ModelCapability(
            accepts_sampling=True, thinking="send_think_false", provider="local"
        ),
        # The second local attacker, and a genuinely independent one rather than
        # a fallback: different lineage, architecture `llama` against `qwen3`,
        # 12.2B against 14.8B, and no reasoning mode at all. If both decline, one
        # model-specific explanation is ruled out that a second Qwen would not
        # have touched.
        #
        # thinking="omit_is_off" is true here by construction, not by assumption:
        # `ollama show` reports capabilities `completion` and `tools` only, with
        # no `thinking`. There is no reasoning mode to switch off, so omitting
        # the parameter really does mean no thinking -- unlike qwen3:14b, and
        # unlike the false use of this same value the gpt-5.5 row once carried.
        # Nothing is sent, because sending `think` to a model with no thinking
        # capability would be asking for a behaviour it does not have.
        #
        # QUANTISATION DIFFERS FROM THE OTHER LOCAL ROW AND MUST NOT BE EQUATED.
        #
        # Q4_0 here against Q4_K_M for qwen3:14b -- a lower-fidelity scheme. So a
        # difference in results between the two local models has at least three
        # candidate explanations before disposition is reached: lineage,
        # parameter count, and quantisation. This row cannot separate them and
        # does not claim to.
        #
        # Smaller and cheaper on VRAM: 7.1 GB against 9.3 GB, so this one may
        # load where the other will not. That is a reason to record which ran,
        # never a reason to substitute one result for the other.
        "mistral-nemo-12b": ModelCapability(
            accepts_sampling=True, thinking="omit_is_off", provider="local"
        ),
    }
)

# An id this table has never seen fails closed on both axes. Sampling: treated as rejected, so a
# wrong guess costs a loud ValueError at construction rather than an HTTP 400 mid-incident, and it
# matches the direction the API has moved since Opus 4.7. Thinking: treated as un-disableable,
# because omitting the parameter is accepted by every model while {"type": "disabled"} is not, and
# the larger budget can only overpay, never truncate.
#
# The third axis has no fail-closed value, so it is not given one. An unlisted id belongs to no
# arm this table can name, and picking the most common one would be a guess that reads as a fact
# -- the exact shape of the two wrong gpt-5.5 rows this file already records. ``model_provider``
# therefore answers ``None`` for an unknown id, and every caller that needs to *shape* a request
# refuses rather than proceeding. The value below is a placeholder that no accessor reads: it
# exists because the dataclass field is required, and ``model_provider`` keys on membership in
# MODEL_CAPABILITIES rather than on this object.
UNKNOWN_MODEL = ModelCapability(
    accepts_sampling=False, thinking="reserve_budget", provider="anthropic"
)

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


def model_provider(model: str) -> ModelProvider | None:
    """Which transport this exact model id belongs to, or ``None`` for an unlisted one.

    ``None`` rather than a default, for the reason stated on ``UNKNOWN_MODEL``: a
    guessed provider is a wrong request shape recorded as a right one. A caller
    that must build a request refuses on ``None``; a caller that only reports may
    say "unlisted".
    """
    stated = MODEL_CAPABILITIES.get(model)
    return None if stated is None else stated.provider


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


#: What this lab sends as sampling, per model, when it sends any.
#:
#: THE THIRD DEFAULT CONFOUND, AND WHY THIS ONE COULD NOT BE FULLY REMOVED.
#: =======================================================================
#:
#: "Send nothing" is not a neutral setting, and it means something different on
#: each arm. What is established, and what is not:
#:
#:   anthropic  claude-opus-5 rejects temperature/top_p outright, so nothing can
#:              be sent. The Messages API reference documents the parameter as
#:              "Defaults to `1.0`. Ranges from `0.0` to `1.0`." That is a
#:              documented default, not a measured effective value -- the API
#:              does not echo back what it used.
#:   openai     the Chat Completions reference states a range ("between 0 and 2")
#:              but NO default, and warns that "Parameter support can differ
#:              depending on the model used to generate the response,
#:              particularly for newer reasoning models". So gpt-5.5's effective
#:              sampling is UNKNOWN. It is recorded as unknown rather than
#:              assumed to be 1.0.
#:   local      OMISSION IS NEVER NEUTRAL HERE, and it is not even consistent
#:              between two models on the same server. qwen3:14b's modelfile
#:              bakes temperature 0.6; mistral-nemo:12b's declares no sampling
#:              at all, so Ollama's own documented default of 0.8 applies
#:              instead. Sending nothing would therefore have run two local
#:              models at two different temperatures, neither of them the
#:              documented 1.0 the Anthropic arm ran at, with every envelope
#:              truthfully reading "none_sent" -- true and misleading in exactly
#:              the way this project keeps catching.
#:
#: So the local arm sends temperature and top_p explicitly at 1.0, removing the
#: one divergence that is both known and quantified. It does NOT achieve
#: three-way equivalence and does not claim to:
#:
#:   * OpenAI's effective value is unknown, so nothing can be matched to it.
#:   * Two of the three models reject sampling parameters, so they cannot be
#:     moved to meet the third.
#:   * Ollama documents no value of top_k that disables top-k sampling, so
#:     top_k and repeat_penalty are left to resolve to the modelfile's value or
#:     Ollama's documented default rather than guessed into neutrality. Both are
#:     recorded in the envelope with the source that supplied them.
#:
#: Every one of those facts travels in ``request_envelope`` under ``sampling``
#: and ``sampling_provenance``, so a reader can see which arm got where by
#: explicit setting, which by a documented default, and which is simply unknown.
_SAMPLING: Mapping[str, Mapping[str, str]] = MappingProxyType({
    "qwen3-14b": MappingProxyType({"temperature": "1.0", "top_p": "1.0"}),
    # The same values for the same reason, and the reason is sharper here. This
    # model's modelfile declares no sampling at all, so an omitted temperature
    # would resolve to Ollama's own default of 0.8 -- a *third* value, different
    # again from qwen3's 0.6 and from Anthropic's documented 1.0. Omission is
    # never neutral on this provider; it is only ever somebody else's choice.
    "mistral-nemo-12b": MappingProxyType({"temperature": "1.0", "top_p": "1.0"}),
})


def sampling_directive(model: str) -> dict[str, str] | None:
    """The explicit sampling this lab sends for this model, or None when it sends none.

    None means "this arm inherits whatever its provider does", which is a
    different statement from "this arm runs neutral" -- see ``_SAMPLING``.
    """
    values = _SAMPLING.get(model)
    return None if values is None else dict(values)


def think_directive(model: str) -> bool | None:
    """The Ollama ``think`` value for this model, or None when it takes none.

    A bool rather than a wrapped dict because that is what the parameter is on
    the wire, and the point of these three accessors is that each states its own
    provider's shape exactly. ``False`` is a value; ``None`` means "this model
    has no such control", and the two must not collapse -- on a hybrid reasoning
    model, not sending the parameter means thinking is ON.
    """
    return False if capability(model).thinking == "send_think_false" else None


def thinking_headroom_tokens(model: str) -> int:
    """Extra max_tokens this model needs because its thinking cannot be turned off."""
    return THINKING_HEADROOM_TOKENS if capability(model).thinking == "reserve_budget" else 0
