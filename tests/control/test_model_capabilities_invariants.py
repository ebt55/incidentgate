"""The capability table's cross-arm invariant, which used to be a sentence in a docstring.

Three accessors dispatch on one ``thinking`` field to shape a request for three
different endpoints. What makes that safe is not obvious, and the file said so
wrongly: it claimed the split worked "only because no two providers currently
share a policy value", and called that a coincidence. Two providers have shared
``omit_is_off`` since ``mistral-nemo-12b`` was added. The claim was false when it
was written and the dispatch was correct anyway, because it never rested on that
premise -- ``omit_is_off`` emits no directive from any accessor, so no accessor
answers for it.

A true mechanism beside a false reason survives review, because the mechanism
works. What these tests pin is the reason, so the next provider cannot quietly
invalidate it.

**The Phase 2 case is the point.** An endpoint that speaks OpenAI Chat Completions
takes the same flat ``reasoning_effort``, so a new provider would reuse
``send_effort_none`` and ``reasoning_directive`` would begin answering for two
arms without a line changing. That must fail, loudly, until somebody widens the
declaration on purpose.
"""

from __future__ import annotations

from dataclasses import replace
from typing import get_args

import pytest

from incidentgate.control import model_capabilities as caps
from incidentgate.control.model_capabilities import (
    MODEL_CAPABILITIES,
    POLICY_WIRE_PROVIDERS,
    CapabilityTableInvariant,
    ModelCapability,
    ModelProvider,
    ThinkingPolicy,
    reasoning_directive,
    think_directive,
    thinking_directive,
)


def test_the_declaration_covers_every_policy_value_and_only_real_arms() -> None:
    assert set(POLICY_WIRE_PROVIDERS) == set(get_args(ThinkingPolicy))
    arms = set(get_args(ModelProvider))
    for policy, owners in POLICY_WIRE_PROVIDERS.items():
        assert set(owners) <= arms, f"{policy} names an arm with no transport"


def test_the_two_send_nothing_values_are_the_only_shareable_ones() -> None:
    """An empty owner set is a claim: this value puts no parameter on any wire.

    It is checked against the accessors rather than asserted, because "emits
    nothing" is what makes sharing safe and the accessors are what would emit.
    """
    shareable = {p for p, owners in POLICY_WIRE_PROVIDERS.items() if not owners}
    assert shareable == {"omit_is_off", "reserve_budget"}
    for policy in shareable:
        for model, stated in MODEL_CAPABILITIES.items():
            if stated.thinking != policy:
                continue
            assert thinking_directive(model) is None
            assert reasoning_directive(model) is None
            assert think_directive(model) is None


def test_the_shared_value_this_table_actually_has_is_still_shared() -> None:
    """The premise the old docstring denied. Kept as a test so it cannot be re-denied.

    If this ever fails, ``omit_is_off`` stopped being carried by two arms and the
    prose about why sharing is safe should be re-read rather than assumed.
    """
    arms = {
        stated.provider
        for stated in MODEL_CAPABILITIES.values()
        if stated.thinking == "omit_is_off"
    }
    assert arms == {"anthropic", "local"}


def test_at_most_one_accessor_answers_for_any_model() -> None:
    """The property ``ModelAgentProposer`` and ``StructuredMonitorCallerV3`` rely on.

    Both set all three directives from the table and comment that at most one is
    ever non-None. Asserted here over every row rather than trusted.
    """
    for model in MODEL_CAPABILITIES:
        answered = [
            directive
            for directive in (
                thinking_directive(model), reasoning_directive(model), think_directive(model)
            )
            if directive is not None
        ]
        assert len(answered) <= 1, f"{model} is answered for by more than one endpoint"


def test_an_accessor_only_ever_answers_for_an_arm_it_is_declared_for() -> None:
    for model, stated in MODEL_CAPABILITIES.items():
        for policy, accessor in (
            ("send_disabled", thinking_directive),
            ("send_effort_none", reasoning_directive),
            ("send_think_false", think_directive),
        ):
            if accessor(model) is None:
                continue
            assert stated.provider in POLICY_WIRE_PROVIDERS[policy], (
                f"{model} is a {stated.provider} model but was answered for by the "
                f"{policy} accessor"
            )


# --------------------------------------------------------------------------
# The Phase 2 case: a new provider that shares an existing policy value.
# --------------------------------------------------------------------------


def _table_with(monkeypatch: pytest.MonkeyPatch, model: str, row: ModelCapability) -> None:
    monkeypatch.setattr(
        caps, "MODEL_CAPABILITIES", {**MODEL_CAPABILITIES, model: row}, raising=True
    )


def test_a_new_provider_sharing_a_policy_value_cannot_be_added_silently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact shape Phase 2 will take, and it must not import.

    ``xai`` is spelled here as a provider the declaration does not name. Whether
    ``ModelProvider`` has grown the literal by then is beside the point: the check
    reads the row's provider against the value's declared owners, so a row whose
    arm is not declared for ``send_effort_none`` fails whether the arm is new or
    merely misfiled.
    """
    row = ModelCapability(
        accepts_sampling=False, thinking="send_effort_none", provider="xai"
    )
    _table_with(monkeypatch, "grok-5", row)
    with pytest.raises(CapabilityTableInvariant, match="declared as the wire shape of"):
        caps._require_policies_name_their_arm()


def test_widening_the_declaration_is_what_makes_it_legal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The escape hatch is a deliberate edit in the file that explains the cost.

    Two arms may share ``send_effort_none`` -- they take the same wire field --
    but only once somebody has said so where the accessor's docstring can be
    changed in the same edit. That is the whole difference between this and the
    coincidence it replaced.
    """
    row = ModelCapability(
        accepts_sampling=False, thinking="send_effort_none", provider="xai"
    )
    _table_with(monkeypatch, "grok-5", row)
    monkeypatch.setattr(
        caps,
        "POLICY_WIRE_PROVIDERS",
        {**POLICY_WIRE_PROVIDERS, "send_effort_none": frozenset({"openai", "xai"})},
        raising=True,
    )
    monkeypatch.setattr(
        caps, "ModelProvider", caps.Literal["anthropic", "openai", "local", "xai"], raising=True
    )
    caps._require_policies_name_their_arm()


def test_an_anthropic_row_cannot_borrow_the_local_off_switch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A misfiled existing arm fails the same way a new arm does.

    ``send_think_false`` is Ollama's boolean; sent at an Anthropic endpoint it is
    a parameter that endpoint does not have.
    """
    row = replace(MODEL_CAPABILITIES["claude-opus-5"], thinking="send_think_false")
    _table_with(monkeypatch, "claude-opus-5", row)
    with pytest.raises(CapabilityTableInvariant, match="declared as the wire shape of"):
        caps._require_policies_name_their_arm()


def test_a_policy_value_with_no_declaration_fails_rather_than_owning_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adding an off-switch spelling without saying whose it is is not a default.

    An undeclared value would silently behave like ``omit_is_off`` -- answered
    for by nobody -- which is the wrong failure: a value nobody emits is a model
    running at its provider's reasoning default while the table says a directive
    was chosen.
    """
    monkeypatch.setattr(
        caps,
        "POLICY_WIRE_PROVIDERS",
        {p: owners for p, owners in POLICY_WIRE_PROVIDERS.items() if p != "send_think_false"},
        raising=True,
    )
    with pytest.raises(CapabilityTableInvariant, match="must name every thinking policy"):
        caps._require_policies_name_their_arm()


def test_the_unlisted_model_default_is_held_to_the_same_rule() -> None:
    """A fail-closed default that acquired a directive would emit it for every unknown id."""
    owners = POLICY_WIRE_PROVIDERS[caps.UNKNOWN_MODEL.thinking]
    assert not owners, "the unknown-model default must emit no directive at any endpoint"
    assert thinking_directive("an-id-this-table-has-never-seen") is None
    assert reasoning_directive("an-id-this-table-has-never-seen") is None
    assert think_directive("an-id-this-table-has-never-seen") is None
