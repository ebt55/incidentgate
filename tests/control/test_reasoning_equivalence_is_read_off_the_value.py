"""A provenance field must answer the question it names, not a nearby one.

``reasoning_equivalence`` is published in every capture's ``request_envelope``
and says whether this arm's reasoning setting can be compared with the other
arms'. Three transports computed it from *whether a directive was sent*:

    "not_set:provider_default_applies" if directive is None else "explicitly_off:..."

Sent and off are not the same fact. ``think=True`` is a directive, and it turns
reasoning on: the descriptor would have carried ``reasoning_control=think=true``
beside ``reasoning_equivalence=explicitly_off`` in the same object. Every clause
of that code was true of the values actually sent, and the conclusion did not
follow from the test it ran -- this repository's recurring defect shape, and the
reason the branch now lives in one function with a name that states its subject.

**Latent, not live.** Every directive this lab sends today is off, so no
committed capture carries a wrong value and none is being re-taken.
:func:`test_no_committed_capture_moved_a_byte` is the proof of that rather than
the assertion of it: it rebuilds each published envelope's equivalence claim from
the ``reasoning_control`` recorded beside it, through the code as it stands now.

Two properties:

* the claim is read off the directive's value, on all three arms;
* the two published strings are still produced for the values that produced them,
  so fixing the branch rewrote nothing.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from incidentgate.control.local_weights import ollama_envelope_descriptor
from incidentgate.control.model_capabilities import (
    REASONING_EXPLICITLY_ON,
    REASONING_NOT_SET,
    reasoning_equivalence,
)
from incidentgate.control.model_proposal import anthropic_envelope_descriptor
from incidentgate.control.openai_completion import openai_envelope_descriptor

ROOT = pathlib.Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "artifacts"

#: The exact strings sitting in committed captures. Written out here rather than
#: imported, so a rename in the source is a visible edit to this file too.
ANTHROPIC_OFF = "explicitly_off:analogous_to_the_other_arm_not_identical"
OPENAI_OFF = "explicitly_off:analogous_to_the_other_arm_not_identical"
LOCAL_OFF = "explicitly_off:analogous_to_the_other_arms_not_identical"


def _anthropic(directive: dict[str, str] | None) -> dict[str, str]:
    return anthropic_envelope_descriptor(directive)


def _openai(directive: dict[str, str] | None) -> dict[str, str]:
    return openai_envelope_descriptor(directive)


def _local(directive: bool | None) -> dict[str, str]:
    return ollama_envelope_descriptor(directive, None, "qwen3-14b")


# (arm label, descriptor, off directive, an on directive, that arm's off string)
ARMS: list[tuple[str, Any, Any, Any, str]] = [
    ("anthropic", _anthropic, {"type": "disabled"}, {"type": "enabled"}, ANTHROPIC_OFF),
    ("openai", _openai, {"effort": "none"}, {"effort": "medium"}, OPENAI_OFF),
    ("local", _local, False, True, LOCAL_OFF),
]
ARM_IDS = [arm[0] for arm in ARMS]


@pytest.mark.parametrize(("_arm", "descriptor", "off", "_on", "off_label"), ARMS, ids=ARM_IDS)
def test_an_off_directive_still_publishes_the_string_it_always_published(
    _arm: str, descriptor: Any, off: Any, _on: Any, off_label: str
) -> None:
    """The positive control, and the half that must not move: these bytes are published."""
    assert descriptor(off)["reasoning_equivalence"] == off_label


@pytest.mark.parametrize(("_arm", "descriptor", "_off", "on", "off_label"), ARMS, ids=ARM_IDS)
def test_a_directive_that_is_not_off_is_never_called_explicitly_off(
    _arm: str, descriptor: Any, _off: Any, on: Any, off_label: str
) -> None:
    """The defect, driven through each of the three code paths that carried it."""
    claim = descriptor(on)["reasoning_equivalence"]
    assert claim == REASONING_EXPLICITLY_ON
    assert claim != off_label
    assert "explicitly_off" not in claim


@pytest.mark.parametrize(("_arm", "descriptor", "_off", "_on", "_label"), ARMS, ids=ARM_IDS)
def test_sending_nothing_remains_its_own_third_answer(
    _arm: str, descriptor: Any, _off: Any, _on: Any, _label: str
) -> None:
    """"Omitted" is not a synonym for either of the other two.

    An omitted parameter runs at whatever the provider defaults to, and this lab
    has measured that those defaults differ per provider and per local model. The
    arm can claim nothing in either direction.
    """
    claim = descriptor(None)["reasoning_equivalence"]
    assert claim == REASONING_NOT_SET
    assert "explicitly" not in claim


@pytest.mark.parametrize(("_arm", "descriptor", "off", "on", "_label"), ARMS, ids=ARM_IDS)
def test_the_two_reasoning_fields_of_one_descriptor_cannot_contradict_each_other(
    _arm: str, descriptor: Any, off: Any, on: Any, _label: str
) -> None:
    """The shape of the bug, asserted as a property of the object rather than a value.

    ``reasoning_control`` says what went on the wire and ``reasoning_equivalence``
    says what that means. A descriptor claiming reasoning was explicitly off while
    its own control field records the on value is self-contradicting, and that is
    precisely the object the old branch would have produced.
    """
    for directive, is_off in ((off, True), (on, False)):
        rendered = descriptor(directive)
        control, claim = rendered["reasoning_control"], rendered["reasoning_equivalence"]
        assert "omitted" not in control, control
        assert claim.startswith("explicitly_off:") is is_off, (control, claim)


def test_the_helper_treats_none_as_a_third_state_rather_than_as_on() -> None:
    """Asserted at the shared function, because a bool would have collapsed the three."""
    assert reasoning_equivalence(off=None, off_label=ANTHROPIC_OFF) == REASONING_NOT_SET
    assert reasoning_equivalence(off=True, off_label=ANTHROPIC_OFF) == ANTHROPIC_OFF
    assert reasoning_equivalence(off=False, off_label=ANTHROPIC_OFF) == REASONING_EXPLICITLY_ON


# --------------------------------------------------------------------------
# The published half: nothing that was already written down changed.
# --------------------------------------------------------------------------

#: How each arm's ``reasoning_control`` string maps back to the directive that
#: produced it, so a committed envelope can be re-derived rather than trusted.
_REBUILD: dict[str, Any] = {
    "anthropic": {
        "thinking:omitted": (_anthropic, None),
        "thinking.type=disabled": (_anthropic, {"type": "disabled"}),
    },
    "openai": {
        "reasoning_effort:omitted:provider_default_applies": (_openai, None),
        "reasoning_effort=none": (_openai, {"effort": "none"}),
    },
    "local": {
        "think:omitted:model_default_applies": (_local, None),
        "think=false": (_local, False),
        "think=true": (_local, True),
    },
}


def _published_envelopes() -> list[dict[str, Any]]:
    """Every recorded envelope in the committed artifacts, however deeply nested.

    Envelopes appear both as objects and as JSON strings inside a field, because
    a couple of provenance fields carry canonical JSON. Both are walked.
    """
    found: list[dict[str, Any]] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if "reasoning_equivalence" in node:
                found.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str) and "reasoning_equivalence" in node:
            try:
                walk(json.loads(node))
            except ValueError:
                pass

    for path in sorted(ARTIFACTS.rglob("*.json")):
        try:
            walk(json.loads(path.read_text(encoding="utf-8")))
        except ValueError:
            continue
    return found


def test_there_are_published_envelopes_to_check() -> None:
    """Guard on the guard: an empty sweep would make the check below vacuous."""
    envelopes = _published_envelopes()
    assert len(envelopes) >= 16
    claims = {envelope["reasoning_equivalence"] for envelope in envelopes}
    # Both published outcomes must be represented, or the sweep only proves one.
    assert REASONING_NOT_SET in claims
    assert any(claim.startswith("explicitly_off:") for claim in claims)


def test_no_committed_capture_moved_a_byte() -> None:
    """Each published claim is re-derived from the control field recorded beside it.

    Not a snapshot of expected values: it runs the current code against the
    setting each capture says it sent, so it fails if the mapping from setting to
    claim ever drifts from what the artifacts already assert.
    """
    for envelope in _published_envelopes():
        provider = envelope["provider"]
        control = envelope["reasoning_control"]
        descriptor, directive = _REBUILD[provider][control]
        rebuilt = descriptor(directive)
        assert rebuilt["reasoning_control"] == control, envelope
        assert rebuilt["reasoning_equivalence"] == envelope["reasoning_equivalence"], envelope
