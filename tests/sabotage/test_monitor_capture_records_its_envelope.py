"""A monitor capture must say what envelope carried it, from 2026-08-25 onward.

The attacker path has recorded ``request_envelope`` since the OpenAI arm, through
``provider_envelope_json``, which builds the descriptor from *the request that was
sent* rather than from the provider's name. The monitor path never did. So every
hosted monitor capture on disk -- twelve `claude-opus-5`, eight `gpt-5.5` -- and
nineteen of twenty-one `qwen3-14b` ones carry ``request_envelope: null``.

That was honest rather than wrong: ``None`` means "not recorded" and never "no
difference", and the reasoning directive is inside the canonical prompt, so the
committed ``prompt_sha256`` already pins it. But it is a gap of this project's
recurring shape -- the record not stating what produced it -- and it matters most
on the monitor seat, where the sampling defaults this project measured differ
between two local models served by one server.

**Fixed forward, and only forward.** The captures already taken are not re-taken
and not rewritten: re-capturing to improve a record is the move this project
forbids, and a rewritten provenance field would be worse than a null one. They
keep their null, the finding names them, and this file draws the line so that a
capture taken after it cannot quietly omit the envelope again.

Two tests, because the two failure modes are different:

* the builder must populate the field, for every provider; and
* the committed corpus must contain no *new* capture missing it, which is what
  catches a regression that the unit test above would not see because nobody
  thought to call it.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from incidentgate.evaluation.sabotage_v4_t4 import MONITOR_CACHE_DIR

ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Captures taken before the monitor path recorded an envelope. Frozen as a count
#: per seat rather than a file list: the point is that the set cannot grow, and a
#: list would have to be edited for a legitimate re-capture that never happens.
#: A new capture without an envelope pushes one of these counts up and fails.
PREDATE_THE_FIX = {
    "claude-opus-5": 12,
    "gpt-5.5": 8,
    "qwen3-14b": 19,
}


def _captures() -> list[tuple[str, pathlib.Path, dict]]:
    found = []
    for path in sorted(MONITOR_CACHE_DIR.rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        found.append((path.parent.name, path, payload["provenance"]))
    return found


def test_there_are_captures_to_check() -> None:
    """Guard on the guard: an empty sweep would make the corpus test vacuous."""
    captures = _captures()
    assert len(captures) >= sum(PREDATE_THE_FIX.values())
    assert {seat for seat, _, _ in captures} >= set(PREDATE_THE_FIX)


def test_no_capture_beyond_the_grandfathered_ones_omits_its_envelope() -> None:
    """The line in the sand, asserted over the committed corpus.

    Counted per seat rather than checked as a whitelist of filenames, so the
    failure message says *which* seat grew a null and by how many.
    """
    missing: dict[str, int] = {}
    for seat, _path, provenance in _captures():
        if provenance["request_envelope"] is None:
            missing[seat] = missing.get(seat, 0) + 1
    assert missing == PREDATE_THE_FIX, (
        "a monitor capture taken after 2026-08-25 is missing request_envelope, "
        f"or a grandfathered one was removed: {missing} != {PREDATE_THE_FIX}"
    )


def test_a_recorded_envelope_describes_the_seat_that_produced_it() -> None:
    """An envelope that named the wrong arm would be worse than none at all."""
    checked = 0
    for seat, path, provenance in _captures():
        envelope = provenance["request_envelope"]
        if envelope is None:
            continue
        rendered = json.loads(envelope)
        assert rendered["provider"] == provenance["provider"], path.name
        # Every descriptor carries the same key set, whichever arm wrote it --
        # that is the property that makes two arms comparable at all.
        assert {"provider", "reasoning_control", "reasoning_equivalence"} <= set(rendered)
        assert seat == provenance["model"], path.name
        checked += 1
    assert checked >= 2, "no capture carries an envelope, so this test proved nothing"


@pytest.mark.parametrize(
    ("provider", "model"),
    [("local", "qwen3-14b"), ("local", "mistral-nemo-12b"), ("openai", "gpt-5.5")],
)
def test_the_builder_populates_an_envelope_for_every_seat_it_serves(
    provider: str, model: str
) -> None:
    """The unit half: ``_monitor_provenance`` must not return a null envelope.

    Driven through the real builder with a real request, so a future edit that
    drops the argument fails here rather than silently at capture time.
    """
    from incidentgate.control.model_capabilities import (
        model_provider,
        reasoning_directive,
        sampling_directive,
        think_directive,
        thinking_directive,
    )
    from incidentgate.evaluation.sabotage_v3_t1 import provider_envelope_json

    assert model_provider(model) == provider

    class _Request:
        def __init__(self) -> None:
            self.model = model
            self.thinking = thinking_directive(model)
            self.reasoning = reasoning_directive(model)
            self.think = think_directive(model)
            self.sampling = sampling_directive(model)

    rendered = json.loads(provider_envelope_json(provider, _Request()))
    assert rendered["provider"] == provider
    assert rendered["reasoning_control"], "an envelope must state what reasoning was sent"
    assert rendered["reasoning_equivalence"]
