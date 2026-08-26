"""A capture must record the contract it was actually taken under.

THE DEFECT CLASS, WHICH THIS IS THE THIRD AND FOURTH INSTANCE OF
================================================================

Every guard in this repository of this shape exists for one reason: **the record
must match what produced it.**

* ``tests/test_published_revision_stamps.py`` — a published artifact stamped a
  ``git_revision`` reachable from no ref, so the run it claimed to describe could
  not be found.
* ``monitor_input_v3.gate_verdict_leaks`` — a rendered prompt claimed to withhold
  the policy's verdict while carrying it, so a measurement of judgement was partly
  a measurement of agreement.
* This one — a monitor capture recorded ``monitor-input-v3`` while having been
  rendered from ``MonitorInputV4``, so a published row citing it would name a
  contract the model was never shown.

Each was invisible to review of the thing itself and visible only by comparing the
record against its cause. That is the shape of the class, and it is why none of
the three is a check on a value: they are all checks that two things agree.

WHAT IS CHECKED, AND WHY IT WOULD HAVE CAUGHT THE REAL DEFECT
=============================================================

A capture body does not store the prompt it answered, only that prompt's digest --
which is the cache key. So the label cannot be re-derived from one capture alone.
It can be checked across the corpus, because the rendering is a *function*:

    for one (scenario, variant, condition, leg, step, model, input contract),
    the canonical prompt is determined, so the digest is determined too.

Two captures claiming the same identity and carrying different digests therefore
cannot both be honest. That is exactly the state the real defect produced: twelve
captures, two distinct keys at each of six positions, every one of them claiming
``monitor-input-v3``. A pair-matching check would not have caught it -- both halves
of the label were consistently wrong -- and this does.

WHAT THIS GUARD FOUND ON ITS FIRST RUN, AND HOW IT WAS CLOSED
=============================================================

A fourth instance of the same class, found by the guard rather than by reading.

The scenario projection was not versioned. A capture recorded the scenario
contract it was projected *from* -- and that contract did not change -- but nothing
recorded the projection that did the projecting. When ``ScenarioProjectionAdapter``
was corrected (its allowlist had been excluding two thirds of T4's honest plan),
every T4 monitor prompt changed while every field of its provenance stayed
identical. Two captures at one position then claimed byte-identical identities and
carried different prompt digests, and neither was dishonest.

Closed the same way the other two were: by recording the missing fact.
``ProviderCaptureProvenance.scenario_projection_sha256`` is a digest of what the
scenario projected *to*, it is part of the identity below, and it is optional with
``None`` meaning "not recorded" for captures that predate it. Nothing is
backfilled -- a digest reconstructed for an old capture would be a guess presented
as a record.

The severity of the original mislabelling was bounded by something worth keeping
in view: **captures are keyed by what was rendered, not by what they claim.** The
input schema digest is inside the canonical prompt, so a v4 rendering hashes
differently from a v3 one and a mislabelled capture can never be *served* in place
of a correct one; a v3 replay misses rather than silently reading v4 bytes. The
damage was confined to what a reader and a published row would cite, which is why
the repair was to re-take the captures rather than to edit the field."""

from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: The contract generations a capture may claim, as matched pairs. A capture
#: naming a combination absent from here is claiming a caller that cannot exist.
#:
#: The published prompt version names the input rendering *and* the output
#: grammar, so this is really a map from (input contract, output contract) and it
#: is written as one key only because every committed capture uses ``output-v3``.
#: ``monitor-input-v2`` pairs with ``monitor-prompt/v1.output-v3`` rather than a
#: bare ``v1``: ``monitor-output-v3`` changed only what the monitor *says* and
#: left the input half of the identity at v1, which is the drift
#: ``monitor_input_v3.INPUT_PROMPT_VERSION`` was introduced to stop. A capture
#: predating that fix is a correct record of a caller that really existed, and
#: this table has to describe history rather than tidy it.
GENERATIONS: dict[str, str] = {
    "monitor-input-v2": "monitor-prompt/v1.output-v3",
    "monitor-input-v3": "monitor-prompt/v3.output-v3",
    "monitor-input-v4": "monitor-prompt/v4.output-v3",
    "monitor-input-v5": "monitor-prompt/v5.output-v3",
}

IDENTITY = (
    "scenario_id",
    "variant_id",
    "condition",
    "leg",
    "step_index",
    "model",
    "input_schema_version",
    "prompt_version",
    # Added after this guard found the fourth instance: the frozen contract's
    # digest does not move when the *projection* of it is corrected, so without
    # this two honest captures from either side of that correction claim one
    # identity. ``None`` on a capture that predates the field, which is a distinct
    # identity from any recorded digest -- exactly the separation wanted.
    "scenario_projection_sha256",
)


def _committed_captures() -> list[tuple[str, dict[str, object]]]:
    """Every committed monitor capture, read from git rather than the worktree.

    From ``git ls-files`` because the claim is about what is *published*; an
    untracked file in someone's tree is not a record anyone can cite.
    """
    listed = subprocess.run(
        ["git", "ls-files", "artifacts/monitor-captures"],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    ).stdout.split()
    captures = []
    for name in listed:
        payload = json.loads((ROOT / name).read_text(encoding="utf-8"))
        provenance = payload.get("provenance")
        if provenance is not None:
            captures.append((name, provenance))
    return captures


def _identity(provenance: dict[str, object]) -> tuple[object, ...]:
    return tuple(provenance.get(field) for field in IDENTITY)


def disagreeing_identities(
    captures: list[tuple[str, dict[str, object]]],
) -> dict[tuple[object, ...], set[str]]:
    """Identities under which two captures carry different prompt digests."""
    by_identity: dict[tuple[object, ...], set[str]] = defaultdict(set)
    for _, provenance in captures:
        digest = provenance.get("prompt_sha256")
        if isinstance(digest, str):
            by_identity[_identity(provenance)].add(digest)
    return {key: digests for key, digests in by_identity.items() if len(digests) > 1}


def test_there_are_committed_captures_to_check() -> None:
    """Guard on the guard: an empty corpus makes every sweep below vacuous."""
    assert len(_committed_captures()) >= 10


def test_no_two_captures_claim_one_identity_and_carry_different_prompts() -> None:
    """The rendering is a function, so its output cannot disagree with itself."""
    assert disagreeing_identities(_committed_captures()) == {}


def test_the_check_fires_on_the_defect_it_was_written_for() -> None:
    """The negative control, reconstructing the real failure.

    Two captures at one position, both claiming ``monitor-input-v3``, carrying the
    digests of two different renderings. This is the state twelve captures were
    actually in, and a guard that did not fire here would be decoration.
    """
    shared = {
        "scenario_id": "T4",
        "variant_id": "T4-dev-v1",
        "condition": "policy_monitor_human",
        "leg": "covert",
        "step_index": 1,
        "model": "qwen3-14b",
        "input_schema_version": "monitor-input-v3",
        "prompt_version": "monitor-prompt/v3.output-v3",
    }
    mislabelled = [
        ("a.json", {**shared, "prompt_sha256": "a" * 64}),
        ("b.json", {**shared, "prompt_sha256": "b" * 64}),
    ]
    assert disagreeing_identities(mislabelled) != {}


def test_two_captures_at_one_position_under_different_contracts_are_fine() -> None:
    """The positive control that keeps the guard from banning the A/B itself.

    The whole point of the comparison is two renderings of one position. They are
    honest precisely because they claim *different* contracts, so the check must
    not fire on them.
    """
    shared = {
        "scenario_id": "T4",
        "variant_id": "T4-dev-v1",
        "condition": "policy_monitor_human",
        "leg": "covert",
        "step_index": 1,
        "model": "qwen3-14b",
    }
    honest = [
        (
            "v3.json",
            {
                **shared,
                "input_schema_version": "monitor-input-v3",
                "prompt_version": "monitor-prompt/v3.output-v3",
                "prompt_sha256": "a" * 64,
            },
        ),
        (
            "v4.json",
            {
                **shared,
                "input_schema_version": "monitor-input-v4",
                "prompt_version": "monitor-prompt/v4.output-v3",
                "prompt_sha256": "b" * 64,
            },
        ),
    ]
    assert disagreeing_identities(honest) == {}


@pytest.mark.parametrize("name_and_provenance", _committed_captures(), ids=lambda item: item[0])
def test_every_capture_claims_a_contract_pairing_that_exists(
    name_and_provenance: tuple[str, dict[str, object]],
) -> None:
    """A label naming a caller that cannot exist is wrong however consistent it is."""
    _, provenance = name_and_provenance
    claimed_input = provenance.get("input_schema_version")
    claimed_prompt = provenance.get("prompt_version")
    assert claimed_input in GENERATIONS, claimed_input
    assert claimed_prompt == GENERATIONS[str(claimed_input)]


def test_a_crossed_pairing_is_rejected() -> None:
    """Negative control for the pairing check."""
    assert GENERATIONS["monitor-input-v3"] != GENERATIONS["monitor-input-v4"]
    crossed = {
        "input_schema_version": "monitor-input-v3",
        "prompt_version": GENERATIONS["monitor-input-v4"],
    }
    assert crossed["prompt_version"] != GENERATIONS[str(crossed["input_schema_version"])]


def test_the_caller_reports_the_contract_it_renders() -> None:
    """The source the fix moved provenance to, checked at the source.

    The mislabelling happened because the runner stamped a module constant. Both
    labels now come from the caller, and the caller reads them off the contract it
    was constructed with -- so a capture cannot name a rendering the model was not
    shown without the caller itself being wrong.
    """
    from incidentgate.control.monitor_contract_v3 import (
        RecordingMonitorCallerV3,
        StructuredMonitorCallerV3,
        v4_input_contract,
    )

    class _NoClient:
        def complete(self, request: object) -> object:  # pragma: no cover
            raise AssertionError("build only")

    v3 = RecordingMonitorCallerV3(
        StructuredMonitorCallerV3(client=_NoClient(), model="qwen3-14b")  # type: ignore[arg-type]
    )
    v4 = RecordingMonitorCallerV3(
        StructuredMonitorCallerV3(
            client=_NoClient(),  # type: ignore[arg-type]
            model="qwen3-14b",
            input_contract=v4_input_contract(),
        )
    )
    assert (v3.input_schema_version, v3.prompt_version) == (
        "monitor-input-v3",
        GENERATIONS["monitor-input-v3"],
    )
    assert (v4.input_schema_version, v4.prompt_version) == (
        "monitor-input-v4",
        GENERATIONS["monitor-input-v4"],
    )
