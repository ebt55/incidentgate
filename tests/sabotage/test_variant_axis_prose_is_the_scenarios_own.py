"""A table may not explain its own collapse with another scenario's mechanism.

The variant-axis section fires on any scenario whose variants issue identical
covert legs, and it used to carry T4's explanation hardcoded: drains, maintenance
windows, a sequence-conformance whitelist, and "no free parameter for a seed to
select, as T1's ``source_ref`` is". All of that is true of T4 and of nothing else.

So publishing any other collapsing scenario -- T7 is the next candidate -- would
have printed T4's sentences as its own: a description of an assembly across calls,
naming T4's capabilities, in an artifact whose entire purpose is to state what
*was* measured.

This is the same defect class ``covert_no_store_reason`` already exists for, and
its comment says so in the same words: "Publishing T2 with T4's sentence would have
described a single prohibited call as an assembly across calls -- a plainly false
statement about what was measured."

Two properties, and the second is what makes the first safe to have made:

* a scenario that states no reason prints **no** reason, rather than a borrowed one;
* every published matrix still renders byte-identically, so moving the prose to
  data did not move a single published byte.
"""

from __future__ import annotations

import dataclasses
import pathlib

import pytest

from incidentgate.evaluation.sabotage import SabotageRawEnvelope
from incidentgate.evaluation.sabotage_matrix import (
    SABOTAGE_SCENARIOS,
    _render_variant_axis,
    load_scenario,
    render_markdown,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
PUBLISHED = sorted((ROOT / "artifacts" / "sabotage-matrix").rglob("sabotage-matrix.json"))

#: Words that belong to T4's mechanism and to no other scenario's.
T4_ONLY = ("maintenance window", "traffic drain", "sequence-conformance", "source_ref")


def _envelope(path: pathlib.Path) -> SabotageRawEnvelope:
    return SabotageRawEnvelope.model_validate_json(path.read_text(encoding="utf-8"))


def test_there_are_published_matrices_to_check() -> None:
    """Guard on the guard: an empty sweep would make everything below vacuous."""
    assert len(PUBLISHED) >= 4


@pytest.mark.parametrize("path", PUBLISHED, ids=lambda p: p.parent.name or "root")
def test_every_published_matrix_still_renders_byte_identically(path: pathlib.Path) -> None:
    """Moving prose from a literal into scenario data moved no published byte."""
    published = (ROOT / str(path).replace(".json", ".md")).read_text(encoding="utf-8")
    assert render_markdown(_envelope(path)) == published


def test_t4_still_explains_its_own_collapse() -> None:
    """The positive control. A fix that silenced everyone would pass the test below."""
    path = next(p for p in PUBLISHED if p.parent.name == "T4")
    rendered = "\n".join(_render_variant_axis(_envelope(path), load_scenario("T4")))
    assert "Why the variants are identical" in rendered
    assert "no covert variant could have distinguished this monitor" in rendered
    assert "source_ref" in rendered


def test_a_scenario_that_states_no_reason_borrows_none() -> None:
    """The defect, driven through the code path that had it.

    T4's own envelope rendered against a scenario with both fields cleared stands
    in for the next collapsing scenario to be published. It must disclose the
    collapse and explain nothing.
    """
    path = next(p for p in PUBLISHED if p.parent.name == "T4")
    silent = dataclasses.replace(
        load_scenario("T4"), variant_collapse_reason="", variant_axis_monitor_blindness=""
    )
    rendered = "\n".join(_render_variant_axis(_envelope(path), silent))
    for word in T4_ONLY:
        assert word not in rendered, word
    # The observation is measured from the rows and survives; only the borrowed
    # explanation goes. A table that discloses nothing would be a worse fix.
    assert "degenerate" in rendered
    assert "replicates" in rendered


def test_no_scenario_carries_another_scenarios_mechanism() -> None:
    """Swept across every scenario, not only the ones published today."""
    for scenario_id in SABOTAGE_SCENARIOS:
        scenario = load_scenario(scenario_id)
        prose = f"{scenario.variant_collapse_reason} {scenario.variant_axis_monitor_blindness}"
        if scenario_id == "T4":
            continue
        for word in T4_ONLY:
            assert word not in prose, (scenario_id, word)


def test_the_fields_default_to_silence() -> None:
    """A new scenario says nothing until someone writes its reason down."""
    fields = {f.name: f for f in dataclasses.fields(load_scenario("T4"))}
    assert fields["variant_collapse_reason"].default == ""
    assert fields["variant_axis_monitor_blindness"].default == ""


# --------------------------------------------------------------------------
# The partial-collapse branch had the same defect, and needed the same fix.
# --------------------------------------------------------------------------

#: Words belonging to T1's and T2's mechanism -- a parameter derived from seed
#: parity -- and to no other scenario's.
PARITY_ONLY = ("seed parity", "consecutive integers")


@pytest.mark.parametrize(
    ("scenario_id", "folder"), [("T1", "sabotage-matrix"), ("T2", "T2")]
)
def test_t1_and_t2_still_explain_their_own_collision(scenario_id: str, folder: str) -> None:
    """Positive control for the partial branch, as T4 is for the total branch.

    Both derive their one free parameter from ``seed % 2`` -- T1's ``source_ref``
    and T2's ``covert_target`` -- so seed parity really is their cause and each
    must still say so.
    """
    path = next(p for p in PUBLISHED if p.parent.name == folder)
    rendered = "\n".join(_render_variant_axis(_envelope(path), load_scenario(scenario_id)))
    assert "seed parity" in rendered
    assert "development and holdout" in rendered
    assert f"{scenario_id}-holdout-v1" in rendered


def test_a_partially_collapsing_scenario_with_no_reason_borrows_none() -> None:
    """T2's envelope against a silent scenario stands in for the next one published."""
    path = next(p for p in PUBLISHED if p.parent.name == "T2")
    silent = dataclasses.replace(load_scenario("T2"), variant_collapse_reason="")
    rendered = "\n".join(_render_variant_axis(_envelope(path), silent))
    for word in PARITY_ONLY:
        assert word not in rendered, word
    # The collision is still named, and which pair collides is still the finding.
    assert "That promise does not hold here" in rendered
    assert "T2-holdout-v1" in rendered


def test_neither_branch_can_borrow_from_the_other() -> None:
    """T4 explains a total collapse, T1 and T2 a partial one, and the field is the
    same field -- so a scenario cannot end up printing the wrong one of the two."""
    t4 = load_scenario("T4").variant_collapse_reason
    t2 = load_scenario("T2").variant_collapse_reason
    assert "seed parity" in t2 and "seed parity" not in t4
    assert "maintenance window" in t4 and "maintenance window" not in t2
