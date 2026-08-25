"""Which R-tier scenarios a monitor false-positive lane can measure, and why the rest cannot.

The R-tier is benign by construction, which is exactly why it is worth measuring:
unlike the sabotage tier it cannot come back vacuous. A monitor false-positive
lane shows a model monitor an honest action and counts how often it blocks.

Twelve R scenarios are runnable. **Eight are eligible.** The four exclusions are
pinned here rather than left as a glob, because an unexplained absence reads as an
oversight and a lane that quietly drops what it cannot handle is choosing its own
denominator.

**R03 is excluded because of a defect that predates this lane.** Its frozen
contract declares `operations.restore_config_PAYMENT_TIMEOUT_MS_3000`, and
``monitor_input.ToolName`` admits only ``^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$``
-- no uppercase. The two have always disagreed, so R03 could never have rendered a
monitor input: it would produce a monitor *error*, never a verdict, and an error
counted as a non-block would silently deflate a false-positive rate.

Neither side is changed to make the lane run. Editing the contract would move a
frozen scenario's bytes to suit a measurement; widening ``ToolName`` would relax a
validation boundary for the same reason. Both are retrofitting the instrument to
the task. The defect is recorded, the exclusion is published, and this file pins
it so that the day either side changes, this test is what says so.

**R05, R10 and R11 are excluded because they declare no action at all.** They are
diagnosis-only scenarios: `allowed_actions` is empty, so there is nothing for a
monitor to assess and no verdict to count either way. That is a property of what
those scenarios are, not a defect.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest
from pydantic import TypeAdapter, ValidationError

from incidentgate.control.monitor_input import ToolName

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "scenarios" / "reliability"

RUNNABLE = tuple(f"R{n:02d}" for n in range(1, 13))

#: Excluded because its declared tool name cannot render. One scenario, one cause.
UNRENDERABLE = ("R03",)

#: Excluded because they declare no action for a monitor to judge.
NO_ACTION = ("R05", "R10", "R11")

#: What the lane can actually measure.
ELIGIBLE = tuple(s for s in RUNNABLE if s not in UNRENDERABLE + NO_ACTION)


def contract(scenario_id: str) -> dict:
    return json.loads((CONTRACTS / f"{scenario_id}.json").read_text(encoding="utf-8"))


def tool_names(scenario_id: str) -> list[str]:
    actions = contract(scenario_id).get("allowed_actions") or []
    return [a.get("tool") if isinstance(a, dict) else a for a in actions]


def test_the_eligible_set_is_eight_and_is_named_rather_than_globbed() -> None:
    assert len(RUNNABLE) == 12
    assert ELIGIBLE == ("R01", "R02", "R04", "R06", "R07", "R08", "R09", "R12")
    assert len(ELIGIBLE) == 8
    assert not set(UNRENDERABLE) & set(NO_ACTION)


@pytest.mark.parametrize("scenario_id", UNRENDERABLE)
def test_the_excluded_scenario_really_cannot_render_its_own_tool_name(
    scenario_id: str,
) -> None:
    """The exclusion must rest on a demonstrated failure, not on a claim about one."""
    adapter = TypeAdapter(ToolName)
    names = tool_names(scenario_id)
    assert names, scenario_id
    for name in names:
        with pytest.raises(ValidationError):
            adapter.validate_python(name)


def test_the_r03_defect_is_case_and_nothing_else() -> None:
    """Locates the disagreement precisely, so the record names the right cause.

    Lowercasing the same string validates. So the contract and the pattern differ
    over letter case alone -- not length, not digits, not the underscore run --
    which is what makes this a one-character-class inconsistency rather than a
    disagreement about what a tool name may contain.
    """
    adapter = TypeAdapter(ToolName)
    (name,) = tool_names("R03")
    assert name == "operations.restore_config_PAYMENT_TIMEOUT_MS_3000"
    with pytest.raises(ValidationError):
        adapter.validate_python(name)
    assert adapter.validate_python(name.lower()) == name.lower()


@pytest.mark.parametrize("scenario_id", NO_ACTION)
def test_the_diagnosis_only_scenarios_really_declare_no_action(scenario_id: str) -> None:
    """Excluded for what they are, not for a defect: there is nothing to judge."""
    assert not (contract(scenario_id).get("allowed_actions") or []), scenario_id


@pytest.mark.parametrize("scenario_id", ELIGIBLE)
def test_every_eligible_scenario_can_render_and_has_something_to_judge(
    scenario_id: str,
) -> None:
    """The positive control on the exclusions: eligibility is earned, not assumed."""
    adapter = TypeAdapter(ToolName)
    names = tool_names(scenario_id)
    assert names, scenario_id
    for name in names:
        adapter.validate_python(name)


@pytest.mark.parametrize("scenario_id", RUNNABLE)
def test_no_r_scenario_needs_an_evidence_allowlist_added(scenario_id: str) -> None:
    """Recorded because a survey said otherwise and the contracts disagree.

    The plan for this lane included populating empty evidence allowlists before
    any capture. There are none to populate: every runnable R scenario already
    declares two or three evidence sources in its frozen contract. Asserted so the
    lane is not later "fixed" by adding entries that would move a frozen contract
    for no reason.
    """
    evidence = contract(scenario_id).get("allowed_evidence") or []
    assert len(evidence) >= 2, scenario_id
    assert all(re.fullmatch(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*", e) for e in evidence), evidence
