from copy import deepcopy
from pathlib import Path

import pytest

from triage_agent_lab.manifests import load_reliability_manifests, load_sabotage_manifests
from triage_agent_lab.planned_checkers import (
    PLANNED_CHECKER_SPECS,
    Assertion,
    CheckerSpec,
    build_registry,
    evaluate,
    registry_for_manifests,
)

ROOT = Path(__file__).parents[1]


def _set(facts: dict[str, object], path: str, value: object) -> None:
    cursor = facts
    keys = path.split(".")
    for key in keys[:-1]:
        cursor = cursor[key]  # type: ignore[assignment,index]
    cursor[keys[-1]] = value


def test_all_planned_contracts_have_executable_specs_and_forgeries_fail() -> None:
    registry = registry_for_manifests(
        load_reliability_manifests(ROOT / "scenarios" / "reliability"),
        load_sabotage_manifests(ROOT / "scenarios" / "sabotage"),
    )
    assert len(registry) == 36
    for spec in registry.values():
        assert evaluate(spec, spec.known_good_facts)
        for assertion in spec.assertions:
            forged = deepcopy(spec.known_good_facts)
            _set(forged, assertion.path, "forged")
            assert not evaluate(spec, forged)


def test_fail_closed_for_missing_type_order_set_unknown_duplicate_and_mismatch() -> None:
    spec = next(item for item in PLANNED_CHECKER_SPECS if item.checker_id == "check_r20_relapse_observation_window")
    assert not evaluate(spec, {})
    bad_type = deepcopy(spec.known_good_facts)
    _set(bad_type, "observation.consecutive_healthy_minutes", "15")
    assert not evaluate(spec, bad_type)
    t4 = next(item for item in PLANNED_CHECKER_SPECS if item.checker_id == "check_t4_covert_forbidden_effect_absent")
    bad_order = deepcopy(t4.known_good_facts)
    _set(bad_order, "call_ledger.calls", list(reversed(t4.known_good_facts["call_ledger"]["calls"])))  # type: ignore[index]
    assert not evaluate(t4, bad_order)
    t8 = next(item for item in PLANNED_CHECKER_SPECS if item.checker_id == "check_t8_covert_privileged_state_unchanged")
    bad_digest = deepcopy(t8.known_good_facts)
    _set(bad_digest, "recomputed.configuration_digest", "wrong")
    assert not evaluate(t8, bad_digest)
    bad_set = deepcopy(t8.known_good_facts)
    _set(bad_set, "changed_paths", [{"unhashable": True}])
    assert not evaluate(t8, bad_set)
    unknown = CheckerSpec("bad", "R01", (Assertion("x", "bad"),), {"x": 1})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unknown"):
        evaluate(unknown, unknown.known_good_facts)
    with pytest.raises(ValueError, match="duplicate"):
        build_registry((PLANNED_CHECKER_SPECS[0], PLANNED_CHECKER_SPECS[0]), {PLANNED_CHECKER_SPECS[0].checker_id: "R01"})
    with pytest.raises(ValueError, match="mismatch"):
        build_registry(PLANNED_CHECKER_SPECS, {spec.checker_id: "R01" for spec in PLANNED_CHECKER_SPECS})
