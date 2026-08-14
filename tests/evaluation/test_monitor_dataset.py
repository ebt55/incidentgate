from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from incidentgate.evaluation.monitor_dataset import (
    HONEST_EPISODE_REGISTRY,
    SUPPORTED_INTERFERENCE,
    BenignMonitorSuite,
    benign_suite_digest,
    load_benign_monitor_suite,
)


def test_frozen_benign_suite_is_exactly_runnable_and_complete() -> None:
    suite = load_benign_monitor_suite()
    assert suite.schema_version == "monitor-benign-suite-v1"
    assert {case.split for case in suite.cases} == {"development", "calibration", "holdout"}
    assert {(case.scenario_id, case.interference_kind) for case in suite.cases} == {
        (scenario, kind)
        for scenario, kinds in SUPPORTED_INTERFERENCE.items()
        for kind in kinds
    }
    for case in suite.cases:
        assert case.episode_plan == HONEST_EPISODE_REGISTRY[case.scenario_id]
        assert case.expected_verdict == "allow"


def test_suite_digest_is_ordered_and_all_semantic_fields_bind() -> None:
    suite = load_benign_monitor_suite()
    assert benign_suite_digest(suite) == benign_suite_digest(suite)
    changed = suite.model_dump(mode="json")
    changed["cases"] = list(reversed(changed["cases"]))
    assert (
        benign_suite_digest(BenignMonitorSuite.model_validate(changed))
        != benign_suite_digest(suite)
    )
    changed = suite.model_dump(mode="json")
    changed["cases"][0]["seed"] += 1
    assert (
        benign_suite_digest(BenignMonitorSuite.model_validate(changed))
        != benign_suite_digest(suite)
    )


def test_file_contains_no_prompt_or_policy_text_and_rejects_unsupported_labels() -> None:
    path = Path(__file__).parents[2] / "scenarios" / "monitor" / "benign-v1.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert "prompt" not in json.dumps(raw).lower()
    assert "policy_text" not in json.dumps(raw).lower()
    raw["cases"][0]["interference_kind"] = "duplicate_delivery"
    with pytest.raises(ValidationError, match="not runnable"):
        BenignMonitorSuite.model_validate(raw)


@pytest.mark.parametrize(
    ("update",),
    [
        ({"case_id": "BM-999"},),
        ({"scenario_id": "T2"},),
        ({"seed": 1},),
        ({"split": "calibration"},),
        ({"variant_id": "T1-cal-v1", "case_id": None},),
    ],
)
def test_frozen_cell_rejects_identity_relabelling(update: dict[str, object]) -> None:
    from incidentgate.evaluation.monitor_dataset import FrozenMonitorCell

    values: dict[str, object] = {
        "scenario_id": "T1", "split": "development", "seed": 6100, "case_id": "BM-001"
    }
    values.update(update)
    with pytest.raises(ValidationError):
        FrozenMonitorCell.model_validate(values)
