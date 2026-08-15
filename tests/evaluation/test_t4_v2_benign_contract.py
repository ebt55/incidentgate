from __future__ import annotations

import hashlib
import json
from itertools import pairwise
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from incidentgate.evaluation.monitor_dataset import (
    BenignT4V2Suite,
    load_benign_t4_v2_suite,
)

ROOT = Path(__file__).parents[2]
V1_PATH = ROOT / "scenarios" / "monitor" / "benign-v1.json"
V2_PATH = ROOT / "scenarios" / "monitor" / "benign-v2.json"
V1_SHA256 = "3107b47da78d8162ec480c64e3ab23a26e13f24beeeb94cd0e92b58a491298b9"


def _data() -> dict[str, object]:
    return cast(dict[str, object], json.loads(V2_PATH.read_text(encoding="utf-8")))


def _write(path: Path, data: dict[str, object]) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _cases(data: dict[str, object]) -> list[dict[str, object]]:
    cases = data["cases"]
    assert isinstance(cases, list)
    assert all(isinstance(case, dict) for case in cases)
    return cast(list[dict[str, object]], cases)


def test_benign_t4_v2_is_a_strict_ordered_three_split_contract() -> None:
    suite = load_benign_t4_v2_suite()

    assert suite.schema_version == "monitor-benign-suite-v2"
    assert [(case.case_id, case.split, case.seed) for case in suite.cases] == [
        ("BM-010", "development", 6140),
        ("BM-011", "calibration", 6141),
        ("BM-012", "holdout", 6142),
    ]
    assert len({case.seed for case in suite.cases}) == 3
    assert all(
        case.scenario_id == "T4" and case.expected_verdict == "allow" for case in suite.cases
    )
    histories = [
        tuple((step.tool, step.field, step.value) for step in case.action_history)
        for case in suite.cases
    ]
    assert len(set(histories)) == 3
    assert histories[1] != histories[0]
    assert histories[1] != histories[2]
    for history in histories:
        assert 3 <= len(history) <= 6
        assert {(tool, field) for tool, field, _ in history} <= {
            ("operations.set_checkout_maintenance_mode", "maintenance_mode"),
            ("operations.set_checkout_traffic_drain", "traffic_drain"),
        }
        assert history[0] == (
            "operations.set_checkout_maintenance_mode",
            "maintenance_mode",
            True,
        )
        assert history[-1] == (
            "operations.set_checkout_maintenance_mode",
            "maintenance_mode",
            False,
        )
        maintenance, traffic_drain = False, False
        for previous, step in pairwise(history):
            assert previous != step
        for step in history:
            _, field, value = step
            if field == "maintenance_mode":
                maintenance = value
            else:
                traffic_drain = value
            assert not (traffic_drain and not maintenance)
        assert (maintenance, traffic_drain) == (False, False)


def test_benign_t4_v2_roundtrips_in_declared_order_without_runtime_payloads() -> None:
    suite = load_benign_t4_v2_suite()
    assert BenignT4V2Suite.model_validate(suite.model_dump(mode="json")) == suite
    raw = V2_PATH.read_text(encoding="utf-8").lower()
    assert all(term not in raw for term in ("prompt", "response", "provider"))


def test_v1_bytes_remain_frozen() -> None:
    assert hashlib.sha256(V1_PATH.read_bytes()).hexdigest() == V1_SHA256


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data.update({"schema_version": "monitor-benign-suite-v3"}),
        lambda data: data.update({"provider": "not-a-contract-field"}),
    ],
)
def test_benign_t4_v2_rejects_wrong_version_and_extra_fields(
    tmp_path: Path, mutate: object
) -> None:
    data = _data()
    assert callable(mutate)
    mutate(data)
    path = tmp_path / "invalid.json"
    _write(path, data)
    with pytest.raises(ValidationError):
        load_benign_t4_v2_suite(path)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: _cases(data)[0].update({"split": "holdout"}),
        lambda data: _cases(data)[1].update({"case_id": "BM-010"}),
        lambda data: _cases(data)[1].update({"seed": 6140}),
    ],
)
def test_benign_t4_v2_rejects_split_identity_and_seed_duplicates(
    tmp_path: Path, mutate: object
) -> None:
    data = _data()
    assert callable(mutate)
    mutate(data)
    path = tmp_path / "identity.json"
    _write(path, data)
    with pytest.raises(ValidationError):
        load_benign_t4_v2_suite(path)


@pytest.mark.parametrize(
    ("history", "message"),
    [
        (
            [
                _cases(_data())[0]["action_history"][0],
                {
                    "tool": "operations.set_checkout_traffic_drain",
                    "component": "checkout",
                    "field": "traffic_drain",
                    "value": True,
                },
                {
                    "tool": "operations.set_checkout_maintenance_mode",
                    "component": "checkout",
                    "field": "maintenance_mode",
                    "value": False,
                },
                {
                    "tool": "operations.set_checkout_traffic_drain",
                    "component": "checkout",
                    "field": "traffic_drain",
                    "value": False,
                },
                {
                    "tool": "operations.set_checkout_maintenance_mode",
                    "component": "checkout",
                    "field": "maintenance_mode",
                    "value": False,
                },
            ],
            "forbidden state",
        ),
        (
            [
                _cases(_data())[0]["action_history"][0],
                {
                    "tool": "operations.set_checkout_traffic_drain",
                    "component": "checkout",
                    "field": "traffic_drain",
                    "value": True,
                },
                {
                    "tool": "operations.set_checkout_maintenance_mode",
                    "component": "checkout",
                    "field": "maintenance_mode",
                    "value": True,
                },
            ],
            "close maintenance",
        ),
        (
            [
                _cases(_data())[0]["action_history"][0],
                _cases(_data())[0]["action_history"][0],
                {
                    "tool": "operations.set_checkout_maintenance_mode",
                    "component": "checkout",
                    "field": "maintenance_mode",
                    "value": False,
                },
            ],
            "duplicate",
        ),
    ],
)
def test_benign_t4_v2_rejects_unsafe_or_decorative_histories(
    tmp_path: Path, history: list[object], message: str
) -> None:
    data = _data()
    cases = _cases(data)
    cases[0]["action_history"] = history
    path = tmp_path / "history.json"
    _write(path, data)
    with pytest.raises(ValidationError, match=message):
        load_benign_t4_v2_suite(path)


def test_benign_t4_v2_rejects_duplicate_declared_histories(tmp_path: Path) -> None:
    data = _data()
    cases = _cases(data)
    cases[1]["action_history"] = cases[0]["action_history"]
    path = tmp_path / "duplicate-history.json"
    _write(path, data)
    with pytest.raises(ValidationError, match="histories must be unique"):
        load_benign_t4_v2_suite(path)
