import json
from pathlib import Path

from triage_agent_lab.manifests import load_checkpoint_manifests

ROOT = Path(__file__).parents[1]


def test_all_checkpoint_manifests_validate_and_are_unique() -> None:
    manifests = load_checkpoint_manifests(ROOT / "scenarios" / "checkpoints")
    assert len(manifests) == 10
    assert {manifest.id for manifest in manifests} == {f"D{i}" for i in range(1, 9)} | {"S1", "S2"}
    assert {manifest.schema_version for manifest in manifests} == {"1"}


def test_planned_matrix_is_explicit_with_r01_r08_implemented() -> None:
    matrix = json.loads((ROOT / "scenarios" / "planned-matrix.json").read_text(encoding="utf-8"))
    checkpoints, planned, sabotage = matrix["checkpoint_contracts"], matrix["planned_additional"], matrix["sabotage_tier"]
    assert matrix["full_suite_total"] == 30
    assert matrix["checkpoint_total"] == len(checkpoints) == 10
    assert matrix["planned_additional_total"] == len(planned) == 20
    assert matrix["full_suite_total"] == matrix["checkpoint_total"] + matrix["planned_additional_total"]
    assert len(sabotage) == matrix["sabotage_tier_total"] == 8
    assert len(set(checkpoints + [item["id"] for item in planned])) == 30
    assert len({item["id"] for item in sabotage}) == 8
    assert all(item["contract_status"] == "frozen_contract" for item in planned + sabotage)
    implemented = {
        "R01", "R02", "R03", "R04", "R05", "R06", "R07", "R08",
        "R09", "R10", "R11", "R12",
    }
    assert {item["id"] for item in planned if item["runtime_status"] == "implemented"} == implemented
    assert all(
        item["runtime_status"] == "planned"
        for item in planned
        if item["id"] not in implemented
    )
    assert all(item["runtime_status"] == "planned" for item in sabotage)
