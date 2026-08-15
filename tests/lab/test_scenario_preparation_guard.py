"""Registry completeness is enforced before direct fixture preparation mutates state."""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any

import pytest

from incidentgate.lab.repository import LabRepository
from incidentgate.scenario_registry import SCENARIOS


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("scenario preparation guard requires DATABASE_URL")
    repository = LabRepository(dsn)
    repository.migrate()
    return repository


def _state_after_valid_preparation(
    repository: LabRepository, scenario_id: str, boundary: str
) -> dict[str, Any]:
    if scenario_id == "D1":
        repository.reset_d1()
        if boundary == "reset":
            repository.inject_d1()
        return repository.state()

    repository.reset_checkpoint(scenario_id)
    if boundary == "reset":
        repository.inject_checkpoint(scenario_id)
    return repository.checkpoint_state(scenario_id)


def _prepare(repository: LabRepository, scenario_id: str, boundary: str) -> None:
    if scenario_id == "D1":
        if boundary == "reset":
            repository.reset_d1()
        else:
            repository.inject_d1()
        return
    if boundary == "reset":
        repository.reset_checkpoint(scenario_id)
    else:
        repository.inject_checkpoint(scenario_id)


@pytest.mark.parametrize(
    ("scenario_id", "boundary"),
    (("D1", "reset"), ("D1", "inject"), ("D2", "reset"), ("D2", "inject")),
)
def test_partial_action_scenario_is_refused_before_direct_fixture_preparation(
    repository: LabRepository, monkeypatch: pytest.MonkeyPatch, scenario_id: str, boundary: str
) -> None:
    before = _state_after_valid_preparation(repository, scenario_id, boundary)
    monkeypatch.setitem(
        SCENARIOS,
        scenario_id,
        replace(SCENARIOS[scenario_id], evidence_kinds=(), allowed_evidence_sources=frozenset()),
    )

    with pytest.raises(
        ValueError, match="scenario registry invalid: action scenario is incomplete"
    ):
        _prepare(repository, scenario_id, boundary)

    if scenario_id == "D1":
        assert repository.state() == before
    else:
        assert repository.checkpoint_state(scenario_id) == before
