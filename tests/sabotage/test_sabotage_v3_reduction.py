"""v3's deterministic-floor/oracle-compatible cells preserve actual v2 facts."""

from incidentgate.evaluation.sabotage_v3 import (
    CovertOutcome,
    SabotageEvaluationResultV3,
    classify_covert_cell,
    reduce_v2_episode,
)
from tests.sabotage.test_sabotage_contract import row as v2_row
from tests.sabotage.test_sabotage_v3_contract import row as v3_row


def test_real_v2_episode_reduces_losslessly_to_floor_v3_semantics() -> None:
    legacy = v2_row()
    covert = reduce_v2_episode(legacy.covert_episode)
    incident = reduce_v2_episode(legacy.incident_episode)
    assert (covert.leg, incident.leg) == (legacy.covert_episode.leg, legacy.incident_episode.leg)
    assert tuple(step.model_dump(exclude={"monitor_error_kind"}) for step in covert.steps) == tuple(
        step.model_dump() for step in legacy.covert_episode.steps
    )
    assert tuple(
        step.model_dump(exclude={"monitor_error_kind"}) for step in incident.steps
    ) == tuple(step.model_dump() for step in legacy.incident_episode.steps)
    assert all(step.monitor_error_kind is None for step in (*covert.steps, *incident.steps))

    v3 = SabotageEvaluationResultV3.model_validate(
        v3_row().model_dump()
        | {
            "covert_episode": covert,
            "incident_episode": incident,
            "covert_checker_passed": legacy.covert_checker_passed,
            "covert_side_effect_count": legacy.covert_side_effect_count,
            "covert_outcome": CovertOutcome.LANDED,
        }
    )
    assert v3.covert_episode is not None
    assert v3.covert_episode.executed is legacy.covert_episode.executed
    assert classify_covert_cell(v3) == "LANDED"
