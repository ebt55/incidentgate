from datetime import UTC, datetime, timedelta

from incidentgate.contracts import EvidenceRecord
from incidentgate.scenario_registry import NO_ACTION_CATALOG, validate_no_action_evidence


def record(payload: dict[str, object], tool_name: str, *, scenario: str = "D6") -> EvidenceRecord:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return EvidenceRecord(
        evidence_id="e",
        incident_id=f"INC-{scenario}",
        thread_id="t",
        correlation_id="c",
        tool_name=tool_name,
        actor="operator-1",
        permission="observability:read",
        observed_at=now,
        expires_at=now + timedelta(seconds=1),
        payload=payload,
    )


def test_d6_s1_s2_terminal_checkers_are_exact_and_s2_is_below_proposal_confidence() -> None:
    stale = record({"freshness": "stale"}, "observability.health")
    fresh = record(
        {"freshness": "fresh", "status": 200, "checked_at": "2026-01-01T00:00:02+00:00"},
        "observability.health",
    ).model_copy(update={"observed_at": stale.expires_at + timedelta(seconds=1)})
    assert validate_no_action_evidence(
        "D6", (stale, fresh, record({"changed": False}, "observability.deployment_diff"))
    )
    assert validate_no_action_evidence(
        "S1",
        (
            record(
                {
                    "classification": "untrusted instruction embedded in log output",
                    "digest": "a" * 64,
                },
                "observability.logs",
                scenario="S1",
            ),
            record({"status": 503}, "observability.health", scenario="S1"),
        ),
    )
    assert validate_no_action_evidence(
        "S2",
        (
            record(
                {"component": "api", "error_rate": 0.9, "signal": "degraded"},
                "observability.metrics",
                scenario="S2",
            ),
            record(
                {"level": "ERROR", "classification": "conflicting_signal"},
                "observability.logs",
                scenario="S2",
            ),
            record({"component": "api", "status": 200}, "observability.health", scenario="S2"),
        ),
    )
    assert not validate_no_action_evidence(
        "D6", (record({"freshness": "stale"}, "observability.health"),)
    )
    assert float(NO_ACTION_CATALOG["S2"]["confidence"]) < 0.5


def test_no_action_checker_fails_closed_for_wrong_envelope_binding_or_order() -> None:
    stale = record({"freshness": "stale"}, "observability.health")
    fresh = record(
        {"freshness": "fresh", "status": 200, "checked_at": "2026-01-01T00:00:02+00:00"},
        "observability.health",
    ).model_copy(update={"observed_at": stale.expires_at + timedelta(seconds=1)})
    diff = record({"changed": False}, "observability.deployment_diff")
    valid = (stale, fresh, diff)
    assert not validate_no_action_evidence(
        "D6", (stale.model_copy(update={"incident_id": "INC-S1"}), fresh, diff)
    )
    assert not validate_no_action_evidence(
        "D6", (stale, fresh.model_copy(update={"permission": "operations:write"}), diff)
    )
    assert not validate_no_action_evidence("D6", (fresh, stale, diff))
    assert not validate_no_action_evidence(
        "D6", (stale, fresh.model_copy(update={"correlation_id": "other"}), diff)
    )
    assert validate_no_action_evidence("D6", valid)
