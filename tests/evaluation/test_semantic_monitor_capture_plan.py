"""Characterization of the offline semantic-monitor capture audit."""

from __future__ import annotations

import os
from typing import Literal

import pytest

from incidentgate.evaluation.semantic_monitor_capture_plan import (
    AuditInstabilityRefusal,
    MonitorAuditObservation,
    MonitorAuditSource,
    ReachedRequestIdentity,
    audit_frozen_semantic_monitor_requests,
    build_capture_audit,
    compare_cold_observations,
)


def _request(token: str) -> ReachedRequestIdentity:
    return ReachedRequestIdentity(
        canonical_prompt_sha256=token * 64,
        request_schema_sha256="b" * 64,
        model="claude-opus-5",
        provider=None,
        max_tokens=1024,
        temperature=0,
        thinking=None,
        system_sha256="c" * 64,
        user_content_sha256="d" * 64,
        canonical_prompt='{"audit":"offline"}',
    )


def _source(
    *,
    split: Literal["development", "calibration", "holdout"] = "development",
    variant: str = "T1-dev-v1",
) -> MonitorAuditSource:
    return MonitorAuditSource(
        scenario_id="T1", split=split, seed=1, variant_id=variant, leg="incident"
    )


def _consulted(
    source: MonitorAuditSource, request: ReachedRequestIdentity
) -> MonitorAuditObservation:
    return MonitorAuditObservation(source, True, request, "fixture_no_call")


def test_cold_comparison_returns_byte_stable_observations() -> None:
    observations = (_consulted(_source(), _request("a")),)
    assert compare_cold_observations(observations, observations) == observations


def test_cold_comparison_refuses_instability() -> None:
    with pytest.raises(AuditInstabilityRefusal, match="not stable"):
        compare_cold_observations(
            (_consulted(_source(), _request("a")),),
            (_consulted(_source(), _request("e")),),
        )


def test_duplicate_and_cross_split_collisions_make_labelled_capture_unsafe() -> None:
    same_request = _request("a")
    audit = build_capture_audit(
        (
            _consulted(_source(split="development", variant="T1-dev-v1"), same_request),
            _consulted(_source(split="holdout", variant="T1-holdout-v1"), same_request),
        )
    )
    assert audit.labelled_cell_capture_safe is False
    assert len(audit.unique_requests) == 1
    assert len(audit.collision_groups) == len(audit.cross_split_collision_groups) == 1


@pytest.mark.integration
def test_frozen_runtime_audit_is_cold_stable_and_never_calls_a_provider() -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("semantic monitor capture audit requires local DATABASE_URL")
    audit = audit_frozen_semantic_monitor_requests(dsn)
    assert audit.stable is True
    assert {row.source.scenario_id for row in audit.observations} == {"T1", "T2", "T4"}
    benign_rows = tuple(row for row in audit.observations if row.source.case_id is not None)
    assert {row.source.case_id for row in benign_rows} == {
        "BM-001", "BM-002", "BM-003", "BM-004", "BM-005", "BM-006", "BM-007", "BM-008", "BM-009"
    }
    assert all(row.source.leg == "incident" for row in benign_rows)
    assert any(not row.consulted for row in audit.observations)
    assert all(
        row.invocation_kind == "fixture_no_call"
        for row in audit.observations
        if row.consulted
    )
    for case_id in ("BM-002", "BM-005", "BM-008"):
        assert any(
            row.source.case_id == case_id
            and row.source.leg == "incident"
            and row.source.step_index == 0
            and row.redelivered
            for row in audit.observations
        )
    assert all(
        row.redelivered is False
        for row in audit.observations
        if row.source.case_id in {"BM-001", "BM-003", "BM-004", "BM-006", "BM-007", "BM-009"}
    )
    assert audit.collision_groups
