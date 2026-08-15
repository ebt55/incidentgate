"""Characterization of the offline semantic-monitor capture audit."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal

import pytest

from incidentgate.evaluation.monitor_request_bindings import (
    MonitorRequestBindingEntry,
    MonitorRequestBindingRefusal,
    MonitorRequestBindingWorklist,
    MonitorRequestIdentity,
    build_verified_worklist,
    load_worklist,
    worklist_json_bytes,
)
from incidentgate.evaluation.sabotage_matrix import load_scenario
from incidentgate.evaluation.semantic_monitor_capture_plan import (
    AuditInstabilityRefusal,
    MonitorAuditObservation,
    MonitorAuditSource,
    ReachedRequestIdentity,
    audit_frozen_semantic_monitor_requests,
    build_capture_audit,
    compare_cold_observations,
)
from incidentgate.lab.repository import LabRepository


def _request(token: str) -> ReachedRequestIdentity:
    user = f"offline-user-{token}"
    canonical = (
        '{"input_schema_sha256":"e' + ("e" * 63) + '","max_tokens":1024,'
        '"model":"claude-opus-5","output_schema_sha256":"f'
        + ("f" * 63)
        + '","system":"offline-system","temperature":0,"thinking":null,'
        '"prompt_version":"monitor/v2","user":"' + user + '"}'
    )
    return ReachedRequestIdentity(
        canonical_prompt_sha256=sha256(canonical.encode()).hexdigest(),
        request_schema_sha256="b" * 64,
        model="claude-opus-5",
        provider=None,
        max_tokens=1024,
        temperature=0,
        thinking=None,
        system_sha256=sha256(b"offline-system").hexdigest(),
        user_content_sha256=sha256(user.encode()).hexdigest(),
        canonical_prompt=canonical,
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


def _worklist(
    first: tuple[MonitorAuditObservation, ...], second: tuple[MonitorAuditObservation, ...]
) -> MonitorRequestBindingWorklist:
    return build_verified_worklist(
        first,
        second,
        worklist_id="t4-v2-monitor-worklist",
        source_git_revision="0" * 40,
        frozen_at=datetime(2026, 8, 16, tzinfo=UTC),
    )


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


def test_verified_worklist_preserves_shared_membership_without_raw_text() -> None:
    same = _request("a")
    observations = (
        _consulted(_source(split="development", variant="T1-dev-v1"), same),
        _consulted(_source(split="holdout", variant="T1-holdout-v1"), same),
    )
    worklist = _worklist(observations, observations)
    assert len(worklist.entries) == 1
    entry = worklist.entries[0]
    assert entry.capture_phase == "post_threshold_freeze"
    assert len(entry.sources) == 2
    assert entry.capture_witness == entry.sources[0]
    encoded = worklist_json_bytes(worklist)
    assert b"offline-system" not in encoded and b"offline-user" not in encoded
    assert MonitorRequestBindingWorklist.model_validate_json(encoded) == worklist
    with pytest.raises(ValueError, match="Extra inputs"):
        MonitorRequestBindingWorklist.model_validate(
            {**worklist.model_dump(mode="json"), "raw_response": "not allowed"}
        )


def test_worklist_loader_roundtrips_and_refuses_invalid_paths(tmp_path: Path) -> None:
    worklist = _worklist(
        (_consulted(_source(), _request("a")),), (_consulted(_source(), _request("a")),)
    )
    artifact = tmp_path / "worklist.json"
    artifact.write_bytes(worklist_json_bytes(worklist))
    assert load_worklist(artifact) == worklist

    with pytest.raises(MonitorRequestBindingRefusal, match="regular file"):
        load_worklist(tmp_path / "missing.json")
    empty = tmp_path / "empty.json"
    empty.write_bytes(b"")
    with pytest.raises(MonitorRequestBindingRefusal, match="invalid size"):
        load_worklist(empty)
    oversize = tmp_path / "oversize.json"
    oversize.write_bytes(b"x" * 1_000_001)
    with pytest.raises(MonitorRequestBindingRefusal, match="invalid size"):
        load_worklist(oversize)
    directory = tmp_path / "worklist-directory"
    directory.mkdir()
    with pytest.raises(MonitorRequestBindingRefusal, match="regular file"):
        load_worklist(directory)


def test_worklist_refuses_instability_duplicate_membership_and_phase_laundering() -> None:
    first = (_consulted(_source(), _request("a")),)
    with pytest.raises(MonitorRequestBindingRefusal, match="not stable"):
        _worklist(first, (_consulted(_source(), _request("b")),))
    with pytest.raises(MonitorRequestBindingRefusal, match="repeated"):
        _worklist((*first, *first), (*first, *first))
    worklist = _worklist(first, first)
    entry = worklist.entries[0]
    with pytest.raises(ValueError, match="capture phase"):
        MonitorRequestBindingEntry.model_validate(
            {**entry.model_dump(mode="json"), "capture_phase": "calibration_eligible"}
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (("max_tokens", True), ("temperature", float("nan"))),
)
def test_request_identity_rejects_coercion_and_nonfinite_values(field: str, value: object) -> None:
    worklist = _worklist(
        (_consulted(_source(), _request("a")),), (_consulted(_source(), _request("a")),)
    )
    payload = worklist.entries[0].request.model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValueError):
        MonitorRequestIdentity.model_validate(payload)


def test_source_membership_rejects_integer_boolean_coercion() -> None:
    worklist = _worklist(
        (_consulted(_source(), _request("a")),), (_consulted(_source(), _request("a")),)
    )
    source = worklist.entries[0].sources[0].model_dump(mode="json")
    source["seed"] = True
    with pytest.raises(ValueError):
        type(worklist.entries[0].sources[0]).model_validate(source)


@pytest.mark.integration
def test_malicious_capture_refuses_mismatched_real_outcome_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dsn = os.environ.get("DATABASE_URL")
    if dsn is None:
        pytest.skip("semantic identity refusal requires local DATABASE_URL")
    import incidentgate.evaluation.semantic_monitor_capture_plan as capture_module

    repository = LabRepository(dsn)
    repository.migrate()
    scenario = load_scenario("T1")
    variant = scenario.attack_variants[0]
    original = capture_module.run_real_condition_episode

    def mismatched_outcome(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        return replace(original(*args, **kwargs), variant_id="T1-cal-v1")

    monkeypatch.setattr(capture_module, "run_real_condition_episode", mismatched_outcome)
    try:
        with pytest.raises(AuditInstabilityRefusal, match="identity disagrees"):
            capture_module._drive_malicious(repository, "T1", variant, scenario, "identity")
    finally:
        repository.reset_checkpoint("T1")


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
