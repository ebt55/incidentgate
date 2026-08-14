"""DB-free characterization of the no-spend proposer capture audit."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from incidentgate.contracts import EvaluationMode
from incidentgate.control.model_proposal import (
    CompletionRequest,
    ProposerPromptContract,
    proposer_input_envelope_schema,
)
from incidentgate.evaluation.proposer_capture_plan import (
    ProposerAuditInstabilityRefusal,
    ProposerAuditObservation,
    ProposerAuditSource,
    ProposerCaptureRefusal,
    ProposerRequestIdentity,
    audit_frozen_proposer_requests,
    build_capture_audit,
    build_verified_capture_audit,
    capture_work_items,
    compare_cold_observations,
)
from incidentgate.lab.repository import LabRepository


def _request(token: str = "a") -> CompletionRequest:
    canonical = json.dumps(
        {
            "system": "system",
            "user": json.dumps({"evidence_digest": []}, separators=(",", ":")),
            "model": "claude-opus-5",
            "max_tokens": 1,
            "temperature": None,
            "thinking": None,
            "schema_fingerprint": "d" * 64,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return CompletionRequest(
        model="claude-opus-5",
        system="system",
        user_content=json.dumps({"evidence_digest": []}, separators=(",", ":")),
        max_tokens=1,
        temperature=None,
        thinking=None,
        schema={"type": "object"},
        canonical_prompt=canonical,
        prompt_sha256=(
            hashlib.sha256(canonical.encode()).hexdigest() if token == "a" else token * 64
        ),
    )


def _row(
    split: str = "development", token: str = "a", runtime_token: str = "cold-a"
) -> ProposerAuditObservation:
    request = _request(token)
    identity = ProposerRequestIdentity.from_request(request)
    input_schema_sha256 = hashlib.sha256(
        json.dumps(proposer_input_envelope_schema(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ProposerAuditObservation(
        ProposerAuditSource("T1", f"T1-{split[:3]}-v1", split, 1),
        identity,
        request,
        ProposerPromptContract(
            "proposal/v1",
            "claude-opus-5",
            identity.system_sha256,
            "proposal-evidence-digest/v1",
            input_schema_sha256,
            "d" * 64,
            identity.provider_schema_sha256,
        ),
        hashlib.sha256(runtime_token.encode()).hexdigest(),
    )


def test_cold_comparison_refuses_request_instability() -> None:
    with pytest.raises(ProposerAuditInstabilityRefusal, match="not stable"):
        compare_cold_observations((_row(),), (_row(token="f"),))


def test_cold_comparison_refuses_reused_runtime_identity() -> None:
    with pytest.raises(ProposerAuditInstabilityRefusal, match="not stable"):
        compare_cold_observations((_row(),), (_row(runtime_token="cold-a"),))


def test_cross_split_collision_is_visible_and_refuses_provider_work() -> None:
    audit = build_verified_capture_audit(
        (_row(), _row("holdout")),
        (_row(runtime_token="cold-b"), _row("holdout", runtime_token="cold-b")),
    )
    assert audit.labelled_cell_capture_safe is False
    assert len(audit.unique_requests) == len(audit.cross_split_collision_groups) == 1
    with pytest.raises(ProposerCaptureRefusal, match="duplicate"):
        capture_work_items(
            audit, capture_command="pytest tests/evaluation", git_revision="a" * 40
        )


def test_invalid_revision_refuses_even_a_stable_unique_request() -> None:
    audit = build_verified_capture_audit((_row(),), (_row(runtime_token="cold-b"),))
    with pytest.raises(ProposerCaptureRefusal, match="40-hex"):
        capture_work_items(audit, capture_command="pytest tests/evaluation", git_revision="dirty")


def test_dirty_worktree_refuses_even_an_exact_revision() -> None:
    audit = build_verified_capture_audit((_row(),), (_row(runtime_token="cold-b"),))
    with pytest.raises(ProposerCaptureRefusal, match="dirty"):
        capture_work_items(
            audit,
            capture_command="pytest tests/evaluation",
            git_revision="a" * 40,
            worktree_clean=False,
        )


def test_stable_unique_item_preserves_initial_covert_source_and_contract() -> None:
    row = _row()
    audit = build_verified_capture_audit((row,), (_row(runtime_token="cold-b"),))
    item = capture_work_items(
        audit, capture_command="pytest tests/evaluation", git_revision="a" * 40
    )[0]
    assert item.request == row.completion_request
    assert item.context.role == "proposer"
    assert item.context.leg == "covert" and item.context.step_index == 0
    assert item.context.scenario_id == row.source.scenario_id
    assert item.context.variant_id == row.source.variant_id
    assert item.context.condition == row.source.condition
    assert item.context.split == row.source.split
    assert item.context.input_schema_version == row.contract.input_schema_version
    assert item.context.input_schema_sha256 == row.contract.input_schema_sha256
    assert item.context.prompt_version == row.contract.prompt_version
    assert item.context.output_schema_sha256 == row.contract.output_schema_sha256


@pytest.mark.parametrize(
    "audit",
    (
        build_capture_audit((_row(),), stable=True),
        replace(
            build_verified_capture_audit((_row(),), (_row(runtime_token="cold-b"),)),
            cold_identity_pairs=(),
        ),
    ),
)
def test_capture_items_refuse_fabricated_or_partial_cold_proof(audit: object) -> None:
    with pytest.raises(ProposerCaptureRefusal, match="unstable|incomplete"):
        capture_work_items(
            audit,  # type: ignore[arg-type]
            capture_command="pytest tests/evaluation",
            git_revision="a" * 40,
        )


def test_capture_items_refuse_replaced_capture_relevant_observations_and_summaries() -> None:
    verified = build_verified_capture_audit((_row(),), (_row(runtime_token="cold-b"),))
    row = verified.observations[0]
    source_step = replace(row.source, step_index=1)  # type: ignore[arg-type]
    source_condition = replace(row.source, condition=EvaluationMode.UNGATED)
    source_leg = replace(row.source, leg="incident")  # type: ignore[arg-type]
    altered_source = replace(verified, observations=(replace(row, source=source_step),))
    altered_condition = replace(
        verified, observations=(replace(row, source=source_condition),)
    )
    altered_leg = replace(verified, observations=(replace(row, source=source_leg),))
    altered_contract = replace(
        verified,
        observations=(replace(row, contract=replace(row.contract, model="other-model")),),
    )
    altered_request = replace(
        verified,
        observations=(replace(row, request=replace(row.request, max_tokens=2)),),
    )
    altered_summary = replace(verified, unique_requests=())
    altered_pair = replace(verified, cold_identity_pairs=(("a" * 64, "b" * 64),))
    for tampered in (
        altered_source,
        altered_condition,
        altered_leg,
        altered_contract,
        altered_request,
        altered_summary,
        altered_pair,
    ):
        with pytest.raises(ProposerCaptureRefusal, match="inconsistent|incomplete"):
            capture_work_items(
                tampered,
                capture_command="pytest tests/evaluation",
                git_revision="a" * 40,
            )


def test_capture_items_refuse_replaced_dispatchable_completion_request() -> None:
    verified = build_verified_capture_audit((_row(),), (_row(runtime_token="cold-b"),))
    row = verified.observations[0]
    request = row.completion_request
    coherent_envelope = json.loads(request.canonical_prompt)
    coherent_envelope["system"] = "other-system"
    coherent_canonical = json.dumps(coherent_envelope, sort_keys=True, separators=(",", ":"))
    coherent_system = replace(
        request,
        system="other-system",
        canonical_prompt=coherent_canonical,
        prompt_sha256=hashlib.sha256(coherent_canonical.encode()).hexdigest(),
    )
    replacements = (
        replace(request, system="other-system"),
        replace(request, user_content='{"evidence_digest":["other"]}'),
        replace(request, schema={"type": "array"}),
        replace(request, model="other-model"),
        replace(request, max_tokens=2),
        replace(request, canonical_prompt="{}"),
        replace(request, prompt_sha256="f" * 64),
        coherent_system,
    )
    for replacement in replacements:
        tampered = replace(
            verified, observations=(replace(row, completion_request=replacement),)
        )
        with pytest.raises(ProposerCaptureRefusal, match="incomplete|disagreement"):
            capture_work_items(
                tampered,
                capture_command="pytest tests/evaluation",
                git_revision="a" * 40,
            )


@pytest.mark.integration
def test_frozen_runtime_audit_is_cold_stable_initial_only_and_has_no_side_effects() -> None:
    """The audit inventories only initial covert consultations, never adaptive later steps."""
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("proposer capture audit requires local DATABASE_URL")
    cache_root = Path(__file__).parents[1] / "fixtures" / "model_cache"
    before = {
        path.relative_to(cache_root): path.read_bytes()
        for path in cache_root.rglob("*")
        if path.is_file()
    }
    audit = audit_frozen_proposer_requests(dsn)
    repeated_audit = audit_frozen_proposer_requests(dsn)
    after = {
        path.relative_to(cache_root): path.read_bytes()
        for path in cache_root.rglob("*")
        if path.is_file()
    }
    assert after == before
    first_items = capture_work_items(
        audit, capture_command="pytest tests/evaluation", git_revision="a" * 40
    )
    repeated_items = capture_work_items(
        repeated_audit, capture_command="pytest tests/evaluation", git_revision="a" * 40
    )
    assert tuple((item.request, item.context) for item in repeated_items) == tuple(
        (item.request, item.context) for item in first_items
    )
    assert audit.stable is True and audit.labelled_cell_capture_safe is True
    assert {row.source.variant_id for row in audit.observations} == {
        "T1-dev-v1", "T1-cal-v1", "T1-holdout-v1",
        "T2-dev-v1", "T2-cal-v1", "T2-holdout-v1",
        "T4-dev-v1", "T4-cal-v1", "T4-holdout-v1",
    }
    assert len(audit.observations) == len(audit.unique_requests) == 9
    assert len(audit.collision_groups) == len(audit.cross_split_collision_groups) == 0
    assert len({row.contract.system_prompt_sha256 for row in audit.observations}) == 9
    assert len(audit.cold_identity_pairs) == 9
    assert all(left != right for left, right in audit.cold_identity_pairs)
    assert audit.cold_identity_pairs != repeated_audit.cold_identity_pairs
    for row in audit.observations:
        assert row.source.condition is EvaluationMode.COMPLETE
        assert row.source.leg == "covert" and row.source.step_index == 0
        assert row.invocation_kind == "fixture_no_call"
        assert row.contract.model == row.completion_request.model == row.request.model
        assert row.contract.system_prompt_sha256 == row.request.system_sha256
        assert row.contract.provider_schema_sha256 == row.request.provider_schema_sha256
        assert row.contract.output_schema_sha256 == json.loads(
            row.completion_request.canonical_prompt
        )["schema_fingerprint"]
    repository = LabRepository(dsn)
    for scenario_id in ("T1", "T2", "T4"):
        counts = repository.sabotage_durable_counts(scenario_id)
        assert not any(counts.ledger_rows.values())
        assert counts.approvals_recorded == counts.approvals_consumed == 0
    assert repository.t1_end_state().mutation_count == 0
    assert repository.t2_end_state().mutation_count == 0
    assert repository.t4_end_state().mutation_count == 0
