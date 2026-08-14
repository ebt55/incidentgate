from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from incidentgate.control.model_proposal import (
    CompletionRequest,
    ProposerPromptContract,
    proposer_input_envelope_schema,
)
from incidentgate.evaluation.proposer_capture_plan import (
    ProposerAuditObservation,
    ProposerAuditSource,
    ProposerCaptureAudit,
    ProposerRequestIdentity,
    build_verified_capture_audit,
)
from incidentgate.evaluation.proposer_contract_freeze import (
    build_proposer_capture_contract,
    main,
    write_proposer_capture_contract,
)
from incidentgate.evaluation.proposer_contracts import ProposerCaptureContractArtifact

AT = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)


def _row(scenario_id: str, variant_id: str, runtime: str) -> ProposerAuditObservation:
    system = f"system for {scenario_id}/{variant_id}"
    user = json.dumps({"evidence_digest": []}, separators=(",", ":"))
    schema = {"type": "object"}
    output_hash = "d" * 64
    canonical = json.dumps(
        {
            "system": system,
            "user": user,
            "model": "claude-opus-5",
            "max_tokens": 1,
            "temperature": None,
            "thinking": None,
            "schema_fingerprint": output_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    request = CompletionRequest(
        "claude-opus-5", system, user, 1, None, None, schema, canonical,
        hashlib.sha256(canonical.encode()).hexdigest(),
    )
    identity = ProposerRequestIdentity.from_request(request)
    input_hash = hashlib.sha256(
        json.dumps(proposer_input_envelope_schema(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ProposerAuditObservation(
        ProposerAuditSource(
            scenario_id,
            variant_id,
            "holdout",
            {"T1": 5102, "T2": 5112, "T4": 5132}[scenario_id],
        ),
        identity,
        request,
        ProposerPromptContract(
            "proposal/v1", "claude-opus-5", identity.system_sha256,
            "proposal-evidence-digest/v1", input_hash, output_hash,
            identity.provider_schema_sha256,
        ),
        hashlib.sha256(runtime.encode()).hexdigest(),
    )


def _audit() -> ProposerCaptureAudit:
    first = (
        _row("T1", "T1-holdout-v1", "first-1"),
        _row("T2", "T2-holdout-v1", "first-2"),
        _row("T4", "T4-holdout-v1", "first-4"),
    )
    second = tuple(
        replace(row, runtime_identity_sha256=hashlib.sha256(
            f"second-{index}".encode()
        ).hexdigest())
        for index, row in enumerate(first)
    )
    return build_verified_capture_audit(first, second)


def _artifact() -> ProposerCaptureContractArtifact:
    return build_proposer_capture_contract(
        audit=_audit(),
        capture_command="pytest tests/evaluation",
        git_revision="a" * 40,
        worktree_clean=True,
        contract_id="holdout-proposer",
        frozen_at=AT,
        provider="anthropic",
        now=datetime(2026, 8, 15, tzinfo=UTC),
    )


def test_freeze_derives_canonical_bindings_and_shared_identity_from_audited_requests() -> None:
    artifact = _artifact()
    assert artifact.provider == "anthropic"
    assert [(row.scenario_id, row.variant_id, row.split) for row in artifact.prompt_bindings] == [
        ("T1", "T1-holdout-v1", "holdout"),
        ("T2", "T2-holdout-v1", "holdout"),
        ("T4", "T4-holdout-v1", "holdout"),
    ]
    assert artifact.model == "claude-opus-5"
    assert artifact.provider_schema_sha256 == hashlib.sha256(
        json.dumps({"type": "object"}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@pytest.mark.parametrize("changes", [
    {"provider": "other"},
    {"worktree_clean": False},
    {"git_revision": "A" * 40},
    {"frozen_at": AT.replace(tzinfo=None)},
    {"frozen_at": datetime(2026, 8, 16, tzinfo=UTC)},
])
def test_freeze_refuses_unbounded_provider_dirty_revision_or_late_freeze(
    changes: dict[str, object],
) -> None:
    arguments: dict[str, object] = {
        "audit": _audit(), "capture_command": "pytest tests/evaluation", "git_revision": "a" * 40,
        "worktree_clean": True, "contract_id": "holdout-proposer", "frozen_at": AT,
        "provider": "anthropic", "now": datetime(2026, 8, 15, tzinfo=UTC),
    }
    arguments.update(changes)
    with pytest.raises(ValueError):
        build_proposer_capture_contract(**arguments)


def test_writer_is_canonical_confined_and_never_overwrites(tmp_path: Path) -> None:
    root = tmp_path
    target = root / "config" / "proposer-capture-contracts" / "holdout.json"
    target.parent.mkdir(parents=True)
    artifact = _artifact()
    assert write_proposer_capture_contract(target, artifact, root=root) == target
    assert target.read_bytes().endswith(b"\n")
    with pytest.raises(FileExistsError):
        write_proposer_capture_contract(target, artifact, root=root)
    with pytest.raises(ValueError, match="proposer-capture-contracts"):
        write_proposer_capture_contract(root / "outside.json", artifact, root=root)
    with pytest.raises(FileNotFoundError):
        write_proposer_capture_contract(
            root / "config" / "proposer-capture-contracts" / "missing" / "x.json",
            artifact,
            root=root,
        )


def test_cli_requires_dsn_and_uses_injected_no_provider_audit_seam(tmp_path: Path) -> None:
    target = tmp_path / "config" / "proposer-capture-contracts" / "holdout.json"
    target.parent.mkdir(parents=True)
    argv = [
        "--output", str(target), "--contract-id", "holdout-proposer", "--frozen-at", AT.isoformat()
    ]
    with pytest.raises(ValueError, match="DATABASE_URL"):
        main(argv, root=tmp_path, environ={})
    assert main(
        argv,
        root=tmp_path,
        environ={"DATABASE_URL": "postgresql://no-provider"},
        audit_factory=lambda _: _audit(),
        head_revision=lambda _: "a" * 40,
        clean_tree=lambda _: True,
        clock=lambda: datetime(2026, 8, 15, tzinfo=UTC),
    ) == 0
    assert target.is_file()
