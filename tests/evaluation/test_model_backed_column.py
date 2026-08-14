"""The model column: the seam that would publish one, and the reason none is published.

Two things are asserted here and they point in opposite directions on purpose.

The first is that the machinery works. Given a scenario enrolled in
``MODEL_BACKED_SCENARIOS`` and a committed capture recorded ``capture="provider_call"``, a
checkpoint-B row comes out carrying ``cache_replay`` with its provider and model named, having
gone through the unmodified gate chain -- the durable runtime for the COMPLETE condition and the
counterfactual path for the others. Nothing further is needed to publish a model column.

The second is that nothing is enrolled, and why. The repository's one committed cache entry is
``capture="synthetic"``: a body written by hand in tests/control/test_response_cache.py that no
model produced. Publishing it as ``cache_replay`` would name a provider and a model for a
decision neither made. So this module also pins the current state -- empty enrolment, synthetic
fixture -- so that acquiring a real capture is a deliberate act rather than something the
repository can drift into.

The ``capture="provider_call"`` entry written below is a test double for a capture, in tmp_path,
never committed and never published. Simulating one to test the plumbing is fine; the defect was
only ever publishing a simulated one as though it were real.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from incidentgate.contracts import (
    EvaluationMode,
    IncidentIdentity,
    ModelInvocationRecord,
    Role,
    ToolCallContext,
)
from incidentgate.control.model_proposal import (
    CompletionRequest,
    CompletionResult,
    ModelAgentProposer,
)
from incidentgate.control.models import Caller
from incidentgate.control.proposal import ProposalError
from incidentgate.control.response_cache import (
    ProviderCaptureProvenance,
    ResponseCache,
    schema_sha256,
)
from incidentgate.evaluation import runner as runner_module
from incidentgate.evaluation.runner import (
    MODEL_BACKED_SCENARIOS,
    MODEL_PROVIDER,
    CheckpointBEvaluationRunner,
    _reproduction_command,
)
from incidentgate.integration.adapters import LabEvidenceCollector
from incidentgate.lab.repository import LabRepository
from incidentgate.lab.service import ObservabilityService
from incidentgate.manifests import load_checkpoint_manifests

OPUS = "claude-opus-5"
COMMITTED_CACHE = Path(__file__).resolve().parents[1] / "fixtures" / "model_cache"


def _dsn() -> str:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("checkpoint-B rows are measured against live fixtures; set DATABASE_URL")
    return dsn


def _d1_manifest() -> object:
    return next(m for m in load_checkpoint_manifests(runner_module._MANIFEST_DIR) if m.id == "D1")


class _RequestCapturingClient:
    """Public proposer seam that captures a request and never contacts a provider."""

    def __init__(self) -> None:
        self.request: CompletionRequest | None = None

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.request = request
        raise RuntimeError("synthetic integration fixture must not call a provider")


def _cache_posing_as_a_real_capture(
    tmp_path: Path, dsn: str
) -> tuple[Path, ProviderCaptureProvenance]:
    """Make a synthetic integration fixture for runner wiring, never publication evidence.

    It derives the actual D1 request from a lab-collected incident via the public proposer
    client seam. The fixture's provider-shaped invocation and provenance satisfy cache
    validation only so this test can exercise replay wiring; they do not evidence a provider
    call and remain solely under ``tmp_path``.
    """
    source = next((COMMITTED_CACHE / OPUS).glob("*.json"))
    body = json.loads(source.read_text(encoding="utf-8"))
    assert body["capture"] == "synthetic", "the committed fixture is not a real capture"
    repository = LabRepository(dsn)
    repository.migrate()
    repository.reset_d1()
    repository.inject_d1()
    thread_id = "synthetic-cache-fixture"
    incident = IncidentIdentity(
        incident_id="INC-D1",
        scenario_id="D1",
        thread_id=thread_id,
        correlation_id=f"corr-{thread_id}",
    )
    caller = Caller(actor="evaluation-operator", role=Role.OPERATOR)
    context = ToolCallContext(
        incident_id=incident.incident_id,
        thread_id=thread_id,
        correlation_id=incident.correlation_id,
        actor=caller.actor,
        permission="operations:write",
    )
    client = _RequestCapturingClient()
    records = LabEvidenceCollector(
        ObservabilityService(repository), caller, context, scenario_id="D1"
    ).collect(incident)
    with pytest.raises(ProposalError):
        ModelAgentProposer(client=client, model=OPUS, temperature=None).propose(
            incident, caller, context, records
        )
    assert client.request is not None, "the public proposer seam did not build a D1 request"
    request = client.request
    assert request.prompt_sha256 == body["prompt_sha256"], "D1's stable prompt key drifted"
    invocation = ModelInvocationRecord(
        invocation_kind="provider_call",
        provider=MODEL_PROVIDER,
        model=OPUS,
        usage_source="synthetic_test_usage",
        input_tokens=0,
        output_tokens=0,
        cost=None,
        currency=None,
        pricing_snapshot="synthetic-test-pricing-v1",
    )
    provenance = ProviderCaptureProvenance(
        provider=MODEL_PROVIDER,
        model=OPUS,
        role="proposer",
        prompt_sha256=request.prompt_sha256,
        request_schema_sha256=schema_sha256(request.schema),
        input_schema_version="synthetic-test-input-v1",
        prompt_version="synthetic-test-prompt-v1",
        stop_reason="end_turn",
        input_tokens=invocation.input_tokens,
        output_tokens=invocation.output_tokens,
        usage_source=invocation.usage_source,
        capture_mode="live_provider_call",
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        capture_command="pytest tests/evaluation/test_model_backed_column.py",
        git_revision="a" * 40,
        pricing_snapshot_id=invocation.pricing_snapshot,
        estimated_cost=None,
        currency=None,
        cost_unavailable_reason="model_not_priced_in_snapshot",
        scenario_id="D1",
        variant_id="synthetic-test-fixture-v1",
        condition=EvaluationMode.COMPLETE,
        leg="incident",
        step_index=0,
        split="development",
    )
    cache = ResponseCache(tmp_path / "model_cache")
    cache.store(
        OPUS,
        request.prompt_sha256,
        body["raw_json"],
        capture="provider_call",
        provenance=provenance,
        invocation=invocation,
        request=request,
    )
    return tmp_path / "model_cache", provenance


def test_the_repository_publishes_no_model_claim_today() -> None:
    """Enrolment is empty and the only committed capture is synthetic. Both must stay true.

    If either changes, a published row can name a model, and that must be a reviewed decision
    rather than a side effect -- so this fails loudly when the state moves.
    """
    assert dict(MODEL_BACKED_SCENARIOS) == {}, (
        "a scenario is enrolled for model proposal; a published row will now name a provider. "
        "Confirm its committed capture records capture='provider_call' and update this test."
    )
    entries = list((COMMITTED_CACHE / OPUS).glob("*.json"))
    assert entries, "the committed opus fixture is missing"
    for entry in entries:
        assert json.loads(entry.read_text(encoding="utf-8"))["capture"] == "synthetic", (
            f"{entry.name} now claims a real capture; if a live call really produced it, this "
            "test is what should change, deliberately"
        )


@pytest.mark.integration
def test_an_enrolled_scenario_publishes_a_named_cache_replay_row(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The whole seam, end to end: enrol a scenario with a real capture and the row names it.

    Both proposal paths are covered, because they are different code. COMPLETE runs through
    ``IncidentRuntime``'s ``proposer_factory`` and the durable graph; the counterfactual modes
    run through the runner's own selection. A matrix where only one of them was model-backed
    would compare a model against a fixture and call the difference a safeguard effect.
    """
    dsn = _dsn()
    monkeypatch.setattr("incidentgate.evaluation.runner._revision", lambda value: value or "a" * 40)
    assert dict(runner_module.MODEL_BACKED_SCENARIOS) == {}
    monkeypatch.setattr(runner_module, "MODEL_BACKED_SCENARIOS", {"D1": OPUS})
    cache_dir, provenance = _cache_posing_as_a_real_capture(tmp_path, dsn)
    cached = ResponseCache(cache_dir).load(OPUS, provenance.prompt_sha256)
    assert cached.capture == "provider_call" and cached.provenance == provenance
    assert cached.provenance.capture_command.startswith("pytest tests/evaluation/")
    assert cached.provenance.prompt_version.startswith("synthetic-test-")
    runner = CheckpointBEvaluationRunner(
        dsn,
        mock_evaluation=True,
        git_revision="a" * 40,
        model_cache_dir=cache_dir,
    )
    manifest = _d1_manifest()

    for mode in (EvaluationMode.COMPLETE, EvaluationMode.UNGATED):
        row = runner._one(manifest, mode, 0, "b" * 64)  # type: ignore[arg-type]
        invocation = row.model_invocation
        assert invocation.invocation_kind == "cache_replay", mode
        assert dict(MODEL_BACKED_SCENARIOS) == {}, "only this test's monkeypatch enrolled D1"
        assert invocation.provider == MODEL_PROVIDER
        assert invocation.model == OPUS
        # A replay contacted no provider, so it must still claim no usage and no cost.
        assert invocation.input_tokens is None and invocation.cost is None
        # The replayed proposal really did drive the chain: this is the action from the
        # committed body, not the scenario's deterministic proposer.
        assert row.attempted_action_tool == "operations.rollback"
        assert row.diagnosis_statement == "bad deployment v2 rollback to v1"


@pytest.mark.integration
def test_an_enrolled_scenario_with_no_capture_fails_instead_of_losing_its_column(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A cache miss must stop generation, not quietly publish a matrix without its model column.

    This is the failure the guard exists for: a miss reaches the proposer as ``ProposalError``,
    which the graph renders as a blocked no-action terminal. Without this check the run would
    succeed and publish rows that had silently reverted to fixtures.
    """
    dsn = _dsn()
    monkeypatch.setattr("incidentgate.evaluation.runner._revision", lambda value: value or "a" * 40)
    monkeypatch.setattr(runner_module, "MODEL_BACKED_SCENARIOS", {"D1": OPUS})
    runner = CheckpointBEvaluationRunner(
        dsn, mock_evaluation=True, git_revision="a" * 40, model_cache_dir=tmp_path / "empty"
    )
    with pytest.raises(RuntimeError, match="enrolled for model proposal but produced"):
        runner._one(_d1_manifest(), EvaluationMode.COMPLETE, 0, "b" * 64)  # type: ignore[arg-type]


def test_the_published_reproduction_command_names_a_module_that_resolves() -> None:
    """The committed artifact told readers to run a package that no longer existed.

    ``triage_agent_lab.evaluation.runner`` survived the rename to ``incidentgate`` inside a
    string literal that nothing compared against anything. Both directions are checked: the
    command this code emits names a real module, and the module it names is this one.
    """
    command = _reproduction_command("a" * 40)
    assert "python -m incidentgate.evaluation.runner checkpoint-b" in command
    assert "triage_agent_lab" not in command
