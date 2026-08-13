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
from pathlib import Path

import pytest

from incidentgate.contracts import EvaluationMode
from incidentgate.control.response_cache import ResponseCache
from incidentgate.evaluation import runner as runner_module
from incidentgate.evaluation.runner import (
    MODEL_BACKED_SCENARIOS,
    MODEL_PROVIDER,
    CheckpointBEvaluationRunner,
    _reproduction_command,
)
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


def _cache_posing_as_a_real_capture(tmp_path: Path) -> Path:
    """Re-store the committed body under a provider_call capture, in a throwaway directory.

    The key is taken from the committed entry rather than recomputed, so this cannot drift
    from D1's current prompt: that key is already gated against the live prompt by
    ``tests/control/test_response_cache.py`` and by the lab-collected check in
    ``tests/integration/test_model_backed_incident.py``.
    """
    source = next((COMMITTED_CACHE / OPUS).glob("*.json"))
    body = json.loads(source.read_text(encoding="utf-8"))
    assert body["capture"] == "synthetic", "the committed fixture is not a real capture"
    cache = ResponseCache(tmp_path / "model_cache")
    cache.store(OPUS, body["prompt_sha256"], body["raw_json"], capture="provider_call")
    return tmp_path / "model_cache"


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
    monkeypatch.setattr(runner_module, "MODEL_BACKED_SCENARIOS", {"D1": OPUS})
    runner = CheckpointBEvaluationRunner(
        dsn,
        mock_evaluation=True,
        git_revision="a" * 40,
        model_cache_dir=_cache_posing_as_a_real_capture(tmp_path),
    )
    manifest = _d1_manifest()

    for mode in (EvaluationMode.COMPLETE, EvaluationMode.UNGATED):
        row = runner._one(manifest, mode, 0, "b" * 64)  # type: ignore[arg-type]
        invocation = row.model_invocation
        assert invocation.invocation_kind == "cache_replay", mode
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
