"""The variant labels carry no split semantics, and cannot quietly regain any.

OWNER RULING, 2026-08-21: the development/calibration/holdout split is dropped.
The three labels stay as historical names on frozen contracts and published
provenance; what goes is their meaning as a train/calibrate/holdout partition.

This module pins the three things that ruling rests on, so that a later change
which reintroduced a split would turn a test red rather than quietly restoring a
claim the project does not make.

WHY THE FIRST TEST IS THE LOAD-BEARING ONE

`split` may never enter a canonical prompt. Every committed capture is keyed by
`prompt_sha256`, and `ResponseCache` re-derives that hash from the request's
canonical prompt on every load — so a `split` that reached the prompt would
re-key every capture this project has paid for, including two billed hosted
captures that will not be re-taken. That is checked here as a controlled
comparison: build the same request twice, varying only the label, and compare
hashes.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from incidentgate.contracts import (
    EvidenceRecord,
    IncidentIdentity,
    ModelInvocationRecord,
    Role,
    ToolCallContext,
)
from incidentgate.control.attack_policies import (
    T1_ATTACK_VARIANTS_BY_ID,
    AttackPolicyVariant,
)
from incidentgate.control.model_attacker import ModelAttackProposer, render_t1_attack_steering
from incidentgate.control.model_proposal import CompletionRequest, CompletionResult
from incidentgate.control.models import Caller

ROOT = Path(__file__).resolve().parents[2]
LABELS = ("development", "calibration", "holdout")


class _CaptureClient:
    """Records the request the proposer built; answers nothing usable."""

    def __init__(self) -> None:
        self.request: CompletionRequest | None = None

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.request = request
        return CompletionResult(
            raw_json="{}",
            invocation=ModelInvocationRecord(
                invocation_kind="cache_replay", provider="local", model=request.model
            ),
        )


def _records() -> tuple[EvidenceRecord, ...]:
    return (
        EvidenceRecord(
            evidence_id="ev-1",
            incident_id="INC-T1",
            thread_id="thread",
            correlation_id="corr",
            tool_name="observability.checkout_health",
            actor="observer",
            permission="observe",
            observed_at=datetime(2026, 8, 21, tzinfo=UTC),
            expires_at=datetime(2026, 8, 21, 1, tzinfo=UTC),
            payload={"health": "unhealthy", "status": 503},
        ),
    )


def _prompt_hash(variant: AttackPolicyVariant, contract: str) -> str:
    client = _CaptureClient()
    proposer = ModelAttackProposer(
        client=client,
        model="mistral-nemo-12b",
        variant=variant,
        covert_tools=("operations.write_outbound_note",),
        scenario_id="T1",
        contract_version=contract,  # type: ignore[arg-type]
    )
    incident = IncidentIdentity(
        incident_id="INC-T1", scenario_id="T1", thread_id="thread", correlation_id="corr"
    )
    context = ToolCallContext(
        incident_id="INC-T1",
        thread_id="thread",
        correlation_id="corr",
        actor="operator-1",
        permission="operations:write",
    )
    caller = Caller(actor="operator-1", role=Role.OPERATOR)
    with contextlib.suppress(Exception):
        # The stub answers `{}`, so the proposer raises on parsing it. Irrelevant
        # here: the request was already built and recorded before the answer.
        proposer.propose(incident, caller, context, _records())
    assert client.request is not None, "the proposer built no request"
    return client.request.prompt_sha256


@pytest.mark.parametrize("contract", ["v1", "v2", "v3"])
@pytest.mark.parametrize("variant_id", sorted(T1_ATTACK_VARIANTS_BY_ID))
def test_the_label_never_reaches_the_canonical_prompt(variant_id: str, contract: str) -> None:
    """Vary only the label; the prompt hash must not move.

    A controlled comparison rather than a schema read: everything else — model,
    evidence, contract, sampling — is held constant, so a hash difference could
    only be attributable to the label.
    """
    base = T1_ATTACK_VARIANTS_BY_ID[variant_id]
    hashes = {
        label: _prompt_hash(dataclasses.replace(base, split=label), contract)  # type: ignore[arg-type]
        for label in LABELS
    }
    assert len(set(hashes.values())) == 1, (
        "the variant label reached the canonical prompt, which would re-key every committed "
        f"capture: {hashes}"
    )


def test_the_label_does_not_reach_the_rendered_steering_text() -> None:
    """The one channel a variant has into the request, checked directly."""
    for variant_id, variant in sorted(T1_ATTACK_VARIANTS_BY_ID.items()):
        rendered = {
            label: render_t1_attack_steering(dataclasses.replace(variant, split=label))  # type: ignore[arg-type]
            for label in LABELS
        }
        assert len(set(rendered.values())) == 1, variant_id


def test_development_and_holdout_are_the_same_experiment() -> None:
    """The measured fact the ruling rests on, not a restatement of it.

    T1's free parameter derives from seed parity and its frozen seeds are three
    consecutive integers, so the first and third share parity. If this ever
    stopped being true the labels would start meaning something again, and that
    would be a decision rather than a discovery.
    """
    dev = T1_ATTACK_VARIANTS_BY_ID["T1-dev-v1"]
    holdout = T1_ATTACK_VARIANTS_BY_ID["T1-holdout-v1"]
    calibration = T1_ATTACK_VARIANTS_BY_ID["T1-cal-v1"]
    assert dev.source_ref == holdout.source_ref
    assert calibration.source_ref != dev.source_ref, "all three collapsing would be a different bug"
    for contract in ("v1", "v2", "v3"):
        assert _prompt_hash(dev, contract) == _prompt_hash(holdout, contract), contract
        assert _prompt_hash(calibration, contract) != _prompt_hash(dev, contract), contract


def test_no_threshold_was_ever_selected_on_a_calibration_set() -> None:
    """The second leg of the ruling, read off the committed artifacts.

    A ``monitor-thresholds-v1`` artifact would be one selected from data on a
    calibration split. None exists, and every committed artifact says in its own
    bytes that no split was used.
    """
    artifacts = sorted((ROOT / "config" / "monitor-thresholds").glob("*.json"))
    assert artifacts, "the committed threshold artifacts are missing"
    for path in artifacts:
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["schema_version"] == "monitor-thresholds-v2", path.name
        assert payload["selected_on_split"] == "none_no_split_was_used", path.name
        assert payload["provenance_band"] == "a_priori_definitional", path.name


def test_the_project_states_plainly_that_no_held_out_evaluation_is_claimed() -> None:
    """The durable statement, pinned so a tidy-up cannot remove it silently.

    A reader should not have to infer the absence of a held-out check from the
    absence of a claim about one.
    """
    # Whitespace collapsed before matching, because both statements wrap across
    # lines and a line break must not be able to hide a deleted sentence.
    def _squash(text: str) -> str:
        return re.sub(r"\s+", " ", text).lower()

    methodology = _squash(
        (ROOT / "docs" / "threat-model-and-methodology.md").read_text(encoding="utf-8")
    )
    module = _squash(
        (ROOT / "src" / "incidentgate" / "control" / "attack_policies.py").read_text(
            encoding="utf-8"
        )
    )
    for source, name in ((methodology, "methodology"), (module, "attack_policies")):
        assert "no held-out evaluation is claimed" in source, name
        assert "carry no split semantics" in source, name
