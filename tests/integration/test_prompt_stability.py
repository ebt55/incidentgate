"""A scenario may not be enrolled for model proposal until its prompt is proven stable.

Positional citation labels removed the two per-run fields the prompt used to carry, so a
lab-collected incident can now hash to the same prompt twice and hit a committed
response-cache fixture. That is a property of the *digest shape*, and it is necessary but
not sufficient: the digest still carries a payload projection, so the prompt is stable only
if the payloads are. At least one scenario's are not, which is exactly why this is measured
per scenario rather than argued once for the shape.

The measurement is two cold collections of the same incident -- reset, inject, collect,
twice -- and an equality assertion on ``CompletionRequest.prompt_sha256``. Each collection
mints fresh ``uuid4()`` evidence ids and a fresh ``observed_at``, so the two runs differ in
precisely the fields lab collection controls. Every case carries a negative control that
rebuilds the pre-change digest from the same records and asserts *it* moved, because a
stability test whose two inputs were accidentally identical would pass while proving
nothing.

Enrollment is a decision this file owns: ``PROMPT_STABLE`` and ``PROMPT_UNSTABLE`` must
between them classify every scenario ``LabEvidenceCollector`` can serve, so adding one to
the collector without measuring it turns this suite red instead of quietly shipping a
scenario whose fixtures can never hit.
"""

from __future__ import annotations

import json
import os
from hashlib import sha256
from typing import Any

import pytest

from incidentgate.contracts import (
    EvidenceRecord,
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
from incidentgate.integration.adapters import LabEvidenceCollector
from incidentgate.lab.repository import LabRepository
from incidentgate.lab.service import ObservabilityService
from incidentgate.scenario_registry import RUNNABLE_SCENARIOS

OPUS = "claude-opus-5"

# Every scenario the production collector can read evidence for. Derived, never hand-listed:
# a hand copy is how the flagship chaos table silently omitted a whole tier.
COLLECTOR_SCENARIOS = sorted(set(LabEvidenceCollector._kinds) & set(RUNNABLE_SCENARIOS))

# Scenarios whose prompt is proven stable across two cold collections, by the test below.
# This is the enrollment gate for model proposal: nothing belongs here on argument.
PROMPT_STABLE = (
    "D1",
    "D2",
    "D3",
    "D4",
    "D5",
    "D7",
    "D8",
    "R01",
    "R02",
    "R03",
    "R04",
    "R05",
    "R06",
    "R07",
    "R08",
    "R09",
    "R10",
    "R11",
    "R12",
    "S1",
    "S2",
    "T1",
    "T2",
    "T4",
    "T7",
    "T8",
)

# Scenarios whose prompt is NOT stable, with the measured cause. Being listed here is a bar
# on model proposal, not a bug report against the label scheme: the label scheme fixed the
# digest's own per-run fields, and what remains is per-run content inside a payload.
PROMPT_UNSTABLE: dict[str, str] = {
    "D6": (
        "D6's second health read embeds checked_at=now().isoformat() in its payload, and an "
        "ISO timestamp survives the payload projection intact -- every character is inside "
        "_SAFE_STRING and it is well under _MAX_STRING. D6 is a no-action scenario, so no "
        "proposer runs there today and nothing is broken by this; it is the standing "
        "counter-example to assuming shape stability implies prompt stability."
    ),
}


def _dsn() -> str:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("prompt stability is measured against live fixtures; set DATABASE_URL")
    return dsn


@pytest.fixture
def repository() -> LabRepository:
    repo = LabRepository(_dsn())
    repo.migrate()
    return repo


class CapturingClient:
    """Records the request, then returns an output valid for any non-empty evidence set."""

    def __init__(self) -> None:
        self.requests: list[CompletionRequest] = []

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.requests.append(request)
        # e0 exists for every scenario, because _build_request refuses an empty citable set.
        # Citing exactly it keeps this probe scenario-agnostic while still exercising the
        # real decode: propose() only returns if the label resolved to a real evidence id.
        return CompletionResult(
            raw_json=json.dumps(
                {
                    "hypothesis_id": "prompt-stability-probe",
                    "diagnosis": "probe",
                    "confidence": 0.5,
                    "tool_name": "operations.restart",
                    "arguments": {"kind": "restart", "component": "api"},
                    "citations": ["e0"],
                }
            ),
            invocation=ModelInvocationRecord(invocation_kind="fixture_no_call"),
        )


def _inputs(scenario: str) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    thread = f"prompt-stability-{scenario.lower()}"
    incident = IncidentIdentity(
        incident_id=f"INC-{scenario}",
        scenario_id=scenario,
        thread_id=thread,
        correlation_id=f"corr-{thread}",
    )
    caller = Caller(actor="evaluation-operator", role=Role.OPERATOR)
    context = ToolCallContext(
        incident_id=f"INC-{scenario}",
        thread_id=thread,
        correlation_id=f"corr-{thread}",
        actor="evaluation-operator",
        permission="operations:write",
    )
    return incident, caller, context


def _collect(repository: LabRepository, scenario: str) -> tuple[EvidenceRecord, ...]:
    """One cold collection: fixture reset, fault injected, evidence read through production."""
    if scenario == "D1":
        # D1 predates the generic checkpoint fixture API and keeps its own.
        repository.reset_d1()
        repository.inject_d1()
    else:
        repository.reset_checkpoint(scenario)
        repository.inject_checkpoint(scenario)
    incident, caller, context = _inputs(scenario)
    return LabEvidenceCollector(
        ObservabilityService(repository), caller, context, scenario_id=scenario
    ).collect(incident)


def _prompt_hash(scenario: str, records: tuple[EvidenceRecord, ...]) -> str:
    incident, caller, context = _inputs(scenario)
    client = CapturingClient()
    ModelAgentProposer(client=client, model=OPUS, temperature=None).propose(
        incident, caller, context, records
    )
    assert client.requests, "no request was built, so there is no prompt to compare"
    return client.requests[0].prompt_sha256


def _legacy_digest_hash(records: tuple[EvidenceRecord, ...]) -> str:
    """The pre-change digest shape, kept only as this file's negative control.

    Sorted by ``evidence_id``, rendering ``evidence_id`` and ``observed_at``. Reproduced
    rather than imported because the point is to compare against something the proposer no
    longer does; if this ever stops differing across two cold runs, the stability assertions
    above have gone vacuous and are passing on identical inputs.
    """
    digest: list[dict[str, Any]] = [
        {
            "evidence_id": record.evidence_id,
            "tool_name": record.tool_name,
            "observed_at": record.observed_at.isoformat(),
        }
        for record in sorted(records, key=lambda item: item.evidence_id)
    ]
    return sha256(
        json.dumps(digest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def test_every_collector_scenario_is_classified() -> None:
    """No scenario may be silently unmeasured; the two lists must partition the collector."""
    classified = set(PROMPT_STABLE) | set(PROMPT_UNSTABLE)
    assert classified == set(COLLECTOR_SCENARIOS), (
        "these scenarios are neither proven stable nor recorded unstable: "
        f"{sorted(set(COLLECTOR_SCENARIOS) - classified)}; and these are classified but no "
        f"longer collectable: {sorted(classified - set(COLLECTOR_SCENARIOS))}"
    )
    assert not set(PROMPT_STABLE) & set(PROMPT_UNSTABLE)


@pytest.mark.parametrize("scenario", PROMPT_STABLE)
def test_two_cold_collections_produce_the_same_prompt(
    repository: LabRepository, scenario: str
) -> None:
    """The enrollment gate: this scenario's incident hashes to one prompt, run after run."""
    first = _collect(repository, scenario)
    second = _collect(repository, scenario)
    assert first and second, f"{scenario} collected no evidence; the check would be vacuous"

    # The control. Two collections really are two collections: fresh uuid4 ids each time, and
    # the digest that carried them really did move.
    assert {record.evidence_id for record in first}.isdisjoint(
        record.evidence_id for record in second
    ), f"{scenario} reused evidence ids across cold runs; this test would prove nothing"
    assert _legacy_digest_hash(first) != _legacy_digest_hash(second), (
        f"{scenario}'s pre-change digest did not move across two cold collections, so the "
        "equality below is not evidence that anything was fixed"
    )

    assert _prompt_hash(scenario, first) == _prompt_hash(scenario, second), (
        f"{scenario}'s prompt is not stable across cold runs, so no committed cache fixture "
        "can ever hit for it; find the per-run value still reaching the digest"
    )


@pytest.mark.parametrize("scenario", sorted(PROMPT_UNSTABLE))
def test_recorded_unstable_scenarios_really_are_unstable(
    repository: LabRepository, scenario: str
) -> None:
    """The other direction, so the bar list cannot rot into a superstition.

    A scenario sitting in ``PROMPT_UNSTABLE`` after its payload was fixed would go on
    blocking model proposal for a reason that stopped being true. This fails when that
    happens, and the fix is to move the entry into ``PROMPT_STABLE``.
    """
    first = _collect(repository, scenario)
    second = _collect(repository, scenario)
    assert _prompt_hash(scenario, first) != _prompt_hash(scenario, second), (
        f"{scenario} is recorded as prompt-unstable but now hashes identically across two "
        f"cold runs; if its payload was fixed, move it to PROMPT_STABLE. Recorded cause: "
        f"{PROMPT_UNSTABLE[scenario]}"
    )


def test_the_unstable_cause_is_payload_content_not_digest_shape(
    repository: LabRepository,
) -> None:
    """Name D6's defect precisely, rather than leaving 'unstable' as an unexplained label.

    The distinction matters for what the next chunk should fix. The digest shape is already
    run-independent -- the labels and tool names are identical across cold runs -- and the
    entire difference is a wall-clock string the projection is happy to forward, because it
    is a perfectly ordinary safe scalar. Deterministic evidence ids would not touch it.
    """
    first = _collect(repository, "D6")
    second = _collect(repository, "D6")

    assert [record.tool_name for record in first] == [record.tool_name for record in second]
    moved = [
        (index, key)
        for index, (before, after) in enumerate(zip(first, second, strict=True))
        for key in sorted(set(before.payload) | set(after.payload))
        if before.payload.get(key) != after.payload.get(key)
    ]
    assert moved == [(1, "checked_at")], moved
