"""The evaluation lanes must gate on a declared evidence surface, not a derived one.

Both the checkpoint lane (``evaluation/runner.py``) and the reliability lane
(``evaluation/reliability_v2.py``) built their allowed-source set as
``frozenset(r.tool_name for r in records)`` -- from the very records they were
about to judge. Every cited record's tool name was therefore a member by
construction, so ``unallowed_evidence_source`` could not fire in those lanes for
any input whatsoever. The lanes were not enforcing a weak version of the
evidence-source rule; they were running a predicate with no failing input, and
reporting the result as though it had been checked.

That is the same vacuity class as a checker that cannot fail: the claim was
unfalsifiable rather than wrong. These tests make the predicate's ability to fire
a measured fact per lane, and pin the declared surface as the single owner so a
future edit cannot quietly re-derive it.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from incidentgate.contracts import (
    EvidenceRecord,
    IncidentIdentity,
    PolicyConfiguration,
    Role,
    ToolCallContext,
)
from incidentgate.control.evidence import EvidenceValidator
from incidentgate.control.models import Caller, EvidenceState
from incidentgate.control.proposal import DeterministicD3Proposer, DeterministicR01Proposer
from incidentgate.evaluation import reliability_v2 as reliability_module
from incidentgate.evaluation import runner as runner_module
from incidentgate.evaluation.sabotage_episodes import load_policy_configuration
from incidentgate.integration.adapters import LabEvidenceCollector
from incidentgate.lab.auth import Principal
from incidentgate.lab.repository import LabRepository
from incidentgate.lab.service import ObservabilityService
from incidentgate.reasons import UNALLOWED_EVIDENCE_SOURCE_PREFIX
from incidentgate.scenario_registry import (
    ALLOWED_EVIDENCE_SOURCES,
    NO_ACTION_SCENARIOS,
    RUNNABLE_SCENARIOS,
)

CHECKPOINT_LANE_SCENARIOS = sorted(
    scenario
    for scenario in RUNNABLE_SCENARIOS
    if scenario.startswith("D") and scenario not in NO_ACTION_SCENARIOS
)
RELIABILITY_LANE_SCENARIOS = sorted(reliability_module._PROPOSERS)


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("evidence-source enforcement runs against live fixtures; set DATABASE_URL")
    repo = LabRepository(dsn)
    repo.migrate()
    return repo


def _inputs(scenario: str) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    thread = f"evidence-source-{scenario.lower()}"
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
    """Collect a scenario's real fixture evidence the way its lane does."""
    if scenario == "D1":
        # D1 predates the generic checkpoint fixture API and keeps its own.
        repository.reset_d1()
        repository.inject_d1()
    else:
        repository.reset_checkpoint(scenario)
        repository.inject_checkpoint(scenario)
    incident, caller, context = _inputs(scenario)
    if scenario in CHECKPOINT_LANE_SCENARIOS:
        return LabEvidenceCollector(
            ObservabilityService(repository), caller, context, scenario_id=scenario
        ).collect(incident)
    read_context = context.model_copy(update={"permission": "observability:read"})
    principal = Principal(caller.actor, caller.role)
    return tuple(
        ObservabilityService(repository).get(read_context, principal, kind)
        for kind in LabEvidenceCollector._kinds[scenario]
    )


def _validator(scenario: str, policy: PolicyConfiguration) -> EvidenceValidator:
    """Constructed exactly as both lanes now construct it."""
    return EvidenceValidator(
        policy, lambda: datetime.now(UTC), allowed_sources=ALLOWED_EVIDENCE_SOURCES[scenario]
    )


# ---------------------------------------------------------------------------
# Ownership: one declared surface, read by both lanes.
# ---------------------------------------------------------------------------


def test_both_evaluation_lanes_read_the_shared_evidence_surface() -> None:
    """Identity, not equality -- the same pin the sabotage lane already carries.

    An equal-by-coincidence hand copy is exactly what failed before in the
    sabotage harness, and no equality assertion could have caught it. These lanes
    must reference the one object, so that editing the registry moves them too.
    """
    assert runner_module.ALLOWED_EVIDENCE_SOURCES is ALLOWED_EVIDENCE_SOURCES
    assert reliability_module.ALLOWED_EVIDENCE_SOURCES is ALLOWED_EVIDENCE_SOURCES


def test_every_scenario_the_lanes_evaluate_declares_a_surface() -> None:
    """Reading the mapping by scenario id means an undeclared scenario is a KeyError.

    Better a red test here than a KeyError partway through a published
    evaluation run, so the two lanes' scenario sets are checked against the
    registry directly rather than trusted.
    """
    assert set(CHECKPOINT_LANE_SCENARIOS) <= set(ALLOWED_EVIDENCE_SOURCES)
    assert set(RELIABILITY_LANE_SCENARIOS) <= set(ALLOWED_EVIDENCE_SOURCES)
    # And the sets are non-empty, so the containment above cannot pass vacuously.
    assert CHECKPOINT_LANE_SCENARIOS and RELIABILITY_LANE_SCENARIOS


# ---------------------------------------------------------------------------
# The declared surface admits every legitimate fixture, for every scenario.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario", CHECKPOINT_LANE_SCENARIOS + RELIABILITY_LANE_SCENARIOS
)
def test_declared_surface_admits_the_real_fixture_sources(
    repository: LabRepository, scenario: str
) -> None:
    """The risk the change actually carries, checked against live fixtures.

    Swapping a derived set for a declared one can only break by declaring the
    wrong names, and the tiers do not spell them uniformly: ``db_pool_metrics``
    is served as ``metrics.db_pool`` while every other kind becomes
    ``observability.<kind>``. Rather than re-encode that rule here -- which would
    be a second copy of exactly the thing this chunk is removing -- this collects
    each scenario's evidence through the production service and checks the names
    it really produces.
    """
    records = _collect(repository, scenario)
    assert records, f"{scenario} collected no evidence; the check below would be vacuous"
    undeclared = {
        record.tool_name
        for record in records
        if record.tool_name not in ALLOWED_EVIDENCE_SOURCES[scenario]
    }
    assert not undeclared, (
        f"{scenario} collects evidence from sources its declared surface omits: "
        f"{sorted(undeclared)}"
    )


# ---------------------------------------------------------------------------
# The negative control, per lane: the reason can actually fire.
# ---------------------------------------------------------------------------


def test_checkpoint_lane_refuses_evidence_from_an_undeclared_source(
    repository: LabRepository,
) -> None:
    """D3 is the sharpest case: its surface is the one with a non-uniform name.

    The action is proposed from the legitimate records first, so the citation is
    genuine; only the record's origin is then changed. That models an agent
    citing evidence that really came from somewhere it may not cite, which is
    the thing the lane claimed to catch and could not.
    """
    policy = load_policy_configuration()
    records = _collect(repository, "D3")
    incident, caller, context = _inputs("D3")
    _, action = DeterministicD3Proposer().propose(incident, caller, context, records)

    assert "observability.deployment_diff" not in ALLOWED_EVIDENCE_SOURCES["D3"]
    tampered = tuple(
        record.model_copy(update={"tool_name": "observability.deployment_diff"})
        if record.evidence_id == action.evidence_ids[0]
        else record
        for record in records
    )
    validation = _validator("D3", policy).validate(action, tampered, context)

    assert validation.state is EvidenceState.INVALID
    assert any(
        reason.startswith(UNALLOWED_EVIDENCE_SOURCE_PREFIX) for reason in validation.reasons
    ), validation.reasons


def test_checkpoint_lane_accepts_the_declared_fixture_sources(
    repository: LabRepository,
) -> None:
    """The control that stops the test above passing for the wrong reason."""
    policy = load_policy_configuration()
    records = _collect(repository, "D3")
    incident, caller, context = _inputs("D3")
    _, action = DeterministicD3Proposer().propose(incident, caller, context, records)

    validation = _validator("D3", policy).validate(action, records, context)

    assert validation.state is EvidenceState.VALID, validation.reasons


def test_reliability_lane_refuses_evidence_from_an_undeclared_source(
    repository: LabRepository,
) -> None:
    """The same measurement in the other lane, which had the identical defect."""
    policy = load_policy_configuration()
    records = _collect(repository, "R01")
    incident, caller, context = _inputs("R01")
    _, action = DeterministicR01Proposer().propose(incident, caller, context, records)

    assert "observability.error_logs" not in ALLOWED_EVIDENCE_SOURCES["R01"]
    tampered = tuple(
        record.model_copy(update={"tool_name": "observability.error_logs"})
        if record.evidence_id == action.evidence_ids[0]
        else record
        for record in records
    )
    validation = _validator("R01", policy).validate(action, tampered, context)

    assert validation.state is EvidenceState.INVALID
    assert any(
        reason.startswith(UNALLOWED_EVIDENCE_SOURCE_PREFIX) for reason in validation.reasons
    ), validation.reasons


def test_reliability_lane_accepts_the_declared_fixture_sources(
    repository: LabRepository,
) -> None:
    """The control for the reliability arm."""
    policy = load_policy_configuration()
    records = _collect(repository, "R01")
    incident, caller, context = _inputs("R01")
    _, action = DeterministicR01Proposer().propose(incident, caller, context, records)

    validation = _validator("R01", policy).validate(action, records, context)

    assert validation.state is EvidenceState.VALID, validation.reasons


def test_the_old_derived_surface_could_not_have_failed(repository: LabRepository) -> None:
    """The defect itself, pinned as a fact rather than left as a claim in prose.

    Deriving the surface from the records under test admits the tampered record
    too, because the tampering changed the very set the check was built from. The
    same input that the declared surface rejects above is accepted here -- which
    is what "unfalsifiable" meant concretely, and why no amount of test data
    would ever have caught it.
    """
    policy = load_policy_configuration()
    records = _collect(repository, "D3")
    incident, caller, context = _inputs("D3")
    _, action = DeterministicD3Proposer().propose(incident, caller, context, records)
    tampered = tuple(
        record.model_copy(update={"tool_name": "observability.deployment_diff"})
        if record.evidence_id == action.evidence_ids[0]
        else record
        for record in records
    )

    derived = EvidenceValidator(
        policy,
        lambda: datetime.now(UTC),
        allowed_sources=frozenset(record.tool_name for record in tampered),
    ).validate(action, tampered, context)

    assert not any(
        reason.startswith(UNALLOWED_EVIDENCE_SOURCE_PREFIX) for reason in derived.reasons
    ), "the derived surface was supposed to be incapable of rejecting anything"
