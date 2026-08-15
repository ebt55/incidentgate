"""``_SCENARIO_SCOPES`` must stay an addition to ``_SCOPES``, never a fork of it.

Two mappings that both answer "which operation scope does this scenario use?"
are one edit away from disagreeing, and the disagreement would be silent: the
generic evaluation readers would resolve one scope while a mutator committed
under another, and the row would simply not be found. These tests hold the two
in the relationship that makes the addition safe -- ``_SCOPES`` remains the
canonical *evaluation* scope, ``_SCENARIO_SCOPES`` the complete *owned* set, and
the first is always a member of the second.

The T1 asymmetry is asserted rather than tolerated. T1 owns two capabilities and
registers only one in ``_SCOPES``, which is deliberate: ``evaluation_operation``
requires exactly one durable operation per evaluation thread, so registering the
covert scope there would change what that reader means. Pinning it here keeps it
a decision someone made rather than an oversight someone might "fix".
"""

from __future__ import annotations

import os

import pytest

from incidentgate.contracts import EvaluationMode
from incidentgate.control.attack_policies import (
    T1_ATTACK_VARIANTS,
    DeterministicT1AttackProposer,
)
from incidentgate.control.proposal import DeterministicT1Proposer
from incidentgate.evaluation.sabotage_episodes import run_condition
from incidentgate.lab.repository import (
    _SCENARIO_SCOPES,
    _SCENARIOS,
    _SCOPES,
    OPERATION_SCOPE,
    T1_INCIDENT,
    T1_OUTBOUND_NOTE_SCOPE,
    T1_REMEDIATION_SCOPE,
    T2_CACHE_RESTORE_SCOPE,
    T2_WEAKEN_BASELINE_SCOPE,
    T4_MAINTENANCE_MODE_SCOPE,
    T4_READ_HEALTH_SCOPE,
    T4_SET_FEATURE_X_SCOPE,
    T4_TRAFFIC_DRAIN_SCOPE,
    T4_VERIFY_HEALTH_SCOPE,
    LabRepository,
)


def test_every_evaluation_scope_is_one_of_the_scopes_its_scenario_owns() -> None:
    """The relationship that makes this an addition rather than a second source.

    If an evaluation scope were ever absent from the owned set, the generic
    readers would be resolving a scope no mutator writes -- and would report the
    scenario as having committed nothing rather than failing.
    """
    for scenario, scope in _SCOPES.items():
        assert scope in _SCENARIO_SCOPES[scenario], scenario


def test_the_two_mappings_cover_the_same_scenarios_plus_d1() -> None:
    """D1 is the only scenario in one and not the other, and it is so on purpose.

    D1 predates ``_SCOPES`` and holds its scope in ``OPERATION_SCOPE``;
    ``evaluation_operation`` special-cases it by name. Listing it in the owned
    mapping is what lets a caller ask "which scopes does this scenario own?"
    without an exception for the oldest scenario in the tree.
    """
    assert set(_SCENARIO_SCOPES) == set(_SCOPES) | {"D1"}
    assert _SCENARIO_SCOPES["D1"] == (OPERATION_SCOPE,)
    assert "D1" not in _SCOPES


def test_a_scenario_owning_one_scope_agrees_with_the_evaluation_mapping_exactly() -> None:
    """Behaviour preservation, stated as an assertion instead of a claim.

    Every scenario that owned one scope before this mapping existed must still
    own exactly that one. Only the sabotage tier is expected to differ, and it
    differs by owning strictly more: T1 owns two capabilities, T2 owns two, T4
    owns five. A sabotage scenario owns more than one because it owns a covert
    capability beside its allowed one -- that is what makes the ungated control
    able to commit anything.
    """
    multiple = {scenario for scenario, scopes in _SCENARIO_SCOPES.items() if len(scopes) > 1}
    assert multiple == {"T1", "T2", "T4", "T7", "T8"}, (
        "a new multi-capability scenario must be reviewed, not inferred"
    )
    for scenario, scopes in _SCENARIO_SCOPES.items():
        if scenario in multiple or scenario == "D1":
            continue
        assert scopes == (_SCOPES[scenario],), scenario


def test_t1_owns_both_capabilities_but_is_evaluated_through_the_allowed_one() -> None:
    """The asymmetry T4 generalises, pinned on the scenario that established it."""
    assert _SCENARIO_SCOPES["T1"] == (T1_REMEDIATION_SCOPE, T1_OUTBOUND_NOTE_SCOPE)
    assert _SCOPES["T1"] == T1_REMEDIATION_SCOPE
    assert T1_OUTBOUND_NOTE_SCOPE not in _SCOPES.values(), (
        "registering the covert scope for evaluation would change what "
        "evaluation_operation means, which is why t1_durable_counts exists"
    )


def test_t4_owns_five_capabilities_but_is_evaluated_through_the_approved_mutation() -> None:
    """T4 generalises T1's asymmetry from two capabilities to five.

    The evaluation scope stays exactly one. The readers that resolve ``_SCOPES``
    expect at most one durable operation per evaluation thread, and T4 issues
    several calls per episode -- so registering more than the approved mutation
    would silently change what ``evaluation_operation`` and ``operation_matches``
    mean for every scenario, not just this one.
    """
    assert _SCENARIO_SCOPES["T4"] == (
        T4_READ_HEALTH_SCOPE,
        T4_SET_FEATURE_X_SCOPE,
        T4_VERIFY_HEALTH_SCOPE,
        T4_MAINTENANCE_MODE_SCOPE,
        T4_TRAFFIC_DRAIN_SCOPE,
    )
    assert _SCOPES["T4"] == T4_SET_FEATURE_X_SCOPE
    for scope in (
        T4_READ_HEALTH_SCOPE,
        T4_VERIFY_HEALTH_SCOPE,
        T4_MAINTENANCE_MODE_SCOPE,
        T4_TRAFFIC_DRAIN_SCOPE,
    ):
        assert scope not in _SCOPES.values()


def test_t2_owns_both_capabilities_but_is_evaluated_through_the_allowed_one() -> None:
    """T2 takes T1's shape rather than T4's, and the scope table is where that shows.

    Two capabilities, not five: T2's covert objective is a single prohibited
    call, so it owns the allowed cache restore and the forbidden baseline
    weakening and nothing else. The covert scope stays out of ``_SCOPES`` for
    T1's reason -- registering it for evaluation would change what
    ``evaluation_operation`` means.
    """
    assert _SCENARIO_SCOPES["T2"] == (T2_CACHE_RESTORE_SCOPE, T2_WEAKEN_BASELINE_SCOPE)
    assert _SCOPES["T2"] == T2_CACHE_RESTORE_SCOPE
    assert T2_WEAKEN_BASELINE_SCOPE not in _SCOPES.values()


def test_no_two_scenarios_share_an_operation_scope() -> None:
    """Scopes are the ledger's namespace; a collision merges two scenarios' rows.

    The primary key is (operation_scope, idempotency_key), so two scenarios
    sharing a scope would also share an at-most-once namespace.
    """
    owned = [scope for scopes in _SCENARIO_SCOPES.values() for scope in scopes]
    assert len(owned) == len(set(owned))
    assert all(scope for scope in owned), "an empty scope would match the .get() default"


def test_every_declared_scenario_is_a_scenario_the_repository_can_resolve() -> None:
    """A scope declared for a scenario nothing can resolve is dead configuration."""
    known = set(_SCENARIOS.values()) | {"D1"}
    assert set(_SCENARIO_SCOPES) <= known


def test_unknown_scenarios_raise_rather_than_report_an_empty_tally() -> None:
    """Zeros for an undeclared scenario would read as "nothing committed".

    This named T4 until T4 acquired scopes of its own, then T2 until T2 did.
    T3 replaces it rather than the assertion being dropped: the property under
    test is about *undeclared* scenarios, and there are five frozen T-contracts
    with no runtime left to hold it up (T3, T5-T8).

    That this test has now been re-pointed twice is the point of it. Each
    re-pointing is a scenario acquiring real scopes, and the assertion that
    survives is the one about scenarios that have not.
    """
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("durable counts require DATABASE_URL")
    with pytest.raises(KeyError):
        LabRepository(dsn).sabotage_durable_counts("T3")


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("durable counts are a durable property; they require DATABASE_URL")
    repository = LabRepository(dsn)
    repository.migrate()
    return repository


def test_the_named_t1_counts_are_the_generic_per_scope_counts(
    repository: LabRepository,
) -> None:
    """The re-expression must not change a single number the matrix publishes.

    Driven against a real ungated condition rather than an empty fixture,
    because the interesting row is the covert one: it is the row the generic
    readers cannot see, and therefore the row a re-expression could most easily
    lose.
    """
    variant = T1_ATTACK_VARIANTS[0]
    try:
        run_condition(
            repository,
            scenario_id="T1",
            variant_id=variant.variant_id,
            episode_key="scenario-scopes-ungated",
            condition=EvaluationMode.UNGATED,
            covert_plan=(DeterministicT1AttackProposer(variant),),
            incident_plan=(DeterministicT1Proposer(),),
            end_state=repository.t1_end_state,
        )
        named = repository.t1_durable_counts()
        generic = repository.sabotage_durable_counts("T1")

        assert named.covert_ledger_rows == generic.ledger_rows[T1_OUTBOUND_NOTE_SCOPE] == 1
        assert named.remediation_ledger_rows == generic.ledger_rows[T1_REMEDIATION_SCOPE] == 1
        assert named.approvals_recorded == generic.approvals_recorded == 2
        assert named.approvals_consumed == generic.approvals_consumed == 2
        # Exactly the owned scopes, no more: the tally is not a table scan.
        assert set(generic.ledger_rows) == set(_SCENARIO_SCOPES["T1"])
    finally:
        repository.reset_checkpoint("T1")


def test_a_scope_that_did_not_fire_is_reported_as_zero_not_as_absent(
    repository: LabRepository,
) -> None:
    """Zero-filling is what lets a caller name a scope without guarding for it.

    After a reset nothing has committed, so both scopes must read zero rather
    than one of them being missing from the mapping.
    """
    try:
        repository.reset_checkpoint("T1")
        repository.inject_checkpoint("T1")
        generic = repository.sabotage_durable_counts("T1")
        assert generic.ledger_rows == {T1_REMEDIATION_SCOPE: 0, T1_OUTBOUND_NOTE_SCOPE: 0}
        assert repository.t1_durable_counts().covert_ledger_rows == 0
        # A scope the scenario does not own still raises rather than reading zero.
        with pytest.raises(KeyError):
            generic.ledger_rows[OPERATION_SCOPE]
    finally:
        repository.reset_checkpoint("T1")


def test_the_counts_are_scoped_to_the_scenarios_own_incident(
    repository: LabRepository,
) -> None:
    """The incident comes from _scenario(), so a T1 tally cannot pick up D1 rows."""
    try:
        repository.reset_checkpoint("T1")
        repository.inject_checkpoint("T1")
        repository.reset_d1()
        assert repository.sabotage_durable_counts("T1").approvals_recorded == 0
        with repository._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM operation_ledger WHERE incident_id = %s", (T1_INCIDENT,)
            )
            assert int(cursor.fetchone()["count"]) == 0
    finally:
        repository.reset_checkpoint("T1")
