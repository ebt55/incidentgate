"""The agreements between the scenario registry and everything that duplicated it.

Before the registry existed, the same twenty-five scenarios were described by
seven independent tables: the tool-name literal on ``CanonicalAction``, the tool
map in ``config/policy.example.json``, the ``OperationsRepository`` Protocol, the
evidence kinds on ``LabEvidenceCollector``, the recovery predicates in
``LabRecoveryVerifier``, the end-state queries in ``chaos/enddiff``, and the two
hand-written scenario lists in ``_scenario_span`` and ``_build_graph``. Every one
of them was correct. Nothing made them agree, and the duplication had already
bitten once: T4 was added to ``_build_graph`` and not to ``_scenario_span``, and
every T4 run failed inside the policy node, a long way from the cause.

These are the agreements made structural. They are checks rather than a
migration on purpose: nothing reads the registry yet, so a failure here is a
statement about the tables as they stand today rather than about the registry
having been mis-copied.

Two of them fail as equalities and are written as the inequality they actually
are, with the finding named. That is the honest form -- see
``test_two_capabilities_share_one_commit_transition`` and
``test_the_mcp_operations_surface_is_smaller_than_the_repository`` below.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, get_args, get_type_hints

import pytest

from incidentgate.contracts import ActionArguments, CanonicalAction, PolicyConfiguration
from incidentgate.integration.adapters import LabEvidenceCollector
from incidentgate.lab.repository import registered_operation_specs
from incidentgate.lab.service import OperationsRepository
from incidentgate.scenario_registry import (
    ACTION_TAKING_SCENARIOS,
    ALLOWED_EVIDENCE_SOURCES,
    FROZEN_RELIABILITY_SCENARIOS,
    FROZEN_SABOTAGE_SCENARIOS,
    NO_ACTION_SCENARIOS,
    RUNNABLE_SCENARIOS,
    SCENARIOS,
    EpisodePolicy,
    ScenarioRuntimeDefinition,
    ScenarioStatus,
    operation_spec_by_tool,
    scope_by_tool,
)

PROMOTED = sorted(
    definition.scenario_id
    for definition in SCENARIOS.values()
    if definition.status is ScenarioStatus.PROMOTED
)
ACTING = sorted(ACTION_TAKING_SCENARIOS)


def _policy_tools() -> set[str]:
    config = PolicyConfiguration.model_validate(
        json.loads((Path(__file__).parents[1] / "config" / "policy.example.json").read_text())
    )
    return set(config.tools)


def _protocol_capabilities() -> set[str]:
    return {
        name
        for name in get_type_hints(OperationsRepository, include_extras=True)
        if not name.startswith("_")
    } or {name for name in vars(OperationsRepository) if not name.startswith("_")}


# ---------------------------------------------------------------------------
# The three hand-agreements between the wire, the policy and the repository
# ---------------------------------------------------------------------------
def test_the_registry_names_exactly_the_tools_the_action_contract_admits() -> None:
    """A capability that cannot be named on the wire cannot be committed."""
    assert set(operation_spec_by_tool()) == set(
        get_args(get_type_hints(CanonicalAction)["tool_name"])
    )


def test_the_registry_names_exactly_the_tools_the_policy_configures() -> None:
    """A registered capability with no policy rule would be ungoverned.

    The reverse gap is the worse one: a policy rule for a capability nothing
    implements would let a published table credit a gate with denying an action
    that could not have happened anyway.
    """
    assert set(operation_spec_by_tool()) == _policy_tools()


def test_the_registry_names_exactly_the_methods_the_repository_protocol_declares() -> None:
    """``lab/service.py``'s structural contract, checked as a set rather than by type."""
    expected = {spec.tool_name.removeprefix("operations.") for spec in registered_operation_specs()}
    assert expected == _protocol_capabilities()


# ---------------------------------------------------------------------------
# Scope identity
# ---------------------------------------------------------------------------
def test_no_two_capabilities_share_an_operation_scope() -> None:
    """The ledger's primary key is (scope, idempotency_key).

    A shared scope would make two capabilities collide on one row under the
    same delivery key -- which is to say, one of them would silently return the
    other's result as a duplicate.
    """
    scopes = [spec.operation_scope for spec in registered_operation_specs()]
    assert len(scopes) == len(set(scopes))


@pytest.mark.parametrize("scenario_id", ACTING, ids=ACTING)
def test_every_evaluation_scope_is_one_of_its_own_scenarios_capabilities(
    scenario_id: str,
) -> None:
    """One durable operation per evaluation thread, and it must be a real one."""
    definition = SCENARIOS[scenario_id]
    owned = {spec.operation_scope for spec in definition.operations()}
    assert owned, f"{scenario_id} takes action but registers no capability"
    assert definition.evaluation_scope in owned


def test_the_scope_lookup_agrees_with_the_specs_it_projects() -> None:
    assert scope_by_tool() == {
        spec.tool_name: spec.operation_scope for spec in registered_operation_specs()
    }


# ---------------------------------------------------------------------------
# The two hand-written scenario lists
# ---------------------------------------------------------------------------
def test_the_action_taking_set_is_the_runnable_set_minus_the_no_action_ones() -> None:
    """The distinction the codebase kept in two sets, derived from one field.

    ``ACTION_TAKING`` is "the runtime builds an action-taking workflow for it";
    ``RUNNABLE`` is "it may produce a published result". They are genuinely
    different questions -- a scenario has a graph before it is promoted -- and
    today the only difference is the no-action scenarios, because nothing is
    currently sitting in the window between the two.
    """
    unpromoted_with_runtime = {
        definition.scenario_id
        for definition in SCENARIOS.values()
        if definition.status is ScenarioStatus.HAS_RUNTIME_UNPROMOTED
    }
    assert ACTION_TAKING_SCENARIOS == (RUNNABLE_SCENARIOS - NO_ACTION_SCENARIOS) | (
        unpromoted_with_runtime
    )


def test_the_promoted_set_is_the_runnable_set() -> None:
    """C7 turns this into a derivation; here it is still an agreement."""
    assert set(PROMOTED) == set(RUNNABLE_SCENARIOS)


# ---------------------------------------------------------------------------
# What a promoted scenario has to have declared
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("scenario_id", PROMOTED, ids=PROMOTED)
def test_every_promoted_scenario_declares_a_durable_end_state_to_diff(
    scenario_id: str,
) -> None:
    """Promotion makes a scenario kill-matrix eligible, so it needs a capture.

    Without one the chaos differ has nothing to compare and every cell for it
    would be vacuously clean.
    """
    assert SCENARIOS[scenario_id].fixture_capture is not None


@pytest.mark.parametrize(
    "scenario_id", [s for s in PROMOTED if s.startswith("T")], ids=lambda s: s
)
def test_every_promoted_sabotage_scenario_declares_a_covert_surface(scenario_id: str) -> None:
    """An empty covert capture means "declares no covert store", not "measured empty".

    That convention is what makes a green covert cell mean something, so a
    promoted sabotage scenario without one would publish a permanently clean
    column about nothing.
    """
    assert SCENARIOS[scenario_id].covert_capture is not None


@pytest.mark.parametrize("scenario_id", ACTING, ids=ACTING)
def test_every_action_taking_scenario_declares_how_recovery_is_verified(
    scenario_id: str,
) -> None:
    """Fresh post-commit evidence before a recovery claim needs a claim to make."""
    definition = SCENARIOS[scenario_id]
    assert definition.recovery_predicate
    assert definition.recovery_evidence_kinds


@pytest.mark.parametrize("scenario_id", ACTING, ids=ACTING)
def test_every_action_taking_scenario_names_a_proposer_that_exists(scenario_id: str) -> None:
    """The graph builder resolves this name at build time, so it has to resolve."""
    from incidentgate.control import proposal

    name = SCENARIOS[scenario_id].proposer
    assert name is not None
    assert callable(getattr(proposal, name))


# ---------------------------------------------------------------------------
# The registry against the tables it will replace
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS), ids=sorted(SCENARIOS))
def test_the_declared_evidence_kinds_match_the_collector_that_reads_them(
    scenario_id: str,
) -> None:
    collector_kinds = LabEvidenceCollector._kinds
    definition = SCENARIOS[scenario_id]
    if definition.status is ScenarioStatus.FROZEN_CONTRACT_ONLY:
        assert definition.evidence_kinds == ()
        assert scenario_id not in collector_kinds
        return
    assert definition.evidence_kinds == collector_kinds[scenario_id]


@pytest.mark.parametrize("scenario_id", ACTING, ids=ACTING)
def test_the_declared_evidence_allowlist_matches_the_contract_projection(
    scenario_id: str,
) -> None:
    assert SCENARIOS[scenario_id].allowed_evidence_sources == ALLOWED_EVIDENCE_SOURCES[scenario_id]


# ---------------------------------------------------------------------------
# The arguments class is the binding, from both ends
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "spec",
    sorted(registered_operation_specs(), key=lambda spec: spec.operation_scope),
    ids=lambda spec: spec.operation_scope,
)
def test_every_capability_is_bound_to_a_reachable_arguments_class(spec: Any) -> None:
    """``CanonicalAction`` validates ``tool_name == f"operations.{kind}"``.

    Binding off the class and asserting the name is what closes that loop from
    the other end, so a capability cannot be registered against an arguments
    class no action could ever carry.
    """
    # ActionArguments is an Annotated discriminated union, so the members are one
    # unwrapping in: get_args gives (union, FieldInfo).
    members = set(get_args(get_args(ActionArguments)[0]))
    assert members, "the action-arguments union no longer unwraps the way this reads it"
    assert spec.arguments_type in members
    kind = get_args(get_type_hints(spec.arguments_type)["kind"])[0]
    assert spec.tool_name == f"operations.{kind}"


# ---------------------------------------------------------------------------
# The disagreements. Recorded as they are, not repaired.
# ---------------------------------------------------------------------------
def test_two_capabilities_share_one_commit_transition() -> None:
    """A finding, written as what it is rather than as a check that fails.

    The completeness rule this replaces was "commit_transition values are
    unique". They are not: D3 and D8 both emit ``restart_committed``, because
    both of them really are a restart and the audit vocabulary names the
    transition rather than the scenario.

    That is load-bearing rather than sloppy. ``chaos/enddiff`` compares
    ``audit_sequence`` as (event_type, actor, reason, action_hash-present) for
    exact equality within one incident, and D3 and D8 are different incidents,
    so the shared name is never ambiguous where it is read. Making the values
    unique would rename a published audit event for no gain. The rule that
    holds is the weaker, true one: unique *per incident*.
    """
    by_incident: dict[str, list[str]] = {}
    for spec in registered_operation_specs():
        if spec.commit_transition is not None:
            by_incident.setdefault(spec.incident_id, []).append(spec.commit_transition)
    for incident, transitions in by_incident.items():
        assert len(transitions) == len(set(transitions)), incident
    shared = [
        spec.commit_transition
        for spec in registered_operation_specs()
        if spec.commit_transition is not None
    ]
    assert len(shared) != len(set(shared)), (
        "if commit transitions became globally unique, this finding is stale"
    )


def test_the_mcp_operations_surface_is_smaller_than_the_repository() -> None:
    """A second finding, and the reason it is recorded rather than closed.

    The MCP operations server surfaces thirteen of the twenty-two registered
    capabilities. The nine it omits are the whole sabotage tier -- T1's two,
    T2's two and T4's five -- so a client speaking only MCP cannot reach any
    capability the sabotage measurements depend on.

    That gap is a protocol-boundary question, not a registry question: closing
    it means deciding whether the forbidden capabilities should be reachable
    over a transport at all, which is a different phase's decision. Recorded
    here because the registry is the first place both sets have been countable
    side by side.
    """
    from incidentgate.mcp_servers.operations import OperationsAdapter

    served = {name for name in vars(OperationsAdapter) if not name.startswith("_")}
    registered = {
        spec.tool_name.removeprefix("operations.") for spec in registered_operation_specs()
    }
    assert not served - registered, "the MCP surface serves something nothing registers"
    assert sorted(registered - served) == [
        "read_checkout_health",
        "record_checkout_remediation",
        "restore_cache",
        "set_checkout_feature_x_false",
        "set_checkout_maintenance_mode",
        "set_checkout_traffic_drain",
        "verify_checkout_health",
        "weaken_permission_or_audit",
        "write_outbound_note",
    ]


# ---------------------------------------------------------------------------
# Placeholder derivation: derive what is not built, keep the admitted set literal
# ---------------------------------------------------------------------------
def test_the_unbuilt_scenarios_are_derived_and_non_empty() -> None:
    """The set that must never be hand-written, because it shrinks on promotion."""
    unbuilt = {
        definition.scenario_id
        for definition in SCENARIOS.values()
        if definition.status is ScenarioStatus.FROZEN_CONTRACT_ONLY
    }
    assert unbuilt
    assert unbuilt == (FROZEN_SABOTAGE_SCENARIOS | FROZEN_RELIABILITY_SCENARIOS) - (
        RUNNABLE_SCENARIOS
    )


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS), ids=sorted(SCENARIOS))
def test_a_frozen_contract_only_scenario_declares_nothing_it_does_not_have(
    scenario_id: str,
) -> None:
    definition: ScenarioRuntimeDefinition = SCENARIOS[scenario_id]
    if definition.status is not ScenarioStatus.FROZEN_CONTRACT_ONLY:
        return
    assert definition.operations() == ()
    assert definition.proposer is None
    assert definition.fixture_capture is None
    assert definition.evaluation_scope is None
    assert definition.episode_policy is EpisodePolicy.SINGLE_CALL
