"""THE GATE CANNOT SILENTLY IGNORE A CONSTRAINT IT WAS GIVEN.

The policy engine used to validate action arguments against a hard-coded name
set inside an if/elif chain with no ``else``. A constraint whose name matched no
branch -- not ``*_pattern``, not ``max_bytes``, not one of fifteen literal plain
names, not ``*_prefix`` -- fell through every branch and was never checked at
all. No error, no reason, no log. The policy author saw a constrained
capability; the gate saw nothing.

In a lab whose central claim is that the gate is deterministic and enforced,
that is the worst available failure mode. It does not produce a red result that
someone investigates. It produces a green one that means nothing.

It was not hypothetical: the R09-R12 work had to add ``backoff_seconds`` and
``response_adapter`` to the hard-coded set for those constraints to be enforced
at all, and the T1 slice sidestepped it by picking names that happened to hit
surviving branches.

These tests close it from three directions.

  1. ENUMERATION -- every argument-constraint name in every policy
     configuration shipped in this repository resolves to a real check over a
     real field of that specific capability's typed contract. A future scenario
     that adds a name with no branch fails here.
  2. BRANCH PROOF -- every ``ArgumentConstraintKind`` is shown denying an actual
     violation through the real engine. "Resolves to a kind" only means
     something because each kind is separately proven to be a checking branch.
  3. FAIL-CLOSED -- a stray name is rejected when the rule is built, and if a
     rule carrying one reaches the engine anyway, the engine denies rather than
     passing over it.

(1) and (2) compose: (1) maps every shipped name onto a kind, (2) proves every
kind is enforced. Together they are the claim "every configured constraint is
actually checked", which neither half states alone.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from incidentgate.contracts import (
    CAPABILITY_ARGUMENT_FIELDS,
    ArgumentConstraintKind,
    CanonicalAction,
    CleanupArgs,
    PolicyConfiguration,
    RestartArgs,
    RestoreConfigArgs,
    Role,
    RouteCustomerReadsPrimaryArgs,
    ToolPolicyRule,
    resolve_argument_constraint,
)
from incidentgate.control.models import EvidenceState, EvidenceValidation
from incidentgate.control.policy import DeterministicPolicyEngine
from incidentgate.reasons import (
    EVIDENCE_VALID,
    POLICY_VALID,
    argument_constraint,
    unenforceable_constraint,
)

ROOT = Path(__file__).resolve().parents[2]
VALID_EVIDENCE = EvidenceValidation(
    state=EvidenceState.VALID, reasons=(EVIDENCE_VALID,), evidence_ids=("ev",), digest=()
)


# ---------------------------------------------------------------------------
# Discovery. The enumeration must not be a list someone maintains by hand --
# that list is exactly what would go stale when a new scenario is added.
# ---------------------------------------------------------------------------
def _is_policy_document(body: object) -> bool:
    return isinstance(body, dict) and {"policy_version", "tools", "modes"} <= set(body)


def _policy_documents(directory: Path) -> list[tuple[Path, dict[str, Any]]]:
    documents = []
    for path in sorted(directory.rglob("*.json")):
        body = json.loads(path.read_text(encoding="utf-8"))
        if _is_policy_document(body):
            documents.append((path, body))
    return documents


POLICY_DOCUMENTS = _policy_documents(ROOT / "config")

# (policy file, tool name, constraint name) for every constraint in the repo.
SHIPPED_CONSTRAINTS: tuple[tuple[str, str, str], ...] = tuple(
    (path.name, tool_name, constraint)
    for path, body in POLICY_DOCUMENTS
    for tool_name, rule in body["tools"].items()
    for constraint in rule["arguments"]
)


def test_the_enumeration_found_the_policy_configurations_it_claims_to_cover() -> None:
    """A discovery sweep that silently found nothing would prove nothing."""
    assert POLICY_DOCUMENTS, "no policy configuration found; the enumeration below is vacuous"
    assert len(SHIPPED_CONSTRAINTS) >= 20, (
        f"only {len(SHIPPED_CONSTRAINTS)} constraints discovered; the sweep is probably broken"
    )


def test_no_scenario_contract_carries_a_policy_configuration_of_its_own() -> None:
    """The enumeration covers ``config/``; this is what makes that sufficient.

    Scenario contracts currently declare capabilities by name (``allowed_actions``,
    ``forbidden_actions``) and hold no ``arguments`` mappings, so every constraint
    in the repository lives in ``config/``. If a scenario ever ships its own
    policy configuration, this fails and says the enumeration must be widened
    rather than letting the new constraints go unenumerated.
    """
    carriers = [
        str(path.relative_to(ROOT))
        for path in sorted((ROOT / "scenarios").rglob("*.json"))
        if _is_policy_document(json.loads(path.read_text(encoding="utf-8")))
    ]
    assert not carriers, (
        f"scenario contracts now carry policy configurations: {carriers}. "
        "Widen _policy_documents() to enumerate them too."
    )


# ---------------------------------------------------------------------------
# 2. BRANCH PROOF -- each kind, shown denying a real violation.
# ---------------------------------------------------------------------------
# Every case is a real capability from the shipped policy, perturbed in exactly
# the argument its rule constrains. ``model_construct`` is how the perturbation
# gets past the typed contract; that is the point, since the gate must not rely
# on the contract having already refused the action.
BRANCH_CASES: tuple[tuple[ArgumentConstraintKind, str, Any, str], ...] = (
    (
        ArgumentConstraintKind.PATTERN,
        "operations.restart",
        RestartArgs.model_construct(kind="restart", component="NOT A COMPONENT"),
        "component",
    ),
    (
        ArgumentConstraintKind.PREFIX,
        "operations.restore_config",
        RestoreConfigArgs.model_construct(
            kind="restore_config",
            component="api",
            variable_name="PAYMENT_TIMEOUT_MS",
            approved_value_ref="s3://elsewhere/value",
        ),
        "approved_value_ref",
    ),
    (
        ArgumentConstraintKind.MAX_BYTES,
        "operations.cleanup",
        CleanupArgs.model_construct(
            kind="cleanup", component="api", cleanup_scope="simulated_logs", max_bytes=1
        ),
        "max_bytes",
    ),
    (
        ArgumentConstraintKind.EQUALITY,
        "operations.route_customer_reads_primary",
        RouteCustomerReadsPrimaryArgs.model_construct(
            kind="route_customer_reads_primary", routing="replica"
        ),
        "routing",
    ),
)

KINDS_WITH_A_PROVEN_BRANCH = frozenset(kind for kind, _, _, _ in BRANCH_CASES)


def _shipped_policy() -> PolicyConfiguration:
    path = ROOT / "config" / "policy.example.json"
    return PolicyConfiguration.model_validate(json.loads(path.read_text(encoding="utf-8")))


def _action(tool_name: str, arguments: Any) -> CanonicalAction:
    return CanonicalAction.model_construct(
        tool_name=tool_name,
        incident_id="INC-CONSTRAINT",
        thread_id="thread",
        actor="operator-1",
        permission="operations:write",
        evidence_ids=("ev",),
        arguments=arguments,
    )


@pytest.mark.parametrize(
    ("kind", "tool_name", "arguments", "argument_key"), BRANCH_CASES, ids=lambda value: str(value)
)
def test_every_constraint_kind_is_an_actual_checking_branch(
    kind: ArgumentConstraintKind, tool_name: str, arguments: Any, argument_key: str
) -> None:
    """Each kind denies a violation, naming the contract field it read."""
    outcome = DeterministicPolicyEngine(_shipped_policy()).evaluate(
        _action(tool_name, arguments), Role.OPERATOR, VALID_EVIDENCE
    )
    assert outcome.decision.value == "deny"
    assert argument_constraint(argument_key) in outcome.reasons


def test_the_branch_proof_covers_every_kind_the_engine_can_resolve() -> None:
    """No kind may exist without a test above proving it is enforced.

    Adding a member to ``ArgumentConstraintKind`` without proving its branch
    would let the enumeration below map a name onto an unenforced kind -- the
    original hole, one level up.
    """
    assert KINDS_WITH_A_PROVEN_BRANCH == set(ArgumentConstraintKind)


# ---------------------------------------------------------------------------
# 1. ENUMERATION -- every shipped constraint name, checked for reachability.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("document", "tool_name", "constraint"),
    SHIPPED_CONSTRAINTS,
    ids=[f"{document}:{tool}:{name}" for document, tool, name in SHIPPED_CONSTRAINTS],
)
def test_every_shipped_constraint_name_reaches_a_checking_branch(
    document: str, tool_name: str, constraint: str
) -> None:
    """The regression guard for the whole defect.

    A future scenario that adds a constraint name the engine cannot check fails
    here -- and, because the same resolution runs in ``ToolPolicyRule``, fails
    at policy construction before any incident runs.
    """
    resolved = resolve_argument_constraint(constraint)
    assert resolved is not None, (
        f"{document}:{tool_name} constrains {constraint!r}, which reaches no checking "
        "branch in the policy engine and would be silently unenforced"
    )
    assert resolved.kind in KINDS_WITH_A_PROVEN_BRANCH
    # And it constrains an argument this capability actually has.
    capability_fields = CAPABILITY_ARGUMENT_FIELDS.get(tool_name)
    assert capability_fields is not None, f"{tool_name} is not a known capability"
    assert resolved.argument_key in capability_fields, (
        f"{document}:{tool_name} constrains {constraint!r} -> {resolved.argument_key!r}, "
        f"which is not one of its arguments: {sorted(capability_fields)}"
    )


# ---------------------------------------------------------------------------
# 3. FAIL-CLOSED -- the stray name itself.
# ---------------------------------------------------------------------------
def _rule(arguments: dict[str, str | int | bool], **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "roles": ["operator"],
        "permission": "operations:write",
        "risk": "medium",
        "approval_required": True,
        "arguments": arguments,
        "evidence": {"citation_required": True, "max_age_seconds": 120},
        "retry_budget": 0,
    }
    return {**body, **overrides}


def test_a_constraint_the_gate_cannot_check_is_rejected_when_the_rule_is_built() -> None:
    """Construction time, because the policy set is static and one file deep.

    The error therefore arrives when the configuration is loaded, not during the
    incident the unenforced constraint was supposed to govern.
    """
    with pytest.raises(ValidationError, match="silently unenforced"):
        ToolPolicyRule.model_validate(_rule({"note_body": "anything"}))
    # A near-miss of a real field is the realistic version of this mistake.
    with pytest.raises(ValidationError, match="silently unenforced"):
        ToolPolicyRule.model_validate(_rule({"cleanup_scoop": "simulated_logs"}))
    # Suffix branches are not an escape hatch: the stem must still be a field.
    with pytest.raises(ValidationError, match="silently unenforced"):
        ToolPolicyRule.model_validate(_rule({"note_body_pattern": "^.*$"}))
    with pytest.raises(ValidationError, match="silently unenforced"):
        ToolPolicyRule.model_validate(_rule({"note_body_prefix": "x"}))


def test_a_constraint_on_a_field_another_capability_owns_is_rejected() -> None:
    """``routing`` is a real field -- just not one ``operations.restart`` has."""
    path = ROOT / "config" / "policy.example.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    body["tools"]["operations.restart"] = _rule({"routing": "primary"})
    with pytest.raises(ValidationError, match="no such argument to constrain"):
        PolicyConfiguration.model_validate(body)


def test_a_stray_constraint_reaching_the_engine_denies_instead_of_passing() -> None:
    """The backstop under the construction-time rejection.

    ``model_construct`` is how a rule gets past validation, and it stands in for
    any future path that assembles a rule without validating it. Before this
    change the engine returned REQUIRE_APPROVAL here: the stray constraint was
    skipped, and the action was treated as having satisfied every constraint the
    policy declared. The control run is the same rule with the stray name
    removed, which still reaches approval -- so the deny below is attributable
    to the stray constraint and to nothing else.
    """
    configuration = _shipped_policy()
    arguments = RouteCustomerReadsPrimaryArgs(
        kind="route_customer_reads_primary", routing="primary"
    )
    action = _action("operations.route_customer_reads_primary", arguments)
    honest_rule = configuration.tools["operations.route_customer_reads_primary"]

    # Control: the untouched rule allows this action through to approval.
    control = DeterministicPolicyEngine(configuration).evaluate(
        action, Role.OPERATOR, VALID_EVIDENCE
    )
    assert control.decision.value == "require_approval"
    assert control.reasons == (POLICY_VALID,)

    # The same action, against the same rule plus one unenforceable constraint.
    smuggled = ToolPolicyRule.model_construct(
        **{**honest_rule.model_dump(), "arguments": {"routing": "primary", "note_body": "anything"}}
    )
    tampered = PolicyConfiguration.model_construct(
        **{
            **configuration.model_dump(),
            "tools": {**configuration.tools, "operations.route_customer_reads_primary": smuggled},
        }
    )
    outcome = DeterministicPolicyEngine(tampered).evaluate(action, Role.OPERATOR, VALID_EVIDENCE)
    assert outcome.decision.value == "deny"
    assert outcome.reasons == (unenforceable_constraint("note_body"),)


def test_a_prohibited_capability_cannot_declare_constraints_it_will_never_check() -> None:
    """The same defect, one level up.

    A prohibited rule denies before it reads any argument, so a constraint
    declared on it is a constraint that is never evaluated -- which is exactly
    the silently-unenforced configuration this module exists to prevent.
    """
    with pytest.raises(ValidationError, match="would never be enforced"):
        ToolPolicyRule.model_validate(
            _rule({"component": "checkout"}, approval_required=False, prohibited=True)
        )


def test_a_prohibited_capability_cannot_also_be_approvable() -> None:
    """No human approval may unlock a prohibition, so none may be declared."""
    with pytest.raises(ValidationError, match="cannot also be approvable"):
        ToolPolicyRule.model_validate(_rule({}, approval_required=True, prohibited=True))


def test_a_satisfied_constraint_does_not_fall_through_into_another_branch() -> None:
    """The old chain folded value comparisons into its branch conditions.

    A satisfied exact-match therefore dropped into the next ``elif`` and was
    re-tested by an unrelated rule. It was harmless only because no plain name
    happened to end in ``_prefix``. Every kind is now decided exactly once, so a
    fully satisfying action reaches approval with no argument reason at all.
    """
    outcome = DeterministicPolicyEngine(_shipped_policy()).evaluate(
        _action(
            "operations.cleanup",
            CleanupArgs(
                kind="cleanup",
                component="api",
                cleanup_scope="simulated_logs",
                max_bytes=67_108_864,
            ),
        ),
        Role.OPERATOR,
        VALID_EVIDENCE,
    )
    assert outcome.decision.value == "require_approval"
    assert outcome.reasons == (POLICY_VALID,)
