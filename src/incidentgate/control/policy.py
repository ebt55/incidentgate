"""Deterministic, deny-first evaluation of the frozen policy configuration."""

from __future__ import annotations

import re

from incidentgate.contracts import (
    ArgumentConstraintKind,
    CanonicalAction,
    PolicyConfiguration,
    PolicyDecision,
    PolicyOutcome,
    Role,
    canonical_action_hash,
    resolve_argument_constraint,
)
from incidentgate.reasons import (
    CALLER_PERMISSION_DENIED,
    CALLER_ROLE_DENIED,
    CAPABILITY_PROHIBITED,
    POLICY_VALID,
    UNKNOWN_TOOL,
    argument_constraint,
    unenforceable_constraint,
)

from .models import EvidenceState, EvidenceValidation


class DeterministicPolicyEngine:
    def __init__(self, configuration: PolicyConfiguration) -> None:
        self.configuration = configuration

    def evaluate(
        self, action: CanonicalAction, caller: Role, evidence: EvidenceValidation
    ) -> PolicyOutcome:
        action_hash = canonical_action_hash(action)
        rule = self.configuration.tools.get(action.tool_name)
        reasons: list[str] = []
        if rule is None:
            reasons.append(UNKNOWN_TOOL)
        elif rule.prohibited:
            # A prohibition is the whole decision, so it is the whole reason.
            #
            # Nothing downstream is consulted -- not the permission, not the
            # arguments, not the evidence. That is deliberate: the refusal must
            # not become contingent on the quality of the proposal. A covert
            # action denied here is denied identically whether its evidence was
            # fresh or stale, which is what lets the result row be read as a
            # statement about the gate rather than about the attempt.
            #
            # ``roles`` names the caller contexts the prohibition is stated
            # against. A caller outside them still meets the ordinary role
            # denial below the rule, so default-deny remains the backstop.
            reasons.append(CAPABILITY_PROHIBITED if caller in rule.roles else CALLER_ROLE_DENIED)
        else:
            if caller not in rule.roles:
                reasons.append(CALLER_ROLE_DENIED)
            if action.permission != rule.permission:
                reasons.append(CALLER_PERMISSION_DENIED)
            arguments = action.arguments.model_dump(mode="python")
            for name, constraint in rule.arguments.items():
                resolved = resolve_argument_constraint(name)
                if resolved is None:
                    # FAIL CLOSED.  ``ToolPolicyRule`` rejects these at
                    # construction, so this is the backstop for a rule that got
                    # past validation -- ``model_construct``, or any future
                    # dynamically assembled rule.  Denying is the only honest
                    # option: a constraint the engine cannot check must never
                    # read as a constraint the action satisfied.
                    reasons.append(unenforceable_constraint(name))
                    continue
                # ``bool`` is a subclass of ``int`` in Python.  Policy literals
                # are capability bindings, so their types must match as well.
                if name in arguments and type(arguments[name]) is not type(constraint):
                    reasons.append(argument_constraint(name))
                    continue
                key = resolved.argument_key
                # Exhaustive over ArgumentConstraintKind, and deliberately a
                # match rather than an if/elif chain: the previous chain had no
                # ``else``, and folded the value comparisons into the branch
                # conditions, so a satisfied constraint fell through into the
                # next branch's test.  Every kind is now decided exactly once.
                match resolved.kind:
                    case ArgumentConstraintKind.PATTERN:
                        satisfied = (
                            re.fullmatch(str(constraint), str(arguments.get(key, ""))) is not None
                        )
                    case ArgumentConstraintKind.PREFIX:
                        satisfied = str(arguments.get(key, "")).startswith(str(constraint))
                    case ArgumentConstraintKind.MAX_BYTES:
                        satisfied = int(arguments.get(key, -1)) == int(constraint)
                    case ArgumentConstraintKind.EQUALITY:
                        satisfied = arguments.get(key) == constraint
                if not satisfied:
                    reasons.append(argument_constraint(key))
            if evidence.state is not EvidenceState.VALID:
                reasons.extend(evidence.reasons)
        if reasons:
            return PolicyOutcome(
                decision=PolicyDecision.DENY,
                policy_version=self.configuration.policy_version,
                reasons=tuple(sorted(set(reasons))),
                action_hash=action_hash,
            )
        decision = (
            PolicyDecision.REQUIRE_APPROVAL
            if rule and rule.approval_required
            else PolicyDecision.ALLOW
        )
        return PolicyOutcome(
            decision=decision,
            policy_version=self.configuration.policy_version,
            reasons=(POLICY_VALID,),
            action_hash=action_hash,
        )
