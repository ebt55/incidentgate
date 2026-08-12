"""Deterministic, deny-first evaluation of the frozen policy configuration."""

from __future__ import annotations

import re

from incidentgate.contracts import (
    CanonicalAction,
    PolicyConfiguration,
    PolicyDecision,
    PolicyOutcome,
    Role,
    canonical_action_hash,
)
from incidentgate.reasons import (
    CALLER_PERMISSION_DENIED,
    CALLER_ROLE_DENIED,
    POLICY_VALID,
    UNKNOWN_TOOL,
    argument_constraint,
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
        else:
            if caller not in rule.roles:
                reasons.append(CALLER_ROLE_DENIED)
            if action.permission != rule.permission:
                reasons.append(CALLER_PERMISSION_DENIED)
            arguments = action.arguments.model_dump(mode="python")
            for name, constraint in rule.arguments.items():
                # ``bool`` is a subclass of ``int`` in Python.  Policy literals
                # are capability bindings, so their types must match as well.
                if name in arguments and type(arguments[name]) is not type(constraint):
                    reasons.append(argument_constraint(name))
                    continue
                if name.endswith("_pattern"):
                    key = name.removesuffix("_pattern")
                    if not re.fullmatch(str(constraint), str(arguments.get(key, ""))):
                        reasons.append(argument_constraint(key))
                elif name == "max_bytes" and int(arguments.get(name, -1)) != int(constraint):
                    reasons.append(argument_constraint("max_bytes"))
                elif (
                    name
                    in {
                        "component",
                        "cleanup_scope",
                        "schema_version",
                        "flag",
                        "enabled",
                        "variable_name",
                        "value",
                        "config_version",
                        "old_pods",
                        "new_pods",
                        "index",
                        "routing",
                        "active_id",
                        "backoff_seconds",
                        "response_adapter",
                    }
                    and arguments.get(name) != constraint
                ):
                    reasons.append(argument_constraint(name))
                elif name.endswith("_prefix"):
                    key = name.removesuffix("_prefix")
                    # The frozen policy uses the capability-neutral name while the
                    # typed contract calls the field ``approved_value_ref``.
                    argument_key = "approved_value_ref" if key == "value_reference" else key
                    if not str(arguments.get(argument_key, "")).startswith(str(constraint)):
                        reasons.append(argument_constraint(argument_key))
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
