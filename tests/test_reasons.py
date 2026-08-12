"""The freeze: the terminal-reason vocabulary cannot change by accident.

Reasons are wire values. The chaos differ compares them for exact equality and
the reliability evaluation asserts a scenario's reasons equal its frozen
no-action contract, so adding, removing or respelling one silently changes a
verdict. The golden sets below exist to make any such change show up as a
deliberate diff in this file, reviewed on its own terms, rather than as a line
buried in a refactor.

If you are here because this test failed: that is the mechanism working. Decide
whether the vocabulary change is intended, then update the golden set in the
same commit that changes the emission site.
"""

from __future__ import annotations

from incidentgate import reasons
from incidentgate.scenario_registry import NO_ACTION_CATALOG

FROZEN_STATIC_REASONS = frozenset(
    {
        # context guards
        "caller_actor_mismatch",
        "collection_context_mismatch",
        "incident_context_mismatch",
        "no_action_evidence_validation_failed",
        "thread_context_mismatch",
        # policy
        "caller_permission_denied",
        "caller_role_denied",
        "policy_valid",
        "unknown_tool",
        # evidence
        "citations_required",
        "evidence_valid",
        # monitor
        "monitor_action_hash_mismatch",
        "monitor_block",
        # approval, result position
        "approval_token_required",
        "defer_reason_required",
        "human_rejected",
        # recovery
        "recovery_failed",
        "recovery_verified",
        # proposal
        "proposal_ambiguous_evidence",
        "proposal_below_threshold",
        "proposal_context_mismatch",
        "proposal_evidence_unrenderable",
        "proposal_missing_required_evidence",
        "proposal_model_output_invalid",
        "proposal_model_output_truncated",
        "proposal_model_unavailable",
        "proposal_no_d1_fault",
        "proposal_request_too_large",
        "proposal_uncited_evidence",
        "proposal_wrong_config",
        "proposal_wrong_reliability_fixture",
        "proposal_wrong_revision_diff",
        "proposal_wrong_state",
        # budgets and collection outcomes
        "observability_tool_timeout",
        "retry_budget_exhausted",
        "time_budget_exhausted",
        "upstream_timeout",
        # no-action outcomes
        "ambiguous_evidence_human_review_recommended",
        "dns_nxdomain_network_owner_required",
        "lock_auto_release_observed_no_action",
        "stale_evidence_rechecked_no_action",
        "unexpected_certificate_network_owner_required",
        "untrusted_instruction_recorded",
        # audit position
        "approved",
        "approver_role_required",
        "executed",
        "failed",
        "passed",
        "rejected",
        "request_expired",
        "request_not_active",
        "token_required",
    }
)

FROZEN_FAMILY_PREFIXES = frozenset(
    {
        "approval_invalid:",
        "argument_constraint:",
        "correlation_context_mismatch:",
        "cross_context_evidence:",
        "embedded_instruction_data:",
        "expired_evidence:",
        "monitor_verdict:",
        "stale_evidence:",
        "unallowed_evidence_source:",
        "unknown_evidence:",
    }
)


def test_static_reason_vocabulary_is_frozen() -> None:
    added = reasons.STATIC_REASONS - FROZEN_STATIC_REASONS
    removed = FROZEN_STATIC_REASONS - reasons.STATIC_REASONS
    assert not added, f"new reasons must be acknowledged in this golden set: {sorted(added)}"
    assert not removed, f"reasons were removed from the vocabulary: {sorted(removed)}"


def test_reason_family_prefixes_are_frozen() -> None:
    assert reasons.REASON_FAMILY_PREFIXES == FROZEN_FAMILY_PREFIXES


def test_every_family_prefix_ends_with_its_separator() -> None:
    """A prefix without its colon would match unrelated reasons by accident."""
    for prefix in reasons.REASON_FAMILY_PREFIXES:
        assert prefix.endswith(":"), prefix


def test_no_static_reason_collides_with_a_family_prefix() -> None:
    """A static reason that started with a family prefix would be ambiguous."""
    for reason in reasons.STATIC_REASONS:
        for prefix in reasons.REASON_FAMILY_PREFIXES:
            assert not reason.startswith(prefix), f"{reason} shadows family {prefix}"


def test_is_known_reason_accepts_statics_and_populated_families() -> None:
    for reason in reasons.STATIC_REASONS:
        assert reasons.is_known_reason(reason)
    assert reasons.is_known_reason(reasons.approval_invalid(reasons.TOKEN_EXPIRED))
    assert reasons.is_known_reason(reasons.unknown_evidence("ev-1"))
    assert reasons.is_known_reason(reasons.argument_constraint("component"))
    assert reasons.is_known_reason(reasons.monitor_verdict("allow"))


def test_is_known_reason_rejects_strangers_and_bare_prefixes() -> None:
    assert not reasons.is_known_reason("totally_made_up")
    assert not reasons.is_known_reason("")
    # A bare prefix carries no cause and is not a reason.
    for prefix in reasons.REASON_FAMILY_PREFIXES:
        assert not reasons.is_known_reason(prefix)
    # Near-misses of real reasons must not pass.
    assert not reasons.is_known_reason("policy_invalid")
    assert not reasons.is_known_reason("monitor_blocked")


def test_unknown_reasons_reports_only_the_strangers() -> None:
    observed = ("policy_valid", "made_up_reason", "unknown_evidence:ev-9", "another_stranger")
    assert reasons.unknown_reasons(observed) == ("made_up_reason", "another_stranger")
    assert reasons.unknown_reasons(()) == ()
    assert reasons.unknown_reasons(None) == ()


def test_every_token_cause_wraps_into_a_known_reason() -> None:
    """The token causes are only ever legal wrapped; the prefix is what makes them reasons."""
    for cause in reasons.TOKEN_CAUSES:
        assert not reasons.is_known_reason(cause) or cause in reasons.STATIC_REASONS
        assert reasons.is_known_reason(reasons.approval_invalid(cause))


def test_no_action_catalog_reasons_are_all_in_the_frozen_vocabulary() -> None:
    """The scenario contracts and the registry must not be able to drift apart."""
    for scenario, entry in NO_ACTION_CATALOG.items():
        reason = str(entry["reason"])
        assert reasons.is_known_reason(reason), f"{scenario} emits unregistered reason {reason}"
