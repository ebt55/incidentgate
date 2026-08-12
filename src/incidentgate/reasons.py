"""The frozen terminal-reason vocabulary.

Every reason string this system emits is a wire value. Reasons land in
``WorkflowResult.reasons`` and in ``audit_timeline.payload.reason``; the chaos
end-state differ compares both for exact equality (``chaos/enddiff.py`` field
specs ``terminal_reasons`` and ``audit_sequence``), and the reliability
evaluation asserts a scenario's reasons equal its frozen no-action contract.
A typo in any of them is not a cosmetic defect: it is a silent verdict change.

Until this module existed the vocabulary was held only by the emission sites
themselves -- 70-odd literals spread across nine files, several spelled two
ways, with nothing anywhere that could enumerate them. ``enddiff`` already
described the field as "fixed vocabulary values; no normalization needed",
which was an aspiration rather than a fact. This module makes it a fact.

Placement is deliberate. This is a top-level leaf module beside ``contracts``:
it imports nothing from the package, so ``control``, ``evaluation``, ``chaos``,
``lab``, ``integration`` and ``scenario_registry`` can all depend on it without
a cycle and without an inversion. Putting it under ``control`` would have made
the lab substrate and the chaos harness import from the control plane.

Two kinds of reason live here:

* **Static reasons** -- fixed strings, enumerated in ``STATIC_REASONS``.
* **Parameterized families** -- a fixed prefix plus a run-scoped suffix (an
  evidence id, an argument name, a token-validation cause). These cannot be
  enumerated, so each one gets a constructor function and a prefix in
  ``REASON_FAMILY_PREFIXES``. Constructing them here is what keeps free-form
  f-string interpolation of reasons out of the emission sites.

Adding a reason means editing this module, which makes the golden freeze test
in ``tests/test_reasons.py`` fail until the addition is acknowledged. That
failure is the point.
"""

from __future__ import annotations

from typing import Final

# --------------------------------------------------------------------------
# Context guards -- the envelope did not match the durable incident identity.
# --------------------------------------------------------------------------
COLLECTION_CONTEXT_MISMATCH: Final = "collection_context_mismatch"
THREAD_CONTEXT_MISMATCH: Final = "thread_context_mismatch"
INCIDENT_CONTEXT_MISMATCH: Final = "incident_context_mismatch"
CALLER_ACTOR_MISMATCH: Final = "caller_actor_mismatch"
NO_ACTION_EVIDENCE_VALIDATION_FAILED: Final = "no_action_evidence_validation_failed"

# --------------------------------------------------------------------------
# Policy.  ``POLICY_VALID`` is emitted from three different nodes on purpose:
# the policy result is re-audited at each gate it survives, so the audit trail
# shows the decision still holding rather than being asserted once and assumed.
# --------------------------------------------------------------------------
POLICY_VALID: Final = "policy_valid"
UNKNOWN_TOOL: Final = "unknown_tool"
CALLER_ROLE_DENIED: Final = "caller_role_denied"
CALLER_PERMISSION_DENIED: Final = "caller_permission_denied"
# The policy knows this capability and refuses it for this caller context.
# Deliberately distinct from UNKNOWN_TOOL, which says only that no rule was
# found: the two are different facts about the gate and a result row that
# conflates them overstates one and understates the other.  A prohibition is a
# decision the audit trail can attribute; an unknown tool is default-deny.
CAPABILITY_PROHIBITED: Final = "capability_prohibited"

# --------------------------------------------------------------------------
# Evidence validation.  These reach the result through policy: a denied policy
# outcome extends its own reasons with the evidence reasons, so the two
# vocabularies are not disjoint (``UNKNOWN_TOOL`` is emitted by both).
# --------------------------------------------------------------------------
EVIDENCE_VALID: Final = "evidence_valid"
CITATIONS_REQUIRED: Final = "citations_required"

# --------------------------------------------------------------------------
# Monitor.
# --------------------------------------------------------------------------
MONITOR_BLOCK: Final = "monitor_block"
MONITOR_ACTION_HASH_MISMATCH: Final = "monitor_action_hash_mismatch"

# --------------------------------------------------------------------------
# Approval, result position.
# --------------------------------------------------------------------------
HUMAN_REJECTED: Final = "human_rejected"
DEFER_REASON_REQUIRED: Final = "defer_reason_required"
APPROVAL_TOKEN_REQUIRED: Final = "approval_token_required"

# --------------------------------------------------------------------------
# Recovery verification.
# --------------------------------------------------------------------------
RECOVERY_VERIFIED: Final = "recovery_verified"
RECOVERY_FAILED: Final = "recovery_failed"

# --------------------------------------------------------------------------
# Proposal, deterministic and model-backed.
# --------------------------------------------------------------------------
PROPOSAL_CONTEXT_MISMATCH: Final = "proposal_context_mismatch"
PROPOSAL_MISSING_REQUIRED_EVIDENCE: Final = "proposal_missing_required_evidence"
PROPOSAL_AMBIGUOUS_EVIDENCE: Final = "proposal_ambiguous_evidence"
PROPOSAL_NO_D1_FAULT: Final = "proposal_no_d1_fault"
PROPOSAL_WRONG_REVISION_DIFF: Final = "proposal_wrong_revision_diff"
PROPOSAL_WRONG_STATE: Final = "proposal_wrong_state"
PROPOSAL_WRONG_CONFIG: Final = "proposal_wrong_config"
PROPOSAL_BELOW_THRESHOLD: Final = "proposal_below_threshold"
PROPOSAL_WRONG_RELIABILITY_FIXTURE: Final = "proposal_wrong_reliability_fixture"
PROPOSAL_MODEL_OUTPUT_TRUNCATED: Final = "proposal_model_output_truncated"
PROPOSAL_MODEL_OUTPUT_INVALID: Final = "proposal_model_output_invalid"
PROPOSAL_MODEL_UNAVAILABLE: Final = "proposal_model_unavailable"
PROPOSAL_UNCITED_EVIDENCE: Final = "proposal_uncited_evidence"
PROPOSAL_EVIDENCE_UNRENDERABLE: Final = "proposal_evidence_unrenderable"
PROPOSAL_REQUEST_TOO_LARGE: Final = "proposal_request_too_large"

# --------------------------------------------------------------------------
# Budgets and collection outcomes.  ``RETRY_BUDGET_EXHAUSTED`` is emitted from
# four places -- the D4 and D7 no-action catalog entries, the deferred
# collector's initial value, and the repository's attempt accounting -- which
# is why it is one constant rather than four spellings that happen to agree.
# --------------------------------------------------------------------------
RETRY_BUDGET_EXHAUSTED: Final = "retry_budget_exhausted"
TIME_BUDGET_EXHAUSTED: Final = "time_budget_exhausted"
UPSTREAM_TIMEOUT: Final = "upstream_timeout"
OBSERVABILITY_TOOL_TIMEOUT: Final = "observability_tool_timeout"

# --------------------------------------------------------------------------
# No-action outcomes.  These are deliberately descriptive rather than terse:
# each one is the whole finding, readable without the scenario contract in
# hand, and they are frozen in that form.
# --------------------------------------------------------------------------
LOCK_AUTO_RELEASE_OBSERVED_NO_ACTION: Final = "lock_auto_release_observed_no_action"
DNS_NXDOMAIN_NETWORK_OWNER_REQUIRED: Final = "dns_nxdomain_network_owner_required"
UNEXPECTED_CERTIFICATE_NETWORK_OWNER_REQUIRED: Final = (
    "unexpected_certificate_network_owner_required"
)
STALE_EVIDENCE_RECHECKED_NO_ACTION: Final = "stale_evidence_rechecked_no_action"
UNTRUSTED_INSTRUCTION_RECORDED: Final = "untrusted_instruction_recorded"
AMBIGUOUS_EVIDENCE_HUMAN_REVIEW_RECOMMENDED: Final = "ambiguous_evidence_human_review_recommended"

# --------------------------------------------------------------------------
# Token validation causes.
#
# These are NOT reasons on their own.  Each one only ever reaches a result or
# an audit entry wrapped by ``approval_invalid()``, so the family prefix is
# what disambiguates them.  That matters for ``TOKEN_ACTION_HASH_MISMATCH``:
# the bare string ``action_hash_mismatch`` also describes a monitor
# disagreement, and the two are different facts.  The monitor one is
# ``MONITOR_ACTION_HASH_MISMATCH`` and is never wrapped; this one is never
# unwrapped.  ``TOKEN_VALID`` is the success return and never becomes a reason.
# --------------------------------------------------------------------------
TOKEN_MISSING: Final = "missing"
TOKEN_ACTION_HASH_MISMATCH: Final = "action_hash_mismatch"
TOKEN_ACTOR_MISMATCH: Final = "actor_mismatch"
TOKEN_APPROVER_MISMATCH: Final = "approver_mismatch"
TOKEN_ONE_TIME_USE_ID_MISMATCH: Final = "one_time_use_id_mismatch"
TOKEN_REQUESTED_AT_MISMATCH: Final = "requested_at_mismatch"
TOKEN_APPROVED_AT_MISMATCH: Final = "approved_at_mismatch"
TOKEN_EXPIRES_AT_MISMATCH: Final = "expires_at_mismatch"
TOKEN_CONSUMED: Final = "consumed"
TOKEN_EXPIRED: Final = "expired"
TOKEN_VALID: Final = "valid"

TOKEN_CAUSES: Final[frozenset[str]] = frozenset(
    {
        TOKEN_MISSING,
        TOKEN_ACTION_HASH_MISMATCH,
        TOKEN_ACTOR_MISMATCH,
        TOKEN_APPROVER_MISMATCH,
        TOKEN_ONE_TIME_USE_ID_MISMATCH,
        TOKEN_REQUESTED_AT_MISMATCH,
        TOKEN_APPROVED_AT_MISMATCH,
        TOKEN_EXPIRES_AT_MISMATCH,
        TOKEN_CONSUMED,
        TOKEN_EXPIRED,
        TOKEN_VALID,
    }
)

# --------------------------------------------------------------------------
# Audit-position reasons.
#
# The audit timeline is compared by the chaos differ exactly as strictly as the
# terminal reasons are, so its vocabulary is frozen here too.  These describe
# what happened at a gate rather than why an incident terminated.
# --------------------------------------------------------------------------
AUDIT_REJECTED: Final = "rejected"
AUDIT_TOKEN_REQUIRED: Final = "token_required"
AUDIT_APPROVED: Final = "approved"
AUDIT_EXECUTED: Final = "executed"
AUDIT_PASSED: Final = "passed"
AUDIT_FAILED: Final = "failed"
AUDIT_APPROVER_ROLE_REQUIRED: Final = "approver_role_required"
AUDIT_REQUEST_NOT_ACTIVE: Final = "request_not_active"
AUDIT_REQUEST_EXPIRED: Final = "request_expired"

# --------------------------------------------------------------------------
# Parameterized families.
# --------------------------------------------------------------------------
APPROVAL_INVALID_PREFIX: Final = "approval_invalid:"
MONITOR_VERDICT_PREFIX: Final = "monitor_verdict:"
ARGUMENT_CONSTRAINT_PREFIX: Final = "argument_constraint:"
UNENFORCEABLE_CONSTRAINT_PREFIX: Final = "unenforceable_constraint:"
UNKNOWN_EVIDENCE_PREFIX: Final = "unknown_evidence:"
CROSS_CONTEXT_EVIDENCE_PREFIX: Final = "cross_context_evidence:"
CORRELATION_CONTEXT_MISMATCH_PREFIX: Final = "correlation_context_mismatch:"
EXPIRED_EVIDENCE_PREFIX: Final = "expired_evidence:"
STALE_EVIDENCE_PREFIX: Final = "stale_evidence:"
UNALLOWED_EVIDENCE_SOURCE_PREFIX: Final = "unallowed_evidence_source:"
EMBEDDED_INSTRUCTION_DATA_PREFIX: Final = "embedded_instruction_data:"


def approval_invalid(cause: str) -> str:
    """Wrap a token-validation cause. Used at both the result and audit positions."""
    return f"{APPROVAL_INVALID_PREFIX}{cause}"


def monitor_verdict(verdict: object) -> str:
    """Name the advisory verdict an audit entry recorded.

    The audit position used to persist ``str(verdict)`` -- a bare StrEnum repr,
    so ``block`` -- which collided with nothing but stood alone in the
    vocabulary as the only unprefixed enum value, and read as a second spelling
    of ``monitor_block``. Prefixing it says which axis the value belongs to.
    """
    return f"{MONITOR_VERDICT_PREFIX}{verdict}"


def argument_constraint(argument_name: str) -> str:
    """Name the frozen capability argument whose binding the action violated."""
    return f"{ARGUMENT_CONSTRAINT_PREFIX}{argument_name}"


def unenforceable_constraint(constraint_name: str) -> str:
    """Name a policy constraint the gate has no branch to check.

    This is a deny reason about the *policy*, not about the action -- which is
    why it is not an ``argument_constraint``. It says the configuration asked
    for a check the engine cannot perform, so the engine refused rather than
    proceeding as though the constraint had been satisfied. Reaching it means a
    rule was built past ``ToolPolicyRule`` validation (``model_construct``, or
    some future dynamically assembled rule); the deny is the backstop under the
    construction-time rejection, not a substitute for it.
    """
    return f"{UNENFORCEABLE_CONSTRAINT_PREFIX}{constraint_name}"


def unknown_evidence(evidence_id: str) -> str:
    """Cited evidence that was not collected."""
    return f"{UNKNOWN_EVIDENCE_PREFIX}{evidence_id}"


def cross_context_evidence(evidence_id: str) -> str:
    """Evidence belonging to a different incident or thread."""
    return f"{CROSS_CONTEXT_EVIDENCE_PREFIX}{evidence_id}"


def correlation_context_mismatch(evidence_id: str) -> str:
    """Evidence carrying a different correlation id than the call envelope."""
    return f"{CORRELATION_CONTEXT_MISMATCH_PREFIX}{evidence_id}"


def expired_evidence(evidence_id: str) -> str:
    """Evidence past its own expiry."""
    return f"{EXPIRED_EVIDENCE_PREFIX}{evidence_id}"


def stale_evidence(evidence_id: str) -> str:
    """Evidence older than the tool's freshness rule."""
    return f"{STALE_EVIDENCE_PREFIX}{evidence_id}"


def unallowed_evidence_source(evidence_id: str) -> str:
    """Evidence produced by a tool outside the allowed source set."""
    return f"{UNALLOWED_EVIDENCE_SOURCE_PREFIX}{evidence_id}"


def embedded_instruction_data(evidence_id: str) -> str:
    """Evidence whose payload contained instruction-shaped text."""
    return f"{EMBEDDED_INSTRUCTION_DATA_PREFIX}{evidence_id}"


STATIC_REASONS: Final[frozenset[str]] = frozenset(
    {
        COLLECTION_CONTEXT_MISMATCH,
        THREAD_CONTEXT_MISMATCH,
        INCIDENT_CONTEXT_MISMATCH,
        CALLER_ACTOR_MISMATCH,
        NO_ACTION_EVIDENCE_VALIDATION_FAILED,
        POLICY_VALID,
        UNKNOWN_TOOL,
        CALLER_ROLE_DENIED,
        CALLER_PERMISSION_DENIED,
        CAPABILITY_PROHIBITED,
        EVIDENCE_VALID,
        CITATIONS_REQUIRED,
        MONITOR_BLOCK,
        MONITOR_ACTION_HASH_MISMATCH,
        HUMAN_REJECTED,
        DEFER_REASON_REQUIRED,
        APPROVAL_TOKEN_REQUIRED,
        RECOVERY_VERIFIED,
        RECOVERY_FAILED,
        PROPOSAL_CONTEXT_MISMATCH,
        PROPOSAL_MISSING_REQUIRED_EVIDENCE,
        PROPOSAL_AMBIGUOUS_EVIDENCE,
        PROPOSAL_NO_D1_FAULT,
        PROPOSAL_WRONG_REVISION_DIFF,
        PROPOSAL_WRONG_STATE,
        PROPOSAL_WRONG_CONFIG,
        PROPOSAL_BELOW_THRESHOLD,
        PROPOSAL_WRONG_RELIABILITY_FIXTURE,
        PROPOSAL_MODEL_OUTPUT_TRUNCATED,
        PROPOSAL_MODEL_OUTPUT_INVALID,
        PROPOSAL_MODEL_UNAVAILABLE,
        PROPOSAL_UNCITED_EVIDENCE,
        PROPOSAL_EVIDENCE_UNRENDERABLE,
        PROPOSAL_REQUEST_TOO_LARGE,
        RETRY_BUDGET_EXHAUSTED,
        TIME_BUDGET_EXHAUSTED,
        UPSTREAM_TIMEOUT,
        OBSERVABILITY_TOOL_TIMEOUT,
        LOCK_AUTO_RELEASE_OBSERVED_NO_ACTION,
        DNS_NXDOMAIN_NETWORK_OWNER_REQUIRED,
        UNEXPECTED_CERTIFICATE_NETWORK_OWNER_REQUIRED,
        STALE_EVIDENCE_RECHECKED_NO_ACTION,
        UNTRUSTED_INSTRUCTION_RECORDED,
        AMBIGUOUS_EVIDENCE_HUMAN_REVIEW_RECOMMENDED,
        AUDIT_REJECTED,
        AUDIT_TOKEN_REQUIRED,
        AUDIT_APPROVED,
        AUDIT_EXECUTED,
        AUDIT_PASSED,
        AUDIT_FAILED,
        AUDIT_APPROVER_ROLE_REQUIRED,
        AUDIT_REQUEST_NOT_ACTIVE,
        AUDIT_REQUEST_EXPIRED,
    }
)

REASON_FAMILY_PREFIXES: Final[frozenset[str]] = frozenset(
    {
        APPROVAL_INVALID_PREFIX,
        MONITOR_VERDICT_PREFIX,
        ARGUMENT_CONSTRAINT_PREFIX,
        UNKNOWN_EVIDENCE_PREFIX,
        CROSS_CONTEXT_EVIDENCE_PREFIX,
        CORRELATION_CONTEXT_MISMATCH_PREFIX,
        EXPIRED_EVIDENCE_PREFIX,
        STALE_EVIDENCE_PREFIX,
        UNALLOWED_EVIDENCE_SOURCE_PREFIX,
        EMBEDDED_INSTRUCTION_DATA_PREFIX,
        UNENFORCEABLE_CONSTRAINT_PREFIX,
    }
)


def is_known_reason(reason: str) -> bool:
    """True when ``reason`` is in the frozen vocabulary.

    Static reasons match exactly. Family members match by prefix and must carry
    a non-empty suffix, so a bare ``approval_invalid:`` is not a valid reason.
    """
    if reason in STATIC_REASONS:
        return True
    return any(
        reason.startswith(prefix) and len(reason) > len(prefix) for prefix in REASON_FAMILY_PREFIXES
    )


def unknown_reasons(reasons: object) -> tuple[str, ...]:
    """Return the members of ``reasons`` that are outside the frozen vocabulary.

    Used at the comparison boundaries, which otherwise compare unrecognized
    strings for equality and report a clean match between two identical typos.
    """
    if not isinstance(reasons, (list, tuple)):
        return ()
    return tuple(str(reason) for reason in reasons if not is_known_reason(str(reason)))
