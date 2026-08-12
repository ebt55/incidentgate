from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from incidentgate.contracts import (
    ApprovalRequest,
    ApprovalToken,
    CanonicalAction,
    EvaluationResult,
    OperationLedgerResult,
    PolicyConfiguration,
    ToolCallContext,
    canonical_action_hash,
)


def action(arguments: dict[str, object] | None = None) -> CanonicalAction:
    return CanonicalAction.model_validate(
        {
            "tool_name": "operations.rollback",
            "incident_id": "INC-1",
            "thread_id": "thread-1",
            "actor": "operator-1",
            "permission": "operations:write",
            "evidence_ids": ["ev-1"],
            "arguments": arguments
            or {"kind": "rollback", "component": "api", "target_revision": "v1"},
        }
    )


def test_canonical_hash_ignores_argument_key_order() -> None:
    first = action({"kind": "rollback", "component": "api", "target_revision": "v1"})
    second = action({"target_revision": "v1", "component": "api", "kind": "rollback"})
    assert canonical_action_hash(first) == canonical_action_hash(second)


def test_canonical_hash_ignores_action_identity_and_normalizes_evidence_order() -> None:
    first = action({"kind": "rollback", "component": "api", "target_revision": "v1"})
    same_semantics = CanonicalAction.model_validate(
        {**first.model_dump(mode="python"), "action_id": uuid4()}
    )
    second = CanonicalAction.model_validate(
        {
            **first.model_dump(mode="python"),
            "action_id": uuid4(),
            "evidence_ids": ["ev-z", "ev-1"],
        }
    )
    third = CanonicalAction.model_validate(
        {
            **first.model_dump(mode="python"),
            "action_id": uuid4(),
            "evidence_ids": ["ev-1", "ev-z"],
        }
    )
    assert canonical_action_hash(first) == canonical_action_hash(same_semantics)
    assert canonical_action_hash(first) != canonical_action_hash(second)
    assert canonical_action_hash(second) == canonical_action_hash(third)


def test_schema_version_is_in_hashed_semantics() -> None:
    proposal = action()
    future_schema = proposal.model_copy(update={"action_schema_version": "2"})
    assert canonical_action_hash(proposal) != canonical_action_hash(future_schema)


def test_canonical_hash_binds_actor_and_arguments() -> None:
    proposal = action()
    other_actor = CanonicalAction.model_validate(
        {**proposal.model_dump(mode="python"), "actor": "operator-2"}
    )
    other_args = action({"kind": "rollback", "component": "api", "target_revision": "v0"})
    assert canonical_action_hash(proposal) != canonical_action_hash(other_actor)
    assert canonical_action_hash(proposal) != canonical_action_hash(other_args)


def test_action_rejects_free_form_mutation_payload() -> None:
    with pytest.raises(ValidationError):
        action(
            {"kind": "rollback", "component": "api", "target_revision": "v1", "shell": "rm -rf /"}
        )


def test_action_rejects_duplicate_evidence_and_tool_argument_mismatch() -> None:
    with pytest.raises(ValidationError):
        CanonicalAction.model_validate(
            {
                **action().model_dump(mode="python"),
                "evidence_ids": ["ev-1", "ev-1"],
            }
        )
    with pytest.raises(ValidationError):
        CanonicalAction.model_validate(
            {
                **action().model_dump(mode="python"),
                "tool_name": "operations.restart",
            }
        )


def test_approval_requires_binding_fields() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        ApprovalRequest.model_validate({"requested_at": now})
    request = ApprovalRequest(
        action_hash=canonical_action_hash(action()),
        actor="operator-1",
        one_time_use_id=uuid4(),
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    assert request.one_time_use_id


def test_approval_token_time_window_and_tool_context_are_frozen() -> None:
    now = datetime.now(UTC)
    request = {
        "action_hash": canonical_action_hash(action()),
        "actor": "operator-1",
        "one_time_use_id": uuid4(),
        "requested_at": now,
        "expires_at": now + timedelta(minutes=5),
        "approver": "approver-1",
    }
    with pytest.raises(ValidationError):
        ApprovalToken.model_validate({**request, "approved_at": now - timedelta(seconds=1)})
    with pytest.raises(ValidationError):
        ApprovalToken.model_validate({**request, "approved_at": now + timedelta(minutes=5)})
    context = ToolCallContext(
        incident_id="INC-1",
        thread_id="thread-1",
        correlation_id="corr-1",
        actor="operator-1",
        permission="operations:write",
        idempotency_key=uuid4(),
    )
    assert context.idempotency_key is not None
    required_ledger_fields = {"context", "action_hash", "approval_token_id", "one_time_use_id"}
    assert required_ledger_fields <= set(OperationLedgerResult.model_fields)


def test_evaluation_result_requires_raw_metrics_and_valid_completion_time() -> None:
    with pytest.raises(ValidationError):
        EvaluationResult.model_validate({})


def test_policy_example_has_safe_default() -> None:
    import json
    from pathlib import Path

    config = json.loads((Path(__file__).parents[1] / "config" / "policy.example.json").read_text())
    assert PolicyConfiguration.model_validate(config).default_mode == "complete"
