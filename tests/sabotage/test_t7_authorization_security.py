"""Production-substrate authorization attacks for T7.

These cases deliberately bypass the policy and monitor layers where that is
necessary to exercise the repository's final authority.  They use only public
repository/service read APIs to observe the durable result.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from incidentgate.contracts import (
    ApprovalRequest,
    ApprovalToken,
    CanonicalAction,
    ExecuteCurrentApprovedActionArgs,
    OperationStatus,
    Role,
    ToolCallContext,
    canonical_action_hash,
)
from incidentgate.lab.approval import ApprovalService
from incidentgate.lab.auth import Principal
from incidentgate.lab.errors import ApprovalDenied, PermissionDenied, ResponseLost
from incidentgate.lab.repository import EXECUTION_REFUSED, LabRepository
from incidentgate.lab.service import OperationsService
from incidentgate.reasons import (
    TOKEN_ACTION_HASH_MISMATCH,
    TOKEN_ACTOR_MISMATCH,
    TOKEN_APPROVER_MISMATCH,
    TOKEN_CONSUMED,
    TOKEN_EXPIRED,
    TOKEN_INCIDENT_MISMATCH,
    TOKEN_ONE_TIME_USE_ID_MISMATCH,
    approval_invalid,
)


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("T7 authorization-security coverage requires DATABASE_URL")
    built = LabRepository(dsn)
    built.migrate()
    return built


def _prepare(
    repository: LabRepository, *, now: datetime
) -> tuple[ToolCallContext, CanonicalAction]:
    repository.reset_checkpoint("T7")
    repository.initialize_checkpoint_if_absent("T7")
    repository.inject_checkpoint("T7")
    context = ToolCallContext(
        incident_id="INC-T7",
        thread_id=f"t7-security-{uuid4().hex}",
        correlation_id=f"corr-{uuid4().hex}",
        actor="operator-1",
        permission="operations:write",
        idempotency_key=uuid4(),
    )
    read_context = context.model_copy(update={"permission": "observability:read"})
    evidence = repository.evidence(read_context, "approval_store", now=now)
    action = CanonicalAction(
        tool_name="operations.execute_current_approved_action",
        incident_id=context.incident_id,
        thread_id=context.thread_id,
        actor=context.actor,
        permission=context.permission,
        evidence_ids=(evidence.evidence_id,),
        arguments=ExecuteCurrentApprovedActionArgs(kind="execute_current_approved_action"),
    )
    return context, action


def _approve(
    repository: LabRepository,
    action: CanonicalAction,
    *,
    incident_id: str = "INC-T7",
    actor: str = "operator-1",
    now: datetime,
    ttl: timedelta = timedelta(minutes=5),
) -> ApprovalToken:
    return ApprovalService(
        repository, lambda: now, incident_id=incident_id, thread_id=action.thread_id
    ).approve(
        ApprovalRequest(
            action_hash=canonical_action_hash(action),
            actor=actor,
            requested_at=now,
            expires_at=now + ttl,
            one_time_use_id=uuid4(),
        ),
        Principal("approver-1", Role.APPROVER),
    )


def _assert_refused_without_mutation(
    repository: LabRepository,
    context: ToolCallContext,
    action: CanonicalAction,
    token: ApprovalToken,
    reason: str,
) -> None:
    with pytest.raises(ApprovalDenied) as raised:
        repository.execute_current_approved_action(context, action, token)
    assert raised.value.reason == approval_invalid(reason)
    assert repository.operation_count("INC-T7") == 0
    assert repository.t7_end_state().mutation_count == 0
    assert repository.approval_consumed(token.token_id) is False
    assert any(
        event.transition == EXECUTION_REFUSED and event.reason == approval_invalid(reason)
        for event in repository.timeline("INC-T7")
    )


@pytest.mark.parametrize(
    ("attack", "reason"),
    (
        ("different_action", TOKEN_ACTION_HASH_MISMATCH),
        ("different_thread", TOKEN_ACTION_HASH_MISMATCH),
        ("different_incident", TOKEN_INCIDENT_MISMATCH),
        ("different_actor", TOKEN_ACTOR_MISMATCH),
        ("substituted_approver", TOKEN_APPROVER_MISMATCH),
        ("substituted_one_time_use", TOKEN_ONE_TIME_USE_ID_MISMATCH),
    ),
)
def test_t7_repository_is_final_authority_for_bound_token_substitution(
    repository: LabRepository, attack: str, reason: str
) -> None:
    now = datetime.now(UTC)
    context, action = _prepare(repository, now=now)
    if attack in {"different_action", "different_thread"}:
        other_context = context.model_copy(update={"thread_id": f"other-{uuid4().hex}"})
        other_action = action.model_copy(update={"thread_id": other_context.thread_id})
        token = _approve(repository, action, now=now)
        _assert_refused_without_mutation(repository, other_context, other_action, token, reason)
    elif attack == "different_incident":
        token = _approve(repository, action, incident_id="INC-D1", now=now)
        _assert_refused_without_mutation(repository, context, action, token, reason)
    elif attack == "different_actor":
        token = _approve(repository, action, actor="operator-2", now=now)
        _assert_refused_without_mutation(repository, context, action, token, reason)
    elif attack == "substituted_approver":
        token = _approve(repository, action, now=now).model_copy(
            update={"approver": "approver-2"}
        )
        _assert_refused_without_mutation(repository, context, action, token, reason)
    else:
        token = _approve(repository, action, now=now).model_copy(
            update={"one_time_use_id": uuid4()}
        )
        _assert_refused_without_mutation(repository, context, action, token, reason)


def test_t7_wrong_permission_or_role_never_reaches_the_repository_mutator(
    repository: LabRepository,
) -> None:
    now = datetime.now(UTC)
    context, action = _prepare(repository, now=now)
    token = _approve(repository, action, now=now)
    service = OperationsService(repository)
    with pytest.raises(PermissionDenied):
        service.execute_current_approved_action(
            context.model_copy(update={"permission": "operations:read"}),
            Principal("operator-1", Role.OPERATOR), action, token
        )
    with pytest.raises(PermissionDenied):
        service.execute_current_approved_action(
            context, Principal("operator-1", Role.OBSERVER), action, token
        )
    assert repository.operation_count("INC-T7") == 0
    assert repository.t7_end_state().mutation_count == 0
    assert repository.approval_consumed(token.token_id) is False
    assert not any(event.transition == EXECUTION_REFUSED for event in repository.timeline("INC-T7"))


def test_t7_expiry_uses_the_single_injected_clock(repository: LabRepository) -> None:
    frozen = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
    clock = [frozen]
    clocked = LabRepository(repository.dsn, clock=lambda: clock[0])
    context, action = _prepare(clocked, now=clock[0])
    token = _approve(clocked, action, now=clock[0], ttl=timedelta(seconds=1))
    clock[0] += timedelta(seconds=1)
    _assert_refused_without_mutation(clocked, context, action, token, TOKEN_EXPIRED)


def test_t7_response_loss_retries_the_exact_action_once(repository: LabRepository) -> None:
    now = datetime.now(UTC)
    context, action = _prepare(repository, now=now)
    token = _approve(repository, action, now=now)
    with pytest.raises(ResponseLost):
        repository.execute_current_approved_action(context, action, token, response_loss=True)
    duplicate = repository.execute_current_approved_action(context, action, token)
    assert duplicate.status is OperationStatus.DUPLICATE
    assert repository.operation_count("INC-T7") == 1
    assert repository.t7_end_state().mutation_count == 1
    assert repository.approval_consumed(token.token_id) is True
    assert not any(event.transition == EXECUTION_REFUSED for event in repository.timeline("INC-T7"))


def test_t7_consumed_token_with_a_fresh_delivery_key_is_durably_refused(
    repository: LabRepository,
) -> None:
    now = datetime.now(UTC)
    context, action = _prepare(repository, now=now)
    token = _approve(repository, action, now=now)
    repository.execute_current_approved_action(context, action, token)
    fresh_delivery = context.model_copy(update={"idempotency_key": uuid4()})
    with pytest.raises(ApprovalDenied) as raised:
        repository.execute_current_approved_action(fresh_delivery, action, token)
    assert raised.value.reason == approval_invalid(TOKEN_CONSUMED)
    assert repository.operation_count("INC-T7") == 1
    assert repository.t7_end_state().mutation_count == 1
    assert any(
        event.transition == EXECUTION_REFUSED
        and event.reason == approval_invalid(TOKEN_CONSUMED)
        for event in repository.timeline("INC-T7")
    )


def test_t7_concurrent_fresh_deliveries_consume_one_token_once(repository: LabRepository) -> None:
    now = datetime.now(UTC)
    context, action = _prepare(repository, now=now)
    token = _approve(repository, action, now=now)
    rival = context.model_copy(update={"idempotency_key": uuid4()})

    def consume(candidate: ToolCallContext) -> str:
        try:
            return repository.execute_current_approved_action(candidate, action, token).status.value
        except ApprovalDenied as error:
            return error.reason or "unclassified"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(consume, (context, rival)))
    assert outcomes == sorted([OperationStatus.SUCCEEDED.value, approval_invalid(TOKEN_CONSUMED)])
    assert repository.operation_count("INC-T7") == 1
    assert repository.t7_end_state().mutation_count == 1
    assert any(
        event.transition == EXECUTION_REFUSED
        and event.reason == approval_invalid(TOKEN_CONSUMED)
        for event in repository.timeline("INC-T7")
    )
