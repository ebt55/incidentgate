"""Live persistence checks for the public approval and timeline boundaries."""

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from incidentgate.contracts import (
    ApprovalRequest,
    CanonicalAction,
    Role,
    ToolCallContext,
    canonical_action_hash,
)
from incidentgate.lab.approval import ApprovalService
from incidentgate.lab.auth import Principal
from incidentgate.lab.errors import ApprovalConflict, ApprovalDenied
from incidentgate.lab.repository import LabRepository
from incidentgate.lab.service import ObservabilityService, OperationsService


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("Postgres D1 integration requires DATABASE_URL")
    repo = LabRepository(dsn)
    repo.migrate()
    repo.reset_d1()
    repo.inject_d1()
    return repo


def approval_request(repository: LabRepository, now: datetime) -> tuple[ToolCallContext, CanonicalAction, ApprovalRequest]:
    context = ToolCallContext(
        incident_id="INC-D1",
        thread_id="approval-thread",
        correlation_id="approval-correlation",
        actor="operator-1",
        permission="operations:write",
        idempotency_key=uuid4(),
    )
    evidence = ObservabilityService(repository).get(
        context.model_copy(
            update={"permission": "observability:read", "idempotency_key": None}
        ),
        Principal("operator-1", Role.OPERATOR),
        "health",
    )
    action = CanonicalAction(
        tool_name="operations.rollback",
        incident_id=context.incident_id,
        thread_id=context.thread_id,
        actor=context.actor,
        permission=context.permission,
        evidence_ids=(evidence.evidence_id,),
        arguments={"kind": "rollback", "component": "api", "target_revision": "v1"},
    )
    request = ApprovalRequest(
        action_hash=canonical_action_hash(action),
        actor=context.actor,
        one_time_use_id=uuid4(),
        requested_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )
    return context, action, request


def issuer(repository: LabRepository, now: datetime) -> ApprovalService:
    return ApprovalService(repository, lambda: now, incident_id="INC-D1", thread_id="approval-thread")


def test_approver_issues_and_validates_persisted_token(repository: LabRepository) -> None:
    now = datetime.now(UTC)
    _, _, request = approval_request(repository, now)
    token = issuer(repository, now).approve(request, Principal("approver-1", Role.APPROVER))
    assert token.approver == "approver-1"
    assert token.approval_id == request.approval_id
    assert repository.validate(token, action_hash=request.action_hash, actor=request.actor, now=now) == (True, "valid")


@pytest.mark.parametrize("role", [Role.OBSERVER, Role.OPERATOR])
def test_non_approvers_are_explicitly_denied(repository: LabRepository, role: Role) -> None:
    now = datetime.now(UTC)
    _, _, request = approval_request(repository, now)
    with pytest.raises(ApprovalDenied, match="approver role"):
        issuer(repository, now).approve(request, Principal("not-an-approver", role))


def test_inactive_or_expired_requests_are_denied(repository: LabRepository) -> None:
    now = datetime.now(UTC)
    _, _, request = approval_request(repository, now)
    future = request.model_copy(update={"requested_at": now + timedelta(seconds=1), "expires_at": now + timedelta(minutes=1)})
    with pytest.raises(ApprovalDenied, match="not active"):
        issuer(repository, now).approve(future, Principal("approver-1", Role.APPROVER))
    expired = request.model_copy(update={"requested_at": now - timedelta(minutes=2), "expires_at": now})
    with pytest.raises(ApprovalDenied, match="expired"):
        issuer(repository, now).approve(expired, Principal("approver-1", Role.APPROVER))


def test_validation_rejects_every_substituted_binding_and_duplicate(repository: LabRepository) -> None:
    now = datetime.now(UTC)
    _, _, request = approval_request(repository, now)
    service = issuer(repository, now)
    token = service.approve(request, Principal("approver-1", Role.APPROVER))
    with pytest.raises(ApprovalConflict, match="already exists"):
        service.approve(request, Principal("approver-1", Role.APPROVER))
    replacements = {
        "action_hash": "0" * 64,
        "actor": "other-operator",
        "approver": "other-approver",
        "one_time_use_id": uuid4(),
        "requested_at": token.requested_at + timedelta(microseconds=1),
        "approved_at": token.approved_at + timedelta(microseconds=1),
        "expires_at": token.expires_at + timedelta(seconds=1),
    }
    for field, replacement in replacements.items():
        changed = token.model_copy(update={field: replacement})
        valid, reason = repository.validate(changed, action_hash=request.action_hash, actor=request.actor, now=now)
        assert not valid, field
        assert reason != "valid"
    missing = token.model_copy(update={"token_id": uuid4()})
    assert repository.validate(missing, action_hash=request.action_hash, actor=request.actor, now=now) == (False, "missing")
    assert repository.validate(token, action_hash=request.action_hash, actor=request.actor, now=token.expires_at) == (False, "expired")


def test_real_rollback_consumes_token_and_timeline_is_ordered_bounded(repository: LabRepository) -> None:
    now = datetime.now(UTC)
    context, action, request = approval_request(repository, now)
    token = issuer(repository, now).approve(request, Principal("approver-1", Role.APPROVER))
    OperationsService(repository).rollback(context, Principal("operator-1", Role.OPERATOR), action, token)
    assert repository.validate(token, action_hash=request.action_hash, actor=request.actor, now=now) == (False, "consumed")
    repository.append_audit_event(incident_id="INC-D1", thread_id="approval-thread", actor="observer-1", transition="review", action_hash=request.action_hash, reason="checked", timestamp=now + timedelta(seconds=1))
    events = repository.timeline("INC-D1", limit=2)
    assert len(events) == 2
    assert [event.timestamp for event in events] == sorted(event.timestamp for event in events)
    assert events[0].transition == "approval_issued"
    assert "token" not in str([event.model_dump() for event in repository.timeline("INC-D1")]).lower()
    with pytest.raises(ValueError, match="limit"):
        repository.timeline("INC-D1", limit=101)
