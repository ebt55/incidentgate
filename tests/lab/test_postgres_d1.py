import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest

from triage_agent_lab.contracts import (
    ApprovalToken,
    CanonicalAction,
    Role,
    RollbackArgs,
    ToolCallContext,
    canonical_action_hash,
)
from triage_agent_lab.lab.auth import Principal
from triage_agent_lab.lab.errors import ApprovalDenied, LabError, ResponseLost
from triage_agent_lab.lab.repository import LabRepository
from triage_agent_lab.lab.service import ObservabilityService, OperationsService, TicketsService

Change = Callable[
    [ToolCallContext, CanonicalAction, ApprovalToken],
    tuple[ToolCallContext, CanonicalAction, ApprovalToken],
]
TokenChange = Callable[[ApprovalToken], ApprovalToken]


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("Postgres D1 integration requires DATABASE_URL; Docker is not required for unit tests")
    repo = LabRepository(dsn)
    repo.migrate()
    repo.migrate()
    repo.reset_d1()
    repo.inject_d1()
    return repo


def operation(repository: LabRepository) -> tuple[ToolCallContext, Principal, CanonicalAction, ApprovalToken]:
    context = ToolCallContext(
        incident_id="INC-D1",
        thread_id="thread-d1",
        correlation_id="corr-d1",
        actor="operator-1",
        permission="operations:write",
        idempotency_key=uuid4(),
    )
    evidence_context = context.model_copy(
        update={"permission": "observability:read", "idempotency_key": None}
    )
    evidence = ObservabilityService(repository).get(
        evidence_context, Principal("operator-1", Role.OPERATOR), "health"
    )
    action = CanonicalAction(
        tool_name="operations.rollback",
        incident_id="INC-D1",
        thread_id="thread-d1",
        actor="operator-1",
        permission="operations:write",
        evidence_ids=(evidence.evidence_id,),
        arguments={"kind": "rollback", "component": "api", "target_revision": "v1"},
    )
    now = datetime.now(UTC)
    token = ApprovalToken(
        action_hash=canonical_action_hash(action),
        actor="operator-1",
        approver="approver-1",
        one_time_use_id=uuid4(),
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
        approved_at=now,
    )
    return context, Principal("operator-1", Role.OPERATOR), action, token


def assert_unchanged(repository: LabRepository) -> None:
    assert repository.state()["mutation_count"] == 0


def test_d1_evidence_and_permission(repository: LabRepository) -> None:
    service = ObservabilityService(repository)
    context = ToolCallContext(
        incident_id="INC-D1",
        thread_id="thread-d1",
        correlation_id="corr-d1",
        actor="observer-1",
        permission="observability:read",
    )
    principal = Principal("observer-1", Role.OBSERVER)
    health = service.get(context, principal, "health")
    assert health.payload["status"] == 500
    assert health.source_uri is not None
    assert health.expires_at > health.observed_at
    assert service.get(context, principal, "deployment_diff").payload["to_revision"] == "v2"
    assert "v2" in str(service.get(context, principal, "logs").payload)
    with pytest.raises(ApprovalDenied):
        TicketsService(repository).append_disabled(context, principal, "not authorized")


def test_initialize_is_idempotent_and_preserves_injected_state(repository: LabRepository) -> None:
    repository.reset_d1()
    repository.initialize_d1_if_absent()
    repository.initialize_d1_if_absent()
    assert repository.state()["revision"] == "v1"
    repository.inject_d1()
    repository.initialize_d1_if_absent()
    assert repository.state()["revision"] == "v2"


def test_rollback_is_bound_atomic_and_idempotent(repository: LabRepository) -> None:
    context, principal, action, token = operation(repository)
    service = OperationsService(repository)
    with pytest.raises(ApprovalDenied):
        service.rollback(context, principal, action, token)
    assert_unchanged(repository)
    repository.record_approval(token, "INC-D1")
    with pytest.raises(ResponseLost):
        service.rollback(context, principal, action, token, response_loss=True)
    retry = service.rollback(context, principal, action, token)
    assert retry.status.value == "duplicate"
    assert retry.context == context
    assert retry.result == {
        "component": "api",
        "revision": "v1",
        "health_status": 200,
        "result": "rolled_back",
    }
    assert repository.state() == {"revision": "v1", "health_status": 200, "mutation_count": 1}
    with pytest.raises(ApprovalDenied):
        service.rollback(context.model_copy(update={"idempotency_key": uuid4()}), principal, action, token)
    assert repository.state()["mutation_count"] == 1


def test_valid_approval_against_non_injected_target_is_not_consumed(repository: LabRepository) -> None:
    repository.reset_d1()
    context, principal, action, token = operation(repository)
    repository.record_approval(token, "INC-D1")
    with pytest.raises(ApprovalDenied):
        OperationsService(repository).rollback(context, principal, action, token)
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT consumed_at FROM approvals WHERE token_id = %s", (token.token_id,))
        assert cursor.fetchone() == {"consumed_at": None}
        cursor.execute(
            "SELECT count(*) AS total FROM operation_ledger "
            "WHERE incident_id = %s AND thread_id = %s AND operation_scope = %s",
            (context.incident_id, context.thread_id, "d1-api"),
        )
        assert cursor.fetchone() == {"total": 0}
    assert_unchanged(repository)


@pytest.mark.parametrize(
    "change",
    [
        lambda c, a, t: (c.model_copy(update={"incident_id": "INC-OTHER"}), a, t),
        lambda c, a, t: (c.model_copy(update={"thread_id": "other"}), a, t),
        lambda c, a, t: (c.model_copy(update={"actor": "other"}), a, t),
        lambda c, a, t: (c.model_copy(update={"permission": "other:write"}), a, t),
        lambda c, a, t: (c, a.model_copy(update={"actor": "other"}), t),
        lambda c, a, t: (c, a.model_copy(update={"thread_id": "other"}), t),
        lambda c, a, t: (c, a.model_copy(update={"permission": "other:write"}), t),
        lambda c, a, t: (
            c,
            a.model_copy(
                update={
                    "arguments": RollbackArgs(
                        kind="rollback", component="other", target_revision="v1"
                    )
                }
            ),
            t,
        ),
    ],
)
def test_context_or_action_mismatch_never_mutates(
    repository: LabRepository, change: Change
) -> None:
    context, principal, action, token = operation(repository)
    repository.record_approval(token, "INC-D1")
    altered_context, altered_action, altered_token = change(context, action, token)
    with pytest.raises(LabError):
        OperationsService(repository).rollback(altered_context, principal, altered_action, altered_token)
    assert_unchanged(repository)


@pytest.mark.parametrize(
    "change",
    [
        lambda t: t.model_copy(update={"action_hash": "0" * 64}),
        lambda t: t.model_copy(update={"actor": "other"}),
        lambda t: t.model_copy(update={"approver": "other"}),
        lambda t: t.model_copy(update={"one_time_use_id": uuid4()}),
        lambda t: t.model_copy(update={"expires_at": t.expires_at + timedelta(minutes=1)}),
    ],
)
def test_token_mismatch_never_mutates(repository: LabRepository, change: TokenChange) -> None:
    context, principal, action, token = operation(repository)
    repository.record_approval(token, "INC-D1")
    with pytest.raises(ApprovalDenied):
        OperationsService(repository).rollback(context, principal, action, change(token))
    assert_unchanged(repository)


def test_replay_rejects_substituted_context_or_token(repository: LabRepository) -> None:
    context, principal, action, token = operation(repository)
    repository.record_approval(token, "INC-D1")
    service = OperationsService(repository)
    service.rollback(context, principal, action, token)
    retry = service.rollback(context.model_copy(update={"correlation_id": "retry-correlation"}), principal, action, token)
    assert retry.context == context
    with pytest.raises(ApprovalDenied):
        service.rollback(context.model_copy(update={"thread_id": "other"}), principal, action, token)
    with pytest.raises(ApprovalDenied):
        service.rollback(context, principal, action, token.model_copy(update={"approver": "other"}))
    assert repository.state()["mutation_count"] == 1


def test_unknown_or_disallowed_evidence_never_mutates(repository: LabRepository) -> None:
    context, principal, action, token = operation(repository)
    unknown_action = action.model_copy(update={"evidence_ids": ("unknown-evidence",)})
    unknown_token = token.model_copy(
        update={
            "token_id": uuid4(),
            "one_time_use_id": uuid4(),
            "action_hash": canonical_action_hash(unknown_action),
        }
    )
    repository.record_approval(unknown_token, "INC-D1")
    with pytest.raises(ApprovalDenied):
        OperationsService(repository).rollback(context, principal, unknown_action, unknown_token)
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE evidence_records SET tool_name = 'observability.unsupported' WHERE evidence_id = %s",
            (action.evidence_ids[0],),
        )
    repository.record_approval(token, "INC-D1")
    with pytest.raises(ApprovalDenied):
        OperationsService(repository).rollback(context, principal, action, token)
    assert_unchanged(repository)


def test_immutable_evidence_metadata_and_staleness_block_mutation(repository: LabRepository) -> None:
    context, principal, action, token = operation(repository)
    evidence_id = action.evidence_ids[0]
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT source_id, incident_id, thread_id, actor FROM evidence_records WHERE evidence_id = %s",
            (evidence_id,),
        )
        metadata = cursor.fetchone()
        assert metadata == {
            "source_id": metadata["source_id"],
            "incident_id": "INC-D1",
            "thread_id": "thread-d1",
            "actor": "operator-1",
        }
        with pytest.raises(psycopg.errors.RaiseException):
            cursor.execute(
                "UPDATE immutable_evidence_source SET payload = payload WHERE source_id = %s",
                (metadata["source_id"],),
            )
        connection.rollback()
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "UPDATE evidence_records SET observed_at = %s, expires_at = %s WHERE evidence_id = %s",
            (
                datetime.now(UTC) - timedelta(minutes=3),
                datetime.now(UTC) - timedelta(minutes=2),
                evidence_id,
            ),
        )
    repository.record_approval(token, "INC-D1")
    with pytest.raises(ApprovalDenied):
        OperationsService(repository).rollback(context, principal, action, token)
    assert_unchanged(repository)


def test_expired_locked_approval_never_mutates(repository: LabRepository) -> None:
    context, principal, action, token = operation(repository)
    now = datetime.now(UTC)
    expired = token.model_copy(
        update={
            "requested_at": now - timedelta(minutes=3),
            "approved_at": now - timedelta(minutes=2),
            "expires_at": now - timedelta(minutes=1),
        }
    )
    repository.record_approval(expired, "INC-D1")
    with pytest.raises(ApprovalDenied):
        OperationsService(repository).rollback(context, principal, action, expired)
    assert_unchanged(repository)
