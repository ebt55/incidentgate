"""Focused durable D2/D3 substrate checks; these share the local lab database serially."""

import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest

from incidentgate.contracts import (
    ApprovalToken,
    CanonicalAction,
    Role,
    ToolCallContext,
    canonical_action_hash,
)
from incidentgate.lab.auth import Principal
from incidentgate.lab.errors import ApprovalDenied, ResponseLost
from incidentgate.lab.repository import APPROVED_API_URL_REF, LabRepository
from incidentgate.lab.service import ObservabilityService, OperationsService


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("Checkpoint A Postgres integration requires DATABASE_URL")
    repo = LabRepository(dsn)
    try:
        repo.migrate()
    except psycopg.Error as error:  # pragma: no cover - local Docker may be absent
        pytest.skip(f"Checkpoint A Postgres integration requires DATABASE_URL: {error}")
    repo.reset_checkpoint("D2")
    repo.reset_checkpoint("D3")
    return repo


def context(
    incident: str,
    thread: str = "checkpoint-thread",
    *,
    correlation_id: str | None = None,
    actor: str = "operator-1",
) -> ToolCallContext:
    return ToolCallContext(
        incident_id=incident,
        thread_id=thread,
        correlation_id=correlation_id or f"corr-{thread}",
        actor=actor,
        permission="operations:write",
        idempotency_key=uuid4(),
    )


def token(repo: LabRepository, incident: str, action: CanonicalAction) -> ApprovalToken:
    now = datetime.now(UTC)
    approved = ApprovalToken(
        action_hash=canonical_action_hash(action),
        actor=action.actor,
        approver="approver-1",
        one_time_use_id=uuid4(),
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
        approved_at=now,
    )
    repo.record_approval(approved, incident)
    return approved


def citations(
    repo: LabRepository,
    incident: str,
    thread: str,
    kinds: tuple[str, ...],
    *,
    correlation_id: str | None = None,
    actor: str = "operator-1",
) -> tuple[str, ...]:
    read = ToolCallContext(
        incident_id=incident,
        thread_id=thread,
        correlation_id=correlation_id or f"corr-{thread}",
        actor=actor,
        permission="observability:read",
    )
    service = ObservabilityService(repo)
    principal = Principal(actor, Role.OPERATOR)
    return tuple(service.get(read, principal, kind).evidence_id for kind in kinds)


def action_for(
    repo: LabRepository, scenario: str, call: ToolCallContext, evidence_ids: tuple[str, ...]
) -> CanonicalAction:
    if scenario == "D2":
        return CanonicalAction(
            tool_name="operations.restore_config",
            incident_id=call.incident_id,
            thread_id=call.thread_id,
            actor=call.actor,
            permission=call.permission,
            evidence_ids=evidence_ids,
            arguments={
                "kind": "restore_config",
                "component": "api",
                "variable_name": "REQUIRED_API_URL",
                "approved_value_ref": APPROVED_API_URL_REF,
            },
        )
    return CanonicalAction(
        tool_name="operations.restart",
        incident_id=call.incident_id,
        thread_id=call.thread_id,
        actor=call.actor,
        permission=call.permission,
        evidence_ids=evidence_ids,
        arguments={"kind": "restart", "component": "api"},
    )


def assert_denied_unchanged(
    repo: LabRepository, call: ToolCallContext, approved: ApprovalToken, scenario: str
) -> None:
    with repo._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) AS count FROM operation_ledger WHERE thread_id = %s", (call.thread_id,)
        )
        assert cursor.fetchone()["count"] == 0
        cursor.execute(
            "SELECT consumed_at FROM approvals WHERE token_id = %s", (approved.token_id,)
        )
        assert cursor.fetchone()["consumed_at"] is None
    state = repo.state() if scenario == "D1" else repo.checkpoint_state(scenario)
    assert state["mutation_count"] == 0


def test_d2_restores_only_bounded_reference_and_is_idempotent(repository: LabRepository) -> None:
    assert repository.checkpoint_state("D2")["health_status"] == 200
    repository.inject_checkpoint("D2")
    current = repository.checkpoint_state("D2")
    assert current["config_present"] is False and current["config_reference"] is None
    call = context("INC-D2")
    action = CanonicalAction(
        tool_name="operations.restore_config",
        incident_id="INC-D2",
        thread_id=call.thread_id,
        actor=call.actor,
        permission=call.permission,
        evidence_ids=citations(
            repository, "INC-D2", call.thread_id, ("health", "config_diff", "logs")
        ),
        arguments={
            "kind": "restore_config",
            "component": "api",
            "variable_name": "REQUIRED_API_URL",
            "approved_value_ref": APPROVED_API_URL_REF,
        },
    )
    approved = token(repository, "INC-D2", action)
    service = OperationsService(repository)
    result = service.restore_config(call, Principal("operator-1", Role.OPERATOR), action, approved)
    assert result.status.value == "succeeded"
    assert repository.checkpoint_state("D2")["config_reference"] == APPROVED_API_URL_REF
    read = ToolCallContext(
        incident_id="INC-D2",
        thread_id=call.thread_id,
        correlation_id=call.correlation_id,
        actor=call.actor,
        permission="observability:read",
    )
    fresh = ObservabilityService(repository).get(
        read, Principal("operator-1", Role.OPERATOR), "config_diff"
    )
    assert (
        fresh.payload["present"] is True
        and fresh.payload["approved_value_ref"] == APPROVED_API_URL_REF
    )
    assert (
        service.restore_config(
            call, Principal("operator-1", Role.OPERATOR), action, approved
        ).status.value
        == "duplicate"
    )
    assert repository.checkpoint_state("D2")["mutation_count"] == 1


def test_d3_response_loss_retries_once_and_reset_is_isolated(repository: LabRepository) -> None:
    repository.inject_checkpoint("D3")
    call = context("INC-D3")
    action = CanonicalAction(
        tool_name="operations.restart",
        incident_id="INC-D3",
        thread_id=call.thread_id,
        actor=call.actor,
        permission=call.permission,
        evidence_ids=citations(
            repository, "INC-D3", call.thread_id, ("health", "db_pool_metrics", "logs")
        ),
        arguments={"kind": "restart", "component": "api"},
    )
    approved = token(repository, "INC-D3", action)
    service = OperationsService(repository)
    with pytest.raises(ResponseLost):
        service.restart(
            call, Principal("operator-1", Role.OPERATOR), action, approved, response_loss=True
        )
    assert (
        service.restart(call, Principal("operator-1", Role.OPERATOR), action, approved).status.value
        == "duplicate"
    )
    assert repository.checkpoint_state("D3")["mutation_count"] == 1
    read = ToolCallContext(
        incident_id="INC-D3",
        thread_id=call.thread_id,
        correlation_id=call.correlation_id,
        actor=call.actor,
        permission="observability:read",
    )
    fresh = ObservabilityService(repository).get(
        read, Principal("operator-1", Role.OPERATOR), "db_pool_metrics"
    )
    assert fresh.payload == {"component": "api", "used": 2, "capacity": 10}
    repository.inject_checkpoint("D2")
    repository.reset_checkpoint("D3")
    assert repository.checkpoint_state("D2")["health_status"] == 500


def test_checkpoint_substitution_cross_thread_and_precondition_fail_safely(
    repository: LabRepository,
) -> None:
    repository.inject_checkpoint("D2")
    call = context("INC-D2")
    action = CanonicalAction(
        tool_name="operations.restore_config",
        incident_id="INC-D2",
        thread_id=call.thread_id,
        actor=call.actor,
        permission=call.permission,
        evidence_ids=citations(
            repository, "INC-D2", call.thread_id, ("health", "config_diff", "logs")
        ),
        arguments={
            "kind": "restore_config",
            "component": "api",
            "variable_name": "REQUIRED_API_URL",
            "approved_value_ref": APPROVED_API_URL_REF,
        },
    )
    approved = token(repository, "INC-D2", action)
    service = OperationsService(repository)
    with pytest.raises(ApprovalDenied):
        service.restore_config(
            call.model_copy(update={"thread_id": "other"}),
            Principal("operator-1", Role.OPERATOR),
            action,
            approved,
        )
    wrong = action.model_copy(
        update={
            "arguments": {
                "kind": "restore_config",
                "component": "api",
                "variable_name": "OTHER",
                "approved_value_ref": APPROVED_API_URL_REF,
            }
        }
    )
    with pytest.raises(ApprovalDenied):
        service.restore_config(call, Principal("operator-1", Role.OPERATOR), wrong, approved)
    repository.reset_checkpoint("D2")
    with pytest.raises(ApprovalDenied):
        service.restore_config(call, Principal("operator-1", Role.OPERATOR), action, approved)
    assert repository.checkpoint_state("D2")["mutation_count"] == 0


@pytest.mark.parametrize(
    "scenario,kinds",
    [("D2", ("health", "config_diff", "logs")), ("D3", ("health", "db_pool_metrics", "logs"))],
)
@pytest.mark.parametrize(
    "attack", ["foreign_actor", "foreign_correlation", "cross_thread", "wrong_incident", "expired"]
)
def test_checkpoint_evidence_binding_denies_adversarial_citations(
    repository: LabRepository, scenario: str, kinds: tuple[str, ...], attack: str
) -> None:
    incident = f"INC-{scenario}"
    repository.inject_checkpoint(scenario)
    call = context(incident, thread=f"{scenario}-{attack}", correlation_id="corr-action")
    if attack == "foreign_actor":
        evidence_ids = citations(
            repository,
            incident,
            call.thread_id,
            kinds,
            correlation_id="corr-action",
            actor="operator-2",
        )
    elif attack == "foreign_correlation":
        evidence_ids = citations(
            repository, incident, call.thread_id, kinds, correlation_id="corr-foreign"
        )
    elif attack == "cross_thread":
        evidence_ids = citations(
            repository, incident, "foreign-thread", kinds, correlation_id="corr-action"
        )
    elif attack == "wrong_incident":
        other = "INC-D3" if scenario == "D2" else "INC-D2"
        other_kinds = (
            ("health", "db_pool_metrics", "logs")
            if scenario == "D2"
            else ("health", "config_diff", "logs")
        )
        repository.inject_checkpoint(other.removeprefix("INC-"))
        evidence_ids = citations(
            repository, other, call.thread_id, other_kinds, correlation_id="corr-action"
        )
    else:
        observed_at = datetime.now(UTC) - timedelta(minutes=5)
        source_id = uuid4()
        evidence_id = str(uuid4())
        with repository._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO immutable_evidence_source (source_id, incident_id, kind, payload, "
                "observed_at) "
                "VALUES (%s, %s, 'logs', %s, %s)",
                (
                    source_id,
                    incident,
                    json.dumps({"level": "ERROR", "message": "old observation"}),
                    observed_at,
                ),
            )
            cursor.execute(
                "INSERT INTO evidence_records (evidence_id, incident_id, thread_id, "
                "correlation_id, tool_name, actor, permission, source_id, observed_at, expires_at, "
                "payload) "
                "VALUES (%s, %s, %s, %s, 'observability.logs', %s, 'observability:read', %s, %s, "
                "%s, %s)",
                (
                    evidence_id,
                    incident,
                    call.thread_id,
                    call.correlation_id,
                    call.actor,
                    source_id,
                    observed_at,
                    observed_at + timedelta(seconds=120),
                    json.dumps({"level": "ERROR", "message": "old observation"}),
                ),
            )
        evidence_ids = (evidence_id,)
    action = action_for(repository, scenario, call, evidence_ids)
    approved = token(repository, incident, action)
    operations = OperationsService(repository)
    with pytest.raises(ApprovalDenied):
        if scenario == "D2":
            operations.restore_config(call, Principal(call.actor, Role.OPERATOR), action, approved)
        else:
            operations.restart(call, Principal(call.actor, Role.OPERATOR), action, approved)
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) AS count FROM operation_ledger WHERE thread_id = %s", (call.thread_id,)
        )
        assert cursor.fetchone()["count"] == 0
    assert repository.checkpoint_state(scenario)["mutation_count"] == 0


@pytest.mark.parametrize(
    "scenario,kinds",
    [("D2", ("health", "config_diff", "logs")), ("D3", ("health", "db_pool_metrics", "logs"))],
)
def test_checkpoint_action_substitution_and_healthy_precondition_do_not_consume_approval(
    repository: LabRepository, scenario: str, kinds: tuple[str, ...]
) -> None:
    incident = f"INC-{scenario}"
    repository.inject_checkpoint(scenario)
    call = context(incident, thread=f"{scenario}-substitution")
    action = action_for(
        repository, scenario, call, citations(repository, incident, call.thread_id, kinds)
    )
    approved = token(repository, incident, action)
    operations = OperationsService(repository)
    substituted = action.model_copy(update={"arguments": {"kind": "restart", "component": "other"}})
    with pytest.raises(ApprovalDenied):
        if scenario == "D2":
            operations.restore_config(
                call, Principal(call.actor, Role.OPERATOR), substituted, approved
            )
        else:
            operations.restart(call, Principal(call.actor, Role.OPERATOR), substituted, approved)
    assert_denied_unchanged(repository, call, approved, scenario)

    repository.reset_checkpoint(scenario)
    with pytest.raises(ApprovalDenied):
        if scenario == "D2":
            operations.restore_config(call, Principal(call.actor, Role.OPERATOR), action, approved)
        else:
            operations.restart(call, Principal(call.actor, Role.OPERATOR), action, approved)
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) AS count FROM operation_ledger WHERE thread_id = %s", (call.thread_id,)
        )
        assert cursor.fetchone()["count"] == 0
    assert repository.checkpoint_state(scenario)["mutation_count"] == 0


def test_d1_repository_rejects_actor_and_correlation_foreign_evidence(
    repository: LabRepository,
) -> None:
    repository.reset_d1()
    repository.inject_d1()
    call = context("INC-D1", thread="d1-boundary", correlation_id="corr-action")
    evidence_ids = citations(
        repository,
        "INC-D1",
        call.thread_id,
        ("health", "deployment_diff", "logs"),
        correlation_id="corr-foreign",
        actor="operator-2",
    )
    action = CanonicalAction(
        tool_name="operations.rollback",
        incident_id="INC-D1",
        thread_id=call.thread_id,
        actor=call.actor,
        permission=call.permission,
        evidence_ids=evidence_ids,
        arguments={"kind": "rollback", "component": "api", "target_revision": "v1"},
    )
    approved = token(repository, "INC-D1", action)
    with pytest.raises(ApprovalDenied):
        repository.rollback(call, action, approved)
    assert_denied_unchanged(repository, call, approved, "D1")
