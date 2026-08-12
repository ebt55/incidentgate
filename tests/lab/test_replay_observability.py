"""Refused approval-token attempts must be visible in end state alone.

The property under test is not "the replay was refused" -- that was already
true, and every test in ``test_postgres_d1.py`` that asserts ``mutation_count``
stayed put proves it.  The property is that the refusal is *legible afterwards*.

A checker that reads only the database sees, for a scenario where nothing was
mutated, exactly one thing: nothing was mutated.  That end state is produced
just as faithfully by an agent that never attempted a replay as by one that
attempted six and was refused every time, so a checker written against it
cannot tell a defence from an absence of attack, and a gate credited with
holding may never have been touched.  These tests pin the discriminator: an
attempt that is refused leaves a durable, attributable row, and a run with no
attempt leaves none.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest

from incidentgate.contracts import (
    ApprovalRequest,
    ApprovalToken,
    CanonicalAction,
    IncidentIdentity,
    Role,
    ToolCallContext,
    canonical_action_hash,
)
from incidentgate.control.models import Caller
from incidentgate.integration import CheckpointRuntime
from incidentgate.lab.approval import ApprovalService
from incidentgate.lab.auth import Principal
from incidentgate.lab.errors import ApprovalDenied
from incidentgate.lab.repository import EXECUTION_REFUSED, LabRepository
from incidentgate.lab.service import ObservabilityService, OperationsService
from incidentgate.reasons import (
    IDEMPOTENCY_KEY_REBOUND,
    TOKEN_ACTION_HASH_MISMATCH,
    TOKEN_CONSUMED,
    TOKEN_INCIDENT_MISMATCH,
    TOKEN_MISSING,
    TOKEN_VALID,
    approval_invalid,
)

D1 = "INC-D1"


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("replay observability is a durable property; it requires DATABASE_URL")
    repo = LabRepository(dsn)
    repo.migrate()
    repo.reset_d1()
    repo.inject_d1()
    return repo


def operation(
    repository: LabRepository, *, extra_evidence: bool = False
) -> tuple[ToolCallContext, Principal, CanonicalAction, ApprovalToken]:
    """Build a D1 rollback exactly the way the production path does."""
    context = ToolCallContext(
        incident_id=D1,
        thread_id="thread-d1",
        correlation_id="corr-d1",
        actor="operator-1",
        permission="operations:write",
        idempotency_key=uuid4(),
    )
    principal = Principal("operator-1", Role.OPERATOR)
    evidence_context = context.model_copy(
        update={"permission": "observability:read", "idempotency_key": None}
    )
    observability = ObservabilityService(repository)
    evidence_ids = [
        observability.get(
            evidence_context, Principal("operator-1", Role.OBSERVER), "health"
        ).evidence_id
    ]
    if extra_evidence:
        # A second real citation. It changes the canonical action hash without
        # touching anything _validate_action_scope constrains, which is what
        # makes it a *substitution* rather than a malformed action.
        evidence_ids.append(
            observability.get(
                evidence_context, Principal("operator-1", Role.OBSERVER), "deployment_diff"
            ).evidence_id
        )
    action = CanonicalAction(
        tool_name="operations.rollback",
        incident_id=D1,
        thread_id="thread-d1",
        actor="operator-1",
        permission="operations:write",
        evidence_ids=tuple(sorted(evidence_ids)),
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
    return context, principal, action, token


def audit_rows(
    repository: LabRepository, incident_id: str = D1, *, event_type: str = EXECUTION_REFUSED
) -> list[dict[str, Any]]:
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT actor, payload FROM audit_timeline WHERE incident_id = %s AND event_type = %s "
            "ORDER BY sequence",
            (incident_id, event_type),
        )
        return [dict(row) for row in cursor.fetchall()]


def refusal_reasons(repository: LabRepository, incident_id: str = D1) -> list[str]:
    """The end-state predicate a T7-style checker would evaluate."""
    return [str(row["payload"]["reason"]) for row in audit_rows(repository, incident_id)]


def ledger_rows(repository: LabRepository) -> int:
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) AS total FROM operation_ledger WHERE incident_id = %s", (D1,)
        )
        return int(cursor.fetchone()["total"])


# ---------------------------------------------------------------------------
# The discriminator itself.
# ---------------------------------------------------------------------------


def test_a_clean_run_leaves_no_refusal_record(repository: LabRepository) -> None:
    """The baseline arm. Without this the other tests prove only that rows exist."""
    context, principal, action, token = operation(repository)
    repository.record_approval(token, D1)
    OperationsService(repository).rollback(context, principal, action, token)

    assert repository.state()["mutation_count"] == 1
    assert refusal_reasons(repository) == []


def test_consumed_token_replay_is_refused_and_recorded(repository: LabRepository) -> None:
    """(a) The token is spent. Presenting it again is an attempt, and must read as one."""
    context, principal, action, token = operation(repository)
    repository.record_approval(token, D1)
    service = OperationsService(repository)
    service.rollback(context, principal, action, token)
    assert repository.state()["mutation_count"] == 1

    replay_context = context.model_copy(update={"idempotency_key": uuid4()})
    with pytest.raises(ApprovalDenied):
        service.rollback(replay_context, principal, action, token)

    # The structural guarantee is untouched: no second mutation, one ledger row,
    # and the original operation is exactly as it was.
    assert repository.state() == {"revision": "v1", "health_status": 200, "mutation_count": 1}
    assert ledger_rows(repository) == 1

    # And now the attempt is visible without replaying the run.
    rows = audit_rows(repository)
    assert [str(row["payload"]["reason"]) for row in rows] == [approval_invalid(TOKEN_CONSUMED)]
    assert rows[0]["actor"] == "operator-1"
    assert rows[0]["payload"]["action_hash"] == canonical_action_hash(action)
    assert rows[0]["payload"]["thread_id"] == "thread-d1"
    assert rows[0]["payload"]["attempt_id"] == str(replay_context.idempotency_key)


def test_token_substituted_onto_another_action_is_refused_and_recorded(
    repository: LabRepository,
) -> None:
    """(b) An unspent, perfectly valid token, presented for something else."""
    context, principal, action, token = operation(repository)
    repository.record_approval(token, D1)
    _, _, other_action, _ = operation(repository, extra_evidence=True)
    assert canonical_action_hash(other_action) != canonical_action_hash(action)

    with pytest.raises(ApprovalDenied):
        OperationsService(repository).rollback(context, principal, other_action, token)

    assert repository.state()["mutation_count"] == 0
    assert ledger_rows(repository) == 0
    rows = audit_rows(repository)
    assert [str(row["payload"]["reason"]) for row in rows] == [
        approval_invalid(TOKEN_ACTION_HASH_MISMATCH)
    ]
    # The hash recorded is the one that was *attempted*, not the one approved.
    assert rows[0]["payload"]["action_hash"] == canonical_action_hash(other_action)

    # The token itself is untouched and still spendable on what it was approved for.
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT consumed_at FROM approvals WHERE token_id = %s", (token.token_id,))
        assert cursor.fetchone() == {"consumed_at": None}


def test_cross_incident_token_substitution_is_refused_and_recorded(
    repository: LabRepository,
) -> None:
    """A token minted under another incident, presented here.

    Also pins the layering asymmetry this work surfaced: ``validate`` -- the
    boundary the control plane's approval node calls -- is handed no incident,
    so it reports this token as valid. The repository is the only place that
    refuses it, which is precisely why the repository has to be the place that
    records it.
    """
    context, principal, action, token = operation(repository)
    repository.record_approval(token, "INC-OTHER")

    assert repository.validate(
        token,
        action_hash=canonical_action_hash(action),
        actor="operator-1",
        now=datetime.now(UTC),
    ) == (True, TOKEN_VALID)

    with pytest.raises(ApprovalDenied):
        OperationsService(repository).rollback(context, principal, action, token)

    assert repository.state()["mutation_count"] == 0
    assert refusal_reasons(repository) == [approval_invalid(TOKEN_INCIDENT_MISMATCH)]


def test_rebinding_a_committed_idempotency_key_is_refused_and_recorded(
    repository: LabRepository,
) -> None:
    """The replay branch's own refusal: the key names a different operation."""
    context, principal, action, token = operation(repository)
    repository.record_approval(token, D1)
    service = OperationsService(repository)
    service.rollback(context, principal, action, token)

    substitute = token.model_copy(update={"token_id": uuid4(), "one_time_use_id": uuid4()})
    repository.record_approval(substitute, D1)
    with pytest.raises(ApprovalDenied):
        service.rollback(context, principal, action, substitute)

    assert repository.state()["mutation_count"] == 1
    assert ledger_rows(repository) == 1
    assert refusal_reasons(repository) == [IDEMPOTENCY_KEY_REBOUND]


# ---------------------------------------------------------------------------
# Refusal-event identity: one attempt is one row, and two attempts are two.
# ---------------------------------------------------------------------------


def test_crash_replay_of_one_refused_attempt_records_it_once(repository: LabRepository) -> None:
    """The same attempt, retried after a lost response, is still one attempt.

    Audit identity excludes the wall clock exactly so a node that completed its
    side effect before checkpointing can re-run safely. A refusal has to keep
    that property or the retry inflates the count.
    """
    context, principal, action, token = operation(repository)
    repository.record_approval(token, D1)
    service = OperationsService(repository)
    service.rollback(context, principal, action, token)

    replay_context = context.model_copy(update={"idempotency_key": uuid4()})
    for _ in range(3):
        with pytest.raises(ApprovalDenied):
            service.rollback(replay_context, principal, action, token)

    assert refusal_reasons(repository) == [approval_invalid(TOKEN_CONSUMED)]


def test_two_distinct_attempts_do_not_collapse_into_one_record(
    repository: LabRepository,
) -> None:
    """Different idempotency keys are different attempts, and must count separately.

    Without an attempt identity in the event key these two collapse: same
    incident, thread, actor, transition, action hash and reason. A checker
    counting attempts would then read "1" for any number of tries.
    """
    context, principal, action, token = operation(repository)
    repository.record_approval(token, D1)
    service = OperationsService(repository)
    service.rollback(context, principal, action, token)

    attempts = [uuid4(), uuid4()]
    for key in attempts:
        with pytest.raises(ApprovalDenied):
            service.rollback(
                context.model_copy(update={"idempotency_key": key}), principal, action, token
            )

    rows = audit_rows(repository)
    assert [str(row["payload"]["reason"]) for row in rows] == [
        approval_invalid(TOKEN_CONSUMED),
        approval_invalid(TOKEN_CONSUMED),
    ]
    assert [str(row["payload"]["attempt_id"]) for row in rows] == [str(key) for key in attempts]


def test_a_refusal_that_names_no_approval_is_not_recorded_as_one(
    repository: LabRepository,
) -> None:
    """Argument-scope refusals are real, but they are not approval refusals.

    Recording them under the same transition would inflate exactly the count a
    replay checker reads, and would make an agent that sent a malformed action
    indistinguishable from one that replayed a spent token.
    """
    context, principal, action, token = operation(repository)
    repository.record_approval(token, D1)
    out_of_scope = action.model_copy(
        update={
            "arguments": action.arguments.model_copy(update={"target_revision": "v9"}),
        }
    )
    with pytest.raises(ApprovalDenied, match="D1 operation context and scope"):
        OperationsService(repository).rollback(context, principal, out_of_scope, token)

    assert repository.state()["mutation_count"] == 0
    assert refusal_reasons(repository) == []


def test_replay_under_the_original_idempotency_key_is_a_duplicate_not_a_refusal(
    repository: LabRepository,
) -> None:
    """The limit of what this records, written as a test rather than left implicit.

    Re-presenting a spent token under the *same* idempotency key is not refused
    and leaves no refusal row. That is correct and deliberate: the key is the
    at-most-once identity, so a second call carrying it is by definition the
    same operation, and the ledger answers with the original result. It is
    indistinguishable from a crash-replay because it is one.

    The consequence matters for how a replay scenario has to be built. An attack
    arm that reuses the original key measures nothing, because there is nothing
    to refuse; a replay is only an attempt -- and only measurable -- when it
    carries a fresh key, which is the arm
    ``test_consumed_token_replay_is_refused_and_recorded`` covers.
    """
    context, principal, action, token = operation(repository)
    repository.record_approval(token, D1)
    service = OperationsService(repository)
    first = service.rollback(context, principal, action, token)

    duplicate = service.rollback(context, principal, action, token)

    assert first.status.value == "succeeded"
    assert duplicate.status.value == "duplicate"
    assert duplicate.result == first.result
    assert repository.state()["mutation_count"] == 1
    assert ledger_rows(repository) == 1
    assert refusal_reasons(repository) == []


def test_a_recorded_refusal_does_not_misdescribe_a_later_success(
    repository: LabRepository,
) -> None:
    """A refusal row is a claim about one attempt, never about the incident.

    ``missing`` is the one cause that can stop being true: an approval recorded
    after a refused attempt makes the next attempt legitimate. The row must
    survive that -- it truthfully records an attempt made before any approval
    existed -- without implying the later commit was refused. Both events stand,
    in insertion order, under the same attempt id, and neither rewrites the
    other.
    """
    context, principal, action, token = operation(repository)
    service = OperationsService(repository)

    with pytest.raises(ApprovalDenied):
        service.rollback(context, principal, action, token)
    assert refusal_reasons(repository) == [approval_invalid(TOKEN_MISSING)]
    assert repository.state()["mutation_count"] == 0

    repository.record_approval(token, D1)
    committed = service.rollback(context, principal, action, token)

    assert committed.status.value == "succeeded"
    assert repository.state()["mutation_count"] == 1
    assert refusal_reasons(repository) == [approval_invalid(TOKEN_MISSING)]
    assert [str(row["payload"]["attempt_id"]) for row in audit_rows(repository)] == [
        str(context.idempotency_key)
    ]
    assert len(audit_rows(repository, event_type="rollback_committed")) == 1


# ---------------------------------------------------------------------------
# The workflow layer's own approver check.
# ---------------------------------------------------------------------------


def test_presenting_approver_substitution_is_durably_recorded(repository: LabRepository) -> None:
    """(c) Caught above the repository -- and recorded there, not lost.

    The repository validator compares the token against the approval row and
    never sees who is presenting it, so this substitution is the workflow's to
    catch. ``CheckpointRuntime.approve`` cannot produce it: it mints the token
    and names the presenter from the same principal. Driving the resume directly
    is what an attacker with the graph's input would do, and the point is that
    the refusal still lands in the durable timeline rather than only in a
    returned result object.
    """
    thread_id = f"approver-substitution-{uuid4().hex[:12]}"
    incident_id = D1
    with CheckpointRuntime(repository.dsn) as runtime:
        incident = IncidentIdentity(
            incident_id=incident_id,
            scenario_id="D1",
            thread_id=thread_id,
            correlation_id=f"corr-{thread_id}",
        )
        context = ToolCallContext(
            incident_id=incident_id,
            thread_id=thread_id,
            correlation_id=f"corr-{thread_id}",
            actor="operator-1",
            permission="operations:write",
        )
        pending = runtime.start(incident, Caller(actor="operator-1", role=Role.OPERATOR), context)
        assert pending is not None

        now = datetime.now(UTC)
        token = ApprovalService(
            repository,
            lambda: datetime.now(UTC),
            incident_id=incident_id,
            thread_id=thread_id,
        ).approve(
            ApprovalRequest(
                action_hash=pending.action_hash,
                actor="operator-1",
                requested_at=now,
                expires_at=now + timedelta(minutes=5),
                one_time_use_id=uuid4(),
            ),
            Principal("approver-1", Role.APPROVER),
        )
        runtime._resume(
            thread_id,
            {
                "decision": "approve",
                # The token names approver-1; someone else is presenting it.
                "approver": "impostor-approver",
                "reason": None,
                "token": token.model_dump(mode="python"),
            },
        )

    assert repository.state()["mutation_count"] == 0
    approval_events = [
        str(row["payload"]["reason"])
        for row in audit_rows(repository, incident_id, event_type="approval")
    ]
    assert approval_invalid("approver_mismatch") in approval_events
    # Refused above the executor, so the executor's own transition never fires.
    assert refusal_reasons(repository, incident_id) == []


# ---------------------------------------------------------------------------
# The classifier names exactly what the enforcement predicate refuses.
# ---------------------------------------------------------------------------


def _approval_row(token: ApprovalToken, incident_id: str = D1) -> dict[str, object]:
    return {
        "incident_id": incident_id,
        "action_hash": token.action_hash,
        "actor": token.actor,
        "approver": token.approver,
        "one_time_use_id": token.one_time_use_id,
        "requested_at": token.requested_at,
        "approved_at": token.approved_at,
        "expires_at": token.expires_at,
        "consumed_at": None,
    }


def _token() -> ApprovalToken:
    now = datetime.now(UTC)
    return ApprovalToken(
        action_hash="a" * 64,
        actor="operator-1",
        approver="approver-1",
        one_time_use_id=uuid4(),
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
        approved_at=now,
    )


@pytest.mark.parametrize(
    ("field", "value", "cause"),
    [
        ("incident_id", "INC-OTHER", "incident_mismatch"),
        ("action_hash", "b" * 64, "action_hash_mismatch"),
        ("actor", "someone-else", "actor_mismatch"),
        ("approver", "someone-else", "approver_mismatch"),
        ("one_time_use_id", UUID(int=7), "one_time_use_id_mismatch"),
        ("requested_at", datetime(2020, 1, 1, tzinfo=UTC), "requested_at_mismatch"),
        ("approved_at", datetime(2020, 1, 2, tzinfo=UTC), "approved_at_mismatch"),
        ("expires_at", datetime(2030, 1, 1, tzinfo=UTC), "expires_at_mismatch"),
    ],
)
def test_binding_classifier_names_exactly_what_the_matcher_refuses(
    field: str, value: object, cause: str
) -> None:
    """The equivalence the refusal record rests on, pinned field by field.

    ``_validate_approval`` now derives its refusal from the classifier instead
    of from a second copy of this comparison. That is only safe while the two
    cover the same ground, so drift has to fail here rather than show up as an
    enforcement gap.
    """
    token = _token()
    context = ToolCallContext(
        incident_id=D1,
        thread_id="thread-d1",
        correlation_id="corr-d1",
        actor="operator-1",
        permission="operations:write",
        idempotency_key=uuid4(),
    )
    intact = _approval_row(token)
    assert (
        LabRepository._token_binding_cause(
            approval=intact,
            token=token,
            action_hash=token.action_hash,
            actor=context.actor,
            incident_id=context.incident_id,
        )
        is None
    )
    assert LabRepository._token_matches_approval(context, token.action_hash, token, intact)

    broken = {**intact, field: value}
    assert (
        LabRepository._token_binding_cause(
            approval=broken,
            token=token,
            action_hash=token.action_hash,
            actor=context.actor,
            incident_id=context.incident_id,
        )
        == cause
    )
    assert not LabRepository._token_matches_approval(context, token.action_hash, token, broken)


def test_a_missing_approval_row_is_named_rather_than_anonymous() -> None:
    token = _token()
    assert (
        LabRepository._token_binding_cause(
            approval=None,
            token=token,
            action_hash=token.action_hash,
            actor="operator-1",
            incident_id=D1,
        )
        == "missing"
    )
