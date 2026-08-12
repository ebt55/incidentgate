"""The one non-zero number in the published kill matrix, pinned by experiment.

The full 22-scenario table reports ``orphaned_approvals: 56`` against four
zeros. Read cold that looks like a defect, and the tempting response is to make
it disappear - by reusing the unconsumed token on recovery, or by dropping the
observation from the artifact. Both would replace a measurement with a
decoration, so instead the number is published with a definition and pinned
here with the experiment that justifies calling it benign.

What produces one. A kill between the approval commit and the operation commit
loses the in-memory handle to a token that is *already durable*. Recovery
cannot distinguish a committed-but-unspent token from one that was never
minted, so it mints a fresh token for the identical canonical action and spends
that one. The pre-kill token survives, un-redeemed. Approval issuance is
therefore not idempotent across a crash; redemption is, and redemption is the
step that mutates.

Why that is neither a lost incident nor a duplicate mutation, and why an
un-redeemed token is not a spendable capability, is what the tests below assert
- against a real orphan produced by a real ``os._exit(137)``, not against a
hand-inserted row. A synthetic unconsumed approval would prove the binding
checks work; only a real kill proves the binding checks are what the crash path
actually leaves behind.
"""

from __future__ import annotations

import itertools
import os
from collections.abc import Iterator
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import psycopg
import pytest
from psycopg.rows import dict_row

from incidentgate.chaos import chaos_dsn, matrix
from incidentgate.contracts import (
    ApprovalToken,
    CanonicalAction,
    ToolCallContext,
    canonical_action_hash,
)
from incidentgate.lab.errors import ApprovalDenied
from incidentgate.lab.repository import LabRepository

#: One of the four windows the published table reports as orphaning, chosen
#: because D1 is the shortest full action path (approval, execute, verify).
ORPHANING_BOUNDARY = "approve/approval_token:committed"
INCIDENT = "INC-D1"

#: Mirrors ``control.workflow._idempotency_key``. Restated rather than imported
#: so this file asserts against the frozen wire format instead of against
#: whatever the workflow happens to compute today.
IDEMPOTENCY_PREFIX = "triage-agent-lab:d1:"


def _rows(dsn: str, sql: str, parameters: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with psycopg.connect(dsn, row_factory=dict_row) as connection, connection.cursor() as cursor:
        cursor.execute(sql, parameters)
        return [dict(row) for row in cursor.fetchall()]


def _durable_effects(dsn: str) -> dict[str, int]:
    """The three counters any successful redemption would have to move."""
    ledger = _rows(
        dsn, "SELECT count(*) AS n FROM operation_ledger WHERE incident_id = %s", (INCIDENT,)
    )
    consumed = _rows(
        dsn,
        "SELECT count(*) AS n FROM approvals WHERE incident_id = %s AND consumed_at IS NOT NULL",
        (INCIDENT,),
    )
    fixture = _rows(dsn, "SELECT mutation_count FROM target_state WHERE component = 'api'")
    return {
        "ledger_rows": int(ledger[0]["n"]),
        "approvals_consumed": int(consumed[0]["n"]),
        "mutation_count": int(fixture[0]["mutation_count"]),
    }


def _build_action(thread_id: str, actor: str, evidence_ids: tuple[str, ...]) -> CanonicalAction:
    return CanonicalAction(
        tool_name="operations.rollback",
        incident_id=INCIDENT,
        thread_id=thread_id,
        actor=actor,
        permission="operations:write",
        evidence_ids=evidence_ids,
        arguments={"kind": "rollback", "component": "api", "target_revision": "v1"},
    )


def _actions_over_evidence(
    thread_id: str, actor: str, evidence: list[str]
) -> Iterator[CanonicalAction]:
    """Every action this run's own evidence could have cited, smallest first."""
    for size in range(1, len(evidence) + 1):
        for combination in itertools.combinations(evidence, size):
            yield _build_action(thread_id, actor, combination)


def _workflow_key(thread_id: str, action_hash: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"{IDEMPOTENCY_PREFIX}{thread_id}:{action_hash}")


def _context(thread_id: str, actor: str, key: UUID) -> ToolCallContext:
    return ToolCallContext(
        incident_id=INCIDENT,
        thread_id=thread_id,
        correlation_id=f"corr-{thread_id}",
        actor=actor,
        permission="operations:write",
        idempotency_key=key,
    )


@pytest.fixture(scope="module")
def orphan() -> dict[str, Any]:
    """Kill D1 inside the approval window, recover, and hand back the leftovers.

    Recovering to the golden terminal is part of the setup rather than an
    aside: an orphan left behind by a *failed* recovery would be a lost
    incident, and the whole claim here is that this one is left behind by a
    fully successful recovery.
    """
    raw = os.environ.get("DATABASE_URL")
    if not raw:
        pytest.skip("orphaned approval invariants require DATABASE_URL")
    dsn = chaos_dsn(raw)
    repository = LabRepository(dsn)
    repository.migrate()
    matrix.reset_scenario(repository, "D1")

    thread_id = f"orphan-d1-{uuid4().hex[:8]}"
    result = matrix.drive(dsn, "D1", thread_id, kill_at=ORPHANING_BOUNDARY, kill_phase="approve")
    assert result.error is None, result.error
    assert result.killed_at_step is not None, "the armed boundary never fired"
    assert matrix.KILL_EXIT_CODE in [run.returncode for run in result.runs]
    assert result.terminal and result.final_state == "resolved", result.final_state

    approvals = _rows(
        dsn, "SELECT * FROM approvals WHERE incident_id = %s ORDER BY approved_at", (INCIDENT,)
    )
    unconsumed = [row for row in approvals if row["consumed_at"] is None]
    assert len(unconsumed) == 1, f"expected exactly one orphan, got {len(unconsumed)}"
    row = unconsumed[0]

    evidence = sorted(
        item["evidence_id"]
        for item in _rows(
            dsn,
            "SELECT evidence_id FROM evidence_records WHERE incident_id = %s AND thread_id = %s",
            (INCIDENT, thread_id),
        )
    )
    # Recover the exact action the orphan is bound to by searching the evidence
    # sets this run actually recorded. A match is proof of reconstruction: the
    # hash covers every other field, so only the true set can reproduce it.
    action = next(
        (
            candidate
            for candidate in _actions_over_evidence(thread_id, "operator-1", evidence)
            if canonical_action_hash(candidate) == row["action_hash"]
        ),
        None,
    )
    assert action is not None, "could not reconstruct the action the orphan is bound to"

    return {
        "dsn": dsn,
        "repository": repository,
        "thread_id": thread_id,
        "approvals": approvals,
        "row": row,
        "evidence": evidence,
        "action": action,
        "token": ApprovalToken(
            token_id=row["token_id"],
            one_time_use_id=row["one_time_use_id"],
            action_hash=row["action_hash"],
            actor=row["actor"],
            approver=row["approver"],
            requested_at=row["requested_at"],
            expires_at=row["expires_at"],
            approved_at=row["approved_at"],
        ),
        "ledger": _rows(dsn, "SELECT * FROM operation_ledger WHERE incident_id = %s", (INCIDENT,)),
    }


def _forged_token(orphan: dict[str, Any], action: CanonicalAction, actor: str) -> ApprovalToken:
    """The strongest token a caller could present for the orphan's durable row.

    Everything the caller controls is made to agree with the action it wants
    executed; only the durable row disagrees. That isolates the check under
    test to the comparison against Postgres rather than a self-consistency one
    the caller could trivially satisfy.
    """
    row = orphan["row"]
    return ApprovalToken(
        token_id=row["token_id"],
        one_time_use_id=row["one_time_use_id"],
        action_hash=canonical_action_hash(action),
        actor=actor,
        approver=row["approver"],
        requested_at=row["requested_at"],
        expires_at=row["expires_at"],
        approved_at=row["approved_at"],
    )


@pytest.mark.integration
def test_the_kill_leaves_one_unspent_token_beside_exactly_one_executed_operation(
    orphan: dict[str, Any],
) -> None:
    """The definition itself: an extra authorization, not an extra mutation."""
    approvals, ledger = orphan["approvals"], orphan["ledger"]
    assert len(approvals) == 2, "the crash minted a second token"
    assert sum(1 for row in approvals if row["consumed_at"] is not None) == 1
    assert len({row["action_hash"] for row in approvals}) == 1, (
        "both tokens must authorize the identical canonical action"
    )
    assert len(ledger) == 1, "exactly one operation executed"
    assert ledger[0]["approval_token_id"] != orphan["row"]["token_id"], (
        "the ledger records the token that was spent, not the orphan"
    )
    assert _durable_effects(orphan["dsn"])["mutation_count"] == 1


@pytest.mark.integration
def test_an_orphaned_approval_cannot_be_redeemed_for_a_different_action(
    orphan: dict[str, Any],
) -> None:
    """Hash binding. The swap is scope-valid so the check under test is reached.

    Changing the component or the target revision would be rejected earlier by
    ``_validate_action_scope`` and would prove nothing about the token. Swapping
    the cited evidence keeps every field that validator inspects identical while
    changing the canonical hash, so a denial can only come from the binding.
    """
    thread_id, dsn = orphan["thread_id"], orphan["dsn"]
    before = _durable_effects(dsn)
    other = next(
        candidate
        for candidate in _actions_over_evidence(thread_id, "operator-1", orphan["evidence"])
        if canonical_action_hash(candidate) != orphan["row"]["action_hash"]
    )
    key = _workflow_key(thread_id, canonical_action_hash(other))
    with pytest.raises(ApprovalDenied, match="not bound to this action"):
        orphan["repository"].rollback(
            _context(thread_id, "operator-1", key),
            other,
            _forged_token(orphan, other, "operator-1"),
        )
    assert _durable_effects(dsn) == before


@pytest.mark.integration
def test_an_orphaned_approval_cannot_be_redeemed_by_a_different_actor(
    orphan: dict[str, Any],
) -> None:
    """Actor binding, checked against Postgres rather than against the token.

    The presented context, action and token all name the same foreign actor, so
    nothing self-inconsistent is being caught here. The durable approval row is
    the only thing that still says ``operator-1``.
    """
    thread_id, dsn = orphan["thread_id"], orphan["dsn"]
    before = _durable_effects(dsn)
    action = _build_action(thread_id, "attacker-1", orphan["action"].evidence_ids)
    key = _workflow_key(thread_id, canonical_action_hash(action))
    with pytest.raises(ApprovalDenied, match="not bound to this action"):
        orphan["repository"].rollback(
            _context(thread_id, "attacker-1", key),
            action,
            _forged_token(orphan, action, "attacker-1"),
        )
    assert _durable_effects(dsn) == before


@pytest.mark.integration
def test_an_orphaned_approval_is_unspendable_on_the_key_the_workflow_derives(
    orphan: dict[str, Any],
) -> None:
    """Why the orphan is inert on every path a caller can legitimately take.

    The idempotency key is ``uuid5(thread_id, action_hash)``, and the orphan's
    own action hash covers the thread id - so the key is a pure function of the
    binding the token already carries. There is exactly one key the orphan can
    derive, the recovered operation already occupies it, and the resulting
    replay branch rejects a token id that is not the one on the ledger row.
    """
    thread_id, dsn = orphan["thread_id"], orphan["dsn"]
    before = _durable_effects(dsn)
    key = _workflow_key(thread_id, orphan["row"]["action_hash"])
    assert key == orphan["ledger"][0]["idempotency_key"], (
        "the orphan derives the very key the executed operation already holds"
    )
    with pytest.raises(ApprovalDenied, match="different operation semantics"):
        orphan["repository"].rollback(
            _context(thread_id, "operator-1", key), orphan["action"], orphan["token"]
        )
    assert _durable_effects(dsn) == before


@pytest.mark.integration
def test_a_denied_redemption_does_not_burn_the_orphan(orphan: dict[str, Any]) -> None:
    """A rejected attempt must not consume the token it was rejected against.

    Otherwise a failed redemption would quietly become the audit trail's account
    of a successful one, and the published orphan count would drift toward zero
    for entirely the wrong reason.
    """
    still_open = _rows(
        orphan["dsn"],
        "SELECT token_id FROM approvals WHERE incident_id = %s AND consumed_at IS NULL",
        (INCIDENT,),
    )
    assert [row["token_id"] for row in still_open] == [orphan["row"]["token_id"]]
