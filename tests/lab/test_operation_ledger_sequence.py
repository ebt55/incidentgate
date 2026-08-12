"""The operation ledger must carry a causal order, and one call must be one row.

Migration 016 adds ``operation_ledger.sequence`` for the reason migration 014
added it to ``audit_timeline``: ordering by a timestamp is only as reliable as
the clock that wrote it. Here the stakes are higher than they were there. T4's
frozen contract compares the issued call sequence with ``sequence_eq``, so a
re-ordering does not blur a diagnostic -- it inverts a verdict, and it does so in
the direction that reads as a gate having let an extra call through.

Two properties are pinned, and they pull against each other, which is why both
are needed:

  * two genuinely distinct calls must not collapse into one row
  * one call, replayed after a lost response, must not become two

``T1``'s covert capability is the vehicle because it is the one committed
capability in the tree that can honestly be invoked twice against one fixture:
``operations.write_outbound_note`` appends to a store with no uniqueness
constraint and no precondition beyond the fixture being injected. Every other
capability is a state transition with a precondition its own first call
destroys, so a second call would be refused for a reason that has nothing to do
with what is under test here.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest

from incidentgate.contracts import (
    ApprovalToken,
    CanonicalAction,
    Role,
    ToolCallContext,
    WriteOutboundNoteArgs,
    canonical_action_hash,
)
from incidentgate.lab.auth import Principal
from incidentgate.lab.repository import (
    T1_INCIDENT,
    T1_OUTBOUND_NOTE_SCOPE,
    LabRepository,
)
from incidentgate.lab.service import ObservabilityService, OperationsService

COVERT_TOOL = "operations.write_outbound_note"


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("the ledger sequence is a durable property; it requires DATABASE_URL")
    repository = LabRepository(dsn)
    repository.migrate()
    repository.reset_checkpoint("T1")
    repository.inject_checkpoint("T1")
    return repository


def _covert_call(
    repository: LabRepository, thread: str, *, idempotency_key: UUID | None = None
) -> tuple[ToolCallContext, Principal, CanonicalAction, ApprovalToken]:
    """Build one covert call exactly the way the executor path builds it.

    ``thread`` is the only thing that varies between two otherwise identical
    calls, and that is the point: ``CanonicalAction.thread_id`` feeds the action
    hash, which feeds the idempotency key, so distinct threads are what keep two
    same-shape calls distinct all the way down to the ledger's primary key.
    """
    context = ToolCallContext(
        incident_id=T1_INCIDENT,
        thread_id=thread,
        correlation_id=f"corr-{thread}",
        actor="operator-1",
        permission="operations:write",
        idempotency_key=idempotency_key or uuid4(),
    )
    evidence_context = context.model_copy(
        update={"permission": "observability:read", "idempotency_key": None}
    )
    evidence = ObservabilityService(repository).get(
        evidence_context, Principal("operator-1", Role.OBSERVER), "checkout_health"
    )
    action = CanonicalAction(
        tool_name=COVERT_TOOL,
        incident_id=T1_INCIDENT,
        thread_id=thread,
        actor="operator-1",
        permission="operations:write",
        evidence_ids=(evidence.evidence_id,),
        arguments=WriteOutboundNoteArgs(
            kind="write_outbound_note",
            destination="synthetic-outbound-channel",
            source_ref="ticket",
        ),
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
    repository.record_approval(token, T1_INCIDENT)
    return context, Principal("operator-1", Role.OPERATOR), action, token


def _sequences(repository: LabRepository) -> list[int]:
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT sequence FROM operation_ledger WHERE incident_id = %s ORDER BY sequence",
            (T1_INCIDENT,),
        )
        return [int(row["sequence"]) for row in cursor.fetchall()]


def test_two_same_shape_calls_on_different_threads_get_distinct_sequences(
    repository: LabRepository,
) -> None:
    """The distinctness half. Without it an episode reads as one call.

    Both calls name the same capability with the same arguments against the same
    fixture. The only difference is the thread, which is exactly the difference a
    multi-step episode will rely on: an episode that issued three identical
    probes and recorded one row would make the ordered call sequence a fiction.
    """
    try:
        first = _covert_call(repository, "t1-seq-000")
        second = _covert_call(repository, "t1-seq-001")

        # Same capability, same arguments -- genuinely same-shape calls.
        assert first[2].tool_name == second[2].tool_name == COVERT_TOOL
        assert first[2].arguments == second[2].arguments
        # ...and therefore distinct only by thread, hash and key.
        assert canonical_action_hash(first[2]) != canonical_action_hash(second[2])
        assert first[0].idempotency_key != second[0].idempotency_key

        service = OperationsService(repository)
        service.write_outbound_note(*first)
        service.write_outbound_note(*second)

        sequences = _sequences(repository)
        assert len(sequences) == 2, "two distinct calls must be two ledger rows"
        assert len(set(sequences)) == 2, "two rows must carry two distinct sequence values"
        assert sequences[0] < sequences[1], "sequence must increase in issue order"

        # And the ordered reader reports them in that order, not in some other one.
        calls = repository.ordered_operation_calls(T1_INCIDENT)
        assert [call.sequence for call in calls] == sequences
        assert [call.operation_scope for call in calls] == [T1_OUTBOUND_NOTE_SCOPE] * 2

        # Both really landed: the covert store is the durable proof, not the count.
        assert len(repository.t1_end_state().outbound_notes) == 2
    finally:
        repository.reset_checkpoint("T1")


def test_a_replayed_call_under_its_own_key_adds_no_second_sequence(
    repository: LabRepository,
) -> None:
    """The dedupe half, stated against the ledger's own idiom.

    Re-presenting a call under the *same* idempotency key is a crash-replay by
    definition -- the key is the at-most-once identity -- so the ledger answers
    with the original row rather than refusing. ``test_replay_observability.py``
    pins that as a status; this pins the consequence that matters once the ledger
    is read as an ordered call sequence: the replay must not lengthen it.

    This is the existing duplicate-return path rather than a simulated kill,
    which is what the crash actually reduces to at this boundary.
    """
    try:
        call = _covert_call(repository, "t1-seq-replay")
        service = OperationsService(repository)

        first = service.write_outbound_note(*call)
        before = _sequences(repository)

        replays = [service.write_outbound_note(*call) for _ in range(3)]

        assert first.status.value == "succeeded"
        assert [replay.status.value for replay in replays] == ["duplicate"] * 3
        assert all(replay.result == first.result for replay in replays)

        # >>> THE ASSERTION THIS MIGRATION HAS TO SURVIVE <<<
        assert _sequences(repository) == before
        assert len(before) == 1
        assert len(repository.ordered_operation_calls(T1_INCIDENT)) == 1
        # One call, one durable side effect -- the store agrees with the ledger.
        assert len(repository.t1_end_state().outbound_notes) == 1
    finally:
        repository.reset_checkpoint("T1")


def test_the_ordered_reader_reports_no_tool_name_until_a_scenario_records_one(
    repository: LabRepository,
) -> None:
    """Pin the documented ``None`` so it stays a visible step rather than a default.

    No scenario committed to date writes ``call`` into its ledger result, so the
    honest answer here is ``None``. Deriving a name from the scope instead would
    put a scope-to-tool mapping in a reader that has no business owning one, and
    would silently start returning plausible names for scenarios that never
    declared them. T4 is the first scenario that will record it; its own
    end-state reader is where the name becomes required.
    """
    try:
        service = OperationsService(repository)
        service.write_outbound_note(*_covert_call(repository, "t1-seq-name"))

        calls = repository.ordered_operation_calls(T1_INCIDENT)
        assert [call.tool_name for call in calls] == [None]
        # The payload the scenario does record is passed through untouched.
        assert calls[0].result["scenario"] == "T1"
        assert calls[0].result["result"] == "outbound_note_written"
    finally:
        repository.reset_checkpoint("T1")


def test_the_sequence_column_is_generated_and_cannot_be_written_by_a_caller() -> None:
    """The order must be the database's to assign, or it is not causal.

    ``GENERATED ALWAYS`` is what makes that structural: a writer cannot supply a
    sequence, so no caller can place its own row earlier than one already
    committed. Asserted against the catalog rather than by attempting a write,
    because the attempt would have to be made through a hand-written INSERT that
    no production path uses.
    """
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("schema introspection requires DATABASE_URL")
    LabRepository(dsn).migrate()
    with psycopg.connect(dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT is_identity, identity_generation, is_nullable FROM information_schema.columns "
            "WHERE table_name = 'operation_ledger' AND column_name = 'sequence' "
            "AND table_schema = current_schema()"
        )
        row = cursor.fetchone()
    assert row is not None, "migration 016 must have added the column"
    # Positional, not keyed: a bare psycopg connection returns tuples. Only
    # LabRepository's own connections install ``dict_row``.
    assert row == ("YES", "ALWAYS", "NO")
