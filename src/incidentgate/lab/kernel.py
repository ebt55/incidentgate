"""The one transaction protocol every scenario mutation runs inside.

WHY THIS MODULE EXISTS
======================

``lab/repository.py`` used to reach the operation ledger through six independent
transactions, one per scenario family. Each re-implemented idempotency locking,
replay equivalence, approval validation, evidence validation, fixture locking,
mutation, ledger insertion, mutation counting, audit emission and token
consumption. The invariants are cross-scenario; the implementations were not,
and they had drifted -- in the order of two writes, in the vocabulary of five
refusals, in whether an audit fact is emitted at all. Adding six more scenarios
in that pattern would have multiplied the drift surface rather than the
coverage.

:class:`OperationKernel` is the single implementation of the eight-step
protocol. A scenario contributes an :class:`OperationSpec` -- data -- and a
:class:`ScenarioMutation` that receives an already-locked, already-authorized
transaction and can do exactly one thing with it: change its own fixture.

WHAT A MUTATION CANNOT DO, BY CONSTRUCTION
==========================================

:class:`LockedTransaction` hands a *cursor*, never a connection, so a mutation
cannot commit, roll back, or open a second transaction. It hands the clock's
single reading as a *value*, never a callable, so a mutation cannot introduce a
second timebase behind a durable timestamp. It carries no idempotency key, so a
mutation cannot observe or influence the identity its ledger row is keyed by.
And :class:`MutationOutcome` has no field through which a mutation could consume
a token, skip an audit fact, or suppress a ledger write.

WHAT THIS MODULE DELIBERATELY DOES NOT UNIFY
============================================

Three differences between the scenario families are findings rather than
defects, and each is a *required* :class:`OperationSpec` field with no default
so that a new scenario has to state its answer rather than inherit one:

``commit_transition``
    Whether the transaction writes a durable ``<verb>_committed`` row into
    ``audit_timeline``. D1 and the four checkpoint scenarios do; the nine
    reliability scenarios and all of T1/T2/T4 do not. Every published chaos cell
    compares ``audit_sequence`` for exact equality, so uniform emission would
    move twenty scenarios' golden sequences at once.

``stamps_updated_at``
    Whether the fixture's mutation-counter update also stamps the injected
    clock. ``t2_fixture_state`` and ``t4_fixture_state`` carry no clock column
    at all -- migrations 018 and 017 say so deliberately, and the DB-clock
    allowlist in ``tests/lab/test_one_clock_discipline.py`` depends on it.

``missing_key_message``
    Whether a missing idempotency key has its own refusal or folds into the
    identity-binding disjunction. D1 and the checkpoint scenarios raise their
    own; the reliability and sabotage paths merge it. Five vocabularies describe
    the same refusal classes across the six families and each of them is matched
    by name somewhere across a module boundary, so none of them may be respelled
    here.

ONE ORDERING WAS UNIFIED, AND IT IS THE ONLY ONE
================================================

Step 0 evaluates the identity binding *before* the idempotency key for every
capability. D1 already did; the checkpoint path raised the key refusal first.
The two orders differ only for a call that is both unbound and keyless -- no
production caller can produce one, because the workflow derives the key before
it builds the context -- and both refusals are argument-scope refusals carrying
``reason=None``, so neither is durably recorded and neither consumes or mutates
anything. Binding first is the order kept because the binding is the check every
family shares.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

import psycopg

from incidentgate.contracts import (
    ApprovalToken,
    CanonicalAction,
    OperationLedgerResult,
    OperationStatus,
    ToolCallContext,
    canonical_action_hash,
)

from .errors import ApprovalDenied, ResponseLost


class RefusalStage(StrEnum):
    """Names the kernel step a refusal came from, not the outcome it produced.

    Deliberately *not* part of the frozen ``reasons.py`` vocabulary and never
    serialized into ``audit_timeline``: the chaos differ compares terminal
    reasons and audit sequences for equality, so a new durable value here would
    be a publishing event rather than a refactor detail. It exists so a test can
    assert which gate refused without matching prose, and so a future reader has
    a discriminator that is not a string comparison against five vocabularies.
    """

    ARGUMENTS = "arguments"
    IDENTITY_BINDING = "binding"
    REPLAY_DIVERGENCE = "replay"
    AUTHORIZATION = "authorization"
    EVIDENCE = "evidence"
    FIXTURE_ABSENT = "fixture"
    PRECONDITION = "precondition"


@dataclass(frozen=True)
class LockedTransaction:
    """Everything a scenario mutation is allowed to see, and nothing else.

    Handed to the mutation only after steps (1)-(4) have run: the idempotency
    identity is locked, the replay is not a divergence, the approval is valid
    and unconsumed, the evidence is in scope and fresh, and the fixture row is
    locked ``FOR UPDATE`` and satisfies its precondition.
    """

    #: A cursor, never a connection. A mutation cannot commit or roll back.
    cursor: psycopg.Cursor[dict[str, object]]
    #: The injected clock's single reading for the whole transaction, as a value
    #: rather than a callable. Every durable timestamp the remaining steps write
    #: is this instant; a mutation that wanted a second one would have to invent
    #: a timebase, and there is nothing here to invent it from.
    now: datetime
    context: ToolCallContext
    action: CanonicalAction
    action_hash: str
    #: The fixture row as step (4) locked it -- the pre-mutation state. A result
    #: payload that has to quote a column the mutation does not change reads it
    #: from here rather than issuing a second select.
    fixture: Mapping[str, object]


@dataclass(frozen=True)
class MutationOutcome:
    """What a scenario mutation returns, and the whole of what it may decide."""

    #: Becomes ``operation_ledger.result`` verbatim. A free mapping because T4's
    #: is a post-mutation snapshot of the fields its covert objective assembles.
    result: dict[str, Any]
    #: ``False`` only for a ledgered call that changed no state -- T4's two
    #: reads, which are ledgered because the contract measures the call sequence
    #: but which must not move the mutation counter.
    mutating: bool = True
    #: Extra ``SET`` clauses to fold into the mutation-counter update, for the
    #: families that write their fixture fields in the same statement as the
    #: counter rather than in a statement of their own.
    #:
    #: Which of the two a family uses is not a style choice, and the kernel
    #: reproduces both rather than picking one. Folding the write into the
    #: counter statement puts it *after* the ledger insert; issuing it from the
    #: mutation puts it *before*. The durable outcome is identical either way --
    #: it is one transaction -- but ``operation_ledger.sequence`` is a generated
    #: column assigned at insert time, and T4's result payload is a snapshot of
    #: the fixture as it stood after its own call, which is impossible to
    #: produce in ledger-first order without a second write.
    fixture_touch: str = ""
    #: Bound values for ``fixture_touch``. Ordered first in the statement, so
    #: they precede the clock stamp the kernel appends.
    fixture_touch_params: tuple[object, ...] = ()


class ScenarioMutation(Protocol):
    """One scenario's fixture change, and nothing else.

    May read and write its own fixture through ``transaction.cursor``, and may
    refuse by raising ``ApprovalDenied(..., reason=None)``. May not commit, open
    a connection, read a clock, insert into ``operation_ledger``, ``approvals``
    or ``audit_timeline``, or observe the idempotency key.
    """

    def __call__(self, transaction: LockedTransaction) -> MutationOutcome: ...


class ApprovalValidator(Protocol):
    def __call__(
        self,
        context: ToolCallContext,
        action_hash: str,
        token: ApprovalToken,
        approval: dict[str, object] | None,
        now: datetime,
    ) -> None: ...


class ReplayValidator(Protocol):
    def __call__(
        self,
        context: ToolCallContext,
        action_hash: str,
        token: ApprovalToken,
        ledger: dict[str, object],
        approval: dict[str, object] | None,
    ) -> None: ...


def unconditional(_: Mapping[str, object]) -> bool:
    """The precondition of a capability that refuses in neither direction.

    Named rather than spelled ``lambda row: True`` at each site, because the
    capabilities that use it do so for a reason worth being able to grep for:
    a fixture that declined would put the experiment's control in the fixture
    instead of in the gate, and the gated columns would then be measuring a
    missing branch rather than a safeguard.
    """
    return True


def _bound(_: object) -> bool:
    """No argument-value constraint beyond the one the wrapper already made."""
    return True


@dataclass(frozen=True)
class OperationSpec:
    """One executable capability, as data.

    One spec per *capability*, not per scenario: T4 owns five, T1 and T2 own two
    each, and every D and R scenario owns one. The scope is the ledger namespace
    the capability commits into and it is unique across the lab, because
    ``(operation_scope, idempotency_key)`` is the ledger's primary key and its
    uniqueness is what makes a redelivery collapse rather than duplicate.
    """

    scenario_id: str
    #: Half of the ledger primary key; unique per capability across the lab.
    operation_scope: str
    incident_id: str
    tool_name: str
    #: The authority this capability requires at the final mutation boundary.
    #: Both the action and its call context must carry this exact value; agreeing
    #: with each other on a weaker permission is not authority to mutate.
    required_permission: str
    #: Bound off the arguments class rather than the tool name, because that is
    #: the discrimination the type system can check: ``CanonicalAction`` already
    #: validates ``tool_name == f"operations.{arguments.kind}"``, so binding off
    #: the class and asserting the name closes the loop from both ends.
    arguments_type: type
    #: Raises the capability's own argument-scope refusal, with ``reason=None``.
    validate_arguments: Callable[[CanonicalAction], None]
    fixture_lock_sql: str
    fixture_lock_params: tuple[object, ...]
    #: Whether the locked row counts as *there*. Separate from the precondition
    #: because most families keep an ``injected`` column whose absence means the
    #: fault was never installed, which is a different refusal from a fault that
    #: has already been repaired -- and the two carry different prose. The
    #: families whose fixture has no such column, and D1 whose two checks are one
    #: indivisible helper, pass :func:`unconditional` here and put everything in
    #: the precondition.
    fixture_present: Callable[[Mapping[str, object]], bool]
    precondition: Callable[[Mapping[str, object]], bool]
    mutation: ScenarioMutation
    #: The table and row the mutation counter lives on.
    fixture_table: str
    fixture_filter: str
    #: REQUIRED, no default: encodes which families emit a durable commit fact.
    commit_transition: str | None
    #: REQUIRED, no default: encodes which fixtures carry a clock column.
    stamps_updated_at: bool
    # The frozen refusal vocabulary. Every string here is the exact text the
    # capability raises today; several are matched by name across a module
    # boundary and none of them may be respelled.
    binding_message: str
    #: ``None`` where the family folds a missing key into the binding message.
    missing_key_message: str | None
    fixture_absent_message: str
    precondition_message: str
    response_loss_message: str
    #: Extra argument-value constraints that belong to the *binding* refusal
    #: rather than to an argument-scope refusal of their own. D1 is the only
    #: capability that spells its bounded argument values this way.
    binds_arguments: Callable[[object], bool] = _bound


class OperationKernel:
    """Runs the eight-step protocol for every capability in the lab.

    Constructed once per repository, holding exactly the seams the protocol
    needs: a connection factory, the injected clock, the durable-refusal
    recorder, and the two token classifiers. Nothing else about the repository
    is reachable from here, which is what keeps the protocol a protocol rather
    than a second place scenario behaviour can accumulate.
    """

    def __init__(
        self,
        *,
        connect: Callable[[], psycopg.Connection[dict[str, object]]],
        clock: Callable[[], datetime],
        refusal_recorded: Callable[[ToolCallContext, str], AbstractContextManager[None]],
        validate_approval: ApprovalValidator,
        validate_replay: ReplayValidator,
    ) -> None:
        self._connect = connect
        self._clock = clock
        self._refusal_recorded = refusal_recorded
        self._validate_approval = validate_approval
        self._validate_replay = validate_replay

    def commit(
        self,
        spec: OperationSpec,
        context: ToolCallContext,
        action: CanonicalAction,
        token: ApprovalToken,
        *,
        response_loss: bool,
    ) -> OperationLedgerResult:
        """Commit one capability, or refuse before anything durable happens."""
        # ---- step 0: arguments, identity binding, idempotency key -----------
        # Outside the connection, and every refusal here carries reason=None:
        # an argument-scope refusal says nothing about an approval, and
        # recording it as one would inflate exactly the count a substituted-
        # approval measurement reads.
        spec.validate_arguments(action)
        if (
            context.incident_id,
            action.incident_id,
            action.thread_id,
            action.actor,
            action.permission,
            action.tool_name,
            context.permission,
            action.permission,
        ) != (
            spec.incident_id,
            spec.incident_id,
            context.thread_id,
            context.actor,
            context.permission,
            spec.tool_name,
            spec.required_permission,
            spec.required_permission,
        ) or not spec.binds_arguments(action.arguments):
            raise ApprovalDenied(spec.binding_message, stage=RefusalStage.IDENTITY_BINDING)
        if context.idempotency_key is None:
            raise ApprovalDenied(
                spec.missing_key_message or spec.binding_message,
                stage=RefusalStage.IDENTITY_BINDING,
            )
        action_hash = canonical_action_hash(action)
        with (
            # Outermost, so it runs after the inner transaction has rolled back
            # and on its own connection: the record has to survive precisely the
            # rollback that hides the attempt.
            self._refusal_recorded(context, action_hash),
            self._connect() as connection,
            connection.cursor() as cursor,
        ):
            # ---- step 1: lock the idempotency identity ----------------------
            cursor.execute(
                "SELECT * FROM operation_ledger WHERE operation_scope = %s AND idempotency_key = "
                "%s FOR UPDATE",
                (spec.operation_scope, context.idempotency_key),
            )
            existing = cursor.fetchone()
            # ---- step 2: replay equivalence, then DUPLICATE -----------------
            if existing is not None:
                cursor.execute(
                    "SELECT * FROM approvals WHERE token_id = %s FOR UPDATE", (token.token_id,)
                )
                self._validate_replay(context, action_hash, token, existing, cursor.fetchone())
                return ledger_result(
                    existing, OperationStatus.DUPLICATE, spec.operation_scope
                )
            # ---- step 3: authorization and evidence -------------------------
            cursor.execute(
                "SELECT * FROM approvals WHERE token_id = %s FOR UPDATE", (token.token_id,)
            )
            approval = cursor.fetchone()
            # THE ONLY CLOCK READING IN THE TRANSACTION. Every durable timestamp
            # the remaining steps write is this value, and the token is compared
            # against the same instant the ledger row will carry.
            now = self._clock()
            self._validate_approval(context, action_hash, token, approval, now)
            validate_evidence(cursor, context, action.evidence_ids, now)
            # ---- step 4: lock the fixture and re-check the precondition -----
            cursor.execute(spec.fixture_lock_sql, spec.fixture_lock_params)
            fixture = cursor.fetchone()
            if fixture is None or not spec.fixture_present(fixture):
                raise ApprovalDenied(
                    spec.fixture_absent_message, stage=RefusalStage.FIXTURE_ABSENT
                )
            if not spec.precondition(fixture):
                raise ApprovalDenied(
                    spec.precondition_message, stage=RefusalStage.PRECONDITION
                )
            # ---- step 5: the scenario's own change --------------------------
            outcome = spec.mutation(
                LockedTransaction(
                    cursor=cursor,
                    now=now,
                    context=context,
                    action=action,
                    action_hash=action_hash,
                    fixture=fixture,
                )
            )
            # ---- step 6: the ledger row, the counter, the audit fact --------
            #
            # ``arguments`` is written here, in this transaction, from the same
            # ``action`` that produced ``action_hash`` at the top of this method.
            # That is a correctness requirement rather than tidiness: anything
            # that could let the stored arguments diverge from what actually
            # executed would show a later reader -- and a monitor -- a fiction,
            # which is strictly worse than showing it nothing. An uninformed
            # monitor knows it is uninformed; a misinformed one reasons
            # confidently from the wrong thing.
            #
            # It is storage and never identity. Nothing reads it to decide whether
            # a call already happened; that is ``action_hash`` and the idempotency
            # key derived from it, both untouched above.
            cursor.execute(
                "INSERT INTO operation_ledger (operation_scope, idempotency_key, action_hash, "
                "approval_token_id, one_time_use_id, incident_id, thread_id, correlation_id, "
                "actor, permission, approver, result, arguments, committed_at) VALUES (%s, %s, "
                "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    spec.operation_scope,
                    context.idempotency_key,
                    action_hash,
                    token.token_id,
                    token.one_time_use_id,
                    context.incident_id,
                    context.thread_id,
                    context.correlation_id,
                    context.actor,
                    context.permission,
                    token.approver,
                    json.dumps(outcome.result),
                    json.dumps(action.arguments.model_dump(mode="json"), sort_keys=True),
                    now,
                ),
            )
            if outcome.mutating:
                clauses = [outcome.fixture_touch] if outcome.fixture_touch else []
                clauses.append("mutation_count = mutation_count + 1")
                parameters: tuple[object, ...] = outcome.fixture_touch_params
                if spec.stamps_updated_at:
                    clauses.append("updated_at = %s")
                    parameters = (*parameters, now)
                cursor.execute(
                    f"UPDATE {spec.fixture_table} SET {', '.join(clauses)} "
                    f"WHERE {spec.fixture_filter}",
                    parameters,
                )
            if spec.commit_transition is not None:
                cursor.execute(
                    # created_at comes from the same application clock as every
                    # other audit event. Omitting it would take the database
                    # server's DEFAULT now() and put two timebases in one column.
                    "INSERT INTO audit_timeline (audit_id, incident_id, event_type, actor, "
                    "payload, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
                    (
                        uuid4(),
                        context.incident_id,
                        spec.commit_transition,
                        context.actor,
                        json.dumps(outcome.result),
                        now,
                    ),
                )
            # ---- step 7: consume the authorization --------------------------
            cursor.execute(
                "UPDATE approvals SET consumed_at = %s WHERE token_id = %s", (now, token.token_id)
            )
            ledger = {
                "action_hash": action_hash,
                "approval_token_id": token.token_id,
                "one_time_use_id": token.one_time_use_id,
                "incident_id": context.incident_id,
                "thread_id": context.thread_id,
                "correlation_id": context.correlation_id,
                "actor": context.actor,
                "permission": context.permission,
                "approver": token.approver,
                "result": outcome.result,
                "committed_at": now,
                "idempotency_key": context.idempotency_key,
            }
        # ---- step 8: committed. Only now may the response be lost -----------
        if response_loss:
            raise ResponseLost(spec.response_loss_message)
        return ledger_result(ledger, OperationStatus.SUCCEEDED, spec.operation_scope)


def validate_evidence(
    cursor: psycopg.Cursor[dict[str, object]],
    context: ToolCallContext,
    evidence_ids: tuple[str, ...],
    now: datetime,
) -> None:
    """Moved here byte for byte from ``LabRepository._validate_evidence``.

    Not edited, and deliberately so. The evidence INSERT this query reads
    against carries no ``ON CONFLICT``, so a crash-replay that re-collects
    produces new evidence ids, a new action hash and therefore a new
    idempotency key -- which means the DUPLICATE branch never fires and a
    second ledger row is written. That interaction is latent today and it is a
    recorded finding for the phase that versions the recovery contract, not
    something to change under cover of an extraction: the six paths all shared
    this function already, so moving it is the one change that provably cannot
    alter what any of them does.
    """
    cursor.execute(
        "SELECT count(*) AS matching FROM evidence_records "
        "JOIN immutable_evidence_source source ON source.source_id = "
        "evidence_records.source_id "
        "WHERE evidence_id = ANY(%s) AND evidence_records.incident_id = %s "
        "AND evidence_records.thread_id = %s "
        "AND evidence_records.correlation_id = %s "
        "AND evidence_records.actor = %s "
        "AND evidence_records.expires_at > %s "
        "AND evidence_records.permission = 'observability:read' "
        "AND evidence_records.tool_name = CASE WHEN source.kind = 'db_pool_metrics' "
        "THEN 'metrics.db_pool' ELSE 'observability.' || source.kind END",
        (
            list(evidence_ids),
            context.incident_id,
            context.thread_id,
            context.correlation_id,
            context.actor,
            now,
        ),
    )
    row = cursor.fetchone()
    if row is None or cast(int, row["matching"]) != len(evidence_ids):
        raise ApprovalDenied("action evidence is missing, out of scope, or stale")


def ledger_result(
    ledger: Mapping[str, object], status: OperationStatus, scope: str
) -> OperationLedgerResult:
    """Moved here from ``LabRepository._ledger_result``, without its default.

    The old signature defaulted ``scope`` to D1's, which is how D1 came to be
    the one path that never passed its own scope. Every capability now carries
    its scope in its spec, so the default has nothing left to mean.
    """
    return OperationLedgerResult(
        context=ToolCallContext(
            incident_id=str(ledger["incident_id"]),
            thread_id=str(ledger["thread_id"]),
            correlation_id=str(ledger["correlation_id"]),
            actor=str(ledger["actor"]),
            permission=str(ledger["permission"]),
            idempotency_key=UUID(str(ledger["idempotency_key"]))
            if ledger.get("idempotency_key") is not None
            else None,
        ),
        idempotency_key=UUID(str(ledger["idempotency_key"])),
        action_hash=str(ledger["action_hash"]),
        approval_token_id=UUID(str(ledger["approval_token_id"])),
        one_time_use_id=UUID(str(ledger["one_time_use_id"])),
        status=status,
        operation_id=f"{scope}:{ledger['idempotency_key']}",
        committed_at=cast(datetime, ledger["committed_at"]),
        result=cast(dict[str, Any], ledger["result"]),
    )
