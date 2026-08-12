"""One clock owns each comparison, proved by injecting skew rather than waiting for it.

Background. This machine has already produced one two-clock defect
(audit_timeline.created_at, fixed by migration 014) and the host/container skew
that caused it is real and measured: on 2026-08-12 a freshly started Docker
Desktop postgres container ran 1.49s AHEAD of the Windows host at the moment it
accepted connections, oscillating between -0.48s and +1.48s over the following
five minutes before converging. An earlier investigation on the same machine
recorded 0.75s in the other direction.

Waiting for that window is a bad test: it needs a cold engine, it cannot run in
CI (GitHub Actions runs postgres as a service container sharing the runner's
clock, so the skew there is exactly zero), and it is not reproducible on demand.
These tests construct the skew at the seam instead, in both directions, so they
are deterministic and they run everywhere.

What is being proved is a conjunction:

1. Offsetting the clock the application runs on does not invert any approval or
   evidence verdict, because one clock owns both sides of every comparison.
2. Timestamps that the DATABASE server wrote, offset by +/-2s from the host, do
   not invert those verdicts either.
3. Exactly-once survives the offset.
4. Every time budget in the system is wide enough that the measured skew cannot
   reach it -- with the margin asserted, not assumed.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from incidentgate.contracts import (
    ApprovalToken,
    CanonicalAction,
    IncidentIdentity,
    PolicyConfiguration,
    Role,
    ToolCallContext,
    canonical_action_hash,
)
from incidentgate.control import EvidenceValidator
from incidentgate.control.models import Caller, EvidenceState
from incidentgate.integration import IncidentRuntime, PendingApproval
from incidentgate.lab.auth import Principal
from incidentgate.lab.errors import ApprovalDenied, ResponseLost
from incidentgate.lab.repository import (
    D6_FRESHNESS_BUDGET_SECONDS,
    EVIDENCE_TTL_SECONDS,
    LabRepository,
)
from incidentgate.lab.service import ObservabilityService, OperationsService
from incidentgate.reasons import TOKEN_EXPIRED, TOKEN_VALID

# The largest host/container disagreement this system is designed to absorb.
#
# Justification for the size, which is the only thing that makes a tolerance
# constant honest. Measured on this machine: +1.49s at container start, decaying
# below 0.3s within ~12 minutes; 0.75s in the opposite direction during an
# earlier investigation. 5.0s is ~3.4x the largest value ever observed here. It
# is chosen to bound the plausible range of Docker Desktop VM clock convergence,
# NOT to make any particular assertion pass -- no comparison in the production
# code widens by this value, and nothing is skipped or retried because of it.
# Its only use is the margin assertion below: every real budget must dwarf it.
MAX_TOLERATED_CLOCK_SKEW_SECONDS = 5.0

# The offset the injection tests apply, in both directions. Deliberately larger
# than the worst skew actually measured, so a passing test is not a coincidence
# of a quiet clock.
INJECTED_SKEW = timedelta(seconds=2)

D1_SOURCES = frozenset(
    {"observability.health", "observability.deployment_diff", "observability.logs"}
)
ROLLBACK = "operations.rollback"


@pytest.fixture
def dsn() -> str:
    value = os.environ.get("DATABASE_URL")
    if not value:
        pytest.skip("one-clock discipline tests require DATABASE_URL")
    return value


@pytest.fixture
def repository(dsn: str) -> LabRepository:
    repo = LabRepository(dsn)
    repo.migrate()
    return repo


def _policy() -> PolicyConfiguration:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    with open(os.path.join(root, "config", "policy.example.json")) as handle:
        return PolicyConfiguration.model_validate(json.load(handle))


def _d1_inputs() -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    thread_id = f"one-clock-{uuid4().hex[:12]}"
    incident = IncidentIdentity(
        incident_id="INC-D1",
        scenario_id="D1",
        thread_id=thread_id,
        correlation_id=f"corr-{thread_id}",
    )
    caller = Caller(actor="operator-1", role=Role.OPERATOR)
    return (
        incident,
        caller,
        ToolCallContext(
            incident_id="INC-D1",
            thread_id=thread_id,
            correlation_id=incident.correlation_id,
            actor="operator-1",
            permission="operations:write",
        ),
    )


def _reinsert_source_at_database_time(
    repo: LabRepository, kind: str, offset_seconds: float
) -> None:
    """Rewrite one D1 evidence source so its observed_at comes from the DB clock.

    This is the skew seam. ``now()`` is evaluated by the postgres server, so the
    row carries the database's timebase, not the host's; the offset then stands
    in for a container clock that disagrees by that much. The source table
    rejects UPDATE, so the row is re-created.
    """
    with repo._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT source_id, payload FROM immutable_evidence_source "
            "WHERE incident_id = 'INC-D1' AND kind = %s ORDER BY observed_at DESC LIMIT 1",
            (kind,),
        )
        row = cursor.fetchone()
        assert row is not None, f"D1 fixture must have a {kind} source"
        cursor.execute(
            "DELETE FROM immutable_evidence_source WHERE incident_id = 'INC-D1' AND kind = %s",
            (kind,),
        )
        cursor.execute(
            "INSERT INTO immutable_evidence_source "
            "(source_id, incident_id, kind, payload, observed_at) "
            "VALUES (%s, 'INC-D1', %s, %s, now() + make_interval(secs => %s))",
            (row["source_id"], kind, json.dumps(row["payload"]), offset_seconds),
        )


@pytest.mark.parametrize("offset_seconds", [-2.0, 0.0, 2.0])
def test_database_written_evidence_does_not_invert_freshness_under_two_second_skew(
    repository: LabRepository, offset_seconds: float
) -> None:
    """A +/-2s database-clock offset must not change any freshness verdict.

    The evidence anchor is written by ``now()`` on the postgres server and then
    judged by the application's clock on the host. If those two timebases were
    allowed to disagree materially the verdict would flip; it must not, because
    the budget is EVIDENCE_TTL_SECONDS and the skew is two seconds.
    """
    repository.reset_d1()
    repository.inject_d1()
    try:
        _reinsert_source_at_database_time(repository, "logs", offset_seconds)
        _reinsert_source_at_database_time(repository, "deployment_diff", offset_seconds)
        _, _, context = _d1_inputs()
        read = context.model_copy(
            update={"permission": "observability:read", "idempotency_key": None}
        )
        principal = Principal("operator-1", Role.OPERATOR)
        service = ObservabilityService(repository)
        records = tuple(
            service.get(read, principal, kind) for kind in ("health", "deployment_diff", "logs")
        )
        action = CanonicalAction(
            tool_name=ROLLBACK,
            incident_id="INC-D1",
            thread_id=context.thread_id,
            actor="operator-1",
            permission="operations:write",
            evidence_ids=tuple(record.evidence_id for record in records),
            arguments={"kind": "rollback", "component": "api", "target_revision": "v1"},
        )
        validation = EvidenceValidator(
            _policy(), lambda: datetime.now(UTC), allowed_sources=D1_SOURCES
        ).validate(action, records, read)
        assert validation.state is EvidenceState.VALID, (
            f"a {offset_seconds}s database-clock offset inverted an evidence freshness verdict: "
            f"{validation.reasons}"
        )
    finally:
        repository.reset_d1()


def test_the_freshness_check_is_not_vacuous(repository: LabRepository) -> None:
    """Anti-vacuity guard for the test above.

    Proving that 2s does not flip the verdict is worthless unless something
    does. Past the TTL, the same code path must reject.

    The margin is deliberately MAX_TOLERATED_CLOCK_SKEW_SECONDS beyond the TTL
    rather than one second beyond it. Written with a one-second margin this
    assertion failed intermittently on this machine, and the reason is the whole
    subject of this file: observed_at here is written by ``now()`` on the
    postgres server while the validator reads the host clock, so a container
    running ~1.5s ahead turns a 121s age into a 119.5s age and the verdict
    inverts. That is a real demonstration of the defect class, not flake -- see
    test_a_near_boundary_mixed_clock_comparison_is_the_hazard below.
    """
    repository.reset_d1()
    repository.inject_d1()
    try:
        stale = -(EVIDENCE_TTL_SECONDS + MAX_TOLERATED_CLOCK_SKEW_SECONDS + 25.0)
        _reinsert_source_at_database_time(repository, "logs", stale)
        _reinsert_source_at_database_time(repository, "deployment_diff", stale)
        _, _, context = _d1_inputs()
        read = context.model_copy(
            update={"permission": "observability:read", "idempotency_key": None}
        )
        principal = Principal("operator-1", Role.OPERATOR)
        service = ObservabilityService(repository)
        records = tuple(
            service.get(read, principal, kind) for kind in ("health", "deployment_diff", "logs")
        )
        action = CanonicalAction(
            tool_name=ROLLBACK,
            incident_id="INC-D1",
            thread_id=context.thread_id,
            actor="operator-1",
            permission="operations:write",
            evidence_ids=tuple(record.evidence_id for record in records),
            arguments={"kind": "rollback", "component": "api", "target_revision": "v1"},
        )
        validation = EvidenceValidator(
            _policy(), lambda: datetime.now(UTC), allowed_sources=D1_SOURCES
        ).validate(action, records, read)
        assert validation.state is EvidenceState.INVALID
        assert any("expired_evidence" in reason for reason in validation.reasons)
    finally:
        repository.reset_d1()


def test_production_never_lets_the_database_clock_write_the_evidence_anchor(
    repository: LabRepository,
) -> None:
    """The invariant that keeps the near-boundary hazard unreachable in production.

    immutable_evidence_source.observed_at flows into evidence_records.expires_at,
    which is then compared against the application clock. If that anchor were
    ever written by the database server -- which the column's DEFAULT now() makes
    possible for any writer that omits it -- the two sides of that comparison
    would come from two machines, and near the TTL boundary the verdict inverts
    under the skew this machine actually produces.

    So the discipline is: the application clock writes the anchor, always. This
    asserts it against the injected clock rather than trusting the convention.
    """
    marker = datetime.now(UTC) - timedelta(days=1)
    scoped = LabRepository(repository.dsn, clock=lambda: marker)
    scoped.reset_d1()
    try:
        scoped.inject_d1()
        with scoped._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT kind, observed_at FROM immutable_evidence_source "
                "WHERE incident_id = 'INC-D1' ORDER BY kind"
            )
            rows = cursor.fetchall()
        assert rows, "the D1 fixture must write evidence sources"
        for row in rows:
            assert row["observed_at"] == marker, (
                f"{row['kind']} took its observed_at from the database clock instead of the "
                "injected application clock; that is the two-timebase defect"
            )
    finally:
        scoped.reset_d1()


@pytest.mark.parametrize("offset_seconds", [-2.0, 2.0])
def test_an_approval_written_by_the_database_clock_is_neither_spuriously_expired_nor_revived(
    repository: LabRepository, offset_seconds: float
) -> None:
    """approvals.expires_at written by postgres, validated on the host.

    Both the live case and the genuinely-expired case are asserted, so a +/-2s
    offset is shown to move neither verdict.
    """
    repository.reset_d1()
    try:
        action = CanonicalAction(
            tool_name=ROLLBACK,
            incident_id="INC-D1",
            thread_id=f"one-clock-{uuid4().hex[:12]}",
            actor="operator-1",
            permission="operations:write",
            evidence_ids=(str(uuid4()),),
            arguments={"kind": "rollback", "component": "api", "target_revision": "v1"},
        )
        action_hash = canonical_action_hash(action)

        for live, expected in ((True, TOKEN_VALID), (False, TOKEN_EXPIRED)):
            token_id, one_time = uuid4(), uuid4()
            # requested_at/expires_at/approved_at all come from the DATABASE
            # clock, shifted by the injected skew; validation below runs on the
            # host clock.
            lifetime = 60.0 if live else -30.0
            with repository._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO approvals (token_id, one_time_use_id, incident_id, action_hash, "
                    "actor, approver, requested_at, expires_at, approved_at) VALUES "
                    "(%s, %s, 'INC-D1', %s, 'operator-1', 'approver-1', "
                    "now() + make_interval(secs => %s), "
                    "now() + make_interval(secs => %s), "
                    "now() + make_interval(secs => %s)) "
                    "RETURNING requested_at, expires_at, approved_at",
                    (
                        token_id,
                        one_time,
                        action_hash,
                        offset_seconds - 120.0,
                        offset_seconds + lifetime,
                        offset_seconds - 120.0,
                    ),
                )
                stored = cursor.fetchone()
                assert stored is not None
            token = ApprovalToken(
                token_id=token_id,
                one_time_use_id=one_time,
                action_hash=action_hash,
                actor="operator-1",
                approver="approver-1",
                requested_at=stored["requested_at"],
                expires_at=stored["expires_at"],
                approved_at=stored["approved_at"],
            )
            valid, reason = repository.validate(
                token, action_hash=action_hash, actor="operator-1", now=datetime.now(UTC)
            )
            assert reason == expected, (
                f"a {offset_seconds}s database-clock offset changed the approval verdict for a "
                f"{'live' if live else 'expired'} token: {reason}"
            )
            assert valid is live
    finally:
        repository.reset_d1()


@pytest.mark.parametrize("offset", [-INJECTED_SKEW, INJECTED_SKEW])
def test_exactly_once_survives_a_two_second_runtime_clock_offset(
    repository: LabRepository, dsn: str, offset: timedelta
) -> None:
    """I2 under injected skew: response loss then retry, still exactly one mutation.

    The runtime clock is offset while the rows already in the database are not.
    Before one-clock discipline this offset never reached LabRepository, which
    read datetime.now(UTC) inline -- so the approval was stamped from one clock
    and re-validated against another inside a single request.
    """
    repository.reset_d1()
    repository.inject_d1()
    incident, caller, context = _d1_inputs()
    try:

        def skewed() -> datetime:
            return datetime.now(UTC) + offset

        with IncidentRuntime(dsn, clock=skewed, response_loss_once=True) as first:
            pending = first.start(incident, caller, context)
            assert isinstance(pending, PendingApproval), (
                f"a {offset.total_seconds()}s clock offset blocked a valid D1 approval"
            )
            with pytest.raises(ResponseLost):
                first.approve(incident.thread_id, Principal("approver-1", Role.APPROVER))
        with IncidentRuntime(dsn, clock=skewed) as second:
            second.resume(incident.thread_id)
            replay = second.retry(incident.thread_id)
        assert replay.result is not None and replay.result.operation is not None
        assert replay.result.operation.status.value == "duplicate"
        assert repository.operation_count("INC-D1") == 1
        assert int(repository.state()["mutation_count"]) == 1
    finally:
        repository.reset_d1()


@pytest.mark.parametrize("offset", [-INJECTED_SKEW, INJECTED_SKEW])
def test_cross_thread_evidence_is_still_refused_under_a_two_second_offset(
    repository: LabRepository, dsn: str, offset: timedelta
) -> None:
    """I3 under injected skew: a clock offset must not buy authority.

    The safety property is that evidence collected on another thread cannot
    spend an otherwise valid approval. A skewed clock must not turn that denial
    into a permit.
    """
    skewed_repository = LabRepository(dsn, clock=lambda: datetime.now(UTC) + offset)
    skewed_repository.reset_d1()
    skewed_repository.inject_d1()
    _, _, context = _d1_inputs()
    mutation_context = context.model_copy(update={"idempotency_key": uuid4()})
    try:
        foreign = mutation_context.model_copy(update={"thread_id": f"foreign-{uuid4().hex}"})
        read = foreign.model_copy(
            update={"permission": "observability:read", "idempotency_key": None}
        )
        principal = Principal("operator-1", Role.OPERATOR)
        service = ObservabilityService(skewed_repository)
        evidence_ids = tuple(
            service.get(read, principal, kind).evidence_id
            for kind in ("health", "deployment_diff", "logs")
        )
        substituted = CanonicalAction(
            tool_name=ROLLBACK,
            incident_id="INC-D1",
            thread_id=mutation_context.thread_id,
            actor="operator-1",
            permission="operations:write",
            evidence_ids=evidence_ids,
            arguments={"kind": "rollback", "component": "api", "target_revision": "v1"},
        )
        issued = datetime.now(UTC) + offset
        token = ApprovalToken(
            action_hash=canonical_action_hash(substituted),
            actor="operator-1",
            approver="approver-1",
            one_time_use_id=uuid4(),
            requested_at=issued,
            expires_at=issued + timedelta(minutes=1),
            approved_at=issued,
        )
        skewed_repository.record_approval(token, "INC-D1")
        with pytest.raises(ApprovalDenied):
            OperationsService(skewed_repository).rollback(
                mutation_context, principal, substituted, token
            )
        assert not skewed_repository.approval_consumed(token.token_id)
        assert skewed_repository.operation_count("INC-D1") == 0
        assert int(skewed_repository.state()["mutation_count"]) == 0
    finally:
        skewed_repository.reset_d1()


def test_every_time_budget_dwarfs_the_maximum_tolerated_clock_skew() -> None:
    """The quantitative reason skew cannot reach these comparisons.

    This is the assertion that makes the whole class of failure impossible
    rather than merely unobserved: the narrowest budget in the system is
    EVIDENCE_TTL_SECONDS, and it exceeds the worst tolerated skew by more than
    an order of magnitude. If someone later tightens a budget toward the skew
    band, this fails and says why.
    """
    policy = _policy()
    budgets = {
        "evidence TTL": float(EVIDENCE_TTL_SECONDS),
        "D6 freshness": float(D6_FRESHNESS_BUDGET_SECONDS),
    }
    for name, rule in policy.tools.items():
        budgets[f"policy max_age {name}"] = float(rule.evidence.max_age_seconds)

    narrowest = min(budgets.values())
    assert narrowest >= MAX_TOLERATED_CLOCK_SKEW_SECONDS * 10, (
        "a time budget has been tightened to within 10x of the tolerated clock skew; "
        f"narrowest={narrowest}s tolerated_skew={MAX_TOLERATED_CLOCK_SKEW_SECONDS}s "
        f"budgets={budgets}"
    )


def test_only_informational_columns_take_their_timestamp_from_the_database_clock(
    repository: LabRepository,
) -> None:
    """The static audit, kept true by execution.

    A column with DEFAULT now() is filled by the postgres server whenever a
    writer omits it -- which is exactly how audit_timeline.created_at ended up
    carrying two timebases. Such a column is only safe if nothing ever compares
    it against a host-produced value. This pins the audited allowlist so that a
    new defaulted timestamp column has to be classified deliberately.
    """
    # Every entry is a column whose value may come from the database clock, with
    # the reason that is harmless. None of these is an operand of a comparison
    # against a host-generated timestamp.
    allowed = {
        # Ordering moved to the `sequence` identity column in migration 014;
        # created_at is informational only. tests/lab/test_audit_ordering.py
        # depends on this default to reproduce the original defect.
        ("audit_timeline", "created_at"),
        # Never read back for a comparison; presentation only.
        ("ticket_notes", "created_at"),
        # Migration bookkeeping.
        ("schema_migrations", "applied_at"),
        # Fixture bookkeeping: last-touched markers, never compared.
        ("target_state", "updated_at"),
        ("scenario_target_state", "updated_at"),
        ("d5_fixture_state", "updated_at"),
        ("d8_fixture_state", "updated_at"),
        # The evidence anchor. Production always supplies observed_at explicitly
        # (LabRepository.evidence / inject_d1 / inject_checkpoint); the default
        # is reachable only from test inserts. It is listed here because
        # removing it is a schema change, not because it is comparison-safe:
        # this value does flow into evidence_records.expires_at.
        ("immutable_evidence_source", "observed_at"),
    }
    reliability = ("r01", "r02", "r03", "r04", "r05", "r06", "r07", "r08", "r09", "r10", "r11")
    for scenario in (*reliability, "r12"):
        allowed.add((f"{scenario}_fixture_state", "updated_at"))
    # The same last-touched marker every other fixture state carries, never
    # compared; production always supplies it (inject_checkpoint / _mutate_t1).
    # T1's two other timestamp columns -- t1_immutable_record.created_at and
    # t1_outbound_note_store.written_at -- deliberately carry no default at all,
    # so they are absent from this list rather than allowlisted into it.
    allowed.add(("t1_fixture_state", "updated_at"))

    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT c.table_name, c.column_name FROM information_schema.columns c "
            "JOIN information_schema.tables t ON t.table_name = c.table_name "
            "AND t.table_schema = c.table_schema "
            "WHERE c.table_schema = current_schema() AND t.table_type = 'BASE TABLE' "
            "AND c.data_type LIKE 'timestamp%%' AND c.column_default IS NOT NULL"
        )
        defaulted = {(row["table_name"], row["column_name"]) for row in cursor.fetchall()}

    unclassified = defaulted - allowed
    assert not unclassified, (
        "these timestamp columns take their value from the database server clock but have not "
        "been classified against the one-clock discipline; either supply the timestamp from the "
        f"application clock or add them to the allowlist with a reason: {sorted(unclassified)}"
    )
