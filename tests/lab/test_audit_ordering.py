"""The audit timeline is ordered by insertion, not by anybody's clock.

audit_timeline.created_at used to be the sort key, and it is written from two
different clocks: append_audit_event supplies a Python datetime from the
application host, while the operation-commit inserts omitted the column and took
the database server's DEFAULT now(). Ordering by that column is only as reliable
as two machines agreeing about the time.

Measured on this machine, a freshly started Docker Desktop postgres container
runs ~0.75s behind the Windows host. That is larger than the gap between issuing
an approval and committing the rollback it authorizes, so the timeline reported
the mutation BEFORE its own approval -- on a cold volume, deterministically. The
same skew is plausible on any warm database at a moment when a transaction is
slow, which is the shape of the unresolved chaos kill-matrix flake recorded in
tests/chaos/test_kill_matrix.py: that failure was also a state-divergence on the
audit sequence. This fix removes one mechanism that could produce it. It does not
close that question, which is tracked separately.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest

from incidentgate.lab.repository import LabRepository

INCIDENT = "INC-AUDIT-ORDER"


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("audit ordering tests require DATABASE_URL")
    repo = LabRepository(dsn)
    repo.migrate()
    with repo._connect() as connection, connection.cursor() as cursor:
        cursor.execute("DELETE FROM audit_timeline WHERE incident_id = %s", (INCIDENT,))
    return repo


def _append(repo: LabRepository, transition: str, when: datetime) -> None:
    repo.append_audit_event(
        incident_id=INCIDENT,
        thread_id="audit-order-thread",
        actor="operator-1",
        transition=transition,
        action_hash=None,
        reason=None,
        timestamp=when,
    )


def test_timeline_order_survives_timestamps_that_run_backwards(
    repository: LabRepository,
) -> None:
    """The load-bearing case: later events carrying earlier timestamps.

    This is exactly what host/container clock skew produced. Written first,
    second, third; timestamped 3rd, 1st, 2nd. Causal order must still win.
    """
    base = datetime.now(UTC)
    _append(repository, "first", base + timedelta(seconds=30))
    _append(repository, "second", base - timedelta(seconds=30))
    _append(repository, "third", base)

    events = repository.timeline(INCIDENT)
    assert [event.transition for event in events] == ["first", "second", "third"]
    # And the timestamps really are out of order, so this is not a vacuous pass.
    stamps = [event.timestamp for event in events]
    assert stamps != sorted(stamps)


def test_identical_timestamps_do_not_make_the_order_ambiguous(
    repository: LabRepository,
) -> None:
    """Ties used to be broken by a content-derived uuid, i.e. arbitrarily."""
    same = datetime.now(UTC)
    for transition in ("alpha", "beta", "gamma", "delta"):
        _append(repository, transition, same)

    order = [event.transition for event in repository.timeline(INCIDENT)]
    assert order == ["alpha", "beta", "gamma", "delta"]


def test_a_committed_operation_is_never_ordered_before_its_own_approval(
    repository: LabRepository,
) -> None:
    """The defect in its original form, reproduced directly against the two writers.

    The approval is appended with an application timestamp; the operation commit
    used to omit created_at and take the database clock. Here the application
    clock is deliberately ahead of the value the commit path would have used.
    """
    dsn = repository.dsn
    approval_time = datetime.now(UTC) + timedelta(seconds=5)
    _append(repository, "approval_issued", approval_time)
    # Simulate the pre-fix commit insert: no created_at, so the database default.
    with psycopg.connect(dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO audit_timeline (audit_id, incident_id, event_type, actor, payload) "
            "VALUES (%s, %s, 'rollback_committed', %s, %s)",
            (uuid4(), INCIDENT, "operator-1", "{}"),
        )

    order = [event.transition for event in repository.timeline(INCIDENT)]
    assert order == ["approval_issued", "rollback_committed"], (
        "a mutation must never be ordered before the approval that authorized it"
    )
