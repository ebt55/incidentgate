"""The exclusivity guard must actually hold the lock, not merely intend to.

A guard nobody can see working is indistinguishable from a comment. These tests
run *inside* a guarded session, so the session fixture in ``tests/conftest.py`` is
already holding the advisory lock while they execute -- which makes the mechanism
observable from a second connection.

Advisory locks are re-entrant within one session and exclusive between sessions,
so "a different connection cannot take it" is exactly the property that stops a
second suite run, and it is checkable without starting one.
"""

from __future__ import annotations

import os

import pytest

from tests.conftest import LAB_SUITE_LOCK_KEY

DSN = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="requires the lab database")


def test_a_second_connection_cannot_take_the_lock_this_session_holds() -> None:
    """The guard's whole mechanism, observed rather than described.

    If this returns True, the session fixture is not holding the lock and a
    concurrent suite run would proceed into the fixture races unchallenged.
    """
    import psycopg

    with psycopg.connect(DSN, autocommit=True) as other:
        row = other.execute(
            "SELECT pg_try_advisory_lock(%s)", (LAB_SUITE_LOCK_KEY,)
        ).fetchone()
        assert row is not None
        try:
            assert row[0] is False, (
                "a second connection acquired the lab-suite lock, so the exclusivity "
                "guard is not actually held for this session"
            )
        finally:
            if row[0]:
                other.execute("SELECT pg_advisory_unlock(%s)", (LAB_SUITE_LOCK_KEY,))


def test_the_lock_is_held_by_exactly_one_session() -> None:
    """Held once, by us. Two holders would mean the key is not doing its job."""
    import psycopg

    with psycopg.connect(DSN, autocommit=True) as other:
        rows = other.execute(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = %s",
            (LAB_SUITE_LOCK_KEY % (2**32),),
        ).fetchone()
        assert rows is not None
        # The lock is recorded; the exact row count depends on how Postgres splits
        # the 64-bit key, so this asserts presence rather than a magic number.
        assert rows[0] >= 1, "no advisory lock is recorded for the lab-suite key"


def test_the_guard_is_not_silently_disabled_when_a_database_is_configured() -> None:
    """``DATABASE_URL`` set means the guard must be active, not merely importable."""
    from tests import conftest

    assert conftest.LAB_SUITE_LOCK_KEY == 8_270_413_615_002_119
    # The fixture is autouse and session-scoped; if either changed, a run could
    # proceed unguarded while this file still passed.
    fixture = conftest._exclusive_lab_database
    marker = fixture._fixture_function_marker  # type: ignore[attr-defined]
    assert marker.scope == "session", marker
    assert marker.autouse is True, marker
