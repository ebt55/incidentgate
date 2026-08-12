"""The chaos reaper must terminate only the chaos harness's own idle backends.

Before the ``application_name`` filter its WHERE clause was "same database, not
me, idle for 20 seconds", which is also an exact description of a developer's
psql session, an open pgAdmin window, and the compose containers' idle pools.
The scoping test below is the one that would have caught that: it puts two idle
backends on the same database and asserts the reaper can tell them apart.
"""

from __future__ import annotations

import os
import time
from contextlib import suppress

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from incidentgate.chaos import CHAOS_APPLICATION_NAME, chaos_dsn, matrix
from incidentgate.chaos.matrix import REAP_IDLE_SECONDS, reap_idle_backends
from incidentgate.lab.repository import LabRepository


def _dsn() -> str:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("chaos reaper tests require DATABASE_URL")
    return dsn


def _alive(dsn: str, pid: int) -> bool:
    with psycopg.connect(dsn, autocommit=True) as connection:
        row = connection.execute("SELECT 1 FROM pg_stat_activity WHERE pid = %s", (pid,)).fetchone()
    return row is not None


def _settle_idle(connection: psycopg.Connection[object]) -> int:
    """Run one statement so the backend reports state='idle' with a fresh state_change.

    autocommit matters: without it psycopg leaves the backend in
    'idle in transaction', which the reaper deliberately never touches.
    """
    connection.execute("SELECT 1").fetchone()
    return connection.info.backend_pid


def test_reaper_terminates_chaos_backends_and_spares_everything_else() -> None:
    """The acceptance core: same database, both idle, only the tagged one dies."""
    dsn = _dsn()
    chaos = psycopg.connect(chaos_dsn(dsn), autocommit=True)
    bystander = psycopg.connect(
        make_conninfo(dsn, application_name="developer-psql"), autocommit=True
    )
    try:
        chaos_pid = _settle_idle(chaos)
        bystander_pid = _settle_idle(bystander)
        assert chaos_pid != bystander_pid

        # Outlive the short threshold this call passes; the default stays 20s.
        time.sleep(1.0)
        reap_idle_backends(dsn, idle_seconds=0.5)

        # pg_terminate_backend signals the backend; it does not block until exit.
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and _alive(dsn, chaos_pid):
            time.sleep(0.1)

        assert not _alive(dsn, chaos_pid), "chaos-tagged idle backend should be reaped"
        assert _alive(dsn, bystander_pid), "untagged idle backend must survive the reaper"
    finally:
        for connection in (chaos, bystander):
            with suppress(psycopg.Error):
                connection.close()


def test_reaper_spares_chaos_backends_younger_than_the_threshold() -> None:
    """Scoping is by name AND age; a freshly idle chaos backend is still in use."""
    dsn = _dsn()
    chaos = psycopg.connect(chaos_dsn(dsn), autocommit=True)
    try:
        chaos_pid = _settle_idle(chaos)
        reap_idle_backends(dsn, idle_seconds=300.0)
        assert _alive(dsn, chaos_pid), "a just-idled chaos backend must not be reaped"
    finally:
        with suppress(psycopg.Error):
            chaos.close()


def test_chaos_dsn_stamps_application_name_without_losing_the_target() -> None:
    """The stamp must survive whatever DSN form the caller used."""
    dsn = _dsn()
    with psycopg.connect(chaos_dsn(dsn), autocommit=True) as connection:
        row = connection.execute(
            "SELECT application_name, current_database() FROM pg_stat_activity "
            "WHERE pid = pg_backend_pid()"
        ).fetchone()
    assert row is not None
    assert row[0] == CHAOS_APPLICATION_NAME
    # Stamping must not have redirected the connection to a different database.
    with psycopg.connect(dsn, autocommit=True) as plain:
        expected = plain.execute("SELECT current_database()").fetchone()
    assert expected is not None
    assert row[1] == expected[0]


def test_the_stamp_reaches_connections_opened_by_chaos_unaware_code() -> None:
    """LabRepository knows nothing about chaos, yet its backends must be reapable.

    This is what makes DSN stamping the right mechanism rather than passing an
    application_name kwarg at each psycopg.connect: the harness only ever hands
    down a DSN string, and everything it hands the DSN to inherits the stamp.
    """
    repository = LabRepository(chaos_dsn(_dsn()))
    with repository._connect() as connection:
        row = connection.execute(
            "SELECT application_name FROM pg_stat_activity WHERE pid = pg_backend_pid()"
        ).fetchone()
    assert row is not None
    assert dict(row)["application_name"] == CHAOS_APPLICATION_NAME


def test_the_stamp_reaches_the_worker_subprocess() -> None:
    """The killed process is the subprocess, so its DSN is the one that must carry it."""
    environment = matrix._worker_env(chaos_dsn(_dsn()), None, None)
    assert f"application_name={CHAOS_APPLICATION_NAME}" in environment["DATABASE_URL"]


def test_reap_idle_seconds_default_is_unchanged() -> None:
    """Parameterizing the interval is for tests; production behavior must not move."""
    assert REAP_IDLE_SECONDS == 20.0


def test_run_matrix_always_reaps_even_when_no_cell_reaches_the_cadence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dormancy fix: reaping must not depend on executing REAP_EVERY_CELLS cells.

    The CI subset now executes 12 cells against a cadence of 12, so the cadence
    fires exactly once and only on the very last cell - it reached zero times
    before R01 joined the subset, and any narrower selection reaches it zero
    times again. An empty scenario set is the sharpest version of that case:
    zero cells, and the reaper must still run exactly once.
    """
    dsn = _dsn()
    calls: list[str] = []
    monkeypatch.setattr(matrix, "reap_idle_backends", lambda target, **_: calls.append(target))

    report = matrix.run_matrix(dsn, ())

    assert report["totals"]["cells"] == 0
    assert len(calls) == 1, "run_matrix must reap once per run regardless of cell count"
    assert f"application_name={CHAOS_APPLICATION_NAME}" in calls[0]
