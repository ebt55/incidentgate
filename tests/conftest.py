"""One suite run at a time against the lab database, enforced rather than assumed.

THE DEFECT THIS EXISTS FOR IS THE SILENCE, NOT THE SHARING.

The suite requires **exclusive** use of the Postgres named by ``DATABASE_URL``,
and until 2026-08-25 nothing said so anywhere. The fixture tables are single-row
shared mutable singletons -- ``t1_fixture_state`` holds one row per scenario with
an ``injected`` boolean that tests reset, inject and consume -- and approval tokens
are single-use by design. Two concurrent runs therefore take each other's fixtures
and burn each other's tokens.

WHY IT READ AS "ENVIRONMENTAL" TO TWO PEOPLE IN A ROW

The failures never look like a race. They land on
``ValueError: sabotage evidence requires injected fixture`` and on
``ApprovalDenied`` -- a fixture that is not injected and a token that is missing,
expired or consumed -- which are exactly what a *correct* system says when the
thing it needed was taken. They are never connect errors and never behavioural
assertions.

And the failing **set varies between runs on an identical tree**: 4 failures, then
3, then 15, then a clean 2405 alone. That variation is the tell. An ordinary
order-dependence bug fails the same way every time; only a race repaints the
target, and "different tests fail each time, all pass in isolation" is precisely
the signature that made both readers reach for "environment" and stop.

WHAT THIS GUARD DOES AND DOES NOT CATCH

It takes a Postgres session-level advisory lock and **fails the run immediately**
if another run holds it. Loud and at startup, rather than 2,400 tests later in a
shape that reads as flake.

It is honest about its reach, which is narrower than it looks:

* it catches another *guarded* suite run -- one that also executes this fixture;
* it does **not** catch a process that uses this database without running this
  fixture: a manual capture run, a matrix regeneration, ``psql``, or a suite from
  a checkout that predates this file;
* it does **not** make the tests order-independent or concurrency-safe, and is not
  meant to. The shared-singleton fixtures are deliberate, and the symptom was
  telling the truth.

So this converts a misleading failure into an accurate one. It does not remove the
constraint, and the constraint is now written down in the README as well.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator

import pytest

#: A fixed application-defined key for ``pg_advisory_lock``. Any constant works;
#: it is written as a literal so two checkouts of this file agree on it, which is
#: the whole mechanism.
LAB_SUITE_LOCK_KEY = 8_270_413_615_002_119

_MESSAGE = """
ANOTHER TEST RUN HOLDS THIS LAB DATABASE.

This suite needs exclusive use of the Postgres at DATABASE_URL. Its fixture tables
are single-row shared singletons and its approval tokens are single-use, so two
concurrent runs consume each other's state. The failures that produces do not look
like a race -- they surface as "sabotage evidence requires injected fixture" and
ApprovalDenied, in a different set of tests each time -- which is why this refuses
up front instead of letting you read the wreckage as flake.

Wait for the other run to finish, then start again.
"""


@pytest.fixture(scope="session", autouse=True)
def _exclusive_lab_database() -> Iterator[None]:
    """Hold an advisory lock for the whole session, or refuse to run."""
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        # No database configured: the DB-backed tests skip anyway, and there is
        # nothing to contend for.
        yield
        return

    try:
        import psycopg
    except ImportError:  # pragma: no cover -- psycopg is a hard dependency
        yield
        return

    try:
        connection = psycopg.connect(dsn, autocommit=True)
    except Exception as error:  # noqa: BLE001
        # A database this run cannot reach is the DB-backed tests' problem to
        # report, in their own words. The guard says plainly that it is not
        # active rather than pretending the run is protected.
        sys.stderr.write(
            f"\nlab-database exclusivity guard INACTIVE: cannot connect ({type(error).__name__}). "
            "Concurrent-run protection is off for this session.\n"
        )
        yield
        return

    with connection:
        acquired = connection.execute(
            "SELECT pg_try_advisory_lock(%s)", (LAB_SUITE_LOCK_KEY,)
        ).fetchone()
        if not acquired or not acquired[0]:
            connection.close()
            pytest.exit(_MESSAGE.strip(), returncode=3)
        try:
            yield
        finally:
            connection.execute("SELECT pg_advisory_unlock(%s)", (LAB_SUITE_LOCK_KEY,))
