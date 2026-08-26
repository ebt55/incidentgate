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

CONFIRMED ON 2026-08-26, RATHER THAN LEFT AS THE BEST AVAILABLE STORY

Eight full-suite runs on an idle machine, interleaved solo/pair/solo/pair, every
arm through the escape hatch below so the guard is not the difference between
them. Both solo arms: **0 failures**, 2468 passed. All six concurrent arms fail
heavily -- 60, 54, 56, 43, 49, 56 -- and **no two failing sets agree**: the two
halves of one pair share 13 of 60 and 54, the next pair 17 of 56 and 43. Of 105
classified failures, 72 are fixture/approval-shaped and the rest are downstream
consequences of the same corruption.

Two things that experiment did *not* establish, kept here because the guard
should not be read as explaining more than it does. It did not reproduce the
connect-shaped failures of the 2026-08-18 flake entry -- zero appeared, and that
entry's own precondition (a just-finished matrix run, and three *consecutive*
runs) was absent, so this is not a fair test of it either way. And the first four
arms were captured with ``--tb=no``, whose suppressed messages made the initial
"no connect failures" reading a scan over empty strings; the shape numbers above
come from a re-run that actually recorded reasons.

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

#: The one way to run concurrent suites on purpose, which exists so that the
#: paragraph above can be *tested* rather than believed.
#:
#: A guard that cannot be turned off cannot be shown to be doing anything. The
#: claim in this docstring -- that concurrency produces fixture and approval
#: failures in a set that varies between runs -- is only a claim until two
#: unguarded runs are put side by side, and that requires getting past this
#: fixture on purpose.
#:
#: Two properties keep this from being a hole:
#:
#: * It is not a boolean. Only the exact token below enables it, so a stray
#:   ``=1`` or ``=true`` inherited from some other tool cannot silently disable
#:   exclusivity. Anything else is treated as absent.
#: * It does not stop locking; it takes the **shared** lock instead of the
#:   exclusive one. Experiment runs therefore race *each other*, which is the
#:   point, while an ordinary run still cannot acquire the exclusive lock and
#:   still refuses with the message below. Someone who starts a normal gate in
#:   the middle of the experiment is protected exactly as before, rather than
#:   being quietly enrolled in it.
CONCURRENCY_EXPERIMENT_VARIABLE = "LAB_ALLOW_CONCURRENT_SUITES"
CONCURRENCY_EXPERIMENT_TOKEN = "yes-i-am-reproducing-the-race"

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

    experiment = (
        os.environ.get(CONCURRENCY_EXPERIMENT_VARIABLE) == CONCURRENCY_EXPERIMENT_TOKEN
    )
    take, release = (
        ("pg_try_advisory_lock_shared", "pg_advisory_unlock_shared")
        if experiment
        else ("pg_try_advisory_lock", "pg_advisory_unlock")
    )
    if experiment:
        sys.stderr.write(
            "\nlab-database exclusivity guard IN EXPERIMENT MODE: holding the shared lock, "
            "so this run may race another experiment run. Results are not a valid gate.\n"
        )

    with connection:
        acquired = connection.execute(
            f"SELECT {take}(%s)", (LAB_SUITE_LOCK_KEY,)
        ).fetchone()
        if not acquired or not acquired[0]:
            connection.close()
            pytest.exit(_MESSAGE.strip(), returncode=3)
        try:
            yield
        finally:
            connection.execute(f"SELECT {release}(%s)", (LAB_SUITE_LOCK_KEY,))
