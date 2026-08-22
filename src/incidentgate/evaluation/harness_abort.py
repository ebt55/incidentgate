"""Telling a harness failure apart from a model observation, by type rather than by name.

WHY THIS IS ITS OWN MODULE.

A run that dies because this machine could not reach Postgres has produced no
observation about any model, and must never be recorded as one. On an arm where a
failure to assess and a BLOCK look identical at the side-effect level -- which is
every observe-only arm -- that distinction is the difference between a number and
a lie. Two runners now need it (T1's observe-only lane and T4's three-call
sequence), and a three-call sequence gives it three chances to fire mid-capture.

WHY BY TYPE, AND WHAT THAT FIXES.

The first version of this check tested ``"OperationalError" in type(error).__name__``.
That is a real defect and it was caught by the check firing on a case it did not
name: ``psycopg.errors.ConnectionTimeout`` *is* a subclass of
``psycopg.OperationalError``, but its class name does not contain the string, so
it fell through to the generic branch. The run was still refused -- exit 3, "this
is not a model observation", nothing written -- but the operator lost the pointer
to the known intermittent failure and could reasonably have read it as a new
fault.

``isinstance`` against the base class catches the whole family, including every
subclass psycopg adds later.

WHAT WAS DROPPED, AND WHY THAT LOSES NOTHING.

The previous check also had a second arm: ``"Address already in use" in str(error)``.
That is the message every logged occurrence of this host's intermittent failure
carried, but matching it is classifying by prose -- it breaks under a locale, a
psycopg rewording, or a driver that says ``EADDRINUSE`` instead. All four logged
occurrences were ``psycopg.OperationalError``, which the type check already
catches, so the string arm was only ever reaching a hypothetical socket error
raised outside psycopg. That case is covered here by type as well: ``OSError``
carrying ``errno.EADDRINUSE``. Nothing in this module is matched on a message.
"""

from __future__ import annotations

import errno
from typing import Final

#: What an operator is told when the database could not be reached. Names the
#: known intermittent failure so a reader does not think they broke something,
#: and says plainly that nothing was recorded.
_CONNECTIVITY_ADVICE: Final = (
    "This is a database connectivity failure on this machine, not a model observation. "
    "Nothing was recorded. An intermittent connect failure on this host is documented in "
    "docs/verification.md with its mechanism still unidentified; check that Postgres is up "
    "(`docker compose up -d postgres`) and re-run."
)

#: What an operator is told for anything else that killed the run.
_GENERIC_ADVICE: Final = (
    "This is a failure of the harness or the environment, not a model observation. "
    "Nothing was recorded."
)


class HarnessAborted(RuntimeError):
    """The run failed for a reason that says nothing about any model."""


def is_connectivity_failure(error: BaseException) -> bool:
    """Whether this is the database failing to answer, tested by type.

    ``psycopg.OperationalError`` is the base of the connection-failure family --
    ``ConnectionTimeout``, ``ConnectionFailure`` and the rest are subclasses -- so
    one ``isinstance`` covers the family and every future member of it.

    The ``OSError`` arm is for a socket failure raised before psycopg wraps it. It
    is keyed on ``errno``, a number, rather than on the message that number gets
    rendered into.
    """
    if isinstance(error, OSError) and error.errno == errno.EADDRINUSE:
        return True
    try:
        import psycopg
    except ImportError:  # pragma: no cover -- psycopg is a hard dependency of the lab
        return False
    return isinstance(error, psycopg.OperationalError)


def abort_message(error: BaseException) -> str:
    """The full operator-facing refusal for a run that must publish nothing."""
    advice = _CONNECTIVITY_ADVICE if is_connectivity_failure(error) else _GENERIC_ADVICE
    return f"HARNESS ABORTED: {type(error).__name__}: {error}\n{advice}\n"
