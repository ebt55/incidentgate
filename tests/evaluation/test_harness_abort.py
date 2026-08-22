"""A harness abort must be legible as a harness abort, including the quiet ones.

The failure this pins is one the previous name-matching classifier actually had.
``psycopg.errors.ConnectionTimeout`` is a subclass of ``psycopg.OperationalError``
whose class *name* does not contain the string ``OperationalError``, so a check
written as ``"OperationalError" in type(error).__name__`` fell through to the
generic branch. The run was still refused either way -- that part was never at
risk -- but the operator lost the pointer to the known intermittent connect
failure on this host and could reasonably have read it as a new fault.

So these tests are about the *classification*, not about whether the run stops.
The negative controls matter as much as the positives: a classifier that returned
``True`` unconditionally would pass every connectivity assertion here and would be
worthless, because its whole job is to not label a model-shaped failure as an
environment one.
"""

from __future__ import annotations

import errno

import psycopg
import pytest

from incidentgate.evaluation.harness_abort import (
    HarnessAborted,
    abort_message,
    is_connectivity_failure,
)

#: Subclasses of ``OperationalError`` whose names do not contain the base name.
#: Every one of these was misclassified by the string check; they are named
#: individually rather than derived so that a psycopg release that reparents one
#: of them is a test failure and not a silent behaviour change.
_CONNECTIVITY_SUBCLASSES = (
    psycopg.errors.ConnectionTimeout,
    psycopg.errors.ConnectionFailure,
    psycopg.errors.ConnectionException,
    psycopg.errors.CannotConnectNow,
    psycopg.errors.AdminShutdown,
)


@pytest.mark.parametrize("error_type", _CONNECTIVITY_SUBCLASSES)
def test_operational_error_subclasses_are_connectivity_failures(
    error_type: type[Exception],
) -> None:
    """The family is caught by base class, not by how the subclass is spelled."""
    assert is_connectivity_failure(error_type("could not connect"))


def test_the_name_check_would_have_missed_connection_timeout() -> None:
    """The specific defect, stated as an executable fact rather than a comment.

    If a future psycopg names this class differently the assertion below stops
    holding and this test starts failing, which is the correct outcome: it would
    mean the regression this file exists to prevent is no longer reachable and
    the reasoning should be re-read rather than the test relaxed.
    """
    assert issubclass(psycopg.errors.ConnectionTimeout, psycopg.OperationalError)
    assert "OperationalError" not in psycopg.errors.ConnectionTimeout.__name__


def test_the_base_class_itself_is_still_matched() -> None:
    assert is_connectivity_failure(psycopg.OperationalError("connect failed"))


def test_a_raw_socket_bind_failure_is_matched_by_errno_not_by_message() -> None:
    """The one case the dropped message-substring arm could have reached.

    Keyed on the number, so it holds under a non-English locale or a reworded
    driver message -- neither of which the old ``"Address already in use" in
    str(error)`` check would have survived.
    """
    assert is_connectivity_failure(OSError(errno.EADDRINUSE, "some other wording entirely"))
    assert not is_connectivity_failure(OSError(errno.ENOENT, "Address already in use"))


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("the monitor returned an unparseable body"),
        ValueError("threshold artifact was not found"),
        psycopg.errors.UndefinedTable("relation does not exist"),
        psycopg.ProgrammingError("syntax error"),
        HarnessAborted("a capture was missing"),
    ],
)
def test_non_connectivity_failures_are_not_reclassified(error: Exception) -> None:
    """The negative control, without which every assertion above is vacuous.

    ``UndefinedTable`` and ``ProgrammingError`` are the interesting members here:
    both are psycopg errors and both reach the same ``except`` clause, so a
    classifier keyed on "did this come from psycopg" would call them connectivity
    failures and send the operator to restart a database that is running fine.
    """
    assert not is_connectivity_failure(error)


def test_connectivity_message_names_the_known_failure_and_says_nothing_was_recorded() -> None:
    message = abort_message(psycopg.errors.ConnectionTimeout("timeout expired"))
    assert "ConnectionTimeout" in message
    assert "timeout expired" in message
    assert "not a model observation" in message
    assert "Nothing was recorded." in message
    assert "docs/verification.md" in message


def test_generic_message_still_refuses_to_call_it_a_model_observation() -> None:
    """The advice differs; the refusal does not.

    A failure the classifier cannot place is the case where a wrong reading is
    most likely, so the "this is not a model observation" line has to be on both
    branches rather than only on the one that was anticipated.
    """
    message = abort_message(RuntimeError("something else entirely"))
    assert "RuntimeError" in message
    assert "not a model observation" in message
    assert "Nothing was recorded." in message
    assert "docker compose" not in message


def test_harness_aborted_is_an_exception_a_runner_can_raise() -> None:
    assert issubclass(HarnessAborted, RuntimeError)
