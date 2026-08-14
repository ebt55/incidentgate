"""The two safety properties the kernel makes structural, checked structurally.

Single-transaction atomicity and the injected-clock discipline are load-bearing
safety properties of this lab, and both of them are the kind of property that a
test exercising behaviour can only sample. A mutation that opened its own
connection would still pass every behavioural test on a machine where nothing
crashed; a mutation that read ``datetime.now`` would still pass every test whose
injected clock happens to agree with the wall clock. So they are asserted over
the source itself.

The rule the kernel enforces by construction is that a scenario mutation
receives a *cursor* and a *value*: it cannot commit because it has no
connection, and it cannot introduce a second timebase because it is handed an
instant rather than a clock. These tests check that the construction is still
the construction -- that nobody widened :class:`LockedTransaction`, and that no
mutation reached around it.
"""

from __future__ import annotations

import ast
import inspect
from dataclasses import fields
from datetime import datetime
from pathlib import Path

import psycopg
import pytest

from incidentgate.lab import kernel, repository
from incidentgate.lab.kernel import LockedTransaction, OperationSpec

#: A mutation is always a function with this name. The convention is what lets
#: the source check below find every one of them, including the ones that are
#: closures returned from a factory.
MUTATION_NAME = "mutation"

#: Names that would put a second timebase behind a durable timestamp.
WALL_CLOCK_NAMES = frozenset({"now", "utcnow", "today", "time", "monotonic"})

#: Tables only the kernel may write. A mutation that named one of these would be
#: taking over a step of the protocol rather than contributing to it.
KERNEL_OWNED_TABLES = ("operation_ledger", "approvals", "audit_timeline")


def _module_source(module: object) -> ast.Module:
    path = Path(inspect.getsourcefile(module) or "")
    return ast.parse(path.read_text(encoding="utf-8"))


def _attribute_calls(tree: ast.AST, attribute: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == attribute
    ]


def _functions(tree: ast.AST) -> dict[str, ast.FunctionDef]:
    return {
        node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    }


def _called_names(node: ast.AST) -> set[str]:
    return {
        call.func.id
        for call in ast.walk(node)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    }


def _mutations_and_their_helpers(tree: ast.AST) -> list[ast.FunctionDef]:
    """Every mutation body, plus every module function a mutation can reach.

    Following the calls is what keeps this check honest: a mutation that moved
    its fixture read into a helper would otherwise leave the helper unchecked,
    and the helper is where the reaching-around would live.
    """
    declared = _functions(tree)
    reachable = [node for name, node in declared.items() if name == MUTATION_NAME]
    seen = {MUTATION_NAME}
    frontier = list(reachable)
    while frontier:
        current = frontier.pop()
        for name in _called_names(current) - seen:
            helper = declared.get(name)
            if helper is None:
                continue
            seen.add(name)
            reachable.append(helper)
            frontier.append(helper)
    return reachable


#: The three writes that make an operation an operation. Each of them existed in
#: six copies, one per scenario family, before the kernel did.
LEDGER_WRITES = (
    "INSERT INTO operation_ledger",
    "UPDATE approvals SET consumed_at",
    "SELECT * FROM operation_ledger WHERE operation_scope",
)


@pytest.mark.parametrize("statement", LEDGER_WRITES)
def test_the_operation_ledger_has_exactly_one_writer(statement: str) -> None:
    """There is no second implementation, and no room to add one quietly.

    The extraction is only worth what this assertion is worth. Six independent
    transactions is how the drift happened: each one was correct when it was
    written and none of them moved when the others did. A flag-gated second
    implementation running beside the kernel would rebuild exactly that, which
    is why there was never a parallel window -- the characterization suite was
    the safety net instead.

    Scanning the source is the check because the alternative -- asserting that
    every capability behaves the same -- is what the six copies already passed.
    """
    package = Path(inspect.getsourcefile(kernel) or "").parents[1]
    writers = sorted(
        module.relative_to(package).as_posix()
        for module in package.rglob("*.py")
        if statement in module.read_text(encoding="utf-8")
    )
    assert writers == ["lab/kernel.py"], f"{statement!r} is written in more than one place"


def test_the_kernel_reads_the_clock_exactly_once() -> None:
    """One reading per transaction, and the whole transaction wears it.

    Every durable timestamp a committed operation writes -- the ledger row, the
    fixture stamp, the audit fact, the consumed marker -- has to be the same
    instant the approval was validated against. Two readings would mean the
    token was checked against one timebase and recorded against another.
    """
    calls = _attribute_calls(_module_source(kernel), "_clock")
    assert len(calls) == 1, "the kernel must read its injected clock exactly once per transaction"


def test_the_kernel_names_no_wall_clock() -> None:
    """The injected clock is the only clock reachable from the kernel."""
    tree = _module_source(kernel)
    named = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not (named & WALL_CLOCK_NAMES), (
        "the kernel reached a wall clock; every instant must arrive through the injected seam"
    )


def test_the_kernel_opens_exactly_one_connection() -> None:
    """Steps 1 through 8 are one transaction, so there is one connection.

    A second ``_connect()`` anywhere in this module would mean some part of the
    protocol could commit while another part rolled back, which is the property
    the whole ledger rests on.
    """
    calls = _attribute_calls(_module_source(kernel), "_connect")
    assert len(calls) == 1, "the operation protocol must run inside exactly one transaction"


def test_a_locked_transaction_hands_a_cursor_and_never_a_connection() -> None:
    """What a mutation can reach is the whole of what it can do.

    A connection would let a mutation commit or roll back on its own; a callable
    clock would let it pick a different instant. It gets neither -- and this is
    the assertion that keeps it that way when somebody adds a field.
    """
    annotations = {field.name: field.type for field in fields(LockedTransaction)}
    assert set(annotations) == {
        "cursor",
        "now",
        "context",
        "action",
        "action_hash",
        "fixture",
    }
    spelled = " ".join(str(value) for value in annotations.values())
    assert "Connection" not in spelled
    assert "Callable" not in spelled
    # And the two that carry the discipline are what they claim to be: a cursor,
    # and an instant rather than a way of asking for one.
    hints = inspect.get_annotations(LockedTransaction, eval_str=True)
    assert hints["cursor"] is psycopg.Cursor[dict[str, object]]
    assert hints["now"] is datetime


@pytest.mark.parametrize(
    "spec",
    sorted(repository._SPECS.values(), key=lambda registered: registered.operation_scope),
    ids=lambda spec: spec.operation_scope,
)
def test_every_registered_mutation_is_findable_by_the_source_check(spec: OperationSpec) -> None:
    """The convention the source check depends on, asserted against the objects.

    A mutation declared under some other name would be invisible to
    :func:`test_no_mutation_reaches_past_its_locked_transaction`, so the naming
    is not cosmetic: it is what makes that check exhaustive rather than
    approximate.
    """
    assert spec.mutation.__name__ == MUTATION_NAME  # type: ignore[attr-defined]


def test_no_mutation_reaches_past_its_locked_transaction() -> None:
    """No scenario mutation reads a clock, opens a transaction, or writes the ledger.

    This is the half of the discipline that types cannot state. A mutation is
    handed a cursor, so nothing stops it *typing* an insert into
    ``operation_ledger``; what stops it is that the one place mutations are
    written is checked for it here.
    """
    tree = _module_source(repository)
    found = _mutations_and_their_helpers(tree)
    assert found, "no scenario mutation was found; the source check would be vacuous"
    for mutation in found:
        called = {
            call.func.attr
            for call in ast.walk(mutation)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
        }
        # ``transaction.now`` is read, never called -- that is the whole point of
        # handing an instant rather than a clock -- so the check is on calls.
        assert not (called & WALL_CLOCK_NAMES), (
            f"{mutation.name} called a wall clock: {sorted(called & WALL_CLOCK_NAMES)}"
        )
        assert "commit" not in called, f"{mutation.name} tried to end its own transaction"
        reached = {
            node.attr for node in ast.walk(mutation) if isinstance(node, ast.Attribute)
        }
        assert not (reached & {"_clock", "_connect"}), (
            f"{mutation.name} reached a repository seam it is not handed"
        )
        literals = [
            node.value
            for node in ast.walk(mutation)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        for table in KERNEL_OWNED_TABLES:
            assert not any(table in literal for literal in literals), (
                f"{mutation.name} named {table}, which only the kernel may write"
            )
