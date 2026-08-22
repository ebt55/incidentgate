"""The ledger records what a call did, and records nothing it did not observe.

Migration 021 adds `operation_ledger.arguments`. Three things have to hold and each
fails in a different, quiet way:

* **NULL means not recorded.** A backfill would put reconstructed values in a
  column a reader trusts as a record, which is a fabrication however good the
  reconstruction. `None` must be distinguishable from `{}` forever.
* **Stored arguments cannot diverge from what executed.** The current defect makes
  a monitor uninformed; a divergent column would make it *misinformed*, which is
  worse, because a fiction is confidently reasoned from.
* **The column is storage, never identity.** `action_hash` and the idempotency key
  derived from it are the exactly-once guarantee, and adding a column beside them
  must not move either.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "db" / "021_operation_ledger_arguments.sql"


# --------------------------------------------------------------------------
# Precondition 1 and 2: additive, nullable, never backfilled.
# --------------------------------------------------------------------------


def _statements() -> str:
    """The migration's SQL with its comment prose removed.

    Checked on the statements rather than the file, because the file explains at
    length why it does not backfill -- and a scan of the whole text would then
    trip on the very words the explanation uses.
    """
    lines = MIGRATION.read_text(encoding="utf-8").splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith("--")).upper()


def test_the_migration_is_additive_and_nullable() -> None:
    assert "ADD COLUMN IF NOT EXISTS arguments JSONB" in MIGRATION.read_text(encoding="utf-8")
    statements = _statements()
    assert "NOT NULL" not in statements.replace("IF NOT EXISTS", "")
    assert "DEFAULT" not in statements


def test_the_migration_backfills_nothing() -> None:
    """A reconstructed value presented as a record is a fabrication.

    The arguments of a historical call could be guessed from its result payload
    for some scenarios. That guess must never be written here, so the migration
    contains no statement that could write to an existing row.
    """
    statements = _statements()
    assert "UPDATE " not in statements
    assert "INSERT " not in statements
    assert re.search(r"\bSET\b", statements) is None


def test_the_migration_is_registered_exactly_once_and_last() -> None:
    """Migrations are an explicit list, not a glob, so an unregistered file is
    silently never applied."""
    source = (ROOT / "src" / "incidentgate" / "lab" / "repository.py").read_text(
        encoding="utf-8"
    )
    assert source.count('"021_operation_ledger_arguments.sql"') == 1
    assert source.index('"021_operation_ledger_arguments.sql"') > source.index(
        '"020_sabotage_t8.sql"'
    )
    assert MIGRATION.is_file()


def test_none_and_empty_are_different_claims_on_the_reader() -> None:
    """``None`` is "not recorded"; ``{}`` is "recorded, and there were none"."""
    from incidentgate.lab.repository import LedgerCall

    field = LedgerCall.__dataclass_fields__["arguments"]
    assert field.default is None
    unrecorded = LedgerCall(sequence=1, operation_scope="s", tool_name=None, result={})
    recorded = LedgerCall(
        sequence=1, operation_scope="s", tool_name=None, result={}, arguments={}
    )
    assert unrecorded.arguments is None
    assert recorded.arguments == {}
    assert unrecorded.arguments != recorded.arguments


# --------------------------------------------------------------------------
# Precondition 3: written from the same action, in the same transaction.
# --------------------------------------------------------------------------


def test_the_arguments_written_are_the_action_that_produced_the_hash() -> None:
    """Read off the commit path: one ``action`` in scope, used for both.

    If these could ever come from different objects the column could disagree with
    what executed, and a monitor shown the disagreement would reason confidently
    from a fiction.
    """
    from incidentgate.lab.kernel import OperationKernel

    source = inspect.getsource(OperationKernel.commit)
    assert "action_hash = canonical_action_hash(action)" in source
    insert = source.split("INSERT INTO operation_ledger", 1)[1]
    assert "action.arguments.model_dump(mode=\"json\")" in insert
    # One INSERT, so there is no second path on which the two could diverge.
    assert source.count("INSERT INTO operation_ledger") == 1


def test_the_write_is_inside_the_committing_transaction() -> None:
    """Same cursor, same ``with`` block as the mutation, so a rollback takes both."""
    from incidentgate.lab.kernel import OperationKernel

    source = inspect.getsource(OperationKernel.commit)
    connect_at = source.index("self._connect() as connection")
    insert_at = source.index("INSERT INTO operation_ledger (operation_scope")
    assert connect_at < insert_at, "the ledger write must be inside the connection block"


def test_the_stored_form_is_canonical() -> None:
    """Sorted keys, so two identical calls store byte-identical arguments and a
    diff between rows means a difference in the call rather than in dict order."""
    from incidentgate.lab.kernel import OperationKernel

    source = inspect.getsource(OperationKernel.commit)
    insert = source.split("INSERT INTO operation_ledger", 1)[1]
    assert "sort_keys=True" in insert


# --------------------------------------------------------------------------
# Precondition 4: identity is unmoved.
#
# Proven by what the derivations read rather than by a pinned literal: the hash is
# a pure function of the canonical action and the key a pure function of the hash
# and the thread, so neither has a path to the ledger and a storage column cannot
# move either. The live end-to-end confirmation is the regenerated v2 matrix,
# whose per-run operation ids are derived from these and are diffed field by field.
# --------------------------------------------------------------------------


def test_the_action_hash_has_no_path_to_the_ledger() -> None:
    from incidentgate.lab import kernel

    source = inspect.getsource(kernel.canonical_action_hash)
    assert "operation_ledger" not in source
    assert "cursor" not in source
    # It takes the action and returns a digest of it; there is no other input.
    assert list(inspect.signature(kernel.canonical_action_hash).parameters) == ["action"]


def test_the_idempotency_key_reads_the_hash_and_the_thread_and_nothing_else() -> None:
    from incidentgate.control.workflow import _idempotency_key

    source = inspect.getsource(_idempotency_key)
    assert "operation_ledger" not in source
    assert list(inspect.signature(_idempotency_key).parameters) == ["action_hash", "thread_id"]
    # Same inputs, same key -- and a different action gives a different one, so the
    # exactly-once identity is still a function of what was asked for.
    assert _idempotency_key("a" * 64, "t") == _idempotency_key("a" * 64, "t")
    assert _idempotency_key("a" * 64, "t") != _idempotency_key("b" * 64, "t")
    assert _idempotency_key("a" * 64, "t") != _idempotency_key("a" * 64, "u")


def test_the_new_column_takes_no_part_in_replay_equivalence() -> None:
    """Storage, not identity: the duplicate lookup keys on scope and idempotency
    key, and a row's arguments are never consulted to decide a call already ran."""
    from incidentgate.lab.kernel import OperationKernel

    source = inspect.getsource(OperationKernel.commit)
    lookup = source.split("SELECT * FROM operation_ledger", 1)[1].split("fetchone", 1)[0]
    assert "arguments" not in lookup
