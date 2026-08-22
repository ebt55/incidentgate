-- Record what a committed operation actually did, not only that it happened.
--
-- operation_ledger has stored `action_hash` since 001: a digest that proves two
-- calls were the same call, and tells a reader nothing about what either one did.
-- For a project whose product is auditability that is a gap on its own merits,
-- and it is also what blocks a monitor from being shown the sequence it is asked
-- to judge -- `MonitorInputV3.committed_calls` carries tool names without values
-- because there are no values here to carry.
--
-- ADDITIVE AND NULLABLE, AND NOT BACKFILLED.
--
-- Every row written before this migration keeps NULL, and NULL means *not
-- recorded*. It does not mean "no arguments" -- an argument-free call records
-- `{}` -- and it must never be filled in later from any source. The arguments of
-- a historical call could be guessed from its result payload for some scenarios,
-- and a guess presented as a record is a fabrication. This project already draws
-- that line elsewhere: `ProviderCaptureProvenance.request_envelope` is optional
-- precisely so `None` can mean "not recorded" and never "no difference".
--
-- So there is deliberately no UPDATE here, no DEFAULT that would silently claim
-- a value for old rows, and no NOT NULL. A reader can always tell whether a row
-- predates the column.
--
-- WHY JSONB AND NOT TEXT.
--
-- The same shape `result` already uses, so the two are queryable the same way,
-- and so a reader comparing what a call was asked to do against what it left
-- behind does not have to parse one of them differently from the other.
--
-- WHAT THIS DOES NOT TOUCH.
--
-- Not `action_hash`, and not the idempotency key derived from it. The exactly-once
-- guarantee is `uuid5(thread_id, action_hash)` and this column is storage, never
-- identity: nothing reads it to decide whether a call already happened. A test
-- pins both digests from bytes so that stays true.
ALTER TABLE operation_ledger
    ADD COLUMN IF NOT EXISTS arguments JSONB;

COMMENT ON COLUMN operation_ledger.arguments IS
    'The canonical action arguments this call committed with, written in the same '
    'transaction as the mutation from the same action that produced action_hash. '
    'NULL means not recorded (the row predates migration 021), never "no arguments" '
    '-- an argument-free call records an empty object.';
