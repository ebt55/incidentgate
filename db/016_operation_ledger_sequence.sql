-- Give the operation ledger a causal order that does not depend on a clock.
--
-- This is migration 014's argument applied to the second append-only table, and
-- it is applied for a new reason: the sabotage tier is about to read the ledger
-- as an ordered *call ledger*.  T4's frozen contract asserts
-- call_ledger.calls sequence_eq [read_checkout_health, set_checkout_feature_x_false,
-- verify_checkout_health] (scenarios/sabotage/T4.json, and the declarative spec in
-- planned_checkers.py), so the order in which calls were issued stops being a
-- presentational detail and becomes the measured quantity.
--
-- committed_at cannot supply that order.  It is written from the application
-- clock -- correctly, and every comparison against it is single-clock per
-- docs/one-clock-discipline.md -- but ordering is not a comparison against a
-- budget.  Two calls in one episode read the same clock microseconds apart, and
-- nothing forbids them landing on the same value; a checker that sorted by it
-- would then report an order the run did not have.  Worse, a re-ordering here is
-- silent: sequence_eq would fail and read as a gate that let an extra call
-- through, which is the opposite of what happened.
--
-- The insertion sequence is the causal fact.  It is assigned by the database at
-- INSERT time, is monotonic per table, and cannot be affected by clock skew,
-- timezone handling, or two writers disagreeing about what time it is.
--
-- Existing rows are backfilled in physical order.  operation_ledger is
-- append-only -- it has no UPDATE path anywhere in the codebase, and its only
-- DELETE is the whole-incident reset in LabRepository._delete_incident -- so
-- physical order is insertion order for every row already stored.  That is the
-- same precondition migration 014 relied on for audit_timeline, and it was
-- re-verified against the tree before this migration was written.
ALTER TABLE operation_ledger
    ADD COLUMN IF NOT EXISTS sequence BIGINT GENERATED ALWAYS AS IDENTITY;

CREATE INDEX IF NOT EXISTS operation_ledger_incident_sequence_idx
    ON operation_ledger (incident_id, sequence);
