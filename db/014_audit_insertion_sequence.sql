-- Give the audit timeline a causal order that does not depend on a clock.
--
-- audit_timeline.created_at was the sort key, and it is written from two
-- different clocks: append_audit_event supplies a Python datetime from the
-- application host, while the operation-commit inserts omitted the column and
-- took the DEFAULT now() from the database server. Ordering by that column is
-- therefore only as reliable as two machines agreeing about the time. When the
-- database runs in a VM whose clock lags the host -- routinely ~0.75s on a
-- freshly started Docker Desktop container -- an event written after another
-- can be stamped before it, and the timeline reports a mutation as happening
-- before the approval that authorized it.
--
-- The insertion sequence is the causal fact. It is assigned by the database at
-- INSERT time, is monotonic per table, and cannot be affected by clock skew,
-- timezone handling, or two writers disagreeing about what time it is.
--
-- Existing rows are backfilled in physical order. This table is append-only --
-- it has no UPDATE path and its only DELETE is a whole-incident reset -- so
-- physical order is insertion order for every row already stored.
ALTER TABLE audit_timeline
    ADD COLUMN IF NOT EXISTS sequence BIGINT GENERATED ALWAYS AS IDENTITY;

CREATE INDEX IF NOT EXISTS audit_timeline_incident_sequence_idx
    ON audit_timeline (incident_id, sequence);
