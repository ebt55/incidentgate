-- Per-workflow D6 freshness cursor.  It is deliberately independent of the
-- scenario fixture so concurrent incident threads cannot consume one another.
CREATE TABLE IF NOT EXISTS d6_collection_runs (
    incident_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    permission TEXT NOT NULL CHECK (permission = 'observability:read'),
    started_at TIMESTAMPTZ NOT NULL,
    deadline_at TIMESTAMPTZ NOT NULL,
    next_read INTEGER NOT NULL DEFAULT 0 CHECK (next_read BETWEEN 0 AND 2),
    PRIMARY KEY (incident_id, thread_id, correlation_id)
);
