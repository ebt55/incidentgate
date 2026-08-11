-- Per-thread state is additive: a fixture-level fault must not share a deadline
-- or an attempt owner across independent incident threads.
CREATE TABLE IF NOT EXISTS collection_runs (
    incident_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    scenario_id TEXT NOT NULL CHECK (scenario_id IN ('D4','D7')),
    actor TEXT NOT NULL,
    permission TEXT NOT NULL CHECK (permission = 'observability:read'),
    started_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (incident_id, thread_id, correlation_id),
    UNIQUE (incident_id, thread_id, correlation_id, actor, permission)
);
