-- Additive, non-mutating collection state for checkpoint B.
ALTER TABLE immutable_evidence_source DROP CONSTRAINT IF EXISTS immutable_evidence_source_kind_check;
ALTER TABLE immutable_evidence_source ADD CONSTRAINT immutable_evidence_source_kind_check
CHECK (kind IN ('health','deployment_diff','logs','config_diff','db_pool_metrics','dependency_metrics','error_logs','tool_timeout','retry_metadata'));

CREATE TABLE IF NOT EXISTS collection_attempts (
    attempt_id UUID PRIMARY KEY,
    incident_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    scenario_id TEXT NOT NULL CHECK (scenario_id IN ('D4','D7')),
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    transition TEXT NOT NULL CHECK (transition IN ('collection_attempt','collection_timeout','collection_retry','collection_deferred')),
    reason TEXT NOT NULL CHECK (reason IN ('upstream_timeout','observability_tool_timeout','retry_budget_exhausted','time_budget_exhausted')),
    started_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    UNIQUE (incident_id, thread_id, correlation_id, actor, attempt_number)
);
CREATE INDEX IF NOT EXISTS collection_attempts_context_idx ON collection_attempts (incident_id, thread_id, correlation_id, actor, attempt_number);
