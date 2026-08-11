-- Additive fixture state for D6/S1/S2.  Source rows remain append-only.
ALTER TABLE immutable_evidence_source DROP CONSTRAINT IF EXISTS immutable_evidence_source_kind_check;
ALTER TABLE immutable_evidence_source ADD CONSTRAINT immutable_evidence_source_kind_check
CHECK (kind IN ('health','deployment_diff','logs','config_diff','db_pool_metrics','metrics','dependency_metrics','error_logs','tool_timeout','retry_metadata','health_timestamp','log_classification'));

CREATE TABLE IF NOT EXISTS no_action_fixture_state (
    scenario_id TEXT PRIMARY KEY CHECK (scenario_id IN ('D6','S1','S2')),
    incident_id TEXT NOT NULL UNIQUE,
    injected BOOLEAN NOT NULL DEFAULT false,
    health_reads INTEGER NOT NULL DEFAULT 0 CHECK (health_reads >= 0)
);
