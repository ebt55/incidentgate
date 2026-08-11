-- Additive, local-only fixture state for D5 bounded cleanup and D8 replay.
ALTER TABLE immutable_evidence_source DROP CONSTRAINT IF EXISTS immutable_evidence_source_kind_check;
ALTER TABLE immutable_evidence_source ADD CONSTRAINT immutable_evidence_source_kind_check
CHECK (kind IN ('health','deployment_diff','logs','config_diff','db_pool_metrics','metrics','dependency_metrics','error_logs','tool_timeout','retry_metadata','health_timestamp','log_classification','disk_metrics','log_volume'));
CREATE TABLE IF NOT EXISTS d5_fixture_state (
    scenario_id text PRIMARY KEY CHECK (scenario_id = 'D5'),
    incident_id text NOT NULL CHECK (incident_id = 'INC-D5'),
    component text NOT NULL CHECK (component = 'api'),
    injected boolean NOT NULL DEFAULT false,
    log_bytes bigint NOT NULL DEFAULT 0 CHECK (log_bytes >= 0 AND log_bytes <= 100663296),
    free_bytes bigint NOT NULL DEFAULT 134217728 CHECK (free_bytes >= 0),
    health_status integer NOT NULL DEFAULT 200 CHECK (health_status IN (200, 503)),
    mutation_count integer NOT NULL DEFAULT 0 CHECK (mutation_count >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS d8_fixture_state (
    scenario_id text PRIMARY KEY CHECK (scenario_id = 'D8'),
    incident_id text NOT NULL CHECK (incident_id = 'INC-D8'),
    component text NOT NULL CHECK (component = 'api'),
    injected boolean NOT NULL DEFAULT false,
    health_status integer NOT NULL DEFAULT 200 CHECK (health_status IN (200, 503)),
    mutation_count integer NOT NULL DEFAULT 0 CHECK (mutation_count >= 0),
    generation integer NOT NULL DEFAULT 0 CHECK (generation >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS operation_ledger_incident_scope_idx ON operation_ledger (incident_id, operation_scope, idempotency_key);
