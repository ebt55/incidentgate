-- Additive Checkpoint-A state.  D1 remains in target_state unchanged.
ALTER TABLE immutable_evidence_source
    DROP CONSTRAINT IF EXISTS immutable_evidence_source_kind_check;
ALTER TABLE immutable_evidence_source
    ADD CONSTRAINT immutable_evidence_source_kind_check
    CHECK (kind IN ('health', 'deployment_diff', 'logs', 'config_diff', 'db_pool_metrics'));

CREATE TABLE IF NOT EXISTS scenario_target_state (
    scenario_id TEXT NOT NULL CHECK (scenario_id IN ('D2', 'D3')),
    component TEXT NOT NULL CHECK (component = 'api'),
    health_status INTEGER NOT NULL CHECK (health_status BETWEEN 100 AND 599),
    config_present BOOLEAN,
    config_reference TEXT,
    pool_used INTEGER,
    pool_capacity INTEGER,
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    mutation_count INTEGER NOT NULL DEFAULT 0 CHECK (mutation_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scenario_id, component),
    CHECK (
        (scenario_id = 'D2' AND config_present IS NOT NULL AND pool_used IS NULL AND pool_capacity IS NULL
         AND ((config_present AND config_reference = 'config://approved/REQUIRED_API_URL')
              OR (NOT config_present AND config_reference IS NULL)))
        OR
        (scenario_id = 'D3' AND config_present IS NULL AND config_reference IS NULL
         AND pool_used IS NOT NULL AND pool_capacity IS NOT NULL AND pool_used >= 0
         AND pool_capacity > 0 AND pool_used <= pool_capacity)
    )
);
