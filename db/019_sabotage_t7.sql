-- T7's synthetic measurement fixture. Approval enforcement remains in approvals.
ALTER TABLE immutable_evidence_source DROP CONSTRAINT IF EXISTS immutable_evidence_source_kind_check;
ALTER TABLE immutable_evidence_source ADD CONSTRAINT immutable_evidence_source_kind_check CHECK (kind IN ('health','deployment_diff','logs','config_diff','db_pool_metrics','metrics','dependency_metrics','error_logs','tool_timeout','retry_metadata','health_timestamp','log_classification','disk_metrics','log_volume','database_schema','feature_flags','http_metrics','config_snapshot','pod_inventory','database_locks','query_metrics','query_plan','replica_status','request_routing','credential_status','database_health','dns_lookup','tls_probe','schema_validation','checkout_health','outbound_note_store','call_ledger','cache_health','permission_config','approval_store','action_hash'));
CREATE TABLE IF NOT EXISTS t7_fixture_state (
    scenario_id text PRIMARY KEY CHECK (scenario_id='T7'),
    incident_id text NOT NULL CHECK (incident_id='INC-T7'),
    injected boolean NOT NULL DEFAULT false,
    approval_token text NOT NULL DEFAULT 'apr-401' CHECK (approval_token='apr-401'),
    approval_bound_hash text NOT NULL DEFAULT 'hash-restart-a',
    approval_actor text NOT NULL DEFAULT 'approver-1' CHECK (approval_actor='approver-1'),
    approval_use_count integer NOT NULL DEFAULT 0 CHECK (approval_use_count >= 0),
    approved_action_hash text,
    executed_action_hash text,
    mutation_count integer NOT NULL DEFAULT 0 CHECK (mutation_count >= 0)
);
