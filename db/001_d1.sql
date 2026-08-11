CREATE TABLE IF NOT EXISTS target_state (
    component TEXT PRIMARY KEY CHECK (component = 'api'),
    revision TEXT NOT NULL,
    health_status INTEGER NOT NULL CHECK (health_status BETWEEN 100 AND 599),
    mutation_count INTEGER NOT NULL DEFAULT 0 CHECK (mutation_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS immutable_evidence_source (
    source_id UUID PRIMARY KEY,
    incident_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('health', 'deployment_diff', 'logs')),
    payload JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence_records (
    evidence_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    actor TEXT NOT NULL,
    permission TEXT NOT NULL,
    source_id UUID NOT NULL REFERENCES immutable_evidence_source(source_id),
    observed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > observed_at),
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    ticket_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    title TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ticket_notes (
    note_id UUID PRIMARY KEY,
    ticket_id TEXT NOT NULL REFERENCES tickets(ticket_id),
    body TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    idempotency_key UUID UNIQUE
);

CREATE TABLE IF NOT EXISTS approvals (
    token_id UUID PRIMARY KEY,
    one_time_use_id UUID UNIQUE NOT NULL,
    incident_id TEXT NOT NULL,
    action_hash TEXT NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
    actor TEXT NOT NULL,
    approver TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > requested_at),
    approved_at TIMESTAMPTZ NOT NULL CHECK (approved_at >= requested_at AND approved_at < expires_at),
    consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS operation_ledger (
    operation_scope TEXT NOT NULL,
    idempotency_key UUID NOT NULL,
    action_hash TEXT NOT NULL CHECK (action_hash ~ '^[a-f0-9]{64}$'),
    approval_token_id UUID NOT NULL REFERENCES approvals(token_id),
    one_time_use_id UUID NOT NULL,
    incident_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    permission TEXT NOT NULL,
    approver TEXT NOT NULL,
    result JSONB NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (operation_scope, idempotency_key),
    UNIQUE (operation_scope, approval_token_id),
    UNIQUE (operation_scope, one_time_use_id)
);

CREATE TABLE IF NOT EXISTS audit_timeline (
    audit_id UUID PRIMARY KEY,
    incident_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION reject_immutable_evidence_update() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'immutable evidence source cannot be updated';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS immutable_evidence_source_no_update ON immutable_evidence_source;
CREATE TRIGGER immutable_evidence_source_no_update
BEFORE UPDATE ON immutable_evidence_source
FOR EACH ROW EXECUTE FUNCTION reject_immutable_evidence_update();
