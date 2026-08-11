CREATE TABLE IF NOT EXISTS collection_fault_state (
 scenario_id TEXT PRIMARY KEY CHECK (scenario_id IN ('D4','D7')), incident_id TEXT NOT NULL UNIQUE,
 injected BOOLEAN NOT NULL DEFAULT false, failure_mode TEXT NOT NULL,
 retry_budget INTEGER NOT NULL CHECK (retry_budget >= 0), time_budget_seconds INTEGER NOT NULL CHECK (time_budget_seconds > 0),
 collection_started_at TIMESTAMPTZ
);
ALTER TABLE collection_attempts ADD COLUMN IF NOT EXISTS permission TEXT NOT NULL DEFAULT 'observability:read';
ALTER TABLE collection_attempts ADD COLUMN IF NOT EXISTS scenario_id TEXT;
ALTER TABLE collection_attempts DROP CONSTRAINT IF EXISTS collection_attempts_scenario_id_check;
ALTER TABLE collection_attempts ADD CONSTRAINT collection_attempts_scenario_id_check CHECK (scenario_id IN ('D4','D7'));
CREATE OR REPLACE FUNCTION reject_collection_attempt_updates() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'collection attempts are append-only'; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS collection_attempts_no_update ON collection_attempts;
CREATE TRIGGER collection_attempts_no_update BEFORE UPDATE ON collection_attempts FOR EACH ROW EXECUTE FUNCTION reject_collection_attempt_updates();
