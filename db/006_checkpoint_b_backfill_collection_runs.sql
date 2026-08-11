-- Upgrade pre-005 durable attempts without resetting their per-thread deadline.
-- A run has one immutable owner; ambiguous historical rows must halt migration.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM collection_attempts
        GROUP BY incident_id, thread_id, correlation_id
        HAVING COUNT(DISTINCT ROW(scenario_id, actor, permission)) <> 1
            OR BOOL_OR(scenario_id IS NULL OR actor IS NULL OR permission IS NULL)
    ) THEN
        RAISE EXCEPTION 'cannot backfill collection_runs: conflicting or incomplete historical run owner';
    END IF;
END;
$$;

INSERT INTO collection_runs (
    incident_id, thread_id, correlation_id, scenario_id, actor, permission, started_at
)
SELECT
    incident_id,
    thread_id,
    correlation_id,
    MIN(scenario_id) AS scenario_id,
    MIN(actor) AS actor,
    MIN(permission) AS permission,
    MIN(started_at) AS started_at
FROM collection_attempts
GROUP BY incident_id, thread_id, correlation_id
ON CONFLICT (incident_id, thread_id, correlation_id) DO NOTHING;
