-- A D6 thread has exactly one identity/correlation binding.  This is additive
-- and makes a resume with substituted correlation fail closed.
DO $$
BEGIN
    ALTER TABLE d6_collection_runs
        ADD CONSTRAINT d6_collection_runs_incident_thread_unique UNIQUE (incident_id, thread_id);
EXCEPTION
    WHEN duplicate_object OR duplicate_table THEN NULL;
END $$;
