"""Upgrade proof for a journal that stopped at Checkpoint-B migration 010."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from incidentgate.lab.repository import LabRepository

ROOT = Path(__file__).parents[2]


def test_011_upgrades_a_001_through_010_journal_once_without_data_loss() -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("migration proof requires DATABASE_URL")
    schema = f"r011_{uuid4().hex}"
    quoted = sql.Identifier(schema)
    with psycopg.connect(dsn, autocommit=True) as connection, connection.cursor() as cursor:
        cursor.execute(sql.SQL("CREATE SCHEMA {} ").format(quoted))
    scoped_dsn = f"{dsn}?options=-csearch_path%3D{schema}"
    try:
        with psycopg.connect(scoped_dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                "CREATE TABLE schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT "
                "NULL DEFAULT now())"
            )
            for number in range(1, 11):
                path = next((ROOT / "db").glob(f"{number:03d}_*.sql"))
                cursor.execute(path.read_text(encoding="utf-8"))
                cursor.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (path.name,))
            cursor.execute(
                "INSERT INTO d5_fixture_state (scenario_id, incident_id, component) VALUES ('D5', "
                "'INC-D5', 'api')"
            )
            cursor.execute(
                "INSERT INTO tickets (ticket_id, incident_id, title) VALUES ('upgrade-ticket', "
                "'INC-D5', 'retained')"
            )
            source_id, token_id, one_time_id, operation_key = uuid4(), uuid4(), uuid4(), uuid4()
            cursor.execute(
                "INSERT INTO immutable_evidence_source (source_id, incident_id, kind, payload) "
                "VALUES (%s, 'INC-D5', 'health', '{}'::jsonb)",
                (source_id,),
            )
            cursor.execute(
                "INSERT INTO evidence_records (evidence_id, incident_id, thread_id, "
                "correlation_id, tool_name, actor, permission, source_id, observed_at, expires_at, "
                "payload) VALUES ('upgrade-evidence', 'INC-D5', 'upgrade-thread', "
                "'upgrade-correlation', 'observability.health', 'operator-1', "
                "'observability:read', %s, now(), now() + interval '1 minute', '{}'::jsonb)",
                (source_id,),
            )
            cursor.execute(
                "INSERT INTO approvals (token_id, one_time_use_id, incident_id, action_hash, "
                "actor, approver, requested_at, expires_at, approved_at) VALUES (%s, %s, 'INC-D5', "
                "%s, 'operator-1', 'approver-1', now(), now() + interval '1 minute', now())",
                (token_id, one_time_id, "a" * 64),
            )
            cursor.execute(
                "INSERT INTO operation_ledger (operation_scope, idempotency_key, action_hash, "
                "approval_token_id, one_time_use_id, incident_id, thread_id, correlation_id, "
                "actor, permission, approver, result, committed_at) VALUES ('upgrade-scope', %s, "
                "%s, %s, %s, 'INC-D5', 'upgrade-thread', 'upgrade-correlation', 'operator-1', "
                "'operations:write', 'approver-1', '{\"retained\":true}'::jsonb, now())",
                (operation_key, "a" * 64, token_id, one_time_id),
            )
        repository = LabRepository(scoped_dsn)
        repository.migrate()
        with psycopg.connect(scoped_dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT name FROM schema_migrations ORDER BY name")
            names = [row[0] for row in cursor.fetchall()]
            expected_names = [
                next((ROOT / "db").glob(f"{number:03d}_*.sql")).name for number in range(1, 15)
            ]
            assert names == expected_names
            cursor.execute("SELECT title FROM tickets WHERE ticket_id='upgrade-ticket'")
            assert cursor.fetchone()[0] == "retained"
            cursor.execute(
                "SELECT count(*) FROM evidence_records WHERE evidence_id='upgrade-evidence'"
            )
            assert cursor.fetchone()[0] == 1
            cursor.execute(
                "SELECT result FROM operation_ledger WHERE operation_scope='upgrade-scope'"
            )
            assert cursor.fetchone()[0] == {"retained": True}
            cursor.execute("SELECT to_regclass(current_schema() || '.r04_fixture_state')")
            assert cursor.fetchone()[0] == "r04_fixture_state"
            cursor.execute(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE "
                "conrelid='immutable_evidence_source'::regclass AND "
                "conname='immutable_evidence_source_kind_check'"
            )
            assert "database_schema" in cursor.fetchone()[0]
        repository.migrate()
        with psycopg.connect(scoped_dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM schema_migrations")
            assert cursor.fetchone()[0] == 14
            cursor.execute(
                "SELECT count(*) FROM schema_migrations WHERE name = '011_reliability_r01_r04.sql'"
            )
            assert cursor.fetchone()[0] == 1
            cursor.execute(
                "SELECT count(*) FROM schema_migrations WHERE name = '012_reliability_r05_r08.sql'"
            )
            assert cursor.fetchone()[0] == 1
            cursor.execute(
                "SELECT count(*) FROM schema_migrations WHERE name = '013_reliability_r09_r12.sql'"
            )
            assert cursor.fetchone()[0] == 1
            cursor.execute(
                "SELECT count(*) FROM operation_ledger WHERE operation_scope='upgrade-scope'"
            )
            assert cursor.fetchone()[0] == 1
    finally:
        with psycopg.connect(dsn, autocommit=True) as connection, connection.cursor() as cursor:
            cursor.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(quoted))
