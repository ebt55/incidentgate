"""Isolated upgrade proof for the additive R05--R08 migration."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from triage_agent_lab.lab.repository import D1Repository

ROOT = Path(__file__).parents[2]


def test_012_upgrades_001_through_011_once_and_retains_prior_durable_rows() -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("migration proof requires DATABASE_URL")
    schema = f"r012_{uuid4().hex}"
    with psycopg.connect(dsn, autocommit=True) as connection, connection.cursor() as cursor:
        cursor.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    scoped_dsn = f"{dsn}?options=-csearch_path%3D{schema}"
    try:
        with psycopg.connect(scoped_dsn) as connection, connection.cursor() as cursor:
            cursor.execute("CREATE TABLE schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
            for number in range(1, 12):
                path = next((ROOT / "db").glob(f"{number:03d}_*.sql"))
                cursor.execute(path.read_text(encoding="utf-8"))
                cursor.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (path.name,))
            cursor.execute("INSERT INTO tickets (ticket_id, incident_id, title) VALUES ('r012-retained', 'INC-D1', 'retained')")
        repository = D1Repository(scoped_dsn)
        repository.migrate()
        repository.migrate()
        with psycopg.connect(scoped_dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT name FROM schema_migrations ORDER BY name")
            assert [row[0] for row in cursor.fetchall()][-1] == "013_reliability_r09_r12.sql"
            cursor.execute("SELECT count(*) FROM schema_migrations")
            assert cursor.fetchone()[0] == 13
            cursor.execute("SELECT title FROM tickets WHERE ticket_id='r012-retained'")
            assert cursor.fetchone()[0] == "retained"
            cursor.execute("SELECT to_regclass(current_schema() || '.r05_collection_runs'), to_regclass(current_schema() || '.r08_fixture_state')")
            assert cursor.fetchone() == ("r05_collection_runs", "r08_fixture_state")
            cursor.execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='immutable_evidence_source'::regclass AND conname='immutable_evidence_source_kind_check'")
            definition = cursor.fetchone()[0]
            assert all(kind in definition for kind in ("database_locks", "query_plan", "credential_status"))
    finally:
        with psycopg.connect(dsn, autocommit=True) as connection, connection.cursor() as cursor:
            cursor.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))
