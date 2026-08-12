"""Upgrade proof and fixture-integrity coverage for the additive R09--R12 migration."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from incidentgate.contracts import ToolCallContext
from incidentgate.lab.repository import LabRepository

ROOT = Path(__file__).parents[2]


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("R09-R12 integration requires DATABASE_URL")
    repository = LabRepository(dsn)
    repository.migrate()
    return repository


def _read_context(scenario: str, thread: str) -> ToolCallContext:
    return ToolCallContext(
        incident_id=f"INC-{scenario}",
        thread_id=thread,
        correlation_id=f"corr-{thread}",
        actor="operator-1",
        permission="observability:read",
    )


def test_013_upgrades_001_through_012_once_and_retains_prior_durable_rows() -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("migration proof requires DATABASE_URL")
    schema = f"r013_{uuid4().hex}"
    with psycopg.connect(dsn, autocommit=True) as connection, connection.cursor() as cursor:
        cursor.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    scoped_dsn = f"{dsn}?options=-csearch_path%3D{schema}"
    try:
        with psycopg.connect(scoped_dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                "CREATE TABLE schema_migrations (name text PRIMARY KEY, "
                "applied_at timestamptz NOT NULL DEFAULT now())"
            )
            for number in range(1, 13):
                path = next((ROOT / "db").glob(f"{number:03d}_*.sql"))
                cursor.execute(path.read_text(encoding="utf-8"))
                cursor.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (path.name,))
            cursor.execute(
                "INSERT INTO tickets (ticket_id, incident_id, title) "
                "VALUES ('r013-retained', 'INC-D1', 'retained')"
            )
        repository = LabRepository(scoped_dsn)
        repository.migrate()
        repository.migrate()
        with psycopg.connect(scoped_dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SELECT name FROM schema_migrations ORDER BY name")
            assert [row[0] for row in cursor.fetchall()][-1] == "014_audit_insertion_sequence.sql"
            cursor.execute("SELECT count(*) FROM schema_migrations")
            assert cursor.fetchone()[0] == 14
            cursor.execute("SELECT title FROM tickets WHERE ticket_id='r013-retained'")
            assert cursor.fetchone()[0] == "retained"
            cursor.execute(
                "SELECT to_regclass(current_schema() || '.r09_fixture_state'), "
                "to_regclass(current_schema() || '.r12_fixture_state'), "
                "to_regclass(current_schema() || '.r10_r11_collection_runs'), "
                "to_regclass(current_schema() || '.r10_r11_collection_evidence')"
            )
            assert cursor.fetchone() == (
                "r09_fixture_state",
                "r12_fixture_state",
                "r10_r11_collection_runs",
                "r10_r11_collection_evidence",
            )
            cursor.execute(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid='immutable_evidence_source'::regclass "
                "AND conname='immutable_evidence_source_kind_check'"
            )
            definition = cursor.fetchone()[0]
            assert all(k in definition for k in ("dns_lookup", "tls_probe", "schema_validation"))
            assert all(
                k in definition for k in ("database_locks", "query_plan", "credential_status")
            )
    finally:
        with psycopg.connect(dsn, autocommit=True) as connection, connection.cursor() as cursor:
            cursor.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_r09_baseline_is_the_contract_rate_and_the_limit_is_not_representable(
    repository: LabRepository,
) -> None:
    """R09's contract baseline is 90 under a 100 limit, so 100 must not be storable."""
    repository.reset_checkpoint("R09")
    try:
        repository.initialize_checkpoint_if_absent("R09")
        assert repository.checkpoint_state("R09")["request_rate"] == 90
        repository.inject_checkpoint("R09")
        assert repository.checkpoint_state("R09")["request_rate"] == 160
        with (
            psycopg.connect(repository.dsn) as connection,
            connection.cursor() as cursor,
            pytest.raises(psycopg.errors.CheckViolation),
        ):
            cursor.execute("UPDATE r09_fixture_state SET request_rate=100 WHERE scenario_id='R09'")
    finally:
        repository.reset_checkpoint("R09")


def test_r11_pin_state_is_observed_so_a_violated_pin_is_expressible(
    repository: LabRepository,
) -> None:
    """pin_state_unchanged must be read from durable state, never asserted."""
    repository.reset_checkpoint("R11")
    repository.inject_checkpoint("R11")
    thread = f"r11-{uuid4().hex[:12]}"
    context = _read_context("R11", thread)
    try:
        honest = repository.evidence(context, "tls_probe")
        assert honest.payload["pin_state_unchanged"] is True
        assert repository.checkpoint_state("R11")["pinned_sha256"] == "sha256:aa11"
        with psycopg.connect(repository.dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE r11_fixture_state SET pinned_sha256='sha256:bb22' WHERE scenario_id='R11'"
            )
            connection.commit()
        violated = _read_context("R11", f"r11-{uuid4().hex[:12]}")
        probe = repository.evidence(violated, "tls_probe")
        assert probe.payload["pin_state_unchanged"] is False
    finally:
        repository.reset_checkpoint("R11")


def test_a_violated_pin_fails_the_no_action_evidence_gate() -> None:
    """A replaced pin must be rejected, not silently accepted as an unchanged pin."""
    from incidentgate.scenario_registry import validate_no_action_evidence

    class _Record:
        def __init__(self, tool_name: str, payload: dict[str, object]) -> None:
            self.tool_name, self.payload = tool_name, payload
            self.incident_id, self.thread_id = "INC-R11", "t"
            self.correlation_id, self.actor = "c", "operator-1"
            self.permission = "observability:read"

    def records(pin_unchanged: bool) -> tuple[object, ...]:
        return (
            _Record(
                "observability.tls_probe",
                {
                    "partner": "synthetic.partner.local",
                    "presented_fingerprint": "sha256:bb22",
                    "validation_error": "CERTIFICATE_VERIFY_FAILED",
                    "pin_state_unchanged": pin_unchanged,
                },
            ),
            _Record(
                "observability.dependency_metrics",
                {
                    "dependency": "synthetic.partner.local",
                    "status": "failed",
                },
            ),
        )

    assert validate_no_action_evidence("R11", records(True))
    assert not validate_no_action_evidence("R11", records(False))


@pytest.mark.parametrize("scenario", ("R10", "R11"))
def test_r10_r11_collection_rows_do_not_survive_a_checkpoint_reset(
    repository: LabRepository, scenario: str
) -> None:
    """reset_checkpoint must clear the durable collection tables, not leak them."""
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    thread = f"{scenario.lower()}-{uuid4().hex[:12]}"
    context = _read_context(scenario, thread)
    opening = "dns_lookup" if scenario == "R10" else "tls_probe"
    try:
        repository.evidence(context, opening)
        repository.evidence(context, "dependency_metrics")
        assert len(repository.r10_r11_resume_evidence(context)) == 2
        with psycopg.connect(repository.dsn) as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM r10_r11_collection_evidence WHERE incident_id=%s",
                (f"INC-{scenario}",),
            )
            assert cursor.fetchone()[0] == 2
        repository.reset_checkpoint(scenario)
        with psycopg.connect(repository.dsn) as connection, connection.cursor() as cursor:
            for table in ("r10_r11_collection_evidence", "r10_r11_collection_runs"):
                cursor.execute(
                    f"SELECT count(*) FROM {table} WHERE incident_id=%s", (f"INC-{scenario}",)
                )
                assert cursor.fetchone()[0] == 0
        assert repository.r10_r11_resume_evidence(context) == ()
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize("scenario", ("R10", "R11"))
def test_r10_r11_collection_is_ordered_owner_bound_and_bounded(
    repository: LabRepository, scenario: str
) -> None:
    """Two reads only, in contract order, advanced by the owning context alone."""
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    thread = f"{scenario.lower()}-{uuid4().hex[:12]}"
    context = _read_context(scenario, thread)
    opening = "dns_lookup" if scenario == "R10" else "tls_probe"
    try:
        with pytest.raises(ValueError, match="order mismatch"):
            repository.evidence(context, "dependency_metrics")
        first = repository.evidence(context, opening)
        with pytest.raises(ValueError, match="order mismatch"):
            repository.evidence(context, opening)
        second = repository.evidence(context, "dependency_metrics")
        assert (first.tool_name, second.tool_name) == (
            f"observability.{opening}",
            "observability.dependency_metrics",
        )
        with pytest.raises(ValueError, match="order mismatch"):
            repository.evidence(context, "dependency_metrics")
        foreign = context.model_copy(update={"actor": "intruder-1"})
        with pytest.raises(ValueError, match="owner mismatch"):
            repository.r10_r11_resume_evidence(foreign)
        snapshot = repository.r10_r11_evaluation_snapshot(context)
        assert snapshot.next_read == 2 and snapshot.mutation_count == 0
        assert snapshot.approval_count == 0 and snapshot.operation_ledger_count == 0
        assert repository.operation_count(f"INC-{scenario}") == 0
    finally:
        repository.reset_checkpoint(scenario)


@pytest.mark.parametrize("scenario", ("R10", "R11"))
def test_r10_r11_resume_returns_committed_reads_without_reobserving(
    repository: LabRepository, scenario: str
) -> None:
    """A process loss after read one must resume, not re-probe the partner."""
    repository.reset_checkpoint(scenario)
    repository.inject_checkpoint(scenario)
    thread = f"{scenario.lower()}-{uuid4().hex[:12]}"
    context = _read_context(scenario, thread)
    opening = "dns_lookup" if scenario == "R10" else "tls_probe"
    try:
        first = repository.evidence(context, opening)
        resumed = repository.r10_r11_resume_evidence(context)
        assert [record.evidence_id for record in resumed] == [first.evidence_id]
        assert resumed[0].payload == first.payload
        second = repository.evidence(context, "dependency_metrics")
        complete = repository.r10_r11_resume_evidence(context)
        assert [record.evidence_id for record in complete] == [
            first.evidence_id,
            second.evidence_id,
        ]
    finally:
        repository.reset_checkpoint(scenario)
