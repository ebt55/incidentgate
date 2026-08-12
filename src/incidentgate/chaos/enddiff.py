"""Normalized durable end-state capture plus the chaos comparison contract.

Thread ids, correlation ids, uuids and wall-clock timestamps differ on every
run, so a killed run can never be compared byte for byte with its golden run.
:data:`COMPARISON_SPEC` is the whole comparison: every field that is captured
is listed there with how it is normalized, the rule applied to it, and the
verdict a violation produces.  :func:`compare` executes that table and nothing
else, so the spec and the check cannot drift apart.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from incidentgate.reasons import unknown_reasons

DUPLICATE_MUTATION = "duplicate-mutation"
LOST_INCIDENT = "lost-incident"
STATE_DIVERGENCE = "state-divergence"

RULE_EQUAL = "equal"
RULE_AT_LEAST = "at-least-golden"

#: Payload keys whose value is a wall-clock instant recorded inside evidence.
TIMESTAMP_PAYLOAD_KEYS = frozenset({"checked_at"})

_FIXTURE_QUERIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "D1": ("SELECT * FROM target_state WHERE component='api'", ()),
    "D2": ("SELECT * FROM scenario_target_state WHERE scenario_id='D2' AND component='api'", ()),
    "D3": ("SELECT * FROM scenario_target_state WHERE scenario_id='D3' AND component='api'", ()),
    "D5": ("SELECT * FROM d5_fixture_state WHERE scenario_id='D5'", ()),
    "D8": ("SELECT * FROM d8_fixture_state WHERE scenario_id='D8'", ()),
    "D4": ("SELECT * FROM collection_fault_state WHERE scenario_id='D4'", ()),
    "D7": ("SELECT * FROM collection_fault_state WHERE scenario_id='D7'", ()),
    "D6": ("SELECT * FROM no_action_fixture_state WHERE scenario_id='D6'", ()),
    "S1": ("SELECT * FROM no_action_fixture_state WHERE scenario_id='S1'", ()),
    "S2": ("SELECT * FROM no_action_fixture_state WHERE scenario_id='S2'", ()),
}


@dataclass(frozen=True)
class FieldSpec:
    """One captured end-state field and the rule the differ applies to it."""

    name: str
    describes: str
    normalization: str
    rule: str
    failure: str
    observation: str | None = None


COMPARISON_SPEC: tuple[FieldSpec, ...] = (
    FieldSpec(
        "terminal_final_state",
        "workflow terminal state the thread reached",
        "fixed vocabulary value; no normalization needed",
        RULE_EQUAL,
        LOST_INCIDENT,
    ),
    FieldSpec(
        "terminal_reasons",
        "ordered reason codes attached to the terminal result",
        "fixed vocabulary values; no normalization needed",
        RULE_EQUAL,
        LOST_INCIDENT,
    ),
    FieldSpec(
        "ledger_rows_by_scope",
        "operation_ledger row count per operation_scope",
        "grouped counts only; ids and timestamps discarded",
        RULE_EQUAL,
        DUPLICATE_MUTATION,
    ),
    FieldSpec(
        "ledger_max_rows_per_key",
        "largest row count for any single (scope, idempotency_key)",
        "grouped count only",
        RULE_EQUAL,
        DUPLICATE_MUTATION,
    ),
    FieldSpec(
        "fixture_mutation_count",
        "mutation_count column of the scenario fixture table",
        "integer read straight from the fixture row",
        RULE_EQUAL,
        DUPLICATE_MUTATION,
    ),
    FieldSpec(
        "fixture_generation",
        "generation column where the fixture counts restarts",
        "integer read straight from the fixture row",
        RULE_EQUAL,
        DUPLICATE_MUTATION,
    ),
    FieldSpec(
        "approvals_consumed",
        "approval rows whose consumed_at is set",
        "count only",
        RULE_EQUAL,
        DUPLICATE_MUTATION,
    ),
    FieldSpec(
        "fixture_state",
        "every column of the scenario fixture row",
        "datetimes become <timestamp>, uuids become <uuid>",
        RULE_EQUAL,
        STATE_DIVERGENCE,
    ),
    FieldSpec(
        "ledger_envelope",
        "distinct (scope, actor, permission, approver) of ledger rows",
        "sorted distinct tuples; ids and timestamps discarded",
        RULE_EQUAL,
        STATE_DIVERGENCE,
    ),
    FieldSpec(
        "ledger_results",
        "sorted ledger result payloads",
        "sorted json with datetimes and uuids replaced",
        RULE_EQUAL,
        STATE_DIVERGENCE,
    ),
    FieldSpec(
        "audit_sequence",
        "audit_timeline events in order",
        "(event_type, actor, reason, action_hash present); "
        "created_at, audit_id, thread_id and the hash value discarded",
        RULE_EQUAL,
        STATE_DIVERGENCE,
    ),
    FieldSpec(
        "evidence_read_kinds",
        "distinct (tool_name, payload) evidence reads",
        "sorted distinct; evidence ids, thread ids and observed_at discarded",
        RULE_EQUAL,
        STATE_DIVERGENCE,
    ),
    FieldSpec(
        "evidence_read_total",
        "total evidence_records rows for the incident",
        "count only",
        RULE_AT_LEAST,
        STATE_DIVERGENCE,
        observation="replayed_reads",
    ),
    FieldSpec(
        "approvals_total",
        "approval rows issued for the incident",
        "count only",
        RULE_AT_LEAST,
        STATE_DIVERGENCE,
        observation="orphaned_approvals",
    ),
    FieldSpec(
        "ticket_notes",
        "ticket note bodies written for the incident",
        "sorted (body, author) pairs",
        RULE_EQUAL,
        STATE_DIVERGENCE,
    ),
    FieldSpec(
        "collection_attempts",
        "ordered bounded collection attempts",
        "(attempt_number, transition, reason); ids and clocks discarded",
        RULE_EQUAL,
        STATE_DIVERGENCE,
    ),
    FieldSpec(
        "collection_runs_total",
        "collection_runs plus d6_collection_runs rows",
        "count only",
        RULE_EQUAL,
        STATE_DIVERGENCE,
    ),
)

#: A replayed read is safe, a *different* read is not: ``evidence_read_total``
#: may exceed golden only while ``evidence_read_kinds`` stays identical.  The
#: same reasoning gives ``approvals_total`` its allowance: a token re-issued
#: after a crash is unconsumed and shares the golden action hash, so spending
#: it would land on the same deterministic idempotency key.
AT_LEAST_RATIONALE = (
    "at-least-golden fields may only grow through crash replay; the paired "
    "equality field pins what the replay is allowed to contain"
)


def _normalize(value: Any) -> Any:
    if isinstance(value, datetime):
        return "<timestamp>"
    if isinstance(value, UUID):
        return "<uuid>"
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {
            str(key): "<timestamp>" if key in TIMESTAMP_PAYLOAD_KEYS else _normalize(item)
            for key, item in sorted(value.items())
        }
    if isinstance(value, list | tuple):
        return [_normalize(item) for item in value]
    return value


def _dumps(value: Any) -> str:
    return json.dumps(_normalize(value), sort_keys=True, default=str)


def capture(
    dsn: str, scenario: str, *, final_state: str | None, reasons: tuple[str, ...]
) -> dict[str, Any]:
    """Read the whole normalized durable end state for one scenario incident."""
    incident = f"INC-{scenario}"
    # The terminal_reasons field spec claims "fixed vocabulary values; no
    # normalization needed". Nothing used to check that, so an unregistered
    # reason compared clean against an identical unregistered reason and the
    # differ reported a match between two strings nobody had ever declared.
    # Fail here instead: a cell that emits a reason outside the frozen
    # vocabulary is a harness error, not a passing comparison.
    strangers = unknown_reasons(reasons)
    if strangers:
        raise ValueError(
            f"{scenario} terminated with reasons outside the frozen vocabulary: "
            f"{', '.join(strangers)}"
        )
    state: dict[str, Any] = {
        "terminal_final_state": final_state,
        "terminal_reasons": list(reasons),
    }
    with psycopg.connect(dsn, row_factory=dict_row) as connection, connection.cursor() as cursor:
        state.update(_capture_ledger(cursor, incident))
        state.update(_capture_approvals(cursor, incident))
        state.update(_capture_audit(cursor, incident))
        state.update(_capture_evidence(cursor, incident))
        state.update(_capture_tickets(cursor, incident))
        state.update(_capture_collection(cursor, incident))
        state.update(_capture_fixture(cursor, scenario))
    return state


def _capture_ledger(cursor: Any, incident: str) -> dict[str, Any]:
    cursor.execute(
        "SELECT operation_scope, idempotency_key, actor, permission, approver, result "
        "FROM operation_ledger WHERE incident_id = %s",
        (incident,),
    )
    rows = cursor.fetchall()
    by_scope: dict[str, int] = {}
    by_key: dict[tuple[str, str], int] = {}
    envelope: set[tuple[str, str, str, str]] = set()
    results: list[str] = []
    for row in rows:
        scope = str(row["operation_scope"])
        key = (scope, str(row["idempotency_key"]))
        by_scope[scope] = by_scope.get(scope, 0) + 1
        by_key[key] = by_key.get(key, 0) + 1
        envelope.add((scope, str(row["actor"]), str(row["permission"]), str(row["approver"])))
        results.append(_dumps(row["result"]))
    return {
        "ledger_rows_by_scope": sorted(by_scope.items()),
        "ledger_max_rows_per_key": max(by_key.values(), default=0),
        "ledger_envelope": sorted(list(item) for item in envelope),
        "ledger_results": sorted(results),
    }


def _capture_approvals(cursor: Any, incident: str) -> dict[str, Any]:
    cursor.execute(
        "SELECT count(*) AS total, count(consumed_at) AS consumed "
        "FROM approvals WHERE incident_id = %s",
        (incident,),
    )
    row = cursor.fetchone() or {"total": 0, "consumed": 0}
    return {"approvals_total": int(row["total"]), "approvals_consumed": int(row["consumed"])}


def _capture_audit(cursor: Any, incident: str) -> dict[str, Any]:
    cursor.execute(
        "SELECT event_type, actor, payload FROM audit_timeline WHERE incident_id = %s "
        "ORDER BY created_at, event_type, coalesce(payload->>'reason', ''), audit_id",
        (incident,),
    )
    events = []
    for row in cursor.fetchall():
        payload = dict(row["payload"] or {})
        events.append(
            [
                str(row["event_type"]),
                str(row["actor"]),
                payload.get("reason"),
                payload.get("action_hash") is not None,
            ]
        )
    return {"audit_sequence": events}


def _capture_evidence(cursor: Any, incident: str) -> dict[str, Any]:
    cursor.execute(
        "SELECT tool_name, payload FROM evidence_records WHERE incident_id = %s",
        (incident,),
    )
    rows = cursor.fetchall()
    kinds = {(str(row["tool_name"]), _dumps(row["payload"])) for row in rows}
    return {
        "evidence_read_kinds": sorted(list(item) for item in kinds),
        "evidence_read_total": len(rows),
    }


def _capture_tickets(cursor: Any, incident: str) -> dict[str, Any]:
    cursor.execute(
        "SELECT body, author FROM ticket_notes WHERE ticket_id IN "
        "(SELECT ticket_id FROM tickets WHERE incident_id = %s) ORDER BY body, author",
        (incident,),
    )
    return {"ticket_notes": [[str(row["body"]), str(row["author"])] for row in cursor.fetchall()]}


def _capture_collection(cursor: Any, incident: str) -> dict[str, Any]:
    cursor.execute(
        "SELECT attempt_number, transition, reason FROM collection_attempts "
        "WHERE incident_id = %s ORDER BY attempt_number, transition, reason",
        (incident,),
    )
    attempts = [
        [int(row["attempt_number"]), str(row["transition"]), str(row["reason"])]
        for row in cursor.fetchall()
    ]
    cursor.execute(
        "SELECT (SELECT count(*) FROM collection_runs WHERE incident_id = %s) "
        "+ (SELECT count(*) FROM d6_collection_runs WHERE incident_id = %s) AS total",
        (incident, incident),
    )
    row = cursor.fetchone() or {"total": 0}
    return {"collection_attempts": attempts, "collection_runs_total": int(row["total"])}


def _capture_fixture(cursor: Any, scenario: str) -> dict[str, Any]:
    query, parameters = _FIXTURE_QUERIES[scenario]
    cursor.execute(query, parameters)
    row = cursor.fetchone() or {}
    fixture = {str(key): _normalize(value) for key, value in sorted(dict(row).items())}
    return {
        "fixture_state": fixture,
        "fixture_mutation_count": int(row.get("mutation_count") or 0),
        "fixture_generation": int(row.get("generation") or 0),
    }


@dataclass(frozen=True)
class Difference:
    """One violated field of the comparison spec."""

    field: str
    verdict: str
    golden: str
    actual: str


@dataclass(frozen=True)
class DiffResult:
    """The verdict for one matrix cell plus everything that produced it."""

    differences: tuple[Difference, ...]
    observations: dict[str, int]

    @property
    def clean(self) -> bool:
        return not self.differences

    @property
    def verdicts(self) -> tuple[str, ...]:
        seen: list[str] = []
        for difference in self.differences:
            if difference.verdict not in seen:
                seen.append(difference.verdict)
        return tuple(seen)


def _as_int(value: Any) -> int:
    return int(value) if isinstance(value, int | float) else 0


def compare(golden: dict[str, Any], actual: dict[str, Any]) -> DiffResult:
    """Apply :data:`COMPARISON_SPEC` field by field; nothing else is checked."""
    differences: list[Difference] = []
    observations: dict[str, int] = {}
    for spec in COMPARISON_SPEC:
        expected, found = golden.get(spec.name), actual.get(spec.name)
        if spec.rule == RULE_AT_LEAST:
            excess = _as_int(found) - _as_int(expected)
            if spec.observation is not None:
                observations[spec.observation] = excess
            if excess < 0:
                differences.append(
                    Difference(spec.name, LOST_INCIDENT, _dumps(expected), _dumps(found))
                )
            continue
        if expected != found:
            differences.append(Difference(spec.name, spec.failure, _dumps(expected), _dumps(found)))
    return DiffResult(differences=tuple(differences), observations=observations)


def spec_rows() -> list[dict[str, str]]:
    """Render the comparison contract for the published artifacts."""
    return [
        {
            "field": spec.name,
            "describes": spec.describes,
            "normalization": spec.normalization,
            "rule": spec.rule,
            "failure": spec.failure,
        }
        for spec in COMPARISON_SPEC
    ]
