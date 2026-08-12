# One clock discipline

This system runs on a Windows host and stores its durable state in a Postgres
container. Those are two machines with two clocks, and they disagree. This
document states which clock owns what, records the audit that classified every
timestamp comparison in the codebase, and explains why the rule is what it is.

## The rule

1. **Durable record timestamps** are written by the **application clock**, always
   supplied explicitly as a parameter. No durable timestamp that later takes part
   in a comparison may come from a column `DEFAULT now()`, because that value is
   produced by the database server's clock.
2. **Every comparison** has both operands from the **same clock**. A
   host-generated value is never compared against a server-generated one.
3. The application clock is the one **injected** into `IncidentRuntime` and
   `LabRepository`. Calling `datetime.now(UTC)` inline is a defect even on the
   host, because it introduces a second timebase behind the same decision: the
   graph validates an approval against the injected clock and the mutator would
   then re-validate the same approval against a different one.

`LabRepository._utc_now` is the single default and the only wall-clock read in
that module. Everything else arrives through `self._clock()`.

## Why: measured skew on this machine

Measured 2026-08-12, Docker Desktop on Windows 11, same machine, same day:

| Moment | Container minus host |
| --- | --- |
| At `pg_isready`, freshly started engine | **+1.494 s** (container ahead) |
| Oscillating over the next 5 minutes (14 samples) | **−0.476 s to +1.484 s** |
| ~12 minutes after engine start | +0.15 s to +0.26 s |
| Earlier investigation, same machine | **−0.75 s** (container behind) |

Round-trip cost of the measurement was ~80 ms, so the true values are slightly
smaller, but the sign and magnitude are real. The skew is bidirectional and
decays as the Docker Desktop VM clock converges after engine start.

CI cannot catch this class of defect: GitHub Actions runs Postgres as a service
container sharing the runner's clock, so the skew there is exactly zero. Any
test that depends on observing real skew is a test that never runs in CI. That
is why the regression tests in `tests/lab/test_one_clock_discipline.py` inject
the skew at the seam instead of waiting for it.

## The classification table

Every site in the codebase that compares two timestamps or derives a duration.
"Host" means the application clock (injected, default `datetime.now(UTC)`).
"DB" means the Postgres server clock (`now()` / `CURRENT_TIMESTAMP` / a column
`DEFAULT now()`).

| # | Site | Left operand | Right operand | Mixed? | Effect of ±2 s skew |
| --- | --- | --- | --- | --- | --- |
| 1 | `lab/approval.py:62` `now < request.requested_at` | Host (injected) | Host (same `IncidentRuntime.approve` call) | No | None — same clock, same call |
| 2 | `lab/approval.py:65` `now >= request.expires_at` | Host (injected) | Host (`now + approval_ttl`, 5 min) | No | None |
| 3 | `control/evidence.py:81` `record.expires_at <= now` | DB row, but **host-written** `observed_at + 120 s` | Host (injected) | No (after fix) | None while the value is far from the boundary; **inverts within the skew band of the boundary** |
| 4 | `control/evidence.py:83` `(now - record.observed_at) > max_age_seconds` | Host (injected) | DB row, host-written | No (after fix) | Same as #3 |
| 5 | `lab/repository.py` `validate()` `approval["expires_at"] <= now` | DB row, host-written | Host — **was inline `datetime.now(UTC)`, now injected** | **Was mixed** | Token expiry judged against a different clock than the one that stamped it |
| 6 | `lab/repository.py` `_validate_approval` `approval["expires_at"] <= now` | DB row, host-written | Host — **was inline, now injected** | **Was mixed** | Same, on the mutation path |
| 7 | `lab/repository.py` `_validate_evidence` `evidence_records.expires_at > %s` | DB row, host-written | Host — **was inline, now injected** | **Was mixed** | Evidence judged stale/fresh against a clock that did not write it |
| 8 | `lab/repository.py` `begin_collection_attempt` `now >= started + time_budget` | Host (injected) | `collection_runs.started_at`, host-written, no DB default | No | None |
| 9 | `lab/repository.py` D6 `run["deadline_at"] <= now` | `d6_collection_runs.deadline_at`, host-written | Host (injected) | No | None — 180 s budget |
| 10 | `lab/repository.py` `d6_resume_state` `now >= run["deadline_at"]` | Host (injected) | Host-written row | No | None |
| 11 | `chaos/matrix.py:372` `state_change < now() - interval` | DB (`pg_stat_activity`) | DB (`now()`) | No | None — **both sides are the database's own clock, which is correct** |
| 12 | `db/001_d1.sql:27` `CHECK (expires_at > observed_at)` | Host-written | Host-written | No | None — same row, same writer |
| 13 | `db/001_d1.sql:55` `CHECK (approved_at >= requested_at AND approved_at < expires_at)` | Host-written | Host-written | No | None |
| 14 | `audit_timeline` ordering | — | — | No (since migration 014) | None — ordering is by the `sequence` identity column, not by any clock |

### Columns that take their value from the database clock

These have `DEFAULT now()`, so any writer that omits them gets the server's
clock. `tests/lab/test_one_clock_discipline.py` pins this list, so a new
defaulted timestamp column has to be classified deliberately.

| Column | Compared against a host value? | Status |
| --- | --- | --- |
| `audit_timeline.created_at` | No — informational since migration 014 | Safe. `tests/lab/test_audit_ordering.py` depends on this default to reproduce the original defect |
| `ticket_notes.created_at` | No | Safe |
| `schema_migrations.applied_at` | No | Safe |
| `target_state.updated_at`, `scenario_target_state.updated_at`, `d5/d8/r01–r12_fixture_state.updated_at` | No | Safe — last-touched markers |
| `immutable_evidence_source.observed_at` | **Yes, indirectly** | **Latent trap.** It flows into `evidence_records.observed_at`/`expires_at`, which sites #3, #4 and #7 compare against the application clock. Production always supplies it explicitly, so the default is unreachable from production code — but it is reachable from any writer that forgets. See "Recommended follow-up" |

## The near-boundary hazard, demonstrated

A wide budget does **not** make a mixed comparison safe. What matters is the
distance between the value and the boundary, not the size of the budget.

While writing the regression tests, an anti-vacuity guard aged an evidence row
by `TTL + 1 s` using the **database** clock and then judged it with the **host**
clock. It failed intermittently. That is not flake: with the container running
~1.5 s ahead, a 121 s age reads as ~119.5 s, which is inside the 120 s TTL, and
the expiry verdict inverts. The guard now uses a margin well outside the skew
band, and the hazard is documented by
`test_production_never_lets_the_database_clock_write_the_evidence_anchor`.

## Wall-clock budgets on the production path

These are real elapsed-time budgets, not just comparisons. They are recorded
here because they are the failure mode that a slow or loaded environment can
trip, independently of any clock skew.

| Budget | Value | Anchored at | Exposure |
| --- | --- | --- | --- |
| `EVIDENCE_TTL_SECONDS` | 120 s | For **D1, D2, D3**: the fixture's `observed_at`, i.e. `inject_*()` time. For **D5, D8, R01–R12**: the read itself | D1/D2/D3 must get from fixture injection to policy evaluation in under 120 s. D5/D8 are immune because they mint evidence at read time |
| policy `evidence.max_age_seconds` | 120 s, every tool | Same anchor | Same |
| `D6_FRESHNESS_BUDGET_SECONDS` | 180 s | The D6 collection run's `started_at` | D6 only |
| D4/D7 `time_budget_seconds` | fixture-supplied | `collection_runs.started_at` | D4/D7 only |
| Approval TTL | 5 min | `IncidentRuntime.approve` | All mutating scenarios |

Measured consequence: aging the D1/D2/D3 evidence anchor past 120 s makes the
workflow return `blocked` with `expired_evidence` and **no pending approval**,
which fails any assertion of the form `assert isinstance(pending,
PendingApproval)`. D5 and D8 are unaffected.

The narrowest budget is 120 s and the worst skew ever measured here is 1.49 s —
a margin of ~80×. `test_every_time_budget_dwarfs_the_maximum_tolerated_clock_skew`
asserts that margin so that tightening a budget toward the skew band fails
loudly.

## Recommended follow-up (not done here — a schema/wire decision)

Drop `DEFAULT now()` from `immutable_evidence_source.observed_at` in a migration
`015`, making the column `NOT NULL` with no default so the trap cannot be reached
by forgetting. This was deliberately **not** bundled with the correctness fix
because it is a schema change requiring:

- a new entry in `LabRepository.migrate()`'s migration tuple;
- `tests/reliability/test_r01_r04_migration.py:79` `range(1, 15)` → `range(1, 16)`;
- `tests/reliability/test_r05_r08_migration.py:45` and
  `tests/reliability/test_r09_r12_migration.py:66`, which assert the last applied
  migration is `014_audit_insertion_sequence.sql`;
- explicit `observed_at` values in the three test inserts that currently omit it
  (`tests/reliability/test_r01_r04_migration.py:47`,
  `tests/integration/test_checkpoint_b_deferred_runtime.py:547` and `:582`).

It changes no value that the chaos differ compares and no idempotency key,
because no production writer omits the column today.
