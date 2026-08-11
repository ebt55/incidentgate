# Verification receipt

## 2026-08-11 Checkpoint B measured local replay

Checkpoint B was measured from code revision `3c19e74ad56a5365f9210b69f0bccf34bd8829b8`; generated artifacts were committed separately at `57daaa075be7ad5d1ad309a4f66ba2fd442ab1f0`. Accepted history must contain commits `3c19e74`, `57daaa0`, and `0321265`; `feature/checkpoint-b-evaluation` is the recovery/development branch used, and `main` is the accepted integration target. The authoritative [raw results](../artifacts/evaluations/checkpoint-b/raw-results.json) contain 30 rows: D1-D8, S1, and S2 in `ungated_evaluation_only`, `policy_only_evaluation_only`, and `policy_monitor_human`. Their SHA-256 is `ddf30df0f933f07095c33ccbafa6e0f0cce22fa1c0d069920b5598ac6001133d`; exact replay matched all 30/30 rows. The derived [CSV](../artifacts/evaluations/checkpoint-b/preliminary.csv), [measured Markdown table](../artifacts/evaluations/checkpoint-b/preliminary.md), and [regression receipt](../artifacts/evaluations/checkpoint-b/regression.json) validate that raw result.

The table is preliminary and describes deterministic/mock local fixtures, not a model/provider benchmark. It records no eligible caught unsafe-proposal rows, so policy and monitor catch fields are N/A—not 0%. In the complete `policy_monitor_human` condition, monitor false positives are 0/5. The deterministic approval simulation used for evaluation is not an observed human decision.

The full suite passed **333 passed, 1 skipped**, with **88 known warnings**. Focused maintenance regressions passed **27/27**; Ruff and mypy (43 source files), `git diff --check`, and `docker compose config --quiet` were green. Semantic falsification corrected action→predicate contradictions before contract acceptance. These checks and results do not demonstrate production safety, external exactly-once delivery, monitor generalization, provider reliability, or real-world model safety.

R01-R08 are implemented local deterministic reliability slices; R09-R20 and T1-T8 remain frozen/planned in [`scenarios/planned-matrix.json`](../scenarios/planned-matrix.json). R05 is a durable read-only no-action lock auto-release observation with exactly three reads under a per-thread/correlation/actor/read-permission cursor, fixture elapsed=45 seconds rather than 45 wall seconds, process-loss resume, and zero approval, operation, or mutation. R06 establishes the exact orders query-plan baseline; R07 routes bounded customer reads to primary; R08 rotates only the credential identifier to `db-app-2026-09`, with no secret/value field. R06-R08 use typed exact actions, deterministic policy, advisory monitor in complete mode, durable human approval, action/context/token/idempotency binding, one Postgres mutation/ledger, response-loss exactly-once replay, and fresh post-commit evidence. Public FastMCP, fresh-host UI, safe telemetry trace chains, and isolated migration 001-012 are tested. Reliability v2 is tested only with local mock fixtures in complete, policy-only, and ungated evaluation modes; full/subset same-trial semantic replay is guarded by a clean revision and excludes only envelope `generated_at`. This does not claim production safety, real DB/query/DNS/credential systems, real 45-second latency, external exactly-once, model/provider benchmarking or generalization, published reliability-v2 artifacts, or continuous Langfuse/Anthropic reliability. Existing dated external smokes remain separately bounded. The remaining frozen contracts, 24 distinct development/calibration/holdout attack-policy variants, and 36 executable fail-closed planned checker specs in [`planned_checkers.py`](../src/triage_agent_lab/planned_checkers.py) are not runtime coverage.

## 2026-08-10 B2 local deterministic checks

D6 rechecks stale health evidence under a durable per-thread cursor and can resume after a process loss without replaying the stale tool call. S1 records only a fixed classification and digest outside immutable fixture storage. S2 is an explicitly non-executable review recommendation. These are local, deterministic fixture checks; they do not establish production security, autonomous remediation safety, provider reliability, or generalization beyond the frozen scenarios.

## 2026-08-10 D1 external telemetry smoke

A clean isolated external Langfuse smoke succeeded against the implemented D1 runtime. An authenticated trace read returned trace ID `78e19818f9307a8c65f0f58ffe0b3c9b` and contained exactly these required span names:

- `d1.workflow`
- `d1.policy`
- `d1.monitor`
- `mcp.observability`
- `d1.approval`
- `mcp.operations`
- `d1.verification`

The same trace continued across a runtime restart, and the run recorded one bundled mock rollback mutation. The installed Langfuse 3.15 `get_trace_url` keyword-only compatibility was exercised; external trace-URL enrichment is non-blocking, while the runtime retains its local trace ID.

This receipt is intentionally narrow. It does not disclose service URLs or credentials, and it does not claim continuous telemetry export, production availability, retention, external exactly-once delivery, or coverage of any scenario other than D1.

## 2026-08-10 guarded Anthropic monitor smoke

The real configured provider path is implemented, while the fixture monitor remains the default for normal network-free local runs. Anthropic requires an explicit provider, API key, and pinned model `claude-haiku-4-5-20251001`. The initial synthetic smoke failed closed with HTTP 400 because the raw Pydantic provider schema contained unsupported constraints. The provider-facing schema was corrected using the official Anthropic SDK `transform_schema`; the original strict local Pydantic validation remains. The corrected guarded live smoke passed exactly once (`1 passed in 9.16s`) using only the synthetic typed restart action and bounded citation digest. No request, response, rationale, key, or provider error body was printed or recorded. The monitor is advisory only; policy and human approval remain authoritative. On every provider or output failure, it returns the same generic hash-bound `BLOCK` result. This does not claim monitor accuracy, calibration, catch rate, false-positive rate, latency or cost, Langfuse model-generation spans, continuous provider reliability, privacy/security certification, or production readiness.
