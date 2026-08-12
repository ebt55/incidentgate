# D1 local runbook and recovery behavior

## Start the local lab

Use Python 3.12, uv, and Docker Compose.

```powershell
uv sync --locked --all-extras
docker compose up --build -d
$env:DATABASE_URL = "postgresql://incidentgate:incidentgate_dev_only@127.0.0.1:5432/incidentgate"
uv run pytest
```

Open `http://127.0.0.1:8090`. Select a local mock operator, prepare the D1 fault, and start analysis. This produces a pending approval rather than a mutation. Select the local mock approver to approve or reject it. Inspect the final timeline and fresh verification result in the UI.

The stack binds only to localhost. `INCIDENTGATE_POSTGRES_PASSWORD` can override the explicitly development-only default for local use. Do not place credentials in committed files. Stop the stack with `docker compose down` when finished.

## Expected D1 recovery path

1. The lab records deployment-diff, error-log, and health evidence for the injected `v2`/500 fault.
2. Deterministic policy accepts only `operations.rollback` for the expected D1 target; the default fixture monitor gives its advisory result. An explicitly complete Anthropic configuration (provider, API key, and pinned model) instead selects the bounded advisory provider path, which fails closed on every provider/output failure. Policy and human approval remain authoritative.
3. A preapproval audit entry is persisted and the workflow pauses for an approver decision.
4. A valid bound approval authorizes the one mock rollback. Reject, expiry, substitution, or replay leaves the incident blocked.
5. The rollback and its idempotency outcome commit together. If the caller loses the response or restarts after commit, it resumes from durable state and does not create a second bundled mock operation.
6. Fresh health evidence must show `v1` with HTTP 200 before recovery is reported.

## Operator recovery notes

If the UI is not ready, check `docker compose ps` and `docker compose logs approval-ui lab postgres`. If the local Postgres database has stale experimental data, stop the stack and use the repository's normal local reset procedure before retrying; this runbook intentionally does not prescribe deletion commands.

Do not treat an HTTP response loss as evidence that the mutation failed. Reopen the incident through the local UI/runtime and inspect its durable timeline. This retry property is specific to the bundled mock rollback, not an external operation guarantee.
