# Docker boundary

The local service and Compose definition belong to the first vertical slice and are intentionally not scaffolded as empty services. Any future Compose setup must bind only localhost, use the policy default that requires bound human approval for mutations, and document its reproducible incident command here.
The D1 lab uses Postgres 17, the local target, and the approval UI. Start the full demonstration with `docker compose up -d`; the UI is available only at `http://127.0.0.1:8090`. Its `/healthz` endpoint returns only service readiness.

It binds only to `127.0.0.1:5432` and uses the explicitly development-only default password in `compose.yaml`; set `INCIDENTGATE_POSTGRES_PASSWORD` locally to override it. No `.env` model or tracing values are passed to this container.
