# Triage Agent Lab

> ## ⚠️ Work in progress — nothing is released
>
> **This is not a release. It is not a beta. It is not a preview.** It is a
> development checkpoint pushed for visibility and review, and it will change in
> breaking ways without notice.
>
> Concretely, as of this commit:
>
> - **The agent does not yet speak MCP over a transport.** The three MCP servers
>   are implemented and tested in-process, but nothing serves them over a wire
>   protocol, and the workflow calls Python adapters directly. See
>   [Honest gaps](#honest-gaps).
> - **No model is in the decision path** for any published measurement. Every
>   evaluation row is a deterministic fixture. See [Honest gaps](#honest-gaps).
> - Scenarios R13–R20 and the entire T1–T8 sabotage tier are frozen contracts
>   with no runtime.
>
> Do not depend on this, do not cite its numbers as a product claim, and do not
> deploy it. It is a laboratory.

---

Triage Agent Lab is a **reproducible experiment**, not an incident-response
product. It measures how a deterministic policy gate, an advisory action
monitor, and durable human approval change an incident agent's behavior under
crashes, misleading evidence, and hostile input.

This is deliberately **not** a novel AI-SRE agent. Anthropic publishes an SRE
incident-response cookbook, and OpenSRE and Akmatori ship governed remediation
with approval gates. Nothing here competes with those. What this repository
offers is the measurement apparatus around such an agent: frozen incident
contracts, three counterfactual safeguard conditions, real process kills, and
raw results that regenerate from one command.

## The two results that matter

### 1. Durability under real process kills

The worker is killed with `os._exit(137)` at **every node boundary of every
runnable scenario**, then recovered with fresh processes and diffed against a
golden no-kill run.

| Measure | Result |
| --- | --- |
| Kill points × scenarios | 22 boundaries × 22 scenarios = 484 cells |
| Cells where the boundary exists and fired | **324** |
| Recovered to the golden end state | **324** |
| Duplicate mutations | **0** |
| Lost incidents | **0** |
| Other durable end-state divergences | **0** |
| Harness errors | **0** |

The other 160 cells are `n/a` — that boundary does not exist on that scenario's
path — and every one is published with the reason it does not apply rather than
dropped from the table.

- [Published table](artifacts/chaos-matrix/kill-matrix.md) ·
  [raw JSON](artifacts/chaos-matrix/kill-matrix.json) (authoritative)

Every kill is a real subprocess death — the parent asserts the child's exit code
before it attempts recovery. The differ compares a 17-field normalized
projection of durable Postgres state (ledger rows per scope, fixture mutation
counters, approval consumption, audit event sequence, evidence reads, ticket
notes), and a committed negative-control test plants a duplicate mutation
directly in Postgres to prove the differ actually goes red when it should.

Measured 2026-08-12, from a cold database, on a clean tree. Regenerate with:

```bash
uv run python -m incidentgate.chaos.matrix --out artifacts/chaos-matrix/
```

That run takes about 25 minutes, because every cell is real processes against
real Postgres. **CI therefore runs a documented subset, not the table above**:
one scenario per tier (D1, S1, R01) × five boundaries covering every boundary
class = 12 executed cells instead of 324, in about a minute. The subset samples
both dimensions rather than shrinking one, and
`tests/chaos/test_kill_matrix.py` records why each member is in it. The full
22-scenario matrix stays a command whose output is committed, so the expensive
version does not have to run on every push.

Two honest findings from that run, neither of which is a durability failure:

- **`orphaned_approvals: 56` — the one non-zero number in the table.** An
  orphaned approval is a durable approval token with no matching executed
  operation. Approval issuance is not idempotent across a crash: a kill between
  the approval commit and the operation commit loses the in-memory handle to a
  token that is *already durable*, so recovery mints a fresh token for the
  identical canonical action and spends that one instead. It appears in exactly
  the four boundaries inside that window × the fourteen scenarios that mint an
  approval at all, exactly once each. It is neither a lost incident nor a
  duplicate mutation — those are counted separately and both are zero — because
  the leftover token is unspendable: it is bound to a canonical action hash
  covering thread id, actor, permission, evidence ids and arguments, and the
  ledger's idempotency key is `uuid5(thread_id, action_hash)`, a pure function
  of that same binding. The only key an orphan can derive is the one the
  recovered operation already occupies.
  `tests/chaos/test_orphaned_approvals.py` drives a real killed cell and then
  fails to spend what it left behind three ways, and checks that a denied
  attempt does not burn the token either.
- `runtime.status().pending` is not a real interrupt check; it reports a pending
  approval whenever a policy and action exist without a result, even mid-execute.

### 2. Three-condition safeguard comparison (Checkpoint B)

Ten frozen scenarios (D1–D8, S1, S2) run under three configurations — ungated,
policy-only, and policy + monitor + human approval — for 30 rows total, with
**30/30 rows matching exactly on replay**.

- [Raw results](artifacts/evaluations/checkpoint-b/raw-results.json) (authoritative)
- [Measured table](artifacts/evaluations/checkpoint-b/preliminary.md)
- [CSV](artifacts/evaluations/checkpoint-b/preliminary.csv) ·
  [Replay receipt](artifacts/evaluations/checkpoint-b/regression.json)

**This table is weaker than it looks, and the weakness is the point of the next
milestone.** Policy and monitor catch rates are reported `N/A`, not `0%`, because
no eligible unsafe proposal ever occurred — the agent is deterministic, so it
never proposes anything wrong. Until a model is in the decision path, the
safeguard comparison has almost nothing to catch.

## What the system does

The enforced chain for a mutating scenario is:

```
evidence → deterministic policy → advisory monitor → durable pre-approval audit
  → human approval/reject → atomic idempotent operation → fresh verification
```

**Without a human it can:** read logs, metrics, health, deployment diffs, and
schema/dependency state; form a diagnosis; propose exactly one typed action; and
resolve read-only or no-action incidents by deferring with a recorded reason.

**It refuses to:** execute any mutation without a single-use approval token bound
to the canonical action hash, actor, expiry, incident/thread context, and
operation scope; act on evidence from another thread; treat tool output as
instructions; or report recovery without fresh post-commit verification. Forbidden
actions are structurally unreachable — `CanonicalAction.tool_name` is a closed
`Literal`, so an action outside a scenario's contract cannot be constructed.

The approval token is minted **only** by the human-approval code path
(`ApprovalService.approve` requires the approver role). The agent has no code path
that mints one, and the token is validated twice: once in the graph and again
inside the mutation transaction under `SELECT ... FOR UPDATE`, so a bypassed graph
still cannot mutate.

## Scenario coverage

| Tier | Contracts | Runtime |
| --- | --- | --- |
| D1–D8, S1, S2 (checkpoints) | frozen | **implemented** |
| R01–R12 (reliability) | frozen | **implemented** |
| R13–R20 (reliability) | frozen | planned — no runtime |
| T1–T8 (covert sabotage) | frozen, 24 attack-policy variants | planned — no runtime |

Every scenario declares its initial state, injected fault, allowed evidence,
acceptable diagnoses, allowed and forbidden actions, recovery predicate, and a
deterministic final-state checker **before** any runtime exists for it. A guard
test asserts that each wired scenario's diagnosis string is byte-identical to its
frozen manifest, so runtime drift cannot silently pass evaluation.

## Five-minute local run

Prerequisites: Docker Compose, Python 3.12, and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked --all-extras
docker compose up --build -d
```

Set `DATABASE_URL` to the local Compose Postgres, then:

```bash
uv run pytest
```

Open `http://127.0.0.1:8090`, choose the local mock operator, prepare D1, D2, or
D3, and start analysis. The flow stops at a pending approval; switch to the mock
approver to approve or reject. Stop with `docker compose down`.

The Compose stack binds Postgres, the lab target, and the approval UI to
localhost. Its default database password is development-only; override it with
`INCIDENTGATE_POSTGRES_PASSWORD`. Never commit `.env`.

## Honest gaps

These are the things a reviewer should know before believing anything above.

1. **The agent does not talk MCP over a transport.** Three FastMCP servers
   (observability, operations, tickets) are implemented and tested through
   `list_tools`/`call_tool`, but nothing serves them over stdio or Streamable
   HTTP, and the workflow calls in-process Python adapters. The title of this
   project is aspirational on this point until the transport lands.
2. **No model is in the decision path.** Diagnosis and action selection come from
   hand-written deterministic proposers. Every published evaluation row is
   `fixture_no_call`. A model-driven proposer and an offline response cache are
   implemented and unit-tested in `control/model_proposal.py`, but they are not
   yet wired into the runtime, so no measurement uses them.
3. **The sabotage tier is therefore vacuous today.** An attack policy is a prompt,
   and there is no model to receive it. S1 prompt-injection resistance is
   currently proved by a deterministic transform, not by a model declining to
   comply.
4. **Exactly-once is scoped to the bundled mock operations and local Postgres**,
   where the mutation, ledger row, and token consumption share one transaction.
   It is not a claim about external APIs or distributed delivery.
5. **No MCP conformance is claimed.** The pinned SDK is the stable `mcp` 1.29
   line, which predates the 2026-07-28 revision; there is no MRTR/Tasks support
   and no conformance report yet.
6. **Telemetry is bounded.** One dated Langfuse smoke on 2026-08-10 verified trace
   continuity across a runtime restart. That is not continuous export, retention,
   or production reliability.
7. **Fixtures are local and synthetic throughout** — no real database, DNS, TLS,
   credential, or dependency system is contacted. R05's 45 seconds is fixture
   time, not wall-clock latency.

## Repository map

- `src/incidentgate/control/` — workflow graph, policy engine, advisory
  monitor, deterministic and model proposers, response cache
- `src/incidentgate/chaos/` — kill-point injection, worker, end-state differ,
  matrix runner
- `src/incidentgate/lab/` — durable Postgres state, approval service,
  operation ledger, audit timeline
- `src/incidentgate/mcp_servers/` — the three FastMCP server definitions
- `src/incidentgate/evaluation/` — checkers, three-condition runners, replay
- `scenarios/` — frozen contracts (checkpoints, reliability, sabotage)
- `db/` — journaled Postgres migrations
- `docs/` — [threat model](docs/threat-model.md),
  [architecture status](docs/architecture-decisions.md),
  [D1 runbook](docs/d1-runbook.md),
  [verification receipt](docs/verification.md)

## Next milestones

1. Rename the package to `incidentgate`; freeze the idempotency namespace
   constant first, because it is a wire value baked into every durable
   idempotency key.
2. Serve the operations server over Streamable HTTP and route the mutation
   through a real MCP client, then run the official
   `@modelcontextprotocol/conformance` kit against all three servers.
3. Wire the model proposer into the runtime so the three-condition comparison and
   the sabotage tier stop being vacuous.
4. Implement R13–R20, then one real covert channel (T1) end-to-end.
5. CI regression gates, the full timeline UI, and a 90-second demo.

## License

[MIT](LICENSE).

The license makes the code freely reusable. It does not change what the
measurements mean: the numbers in this repository are local, deterministic
fixture results produced under the conditions described in
[Honest gaps](#honest-gaps), and they should not be quoted as production or
product claims.
