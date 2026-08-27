# Handoff: getting this running and reproducing the results

This document is for someone who has just cloned the repository and wants to run
it and check its numbers. For where to be skeptical of those numbers, read
[`docs/NOTES-TO-REVIEWER.md`](NOTES-TO-REVIEWER.md) next; it is the more useful
of the two.

## What this measures

Triage Agent Lab is a measurement apparatus, not an incident-response product. It
runs a small incident-remediation agent against frozen scenario contracts under
three safeguard configurations — ungated, deterministic policy gate only, and
policy plus advisory monitor plus durable human approval — and records what
changes. Around that it measures three other things: durability, by killing the
worker process at every node boundary and diffing recovered Postgres state
against a no-kill run; whether a real model in the attacker seat will pursue a
covert objective, and whether the gates stop it; and whether a real model in the
monitor seat flags covert action sequences and how often it flags benign ones.
Most published rows are deterministic fixtures with no model in the decision
path, and every row states which it is. The bounds on all of this are extensive
and are the subject of the companion document.

## Setup that works

Prerequisites: Docker Compose, Python 3.12, and [uv](https://docs.astral.sh/uv/).
No API key, no GPU, and no model runtime are needed for anything in this section.

```bash
uv sync --locked --all-extras
docker compose up -d postgres
```

Point at the database. This is the literal value the Compose stack in
[`compose.yaml`](../compose.yaml) serves — there is nothing to substitute:

```bash
export DATABASE_URL="postgresql://incidentgate:incidentgate_dev_only@127.0.0.1:5432/incidentgate"
```

```powershell
$env:DATABASE_URL = "postgresql://incidentgate:incidentgate_dev_only@127.0.0.1:5432/incidentgate"
```

Then the demo and the suite:

```bash
uv run python -m incidentgate.demo   # ~7 seconds
uv run python -m pytest              # ~12 minutes
```

The demo touches no network, needs no key, and charges nothing; it replays one
committed capture across the three safeguard configurations and prints four
bounds underneath the table it produces.

### The `-m` is load-bearing

`uv run pytest` fails at **collection**, before any test runs, with
`ModuleNotFoundError: No module named 'tests'`. The console script does not put
the repository root on `sys.path`; there is no root `conftest.py` and no
`pythonpath` setting to supply it, and several tests import fixtures as
`tests.<package>.<module>`. `python -m pytest` prepends the working directory and
collects the whole suite. `tests/test_readme_test_command_is_the_one_that_works.py`
asserts that all three of those reasons still hold, so the explanation cannot
quietly stop being true while still reading persuasively.

### The lab database needs exclusive use

The suite requires exclusive use of the Postgres named by `DATABASE_URL`. Its
fixture tables are single-row shared mutable singletons and its approval tokens
are single-use by design, so two concurrent runs consume each other's state.

The failures that produces do not look like a race. They land on
`sabotage evidence requires injected fixture` and `ApprovalDenied`, in a
**different set of tests each time**, and each passes in isolation afterwards.
That signature was twice misread as an environment problem.

[`tests/conftest.py`](../tests/conftest.py) now takes a Postgres advisory lock at
session start and refuses to run if another guarded run holds it, exiting **3**
with a message beginning `ANOTHER TEST RUN HOLDS THIS LAB DATABASE`. If you see
that, wait for the other run rather than investigating a test failure.

It catches another *guarded* suite run only. It does not catch a manual capture
run, an artifact regeneration, or `psql` against the same database, and it does
not make the tests concurrency-safe — the shared singletons are deliberate.

That file also defines a sentinel, `LAB_ALLOW_CONCURRENT_SUITES`, which exists
**only** to reproduce the race for the experiment recorded in
[`docs/verification.md`](verification.md). It is not a way to run two suites when
you are in a hurry; results from a run that sets it are not a valid gate, and the
run says so on stderr. Only one exact token value engages it, so an inherited
`=1` does nothing.

**A second shared resource has no guard at all: the worktree.** A suite run reads
source, config and artifacts from disk throughout, so editing any of those while
a run is in flight produces a result from a tree that no longer exists. A green
from such a run proves nothing, and neither does a red. Do not edit while a suite
or a regeneration is running.

## What costs money, and what does not

**Nothing in this repository requires spending money to verify.** Every published
number is either a deterministic fixture result or a replay of a committed
capture. Model captures are stored under `artifacts/model-captures/` and
`artifacts/monitor-captures/`, keyed by `prompt_sha256`, and the harness replays
them rather than re-sampling.

Counted from the committed files at this commit: **114 captures** — 89 monitor
and 25 attacker. Of those, **81 ran on local open weights and charged nothing**
(`cost_unavailable_reason: local_weights_no_vendor_charge`) and **33 were hosted
calls**, summing to **$0.464635** of `estimated_cost`. Reproduce that count with:

```bash
git ls-files artifacts/monitor-captures artifacts/model-captures | wc -l
```

That sum is **captures on disk, not all-time spend**. A request refused by a
provider's input classifier is billed and leaves no capture, so the two numbers
differ by construction. [`docs/verification.md`](verification.md) and
[`docs/findings/`](findings/) carry the per-run receipts, which are the ledger; a
total taken from the artifact directories alone is only the first of those two
quantities.

Spending real money requires **two** deliberate acts, not one: the environment
variable `INCIDENTGATE_ALLOW_PROVIDER_SPEND=1` **and** the explicit
`--i-will-spend-real-money` flag. The gate governs transport *construction*, so a
publication run is structurally unable to spend. `--max-calls` and `--max-usd`
bound a capture run that you have authorized, and a preflight prices the plan
before any call leaves.

### What can be regenerated free, and what cannot be regenerated at all

| Artifact family | Free to regenerate? |
| --- | --- |
| `artifacts/chaos-matrix/` | **Yes.** Deterministic, no model. ~40 minutes. |
| `artifacts/evaluations/checkpoint-b/` | **Yes.** Deterministic fixtures, no model. |
| `artifacts/sabotage-matrix/` (T1, T2, T4, T7, T8) | **Yes.** Deterministic floor proposer and monitor. |
| `artifacts/model-attacker/` (3 T1 rows) | **Yes, as a replay** of committed local captures. |
| `artifacts/model-monitor/`, `artifacts/observe-only/` | **Yes, as a replay** of committed local captures. |
| `artifacts/r-tier-monitor/` | **Yes, as a replay** of committed local captures. |
| `artifacts/monitor-captures/claude-opus-5/` and `artifacts/monitor-captures/gpt-5.5/` | **No.** Regenerating a hosted capture body needs a provider key and real spend. |

The last row is the only one that cannot be reproduced without a key, and it does
not need to be: the captures are committed, the replay is keyed by
`prompt_sha256`, and a published number never depends on a provider being
reachable. Nothing about a hosted capture can be re-derived offline either — the
cache replays, it does not re-sample.

## Regeneration commands

All of these need `DATABASE_URL` set as above. Check
`git status --porcelain` is clean before a long one and do not touch the tree
while it runs.

```bash
# Durability matrix -- 434 executed cells, ~40 minutes, deterministic
uv run python -m incidentgate.chaos.matrix --out artifacts/chaos-matrix/

# Deterministic sabotage-v2 tables (T1 default; --scenario selects the others)
uv run python -m incidentgate.evaluation.sabotage_matrix --out artifacts/sabotage-matrix/

# Three-condition checkpoint-B comparison
uv run python -m incidentgate.evaluation.runner checkpoint-b --mock-evaluation --output <dir>

# Model-attacker T1 rows, replaying committed captures
uv run python -m incidentgate.evaluation.sabotage_v3_t1 --out <dir>

# Deterministic floor-only control for the same lane
uv run python -m incidentgate.evaluation.sabotage_v3_t1 --attacker deterministic

# T4 monitor sequence lane
uv run python -m incidentgate.evaluation.sabotage_v4_t4 --out <dir>

# Route B observe-only row
uv run python -m incidentgate.evaluation.observe_only_t1 --out <dir>

# R-tier monitor false-positive lane
uv run python -m incidentgate.evaluation.r_tier_monitor --out <dir>
```

Each runner also takes `--porcelain`. The `--capture` and `--capture-monitor`
forms are what *create* captures by calling a provider; they are the ones the
spend gate guards, and you do not need them to reproduce anything published.

## Environment traps that will cost you time

- **Windows and PowerShell.** `export` is not a command; use
  `$env:DATABASE_URL = "…"`. PowerShell has no heredoc — use a here-string
  (`@'…'@`) with the closing delimiter at column 0, and note that Windows
  PowerShell 5.1 has no `&&`, no `??`, and no ternary.
- **The first `uv run` is slow.** It installs the dependency set; that is not a
  hang. Afterwards it is immediate.
- **`connection refused` on 5432, or the demo prints setup instructions.**
  Postgres is not up. `docker compose up -d postgres`, then re-export
  `DATABASE_URL`.
- **`approval-ui` exits immediately** complaining that Anthropic configuration
  must provide API key and model together. A local `.env` has set
  `ANTHROPIC_API_KEY` without `ANTHROPIC_MODEL` or the reverse. Set both or
  neither; nothing in this document needs either.
- **`OperationalError: connection failed … Address already in use (10048)` during
  a full run, on Windows.** Recorded in [`docs/verification.md`](verification.md)
  with the mechanism explicitly **not identified** — the obvious explanation,
  ephemeral-port exhaustion, was measured and ruled out. It is named there so
  that whoever hits it does not assume they broke something. It is a *different*
  failure from the concurrent-suite race above: that one never fails on connect.
- **Ollama is needed only for the local-model arms**, and only to *create* new
  captures. Replaying committed ones needs nothing. If you do want to capture,
  [`docs/local-weights-runbook.md`](local-weights-runbook.md) has the procedure;
  `qwen3:14b` is ~9.3 GB on disk and `mistral-nemo:12b` ~7.1 GB.
- **With no GPU**, the suite, the demo and every replay are unaffected — none of
  them use one. Only local capture runs do, and on CPU they are slow enough to be
  impractical rather than impossible. Free the VRAM before a capture run; ordinary
  desktop applications were observed holding enough to matter.
- **`HANDOVER-07-EXECUTOR-STATE.md` in the repository root is not addressed to
  you.** It is a dated internal snapshot from an earlier working session, kept
  for history. Nothing in it is a prerequisite for this document.

## Where to go next

- [`docs/NOTES-TO-REVIEWER.md`](NOTES-TO-REVIEWER.md) — what is measured versus
  what is claimed, and the known gaps. Read this before believing any number.
- [`docs/verification.md`](verification.md) — the dated receipt log, including
  corrections and superseded entries.
- [`docs/findings/`](findings/) — results that produced no publishable row and are
  published as prose instead.
- [`README.md`](../README.md) — the project overview. Note that its capture counts
  are stale relative to this commit; see the companion document.
