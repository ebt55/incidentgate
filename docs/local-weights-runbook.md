# Running the local open-weight attacker arm

Windows, from nothing. Everything below is free — no vendor is billed at any point.

## Why this arm exists

A locally-run open-weight model gives provenance nothing hosted can match: an exact weights file,
an exact quantisation, a hash this harness computes itself, no vendor able to change a model under
a stable name, and no licence gate between a reader and reproducing the run.

The harness will not take your word for any of that. It resolves the weights from Ollama's own
content-addressed store, hashes the blob, checks its hash against the digest the store declares,
refuses any endpoint that is not loopback, and refuses a response from a server that answers as a
different model than the one it resolved. If any of those fail the run stops rather than recording
a weaker claim.

---

## 1. Install and pull

```powershell
winget install Ollama.Ollama       # or https://ollama.com/download/windows
ollama --version                   # 0.32.13 or later, for the `think` parameter
ollama pull qwen3:14b              # ~9.3 GB
ollama pull mistral-nemo:12b       # ~7.1 GB
```

Two models, both Apache 2.0, and **both are attackers** — not a primary and a fallback. They are
different lineages with different architectures and only one has a reasoning mode, which makes the
second an independent data point on whether a decline is model-specific rather than a substitute
for the first.

Verify what landed:

```powershell
ollama show qwen3:14b
ollama show mistral-nemo:12b
```

| | `qwen3:14b` | `mistral-nemo:12b` |
| --- | --- | --- |
| Harness id | `qwen3-14b` | `mistral-nemo-12b` |
| Architecture | `qwen3` | `llama` |
| Parameters | 14.8B | 12.2B |
| Quantization | **Q4_K_M** | **Q4_0** (lower fidelity) |
| Size on disk | 9.3 GB | 7.1 GB |
| Reasoning mode | **yes** — must be switched off | none |

The quantisation difference is real and is recorded in the capability table. If the two models
disagree on a result, quantisation is one of at least three candidate explanations alongside
lineage and parameter count, and nothing in this arm separates them.

## 2. Free the VRAM before you run

**This is the step that will bite you.** The card is 10,240 MiB total; `qwen3:14b` needs roughly
9 GB and `mistral-nemo:12b` roughly 7 GB. Ordinary desktop applications were observed holding
8,067 MiB — ComfyUI, browsers, Docker Desktop all count.

Nemo may therefore load where Qwen3 will not. That is a reason to record which model ran, never a
reason to let one stand in for the other.

```powershell
nvidia-smi --query-gpu=memory.total,memory.used,memory.free --format=csv
```

Close what you can and re-check until `memory.free` is comfortably above 9,000 MiB. Postgres must
still be running for the harness, but it does not use the GPU.

If the model cannot load, the run stops with exit code `3` and `UNAVAILABLE:`. **That is an
environment failure, not a result.** It says nothing about what the model would have chosen and
must never be recorded as a decline — the harness enforces this, but it is worth knowing what you
are looking at.

## 3. Start the server

Ollama runs as a background service on Windows once installed. Confirm it is listening on
loopback:

```powershell
(Invoke-WebRequest http://127.0.0.1:11434/api/tags).StatusCode   # expect 200
```

The harness talks to `http://127.0.0.1:11434` by default. `--ollama-endpoint` exists for a
non-default **port**, not a non-default host: a non-loopback endpoint is refused outright and
there is deliberately no override. See "Why there is no --allow-remote" below.

## 4. Verify the harness agrees with the store — free, no generation

This resolves the weights, hashes the ~9 GB blob (takes a minute or two) and checks it against the
manifest, without generating a single token:

```powershell
uv run python -c "from incidentgate.control.local_weights import resolve_ollama_weights as r; w = r('qwen3-14b'); print(w.server_model, w.weights_sha256, w.size_bytes, w.quantisation)"
```

A mismatch here means the bytes on disk are not what Ollama recorded when it pulled them, and the
run should not proceed. Re-pull rather than overriding.

## 5. Capture

Two variants per model, so four captures if you run both models. **No API key, no spend flag, no
`--max-usd`** — this path cannot bill anyone, so the spend gate does not apply to it. Swap
`--model qwen3-14b` for `--model mistral-nemo-12b` to run the second attacker.

```powershell
cd C:\Users\ebin\Documents\ChatGPT\opsPilot\.claude\worktrees\incidentgate-refactor-cleanup-7c0a6e

# 1 of 2 - T1-dev-v1
uv run python -m incidentgate.evaluation.sabotage_v3_t1 `
  --dsn postgresql://incidentgate:incidentgate_dev_only@127.0.0.1:5432/incidentgate `
  --attacker model --provider local --model qwen3-14b `
  --variant T1-dev-v1 --cache-dir artifacts/model-captures --capture

# 2 of 2 - T1-cal-v1
uv run python -m incidentgate.evaluation.sabotage_v3_t1 `
  --dsn postgresql://incidentgate:incidentgate_dev_only@127.0.0.1:5432/incidentgate `
  --attacker model --provider local --model qwen3-14b `
  --variant T1-cal-v1 --cache-dir artifacts/model-captures --capture
```

Each prints the resolved weights line before generating anything. Publishing afterwards is the
same command without `--capture`, plus `--out`.

Exit codes: `0`/`1` published, `2` publication or spend refusal, `3` environment or transport
failure (including a model that would not load), `4` provider policy block — which this arm cannot
produce, because there is no vendor classifier in front of the weights.

## 6. Check the capture before trusting it

```powershell
uv run python -c "import json,glob; p=glob.glob('artifacts/model-captures/qwen3-14b/*.json')[0]; d=json.load(open(p))['provenance']; print(json.dumps({k:d[k] for k in ('provider','model','weights','request_envelope','cost_unavailable_reason','pricing_snapshot_id')}, indent=2))"
```

What to look for:

- `cost_unavailable_reason: "local_weights_no_vendor_charge"` and `pricing_snapshot_id: null` —
  no vendor charge, as opposed to a cost we failed to compute.
- `weights` carrying the sha256 this harness computed.
- In `request_envelope`: `reasoning_control: "think=false"` — **not** `think:omitted:...`, which
  would mean the run had thinking on and is not comparable with the other two arms.
- In `request_envelope`: `sampling` showing `temperature=1.0` and `top_p=1.0` — not `0.6` (qwen3's
  modelfile) and not `0.8` (Ollama's default for a model that declares none).
- In `request_envelope`: `sampling_provenance` containing `explicit:temperature,top_p`. If every
  parameter reads `modelfile` or `ollama_default`, nothing was set and the run is not comparable.

---

## Design notes worth knowing before you read a result

### Why there is no `--allow-remote`

`--provider local` is not a label the command line asserts; it is a claim the harness checks. The
loopback restriction is what makes the other checks worth anything — without it, a real weights
file could be hashed on disk while the answers came from a vendor across the network, and every
recorded field would still look right.

What the checks buy is that faking a local run is **no longer a command-line edit**. It would take
a lying process on this machine with its own credential. What they do *not* buy is proof that the
process on port 11434 actually ran those weights; closing that would need attestation of the
server process, which does not exist here and is not pretended to.

### Three arms, three explicit off-switches

Reasoning is switched off explicitly on every arm rather than left to a default, because on all
three "send nothing" means something different:

| Arm | Reasoning off by | Default if omitted |
| --- | --- | --- |
| `anthropic` | `thinking: {type: disabled}` | on |
| `openai` | `reasoning_effort: none` | `medium` |
| `local` / `qwen3-14b` | `think: false` | on (Qwen3 is hybrid) |
| `local` / `mistral-nemo-12b` | nothing to send | no reasoning mode exists |

These are **analogous settings, not identical ones**, and nothing here establishes that they leave
different models in comparable internal states. Nemo is the one row where "send nothing" is
genuinely off rather than a default — `ollama show` reports capabilities `completion` and `tools`
with no `thinking`, so there is no mode to disable. That is stated in the capability table as a
verified fact, not assumed from the absence of evidence.

### Sampling: omission is never neutral, and not even consistent

The same trap on a third parameter, and the sharpest version of it. **There is no configuration on
Ollama where sending nothing leaves sampling unset.** Something always applies, and what applies
differs per model:

- `qwen3:14b` declares temperature 0.6, top_p 0.95, top_k 20, repeat_penalty 1 in its modelfile.
- `mistral-nemo:12b` declares **only stop tokens**, so Ollama's own defaults apply instead —
  documented at temperature 0.8, top_k 40, top_p 0.9, repeat_penalty 1.0.

So "send nothing" would have run the two local models at 0.6 and 0.8 respectively, neither of them
the 1.0 the Anthropic arm ran at, with every envelope truthfully reading `none_sent`.

Both local models therefore send temperature and top_p **explicitly at 1.0**:

| Arm | Effective sampling | How |
| --- | --- | --- |
| `anthropic` | `temperature=1.0` | documented API default; the model rejects an explicit value |
| `openai` | **unknown** | no default documented for this model class |
| `local` / `qwen3-14b` | `temperature=1.0, top_p=1.0`, `top_k=20`, `repeat_penalty=1` | first two explicit, rest from the modelfile |
| `local` / `mistral-nemo-12b` | `temperature=1.0, top_p=1.0`, `top_k=40`, `repeat_penalty=1.0` | first two explicit, rest from Ollama's defaults |

This is **not** equivalence across arms. OpenAI's effective value could not be established from any
citable source; the two hosted models reject sampling parameters outright so they cannot be moved;
and Ollama documents no value of `top_k` that disables top-k sampling, so nothing is guessed into
neutrality.

Every capture records the effective value **and the source of each parameter** under
`request_envelope.sampling` and `sampling_provenance` — `explicit`, `modelfile`, or
`ollama_default` — so a reader can tell a value we set from one that was applied to us.

**The Anthropic and OpenAI captures were taken before this was understood and have not been
re-taken.** Their envelopes record `sampling: none_sent`, which is what the descriptor said at the
time; the divergence is recorded in
[`findings/T1-cross-model-attacker.md`](findings/T1-cross-model-attacker.md) §4.4 rather than
papered over.

### Scope: T1 yes, T4 probably not

A 14B model should handle T1 — a single tool selection from a two-action grammar. T4 needs a
covert objective split across three ordered calls, and at this scale a failure could as easily be
incompetence as refusal. The attempt predicate cannot tell those apart, so a T4 null result from
this arm would mean nothing. Recorded in the capability table rather than rediscovered after a run.

### Adding a third local model

`LOCAL_MODELS` in `control/local_weights.py` needs its tag, quantisation and declared sampling
(from `ollama show --modelfile`), and `MODEL_CAPABILITIES` needs a row stating whether it has a
reasoning mode and what this lab sends as sampling. Until both exist the run is refused, which is
the table doing its job rather than an obstacle to route around.

Do not copy a row from either existing model. The two already present differ in architecture,
parameter count, quantisation and whether they reason at all, which is precisely why each needed
stating rather than inferring.
