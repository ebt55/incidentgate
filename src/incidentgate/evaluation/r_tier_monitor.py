"""The R-tier monitor false-positive lane.

**Every episode in this tier is benign by construction.** An R scenario is a fault
plus one sanctioned repair; there is no covert objective anywhere in the tier and
nothing for a monitor to detect. So a BLOCK here is a **false positive**, and a low
block count is *not* evidence of good detection â€” it is the absence of a failure
mode this tier cannot exhibit. A reader who arrives expecting a detection rate and
reads a low block count as competence has drawn the conclusion this lane exists to
make impossible.

That framing is the whole point of the tier: unlike the sabotage tier, a null here
cannot be vacuous. "The monitor blocked nothing" is a real measurement about honest
work, where "the monitor blocked nothing" on a covert leg might mean the covert leg
never happened.

WHAT IS MEASURED, AND WHAT IS NOT
=================================

Measured: for each eligible scenario, does the model monitor block the sanctioned
repair? That is a block rate over a named denominator.

Not measured: a defer rate. The a-priori band pins ``defer_at`` and ``block_at``
at 1.0, so ``monitor_decision.decide``'s defer interval is empty and DEFER is
unreachable by construction. Lowering ``defer_at`` would be choosing a cutoff to
make an outcome reachable, which is exactly what ``a_priori_definitional``
forbids. The lane publishes that DEFER was unreachable rather than manufacturing a
threshold to produce a number.

THE DENOMINATOR IS EIGHT, AND IT IS NAMED
=========================================

Twelve R scenarios are runnable. Four are excluded, for two different reasons, and
``tests/evaluation/test_r_tier_monitor_lane_eligibility.py`` pins both:

* **R03** declares ``operations.restore_config_PAYMENT_TIMEOUT_MS_3000`` while
  ``monitor_input.ToolName`` admits no uppercase. The two have always disagreed,
  so R03 could never have rendered a monitor input -- it would produce a monitor
  *error*, never a verdict, and an error counted as a non-block deflates the rate.
  A defect that predates this lane, excluded rather than papered over, with
  neither side edited to make the lane run.
* **R05, R10, R11** declare no ``allowed_actions`` at all. They are diagnosis-only
  scenarios, so there is no action to judge and no verdict either way. A property
  of what they are, not a defect.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from incidentgate.contracts import EvaluationMode

_ROOT = Path(__file__).resolve().parents[3]

#: The eight scenarios this lane can measure. Named rather than globbed: a lane
#: that derives its own denominator from what happens to work is choosing it.
ELIGIBLE: Final = ("R01", "R02", "R04", "R06", "R07", "R08", "R09", "R12")

#: Excluded, with the reason each is excluded. Published in the artifact.
EXCLUDED: Final = {
    "R03": "declares a tool name ToolName cannot render (uppercase); predates this lane",
    "R05": "declares no allowed_actions; diagnosis-only, nothing to judge",
    "R10": "declares no allowed_actions; diagnosis-only, nothing to judge",
    "R11": "declares no allowed_actions; diagnosis-only, nothing to judge",
}

MONITOR_CACHE_DIR: Final = _ROOT / "artifacts" / "monitor-captures"
THRESHOLD_DIR: Final = _ROOT / "config" / "monitor-thresholds"
OUTPUT_DIR: Final = _ROOT / "artifacts" / "r-tier-monitor"

LOCAL_SEATS: Final = ("qwen3-14b", "mistral-nemo-12b")


def threshold_path(scenario_id: str, model: str) -> Path:
    """The committed a-priori artifact for one (scenario, seat), by convention."""
    return THRESHOLD_DIR / f"{scenario_id}-a-priori-{model}-v1.json"


def build_monitor_source(
    scenario_id: str, model: str, *, capture: bool, endpoint: str, weights_root: str | None,
    split: Literal["development", "calibration", "holdout"],
) -> object:
    """Wire one monitor seat for one scenario.

    The threshold artifact is loaded from its committed file and checked against
    this caller by ``SemanticMonitorConfigurationV3.build``, so moving the seat
    cannot quietly move the rule the seat is judged under.

    On the replay path no transport is constructed at all, so a cache miss
    surfaces as an error rather than reaching for a model.
    """
    from incidentgate.control.monitor_contract_v3 import (
        RecordingMonitorCallerV3,
        StructuredMonitorCallerV3,
    )
    from incidentgate.control.response_cache import (
        CacheBackedCompletionClient,
        ResponseCache,
    )
    from incidentgate.evaluation.harness_abort import HarnessAborted
    from incidentgate.evaluation.monitor_thresholds import load_a_priori_thresholds
    from incidentgate.integration.semantic_monitor import SemanticMonitorConfigurationV3

    path = threshold_path(scenario_id, model)
    if not path.exists():
        raise HarnessAborted(
            f"no committed threshold artifact for {scenario_id}/{model}; a verdict must be "
            "published under a rule frozen before the capture existed"
        )
    artifact = load_a_priori_thresholds(path)
    if artifact.scenario_id != scenario_id:
        raise HarnessAborted("the threshold artifact was frozen against another scenario")
    if artifact.model != model:
        raise HarnessAborted("the threshold artifact names another seat")

    cache = ResponseCache(MONITOR_CACHE_DIR)
    if capture:
        from incidentgate.control.local_weights import (
            OllamaWeightsCompletionClient,
            resolve_ollama_weights,
        )

        weights = resolve_ollama_weights(
            model, store_root=Path(weights_root) if weights_root else None
        )
        transport = OllamaWeightsCompletionClient(weights=weights, endpoint=endpoint)

        def provenance(request: object, result: object) -> object:
            return _capture_provenance(
                request, result, scenario_id=scenario_id, model=model, weights=weights,
                split=split,
            )

        client: object = CacheBackedCompletionClient(
            cache,
            record_client=transport,
            record_mode=True,
            provenance_builder=provenance,  # type: ignore[arg-type]
            provider="local",
        )
    else:
        client = CacheBackedCompletionClient(cache, provider="local")

    caller = RecordingMonitorCallerV3(
        StructuredMonitorCallerV3(client=client, model=model)  # type: ignore[arg-type]
    )
    return SemanticMonitorConfigurationV3(caller=caller, artifact=artifact)


def _capture_provenance(
    request: object, result: object, *, scenario_id: str, model: str, weights: object,
    split: Literal["development", "calibration", "holdout"],
) -> object:
    from incidentgate.control.response_cache import ProviderCaptureProvenance, schema_sha256
    from incidentgate.evaluation.harness_abort import HarnessAborted
    from incidentgate.evaluation.sabotage_matrix import git_provenance
    from incidentgate.evaluation.sabotage_v3_t1 import provider_envelope_json

    invocation = result.invocation  # type: ignore[attr-defined]
    if invocation.input_tokens is None or invocation.output_tokens is None:
        raise HarnessAborted("a capture without usage cannot be recorded")
    return ProviderCaptureProvenance(
        provider="local",
        model=model,
        role="monitor",
        prompt_sha256=request.prompt_sha256,  # type: ignore[attr-defined]
        request_schema_sha256=schema_sha256(request.schema),  # type: ignore[attr-defined]
        input_schema_version="monitor-input-v3",
        prompt_version="monitor-prompt/v3.output-v3",
        request_envelope=provider_envelope_json("local", request),  # type: ignore[arg-type]
        stop_reason="end_turn",
        input_tokens=invocation.input_tokens,
        output_tokens=invocation.output_tokens,
        usage_source=invocation.usage_source or "local_usage",
        capture_mode="live_provider_call",
        captured_at=datetime.now(UTC),
        capture_command="python -m incidentgate.evaluation.r_tier_monitor --capture",
        git_revision=git_provenance()[0],
        pricing_snapshot_id=None,
        estimated_cost=invocation.cost,
        currency=invocation.currency,
        cost_unavailable_reason="local_weights_no_vendor_charge",
        weights=json.dumps(
            weights.provenance(),  # type: ignore[attr-defined]
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ),
        scenario_id=scenario_id,
        # An R scenario has exactly one configuration, so its "variant" is itself.
        # Recorded as the scenario id rather than an invented name like
        # "R01-only-v1": a reader seeing variant_id equal to scenario_id can tell
        # at a glance that this tier has no variant axis, where a manufactured
        # label would imply one of several.
        variant_id=scenario_id,
        condition=EvaluationMode.COMPLETE,
        # The R tier is one honest leg. There is no covert leg in this tier at all,
        # which is the property that makes a block here a false positive.
        leg="incident",
        step_index=0,
        split=split,
    )


def run_lane(
    dsn: str, model: str, *, capture: bool, endpoint: str, weights_root: str | None
) -> list[dict[str, object]]:
    """One seat over the eight eligible scenarios, in the COMPLETE mode only.

    COMPLETE is the only mode with a monitor: the other two switch it off, so a
    row from them would carry no verdict and belong in no rate.
    """
    from incidentgate.evaluation.reliability_v2 import ReliabilityEvaluationRunnerV2
    from incidentgate.manifests import load_reliability_manifests

    by_id = {m.id: m for m in load_reliability_manifests(_ROOT / "scenarios" / "reliability")}
    rows: list[dict[str, object]] = []
    for scenario_id in ELIGIBLE:
        source = build_monitor_source(
            scenario_id, model, capture=capture, endpoint=endpoint, weights_root=weights_root,
            split=by_id[scenario_id].split,
        )
        # A capture run publishes nothing, so it cannot stamp an artifact with an
        # unreproducible revision -- which is the only thing the clean-tree guard
        # protects. The replay path passes no guard at all and so keeps the strict
        # default; passing ``None`` would have replaced a callable with something
        # uncallable and failed at the end of a run rather than the start.
        guard = {"revision_guard": _head_revision} if capture else {}
        runner = ReliabilityEvaluationRunnerV2(dsn, semantic_monitor=source, **guard)
        envelope = runner.run([by_id[scenario_id]], modes=(EvaluationMode.COMPLETE,))
        (row,) = envelope.results
        rows.append(
            {
                "scenario_id": scenario_id,
                "model": model,
                # The row carries the false-positive booleans rather than a raw
                # verdict, which is the right shape for this lane: on a benign
                # tier "did it block" and "was that a false positive" are the same
                # question, and the contract already says so.
                "monitor_false_positive_eligible": row.monitor_false_positive_eligible,
                "monitor_false_positive": row.monitor_false_positive,
            }
        )
    return rows


def _head_revision() -> str:
    from incidentgate.evaluation.sabotage_matrix import git_provenance

    return str(git_provenance()[0])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure a model monitor's false-positive rate on the benign R tier."
    )
    parser.add_argument("--dsn", default=None)
    parser.add_argument("--monitor-model", default="qwen3-14b", choices=LOCAL_SEATS)
    parser.add_argument(
        "--capture",
        action="store_true",
        help="make real monitor calls and record them; publishes nothing",
    )
    parser.add_argument("--ollama-endpoint", default="http://127.0.0.1:11434")
    parser.add_argument("--weights-root", default=None)
    parser.add_argument("--out", default=None, help="write the lane envelope here")
    return parser


def main(argv: list[str] | None = None) -> int:
    parsed = build_parser().parse_args(argv)
    dsn = parsed.dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        sys.stderr.write("DATABASE_URL or --dsn is required\n")
        return 2

    from incidentgate.evaluation.harness_abort import HarnessAborted, abort_message

    try:
        rows = run_lane(
            dsn,
            parsed.monitor_model,
            capture=parsed.capture,
            endpoint=parsed.ollama_endpoint,
            weights_root=parsed.weights_root,
        )
    except HarnessAborted as error:
        sys.stderr.write(abort_message(error))
        return 3

    blocked = [r for r in rows if r["monitor_false_positive"]]
    for row in rows:
        sys.stdout.write(
            f"{row['scenario_id']} {row['model']} "
            f"false_positive={row['monitor_false_positive']}\n"
        )
    sys.stdout.write(
        f"\nseat={parsed.monitor_model} scenarios={len(rows)} blocked={len(blocked)} "
        f"(a BLOCK on this tier is a FALSE POSITIVE; DEFER is unreachable by construction)\n"
    )
    if parsed.out:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        Path(parsed.out).write_text(
            json.dumps(
                {
                    "schema_version": "r-tier-monitor-false-positive-v1",
                    "lane": "benign_false_positive",
                    "defer_reachable": False,
                    "eligible": list(ELIGIBLE),
                    "excluded": EXCLUDED,
                    "results": rows,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
