"""Validated raw-artifact rendering; raw JSON is always the source of truth."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import cast

from triage_agent_lab.contracts import CheckpointBEvaluationResult, CheckpointBRawEnvelope


def load_raw(path: Path) -> CheckpointBRawEnvelope:
    return CheckpointBRawEnvelope.model_validate_json(path.read_bytes())


def render_reports(raw_path: Path, output: Path) -> tuple[Path, Path]:
    raw = load_raw(raw_path)
    digest = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    csv_path, markdown_path = output / "preliminary.csv", output / "preliminary.md"
    fields = ("mode", "runs", "diagnosis_accepted", "action_contract_passed", "final_checker_passed", "safe_resolution", "unsafe_action", "unauthorized_action", "deferred_correctly", "policy_caught", "monitor_caught", "monitor_false_positive", "duplicate_delivery_observed", "duplicate_side_effects", "mean_tool_calls", "p50_latency_ms", "p95_latency_ms", "input_tokens", "output_tokens", "model_cost")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        handle.write(f"# raw_sha256={digest} git_revision={raw.git_revision}\n")
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for mode in raw.results[0].requested_mode.__class__:
            rows = [row for row in raw.results if row.requested_mode is mode]
            latencies = sorted(row.latency_ms for row in rows)
            def csv_rate(attr: str, eligible: str | None = None, values: list[CheckpointBEvaluationResult] = rows) -> str:
                denominator = [r for r in values if eligible is None or getattr(r, eligible) is True]
                return "N/A" if not denominator else f"{sum(bool(getattr(r, attr)) for r in denominator)}/{len(denominator)}"
            def csv_usage(name: str, rowset: list[CheckpointBEvaluationResult] = rows) -> str:
                values = [getattr(row.model_invocation, name) for row in rowset]
                return "N/A" if all(value is None for value in values) else str(sum(cast(int, value) for value in values if value is not None))
            writer.writerow({"mode": mode.value, "runs": len(rows), "diagnosis_accepted": csv_rate("diagnosis_accepted"), "action_contract_passed": csv_rate("action_contract_passed"), "final_checker_passed": csv_rate("final_checker_passed"), "safe_resolution": csv_rate("safe_resolution"), "unsafe_action": csv_rate("unsafe_action"), "unauthorized_action": csv_rate("unauthorized_action"), "deferred_correctly": csv_rate("deferred_correctly", "deferred_eligible"), "policy_caught": csv_rate("policy_caught", "policy_caught_eligible"), "monitor_caught": csv_rate("monitor_caught", "monitor_caught_eligible"), "monitor_false_positive": csv_rate("monitor_false_positive", "monitor_false_positive_eligible"), "duplicate_delivery_observed": sum(r.duplicate_delivery_observed for r in rows), "duplicate_side_effects": sum(r.duplicate_side_effects for r in rows), "mean_tool_calls": sum(row.tool_calls_total for row in rows) / len(rows), "p50_latency_ms": latencies[(len(latencies) - 1) // 2], "p95_latency_ms": latencies[(95 * len(latencies) + 99) // 100 - 1], "input_tokens": csv_usage("input_tokens"), "output_tokens": csv_usage("output_tokens"), "model_cost": "N/A" if all(row.model_invocation.cost is None for row in rows) else str(sum(row.model_invocation.cost or 0 for row in rows))})
    lines = ["# Checkpoint-B evaluation", "", f"Raw SHA-256: `{digest}`", f"Git revision: `{raw.git_revision}`", "", "0 eligible policy/monitor catch rows is N/A, not 0%.", "", "| " + " | ".join(fields) + " |", "|" + "|".join(["---:"] * len(fields)) + "|"]
    for mode in raw.results[0].requested_mode.__class__:
        rows = [row for row in raw.results if row.requested_mode is mode]
        latencies = sorted(row.latency_ms for row in rows)
        def rate(attr: str, eligible: str | None = None, rowset: list[CheckpointBEvaluationResult] = rows) -> str:
            selected = [r for r in rowset if eligible is None or getattr(r, eligible)]
            return "N/A" if not selected else f"{sum(bool(getattr(r, attr)) for r in selected)}/{len(selected)}"
        def usage(name: str, rowset: list[CheckpointBEvaluationResult] = rows) -> str:
            values = [getattr(row.model_invocation, name) for row in rowset]
            return "N/A" if all(value is None for value in values) else str(sum(cast(int, value) for value in values if value is not None))
        values = (mode.value, len(rows), rate("diagnosis_accepted"), rate("action_contract_passed"), rate("final_checker_passed"), rate("safe_resolution"), rate("unsafe_action"), rate("unauthorized_action"), rate("deferred_correctly", "deferred_eligible"), rate("policy_caught", "policy_caught_eligible"), rate("monitor_caught", "monitor_caught_eligible"), rate("monitor_false_positive", "monitor_false_positive_eligible"), sum(row.duplicate_delivery_observed for row in rows), sum(row.duplicate_side_effects for row in rows), sum(row.tool_calls_total for row in rows) / len(rows), latencies[(len(latencies)-1)//2], latencies[(95 * len(latencies)+99)//100-1], usage("input_tokens"), usage("output_tokens"), "N/A" if all(row.model_invocation.cost is None for row in rows) else str(sum(row.model_invocation.cost or 0 for row in rows)))
        lines.append("| " + " | ".join(str(value) for value in values) + " |")
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return csv_path, markdown_path


def write_raw(envelope: CheckpointBRawEnvelope, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    path = output / "raw-results.json"
    path.write_text(json.dumps(envelope.model_dump(mode="json"), sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path
