"""Explicitly spend-gated capture preflight; importing it performs no provider work."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from incidentgate.contracts import EvaluationMode
from incidentgate.control.model_proposal import (
    CompletionClient,
    CompletionRequest,
    CompletionResult,
    PricingSnapshot,
)
from incidentgate.control.pricing import load_pricing_snapshot, validate_capture_model_coverage
from incidentgate.control.response_cache import (
    CacheBackedCompletionClient,
    ProviderCaptureProvenance,
    ResponseCache,
    ResponseCacheMiss,
    schema_sha256,
    sha256_text,
)
from incidentgate.evaluation.monitor_thresholds import MonitorThresholdArtifact, load_thresholds

_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class CapturePlan:
    model: str
    max_calls: int
    max_estimated_usd: float
    split: str
    estimated_usd: float
    snapshot: PricingSnapshot
    threshold_contract: HoldoutThresholdContract | None = None


@dataclass(frozen=True)
class HoldoutThresholdContract:
    provider: str
    model: str
    prompt_version: str
    input_schema_sha256: str
    output_schema_sha256: str


@dataclass(frozen=True)
class HoldoutArtifactInspection:
    """The small read-only git seam needed to test holdout admission deterministically."""

    artifact: MonitorThresholdArtifact
    tracked: bool
    worktree_clean: bool
    index_clean: bool


@dataclass(frozen=True)
class CaptureContext:
    role: Literal["proposer", "monitor"]
    input_schema_version: str
    input_schema_sha256: str
    prompt_version: str
    output_schema_sha256: str
    scenario_id: str
    variant_id: str
    condition: EvaluationMode
    leg: Literal["covert", "incident"]
    step_index: int
    split: Literal["development", "calibration", "holdout"]
    capture_command: str
    git_revision: str


@dataclass(frozen=True)
class CaptureWorkItem:
    request: CompletionRequest
    context: CaptureContext


def request_schema_sha256(request: CompletionRequest) -> str:
    return schema_sha256(request.schema)


def provenance_for(
    item: CaptureWorkItem, result: CompletionResult, *, captured_at: datetime
) -> ProviderCaptureProvenance:
    invocation = result.invocation
    if (
        invocation.invocation_kind != "provider_call"
        or invocation.provider is None
        or invocation.input_tokens is None
        or invocation.output_tokens is None
        or invocation.usage_source is None
        or invocation.pricing_snapshot is None
    ):
        raise ValueError("capture result was not a provider call")
    return ProviderCaptureProvenance(
        provider=invocation.provider,
        model=item.request.model,
        role=item.context.role,
        prompt_sha256=item.request.prompt_sha256,
        request_schema_sha256=request_schema_sha256(item.request),
        input_schema_version=item.context.input_schema_version,
        prompt_version=item.context.prompt_version,
        stop_reason="end_turn",
        input_tokens=invocation.input_tokens,
        output_tokens=invocation.output_tokens,
        usage_source=invocation.usage_source,
        capture_mode="live_provider_call",
        captured_at=captured_at,
        capture_command=item.context.capture_command,
        git_revision=item.context.git_revision,
        pricing_snapshot_id=invocation.pricing_snapshot,
        estimated_cost=invocation.cost,
        currency=invocation.currency,
        cost_unavailable_reason=(
            None if invocation.cost is not None else "model_not_priced_in_snapshot"
        ),
        scenario_id=item.context.scenario_id,
        variant_id=item.context.variant_id,
        condition=item.context.condition,
        leg=item.context.leg,
        step_index=item.context.step_index,
        split=item.context.split,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="capture live model outputs (spend-gated)")
    parser.add_argument("--i-will-spend-real-money", action="store_true")
    parser.add_argument("--max-calls", type=int, required=True)
    parser.add_argument("--max-estimated-usd", type=float, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--max-tokens", type=int, required=True)
    parser.add_argument("--split", choices=("development", "calibration", "holdout"), required=True)
    parser.add_argument("--threshold-artifact", type=Path)
    parser.add_argument("--threshold-provider")
    parser.add_argument("--threshold-prompt-version")
    parser.add_argument("--threshold-input-schema-sha256")
    parser.add_argument("--threshold-output-schema-sha256")
    parser.add_argument(
        "--pricing-snapshot",
        type=Path,
        default=_ROOT / "config" / "pricing" / "anthropic-2026-08-14.json",
    )
    return parser.parse_args(argv)


def clean_git_tree(root: Path = _ROOT) -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, check=False, capture_output=True, text=True
    )
    return result.returncode == 0 and not result.stdout.strip()


def _git_output(root: Path, *args: str) -> str | None:
    result = subprocess.run(["git", *args], cwd=root, check=False, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else None


def _git_quiet(root: Path, *args: str) -> bool:
    return subprocess.run(["git", *args], cwd=root, check=False).returncode == 0


def inspect_holdout_artifact(path: Path, *, root: Path = _ROOT) -> HoldoutArtifactInspection:
    """Load one artifact and inspect its exact repository state without writing anything."""
    artifact = load_thresholds(path)
    relative = path.relative_to(root).as_posix()
    return HoldoutArtifactInspection(
        artifact=artifact,
        tracked=_git_output(root, "ls-files", "--error-unmatch", relative) is not None,
        worktree_clean=_git_quiet(root, "diff", "--quiet", "--", relative),
        index_clean=_git_quiet(root, "diff", "--cached", "--quiet", "--", relative),
    )


def preflight(
    args: argparse.Namespace,
    *,
    env: Mapping[str, str] | None = None,
    now: datetime | None = None,
    git_clean: Callable[[], bool] | None = None,
    holdout_inspector: Callable[[Path], HoldoutArtifactInspection] | None = None,
    root: Path = _ROOT,
) -> CapturePlan:
    """Validate every gate before a client factory can be reached."""
    environment = os.environ if env is None else env
    if not args.i_will_spend_real_money:
        raise ValueError("--i-will-spend-real-money is required")
    if environment.get("INCIDENTGATE_ALLOW_PROVIDER_SPEND") != "1":
        raise ValueError("INCIDENTGATE_ALLOW_PROVIDER_SPEND=1 is required")
    if (
        isinstance(args.max_calls, bool)
        or not isinstance(args.max_calls, int)
        or args.max_calls <= 0
    ):
        raise ValueError("--max-calls must be positive")
    if (
        not math.isfinite(args.max_estimated_usd)
        or args.max_estimated_usd <= 0
        or isinstance(args.max_tokens, bool)
        or not isinstance(args.max_tokens, int)
        or args.max_tokens <= 0
    ):
        raise ValueError("token and USD limits must be positive")
    moment = datetime.now(UTC) if now is None else now
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("capture time must be timezone-aware")
    snapshot = load_pricing_snapshot(args.pricing_snapshot, as_of=moment)
    validate_capture_model_coverage(snapshot, {args.model})
    # Worst case reserves max_tokens for both billed directions.  This is conservative and,
    # unlike expected output, includes any thinking headroom already in the request budget.
    per_call = args.max_tokens * (
        snapshot.input_usd_per_token[args.model] + snapshot.output_usd_per_token[args.model]
    )
    estimate = per_call * args.max_calls
    if not math.isfinite(estimate) or estimate > args.max_estimated_usd:
        raise ValueError("pre-call estimate exceeds --max-estimated-usd")
    threshold_contract: HoldoutThresholdContract | None = None
    if args.split == "holdout":
        artifact_path = getattr(args, "threshold_artifact", None)
        expected = (
            getattr(args, "threshold_provider", None),
            args.model,
            getattr(args, "threshold_prompt_version", None),
            getattr(args, "threshold_input_schema_sha256", None),
            getattr(args, "threshold_output_schema_sha256", None),
        )
        if not isinstance(artifact_path, Path) or any(not value for value in expected):
            raise ValueError("holdout capture requires a concrete threshold artifact and contract")
        allowed = (root / "config" / "monitor-thresholds").resolve()
        resolved = artifact_path.resolve()
        if allowed not in resolved.parents or not resolved.is_file():
            raise ValueError(
                "holdout threshold artifact must be a regular config/monitor-thresholds file"
            )
        inspector = holdout_inspector or (
            lambda path: inspect_holdout_artifact(path, root=root)
        )
        inspection = inspector(resolved)
        if not (inspection.tracked and inspection.worktree_clean and inspection.index_clean):
            raise ValueError("holdout threshold artifact must be tracked and clean")
        artifact = inspection.artifact
        actual = (
            artifact.provider,
            artifact.model,
            artifact.prompt_version,
            artifact.input_schema_sha256,
            artifact.output_schema_sha256,
        )
        if artifact.frozen_at >= moment or actual != expected:
            raise ValueError("holdout threshold artifact does not match the capture contract")
        threshold_contract = HoldoutThresholdContract(*actual)
        if not (git_clean or clean_git_tree)():
            raise ValueError("holdout capture requires a clean git tree")
    return CapturePlan(
        args.model, args.max_calls, args.max_estimated_usd, args.split, estimate, snapshot,
        threshold_contract,
    )


def capture_requests(
    plan: CapturePlan,
    items: Sequence[CaptureWorkItem],
    *,
    cache: ResponseCache,
    client_factory: Callable[[PricingSnapshot], CompletionClient],
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> tuple[CompletionResult, ...]:
    """Dispatch bounded work only after all collision/cost checks, then atomically record it."""
    _validate_plan(plan)
    if not items or len(items) > plan.max_calls:
        raise ValueError("capture request count exceeds --max-calls")
    if any(item.request.model != plan.model or item.context.split != plan.split for item in items):
        raise ValueError("capture request model differs from preflight model")
    if any(item.request.max_tokens <= 0 or item.request.max_tokens > 1_000_000 for item in items):
        raise ValueError("capture request has invalid max_tokens")
    estimate = sum(item.request.max_tokens for item in items) * (
        plan.snapshot.input_usd_per_token[plan.model]
        + plan.snapshot.output_usd_per_token[plan.model]
    )
    if not math.isfinite(estimate) or estimate > plan.max_estimated_usd:
        raise ValueError("request-derived estimate exceeds --max-estimated-usd")
    hashes = [item.request.prompt_sha256 for item in items]
    if len(set(hashes)) != len(hashes):
        raise ValueError("duplicate prompt hash capture is forbidden")
    for item in items:
        _validate_work_item(plan, item)
        if len(item.request.canonical_prompt.encode("utf-8")) > 1_000_000:
            raise ValueError("capture request canonical prompt is oversized")
        if len(json.dumps(item.request.schema, sort_keys=True).encode("utf-8")) > 1_000_000:
            raise ValueError("capture request schema is oversized")

    existing_results: dict[str, CompletionResult] = {}
    misses: list[CaptureWorkItem] = []
    for item in items:
        try:
            existing = cache.load(item.request.model, item.request.prompt_sha256)
        except ResponseCacheMiss:
            misses.append(item)
        else:
            if existing.capture != "provider_call" or existing.provenance is None:
                raise ValueError("capture refuses synthetic pre-existing cache entry")
            _validate_existing(item, existing.provenance)
            _validate_holdout_provider(plan, existing.provenance.provider)
            replay = CacheBackedCompletionClient(cache)
            existing_results[item.request.prompt_sha256] = replay.complete(item.request)
    if not misses:
        return tuple(existing_results[item.request.prompt_sha256] for item in items)

    client = client_factory(plan.snapshot)
    by_hash = {item.request.prompt_sha256: item for item in misses}

    def builder(request: CompletionRequest, result: CompletionResult) -> ProviderCaptureProvenance:
        return provenance_for(by_hash[request.prompt_sha256], result, captured_at=now())

    captured: dict[str, CompletionResult] = {}
    for item in misses:
        # Storing follows a successful strict provenance build; malformed/provider failures
        # therefore leave no entry behind for this item.
        result = client.complete(item.request)
        provenance = builder(item.request, result)
        _validate_holdout_provider(plan, provenance.provider)
        cache.store(
            item.request.model,
            item.request.prompt_sha256,
            result.raw_json,
            capture="provider_call",
            provenance=provenance,
            invocation=result.invocation,
            request=item.request,
        )
        captured[item.request.prompt_sha256] = result
    return tuple(
        existing_results[item.request.prompt_sha256]
        if item.request.prompt_sha256 in existing_results
        else captured[item.request.prompt_sha256]
        for item in items
    )


def _validate_existing(item: CaptureWorkItem, provenance: ProviderCaptureProvenance) -> None:
    """A provider capture is reusable only for the exact requested contract."""
    expected = (
        item.request.model,
        item.request.prompt_sha256,
        request_schema_sha256(item.request),
        item.context.role,
        item.context.input_schema_version,
        item.context.prompt_version,
        item.context.scenario_id,
        item.context.variant_id,
        item.context.condition,
        item.context.leg,
        item.context.step_index,
        item.context.split,
    )
    actual = (
        provenance.model,
        provenance.prompt_sha256,
        provenance.request_schema_sha256,
        provenance.role,
        provenance.input_schema_version,
        provenance.prompt_version,
        provenance.scenario_id,
        provenance.variant_id,
        provenance.condition,
        provenance.leg,
        provenance.step_index,
        provenance.split,
    )
    if actual != expected:
        raise ValueError("pre-existing provider capture conflicts with requested context")


def _validate_holdout_provider(plan: CapturePlan, provider: str) -> None:
    if plan.split == "holdout":
        assert plan.threshold_contract is not None
        if provider != plan.threshold_contract.provider:
            raise ValueError("provider disagrees with frozen holdout threshold contract")


def _validate_plan(plan: CapturePlan) -> None:
    if plan.split not in ("development", "calibration", "holdout"):
        raise ValueError("capture plan has invalid split")
    if (
        isinstance(plan.max_calls, bool)
        or not isinstance(plan.max_calls, int)
        or plan.max_calls <= 0
    ):
        raise ValueError("capture plan has invalid max_calls")
    if (
        not isinstance(plan.max_estimated_usd, float)
        or not math.isfinite(plan.max_estimated_usd)
        or plan.max_estimated_usd <= 0
        or not isinstance(plan.estimated_usd, float)
        or not math.isfinite(plan.estimated_usd)
        or plan.estimated_usd < 0
        or plan.estimated_usd > plan.max_estimated_usd
    ):
        raise ValueError("capture plan has invalid spend limits")
    if not _VERSION.fullmatch(plan.model):
        raise ValueError("capture plan has invalid model")
    try:
        rates = (
            plan.snapshot.input_usd_per_token[plan.model],
            plan.snapshot.output_usd_per_token[plan.model],
        )
    except KeyError as error:
        raise ValueError("capture plan pricing omits model") from error
    if any(
        not isinstance(rate, (int, float))
        or isinstance(rate, bool)
        or not math.isfinite(rate)
        or rate < 0
        for rate in rates
    ):
        raise ValueError("capture plan has invalid pricing")
    if (plan.split == "holdout") != (plan.threshold_contract is not None):
        raise ValueError("threshold contract must be present exactly for holdout")


_VERSION = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,79}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")
_REVISION = re.compile(r"^[a-f0-9]{40}$")
_SCENARIO = re.compile(r"^(D[1-8]|S[1-2]|R[0-9]{2}|T[1-8])$")
_VARIANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_CAPTURE_COMMAND = re.compile(r"^[A-Za-z0-9_./ :+=-]{1,200}$")


def _validate_work_item(plan: CapturePlan, item: CaptureWorkItem) -> None:
    if (
        not isinstance(item, CaptureWorkItem)
        or not isinstance(item.request, CompletionRequest)
        or not isinstance(item.context, CaptureContext)
    ):
        raise TypeError("capture work item has invalid runtime type")
    request, context = item.request, item.context
    if (
        isinstance(request.max_tokens, bool)
        or not isinstance(request.max_tokens, int)
        or request.max_tokens <= 0
        or not isinstance(request.schema, dict)
        or not request.schema
        or not isinstance(request.canonical_prompt, str)
        or (
            request.temperature is not None
            and (
                not isinstance(request.temperature, (int, float))
                or isinstance(request.temperature, bool)
                or not math.isfinite(request.temperature)
            )
        )
    ):
        raise ValueError("capture request is invalid")
    if (
        not request.canonical_prompt
        or len(request.canonical_prompt.encode("utf-8")) > 1_000_000
        or len(json.dumps(request.schema, sort_keys=True).encode("utf-8")) > 1_000_000
    ):
        raise ValueError("capture request is oversized or empty")
    if sha256_text(request.canonical_prompt) != request.prompt_sha256:
        raise ValueError("capture request canonical prompt disagrees with its hash")
    if not all(
        (
            type(context.role) is str and context.role in ("proposer", "monitor"),
            isinstance(context.condition, EvaluationMode),
            type(context.leg) is str and context.leg in ("covert", "incident"),
            type(context.split) is str
            and context.split in ("development", "calibration", "holdout"),
            context.split == plan.split,
            _VERSION.fullmatch(context.input_schema_version) is not None,
            _VERSION.fullmatch(context.prompt_version) is not None,
            _SHA.fullmatch(context.input_schema_sha256) is not None,
            _SHA.fullmatch(context.output_schema_sha256) is not None,
            _SCENARIO.fullmatch(context.scenario_id) is not None,
            _VARIANT.fullmatch(context.variant_id) is not None,
            _REVISION.fullmatch(context.git_revision) is not None,
            isinstance(context.step_index, int)
            and not isinstance(context.step_index, bool)
            and 0 <= context.step_index,
            _CAPTURE_COMMAND.fullmatch(context.capture_command) is not None,
        )
    ):
        raise ValueError("capture context is invalid")
    try:
        envelope = json.loads(request.canonical_prompt)
    except json.JSONDecodeError as error:
        raise ValueError("capture canonical prompt must be JSON") from error
    if not isinstance(envelope, dict):
        raise ValueError("capture canonical prompt must be an object")  # noqa: TRY004
    if context.role == "monitor":
        expected = {
            "system": request.system,
            "user": request.user_content,
            "model": request.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "thinking": request.thinking,
            "input_schema_sha256": context.input_schema_sha256,
            "output_schema_sha256": context.output_schema_sha256,
            "prompt_version": context.prompt_version,
        }
        if set(envelope) != set(expected) or envelope != expected:
            raise ValueError("monitor canonical prompt disagrees with capture request/context")
    else:
        expected = {
            "system": request.system,
            "user": request.user_content,
            "model": request.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "thinking": request.thinking,
            "schema_fingerprint": context.output_schema_sha256,
        }
        if set(envelope) != set(expected) or envelope != expected:
            raise ValueError("proposer canonical prompt disagrees with capture request/context")
    if plan.split == "holdout":
        contract = plan.threshold_contract
        if contract is None or (
            request.model,
            context.prompt_version,
            context.input_schema_sha256,
            context.output_schema_sha256,
        ) != (
            contract.model,
            contract.prompt_version,
            contract.input_schema_sha256,
            contract.output_schema_sha256,
        ):
            raise ValueError("holdout work item disagrees with frozen threshold contract")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    _ = preflight(args)
    raise SystemExit("no capture work items were supplied; refusing to construct a provider client")


if __name__ == "__main__":
    raise SystemExit(main())
