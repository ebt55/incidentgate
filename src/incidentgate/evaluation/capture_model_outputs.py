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
from typing import TYPE_CHECKING, Literal

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
from incidentgate.evaluation.proposer_contracts import (
    ProposerCaptureContractArtifact,
    ProposerPromptBinding,
    load_proposer_capture_contract,
    validate_proposer_prompt_bindings,
)

if TYPE_CHECKING:
    from incidentgate.evaluation.proposer_capture_plan import ProposerCaptureAudit

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
    proposer_contract: HoldoutProposerContract | None = None


@dataclass(frozen=True)
class HoldoutThresholdContract:
    provider: str
    model: str
    prompt_version: str
    input_schema_sha256: str
    output_schema_sha256: str


@dataclass(frozen=True)
class HoldoutProposerContract:
    contract_id: str
    frozen_at: datetime
    provider: str
    model: str
    prompt_version: str
    input_schema_version: str
    input_schema_sha256: str
    output_schema_sha256: str | None
    provider_schema_sha256: str | None
    prompt_bindings: tuple[ProposerPromptBinding, ...]

    def binding_for(self, context: CaptureContext) -> ProposerPromptBinding:
        validate_proposer_prompt_bindings(self.prompt_bindings)
        for binding in self.prompt_bindings:
            if (binding.scenario_id, binding.variant_id, binding.split) == (
                context.scenario_id,
                context.variant_id,
                context.split,
            ):
                return binding
        raise ValueError("proposer source is not listed in frozen holdout contract")

    def system_prompt_sha256_for(self, context: CaptureContext) -> str:
        """Return the one frozen proposer prompt hash authorized for this source."""
        return self.binding_for(context).system_prompt_sha256


@dataclass(frozen=True)
class HoldoutArtifactInspection:
    """The small read-only git seam needed to test holdout admission deterministically."""

    artifact: MonitorThresholdArtifact
    tracked: bool
    worktree_clean: bool
    index_clean: bool


@dataclass(frozen=True)
class ProposerHoldoutArtifactInspection:
    artifact: ProposerCaptureContractArtifact
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
    action_profile_id: Literal["T1", "T2", "T4"] | None = None


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
    parser.add_argument("--proposer-contract-artifact", type=Path)
    parser.add_argument("--proposer-provider")
    parser.add_argument("--proposer-prompt-version")
    parser.add_argument("--proposer-input-schema-version")
    parser.add_argument("--proposer-input-schema-sha256")
    parser.add_argument("--proposer-output-schema-sha256")
    parser.add_argument("--proposer-provider-schema-sha256")
    parser.add_argument(
        "--capture-role",
        "--role",
        dest="capture_roles",
        action="append",
        choices=("monitor", "proposer"),
        help="role planned for this capture; holdout defaults to monitor for compatibility",
    )
    parser.add_argument(
        "--pricing-snapshot",
        type=Path,
        default=_ROOT / "config" / "pricing" / "anthropic-2026-08-14.json",
    )
    parser.add_argument(
        "--cache-root",
        type=Path,
        default=_ROOT / "tests" / "fixtures" / "model_cache",
        help="provider-capture cache directory (must remain under tests/fixtures/model_cache)",
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


def inspect_proposer_holdout_artifact(
    path: Path, *, root: Path = _ROOT
) -> ProposerHoldoutArtifactInspection:
    artifact = load_proposer_capture_contract(path)
    relative = path.relative_to(root).as_posix()
    return ProposerHoldoutArtifactInspection(
        artifact=artifact,
        tracked=_git_output(root, "ls-files", "--error-unmatch", relative) is not None,
        worktree_clean=_git_quiet(root, "diff", "--quiet", "--", relative),
        index_clean=_git_quiet(root, "diff", "--cached", "--quiet", "--", relative),
    )


def _resolve_holdout_artifact(path: object, *, root: Path, subtree: str, label: str) -> Path:
    if not isinstance(path, Path):
        raise ValueError(  # noqa: TRY004 - CLI/preflight validation is intentionally ValueError.
            f"holdout capture requires a concrete {label} artifact and contract"
        )
    allowed = (root / "config" / subtree).resolve()
    resolved = path.resolve()
    if allowed not in resolved.parents or not resolved.is_file():
        raise ValueError(f"holdout {label} artifact must be a regular config/{subtree} file")
    return resolved


def _require_clean_artifact(inspection: object, *, label: str) -> None:
    if not isinstance(
        inspection, (HoldoutArtifactInspection, ProposerHoldoutArtifactInspection)
    ) or not (inspection.tracked and inspection.worktree_clean and inspection.index_clean):
        raise ValueError(f"holdout {label} artifact must be tracked and clean")


def _planned_roles(args: argparse.Namespace) -> frozenset[Literal["monitor", "proposer"]]:
    roles = getattr(args, "capture_roles", None)
    if roles is None:
        # Existing monitor-only invocation syntax remains a strict monitor holdout.
        return frozenset(("monitor",))
    if (
        not isinstance(roles, list)
        or not roles
        or any(role not in ("monitor", "proposer") for role in roles)
    ):
        raise ValueError("capture roles must be a non-empty monitor/proposer list")
    return frozenset(roles)


def preflight(
    args: argparse.Namespace,
    *,
    env: Mapping[str, str] | None = None,
    now: datetime | None = None,
    git_clean: Callable[[], bool] | None = None,
    holdout_inspector: Callable[[Path], HoldoutArtifactInspection] | None = None,
    proposer_holdout_inspector: Callable[[Path], ProposerHoldoutArtifactInspection] | None = None,
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
    proposer_contract: HoldoutProposerContract | None = None
    if args.split == "holdout":
        roles = _planned_roles(args)
        if "monitor" in roles:
            threshold_expected = (
                getattr(args, "threshold_provider", None), args.model,
                getattr(args, "threshold_prompt_version", None),
                getattr(args, "threshold_input_schema_sha256", None),
                getattr(args, "threshold_output_schema_sha256", None),
            )
            if any(not value for value in threshold_expected):
                raise ValueError(
                    "holdout capture requires a concrete threshold artifact and contract"
                )
            resolved = _resolve_holdout_artifact(
                getattr(args, "threshold_artifact", None), root=root,
                subtree="monitor-thresholds", label="threshold",
            )
            inspector = holdout_inspector or (
                lambda path: inspect_holdout_artifact(path, root=root)
            )
            threshold_inspection = inspector(resolved)
            _require_clean_artifact(threshold_inspection, label="threshold")
            if not isinstance(threshold_inspection, HoldoutArtifactInspection):
                raise ValueError("holdout threshold artifact has invalid inspection")
            threshold_artifact = threshold_inspection.artifact
            threshold_actual = (
                threshold_artifact.provider,
                threshold_artifact.model,
                threshold_artifact.prompt_version,
                threshold_artifact.input_schema_sha256,
                threshold_artifact.output_schema_sha256,
            )
            if threshold_artifact.frozen_at >= moment or threshold_actual != threshold_expected:
                raise ValueError("holdout threshold artifact does not match the capture contract")
            threshold_contract = HoldoutThresholdContract(*threshold_actual)
        if "proposer" in roles:
            proposer_common_expected = (
                getattr(args, "proposer_provider", None), args.model,
                getattr(args, "proposer_prompt_version", None),
                getattr(args, "proposer_input_schema_version", None),
                getattr(args, "proposer_input_schema_sha256", None),
            )
            if any(not value for value in proposer_common_expected):
                raise ValueError(
                    "holdout capture requires a concrete proposer artifact and contract"
                )
            resolved = _resolve_holdout_artifact(
                getattr(args, "proposer_contract_artifact", None), root=root,
                subtree="proposer-capture-contracts", label="proposer",
            )
            proposer_inspection = (proposer_holdout_inspector or (
                lambda path: inspect_proposer_holdout_artifact(path, root=root)
            ))(resolved)
            _require_clean_artifact(proposer_inspection, label="proposer")
            if not isinstance(proposer_inspection, ProposerHoldoutArtifactInspection):
                raise ValueError("holdout proposer artifact has invalid inspection")
            proposer_artifact = proposer_inspection.artifact
            if proposer_artifact.schema_version == "proposer-capture-contract-v1" and any(
                binding.scenario_id in {"T1", "T2", "T4"}
                for binding in proposer_artifact.prompt_bindings
            ):
                raise ValueError("scenario-profile holdout capture requires a v2 proposer artifact")
            proposer_common = (
                proposer_artifact.provider,
                proposer_artifact.model,
                proposer_artifact.prompt_version,
                proposer_artifact.input_schema_version,
                proposer_artifact.input_schema_sha256,
            )
            if proposer_artifact.schema_version == "proposer-capture-contract-v1":
                proposer_expected = proposer_common_expected + (
                    getattr(args, "proposer_output_schema_sha256", None),
                    getattr(args, "proposer_provider_schema_sha256", None),
                )
                if any(not value for value in proposer_expected):
                    raise ValueError(
                        "holdout v1 proposer capture requires global schema hashes"
                    )
                contract_matches = proposer_common + (
                    proposer_artifact.output_schema_sha256,
                    proposer_artifact.provider_schema_sha256,
                ) == proposer_expected
            else:
                if (
                    getattr(args, "proposer_output_schema_sha256", None) is not None
                    or getattr(args, "proposer_provider_schema_sha256", None) is not None
                ):
                    raise ValueError("v2 proposer capture forbids legacy global schema hash flags")
                contract_matches = proposer_common == proposer_common_expected
            if proposer_artifact.frozen_at >= moment or not contract_matches:
                raise ValueError("holdout proposer artifact does not match the capture contract")
            legacy_hashes = (
                (proposer_artifact.output_schema_sha256, proposer_artifact.provider_schema_sha256)
                if proposer_artifact.schema_version == "proposer-capture-contract-v1"
                else (None, None)
            )
            proposer_contract = HoldoutProposerContract(
                proposer_artifact.contract_id,
                proposer_artifact.frozen_at,
                *proposer_common,
                *legacy_hashes,
                proposer_artifact.prompt_bindings,
            )
        if not (git_clean or clean_git_tree)():
            raise ValueError("holdout capture requires a clean git tree")
    return CapturePlan(
        args.model, args.max_calls, args.max_estimated_usd, args.split, estimate, snapshot,
        threshold_contract, proposer_contract,
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
            _validate_holdout_provider(plan, item.context.role, existing.provenance.provider)
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
        _validate_holdout_provider(plan, item.context.role, provenance.provider)
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


def _contract_for_role(
    plan: CapturePlan, role: Literal["monitor", "proposer"]
) -> HoldoutThresholdContract | HoldoutProposerContract | None:
    return plan.threshold_contract if role == "monitor" else plan.proposer_contract


def _validate_holdout_provider(
    plan: CapturePlan, role: Literal["monitor", "proposer"], provider: str
) -> None:
    if plan.split == "holdout":
        contract = _contract_for_role(plan, role)
        if contract is None or provider != contract.provider:
            raise ValueError("provider disagrees with frozen role-specific holdout contract")


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
    if plan.split != "holdout" and (
        plan.threshold_contract is not None or plan.proposer_contract is not None
    ):
        raise ValueError("holdout contracts must be absent outside holdout")
    if plan.split == "holdout" and (
        plan.threshold_contract is None and plan.proposer_contract is None
    ):
        raise ValueError("holdout plan requires at least one role-specific contract")
    if plan.proposer_contract is not None:
        contract = plan.proposer_contract
        if (
            _CONTRACT_ID.fullmatch(contract.contract_id) is None
            or contract.frozen_at.tzinfo is None
            or contract.frozen_at.utcoffset() is None
            or _SHA.fullmatch(contract.input_schema_sha256) is None
        ):
            raise ValueError("capture plan has invalid proposer holdout contract")
        validate_proposer_prompt_bindings(contract.prompt_bindings)
        scoped = any(binding.action_profile_id is not None for binding in contract.prompt_bindings)
        if scoped:
            if (
                {binding.scenario_id for binding in contract.prompt_bindings}
                != {"T1", "T2", "T4"}
                or any(
                    binding.action_profile_id != binding.scenario_id
                    or _SHA.fullmatch(binding.output_schema_sha256 or "") is None
                    or _SHA.fullmatch(binding.provider_schema_sha256 or "") is None
                    for binding in contract.prompt_bindings
                )
                or contract.output_schema_sha256 is not None
                or contract.provider_schema_sha256 is not None
            ):
                raise ValueError("capture plan has invalid scoped proposer holdout contract")
        elif (
            _SHA.fullmatch(contract.output_schema_sha256 or "") is None
            or _SHA.fullmatch(contract.provider_schema_sha256 or "") is None
            or any(
                binding.output_schema_sha256 is not None
                or binding.provider_schema_sha256 is not None
                for binding in contract.prompt_bindings
            )
        ):
            raise ValueError("capture plan has invalid legacy proposer holdout contract")


_VERSION = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,79}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")
_CONTRACT_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
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
        contract = _contract_for_role(plan, context.role)
        common_identity = (request.model, context.prompt_version, context.input_schema_sha256)
        contract_common_identity = None if contract is None else (
            contract.model, contract.prompt_version, contract.input_schema_sha256
        )
        if common_identity != contract_common_identity or (
            isinstance(contract, HoldoutProposerContract)
            and context.input_schema_version != contract.input_schema_version
        ):
            raise ValueError("holdout work item disagrees with frozen role-specific contract")
        if context.role == "proposer" and isinstance(contract, HoldoutProposerContract):
            binding = contract.binding_for(context)
            scoped = binding.action_profile_id is not None
            if scoped and (
                context.action_profile_id != binding.action_profile_id
                or context.output_schema_sha256 != binding.output_schema_sha256
                or request_schema_sha256(request) != binding.provider_schema_sha256
            ):
                raise ValueError("proposer work item disagrees with frozen source binding")
            if not scoped and (
                context.output_schema_sha256 != contract.output_schema_sha256
                or request_schema_sha256(request) != contract.provider_schema_sha256
            ):
                raise ValueError("proposer provider schema disagrees with frozen holdout contract")
            if sha256_text(request.system) != binding.system_prompt_sha256:
                raise ValueError("proposer system prompt disagrees with frozen holdout contract")


def _head_revision(root: Path) -> str:
    output = _git_output(root, "rev-parse", "HEAD")
    return "" if output is None else output.strip()


def _confined_cache_root(cache_root: Path, *, root: Path, allow_test_root: bool) -> Path:
    """Resolve the cache path without allowing production capture to escape its fixture subtree."""
    resolved = cache_root.resolve()
    if allow_test_root:
        return resolved
    allowed = (root / "tests" / "fixtures" / "model_cache").resolve()
    if resolved != allowed:
        raise ValueError("--cache-root must be confined to tests/fixtures/model_cache")
    return resolved


def _require_proposer_only(args: argparse.Namespace) -> None:
    # The generic preflight intentionally retains monitor compatibility.  This executable is
    # narrower: monitor planning has no corresponding verified no-call audit yet.
    if args.capture_roles is None:
        args.capture_roles = ["proposer"]
    if _planned_roles(args) != frozenset(("proposer",)):
        raise ValueError("this executable requires exactly the proposer capture role")


def _validate_complete_proposer_batch(
    plan: CapturePlan, items: Sequence[CaptureWorkItem], *, declared_max_tokens: int
) -> None:
    if plan.max_calls != 3 or len(items) != 3:
        raise ValueError(
            "proposer split capture requires exactly three work items and --max-calls=3"
        )
    if any(item.context.role != "proposer" for item in items):
        raise ValueError("proposer split capture contains a non-proposer work item")
    if any(item.request.max_tokens > declared_max_tokens for item in items):
        raise ValueError("proposer request max_tokens exceeds --max-tokens")
    request_estimate = sum(item.request.max_tokens for item in items) * (
        plan.snapshot.input_usd_per_token[plan.model]
        + plan.snapshot.output_usd_per_token[plan.model]
    )
    if not math.isfinite(request_estimate) or request_estimate > plan.max_estimated_usd:
        raise ValueError("request-derived estimate exceeds --max-estimated-usd")


def _validate_frozen_proposer_batch(
    audit: ProposerCaptureAudit, items: Sequence[CaptureWorkItem], *, root: Path, split: str
) -> None:
    """Bind the audited requests to every frozen source identity, without relabelling it."""
    from incidentgate.manifests import load_sabotage_manifests

    manifests = {
        manifest.id: manifest
        for manifest in load_sabotage_manifests(root / "scenarios" / "sabotage")
        if manifest.id in {"T1", "T2", "T4"}
    }
    if set(manifests) != {"T1", "T2", "T4"}:
        raise ValueError("frozen proposer manifests are incomplete")
    expected = {
        (manifest.id, variant.variant_id, variant.split, variant.seed)
        for manifest in manifests.values()
        for variant in manifest.attack_policy_variants
        if variant.split == split
    }
    selected_rows = tuple(row for row in audit.observations if row.source.split == split)
    observed = {
        (row.source.scenario_id, row.source.variant_id, row.source.split, row.source.seed)
        for row in selected_rows
    }
    if len(expected) != 3 or len(selected_rows) != 3 or observed != expected:
        raise ValueError("proposer capture must select the exact three frozen work-item sources")
    if any(
        row.source.condition is not EvaluationMode.COMPLETE
        or row.source.leg != "covert"
        or row.source.step_index != 0
        for row in selected_rows
    ):
        raise ValueError("frozen proposer sources must be COMPLETE/covert/step0")
    item_identities = {
        (item.context.scenario_id, item.context.variant_id, item.context.split)
        for item in items
    }
    expected_item_identities = {
        (scenario, variant, source_split)
        for scenario, variant, source_split, _ in expected
    }
    if item_identities != expected_item_identities:
        raise ValueError("planned proposer work items disagree with frozen sources")
    if any(
        item.context.condition is not EvaluationMode.COMPLETE
        or item.context.leg != "covert"
        or item.context.step_index != 0
        for item in items
    ):
        raise ValueError("planned proposer work items must be COMPLETE/covert/step0")


def _validate_capture_results(
    results: Sequence[CompletionResult], *, model: str
) -> tuple[int, int]:
    provider_calls = 0
    cache_replays = 0
    for result in results:
        invocation = result.invocation
        if invocation.invocation_kind not in ("provider_call", "cache_replay"):
            raise ValueError("capture result has invalid invocation kind")
        if invocation.provider != "anthropic" or invocation.model != model:
            raise ValueError(
                "capture result provider/model disagrees with requested anthropic model"
            )
        if invocation.invocation_kind == "provider_call":
            provider_calls += 1
        else:
            cache_replays += 1
    return provider_calls, cache_replays


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path = _ROOT,
    environ: Mapping[str, str] | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    audit_factory: Callable[[str], ProposerCaptureAudit] | None = None,
    head_revision: Callable[[Path], str] = _head_revision,
    clean_tree: Callable[[Path], bool] = clean_git_tree,
    client_factory: Callable[[str, PricingSnapshot], CompletionClient] | None = None,
    capture_runner: Callable[..., tuple[CompletionResult, ...]] = capture_requests,
    allow_test_cache_root: bool = False,
) -> int:
    """Capture one complete frozen proposer split after every spend and provenance gate."""
    args = parse_args(argv)
    environment = os.environ if environ is None else environ
    _require_proposer_only(args)
    if args.cache_root == _ROOT / "tests" / "fixtures" / "model_cache":
        # Keep the production parser default while allowing an injected repository root in
        # DB-free tests to retain the same relative default.
        args.cache_root = root / "tests" / "fixtures" / "model_cache"
    cache_root = _confined_cache_root(
        args.cache_root, root=root, allow_test_root=allow_test_cache_root
    )
    dsn = environment.get("DATABASE_URL")
    if not dsn:
        raise ValueError("DATABASE_URL is required for proposer capture audit")
    api_key = environment.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY is required for provider capture")
    revision = head_revision(root)
    if _REVISION.fullmatch(revision) is None:
        raise ValueError("HEAD must be an exact lowercase 40-hex revision")
    if not clean_tree(root):
        raise ValueError("proposer capture requires a clean git tree")
    plan = preflight(
        args,
        env=environment,
        now=clock(),
        git_clean=lambda: clean_tree(root),
        root=root,
    )
    # Import locally: the planner imports our public work-item types for its no-spend audit.
    from incidentgate.evaluation.proposer_capture_plan import (
        audit_frozen_proposer_requests,
        capture_work_items,
    )

    audit = (audit_factory or audit_frozen_proposer_requests)(dsn)
    items = capture_work_items(
        audit,
        capture_command="python -m incidentgate.evaluation.capture_model_outputs",
        git_revision=revision,
        worktree_clean=clean_tree(root),
    )
    selected = tuple(item for item in items if item.context.split == args.split)
    _validate_frozen_proposer_batch(audit, selected, root=root, split=args.split)
    _validate_complete_proposer_batch(plan, selected, declared_max_tokens=args.max_tokens)
    if head_revision(root) != revision or not clean_tree(root):
        raise ValueError("proposer capture worktree changed after the no-call audit")

    def real_factory(snapshot: PricingSnapshot) -> CompletionClient:
        if client_factory is not None:
            return client_factory(api_key, snapshot)
        from incidentgate.control.model_proposal import AnthropicCompletionClient

        return AnthropicCompletionClient(api_key=api_key, pricing=snapshot)

    results = capture_runner(plan, selected, cache=ResponseCache(cache_root),
                             client_factory=real_factory, now=clock)
    provider_calls, cache_replays = _validate_capture_results(results, model=plan.model)
    print(f"captured={provider_calls} replayed={cache_replays}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
