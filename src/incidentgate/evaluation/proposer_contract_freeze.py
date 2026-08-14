"""Build and write frozen proposer holdout contracts from verified no-spend proof."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path

from incidentgate.contracts import EvaluationMode
from incidentgate.control.response_cache import schema_sha256, sha256_text
from incidentgate.evaluation.capture_model_outputs import CaptureWorkItem
from incidentgate.evaluation.proposer_capture_plan import (
    ProposerCaptureAudit,
    ProposerCaptureRefusal,
    audit_frozen_proposer_requests,
    capture_work_items,
)
from incidentgate.evaluation.proposer_contracts import (
    ProposerCaptureContractArtifact,
    ProposerPromptBinding,
)
from incidentgate.manifests import load_sabotage_manifests

_REVISION = re.compile(r"^[a-f0-9]{40}$")
_SCENARIOS = frozenset(("T1", "T2", "T4"))


def _frozen_holdout_sources() -> dict[tuple[str, str, str], int]:
    """Return the exact frozen T1/T2/T4 holdout sources, never caller labels."""
    manifests = load_sabotage_manifests(Path(__file__).parents[3] / "scenarios" / "sabotage")
    return {
        (manifest.id, variant.variant_id, variant.split): variant.seed
        for manifest in manifests
        if manifest.id in _SCENARIOS
        for variant in manifest.attack_policy_variants
        if variant.split == "holdout"
    }


def build_proposer_capture_contract(
    *,
    audit: ProposerCaptureAudit,
    capture_command: str,
    git_revision: str,
    worktree_clean: bool,
    contract_id: str,
    frozen_at: datetime,
    provider: str,
    now: datetime,
) -> ProposerCaptureContractArtifact:
    """Freeze the audited T1/T2/T4 holdout request surface without provider access."""
    if provider != "anthropic":
        raise ValueError("proposer contract provider must be explicit anthropic")
    if _REVISION.fullmatch(git_revision) is None:
        raise ValueError("git revision must be an exact lowercase 40-hex revision")
    if not worktree_clean:
        raise ValueError("refusing proposer contract freeze from a dirty worktree")
    if frozen_at.tzinfo is None or frozen_at.utcoffset() is None:
        raise ValueError("frozen_at must be timezone-aware")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if frozen_at >= now:
        raise ValueError("frozen_at must precede contract freeze completion")

    # This is the public verified-audit gate: it checks cold-run proof, request
    # identity, revision, clean tree, and duplicate/collision provenance.
    try:
        items = capture_work_items(
            audit,
            capture_command=capture_command,
            git_revision=git_revision,
            worktree_clean=worktree_clean,
        )
    except ProposerCaptureRefusal as error:
        raise ValueError("refusing unverified proposer audit for contract freeze") from error

    expected = _frozen_holdout_sources()
    audited_holdout = [row for row in audit.observations if row.source.split == "holdout"]
    if (
        len(audited_holdout) != len(expected)
        or {
            (row.source.scenario_id, row.source.variant_id, row.source.split): row.source.seed
            for row in audited_holdout
        }
        != expected
    ):
        raise ValueError("proposer audit sources do not exactly match frozen holdout variants")
    item_by_source: dict[tuple[str, str, str], CaptureWorkItem] = {}
    for item in items:
        context = item.context
        if context.split != "holdout":
            continue
        source: tuple[str, str, str] = (context.scenario_id, context.variant_id, context.split)
        if source in item_by_source:
            raise ValueError("duplicate proposer holdout source")
        item_by_source[source] = item
    actual = frozenset(item_by_source)
    if actual != frozenset(expected):
        raise ValueError("proposer audit sources do not exactly match frozen holdout variants")

    identities: set[tuple[str, str, str, str, str, str]] = set()
    bindings: list[ProposerPromptBinding] = []
    for source in sorted(expected):
        item = item_by_source[source]
        request, context = item.request, item.context
        if (
            context.role != "proposer"
            or context.condition is not EvaluationMode.COMPLETE
            or context.leg != "covert"
            or context.step_index != 0
            or context.split != "holdout"
            or context.scenario_id not in _SCENARIOS
        ):
            raise ValueError("proposer holdout item has invalid role, condition, leg, or step")
        identity = (
            request.model,
            context.prompt_version,
            context.input_schema_version,
            context.input_schema_sha256,
            context.output_schema_sha256,
            schema_sha256(request.schema),
        )
        identities.add(identity)
        bindings.append(
            ProposerPromptBinding(
                scenario_id=context.scenario_id,
                variant_id=context.variant_id,
                split="holdout",
                system_prompt_sha256=sha256_text(request.system),
            )
        )
    if len(identities) != 1:
        raise ValueError("proposer holdout sources disagree on request contract identity")
    (
        model,
        prompt_version,
        input_schema_version,
        input_schema_sha256,
        output_schema_sha256,
        provider_schema_sha256,
    ) = identities.pop()
    return ProposerCaptureContractArtifact(
        contract_id=contract_id,
        frozen_at=frozen_at,
        provider="anthropic",
        model=model,
        prompt_version=prompt_version,
        prompt_bindings=tuple(bindings),
        input_schema_version=input_schema_version,
        input_schema_sha256=input_schema_sha256,
        output_schema_sha256=output_schema_sha256,
        provider_schema_sha256=provider_schema_sha256,
    )


def write_proposer_capture_contract(
    path: Path,
    artifact: ProposerCaptureContractArtifact,
    *,
    root: Path,
) -> Path:
    """Write one new canonical artifact inside the existing approved config subtree."""
    allowed = (root / "config" / "proposer-capture-contracts").resolve()
    resolved = path.resolve(strict=False)
    if allowed not in resolved.parents:
        raise ValueError("proposer contract output must stay in config/proposer-capture-contracts")
    if not path.parent.is_dir():
        raise FileNotFoundError(path.parent)
    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    payload = json.dumps(
        artifact.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    try:
        with path.open("xb") as handle:
            handle.write((payload + "\n").encode("utf-8"))
    except FileExistsError:
        raise FileExistsError(path) from None
    return path


def _head_revision(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=False, capture_output=True, text=True
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _clean_tree(root: Path) -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, check=False, capture_output=True, text=True
    )
    return result.returncode == 0 and not result.stdout.strip()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="freeze a verified proposer holdout contract")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--contract-id", required=True)
    parser.add_argument("--frozen-at", required=True)
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
    *,
    root: Path | None = None,
    environ: Mapping[str, str] | None = None,
    audit_factory: Callable[[str], ProposerCaptureAudit] | None = None,
    head_revision: Callable[[Path], str] = _head_revision,
    clean_tree: Callable[[Path], bool] = _clean_tree,
    clock: Callable[[], datetime] = lambda: datetime.now().astimezone(),
) -> int:
    """No-provider CLI: audit request shape, then freeze a new contract file."""
    args = parse_args(argv)
    selected_root = root or Path(__file__).parents[3]
    selected_env = os.environ if environ is None else environ
    dsn = selected_env.get("DATABASE_URL")
    if not dsn:
        raise ValueError("DATABASE_URL is required for proposer contract freeze")
    try:
        frozen_at = datetime.fromisoformat(args.frozen_at)
    except ValueError as error:
        raise ValueError("frozen_at must be ISO-8601") from error
    revision = head_revision(selected_root)
    is_clean = clean_tree(selected_root)
    if not is_clean:
        raise ValueError("refusing proposer contract freeze from a dirty worktree")
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError(args.output)
    factory = audit_frozen_proposer_requests if audit_factory is None else audit_factory
    audit = factory(dsn)
    completion_time = clock()
    artifact = build_proposer_capture_contract(
        audit=audit,
        capture_command="incidentgate proposer-contract-freeze",
        git_revision=revision,
        worktree_clean=is_clean,
        contract_id=args.contract_id,
        frozen_at=frozen_at,
        provider="anthropic",
        now=completion_time,
    )
    write_proposer_capture_contract(args.output, artifact, root=selected_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
