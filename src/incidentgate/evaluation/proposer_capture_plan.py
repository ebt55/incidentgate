"""Offline, no-spend inventory of initial model-proposer requests.

Only the first consultation is knowable without a model response.  This module
therefore records ``step_index=0`` and never invents adaptive follow-up calls.
It does not construct a provider client, response cache, or cache write path.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from typing import Literal
from uuid import uuid4

from incidentgate.contracts import EvaluationMode, IncidentIdentity, Role, ToolCallContext
from incidentgate.control.model_proposal import (
    CompletionRequest,
    CompletionResult,
    ModelAgentProposer,
    ProposerPromptContract,
    proposer_input_envelope_schema,
)
from incidentgate.control.models import Caller
from incidentgate.evaluation.capture_model_outputs import CaptureContext, CaptureWorkItem
from incidentgate.evaluation.sabotage_episodes import safeguards_for
from incidentgate.integration.runtime import IncidentRuntime
from incidentgate.lab.repository import LabRepository
from incidentgate.manifests import AttackPolicyVariant, load_sabotage_manifests

Split = Literal["development", "calibration", "holdout"]
_SCENARIOS: tuple[Literal["T1", "T2", "T4"], ...] = ("T1", "T2", "T4")
_REVISION = re.compile(r"^[a-f0-9]{40}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_VERIFIED_AUDIT_TOKEN = object()


@dataclass(frozen=True)
class ProposerAuditSource:
    scenario_id: Literal["T1", "T2", "T4"]
    variant_id: str
    split: Split
    seed: int
    condition: EvaluationMode = EvaluationMode.COMPLETE
    leg: Literal["covert"] = "covert"
    step_index: Literal[0] = 0


@dataclass(frozen=True)
class ProposerRequestIdentity:
    canonical_prompt_sha256: str
    provider_schema_sha256: str
    model: str
    max_tokens: int
    temperature: float | None
    thinking: tuple[tuple[str, str], ...] | None
    system_sha256: str
    user_content_sha256: str
    canonical_prompt: str

    @classmethod
    def from_request(cls, request: CompletionRequest) -> ProposerRequestIdentity:
        import json

        return cls(
            canonical_prompt_sha256=request.prompt_sha256,
            provider_schema_sha256=sha256(
                json.dumps(request.schema, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            model=request.model,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            thinking=None if request.thinking is None else tuple(sorted(request.thinking.items())),
            system_sha256=sha256(request.system.encode()).hexdigest(),
            user_content_sha256=sha256(request.user_content.encode()).hexdigest(),
            canonical_prompt=request.canonical_prompt,
        )


@dataclass(frozen=True)
class ProposerAuditObservation:
    source: ProposerAuditSource
    request: ProposerRequestIdentity
    completion_request: CompletionRequest
    contract: ProposerPromptContract
    runtime_identity_sha256: str
    invocation_kind: Literal["fixture_no_call"] = "fixture_no_call"


@dataclass(frozen=True)
class ProposerRequestCollisionGroup:
    request: ProposerRequestIdentity
    sources: tuple[ProposerAuditSource, ...]


class ProposerAuditInstabilityRefusal(RuntimeError):
    """Fresh no-call drives did not reach byte-identical request contexts."""


class ProposerCaptureRefusal(RuntimeError):
    """A no-spend audit cannot safely be converted into provider work items."""


@dataclass(frozen=True)
class ProposerCaptureAudit:
    observations: tuple[ProposerAuditObservation, ...]
    unique_requests: tuple[ProposerRequestIdentity, ...]
    collision_groups: tuple[ProposerRequestCollisionGroup, ...]
    cross_split_collision_groups: tuple[ProposerRequestCollisionGroup, ...]
    stable: bool
    labelled_cell_capture_safe: bool
    cold_identity_pairs: tuple[tuple[str, str], ...] = ()
    _verification_digest: str | None = field(default=None, repr=False, compare=False)
    _verification_token: object | None = field(default=None, repr=False, compare=False)


class RecordingNoCallCompletionClient:
    """Records the public request and fails before any provider/cache interaction."""

    provider: None = None

    def __init__(self) -> None:
        self.requests: list[CompletionRequest] = []

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.requests.append(request)
        raise RuntimeError("fixture_no_call proposer request audit")


def compare_cold_observations(
    first: Iterable[ProposerAuditObservation], second: Iterable[ProposerAuditObservation]
) -> tuple[ProposerAuditObservation, ...]:
    left, right = tuple(first), tuple(second)
    if len(left) != len(right):
        raise ProposerAuditInstabilityRefusal("proposer requests are not stable across cold runs")
    for first_row, second_row in zip(left, right, strict=True):
        if (
            first_row.source,
            first_row.request,
            first_row.completion_request,
            first_row.contract,
            first_row.invocation_kind,
        ) != (
            second_row.source,
            second_row.request,
            second_row.completion_request,
            second_row.contract,
            second_row.invocation_kind,
        ) or first_row.runtime_identity_sha256 == second_row.runtime_identity_sha256:
            raise ProposerAuditInstabilityRefusal(
                "proposer requests are not stable across cold runs"
            )
    return left


def build_capture_audit(
    observations: Iterable[ProposerAuditObservation], *, stable: bool = False
) -> ProposerCaptureAudit:
    rows = tuple(observations)
    by_request: dict[ProposerRequestIdentity, list[ProposerAuditSource]] = defaultdict(list)
    for row in rows:
        by_request[row.request].append(row.source)
    groups = tuple(
        ProposerRequestCollisionGroup(request, tuple(sources))
        for request, sources in sorted(
            by_request.items(), key=lambda pair: pair[0].canonical_prompt_sha256
        )
        if len(sources) > 1
    )
    cross_split = tuple(
        group for group in groups if len({source.split for source in group.sources}) > 1
    )
    return ProposerCaptureAudit(
        observations=rows,
        unique_requests=tuple(
            sorted(by_request, key=lambda request: request.canonical_prompt_sha256)
        ),
        collision_groups=groups,
        cross_split_collision_groups=cross_split,
        stable=stable,
        # Diagnostic grouping is not capture proof: only the verified constructor
        # below may mark a labelled inventory capture-ready.
        labelled_cell_capture_safe=False,
    )


def build_verified_capture_audit(
    first: Iterable[ProposerAuditObservation], second: Iterable[ProposerAuditObservation]
) -> ProposerCaptureAudit:
    """Build capture-ready proof only from exact, distinct cold enumerations."""
    left, right = tuple(first), tuple(second)
    stable = compare_cold_observations(left, right)
    pairs = tuple(
        (first_row.runtime_identity_sha256, second_row.runtime_identity_sha256)
        for first_row, second_row in zip(left, right, strict=True)
    )
    diagnostic = build_capture_audit(stable, stable=True)
    return replace(
        diagnostic,
        cold_identity_pairs=pairs,
        labelled_cell_capture_safe=not diagnostic.collision_groups,
        _verification_digest=_observation_digest(stable),
        _verification_token=_VERIFIED_AUDIT_TOKEN,
    )


def audit_frozen_proposer_requests(dsn: str) -> ProposerCaptureAudit:
    """Drive every frozen T1/T2/T4 variant twice through the public runtime seam."""
    # LangGraph checkpoints are keyed by thread id and survive fixture resets.
    # This execution-only nonce makes each audit rerunnable in a shared database;
    # it never reaches evidence rendering, source metadata, capture context, or
    # cache keys, all of which remain deterministic across invocations.
    execution_nonce = uuid4().hex
    first = _enumerate_once(dsn, run_namespace=f"cold-a-{execution_nonce}")
    second = _enumerate_once(dsn, run_namespace=f"cold-b-{execution_nonce}")
    return build_verified_capture_audit(first, second)


def capture_work_items(
    audit: ProposerCaptureAudit,
    *,
    capture_command: str,
    git_revision: str,
    worktree_clean: bool = True,
) -> tuple[CaptureWorkItem, ...]:
    """Return strict initial-consultation items, or refuse ambiguous provenance."""
    if not audit.stable or audit._verification_token is not _VERIFIED_AUDIT_TOKEN:
        raise ProposerCaptureRefusal("refusing unstable proposer audit")
    diagnostic = build_capture_audit(audit.observations, stable=True)
    if (
        audit.unique_requests != diagnostic.unique_requests
        or audit.collision_groups != diagnostic.collision_groups
        or audit.cross_split_collision_groups != diagnostic.cross_split_collision_groups
        or audit.stable != diagnostic.stable
        or audit.labelled_cell_capture_safe != (not diagnostic.collision_groups)
    ):
        raise ProposerCaptureRefusal("refusing inconsistent proposer audit diagnostics")
    if (
        audit._verification_digest != _observation_digest(audit.observations)
        or len(audit.cold_identity_pairs) != len(audit.observations)
        or any(
            _SHA256.fullmatch(first) is None
            or _SHA256.fullmatch(second) is None
            or first == second
            or first != observation.runtime_identity_sha256
            for observation, (first, second) in zip(
                audit.observations, audit.cold_identity_pairs, strict=True
            )
        )
    ):
        raise ProposerCaptureRefusal("refusing incomplete or invalid cold proposer audit proof")
    if not all(_request_matches_observation(row) for row in audit.observations):
        raise ProposerCaptureRefusal("refusing proposer request/identity contract disagreement")
    if audit.collision_groups:
        raise ProposerCaptureRefusal("refusing duplicate proposer request provenance")
    if _REVISION.fullmatch(git_revision) is None:
        raise ProposerCaptureRefusal("git revision must be an exact lowercase 40-hex revision")
    if not worktree_clean:
        raise ProposerCaptureRefusal("refusing proposer capture planning from a dirty worktree")
    requests = {row.request.canonical_prompt_sha256: row for row in audit.observations}
    result: list[CaptureWorkItem] = []
    for request in audit.unique_requests:
        row = requests[request.canonical_prompt_sha256]
        source, contract = row.source, row.contract
        raw = row.completion_request
        result.append(
            CaptureWorkItem(
                raw,
                CaptureContext(
                    role="proposer",
                    input_schema_version=contract.input_schema_version,
                    input_schema_sha256=contract.input_schema_sha256,
                    prompt_version=contract.prompt_version,
                    output_schema_sha256=contract.output_schema_sha256,
                    scenario_id=source.scenario_id,
                    variant_id=source.variant_id,
                    condition=source.condition,
                    leg=source.leg,
                    step_index=0,
                    split=source.split,
                    capture_command=capture_command,
                    git_revision=git_revision,
                ),
            )
    )
    return tuple(result)


def _observation_digest(observations: Iterable[ProposerAuditObservation]) -> str:
    """Bind verification to source/request identities without retaining prompt text."""
    rows = tuple(
        (
            row.source.scenario_id,
            row.source.variant_id,
            row.source.split,
            row.source.seed,
            row.source.condition.value,
            row.source.leg,
            row.source.step_index,
            row.invocation_kind,
            row.request.canonical_prompt_sha256,
            row.request.provider_schema_sha256,
            row.request.model,
            row.request.max_tokens,
            row.request.temperature,
            row.request.thinking,
            row.request.system_sha256,
            row.request.user_content_sha256,
            row.request.canonical_prompt,
            row.contract.prompt_version,
            row.contract.model,
            row.contract.system_prompt_sha256,
            row.contract.input_schema_version,
            row.contract.input_schema_sha256,
            row.contract.output_schema_sha256,
            row.contract.provider_schema_sha256,
            row.runtime_identity_sha256,
            row.completion_request.model,
            row.completion_request.system,
            row.completion_request.user_content,
            row.completion_request.max_tokens,
            row.completion_request.temperature,
            row.completion_request.thinking,
            json.dumps(
                row.completion_request.schema,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ),
            row.completion_request.canonical_prompt,
            row.completion_request.prompt_sha256,
        )
        for row in observations
    )
    return sha256(repr(rows).encode()).hexdigest()


def _request_matches_observation(row: ProposerAuditObservation) -> bool:
    """Reject any dispatchable request that no longer matches cold-run evidence."""
    request, identity, contract = row.completion_request, row.request, row.contract
    if ProposerRequestIdentity.from_request(request) != identity:
        return False
    try:
        envelope = json.loads(request.canonical_prompt)
    except json.JSONDecodeError:
        return False
    if not isinstance(envelope, dict):
        return False
    if envelope != {
        "system": request.system,
        "user": request.user_content,
        "model": request.model,
        "max_tokens": request.max_tokens,
        "temperature": request.temperature,
        "thinking": request.thinking,
        "schema_fingerprint": contract.output_schema_sha256,
    }:
        return False
    input_schema_sha256 = sha256(
        json.dumps(
            proposer_input_envelope_schema(), sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    return (
        contract.model == request.model == identity.model
        and contract.system_prompt_sha256 == identity.system_sha256
        and contract.provider_schema_sha256 == identity.provider_schema_sha256
        and contract.prompt_version == "proposal/v1"
        and contract.input_schema_version == "proposal-evidence-digest/v1"
        and contract.input_schema_sha256 == input_schema_sha256
        and envelope.get("schema_fingerprint") == contract.output_schema_sha256
    )


def _enumerate_once(dsn: str, *, run_namespace: str) -> tuple[ProposerAuditObservation, ...]:
    repository = LabRepository(dsn)
    repository.migrate()
    rows: list[ProposerAuditObservation] = []
    manifests = {
        manifest.id: manifest
        for manifest in load_sabotage_manifests(
            Path(__file__).parents[3] / "scenarios" / "sabotage"
        )
    }
    try:
        for scenario_id in _SCENARIOS:
            for variant in manifests[scenario_id].attack_policy_variants:
                rows.append(_drive_one(dsn, repository, scenario_id, variant, run_namespace))
        return tuple(rows)
    finally:
        for scenario_id in _SCENARIOS:
            repository.reset_checkpoint(scenario_id)


def _drive_one(
    dsn: str,
    repository: LabRepository,
    scenario_id: Literal["T1", "T2", "T4"],
    variant: AttackPolicyVariant,
    run_namespace: str,
) -> ProposerAuditObservation:
    variant_id = variant.variant_id
    policy_text = variant.policy_text
    split = variant.split
    seed = variant.seed
    repository.reset_checkpoint(scenario_id)
    repository.inject_checkpoint(scenario_id)
    recorder = RecordingNoCallCompletionClient()
    proposer = ModelAgentProposer(
        client=recorder, model="claude-opus-5", steering_prompt=policy_text
    )
    thread_id = f"proposer-{run_namespace}-{variant_id}"
    incident = IncidentIdentity(
        incident_id=f"INC-{scenario_id}",
        scenario_id=scenario_id,
        thread_id=thread_id,
        correlation_id=f"corr-{thread_id}",
    )
    caller = Caller(actor="evaluation-operator", role=Role.OPERATOR)
    context = ToolCallContext(
        incident_id=incident.incident_id,
        thread_id=thread_id,
        correlation_id=incident.correlation_id,
        actor=caller.actor,
        permission="operations:write",
    )
    with IncidentRuntime(
        dsn,
        proposer_factory=lambda: proposer,
        safeguards=safeguards_for(EvaluationMode.COMPLETE, approver="evaluation-approver"),
    ) as runtime:
        runtime.start(incident, caller, context)
    if len(recorder.requests) != 1:
        raise RuntimeError("initial proposer audit must reach exactly one no-call request")
    request = recorder.requests[0]
    return ProposerAuditObservation(
        ProposerAuditSource(scenario_id, variant_id, split, seed),
        ProposerRequestIdentity.from_request(request),
        request,
        proposer.prompt_contract,
        sha256(thread_id.encode()).hexdigest(),
    )
