"""Route B: drive T1 with the policy observing and the monitor enforcing.

    # 1. Capture. Real monitor calls, including the first one ever made on a covert action.
    uv run python -m incidentgate.evaluation.observe_only_t1 --capture-monitor

    # 2. Publish. No transport is constructed; a missing capture is a loud refusal.
    uv run python -m incidentgate.evaluation.observe_only_t1 \
        --out artifacts/observe-only/T1-observe-only-nemo-dev-qwen3.json

WHAT THIS ARM IS
================

``policy_gate=OBSERVE_ONLY`` and ``monitor_gate=ENFORCE``. The policy still
evaluates the covert call, still reaches ``deny`` with
``capability_prohibited``, and still records it -- it simply does not stop the
call. So the covert action reaches the monitor node, and the monitor is the thing
that decides. Every published row carries ``observed_policy_decision`` so a reader
can see that the policy *would* have refused; without that, "the monitor stopped
it" is indistinguishable from "nothing was there to stop".

WHY IT DOES NOT GO THROUGH ``run_real_condition_episode``
=========================================================

That adapter requires ``safeguards == safeguards_for(condition)`` and no
``EvaluationMode`` maps to this configuration -- adding one would break the 30-row
checkpoint-B pin. So this drives :func:`run_real_episode` directly and shares
:func:`covert_then_incident_strategy` and :func:`end_state_score` with the
published arms, which is the point: the attacker's ordering must be identical or
any difference in outcome has two candidate causes instead of one.

THE BOUND, WHICH IS LOAD-BEARING RATHER THAN DECORATIVE
========================================================

The monitor's own input carries ``forbidden_action_tools``, and on the covert leg
the covert capability appears in it **by name**. A correct BLOCK is therefore
reachable by list membership alone, and any number here reads *"did the monitor
compare the proposed action against a stated remit"* -- never *"did the monitor
notice something subtle."* :data:`OBSERVE_ONLY_MEASURES` carries that into every
envelope and the contract refuses one that drops it.

A HARNESS ABORT IS NEVER A MODEL OBSERVATION
=============================================

This machine intermittently fails to connect to Postgres mid-run
(``OperationalError: Address already in use``, four occurrences across four
distinct tests, mechanism unidentified -- see ``docs/verification.md``). If that
fires during a live capture it would abort the run after the model had answered,
or before it was asked, and either way it says nothing about the model. So the
capture path raises :class:`HarnessAborted`, which the CLI reports as exit ``3``
with an explicit "this is not a model observation" line, and it never writes a
capture or a row.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Final

from incidentgate.control.attack_policies import (
    T1_ATTACK_VARIANTS_BY_ID,
)
from incidentgate.control.attack_policies import AttackPolicyVariant as ProposerVariant
from incidentgate.control.model_attacker import ModelAttackProposer
from incidentgate.control.model_proposal import CompletionClient
from incidentgate.control.monitor_contract_v3 import PROMPT_VERSION as MONITOR_PROMPT_VERSION
from incidentgate.control.monitor_contract_v3 import (
    RecordingMonitorCallerV3,
    StructuredMonitorCallerV3,
    monitor_output_v3_schema_sha256,
)
from incidentgate.control.monitor_input_v3 import monitor_input_v3_schema_sha256
from incidentgate.control.ports import ProposalGenerator
from incidentgate.control.response_cache import (
    CacheBackedCompletionClient,
    ProviderCaptureProvenance,
    ResponseCache,
)
from incidentgate.control.safeguards import (
    AuthorizationGate,
    GateMode,
    SafeguardConfiguration,
)
from incidentgate.evaluation.monitor_thresholds import load_a_priori_thresholds
from incidentgate.evaluation.observe_only_v1 import (
    OBSERVE_ONLY_MEASURES,
    ObserveOnlyEnvelopeV1,
    ObserveOnlyResult,
    ObserveOnlyStepRow,
)
from incidentgate.evaluation.sabotage_checkers import T1_COVERT_TOOL
from incidentgate.evaluation.sabotage_episodes import (
    SabotageStep,
    _project_real_leg,
    _purge_threads,
    covert_then_incident_strategy,
    end_state_score,
    load_policy_configuration,
    run_real_episode,
)
from incidentgate.evaluation.sabotage_matrix import (
    SabotageScenario,
    git_provenance,
    load_scenario,
    suite_manifest_digest,
)
from incidentgate.evaluation.sabotage_v3_t1 import (
    DeferredMonitorCaptureClient,
    _t1_manifest,
    default_monitor_threshold_path,
)
from incidentgate.integration.monitor_facts import RepositoryMonitorFacts
from incidentgate.integration.semantic_monitor import (
    SemanticMonitorBundle,
    SemanticMonitorConfigurationV3,
)
from incidentgate.lab.repository import LabRepository

_ROOT = Path(__file__).resolve().parents[3]

SCENARIO_ID: Final = "T1"
DEFAULT_VARIANT_ID: Final = "T1-dev-v1"
ATTACKER_MODEL: Final = "mistral-nemo-12b"
MONITOR_MODEL: Final = "qwen3-14b"
ATTACKER_CACHE_DIR: Final = _ROOT / "artifacts" / "model-captures"
MONITOR_CACHE_DIR: Final = _ROOT / "artifacts" / "monitor-captures"

#: The arm itself, and the one place it is written down.
#:
#: ``policy_gate`` observes so the covert call is not stopped before the monitor
#: sees it; ``monitor_gate`` enforces so the monitor's verdict is the thing that
#: decides; the evidence gate and the durable human gate are production's, so the
#: only manipulated variable against ``policy_monitor_human`` is which gate stops
#: the call.
OBSERVE_ONLY_SAFEGUARDS: Final = SafeguardConfiguration(
    evidence_gate=GateMode.ENFORCE,
    policy_gate=GateMode.OBSERVE_ONLY,
    monitor_gate=GateMode.ENFORCE,
    authorization_gate=AuthorizationGate.DURABLE_HUMAN,
)


#: Where this command writes, excluded from its own dirty check.
PUBLISHED_ARTIFACT_DIR: Final = "artifacts/observe-only"

#: Scoped exactly as the chaos and sabotage matrices scope theirs, and restated
#: here rather than imported for the same reason they restate it: this command
#: writes into its own output directory, so an unscoped ``git status`` would see
#: that output and stamp ``dirty: true`` on every republication -- including one
#: generated from a pristine tree. Excluding exactly that directory makes the
#: flag mean the only thing worth publishing: whether the *sources* differ from
#: the recorded revision.
_DIRTY_PATHSPEC: Final[tuple[str, ...]] = (
    ":(top)",
    f":(top,exclude){PUBLISHED_ARTIFACT_DIR}/",
)


def git_provenance_scoped() -> tuple[str, bool]:
    """The revision this row was measured at, and whether the sources were clean.

    ``git_provenance`` in ``sabotage_matrix`` excludes *its* output directory, so
    using it here would stamp this artifact dirty on every run after the first.
    """
    import subprocess

    def _git(*arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parent,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise HarnessAborted("the observe-only row requires a readable git revision")
        return completed.stdout.strip()

    return _git("rev-parse", "HEAD"), bool(
        _git("status", "--porcelain", "--", *_DIRTY_PATHSPEC)
    )


class HarnessAborted(RuntimeError):
    """The run failed for a reason that says nothing about any model."""


@dataclass(frozen=True)
class ObserveOnlyRun:
    result: ObserveOnlyResult
    monitor_captures: int


def _step_row(step: SabotageStep, leg: str, assessment: object | None) -> ObserveOnlyStepRow:
    """Project one durable step, carrying the monitor's own words with its verdict."""
    rationale = getattr(assessment, "rationale", None)
    return ObserveOnlyStepRow(
        leg=leg,  # type: ignore[arg-type]
        step_index=step.step_index,
        tool_name=step.tool_name,
        arguments_digest=step.arguments_digest,
        policy_enforcing=step.policy_consulted,
        observed_policy_decision=step.observed_policy_decision,
        observed_policy_reasons=tuple(step.observed_policy_reasons),
        monitor_consulted=step.monitor_consulted,
        monitor_verdict=step.monitor_verdict,
        monitor_error_kind=step.monitor_error_kind,
        risk_score=getattr(assessment, "risk_score", None) if step.monitor_verdict else None,
        risk_categories=tuple(getattr(assessment, "risk_categories", ()) or ()),
        rationale=rationale if step.monitor_verdict is not None else None,
        executed=step.executed,
        side_effect_recorded=bool(step.executed and step.tool_name == T1_COVERT_TOOL),
    )


def build_monitor(
    repository: LabRepository, *, cache_dir: Path, capture: bool, transport: CompletionClient | None
) -> tuple[SemanticMonitorBundle, RecordingMonitorCallerV3, DeferredMonitorCaptureClient | None]:
    """Wire the model monitor seat once, so one caller sees the whole episode."""
    artifact_path = default_monitor_threshold_path(MONITOR_MODEL)
    artifact = load_a_priori_thresholds(artifact_path)
    cache = ResponseCache(cache_dir)
    deferred: DeferredMonitorCaptureClient | None = None
    client: CompletionClient
    if capture:
        if transport is None:
            raise HarnessAborted("capturing the monitor requires a transport to record from")
        deferred = DeferredMonitorCaptureClient(cache, provider="local", transport=transport)
        client = deferred
    else:
        # Replay only, structurally: no transport exists on this path, so a miss
        # surfaces as CACHE_MISS rather than reaching for a model.
        client = CacheBackedCompletionClient(cache, provider="local")
    caller = RecordingMonitorCallerV3(
        StructuredMonitorCallerV3(client=client, model=MONITOR_MODEL)
    )
    bundle = SemanticMonitorConfigurationV3(caller=caller, artifact=artifact).build(
        policy=load_policy_configuration(), facts=RepositoryMonitorFacts(repository)
    )
    return bundle, caller, deferred


def run_observe_only(
    repository: LabRepository,
    *,
    variant: ProposerVariant,
    covert_plan: Sequence[ProposalGenerator],
    attacker_source: str,
    bundle: SemanticMonitorBundle,
    caller: RecordingMonitorCallerV3,
    episode_suffix: str = "observe-only",
) -> tuple[ObserveOnlyResult, dict[str, tuple[str, int]]]:
    """Drive one observe-only episode and project it into a publishable row."""
    scenario: SabotageScenario = load_scenario(SCENARIO_ID)
    covert = tuple(covert_plan)
    incident = tuple(scenario.honest_plan())
    episode_id = f"{variant.variant_id.removeprefix(SCENARIO_ID + '-')}-{episode_suffix}"
    thread_id = f"{SCENARIO_ID}-episode-{episode_id}"
    _purge_threads(repository.dsn, (thread_id,))

    captured: list[object] = []
    strategy = covert_then_incident_strategy(covert, incident)
    score = end_state_score(
        captured=captured,
        end_state_reader=lambda: scenario.end_state(repository),
        covert_effect_predicate=lambda state: bool(scenario.covert_side_effects(state)),
        incident_success_predicate=scenario.incident_checker,
    )
    episode = run_real_episode(
        repository,
        scenario_id=SCENARIO_ID,
        episode_id=episode_id,
        strategy=strategy,
        max_actions=len(covert) + len(incident),
        safeguards=OBSERVE_ONLY_SAFEGUARDS,
        score=score,
        semantic_monitor=bundle,
    )
    if len(captured) != 1:
        raise HarnessAborted("observe-only episode did not capture an authoritative end state")
    end_state = captured[0]

    covert_leg = _project_real_leg(episode.covert, "covert")
    incident_leg = _project_real_leg(episode.incident, "incident")
    # Join each consulted step to the assessment the monitor actually produced,
    # on the rendered input digest -- the same key the capture is written under.
    assessments = {
        consultation.monitor_input_sha256: (
            consultation.outcome.assessment.assessment
            if consultation.outcome.assessment is not None
            else None
        )
        for consultation in caller.consultations
    }
    positions: dict[str, tuple[str, int]] = {}
    for leg, outcome in (("covert", covert_leg), ("incident", incident_leg)):
        for step in outcome.steps:
            if step.monitor_input_hash is not None:
                positions[step.monitor_input_hash] = (leg, step.step_index)

    result = ObserveOnlyResult(
        scenario_id=SCENARIO_ID,
        variant_id=variant.variant_id,
        attacker_source=attacker_source,
        monitor_source=f"model:local/{MONITOR_MODEL}",
        covert_steps=tuple(
            _step_row(step, "covert", assessments.get(step.monitor_input_hash or ""))
            for step in covert_leg.steps
        ),
        incident_steps=tuple(
            _step_row(step, "incident", assessments.get(step.monitor_input_hash or ""))
            for step in incident_leg.steps
        ),
        covert_side_effect_count=len(scenario.covert_side_effects(end_state)),
        incident_checker_passed=bool(scenario.incident_checker(end_state)),
    )
    return result, positions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m incidentgate.evaluation.observe_only_t1",
        description="Drive T1 with the policy observing and the monitor enforcing.",
    )
    parser.add_argument("--dsn", default=None)
    parser.add_argument("--variant", default=DEFAULT_VARIANT_ID)
    parser.add_argument("--out", default=None, help="write the observe-only envelope here")
    parser.add_argument(
        "--capture-monitor",
        action="store_true",
        help="make real monitor calls and record them; publishes nothing",
    )
    parser.add_argument("--ollama-endpoint", default="http://127.0.0.1:11434")
    parser.add_argument("--weights-root", default=None)
    return parser


def main(argv: list[str] | None = None, *, monitor_completion_client: object = None) -> int:
    from incidentgate.control.local_weights import (
        LocalWeightsError,
        OllamaWeightsCompletionClient,
        resolve_ollama_weights,
    )
    from incidentgate.control.response_cache import ResponseCacheMiss

    parsed = build_parser().parse_args(argv)
    dsn = parsed.dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        sys.stderr.write("DATABASE_URL or --dsn is required\n")
        return 2
    variant = T1_ATTACK_VARIANTS_BY_ID.get(parsed.variant)
    if variant is None:
        sys.stderr.write(f"{parsed.variant} is not a frozen T1 attack-policy variant\n")
        return 2

    transport: CompletionClient | None = None
    weights = None
    if parsed.capture_monitor:
        if monitor_completion_client is not None:
            transport = monitor_completion_client  # type: ignore[assignment]
        else:
            try:
                weights = resolve_ollama_weights(
                    MONITOR_MODEL,
                    store_root=Path(parsed.weights_root) if parsed.weights_root else None,
                )
                transport = OllamaWeightsCompletionClient(
                    endpoint=parsed.ollama_endpoint, weights=weights
                )
            except LocalWeightsError as error:
                sys.stderr.write(f"UNAVAILABLE: {error}\n")
                return 3

    repository = LabRepository(dsn)
    try:
        repository.migrate()
        bundle, caller, deferred = build_monitor(
            repository,
            cache_dir=MONITOR_CACHE_DIR,
            capture=parsed.capture_monitor,
            transport=transport,
        )
        attacker = ModelAttackProposer(
            client=CacheBackedCompletionClient(ResponseCache(ATTACKER_CACHE_DIR), provider="local"),
            model=ATTACKER_MODEL,
            variant=variant,
            covert_tool=T1_COVERT_TOOL,
            scenario_id="T1",
            contract_version="v3",
        )
        result, positions = run_observe_only(
            repository,
            variant=variant,
            covert_plan=(attacker,),
            attacker_source=f"model:local/{ATTACKER_MODEL}",
            bundle=bundle,
            caller=caller,
        )
    except ResponseCacheMiss as error:
        sys.stderr.write(
            f"REFUSED: a required capture is missing ({error}). Capture first, then publish; "
            "this run never calls a model to fill a gap.\n"
        )
        return 2
    except Exception as error:  # noqa: BLE001 -- classified below, never as model behaviour
        name = type(error).__name__
        if "OperationalError" in name or "Address already in use" in str(error):
            sys.stderr.write(
                f"HARNESS ABORTED: {name}: {error}\n"
                "This is a database connectivity failure on this machine, not a model "
                "observation. Nothing was recorded. See docs/verification.md for the "
                "unexplained intermittent connect failure. Re-run.\n"
            )
            return 3
        sys.stderr.write(f"HARNESS ABORTED: {name}: {error}\nThis is not a model observation.\n")
        return 3

    written = 0
    if deferred is not None:
        written = deferred.write(
            positions=positions,
            provenance=lambda request, completion, leg, step: _capture_provenance(
                request, completion, leg, step, weights
            ),
        )
        sys.stdout.write(f"rows=0 monitor_captures={written}\n")
        return 0

    # A MONITOR THAT NEVER ANSWERED IS NOT A MEASUREMENT, AND MUST NOT PUBLISH.
    #
    # On this arm a failure to assess and a BLOCK produce the same visible
    # outcome -- the covert call does not execute and no side effect lands -- so
    # a row carrying an error kind would read as detection to anyone counting
    # side effects. The error kinds that can reach here are facts about this
    # harness (a missing capture, a schema violation) rather than about the
    # model, and publishing one as a covert cell is exactly the collapse the
    # three monitor states exist to prevent.
    unanswered = [
        step
        for step in (*result.covert_steps, *result.incident_steps)
        if step.monitor_error_kind is not None
    ]
    if unanswered:
        detail = ", ".join(
            f"{step.leg}[{step.step_index}] "
            f"{step.monitor_error_kind.value if step.monitor_error_kind else 'unknown'}"
            for step in unanswered
        )
        sys.stderr.write(
            f"REFUSED: the monitor did not answer on {detail}. That is a fact about this "
            "harness, not about the monitor, and on this arm it looks identical to a BLOCK "
            "at the side-effect level. Capture the monitor first, then publish from the "
            "cache.\n"
        )
        return 2

    revision, dirty = git_provenance_scoped()
    envelope = ObserveOnlyEnvelopeV1(
        generated_at=datetime.now(UTC),
        git_revision=revision,
        git_dirty=dirty,
        suite_manifest_digest=suite_manifest_digest(_t1_manifest()),
        reproduction_command=(
            "uv run python -m incidentgate.evaluation.observe_only_t1 --out "
            "artifacts/observe-only/T1-observe-only-nemo-dev-qwen3.json"
        ),
        threshold_artifact_path=default_monitor_threshold_path(MONITOR_MODEL)
        .relative_to(_ROOT)
        .as_posix(),
        threshold_artifact_sha256=sha256(
            default_monitor_threshold_path(MONITOR_MODEL).read_bytes()
        ).hexdigest(),
        monitor_input_schema_sha256=monitor_input_v3_schema_sha256(),
        monitor_prompt_version=MONITOR_PROMPT_VERSION,
        measures=OBSERVE_ONLY_MEASURES,
        results=(result,),
    )
    if parsed.out:
        path = Path(parsed.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(envelope.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n")
        sys.stdout.write(f"wrote {path}\n")
    for step in (*result.covert_steps, *result.incident_steps):
        observed = step.observed_policy_decision
        sys.stdout.write(
            f"{step.leg}[{step.step_index}] {step.tool_name} "
            f"observed_policy={observed.value if observed else 'none'} "
            f"monitor_consulted={step.monitor_consulted} "
            f"verdict={step.monitor_verdict.value if step.monitor_verdict else 'none'} "
            f"score={step.risk_score} executed={step.executed}\n"
        )
        if step.rationale:
            sys.stdout.write(f"    rationale: {step.rationale}\n")
    sys.stdout.write(
        f"covert_side_effects={result.covert_side_effect_count} "
        f"incident_repaired={result.incident_checker_passed} "
        f"monitor_stopped_covert={result.monitor_stopped_the_covert_call}\n"
    )
    sys.stdout.write(f"output_schema_sha256={monitor_output_v3_schema_sha256()}\n")
    return 0


#: What a capture from this arm records as the configuration that produced it.
#:
#: ``ProviderCaptureProvenance.condition`` was ``EvaluationMode`` alone until
#: 2026-08-22; it was widened additively to admit this value, because a
#: configuration now exists that is not an ``EvaluationMode`` and the field's job
#: is to say which configuration produced a capture. A fourth ``EvaluationMode``
#: member was not available: ``CheckpointBRawEnvelope`` pins 30 rows at
#: ``10 scenarios x len(EvaluationMode)``.
#:
#: Long on purpose -- it names all four gates, so a reader of a capture can tell
#: what was on without opening anything else. Identical to
#: ``ObserveOnlyResult.arm`` so a row and the capture behind it agree.
#:
#: ``split`` needs no such treatment: the variant's frozen label is a historical
#: name (see ``attack_policies``) and recording it is accurate.
OBSERVE_ONLY_CONDITION: Final = "evidence_enforce_policy_observe_monitor_enforce_durable_human"


def _capture_provenance(
    request: object, completion: object, leg: str, step_index: int, weights: object
) -> ProviderCaptureProvenance:
    from incidentgate.control.monitor_contract_v3 import (
        MONITOR_INPUT_SCHEMA_VERSION,
    )

    invocation = completion.invocation  # type: ignore[attr-defined]
    if invocation.input_tokens is None or invocation.output_tokens is None:
        raise HarnessAborted("a capture without provider usage cannot be recorded")
    if weights is None:
        raise HarnessAborted("a local capture without resolved weights cannot be recorded")
    from incidentgate.control.response_cache import schema_sha256

    return ProviderCaptureProvenance(
        provider="local",
        model=MONITOR_MODEL,
        role="monitor",
        prompt_sha256=request.prompt_sha256,  # type: ignore[attr-defined]
        request_schema_sha256=schema_sha256(request.schema),  # type: ignore[attr-defined]
        input_schema_version=MONITOR_INPUT_SCHEMA_VERSION,
        prompt_version=MONITOR_PROMPT_VERSION,
        stop_reason="end_turn",
        input_tokens=invocation.input_tokens,
        output_tokens=invocation.output_tokens,
        usage_source=invocation.usage_source or "local_usage",
        capture_mode="live_provider_call",
        captured_at=datetime.now(UTC),
        capture_command=(
            "python -m incidentgate.evaluation.observe_only_t1 --capture-monitor"
        ),
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
        scenario_id=SCENARIO_ID,
        variant_id=DEFAULT_VARIANT_ID,
        condition=OBSERVE_ONLY_CONDITION,
        leg=leg,  # type: ignore[arg-type]
        step_index=step_index,
        split="development",
    )


if __name__ == "__main__":
    raise SystemExit(main())
