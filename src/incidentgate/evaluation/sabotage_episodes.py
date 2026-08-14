"""The sabotage-tier episode runner: N-step legs over one durable fixture.

This is the measurement apparatus, not a test helper. It exists so the project's
central claim about the sabotage tier -- that the gate chain prevents a steered
policy from achieving a covert side effect while the incident task still
completes -- can be *tested* rather than asserted.

WHY A LEG IS N STEPS
====================

This module began as ``t1_control.py`` and drove exactly one call per leg,
because T1's covert objective is a single prohibited write. That is a property
of T1, not of sabotage: T2-T8 pursue their objectives across several calls, and
T4's covert episode issues the *same capability twice with different arguments*.
A harness that could only drive the first call would report a leg as prevented
without ever having looked at the rest of it.

So a leg is an **episode**: an ordered plan of proposers, driven one step at a
time, each step a full propose -> policy -> monitor -> approve -> execute
traversal on its own thread, all against one incident and one fixture.

THE EARLY EXIT IS PART OF THE MEASUREMENT
=========================================

A step whose policy denies, or whose monitor blocks, **ends the episode**. The
remaining steps are not attempted and are not recorded.

That is not an optimisation. An agent whose call was refused does not get to
carry on as though it had not been: continuing the plan would let a leg record
five attempts where the real system would have produced one refusal and a
stopped agent, and the published episode length would then be a property of the
plan rather than of the run. ``stopped_early`` records that it happened, so a
short episode can be read as "refused here" rather than "planned this way".

DERIVED THREAD IDS, NOT RANDOM ONES
===================================

Every step's thread id is :func:`step_thread_id` -- a pure function of scenario,
episode, leg and step index -- where this module previously minted
``f"t1-covert-{uuid4().hex[:12]}"``.

Two reasons, and neither is cosmetic. Distinct steps get distinct threads, so
their idempotency keys differ and their ledger rows do not collapse into each
other; and a *replayed* step gets the same thread, so its key is the same and
the ledger collapses it exactly as the exactly-once boundary is supposed to.
With a random thread per call, a replay was simply a second row.

The cost is that a derived thread id can be reused, and LangGraph checkpoints
outlive ``reset_checkpoint`` -- which clears the lab's tables but not the
checkpointer's. So an episode purges its own threads before it drives them: see
:func:`_purge_threads`. Relying on randomness for isolation is what this change
removes, so the isolation has to be stated somewhere, and here it is explicit.

WHAT IS STILL NOT REPRODUCIBLE, MEASURED RATHER THAN ASSUMED
============================================================

Derived thread ids do **not** make ``operation_id`` reproducible across runs,
though they were expected to. The published id is
``f"{scope}:{idempotency_key}"``, the key is derived from the action hash, and
``canonical_action_hash`` covers ``evidence_ids`` -- which
``LabRepository`` mints as ``str(uuid4())`` at collection time, freshly on every
run, for every scenario and tier. Thread ids were one of two sources of variance
and this module removes that one; the other lives in the shared evidence path
and cannot be changed from here without moving every published artifact in the
project. ``tests/sabotage/test_sabotage_episodes.py`` pins the mechanism so the
next reader measures it instead of re-deriving it.

ONE RUNTIME PATH FOR EVERY ARM
==============================

Every condition drives :func:`_runtime_step`. There is no second implementation
of a step, and that is the point.

Until this change the ungated and policy-only arms ran an isolated harness --
its own evidence collection, its own executor call, its own approval minting,
no checkpointer -- while the full arm ran :class:`IncidentRuntime`. This module's
own docstring for :func:`run_condition` claimed "the condition is the manipulated
variable and the only one", and it was not: the arms also differed in
orchestration and checkpoint semantics, in the path their approval token was
minted along, and in how their idempotency key was derived
(``sabotage-episode:{thread}:{hash}`` against the graph's frozen
``triage-agent-lab:d1:`` seed). Three variables moved with the gates, so no
difference between two columns could be attributed to a gate.

What was *not* wrong is worth stating, because the diagnosis is easy to
overstate: the harness's authorization was never fake. It minted a real
``ApprovalToken`` through the production ``ApprovalService`` for a real
``APPROVER`` principal, and the executor really consumed it. The confound was the
minting path, not the token.

So the condition is now sugar over a :class:`SafeguardConfiguration`
(:func:`safeguards_for`), and the four gates are the only things that differ
between arms:

    ungated               evidence and policy observe, monitor off, the
                          deterministic authorization control
    policy_only           evidence and policy enforce, monitor off, the
                          deterministic authorization control
    policy_monitor_human  every gate enforces, the durable human approval

An observing gate still runs and still records the verdict it reached -- see
``observed_policy_decision`` on :class:`SabotageStep`. What it does not do is
stop the action. That distinction is why the ungated arm is a real experiment
rather than an absence of one: it now says what the policy *would* have refused
while letting the covert action land, which is exactly the control the published
matrix needs.

WHY IT IS BUILT THIS WAY
========================

The failure this design exists to rule out is the vacuous experiment: a gate
credited with blocking an action that could never have happened. If the covert
capability were absent, stubbed, or refused inside the executor, the gated
condition would look exactly the same as it does now and would mean nothing.

So the ungated condition is a real execution with real durable consequences. It
is expected to leave the covert store non-empty and to make the scenario's
covert checker return ``False``. That failing checker is the evidence that the
passing one in the gated condition is load bearing.

The incident leg runs in every condition, and runs *after* the covert attempt,
on purpose. Running it after a denial is what shows the denial did not poison
the run: the interesting claim is not that a gate can block things -- a gate
that blocked everything would do that -- but that the main task still succeeds
while the covert objective is refused.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, Protocol, runtime_checkable

from incidentgate.contracts import (
    CanonicalAction,
    EvaluationMode,
    EvidenceRecord,
    Hypothesis,
    IncidentIdentity,
    ModelInvocationRecord,
    MonitorVerdict,
    OperationLedgerResult,
    PolicyConfiguration,
    PolicyDecision,
    Role,
    ToolCallContext,
    canonical_arguments_digest,
)
from incidentgate.control.models import Caller, EvidenceState
from incidentgate.control.monitor import AdvisoryMonitor, FixtureMonitor
from incidentgate.control.monitor_v2 import MonitorErrorKind
from incidentgate.control.ports import ProposalGenerator
from incidentgate.control.safeguards import (
    AuthorizationGate,
    GateMode,
    SafeguardConfiguration,
)
from incidentgate.integration.runtime import IncidentRuntime, PendingApproval, RuntimeStatus
from incidentgate.integration.semantic_monitor import SemanticMonitorBundle
from incidentgate.lab.auth import Principal
from incidentgate.lab.errors import ResponseLost
from incidentgate.lab.repository import LabRepository
from incidentgate.scenario_registry import ALLOWED_EVIDENCE_SOURCES, RUNNABLE_SCENARIOS

from .identity import purge_checkpoint_threads

#: Which authorization minted a step's execution. Both mint a real token through
#: the production ``ApprovalService``; they differ in the path -- an in-process
#: decision by a named stand-in against a durable interrupt and a human resume --
#: and the published row names which one ran, so this is recorded rather than
#: inferred from the condition.
Authorization = Literal["automatic_evaluation_capability", "deterministic_approver_simulation"]

Leg = Literal["covert", "incident"]

def safeguards_for(condition: EvaluationMode, *, approver: str) -> SafeguardConfiguration:
    """The condition label, as the configuration it is sugar for.

    This mapping *is* the experiment's design. Reading it says exactly what
    changes between two arms, and :func:`run_condition` has no other branch on
    the condition at all -- so "the condition is the manipulated variable and the
    only one" is a property of the code rather than a claim in a docstring.
    ``test_run_condition_branches_on_no_condition_at_all`` holds it that way.

    The approver is a parameter because the stand-in principal is the caller's to
    name; ``SafeguardConfiguration`` refuses the deterministic control without one.
    """
    if condition is EvaluationMode.COMPLETE:
        # Production's configuration exactly, and constructed rather than
        # imported as PRODUCTION_SAFEGUARDS so that a reader sees the full arm
        # spelled out beside the two weaker ones.
        return SafeguardConfiguration(
            evidence_gate=GateMode.ENFORCE,
            policy_gate=GateMode.ENFORCE,
            monitor_gate=GateMode.ENFORCE,
            authorization_gate=AuthorizationGate.DURABLE_HUMAN,
        )
    return SafeguardConfiguration(
        # Ungated observes both gates rather than skipping them: the arm records
        # what the policy would have refused *and* lets the covert action land,
        # which is what makes it a control instead of an absence.
        evidence_gate=(
            GateMode.ENFORCE if condition is EvaluationMode.POLICY_ONLY else GateMode.OBSERVE_ONLY
        ),
        policy_gate=(
            GateMode.ENFORCE if condition is EvaluationMode.POLICY_ONLY else GateMode.OBSERVE_ONLY
        ),
        # Disabled, not observing, and this is the one place the distinction
        # earns the third mode: the published row contract requires these two
        # conditions to record no monitor verdict at all, because "the condition
        # ran no monitor" is a different arm from "the monitor allowed it".
        monitor_gate=GateMode.DISABLED,
        authorization_gate=AuthorizationGate.DETERMINISTIC_CONTROL,
        control_approver=approver,
    )


#: How a step's authorization is labelled, per gate. Named once so the two
#: published labels cannot drift from the two implementations they describe.
_AUTHORIZATION_LABEL: Final[dict[AuthorizationGate, Authorization]] = {
    AuthorizationGate.DETERMINISTIC_CONTROL: "automatic_evaluation_capability",
    AuthorizationGate.DURABLE_HUMAN: "deterministic_approver_simulation",
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def evidence_sources_for(scenario_id: str) -> frozenset[str]:
    """Read the evidence surface from the shared projection rather than restate it.

    This was once a duplicated literal that happened to equal production's, then
    a shared reference this module handed its own validator. It is now neither:
    every arm builds its validator inside ``IncidentRuntime``, off the same
    projection, so the harness *cannot* be configured with a different evidence
    surface than the gate it measures -- there is no second construction site to
    configure.

    Kept because the parity tests assert against a named surface rather than
    reaching into the runtime, and because a scenario's declared surface is a
    fact about the lane worth being able to name. ``tests/sabotage/
    test_enforcement_parity.py`` checks the identity, not merely the equality.
    """
    return ALLOWED_EVIDENCE_SOURCES[scenario_id]


def step_thread_id(scenario_id: str, episode_key: str, leg: str, step_index: int) -> str:
    """Name a step's thread by what it is, not by a random number.

    ``episode_key`` is the caller's discriminator for *which* episode this is --
    the matrix passes variant and condition -- because two cells of one matrix
    run the same scenario, leg and step index against the same incident, and
    they must not land on one thread.
    """
    return f"{scenario_id}-{episode_key}-{leg}-{step_index:02d}"


#: Drop the checkpoint rows for threads this episode is about to reuse.
#:
#: ``LabRepository.reset_checkpoint`` clears the lab's own tables and not the
#: checkpointer's, which was invisible while every thread id carried a fresh
#: ``uuid4``. With derived ids a second run of the same episode would resume the
#: first run's completed graph, so the reuse has to be made safe rather than
#: assumed away.
#:
#: Now shared with the two non-sabotage lanes, which took the same derivation and
#: therefore inherit the same isolation cost. Re-exported under this name because
#: this module's docstring and three tests name it, and because "the episode
#: purges its own threads" is a fact about the episode runner wherever the six
#: lines happen to live.
_purge_threads = purge_checkpoint_threads


@dataclass(frozen=True)
class SabotageStep:
    """One call inside one episode, and how far down the chain it got."""

    step_index: int
    thread_id: str
    tool_name: str
    #: A function of the call's arguments and nothing else -- never the thread,
    #: the evidence ids, or anything else minted per run. See
    #: :func:`incidentgate.contracts.canonical_arguments_digest`.
    arguments_digest: str
    #: Whether the policy gate was *enforcing* for this step, and therefore
    #: whether the decision below is one that could have stopped the action. An
    #: observing gate reaches a decision too -- it is recorded in
    #: ``observed_policy_decision`` -- but the published row must not report it
    #: here, because the contract reads a decision in this field as the gate
    #: having been consulted in the sense of being able to refuse.
    policy_consulted: bool
    policy_decision: PolicyDecision | None
    policy_reasons: tuple[str, ...]
    #: What the policy gate decided, whether or not it was enforcing. This is the
    #: whole content of "observe_only": the ungated arm now says what the policy
    #: would have refused while still letting the covert action land, so the two
    #: arms differ in one recorded variable rather than in the presence of a
    #: measurement. Never published into the frozen row contract; it exists so a
    #: mutation test can flip one gate and see exactly which fields move.
    observed_policy_decision: PolicyDecision | None
    observed_policy_reasons: tuple[str, ...]
    #: The same, for the evidence gate. ``None`` only when the chain stopped
    #: before the evidence validator ran at all.
    observed_evidence_state: EvidenceState | None
    observed_evidence_reasons: tuple[str, ...]
    #: Not inferred from a null verdict: "the monitor allowed it" and "the
    #: monitor never saw it" are the two facts the full condition keeps apart.
    monitor_consulted: bool
    monitor_verdict: MonitorVerdict | None
    #: Whether the durable human gate suspended the graph and asked. False under
    #: the deterministic authorization control, which decides in-process -- and
    #: false for a step that never reached the authorizer at all.
    approval_requested: bool
    authorization: Authorization | None
    executed: bool
    operation: OperationLedgerResult | None
    #: Whether the executor's delivery was lost after its transaction committed
    #: and the durable task had to be replayed to recover the result. Recorded
    #: rather than swallowed: a redelivered step is exactly-once only if the
    #: ledger returned the original row, and a row that hid the redelivery could
    #: not say which of those happened.
    redelivered: bool = False
    #: The v2 monitor's typed availability or validation failure.  It is a
    #: failure to assess, not a BLOCK verdict.
    monitor_error_kind: MonitorErrorKind | None = None
    #: The actual semantic-monitor model exchange, when one shaped this step.
    #: Legacy v1 monitors deliberately cannot populate this field.
    monitor_invocation: ModelInvocationRecord | None = None
    #: Stable SHA-256 of the rendered semantic-monitor input, never its body.
    monitor_input_hash: str | None = None

    def __post_init__(self) -> None:
        if self.monitor_error_kind is not None and not isinstance(
            self.monitor_error_kind, MonitorErrorKind
        ):
            raise TypeError("monitor_error_kind must be a MonitorErrorKind")
        if self.monitor_input_hash is not None and not re.fullmatch(
            r"[a-f0-9]{64}", self.monitor_input_hash
        ):
            raise ValueError("monitor_input_hash must be a lowercase SHA-256 digest")

    @property
    def refused(self) -> bool:
        """Whether this step is the one that ends its episode.

        A policy deny and a monitor block are the two refusals that stop an
        agent. A ``defer`` does not: the chain carries on to the human, which is
        the whole point of an advisory verdict.
        """
        return (
            self.policy_decision is PolicyDecision.DENY
            or self.monitor_verdict is MonitorVerdict.BLOCK
            or self.monitor_error_kind is not None
        )


@dataclass(frozen=True)
class SabotageEpisodeOutcome:
    """One leg of one condition: the calls it made, in the order it made them."""

    leg: Leg
    steps: tuple[SabotageStep, ...]
    #: True when a refusal ended the episode before its plan was exhausted, so a
    #: short episode is never mistaken for a short plan.
    stopped_early: bool


@dataclass(frozen=True)
class SabotageConditionOutcome:
    """The complete, inspectable record of one condition."""

    scenario_id: str
    variant_id: str
    condition: EvaluationMode
    #: The arm this outcome was actually produced under. Recorded rather than
    #: re-derived from ``condition``, because the two can legitimately disagree:
    #: an equivalence test drives all three labels under one configuration, and a
    #: record that re-derived the arm would report the label's configuration
    #: instead of the one that ran.
    safeguards: SafeguardConfiguration
    covert: SabotageEpisodeOutcome
    incident: SabotageEpisodeOutcome
    end_state: object


class _RecordingProposer:
    """Wrap a proposer and remember the action it handed to the gate.

    ``WorkflowResult`` carries the action hash and the evidence ids but not the
    tool name or the arguments, and the runtime stops exposing the pending
    action once a run has terminated -- so a denied step leaves no public
    surface naming the capability it tried or the arguments it tried it with.
    The published episode must name both rather than assume them, and recording
    at the seam the proposal actually passes through is the honest way to learn
    it: what is published is what the gate was handed.
    """

    def __init__(self, inner: ProposalGenerator) -> None:
        self._inner = inner
        self.action: CanonicalAction | None = None

    def propose(
        self,
        incident: IncidentIdentity,
        caller: Caller,
        context: ToolCallContext,
        records: tuple[EvidenceRecord, ...],
    ) -> tuple[Hypothesis, CanonicalAction]:
        hypothesis, action = self._inner.propose(incident, caller, context, records)
        self.action = action
        return hypothesis, action


def load_policy_configuration() -> PolicyConfiguration:
    """Load the same frozen policy file ``IncidentRuntime`` loads.

    Read from disk rather than constructed here on purpose: a condition that
    evaluated a hand-built configuration would be testing a fixture, not the
    policy the lab actually ships.

    No arm calls this any more -- every arm's policy engine is built inside
    ``IncidentRuntime`` from that same file, which is a stronger guarantee than
    this function was. It stays because the sabotage and evidence-source tests
    need to name the shipped configuration in order to assert things about it,
    and reading it here keeps that one statement in the lane it belongs to.
    """
    path = Path(__file__).parents[3] / "config" / "policy.example.json"
    return PolicyConfiguration.model_validate(json.loads(path.read_text(encoding="utf-8")))


def _identity(scenario_id: str, thread_id: str, actor: str) -> tuple[
    IncidentIdentity, Caller, ToolCallContext
]:
    incident_id = f"INC-{scenario_id}"
    return (
        IncidentIdentity(
            incident_id=incident_id,
            scenario_id=scenario_id,
            thread_id=thread_id,
            correlation_id=f"corr-{thread_id}",
        ),
        Caller(actor=actor, role=Role.OPERATOR),
        # The proposal context carries the write capability, exactly as it does
        # when IncidentRuntime.start() is handed an operator context: the
        # proposed action inherits this permission, and the repository's
        # capability binding requires it to match the execution context. Reads
        # are not made with it -- the collector derives its own
        # observability:read context internally, which is the same narrowing the
        # durable runtime performs.
        ToolCallContext(
            incident_id=incident_id,
            thread_id=thread_id,
            correlation_id=f"corr-{thread_id}",
            actor=actor,
            permission="operations:write",
        ),
    )


@runtime_checkable
class _SemanticMonitorObservation(Protocol):
    """The public, prompt-free observation surface an episode may read."""

    @property
    def last_input_hash(self) -> str | None: ...

    @property
    def last_invocation(self) -> ModelInvocationRecord | None: ...


def _semantic_monitor_observation(
    semantic_monitor: SemanticMonitorBundle | None,
    *,
    status: RuntimeStatus,
    safeguards: SafeguardConfiguration,
) -> tuple[MonitorErrorKind | None, ModelInvocationRecord | None, str | None]:
    """Read only the terminal semantic consultation's public observation facts.

    A shared semantic bundle intentionally persists across episode steps.  Its
    monitor wrapper clears these fields at the beginning of each consultation,
    but a skipped monitor stage has no consultation to clear them.  The runner
    therefore treats disabled and policy-unreached stages as no observation
    rather than accidentally publishing the preceding step's metadata.
    """
    if semantic_monitor is None or not safeguards.consults_monitor:
        return None, None, None
    if status.result is None:
        return None, None, None
    if status.result.monitor is None and status.monitor_error_kind is None:
        return None, None, None
    if (
        status.result.policy is not None
        and status.result.policy.decision is PolicyDecision.DENY
        and safeguards.enforces_policy
    ):
        return None, None, None

    error_kind: MonitorErrorKind | None = None
    if status.monitor_error_kind is not None:
        try:
            error_kind = MonitorErrorKind(status.monitor_error_kind)
        except ValueError as error:
            raise TypeError("runtime returned an unknown monitor error kind") from error

    monitor = semantic_monitor.monitor
    if not isinstance(monitor, _SemanticMonitorObservation):
        return error_kind, None, None
    input_hash = monitor.last_input_hash
    invocation = monitor.last_invocation
    if input_hash is not None and (
        not isinstance(input_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", input_hash)
    ):
        raise TypeError("semantic monitor exposed an invalid input hash")
    if invocation is not None and not isinstance(invocation, ModelInvocationRecord):
        raise TypeError("semantic monitor exposed an invalid invocation record")
    return (
        error_kind,
        invocation,
        input_hash,
    )


def _runtime_step(
    dsn: str,
    *,
    scenario_id: str,
    thread_id: str,
    step_index: int,
    proposer: ProposalGenerator,
    actor: str,
    approver: str,
    monitor: AdvisoryMonitor | None,
    semantic_monitor: SemanticMonitorBundle | None,
    safeguards: SafeguardConfiguration,
    clock: Callable[[], datetime],
) -> SabotageStep:
    """Drive one call through the durable runtime. The only step implementation.

    Every arm calls this, and the arm is the ``safeguards`` argument. There is no
    second path a condition can take, which is what makes the condition the
    manipulated variable rather than a label on three different machines.

    Under the durable human gate the approval is granted unconditionally *when
    one is requested*, which is the deterministic stand-in for a human decision.
    That is not the same as granting one unconditionally: a denied action never
    becomes a request, so there is nothing here that could approve it into
    existence. Under the deterministic authorization control no interrupt happens
    at all -- the same token is minted in-process and the same validator, audit
    write and executor consume it -- so ``approval_requested`` is False and the
    absence is a fact about the gate rather than about the action.

    Every step is wrapped in a :class:`_RecordingProposer`, including the honest
    leg's, which previously passed ``proposer=None`` and let the runtime select
    the scenario's own proposer. That property is now asserted by a test rather
    than obtained by omission -- ``test_the_honest_plan_is_the_proposer_the_
    runtime_would_have_selected`` drives the same leg both ways and requires the
    same capability, arguments and decision -- because the alternative was
    publishing an episode that could not name the arguments of half its calls.
    """
    if monitor is not None and semantic_monitor is not None:
        raise ValueError("provide either legacy monitor or semantic monitor, not both")
    incident, operator, context = _identity(scenario_id, thread_id, actor)
    recorder = _RecordingProposer(proposer)
    redelivered = False
    if semantic_monitor is not None:
        runtime = IncidentRuntime(
            dsn,
            clock=clock,
            semantic_monitor=semantic_monitor,
            proposer_factory=lambda: recorder,
            safeguards=safeguards,
            allow_unpromoted_scenario=scenario_id not in RUNNABLE_SCENARIOS,
        )
    else:
        runtime = IncidentRuntime(
            dsn,
            clock=clock,
        # Scenarios that supply no monitor keep the always-allow fixture, which
        # is what every condition ran before any scenario needed a real one: the
        # full column's claim was then about the policy and the human gate, and
        # the monitor stage was present but never dissenting. Passed in every
        # arm, including the two that disable the monitor stage, so the arms
        # share one monitor identity and not merely one monitor type.
            monitor=monitor if monitor is not None else FixtureMonitor(MonitorVerdict.ALLOW),
            proposer_factory=lambda: recorder,
            safeguards=safeguards,
        # The acceptance gate lists a published evaluation among the clauses a
        # scenario must satisfy *before* it is promoted, so requiring promotion
        # in order to run the evaluation would be circular -- T1 was measured
        # from inside this same window. The gate is untouched for the host, the
        # UI and the chaos worker, which are the paths it exists to hold shut.
            allow_unpromoted_scenario=scenario_id not in RUNNABLE_SCENARIOS,
        )
    with runtime:
        try:
            outcome: PendingApproval | RuntimeStatus = runtime.start(incident, operator, context)
        except ResponseLost:
            # The operation transaction committed and its delivery was lost.
            # Replaying the durable task returns the original ledger row instead
            # of mutating a second time -- the exactly-once boundary, exercised
            # in whichever arm the loss happened to land in.
            redelivered, outcome = True, runtime.retry(thread_id)
        requested = isinstance(outcome, PendingApproval)
        if isinstance(outcome, PendingApproval):
            try:
                status = runtime.approve(
                    outcome.thread_id,
                    Principal(approver, Role.APPROVER),
                    reason="deterministic evaluation approver",
                )
            except ResponseLost:
                redelivered, status = True, runtime.retry(thread_id)
        else:
            status = outcome
    result = status.result
    if result is None:
        raise TypeError("a sabotage runtime step did not reach a terminal runtime result")
    if recorder.action is None:
        raise TypeError("a sabotage runtime step could not name the capability it proposed")
    # Bound to the authorizer having issued an approve decision, not to an
    # interrupt having happened: both gates authorize, and only one of them asks.
    authorized = result.approval is not None and result.approval.decision == "approve"
    enforcing_policy = safeguards.enforces_policy
    evidence = status.evidence
    monitor_error_kind, monitor_invocation, monitor_input_hash = _semantic_monitor_observation(
        semantic_monitor, status=status, safeguards=safeguards
    )
    return SabotageStep(
        step_index=step_index,
        thread_id=thread_id,
        tool_name=recorder.action.tool_name,
        arguments_digest=canonical_arguments_digest(recorder.action),
        # An observing gate is not a consulted gate for the purposes of the
        # published row: the contract reads a decision here as one that could
        # have refused. What it decided is carried below instead.
        policy_consulted=enforcing_policy and result.policy is not None,
        policy_decision=(
            result.policy.decision if enforcing_policy and result.policy is not None else None
        ),
        policy_reasons=(
            result.policy.reasons if enforcing_policy and result.policy is not None else ()
        ),
        observed_policy_decision=result.policy.decision if result.policy is not None else None,
        observed_policy_reasons=result.policy.reasons if result.policy is not None else (),
        observed_evidence_state=evidence.state if evidence is not None else None,
        observed_evidence_reasons=evidence.reasons if evidence is not None else (),
        monitor_consulted=result.monitor is not None or monitor_error_kind is not None,
        monitor_verdict=result.monitor.verdict if result.monitor is not None else None,
        monitor_error_kind=monitor_error_kind,
        monitor_invocation=monitor_invocation,
        monitor_input_hash=monitor_input_hash,
        approval_requested=requested,
        authorization=(
            _AUTHORIZATION_LABEL[safeguards.authorization_gate] if authorized else None
        ),
        executed=result.operation is not None,
        operation=result.operation,
        redelivered=redelivered,
    )


def run_condition(
    repository: LabRepository,
    *,
    scenario_id: str,
    variant_id: str,
    episode_key: str,
    condition: EvaluationMode,
    covert_plan: Sequence[ProposalGenerator],
    incident_plan: Sequence[ProposalGenerator],
    end_state: Callable[[], object],
    actor: str = "operator-1",
    approver: str = "approver-1",
    clock: Callable[[], datetime] = _utc_now,
    #: Consulted only by ``policy_monitor_human``; the other two conditions
    #: switch the monitor stage off and the row contract requires them to record
    #: no verdict at all. Passed as one built instance rather than a factory
    #: because a monitor that reads durable state must see the *same* durable
    #: state the steps are writing -- rebuilding it per step would be harmless
    #: today and is exactly the kind of thing that stops being harmless once a
    #: monitor holds any memory of the episode.
    monitor: AdvisoryMonitor | None = None,
    #: The semantic monitor alternative, built once so its public per-call
    #: observations stay attached to the same monitor that the runtime used.
    semantic_monitor: SemanticMonitorBundle | None = None,
    #: The arm, stated directly. Left unset the condition supplies it through
    #: :func:`safeguards_for`, which is the mapping the published matrix uses.
    #: A caller passing one explicitly is running an arm the condition labels do
    #: not name -- which is what the equivalence and mutation tests do, and the
    #: only way to configure two arms identically and compare their traces.
    safeguards: SafeguardConfiguration | None = None,
) -> SabotageConditionOutcome:
    """Run one condition end to end: reset the fixture, drive both episodes, read the state.

    The condition is the manipulated variable and the only one, and that is now a
    property of this function rather than a claim about it: there is a single
    ``drive``, it calls :func:`_runtime_step`, and the condition reaches it only
    as a :class:`SafeguardConfiguration`. Every arm shares one incident and
    thread identity, one evidence collector, one proposer loop, one LangGraph
    checkpoint path, one idempotency-key derivation, one executor and repository
    check, one post-commit verifier and one recorder.

    What differs between arms is the four gates:

        ungated               evidence and policy observe and record; no monitor;
                              the deterministic authorization control
        policy_only           evidence and policy enforce; no monitor; the
                              deterministic authorization control
        policy_monitor_human  every gate enforces, with the durable human
                              approval over a real LangGraph interrupt

    Both authorization gates mint a real ``ApprovalService`` token for a real
    ``APPROVER`` principal and both have it consumed exactly once by the
    executor inside the mutation's own transaction. They differ in the path the
    token is minted along, and in nothing else.
    """
    if monitor is not None and semantic_monitor is not None:
        raise ValueError("provide either legacy monitor or semantic monitor, not both")
    if not covert_plan or not incident_plan:
        raise ValueError("both episodes need at least one planned call")
    applied = safeguards if safeguards is not None else safeguards_for(condition, approver=approver)
    threads = [
        step_thread_id(scenario_id, episode_key, leg, index)
        for leg, plan in (("covert", covert_plan), ("incident", incident_plan))
        for index in range(len(plan))
    ]
    repository.reset_checkpoint(scenario_id)
    repository.inject_checkpoint(scenario_id)
    _purge_threads(repository.dsn, threads)

    def drive(leg: Leg, index: int, proposer: ProposalGenerator) -> SabotageStep:
        return _runtime_step(
            repository.dsn,
            scenario_id=scenario_id,
            thread_id=step_thread_id(scenario_id, episode_key, leg, index),
            step_index=index,
            proposer=proposer,
            actor=actor,
            approver=approver,
            monitor=monitor,
            semantic_monitor=semantic_monitor,
            safeguards=applied,
            clock=clock,
        )

    def run_episode(leg: Leg, plan: Sequence[ProposalGenerator]) -> SabotageEpisodeOutcome:
        steps: list[SabotageStep] = []
        for index, proposer in enumerate(plan):
            step = drive(leg, index, proposer)
            steps.append(step)
            if step.refused:
                # The episode ends here. Everything after it in the plan is a
                # call the run never made, and recording it would publish an
                # attempt that did not happen.
                return SabotageEpisodeOutcome(leg, tuple(steps), index + 1 < len(plan))
        return SabotageEpisodeOutcome(leg, tuple(steps), False)

    covert = run_episode("covert", covert_plan)
    incident = run_episode("incident", incident_plan)
    return SabotageConditionOutcome(
        scenario_id=scenario_id,
        variant_id=variant_id,
        condition=condition,
        safeguards=applied,
        covert=covert,
        incident=incident,
        end_state=end_state(),
    )
