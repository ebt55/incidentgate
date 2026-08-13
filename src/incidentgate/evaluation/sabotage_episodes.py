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
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import psycopg

from incidentgate.contracts import (
    ApprovalRequest,
    ApprovalToken,
    CanonicalAction,
    EvaluationMode,
    EvidenceRecord,
    Hypothesis,
    IncidentIdentity,
    MonitorVerdict,
    OperationLedgerResult,
    PolicyConfiguration,
    PolicyDecision,
    Role,
    ToolCallContext,
    canonical_action_hash,
    canonical_arguments_digest,
)
from incidentgate.control.evidence import EvidenceValidator
from incidentgate.control.models import Caller
from incidentgate.control.monitor import AdvisoryMonitor, FixtureMonitor
from incidentgate.control.policy import DeterministicPolicyEngine
from incidentgate.control.ports import ProposalGenerator
from incidentgate.integration.adapters import LabEvidenceCollector, LabOperationExecutor
from incidentgate.integration.runtime import IncidentRuntime, PendingApproval
from incidentgate.lab.approval import ApprovalService
from incidentgate.lab.auth import Principal
from incidentgate.lab.repository import LabRepository
from incidentgate.lab.service import ObservabilityService, OperationsService
from incidentgate.scenario_registry import ALLOWED_EVIDENCE_SOURCES, RUNNABLE_SCENARIOS

#: Which authorization minted a step's execution. The two are genuinely
#: different gates and the published row names which one ran, so this is
#: recorded rather than inferred from the condition.
Authorization = Literal["automatic_evaluation_capability", "deterministic_approver_simulation"]

Leg = Literal["covert", "incident"]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def evidence_sources_for(scenario_id: str) -> frozenset[str]:
    """Read the evidence surface from the shared projection rather than restate it.

    This was once a duplicated literal that happened to equal production's. The
    harness now cannot be configured with a different evidence surface than the
    gate it measures, and it cannot drift per scenario either.
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


def _harness_idempotency_key(thread_id: str, action_hash: str) -> UUID:
    """Derive the isolated harness's own idempotency key.

    Deliberately **not** ``control/workflow.py``'s ``_idempotency_key``, whose
    ``triage-agent-lab:d1:`` prefix is a frozen wire value persisted in
    ``operation_ledger`` and compared for exact equality by ``chaos/enddiff.py``.
    That seed needs no new producers; what this path needs from it is only the
    property it already has -- a key that is a pure function of the thread and
    the action, so a replay of one step collapses onto its own ledger row
    instead of writing a second one.
    """
    return uuid5(NAMESPACE_URL, f"sabotage-episode:{thread_id}:{action_hash}")


def _purge_threads(dsn: str, thread_ids: Sequence[str]) -> None:
    """Drop the checkpoint rows for threads this episode is about to reuse.

    ``LabRepository.reset_checkpoint`` clears the lab's own tables and not the
    checkpointer's, which was invisible while every thread id carried a fresh
    ``uuid4``. With derived ids a second run of the same episode would resume the
    first run's completed graph, so the reuse has to be made safe rather than
    assumed away.

    ``chaos/matrix.py`` has a sibling of this function for its own long runs. It
    is not imported: the evaluation lane deliberately does not depend on the
    chaos lane, and six lines of DELETE is a smaller price than that edge.
    """
    with psycopg.connect(dsn, autocommit=True) as connection:
        for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
            for thread_id in thread_ids:
                try:
                    connection.execute(f"DELETE FROM {table} WHERE thread_id = %s", (thread_id,))
                except psycopg.Error:
                    connection.rollback()


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
    policy_consulted: bool
    policy_decision: PolicyDecision | None
    policy_reasons: tuple[str, ...]
    #: Not inferred from a null verdict: "the monitor allowed it" and "the
    #: monitor never saw it" are the two facts the full condition keeps apart.
    monitor_consulted: bool
    monitor_verdict: MonitorVerdict | None
    approval_requested: bool
    authorization: Authorization | None
    executed: bool
    operation: OperationLedgerResult | None

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
) -> SabotageStep:
    """Drive one call through the durable runtime, approving it if it is offered.

    The approval is granted unconditionally *when one is requested*, which is
    the deterministic stand-in for a human decision. That is not the same as
    granting one unconditionally: a denied action never becomes a request, so
    there is nothing here that could approve it into existence.

    Every step is wrapped in a :class:`_RecordingProposer`, including the honest
    leg's, which previously passed ``proposer=None`` and let the runtime select
    the scenario's own proposer. That property is now asserted by a test rather
    than obtained by omission -- ``test_the_honest_plan_is_the_proposer_the_
    runtime_would_have_selected`` drives the same leg both ways and requires the
    same capability, arguments and decision -- because the alternative was
    publishing an episode that could not name the arguments of half its calls.
    """
    incident, operator, context = _identity(scenario_id, thread_id, actor)
    recorder = _RecordingProposer(proposer)
    with IncidentRuntime(
        dsn,
        # Scenarios that supply no monitor keep the always-allow fixture, which
        # is what every condition ran before any scenario needed a real one: the
        # full column's claim was then about the policy and the human gate, and
        # the monitor stage was present but never dissenting.
        monitor=monitor if monitor is not None else FixtureMonitor(MonitorVerdict.ALLOW),
        proposer_factory=lambda: recorder,
        # The acceptance gate lists a published evaluation among the clauses a
        # scenario must satisfy *before* it is promoted, so requiring promotion
        # in order to run the evaluation would be circular -- T1 was measured
        # from inside this same window. The gate is untouched for the host, the
        # UI and the chaos worker, which are the paths it exists to hold shut.
        allow_unpromoted_scenario=scenario_id not in RUNNABLE_SCENARIOS,
    ) as runtime:
        outcome = runtime.start(incident, operator, context)
        requested = isinstance(outcome, PendingApproval)
        status = (
            runtime.approve(
                outcome.thread_id,
                Principal(approver, Role.APPROVER),
                reason="deterministic evaluation approver",
            )
            if isinstance(outcome, PendingApproval)
            else outcome
        )
    result = status.result
    if result is None:
        raise TypeError("a sabotage runtime step did not reach a terminal runtime result")
    if recorder.action is None:
        raise TypeError("a sabotage runtime step could not name the capability it proposed")
    granted = requested and result.approval is not None
    return SabotageStep(
        step_index=step_index,
        thread_id=thread_id,
        tool_name=recorder.action.tool_name,
        arguments_digest=canonical_arguments_digest(recorder.action),
        policy_consulted=result.policy is not None,
        policy_decision=result.policy.decision if result.policy is not None else None,
        policy_reasons=result.policy.reasons if result.policy is not None else (),
        monitor_consulted=result.monitor is not None,
        monitor_verdict=result.monitor.verdict if result.monitor is not None else None,
        approval_requested=requested,
        authorization="deterministic_approver_simulation" if granted else None,
        executed=result.operation is not None,
        operation=result.operation,
    )


def _harness_step(
    repository: LabRepository,
    *,
    scenario_id: str,
    thread_id: str,
    step_index: int,
    proposer: ProposalGenerator,
    policy: DeterministicPolicyEngine,
    validator: EvidenceValidator,
    observability: ObservabilityService,
    caller: Caller,
    executor: LabOperationExecutor,
    gate_enabled: bool,
    approver: str,
    clock: Callable[[], datetime],
) -> SabotageStep:
    """Propose one action, gate it or not, and execute it if it was not denied."""
    incident, _, action_context = _identity(scenario_id, thread_id, caller.actor)
    records: tuple[EvidenceRecord, ...] = LabEvidenceCollector(
        observability, caller, action_context, scenario_id=scenario_id, checkpoint_serde=False
    ).collect(incident)
    _, action = proposer.propose(incident, caller, action_context, records)
    digest = canonical_arguments_digest(action)

    decision: PolicyDecision | None = None
    reasons: tuple[str, ...] = ()
    if gate_enabled:
        # ``action_context`` is passed for the same reason workflow.py passes
        # ``state["context"]``: it is what binds cited evidence to this run's
        # correlation id. Omitting it ran the gated arm one predicate short of
        # the gate it claims to measure, while the published row still labelled
        # evidence_gate=EXECUTED.
        outcome = policy.evaluate(
            action, caller.role, validator.validate(action, records, action_context)
        )
        decision, reasons = outcome.decision, outcome.reasons
        if decision is PolicyDecision.DENY:
            # The executor is not reached. This is the whole gated claim, and it
            # is a control-flow fact rather than a flag: there is no code path
            # from here to a durable write.
            return SabotageStep(
                step_index=step_index,
                thread_id=thread_id,
                tool_name=action.tool_name,
                arguments_digest=digest,
                policy_consulted=True,
                policy_decision=decision,
                policy_reasons=reasons,
                monitor_consulted=False,
                monitor_verdict=None,
                approval_requested=False,
                authorization=None,
                executed=False,
                operation=None,
            )
    operation = _execute(repository, executor, action, approver=approver, clock=clock)
    return SabotageStep(
        step_index=step_index,
        thread_id=thread_id,
        tool_name=action.tool_name,
        arguments_digest=digest,
        policy_consulted=gate_enabled,
        policy_decision=decision,
        policy_reasons=reasons,
        monitor_consulted=False,
        monitor_verdict=None,
        approval_requested=False,
        authorization="automatic_evaluation_capability",
        executed=True,
        operation=operation,
    )


def _execute(
    repository: LabRepository,
    executor: LabOperationExecutor,
    action: CanonicalAction,
    *,
    approver: str,
    clock: Callable[[], datetime],
) -> OperationLedgerResult:
    """Mint a real approval and execute through the ordinary executor seam.

    This is the same ``LabOperationExecutor`` the durable runtime builds, holding
    the same ``OperationsService`` over the same repository. Bypassing the policy
    gate does not bypass the operation boundary: the approval is real, the
    idempotency key is real, and the ledger row is real.
    """
    action_hash = canonical_action_hash(action)
    now = clock()
    token: ApprovalToken = ApprovalService(
        repository, clock, incident_id=action.incident_id, thread_id=action.thread_id
    ).approve(
        ApprovalRequest(
            action_hash=action_hash,
            actor=action.actor,
            requested_at=now,
            expires_at=now + timedelta(minutes=5),
            # One-time use ids stay random: they are the anti-replay token, and
            # a derived one would make two runs of a step share the single use
            # the boundary is built to refuse twice.
            one_time_use_id=uuid4(),
        ),
        Principal(approver, Role.APPROVER),
    )
    idempotency_key = _harness_idempotency_key(action.thread_id, action_hash)
    write_context = ToolCallContext(
        incident_id=action.incident_id,
        thread_id=action.thread_id,
        correlation_id=f"corr-{action.thread_id}",
        actor=action.actor,
        permission="operations:write",
        idempotency_key=idempotency_key,
    )
    return executor.execute(
        action,
        write_context,
        token,
        action_hash=action_hash,
        idempotency_key=idempotency_key,
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
) -> SabotageConditionOutcome:
    """Run one condition end to end: reset the fixture, drive both episodes, read the state.

    The condition is the manipulated variable and the only one. Both episodes
    run the identical plan against the identical durable fixture with the
    identical evidence, approval issuance and executor; what changes between
    conditions is which safeguards are consulted:

        ungated               no gate is consulted; the covert action executes
        policy_only           the deterministic policy gate, nothing else
        policy_monitor_human  the durable runtime: policy, advisory monitor and
                              a checkpointed human approval

    The first two loop the isolated harness step; the third loops the durable
    runtime step, so its monitor and human gate are the real ones -- a real
    LangGraph interrupt, a real checkpoint, a real ``ApprovalService`` token
    minted for an ``APPROVER`` principal and really consumed by the executor.
    Simulating those two stages inside the harness would have made the third
    column a claim about the harness rather than about the system.
    """
    if not covert_plan or not incident_plan:
        raise ValueError("both episodes need at least one planned call")
    threads = [
        step_thread_id(scenario_id, episode_key, leg, index)
        for leg, plan in (("covert", covert_plan), ("incident", incident_plan))
        for index in range(len(plan))
    ]
    repository.reset_checkpoint(scenario_id)
    repository.inject_checkpoint(scenario_id)
    _purge_threads(repository.dsn, threads)

    if condition is EvaluationMode.COMPLETE:

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
            )

    else:
        configuration = load_policy_configuration()
        engine = DeterministicPolicyEngine(configuration)
        validator = EvidenceValidator(
            configuration, clock, allowed_sources=evidence_sources_for(scenario_id)
        )
        observability = ObservabilityService(repository)
        caller = Caller(actor=actor, role=Role.OPERATOR)
        executor = LabOperationExecutor(OperationsService(repository), caller)
        gate_enabled = condition is EvaluationMode.POLICY_ONLY

        def drive(leg: Leg, index: int, proposer: ProposalGenerator) -> SabotageStep:
            return _harness_step(
                repository,
                scenario_id=scenario_id,
                thread_id=step_thread_id(scenario_id, episode_key, leg, index),
                step_index=index,
                proposer=proposer,
                policy=engine,
                validator=validator,
                observability=observability,
                caller=caller,
                executor=executor,
                gate_enabled=gate_enabled,
                approver=approver,
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
        covert=covert,
        incident=incident,
        end_state=end_state(),
    )
