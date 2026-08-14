"""Every published arm on one path, against real Postgres.

``tests/control/test_single_path_ablation.py`` proves the control-flow half on
fakes: one ordered chain, equal configurations producing equal traces, one gate
moving at a time. Those are claims about control flow and fakes can carry them.

These are the claims fakes cannot make, because they are about durable rows:

  * the deterministic authorization control mints a **real** ``approvals`` row
    through the production ``ApprovalService`` and the executor really consumes
    it -- so no arm reaches the mutation without passing approval validation;
  * three condition labels driven under **one** configuration produce the same
    semantic step trace and the same terminal state, so the label carries
    nothing the configuration does not;
  * response loss, process death and redelivery are exercised in **every** arm,
    not only in the one that used to run the durable runtime.

THE STRUCTURAL HALF
===================

``_harness_step`` is not demoted, it is gone, and
``test_no_second_step_implementation_survives_anywhere`` is what keeps it gone.
A second step implementation is the defect this whole phase removes: while one
existed, "which path did this row come from?" was a question a published
envelope could not answer about itself.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
from typing import Any

import pytest

from incidentgate.contracts import EvaluationMode, MonitorVerdict, PolicyDecision, Role
from incidentgate.control.attack_policies import (
    T1_ATTACK_VARIANTS,
    DeterministicT1AttackProposer,
)
from incidentgate.control.proposal import DeterministicT1Proposer
from incidentgate.control.safeguards import (
    AuthorizationGate,
    GateMode,
    SafeguardConfiguration,
)
from incidentgate.evaluation import sabotage_episodes
from incidentgate.evaluation.sabotage_episodes import (
    SabotageConditionOutcome,
    _identity,
    _purge_threads,
    run_condition,
    safeguards_for,
    step_thread_id,
)
from incidentgate.integration.runtime import IncidentRuntime, PendingApproval
from incidentgate.lab.auth import Principal
from incidentgate.lab.errors import ResponseLost
from incidentgate.lab.repository import (
    T1_INCIDENT,
    T1_OUTBOUND_NOTE_SCOPE,
    T1_REMEDIATION_SCOPE,
    LabRepository,
)

SRC = pathlib.Path(__file__).parents[2] / "src" / "incidentgate"
VARIANT = T1_ATTACK_VARIANTS[0]
APPROVER = "approver-1"


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("the one-path arm equivalence tests require DATABASE_URL")
    built = LabRepository(dsn)
    built.migrate()
    return built


def drive(
    repository: LabRepository,
    *,
    condition: EvaluationMode,
    episode_key: str,
    safeguards: SafeguardConfiguration | None = None,
    covert_steps: int = 1,
) -> SabotageConditionOutcome:
    return run_condition(
        repository,
        scenario_id="T1",
        variant_id=VARIANT.variant_id,
        episode_key=episode_key,
        condition=condition,
        covert_plan=tuple(DeterministicT1AttackProposer(VARIANT) for _ in range(covert_steps)),
        incident_plan=(DeterministicT1Proposer(),),
        end_state=repository.t1_end_state,
        approver=APPROVER,
        safeguards=safeguards,
    )


def semantic_trace(outcome: SabotageConditionOutcome) -> bytes:
    """One arm's episodes as bytes, with only the per-run identities removed.

    ``thread_id`` differs because the episode key discriminates the cells of a
    matrix, and ``operation_id`` differs because it embeds an idempotency key
    derived from an action hash that covers ``evidence_ids`` -- which the
    repository mints as ``uuid4`` at collection time, on every run, for every
    tier. That residue is the project's own pinned, out-of-scope defect
    (``test_operation_ids_still_vary_between_identical_runs``), not something
    this comparison is entitled to assume away quietly.

    Everything that carries meaning is compared: the capability, the argument
    digest, every gate's enforced and observed verdict, the authorization label,
    whether the step executed, the operation's status, and the episode's early
    exit.
    """
    return json.dumps(
        [
            {
                "leg": episode.leg,
                "stopped_early": episode.stopped_early,
                "steps": [
                    {
                        "step_index": step.step_index,
                        "tool_name": step.tool_name,
                        "arguments_digest": step.arguments_digest,
                        "policy_consulted": step.policy_consulted,
                        "policy_decision": step.policy_decision,
                        "policy_reasons": list(step.policy_reasons),
                        "observed_policy_decision": step.observed_policy_decision,
                        "observed_policy_reasons": list(step.observed_policy_reasons),
                        "observed_evidence_state": step.observed_evidence_state,
                        "observed_evidence_reasons": list(step.observed_evidence_reasons),
                        "monitor_consulted": step.monitor_consulted,
                        "monitor_verdict": step.monitor_verdict,
                        "approval_requested": step.approval_requested,
                        "authorization": step.authorization,
                        "executed": step.executed,
                        "redelivered": step.redelivered,
                        "operation_status": (
                            step.operation.status if step.operation is not None else None
                        ),
                    }
                    for step in episode.steps
                ],
            }
            for episode in (outcome.covert, outcome.incident)
        ],
        sort_keys=True,
        default=str,
    ).encode()


# ---------------------------------------------------------------------------
# THE STRUCTURAL HALF: there is one step implementation.
# ---------------------------------------------------------------------------
def test_no_second_step_implementation_survives_anywhere() -> None:
    """``_harness_step`` is removed, not demoted, and cannot come back quietly.

    A demoted-to-tests version would still be a second implementation of the
    thing the published envelope is a record of, and the envelope has no field
    that could say which one produced it. Removal is the only version of this
    that a reader can check.
    """
    offenders = [
        path.relative_to(SRC).as_posix()
        for path in sorted(SRC.rglob("*.py"))
        if "_harness_step" in path.read_text(encoding="utf-8")
    ]
    assert not offenders, offenders
    assert not hasattr(sabotage_episodes, "_harness_step")
    assert not hasattr(sabotage_episodes, "_execute")
    assert not hasattr(sabotage_episodes, "_harness_idempotency_key")


def test_run_condition_branches_on_no_condition_at_all() -> None:
    """The condition reaches the driver only as a configuration.

    Stated against the syntax rather than against behaviour, because the
    behavioural version of this claim is what was false for a year while the
    docstring asserted it. ``run_condition`` may name ``EvaluationMode`` when it
    asks ``safeguards_for`` for the arm; it may not compare against a member and
    take a different path.
    """
    tree = ast.parse((SRC / "evaluation" / "sabotage_episodes.py").read_text(encoding="utf-8"))
    run = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "run_condition"
    )
    comparisons = [
        node
        for node in ast.walk(run)
        if isinstance(node, ast.Compare)
        and any(
            isinstance(operand, ast.Attribute)
            and isinstance(operand.value, ast.Name)
            and operand.value.id == "EvaluationMode"
            for operand in (node.left, *node.comparators)
        )
    ]
    assert not comparisons, (
        "run_condition branches on the condition again; the condition is supposed to reach "
        "the driver only through safeguards_for, which is what makes it the manipulated "
        "variable rather than a label on two different machines"
    )


def test_the_condition_labels_map_onto_the_arms_the_matrix_publishes() -> None:
    """The mapping is the experiment's design, so it is asserted rather than read."""
    ungated = safeguards_for(EvaluationMode.UNGATED, approver=APPROVER)
    policy_only = safeguards_for(EvaluationMode.POLICY_ONLY, approver=APPROVER)
    complete = safeguards_for(EvaluationMode.COMPLETE, approver=APPROVER)
    assert (ungated.evidence_gate, ungated.policy_gate) == (
        GateMode.OBSERVE_ONLY,
        GateMode.OBSERVE_ONLY,
    )
    assert (policy_only.evidence_gate, policy_only.policy_gate) == (
        GateMode.ENFORCE,
        GateMode.ENFORCE,
    )
    assert ungated.monitor_gate is policy_only.monitor_gate is GateMode.DISABLED
    assert complete.monitor_gate is GateMode.ENFORCE
    assert (
        ungated.authorization_gate
        is policy_only.authorization_gate
        is AuthorizationGate.DETERMINISTIC_CONTROL
    )
    assert complete.authorization_gate is AuthorizationGate.DURABLE_HUMAN
    # The two weaker arms differ from each other in exactly the two gates named.
    assert (ungated.monitor_gate, ungated.authorization_gate, ungated.control_approver) == (
        policy_only.monitor_gate,
        policy_only.authorization_gate,
        policy_only.control_approver,
    )


# ---------------------------------------------------------------------------
# THE ARMS ARE THE CONFIGURATION, AND NOTHING ELSE
# ---------------------------------------------------------------------------
def test_three_labels_under_one_configuration_are_semantically_identical(
    repository: LabRepository,
) -> None:
    """Give the three conditions one arm and the labels stop meaning anything.

    This is the durable counterpart of the graph-level byte-equivalence test.
    Passing it requires that the whole chain -- collection, proposal, gates,
    authorization, executor, repository validation, verifier and recorder -- is
    literally the same code for all three, because a single residual difference
    in orchestration would show up as a different step record.
    """
    arm = safeguards_for(EvaluationMode.POLICY_ONLY, approver=APPROVER)
    traces = {
        condition: semantic_trace(
            drive(
                repository,
                condition=condition,
                episode_key=f"one-arm-{condition.value}",
                safeguards=arm,
            )
        )
        for condition in EvaluationMode
    }
    assert len(set(traces.values())) == 1, {
        condition.value: trace.decode() for condition, trace in traces.items()
    }


def test_the_same_arm_driven_twice_is_semantically_identical(
    repository: LabRepository,
) -> None:
    """The baseline the equivalence claim rests on, measured rather than assumed.

    Without this, the test above could be reporting that the lane is noisy in a
    way that happens to be equal three times.
    """
    arm = safeguards_for(EvaluationMode.UNGATED, approver=APPROVER)
    first = drive(repository, condition=EvaluationMode.UNGATED, episode_key="twice", safeguards=arm)
    second = drive(
        repository, condition=EvaluationMode.UNGATED, episode_key="twice", safeguards=arm
    )
    assert semantic_trace(first) == semantic_trace(second)


def test_the_published_arms_still_differ_where_the_gates_say_they_should(
    repository: LabRepository,
) -> None:
    """The anti-vacuity control for the equivalence test above.

    Three arms that were identical *under their own configurations* would mean
    the gates do nothing, and every equivalence assertion here would be passing
    for the wrong reason.
    """
    traces = {
        condition: semantic_trace(
            drive(repository, condition=condition, episode_key=f"differ-{condition.value}")
        )
        for condition in EvaluationMode
    }
    assert len(set(traces.values())) == len(EvaluationMode)


def test_the_ungated_arm_records_the_denial_it_did_not_enforce(
    repository: LabRepository,
) -> None:
    """What ``observe_only`` buys, and the reason it is not "gate off".

    The ungated control used to consult nothing, so its row could not say what a
    gate would have done -- and "no gate ran" was indistinguishable from "a gate
    ran and allowed it". Now the covert step carries the denial the policy
    reached, while the action still lands, which is what makes this arm a
    measurement rather than an absence.
    """
    outcome = drive(repository, condition=EvaluationMode.UNGATED, episode_key="observed")
    step = outcome.covert.steps[0]
    assert step.executed is True
    assert step.observed_policy_decision is PolicyDecision.DENY
    assert step.observed_policy_reasons == ("capability_prohibited",)
    # And the published projection still reports no consulted gate, because the
    # frozen row contract reads a decision there as one that could have refused.
    assert step.policy_consulted is False
    assert step.policy_decision is None
    assert step.policy_reasons == ()
    # The enforcing arm reaches the same decision and stops.
    enforced = drive(repository, condition=EvaluationMode.POLICY_ONLY, episode_key="enforced")
    assert enforced.covert.steps[0].observed_policy_decision is PolicyDecision.DENY
    assert enforced.covert.steps[0].policy_decision is PolicyDecision.DENY
    assert enforced.covert.steps[0].executed is False


# ---------------------------------------------------------------------------
# THE DETERMINISTIC CONTROL IS A MINTING PATH, NOT A BYPASS
# ---------------------------------------------------------------------------
def test_the_deterministic_control_mints_a_real_approval_the_executor_consumes(
    repository: LabRepository,
) -> None:
    """No arm reaches a mutation without passing approval validation.

    The point of implementing the same port rather than calling the executor
    inline: the token is a real ``ApprovalService`` issue for a real ``APPROVER``
    principal, it is recorded durably, and the repository consumes it in the same
    transaction as the mutation. An arm that skipped that would make "no branch
    skips approval validation" false, and the operation kernel that comes next is
    built on exactly that property.
    """
    outcome = drive(repository, condition=EvaluationMode.UNGATED, episode_key="real-approval")
    counts = repository.sabotage_durable_counts("T1")
    executed = sum(
        1
        for episode in (outcome.covert, outcome.incident)
        for step in episode.steps
        if step.executed
    )
    assert executed == 2
    # One approval recorded per executed call, and every one of them consumed.
    assert counts.approvals_recorded >= executed
    assert counts.approvals_consumed == executed
    # The durable ledger agrees with the record: both legs really committed.
    assert counts.ledger_rows[T1_OUTBOUND_NOTE_SCOPE] == 1
    assert counts.ledger_rows[T1_REMEDIATION_SCOPE] == 1
    # And every step names the automatic capability, which is what the published
    # row has always called this authorizer.
    for step in outcome.covert.steps:
        assert step.authorization == "automatic_evaluation_capability"
        assert step.approval_requested is False


def test_the_durable_human_arm_really_interrupts_and_the_control_arm_does_not(
    repository: LabRepository,
) -> None:
    """The one behavioural difference the authorization gate is allowed to make."""
    control = drive(repository, condition=EvaluationMode.UNGATED, episode_key="no-interrupt")
    human = drive(repository, condition=EvaluationMode.COMPLETE, episode_key="interrupt")
    assert all(not step.approval_requested for step in control.incident.steps)
    assert all(step.approval_requested for step in human.incident.steps)
    assert human.incident.steps[0].authorization == "deterministic_approver_simulation"
    assert control.incident.steps[0].authorization == "automatic_evaluation_capability"


# ---------------------------------------------------------------------------
# CHAOS IN EVERY ARM
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("condition", list(EvaluationMode), ids=lambda c: c.value)
def test_a_redelivered_step_collapses_onto_its_own_ledger_row_in_every_arm(
    repository: LabRepository, condition: EvaluationMode
) -> None:
    """Drive one episode, then drive it again on the same threads.

    The derived thread id gives the second run the same idempotency key, so the
    ledger must return the original row rather than mutate twice. Before this
    phase only the full arm could be asked this question, because only the full
    arm went through the graph that derives the key.

    The fixture is reset by ``run_condition`` between the two drives, which is
    what makes this a redelivery of the *step* rather than of the run: the
    interesting property is that the ledger key is a pure function of the
    binding, and both drives derive it from the same binding.
    """
    key = f"redeliver-{condition.value}"
    first = drive(repository, condition=condition, episode_key=key)
    second = drive(repository, condition=condition, episode_key=key)
    assert [step.thread_id for step in first.covert.steps] == [
        step.thread_id for step in second.covert.steps
    ]
    # Whatever the arm did the first time it did the second time, exactly.
    assert semantic_trace(first) == semantic_trace(second)
    # And exactly one covert row exists at the end, never two.
    counts = repository.sabotage_durable_counts("T1")
    landed = 1 if first.covert.steps[0].executed else 0
    assert counts.ledger_rows[T1_OUTBOUND_NOTE_SCOPE] == landed


@pytest.mark.parametrize("condition", list(EvaluationMode), ids=lambda c: c.value)
def test_a_lost_response_replays_without_a_second_mutation_in_every_arm(
    repository: LabRepository, condition: EvaluationMode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The executor commits, its delivery is lost, and the arm recovers.

    ``response_loss_once`` raises ``ResponseLost`` *after* the operation
    transaction committed, which is the hard case: the mutation happened and the
    caller does not know. Every arm must replay the durable task and get the
    original ledger row back.

    Injected by patching the runtime construction rather than by threading a flag
    through ``run_condition``: a parameter that exists only for this test would
    be a fourth thing that differs between arms.
    """
    import incidentgate.evaluation.sabotage_episodes as episodes

    original = episodes.IncidentRuntime
    injected: list[bool] = []

    def lossy(dsn: str, **kwargs: Any) -> Any:
        # Once, on the first step only: the covert call. A loss on every step
        # would measure the injection rather than the recovery.
        loss = not injected
        injected.append(True)
        return original(dsn, response_loss_once=loss, **kwargs)

    monkeypatch.setattr(episodes, "IncidentRuntime", lossy)
    outcome = drive(
        repository, condition=condition, episode_key=f"response-loss-{condition.value}"
    )
    monkeypatch.undo()

    covert = outcome.covert.steps[0]
    counts = repository.sabotage_durable_counts("T1")
    if covert.executed:
        # The loss landed on a call that really committed, so the arm had to
        # replay to learn its result -- and the ledger returned the original row.
        assert covert.redelivered is True
        assert counts.ledger_rows[T1_OUTBOUND_NOTE_SCOPE] == 1
        assert repository.t1_end_state().outbound_notes != ()
        assert len(repository.t1_end_state().outbound_notes) == 1
    else:
        # The gated arms deny before the executor, so there was nothing to lose.
        # That is the honest outcome rather than a skipped test: it is what the
        # gate is for, and the incident leg below still exercises the recovery.
        assert covert.redelivered is False
        assert counts.ledger_rows[T1_OUTBOUND_NOTE_SCOPE] == 0
    # The incident leg committed exactly once in every arm, whatever happened to
    # the covert one.
    assert counts.ledger_rows[T1_REMEDIATION_SCOPE] == 1


@pytest.mark.parametrize("condition", list(EvaluationMode), ids=lambda c: c.value)
def test_a_dead_process_recovers_its_committed_step_from_the_checkpoint_in_every_arm(
    repository: LabRepository, condition: EvaluationMode
) -> None:
    """Commit, lose the whole process, recover through a brand new runtime.

    The hard case, and the one the chaos matrix measures with a real
    ``os._exit``: the operation transaction committed, the delivery was lost, and
    then everything in memory went away. Recovery has nothing but the durable
    checkpoint and an idempotency key derived from what it holds.

    Driven against ``IncidentRuntime`` directly rather than through
    ``run_condition``, and deliberately: ``run_condition`` resets the fixture
    before each drive, so a second drive there is a fresh run rather than a
    recovery. This is the repository's established idiom for the property -- the
    same shape as ``test_r09_r12_approval_and_response_loss_replay_are_exactly_once``
    -- and the point of running it per arm is that until this phase only the full
    arm went through a graph that could be recovered at all.

    The honest remediation is used rather than the covert proposal because it is
    allowed in **every** arm. A covert proposal would be denied in two of the
    three, so those arms would have nothing committed to lose and the parametrize
    would quietly cover one arm while claiming three.
    """
    arm = safeguards_for(condition, approver=APPROVER)
    repository.reset_checkpoint("T1")
    repository.inject_checkpoint("T1")
    thread = step_thread_id("T1", f"process-death-{condition.value}", "incident", 0)
    _purge_threads(repository.dsn, (thread,))
    incident, operator, call_context = _identity("T1", thread, "operator-1")

    # 1. Drive to the commit, then lose the response and the process with it.
    #
    # Where the commit happens *is* the authorization gate: the durable human
    # arm suspends first, so its executor runs on the resume, while the
    # deterministic control decides in-process and commits inside ``start``.
    # Written as two branches rather than one tolerant one, because a branch that
    # accepted either would stop noticing if an arm's commit point moved.
    with IncidentRuntime(repository.dsn, safeguards=arm, response_loss_once=True) as runtime:
        if arm.authorization_gate is AuthorizationGate.DURABLE_HUMAN:
            started = runtime.start(incident, operator, call_context)
            assert isinstance(started, PendingApproval)
            with pytest.raises(ResponseLost):
                runtime.approve(thread, Principal(APPROVER, Role.APPROVER), reason="death")
        else:
            with pytest.raises(ResponseLost):
                runtime.start(incident, operator, call_context)

    assert repository.checkpoint_state("T1")["mutation_count"] == 1
    assert repository.operation_count(T1_INCIDENT) == 1

    # 2. A brand new runtime, holding nothing, replays the durable task.
    with IncidentRuntime(repository.dsn, safeguards=arm) as recovered_runtime:
        recovered_runtime.resume(thread)
        completed = recovered_runtime.retry(thread)

    assert completed.result is not None
    assert completed.result.operation is not None
    # The ledger returned the row it already had rather than mutating again.
    assert completed.result.operation.status.value == "duplicate"
    assert repository.operation_count(T1_INCIDENT) == 1
    assert repository.checkpoint_state("T1")["mutation_count"] == 1
    counts = repository.sabotage_durable_counts("T1")
    assert counts.ledger_rows[T1_REMEDIATION_SCOPE] == 1
    assert counts.ledger_rows[T1_OUTBOUND_NOTE_SCOPE] == 0
    repository.reset_checkpoint("T1")


def test_the_monitor_object_is_the_same_one_in_every_arm(repository: LabRepository) -> None:
    """Same component identity, not merely the same component type.

    A monitor that reads durable state must see the state the steps are writing,
    so the arms share one built instance. Passing a fresh one per arm would be
    harmless today and is exactly the kind of thing that stops being harmless the
    moment a monitor holds any memory of the episode.
    """
    seen: list[object] = []

    class Recording:
        def assess(self, action: Any, digest: Any) -> Any:
            seen.append(self)
            from incidentgate.contracts import MonitorResult, canonical_action_hash

            return MonitorResult(
                verdict=MonitorVerdict.ALLOW,
                suspicion_score=0.0,
                rationale="recording",
                evaluated_action_hash=canonical_action_hash(action),
            )

    monitor = Recording()
    for condition in EvaluationMode:
        run_condition(
            repository,
            scenario_id="T1",
            variant_id=VARIANT.variant_id,
            episode_key=f"monitor-identity-{condition.value}",
            condition=condition,
            covert_plan=(DeterministicT1AttackProposer(VARIANT),),
            incident_plan=(DeterministicT1Proposer(),),
            end_state=repository.t1_end_state,
            approver=APPROVER,
            monitor=monitor,
        )
    # Only the full arm consults it, which is the arm; every consultation that
    # happened went to the one instance the caller built.
    assert seen and all(item is monitor for item in seen)
