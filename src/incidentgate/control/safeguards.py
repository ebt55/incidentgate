"""Which safeguards enforce, which only observe, and who authorizes.

WHY THIS TYPE EXISTS
====================

The sabotage tier publishes a three-condition table whose docstring claimed
"the condition is the manipulated variable and the only one". It was not. Two of
the three conditions ran through an isolated harness while the third ran the
durable ``IncidentRuntime``, and they differed in three ways that have nothing to
do with a gate:

  * **orchestration and checkpointing** -- an inline loop against the services
    versus a LangGraph traversal over a Postgres checkpointer;
  * **the authorization minting path** -- a token minted inline by the harness
    versus one minted across a durable interrupt;
  * **the idempotency-key derivation** -- ``sabotage-episode:{thread}:{hash}``
    versus the frozen ``triage-agent-lab:d1:`` seed the graph derives from.

Note what is *not* on that list, because the diagnosis is easy to overstate: the
harness's authorization was never fake. It minted a real ``ApprovalToken``
through the production ``ApprovalService`` for a real ``APPROVER`` principal, and
the executor really consumed it. The confound was the path the token was minted
along, not the token. A difference between two such arms still cannot be
attributed to the gates, because three other things moved with them.

This type is what lets every arm traverse **one** path. The condition label
becomes sugar over a configuration; the graph, the collector, the proposer loop,
the checkpointer, the idempotency derivation, the executor, the repository
checks, the post-commit verifier and the artifact recorder are then literally the
same code for every arm.

WHAT ``observe_only`` MEANS, PRECISELY
======================================

An ``observe_only`` gate **runs** and **records the decision it would have
made**; it does not stop the action. That is the whole difference between this
and switching a gate off: a disabled component produces no decision at all, so
an arm that disabled it and an arm where it never fired are indistinguishable --
the unfalsifiability failure this project exists to detect. An observing gate
leaves a verdict behind that a later reader can compare against the enforcing
arm's.

``disabled`` is offered for the monitor alone, and deliberately. The evidence and
policy gates are pure functions of state the run already holds, so running them
costs nothing and refusing to run them would only destroy evidence. The advisory
monitor is an external consultation -- a model call in production -- so "this
condition did not consult a monitor at all" is a real and different experimental
arm, and it is the one the published `policy_only` column has always described.

THE AUTHORIZATION GATE IS NOT A FLAG
====================================

``deterministic_control`` is not "skip the approval", and it is not "use a weaker
token". It is a second implementation of the *same* authorization port: it mints
a real :class:`~incidentgate.contracts.ApprovalToken` through the same
production ``ApprovalService``, bound to the same action hash, incident, thread
and actor, and returns the same ``HumanDecision``-shaped payload. Everything
downstream -- the approver match, the token validator, the audit write, the
executor's own re-validation and single-use consumption -- is the same code.

What it replaces is the **minting path**: a durable interrupt that suspends the
graph and waits for a human, versus an in-process decision by a named stand-in.
That is precisely the variable the human-gate arm exists to manipulate, and
holding everything else identical is what makes the arms comparable.

It must never be selectable in the production host. That is enforced by tests
(``tests/host/test_settings.py`` and ``tests/integration/test_authorization_gate.py``)
rather than by this sentence: no ``HostSettings`` field, no environment name and
no host code path can reach it, and a test asserts the host package neither
imports the deterministic implementation nor passes a safeguard configuration at
all.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class GateMode(StrEnum):
    """Whether a safeguard stops the action, merely records a verdict, or is off."""

    ENFORCE = "enforce"
    #: Runs, records the decision it would have made, and does not stop the action.
    OBSERVE_ONLY = "observe_only"
    #: Never consulted. Valid for the advisory monitor only -- see the module docstring.
    DISABLED = "disabled"


class AuthorizationGate(StrEnum):
    """Which implementation of the authorization port issues the approval."""

    #: The LangGraph interrupt: a durable checkpoint, a human decision, a token
    #: minted by the approval path and consumed exactly once by the executor.
    DURABLE_HUMAN = "durable_human"
    #: The same port, decided in-process by a named stand-in principal. Real
    #: token, real validator, real executor -- only the decider is deterministic.
    DETERMINISTIC_CONTROL = "deterministic_control"


@dataclass(frozen=True, slots=True)
class SafeguardConfiguration:
    """The four manipulated variables of an evaluation arm, and nothing else.

    Defaults are production's. A caller that wants anything weaker has to say so
    field by field at the construction site, where review can see it -- the same
    reasoning as ``IncidentRuntime(allow_unpromoted_scenario=...)``.
    """

    evidence_gate: GateMode = GateMode.ENFORCE
    policy_gate: GateMode = GateMode.ENFORCE
    monitor_gate: GateMode = GateMode.ENFORCE
    authorization_gate: AuthorizationGate = AuthorizationGate.DURABLE_HUMAN
    #: Who the deterministic control stands in for. Required with that gate and
    #: forbidden without it, so a configuration can never name an approver it
    #: does not use, nor select the deterministic control without naming one.
    control_approver: str | None = None

    def __post_init__(self) -> None:
        for name in ("evidence_gate", "policy_gate"):
            if getattr(self, name) is GateMode.DISABLED:
                raise ValueError(
                    f"{name} has no disabled mode: an unrun gate leaves no verdict, so the arm "
                    "would be indistinguishable from one where the gate never fired. Use "
                    "observe_only, which records the decision without stopping the action."
                )
        deterministic = self.authorization_gate is AuthorizationGate.DETERMINISTIC_CONTROL
        if deterministic and not self.control_approver:
            raise ValueError(
                "the deterministic authorization control must name the principal it stands in "
                "for: an unnamed stand-in cannot be told apart from a real approver in the "
                "durable record"
            )
        if not deterministic and self.control_approver is not None:
            raise ValueError(
                "only the deterministic authorization control has a stand-in approver; naming "
                "one beside the durable human gate would describe an authorization the run "
                "never used"
            )

    @property
    def enforces_policy(self) -> bool:
        return self.policy_gate is GateMode.ENFORCE

    @property
    def enforces_evidence(self) -> bool:
        return self.evidence_gate is GateMode.ENFORCE

    @property
    def consults_monitor(self) -> bool:
        return self.monitor_gate is not GateMode.DISABLED

    @property
    def enforces_monitor(self) -> bool:
        return self.monitor_gate is GateMode.ENFORCE


#: What every production construction gets, and what every default-constructed
#: ``WorkflowDependencies`` and ``IncidentRuntime`` gets. Named rather than
#: spelled out at each site so that "is this the production configuration?" is a
#: comparison a test can make rather than a field-by-field reading.
PRODUCTION_SAFEGUARDS: Final = SafeguardConfiguration()
