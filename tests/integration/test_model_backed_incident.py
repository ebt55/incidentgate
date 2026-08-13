"""A real captured model output driving the real gate chain, on real collected evidence.

WHAT IS REAL HERE. All of it. The incident's evidence is collected by the production
``LabEvidenceCollector`` through the authenticated observability boundary, so the
evidence ids are the lab's own ``uuid4()`` values and the rows are the rows the lab
wrote. The proposal is a genuine Anthropic model output, captured once and committed
under tests/fixtures/model_cache, replayed with no network. From there the production
components run unmodified against Postgres: the deterministic policy engine evaluates
the model's chosen action, the advisory monitor verdicts it, the graph interrupts for a
human, the lab approval service issues a real durable token, the token validator binds
it, the lab operations executor performs the mutation and records it in the operation
ledger under a graph-derived idempotency key, and the lab recovery verifier re-reads
fresh evidence to confirm recovery. The checkpoint is the runtime's own durable
PostgresSaver, so the interrupt and resume are the production ones, not an in-memory
stand-in.

WHAT IS SUBSTITUTED. Nothing. This module used to carry a ``FixtureEvidenceCollector``
and hand-seeded ``evidence_records`` rows, honestly labelled as the one substituted
component, because the prompt digest rendered each record's ``evidence_id`` and
``observed_at`` and sorted by ``evidence_id``. Lab collection mints both per run, so a
lab-collected incident computed a different cache key every time and could never match a
committed fixture -- and re-keying per run was no escape either, since the captured
output cited specific ids and the proposer rejects any citation outside the run's citable
set. That check is the safety property, so the substitution was the honest option.

The proposer now cites evidence by positional label (``e0``, ``e1``, ...) and drops
``observed_at``, so the prompt describes what was observed rather than where it is
stored. Two collections of the same incident therefore hash to the same prompt, the
substitution has no reason to exist, and it is gone: this test inserts no evidence row of
its own and pins nothing to the fixture's values. What the fixture is keyed to now is
D1's evidence *shape* -- three records, in ``_kinds["D1"]`` collection order, with the
payloads the lab actually serves -- which a real collection reproduces by construction.

Two things this deliberately does NOT claim. Evidence ids are still non-deterministic;
they are simply no longer part of the prompt, which is a weaker and sufficient property.
And prompt stability is a per-scenario fact rather than a consequence of the digest
shape, because the digest still carries payload content: see
tests/integration/test_prompt_stability.py, which measures it for every runnable scenario
and records the one that fails.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from langgraph.types import Command

from incidentgate.contracts import (
    ApprovalRequest,
    EvidenceRecord,
    IncidentIdentity,
    IncidentState,
    MonitorVerdict,
    PolicyConfiguration,
    PolicyDecision,
    Role,
    ToolCallContext,
    canonical_action_hash,
    canonical_arguments_digest,
)
from incidentgate.control import (
    DeterministicPolicyEngine,
    EvidenceValidator,
    FixtureMonitor,
    WorkflowDependencies,
    build_workflow_graph,
)
from incidentgate.control.model_proposal import (
    CompletionRequest,
    CompletionResult,
    ModelAgentProposer,
)
from incidentgate.control.models import Caller
from incidentgate.control.proposal import ProposalError
from incidentgate.control.response_cache import CacheBackedCompletionClient, ResponseCache
from incidentgate.integration import IncidentRuntime
from incidentgate.integration.adapters import (
    LabAuditEmitter,
    LabEvidenceCollector,
    LabOperationExecutor,
    LabRecoveryVerifier,
    LabTokenValidator,
)
from incidentgate.lab.approval import ApprovalService
from incidentgate.lab.auth import Principal
from incidentgate.lab.repository import LabRepository
from incidentgate.lab.service import ObservabilityService, OperationsService
from incidentgate.scenario_registry import ALLOWED_EVIDENCE_SOURCES

OPUS = "claude-opus-5"
COMMITTED_CACHE = Path(__file__).resolve().parents[1] / "fixtures" / "model_cache"
CONFIG = Path(__file__).resolve().parents[2] / "config" / "policy.example.json"

D1_SOURCES = ALLOWED_EVIDENCE_SOURCES["D1"]


def _dsn() -> str:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("model-backed incident test requires DATABASE_URL")
    return dsn


def _fresh_d1(dsn: str) -> LabRepository:
    """A D1 repository with the contract's fault injected and nothing else touched."""
    repository = LabRepository(dsn)
    repository.migrate()
    repository.reset_d1()
    repository.inject_d1()
    return repository


def _inputs(thread_id: str) -> tuple[IncidentIdentity, Caller, ToolCallContext]:
    incident = IncidentIdentity(
        incident_id="INC-D1",
        scenario_id="D1",
        thread_id=thread_id,
        correlation_id=f"corr-{thread_id}",
        state=IncidentState.OPEN,
    )
    caller = Caller(actor="operator-1", role=Role.OPERATOR)
    context = ToolCallContext(
        incident_id=incident.incident_id,
        thread_id=thread_id,
        correlation_id=incident.correlation_id,
        actor=caller.actor,
        permission="operations:write",
    )
    return incident, caller, context


def _collector(
    repository: LabRepository, caller: Caller, context: ToolCallContext
) -> LabEvidenceCollector:
    """The production collector, constructed exactly as the runtime constructs it."""
    return LabEvidenceCollector(
        ObservabilityService(repository), caller, context, scenario_id="D1"
    )


class _WatchingClient:
    """Passes through to the real cache-backed client, remembering the key it looked up."""

    def __init__(self, inner: CacheBackedCompletionClient) -> None:
        self._inner = inner
        self.requests: list[CompletionRequest] = []

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.requests.append(request)
        return self._inner.complete(request)


def _replaying_proposer(client: object | None = None) -> ModelAgentProposer:
    return ModelAgentProposer(
        client=client or CacheBackedCompletionClient(ResponseCache(COMMITTED_CACHE)),  # type: ignore[arg-type]
        model=OPUS,
        temperature=None,
    )


def test_a_lab_collected_incident_passes_the_whole_gate_chain_on_a_replayed_proposal() -> None:
    dsn = _dsn()
    repository = _fresh_d1(dsn)

    thread_id = f"model-seam-{uuid4().hex[:12]}"
    incident, caller, context = _inputs(thread_id)
    now = datetime.now(UTC)

    def clock() -> datetime:
        return datetime.now(UTC)

    config = PolicyConfiguration.model_validate(json.loads(CONFIG.read_text(encoding="utf-8")))
    observability = ObservabilityService(repository)
    proposer = _replaying_proposer()

    # The runtime owns the durable checkpointer and its strict serde allowlist;
    # borrowing it keeps the interrupt/resume path the production one.
    with IncidentRuntime(dsn, clock=clock) as runtime:
        dependencies = WorkflowDependencies(
            # The production collector, reading the lab's own rows. No evidence is inserted
            # by this test, and no clock is pinned: the collected evidence is genuinely
            # fresh, so the validator's freshness window is satisfied rather than arranged.
            collector=_collector(repository, caller, context),
            proposer=proposer,
            evidence_validator=EvidenceValidator(config, clock, allowed_sources=D1_SOURCES),
            policy=DeterministicPolicyEngine(config),
            monitor=FixtureMonitor(MonitorVerdict.ALLOW),
            token_validator=LabTokenValidator(repository),
            executor=LabOperationExecutor(OperationsService(repository), caller),
            verifier=LabRecoveryVerifier(observability, caller, context, clock, repository),
            audit=LabAuditEmitter(repository, caller.actor),
            clock=clock,
            telemetry=None,
        )
        graph = build_workflow_graph(dependencies, checkpointer=runtime._checkpointer)
        run_config = {"configurable": {"thread_id": thread_id}}

        paused = graph.invoke(
            {"incident": incident, "caller": caller, "context": context}, run_config
        )

        # 1. The proposal came from the model path, replayed, with no network. A hit at all
        #    is the headline result: this prompt was built from evidence collected seconds
        #    ago, and it still matched a fixture committed to git.
        assert proposer.last_invocation is not None
        invocation = proposer.last_invocation
        assert invocation.invocation_kind == "cache_replay"
        assert invocation.provider == "anthropic"
        assert invocation.model == OPUS
        assert invocation.input_tokens is None and invocation.cost is None

        # 2. The model's own action reached a human gate rather than executing.
        assert "__interrupt__" in paused, "a model proposal must still stop at the human gate"
        interrupt_value = paused["__interrupt__"][0].value
        action_hash = interrupt_value["action_hash"]

        state = dict(graph.get_state(run_config).values)
        action = state["action"]
        assert action.tool_name == "operations.rollback"
        assert action.arguments.component == "api"
        assert action.arguments.target_revision == "v1"

        # The citations are the model's, decoded to the evidence this run actually
        # collected. Nothing here is a value this module chose: the ids are the lab's,
        # minted at collection time, which is what makes them uuid4-shaped.
        collected = state["records"]
        assert len(collected) == 3
        assert set(action.evidence_ids) == {record.evidence_id for record in collected}
        for evidence_id in action.evidence_ids:
            assert UUID(evidence_id).version == 4, (
                f"{evidence_id} is not a lab-minted id; this test must not seed evidence"
            )

        # 3. The real policy engine evaluated the model's action.
        assert state["policy"].decision is PolicyDecision.REQUIRE_APPROVAL
        assert state["policy"].action_hash == action_hash
        # 4. The real monitor verdicted it.
        assert state["monitor"].verdict is MonitorVerdict.ALLOW

        # Nothing has mutated the target yet: the gate is closed until a human opens it.
        assert repository.state() == {"revision": "v2", "health_status": 500, "mutation_count": 0}

        # 5. A real durable approval token, issued by the lab approval service.
        request = ApprovalRequest(
            action_hash=action_hash,
            actor=action.actor,
            requested_at=now,
            expires_at=now + timedelta(hours=1),
            one_time_use_id=uuid4(),
        )
        token = ApprovalService(
            repository, clock, incident_id=incident.incident_id, thread_id=thread_id
        ).approve(request, Principal("approver-1", Role.APPROVER))

        completed = graph.invoke(
            Command(
                resume={
                    "decision": "approve",
                    "approver": "approver-1",
                    "reason": "verified",
                    "token": token.model_dump(mode="python"),
                }
            ),
            run_config,
        )

    # 6. Execution happened, exactly once, and recovery was verified from fresh evidence.
    result = completed["result"]
    assert result.final_state == "resolved"
    assert result.reasons == ("recovery_verified",)
    assert result.verification is not None and result.verification.passed
    assert repository.state() == {"revision": "v1", "health_status": 200, "mutation_count": 1}

    # 7. The mutation is bound to the approval in the durable ledger.
    assert result.operation is not None
    assert result.idempotency_key is not None
    assert result.approval is not None and result.approval.decision == "approve"

    # The audit trail records the whole chain, in causal order.
    transitions = [event.transition for event in repository.timeline(incident.incident_id)]
    for expected in ("policy", "monitor", "approval", "execution", "verification"):
        assert expected in transitions, f"{expected} missing from {transitions}"


def test_the_committed_fixture_is_keyed_to_real_lab_evidence() -> None:
    """Name the drift, rather than letting it surface as ``proposal_model_unavailable``.

    The committed fixture is recorded offline, from payloads transcribed by hand into
    tests/control/test_response_cache.py, so that ``record_committed_fixture()`` needs no
    Postgres. The cost of transcribing is that nothing in that module can notice when the
    lab starts serving a different payload -- and it did not match to begin with: the
    synthetic logs record carried an invented ``{"component", "lines"}`` payload where the
    lab serves ``{"level", "message"}``. Removing storage identity from the prompt was
    necessary for a lab-collected incident to hit the fixture, and this is the check that
    it is also sufficient.
    """
    dsn = _dsn()
    repository = _fresh_d1(dsn)
    incident, caller, context = _inputs(f"fixture-key-{uuid4().hex[:12]}")
    records: tuple[EvidenceRecord, ...] = _collector(repository, caller, context).collect(incident)

    watcher = _WatchingClient(CacheBackedCompletionClient(ResponseCache(COMMITTED_CACHE)))
    proposer = _replaying_proposer(watcher)
    try:
        proposer.propose(incident, caller, context, records)
    except ProposalError:
        pass  # asserted below, with the key that actually missed
    assert watcher.requests, "no prompt was built, so there is nothing to compare"

    committed = {path.stem for path in (COMMITTED_CACHE / OPUS).glob("*.json")}
    assert watcher.requests[0].prompt_sha256 in committed, (
        f"a lab-collected D1 computes {watcher.requests[0].prompt_sha256} but the committed "
        f"opus fixture is keyed {sorted(committed)}. The lab's D1 evidence and the "
        "transcribed records() in tests/control/test_response_cache.py have diverged: "
        "re-transcribe the payloads the lab now serves, then regenerate with "
        f"record_committed_fixture(). Collected: "
        f"{[(r.tool_name, sorted(r.payload)) for r in records]}"
    )
    assert proposer.last_invocation is not None
    assert proposer.last_invocation.invocation_kind == "cache_replay"


def test_the_replay_is_deterministic_in_what_it_proposes_not_in_run_identity() -> None:
    """Determinism comes from the committed capture, not from sampling parameters.

    This module's predecessor asserted one ``canonical_action_hash`` across two replays,
    which it could only do because it pinned the evidence ids. With real collection each
    run mints its own, and that hash covers ``evidence_ids`` deliberately -- it is an
    idempotency identity, and two runs must not collapse into one ledger row. So the claim
    is split into the two facts that are actually true, rather than kept under a name that
    would no longer describe either: what was *called* is identical, and what *run* called
    it is not. ``canonical_arguments_digest`` exists for exactly that first question.
    """
    dsn = _dsn()
    incident, caller, context = _inputs("determinism-thread")

    identities, calls, proposals, citations = set(), set(), set(), set()
    for _ in range(2):
        repository = _fresh_d1(dsn)
        records = _collector(repository, caller, context).collect(incident)
        proposer = _replaying_proposer()
        hypothesis, action = proposer.propose(incident, caller, context, records)
        identities.add(canonical_action_hash(action))
        calls.add((action.tool_name, canonical_arguments_digest(action)))
        proposals.add((hypothesis.hypothesis_id, hypothesis.statement, hypothesis.confidence))
        citations.add(action.evidence_ids)
        assert proposer.last_invocation is not None
        assert proposer.last_invocation.invocation_kind == "cache_replay"

    # The control: two genuinely separate collections, so the ids really did move. Without
    # this the equalities below could be passing on one collection replayed twice.
    assert len(citations) == 2, "both runs cited the same ids; this proves nothing about replay"
    # What the replay determines: the same diagnosis, the same call, every time.
    assert len(calls) == 1
    assert len(proposals) == 1
    # What it does not, and must not: run identity still moves with the evidence ids.
    assert len(identities) == 2
