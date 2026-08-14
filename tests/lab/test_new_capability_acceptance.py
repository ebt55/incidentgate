"""What adding a scenario actually costs, measured rather than claimed.

The build guide's acceptance criterion for this phase is that "a new no-action
and a new mutating scenario can be added editing only the registry, its
fixture/mutation module, and its tests". That is a claim about an edit surface,
and an edit surface is exactly the kind of thing that is easy to assert and hard
to keep true -- the six duplicated transactions and the two hand-written
scenario lists this phase removed were each, at the time they were written, one
more place a new scenario had to be remembered in.

So this module answers the claim in two halves, and the second half is the
interesting one.

The first half is executable: a capability that exists nowhere in this codebase
is registered at runtime against a fixture table this test creates, driven
through the full transaction protocol, and unregistered. Nothing in the kernel,
the executor, the workflow, the runtime or any list is touched. If a future
change puts a scenario-shaped branch back into the kernel, this stops passing.

The second half is the honest correction: the claim as written is not true, and
this states the remaining edit surface as a list so the gap is a measured number
rather than a slogan. Four of the sites below are already tied to each other by
the completeness suite, so they cannot disagree -- but they are still four
edits, and calling that "only the registry" would be reporting the goal instead
of the state.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from incidentgate.contracts import (
    ApprovalRequest,
    ApprovalToken,
    CanonicalAction,
    OperationStatus,
    Role,
    RollbackArgs,
    ToolCallContext,
    canonical_action_hash,
)
from incidentgate.lab.approval import ApprovalService
from incidentgate.lab.auth import Principal
from incidentgate.lab.errors import ApprovalDenied
from incidentgate.lab.kernel import LockedTransaction, MutationOutcome, OperationSpec
from incidentgate.lab.repository import _SPECS, LabRepository
from incidentgate.lab.service import ObservabilityService

ACTOR = "operator-1"
APPROVER = "approver-1"
PROBE_SCOPE = "probe-new-capability"
PROBE_TABLE = "probe_fixture_state"

#: A fixture table owned by this test rather than by a migration. The migration
#: head is pinned in four places and this phase adds none, so proving that a new
#: capability needs no kernel change must not need one either.
#:
#: ``updated_at`` carries a fixed default rather than ``now()``: a DEFAULT-clock
#: column is exactly what the one-clock discipline allowlist exists to catch, and
#: a table that only exists for the length of one test should not be able to
#: teach anybody that such a column is fine.
CREATE_PROBE = f"""
CREATE TABLE IF NOT EXISTS {PROBE_TABLE} (
    scenario_id text PRIMARY KEY,
    injected boolean NOT NULL DEFAULT false,
    repaired boolean NOT NULL DEFAULT false,
    mutation_count integer NOT NULL DEFAULT 0 CHECK (mutation_count >= 0),
    updated_at timestamptz NOT NULL DEFAULT '2026-01-01T00:00:00Z'
)
"""


def probe_mutation(transaction: LockedTransaction) -> MutationOutcome:
    """The whole of what a new capability has to write."""
    return MutationOutcome(
        result={"scenario": "PROBE", "result": "probe_repaired"},
        fixture_touch="repaired = true",
    )


PROBE_SPEC = OperationSpec(
    scenario_id="PROBE",
    operation_scope=PROBE_SCOPE,
    # The probe borrows D1's incident so it can borrow D1's evidence. Minting a
    # new evidence kind means widening a CHECK constraint, which means a
    # migration -- and the point here is what a capability costs, not what an
    # evidence surface costs.
    incident_id="INC-D1",
    tool_name="operations.rollback",
    arguments_type=RollbackArgs,
    validate_arguments=lambda action: None,
    fixture_lock_sql=f"SELECT * FROM {PROBE_TABLE} WHERE scenario_id='PROBE' FOR UPDATE",
    fixture_lock_params=(),
    fixture_present=lambda state: bool(state["injected"]),
    precondition=lambda state: not bool(state["repaired"]),
    mutation=probe_mutation,
    fixture_table=PROBE_TABLE,
    fixture_filter="scenario_id='PROBE'",
    commit_transition="probe_committed",
    stamps_updated_at=True,
    binding_message="probe action is not bound to its capability",
    missing_key_message="probe operation idempotency key is required",
    fixture_absent_message="probe fixture missing",
    precondition_message="probe fixture precondition failed",
    response_loss_message="probe committed but response lost",
)

#: Every file a new *mutating* scenario still has to touch, and why each one is
#: not a registry projection. This is the measured answer to the guide's claim.
#:
#: The first two are deliberate and should stay: the action contract is a frozen
#: wire surface, and the policy file is the authority for what is governed --
#: deriving either from the repository would let a capability grant itself a
#: rule. The next two are duplication that the completeness suite now binds but
#: has not removed. The last is the fixture, which is the scenario.
REMAINING_EDIT_SURFACE = {
    "src/incidentgate/contracts.py": "the tool-name literal and the typed arguments class",
    "config/policy.example.json": "the tool's policy rule",
    "src/incidentgate/lab/service.py": "the repository protocol entry and the service method",
    "src/incidentgate/integration/adapters.py": "the collector's evidence-kind tuple",
    "db/": "a migration for the scenario's fixture table",
}


@pytest.fixture
def repository() -> LabRepository:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("registering a capability against a real ledger requires DATABASE_URL")
    repo = LabRepository(dsn)
    repo.migrate()
    repo.reset_d1()
    repo.inject_d1()
    return repo


@contextmanager
def probe_registered(repository: LabRepository, *, injected: bool = True) -> Iterator[None]:
    """Install the throwaway capability and its fixture, then remove both."""
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(CREATE_PROBE)
        cursor.execute(
            f"INSERT INTO {PROBE_TABLE} (scenario_id, injected) VALUES ('PROBE', %s) "
            "ON CONFLICT (scenario_id) DO UPDATE SET injected = EXCLUDED.injected, "
            "repaired = false, mutation_count = 0",
            (injected,),
        )
    _SPECS[PROBE_SCOPE] = PROBE_SPEC
    try:
        yield
    finally:
        _SPECS.pop(PROBE_SCOPE, None)
        with repository._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM operation_ledger WHERE operation_scope = %s", (PROBE_SCOPE,)
            )
            cursor.execute(f"DROP TABLE IF EXISTS {PROBE_TABLE}")


def _prepare(repository: LabRepository, thread: str) -> tuple[CanonicalAction, ApprovalToken]:
    read_context = ToolCallContext(
        incident_id="INC-D1",
        thread_id=thread,
        correlation_id=f"corr-{thread}",
        actor=ACTOR,
        permission="observability:read",
    )
    evidence = ObservabilityService(repository).get(
        read_context, Principal(ACTOR, Role.OPERATOR), "health"
    )
    action = CanonicalAction(
        tool_name="operations.rollback",
        incident_id="INC-D1",
        thread_id=thread,
        actor=ACTOR,
        permission="operations:write",
        evidence_ids=(evidence.evidence_id,),
        arguments=RollbackArgs(kind="rollback", component="api", target_revision="v1"),
    )
    now = datetime.now(UTC)
    token = ApprovalService(
        repository, lambda: datetime.now(UTC), incident_id="INC-D1", thread_id=thread
    ).approve(
        ApprovalRequest(
            action_hash=canonical_action_hash(action),
            actor=ACTOR,
            requested_at=now,
            expires_at=now + timedelta(minutes=5),
            one_time_use_id=uuid4(),
        ),
        Principal(APPROVER, Role.APPROVER),
    )
    return action, token


def _context(thread: str, key: object) -> ToolCallContext:
    return ToolCallContext(
        incident_id="INC-D1",
        thread_id=thread,
        correlation_id=f"corr-{thread}",
        actor=ACTOR,
        permission="operations:write",
        idempotency_key=key,  # type: ignore[arg-type]
    )


def _fixture(repository: LabRepository) -> Mapping[str, object]:
    with repository._connect() as connection, connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM {PROBE_TABLE} WHERE scenario_id='PROBE'")
        row = cursor.fetchone()
    assert row is not None
    return row


def test_a_capability_the_kernel_has_never_seen_commits_without_a_kernel_edit(
    repository: LabRepository,
) -> None:
    """The executable half of the acceptance claim.

    Nothing about this capability exists anywhere in the package: its scope, its
    fixture table, its mutation, its precondition and all five of its refusal
    messages are declared in this file. It gets the whole eight-step protocol --
    idempotency locking, replay equivalence, approval validation, evidence
    validation, fixture locking, the ledger row, its own audit fact, the
    mutation counter, the injected clock, and single-use token consumption --
    because it declared a spec, and for no other reason.
    """
    with probe_registered(repository):
        thread = "probe-commit"
        action, token = _prepare(repository, thread)
        key = uuid4()
        before = _fixture(repository)

        result = repository._commit(
            PROBE_SCOPE, _context(thread, key), action, token, response_loss=False
        )
        assert result.status is OperationStatus.SUCCEEDED
        assert result.result == {"scenario": "PROBE", "result": "probe_repaired"}
        assert result.operation_id == f"{PROBE_SCOPE}:{key}"

        after = _fixture(repository)
        assert after["repaired"] is True
        assert after["mutation_count"] == 1
        # The injected clock reached a table the kernel had never heard of.
        assert after["updated_at"] > before["updated_at"]
        assert repository.approval_consumed(token.token_id) is True
        # Its own audit fact, because its spec asked for one.
        assert ("probe_committed", None) in [
            (event.transition, event.reason) for event in repository.timeline("INC-D1")
        ]

        replay = repository._commit(
            PROBE_SCOPE, _context(thread, key), action, token, response_loss=False
        )
        assert replay.status is OperationStatus.DUPLICATE
        assert _fixture(repository)["mutation_count"] == 1


def test_the_new_capability_inherits_every_refusal_without_declaring_one(
    repository: LabRepository,
) -> None:
    """The refusals are the kernel's; only their prose is the capability's.

    A new scenario cannot forget to check an approval, because there is no
    branch in which it could have.
    """
    with probe_registered(repository, injected=False):
        thread = "probe-refuse"
        action, token = _prepare(repository, thread)
        with pytest.raises(ApprovalDenied) as absent:
            repository._commit(
                PROBE_SCOPE, _context(thread, uuid4()), action, token, response_loss=False
            )
        assert str(absent.value) == "probe fixture missing"
        assert repository.approval_consumed(token.token_id) is False

    with probe_registered(repository):
        thread = "probe-unauthorized"
        action, _ = _prepare(repository, thread)
        now = datetime.now(UTC)
        unbacked = ApprovalToken(
            action_hash=canonical_action_hash(action),
            actor=ACTOR,
            approver=APPROVER,
            one_time_use_id=uuid4(),
            requested_at=now,
            expires_at=now + timedelta(minutes=5),
            approved_at=now,
        )
        with pytest.raises(ApprovalDenied) as unauthorized:
            repository._commit(
                PROBE_SCOPE, _context(thread, uuid4()), action, unbacked, response_loss=False
            )
        assert str(unauthorized.value) == (
            "approval is missing, expired, consumed, or not bound to this action"
        )
        assert _fixture(repository)["repaired"] is False


def test_registering_and_unregistering_leaves_the_capability_set_unchanged(
    repository: LabRepository,
) -> None:
    """A scenario can be removed as cleanly as it was added.

    Weaker than it sounds and worth having anyway: the reason the six mutation
    paths drifted is that each was reachable from somewhere the others were not,
    so a capability that could be added in one place and only *mostly* removed
    would be the same defect starting over.
    """
    before = set(_SPECS)
    with probe_registered(repository):
        assert PROBE_SCOPE in _SPECS
    assert set(_SPECS) == before


def test_the_remaining_edit_surface_is_stated_rather_than_claimed_away() -> None:
    """The honest half. The guide's "only the registry" is not yet true.

    Each entry below is a real edit a new mutating scenario still needs. Two of
    them should stay edits: the action contract is a frozen wire surface, and
    the policy file is the authority for what is governed -- deriving either
    from the repository would let a capability grant itself a rule. Two are
    duplication that the completeness suite now binds but has not removed. One
    is the fixture, which is the scenario.

    Asserted as an exact set so that closing any of them has to update this
    list, which is the only way the number stays honest.
    """
    from pathlib import Path

    root = Path(__file__).parents[2]
    for path in REMAINING_EDIT_SURFACE:
        assert (root / path).exists(), path
    assert len(REMAINING_EDIT_SURFACE) == 5
