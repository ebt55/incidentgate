"""The evaluation lanes derive their idempotency keys, and one thing stays random.

WHY THESE ARE STRUCTURAL TESTS
==============================

Every claim here is about what the *source* does, not about what one run
happened to do, because the failure mode is a future edit rather than a present
bug. A new lane that mints ``uuid4()`` for a key, or a new producer of the frozen
``triage-agent-lab:d1:`` seed, would both pass every behavioural test in the
repository on the day they landed and be wrong from then on.

The three things being held apart:

  * an **idempotency key** must be derived, or a redelivery writes a second row
    and exactly-once is unexercised on that path;
  * a **one_time_use_id** must be random, or two runs of one step share the
    single use the anti-replay boundary exists to refuse twice;
  * the **frozen seed** must gain no new producers -- it is persisted in
    ``operation_ledger`` and compared for exact equality by ``chaos/enddiff.py``,
    so a second producer is a second thing that can change it.
"""

from __future__ import annotations

import ast
import pathlib
import re
from uuid import UUID, uuid5

import pytest

from incidentgate.control.workflow import _IDEMPOTENCY_KEY_PREFIX, _idempotency_key
from incidentgate.evaluation.identity import (
    CHECKPOINT_B_IDEMPOTENCY_SEED,
    RELIABILITY_V2_IDEMPOTENCY_SEED,
    derived_idempotency_key,
)

SRC = pathlib.Path(__file__).parents[2] / "src" / "incidentgate"
EVALUATION = SRC / "evaluation"


def sources(root: pathlib.Path) -> dict[pathlib.Path, str]:
    return {path: path.read_text(encoding="utf-8") for path in sorted(root.rglob("*.py"))}


def _docstring_nodes(tree: ast.Module) -> set[int]:
    """Every string constant that is a docstring, by identity.

    Needed because "the seed appears in this file" and "this file produces the
    seed" are different claims, and only the second one matters. Three modules
    discuss the frozen seed in prose -- deliberately, because a wire value nobody
    explains is a wire value someone renames -- and counting those as producers
    would force the explanations out.
    """
    found: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        body = getattr(node, "body", [])
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            found.add(id(body[0].value))
    return found


# ---------------------------------------------------------------------------
# THE FROZEN SEED GAINS NO NEW PRODUCERS
# ---------------------------------------------------------------------------
def test_the_frozen_idempotency_seed_has_exactly_one_producer_in_the_source() -> None:
    """One literal, in ``control/workflow.py``, and nowhere else under ``src/``.

    The seed deliberately tracks neither the project name (renamed to
    incidentgate) nor the scenario -- the ``:d1:`` segment is baked in for D2,
    D3, D5, D8 and every R-tier scenario too -- so a reader who assumes it is a
    display name and "corrects" it converts exactly-once crash replay into
    duplicate mutation. One producer is what makes that a one-line review.

    Scoped to ``src/`` on purpose: ``tests/chaos/test_orphaned_approvals.py``
    restates the literal deliberately, so that it asserts against the frozen wire
    format rather than against whatever the workflow computes today. A test-side
    copy is a second *reader*, which is the useful kind.

    "Producer" means a live string constant, not an appearance. Three modules
    name the seed in prose to explain why they did *not* reuse it, and a check
    that counted those would push the explanations out of the code -- which is
    the opposite of what a frozen wire value needs.
    """
    producers: set[str] = set()
    mentions: set[str] = set()
    for path, body in sources(SRC).items():
        tree = ast.parse(body)
        docstrings = _docstring_nodes(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if "triage-agent-lab:d1:" not in node.value:
                continue
            name = path.relative_to(SRC).as_posix()
            (mentions if id(node) in docstrings else producers).add(name)
    assert producers == {"control/workflow.py"}, (
        "the frozen idempotency seed gained a producer; wire values are forever, and a "
        f"second one is a second thing that can change it: {sorted(producers)}"
    )
    # Anti-vacuity for the docstring exemption: it exists because modules really
    # do explain the seed, and if they stopped the exemption should be noticed
    # rather than silently protecting nothing.
    assert mentions, "no module explains the frozen seed any more; the exemption is now dead"


def test_the_frozen_seed_still_derives_its_golden_uuid() -> None:
    """Restated here beside the lanes that copied its *shape* but not its seed.

    ``tests/control/test_workflow.py`` owns this assertion too. It is repeated
    rather than referenced because the point being made here is different: the
    evaluation lanes now derive keys the same way, and the thing that must stay
    true is that they did not derive them from *this*.
    """
    assert _IDEMPOTENCY_KEY_PREFIX == "triage-agent-lab:d1:"
    assert str(_idempotency_key("hash-golden", "thread-golden")) == (
        "6ec918c4-5943-52d3-9a13-c9661a6cf154"
    )


def test_no_lane_seed_collides_with_another_or_with_the_frozen_one() -> None:
    """Two lanes sharing a seed would derive one key from one binding.

    The collision would present as a spurious ``duplicate`` -- the ledger doing
    its job on a delivery that was never a redelivery -- which is a defect that
    looks like a guarantee.
    """
    seeds = [
        _IDEMPOTENCY_KEY_PREFIX,
        CHECKPOINT_B_IDEMPOTENCY_SEED,
        RELIABILITY_V2_IDEMPOTENCY_SEED,
    ]
    assert len(set(seeds)) == len(seeds)
    binding = ("thread-x", "hash-y")
    keys = {derived_idempotency_key(seed, *binding) for seed in seeds}
    assert len(keys) == len(seeds)


# ---------------------------------------------------------------------------
# THE DERIVATION IS A FUNCTION OF THE DELIVERY
# ---------------------------------------------------------------------------
def test_the_derived_key_is_a_pure_function_of_seed_thread_and_action() -> None:
    first = derived_idempotency_key(CHECKPOINT_B_IDEMPOTENCY_SEED, "thread-1", "hash-1")
    assert first == derived_idempotency_key(CHECKPOINT_B_IDEMPOTENCY_SEED, "thread-1", "hash-1")
    assert first != derived_idempotency_key(CHECKPOINT_B_IDEMPOTENCY_SEED, "thread-2", "hash-1")
    assert first != derived_idempotency_key(CHECKPOINT_B_IDEMPOTENCY_SEED, "thread-1", "hash-2")
    # uuid5, not uuid4: the value is reproducible from its inputs by anyone.
    assert first.version == 5
    assert first == uuid5(UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8"),
                          f"{CHECKPOINT_B_IDEMPOTENCY_SEED}thread-1:hash-1")


def test_the_derivation_shape_matches_the_graphs_without_sharing_its_seed() -> None:
    """Copy the property, leave the wire value. Asserted both directions.

    Same shape means a reviewer can reason about one derivation rather than
    three; a different seed means the frozen one is untouched. A test that
    checked only the first would pass on the day someone reused the seed.
    """
    lane = derived_idempotency_key(CHECKPOINT_B_IDEMPOTENCY_SEED, "t", "h")
    frozen = _idempotency_key("h", "t")
    assert lane != frozen
    # The shape: seed, then thread, then action hash, under the URL namespace.
    assert lane == uuid5(UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8"),
                         f"{CHECKPOINT_B_IDEMPOTENCY_SEED}t:h")
    assert frozen == uuid5(UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8"),
                           f"{_IDEMPOTENCY_KEY_PREFIX}t:h")


# ---------------------------------------------------------------------------
# NO BARE uuid4 KEY SURVIVES, AND one_time_use_id IS STILL ONE
# ---------------------------------------------------------------------------
def test_no_evaluation_lane_assigns_an_idempotency_key_from_uuid4() -> None:
    """A sweep, not a list. The guide's line references had already drifted.

    Written as a scan over the AST rather than as three named line numbers
    because a fixed list is exactly what stops catching the fourth site. Any
    assignment to a name containing ``key``, or any ``idempotency_key=``
    keyword, whose value is a bare ``uuid4()`` call is a finding.
    """
    offenders: list[str] = []
    for path, body in sources(EVALUATION).items():
        tree = ast.parse(body)
        for node in ast.walk(tree):
            value: ast.expr | None = None
            label = ""
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and "key" in target.id.lower():
                    value, label = node.value, target.id
            elif isinstance(node, ast.keyword) and node.arg == "idempotency_key":
                value, label = node.value, "idempotency_key="
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "uuid4"
            ):
                offenders.append(f"{path.relative_to(SRC).as_posix()}:{node.lineno} ({label})")
    assert not offenders, (
        "an idempotency key minted from uuid4 is a fresh identity every time, so a "
        f"redelivery writes a second row instead of collapsing: {offenders}"
    )


def test_every_one_time_use_id_in_the_source_is_minted_randomly_or_carried() -> None:
    """The one identity that must NOT be derived, held from the other side.

    A derived ``one_time_use_id`` would make two runs of one step share the
    single use the anti-replay boundary exists to refuse twice -- and the second
    run's correct refusal would then read as a defect. Scanned across all of
    ``src/`` rather than the evaluation lane alone, because the runtime and the
    deterministic authorization control mint them too.

    Three shapes appear and only one of them can be wrong:

      * a **mint** creates the value, and must be ``uuid4()``;
      * a **carry** passes an existing one along -- ``ApprovalService`` copies
        the request's into the token it issues;
      * a **revival** parses one back out of durable state with ``UUID(...)``.

    Only a mint has any freedom, so only a mint is constrained. The classification
    is closed: anything that is none of the three fails, which is what keeps a
    ``uuid5`` mint from arriving through a shape this test forgot to name.
    """
    mints: list[str] = []
    carried: list[str] = []
    for path, body in sources(SRC).items():
        tree = ast.parse(body)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.keyword) and node.arg == "one_time_use_id"):
                continue
            where = f"{path.relative_to(SRC).as_posix()}:{node.lineno}"
            value = node.value
            if isinstance(value, ast.Name | ast.Attribute | ast.Subscript):
                carried.append(where)
                continue
            revival = (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "UUID"
            )
            if revival:
                carried.append(where)
                continue
            assert (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "uuid4"
            ), (
                f"{where} mints its one_time_use_id from something other than uuid4; two runs "
                "of one step would then share the single use the boundary refuses twice"
            )
            mints.append(where)
    # Anti-vacuity in both directions: a scan that found no mints would pass for
    # the wrong reason, and one that found no carries would mean the shape this
    # test exempts no longer exists and the exemption should go.
    assert len(mints) >= 4, mints
    assert carried, carried


# ---------------------------------------------------------------------------
# THE ISOLATION THE DERIVATION COSTS IS ACTUALLY PAID
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "module",
    ["runner.py", "reliability_v2.py", "sabotage_episodes.py"],
    ids=["checkpoint_b", "reliability_v2", "sabotage"],
)
def test_every_lane_with_derived_identities_purges_its_threads(module: str) -> None:
    """A derived thread id resumes a completed graph unless something clears it.

    ``LabRepository.reset_checkpoint`` clears the lab's tables and not the
    checkpointer's, which is invisible while thread ids are random. Each lane
    that derives its identities has to pay that cost, so each is required to call
    the purge -- and to call it before it drives, which is what the
    behavioural tests in the same lanes then exercise.
    """
    body = (EVALUATION / module).read_text(encoding="utf-8")
    assert re.search(r"\b(purge_checkpoint_threads|_purge_threads)\(", body), (
        f"{module} derives thread ids and idempotency keys but never purges a thread; "
        "a second run would resume the first run's completed graph"
    )


def test_the_runners_no_longer_reach_into_the_runtimes_private_checkpointer() -> None:
    """The purge is a named boundary now, not a reach-through.

    ``runtime._checkpointer.delete_thread(thread)`` did the same job from inside
    the one arm that built a graph. Reaching through a private attribute is how
    the isolation ended up scoped to an arm rather than to a row.
    """
    offenders = [
        f"{path.relative_to(SRC).as_posix()}"
        for path, body in sources(EVALUATION).items()
        if "_checkpointer" in body
    ]
    assert not offenders, offenders
