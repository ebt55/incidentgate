"""Derived identities for the evaluation lanes, and the isolation they cost.

WHY AN EVALUATION ROW'S IDEMPOTENCY KEY MAY NOT BE RANDOM
=========================================================

An idempotency key is the identity a redelivery collapses onto. A ``uuid4`` one
is a fresh identity every time it is minted, so a replayed execution is simply a
second row -- which means the exactly-once boundary is *unexercised* on that
path, not merely untested. Both non-sabotage lanes published tables beside a
chaos matrix whose headline argument is that the ledger key is a pure function of
the binding, while deriving their own keys from nothing at all.

So a key here is ``uuid5`` over a lane seed, the thread, and the action hash:
the same delivery of the same action on the same thread derives the same key and
collapses onto its own ledger row, and two different steps derive different keys
and do not.

THE THREE THINGS THAT MUST NOT BE DERIVED
=========================================

1. ``one_time_use_id`` stays ``uuid4``, everywhere, always. It is the anti-replay
   token: a derived one would make two runs of the same step share the single use
   the boundary exists to refuse twice, and the refusal would then look like a
   defect rather than the guarantee.

2. The frozen ``triage-agent-lab:d1:`` seed in ``control/workflow.py`` gains no
   new producers. It is a wire value persisted in ``operation_ledger`` and
   compared for exact equality by ``chaos/enddiff.py``; what these lanes need
   from it is only the property it already has, so they take the property and
   leave the seed alone. ``tests/evaluation/test_derived_identities.py`` greps
   ``src/`` and requires exactly one producer.

3. The lane seeds are distinct from each other. Two lanes sharing a seed would
   let a checkpoint-B row and a reliability row derive one key from one binding,
   and the collision would present as a spurious duplicate rather than as a
   collision.

WHAT DERIVING DOES *NOT* BUY, MEASURED RATHER THAN ASSUMED
==========================================================

It does not make ``operation_id`` reproducible across runs, and it was not
expected to here either: the published id is ``f"{scope}:{idempotency_key}"``,
the key derives from the action hash, and ``canonical_action_hash`` covers
``evidence_ids``, which ``LabRepository`` mints as ``str(uuid4())`` at collection
time on every run. That residue lives in the shared evidence path and is the
same one ``sabotage_episodes`` measured and pinned. What deriving buys is the
property that matters for exactly-once: a *redelivery within a run* -- the same
action, the same thread, the same evidence -- lands on the same key.

DERIVED IDS COST ISOLATION, AND THE COST HAS TO BE PAID
=======================================================

``LabRepository.reset_checkpoint`` clears the lab's own tables, including
``operation_ledger``, so a derived key is free again on the next run. It does
**not** clear the LangGraph checkpointer's tables, which is invisible while every
thread carries a ``uuid4``: with derived ids a second run of the same row resumes
the first run's *completed* graph and hands back its terminal result instead of
running. :func:`purge_checkpoint_threads` is what pays that cost, and it is
called before a row drives anything rather than relied on not to matter.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final
from uuid import NAMESPACE_URL, UUID, uuid5

import psycopg

#: The checkpoint-B lane's seed. Distinct from the reliability lane's and from
#: the frozen graph seed; see the module docstring on why all three differ.
CHECKPOINT_B_IDEMPOTENCY_SEED: Final = "checkpoint-b-evaluation:"

#: The reliability-v2 lane's seed.
RELIABILITY_V2_IDEMPOTENCY_SEED: Final = "reliability-v2-evaluation:"


def derived_idempotency_key(seed: str, thread_id: str, action_hash: str) -> UUID:
    """Derive one lane's idempotency key from the delivery it identifies.

    The shape is the graph's, deliberately: seed, thread, action hash, in that
    order, under ``NAMESPACE_URL``. Copying the *shape* rather than the seed is
    the whole point -- the property transfers, the frozen wire value does not
    travel with it.
    """
    return uuid5(NAMESPACE_URL, f"{seed}{thread_id}:{action_hash}")


def purge_checkpoint_threads(dsn: str, thread_ids: Sequence[str]) -> None:
    """Drop the checkpoint rows for threads a run is about to reuse.

    Errors are swallowed per table on purpose: on a cold database the
    checkpointer's tables may not exist yet, because ``PostgresSaver.setup()``
    runs when the first runtime is constructed and a purge legitimately precedes
    that. A missing table means there is nothing to resume, which is the state
    this function exists to reach.

    ``chaos/matrix.py`` has a sibling of this for its own long runs. It is not
    imported: the evaluation lane deliberately does not depend on the chaos lane,
    and six lines of DELETE is a smaller price than that edge.
    """
    with psycopg.connect(dsn, autocommit=True) as connection:
        for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
            for thread_id in thread_ids:
                try:
                    connection.execute(f"DELETE FROM {table} WHERE thread_id = %s", (thread_id,))
                except psycopg.Error:
                    connection.rollback()
