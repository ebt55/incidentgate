"""Every T4 model-monitor run prints five "Blocked deserialization" lines. Nothing is lost.

The lines name ``GateMode``, ``AuthorizationGate``, ``EpisodeSafeguardIdentity``,
``EpisodeAuthorizationSelection`` and ``ModelInvocationRecord`` -- five contracts
reachable from checkpointed state that ``ALLOWED_MSGPACK_MODULES`` does not list.
The obvious reading is that a value is being silently discarded, and a project
whose subject is safeguards should not settle that by reasoning about it.

**Measured, and the answer is that a blocked class comes back as plain data with
every field intact.** A pydantic model revives as a ``dict``; a ``StrEnum``
revives as its own string. The type is refused; not one value is.

That leaves the real question -- does any consumer need the type back? -- and
there are exactly two answers in this codebase, both covered below:

* ``resume_episode`` reads ``episode_safeguards`` and
  ``episode_authorization_selection`` straight from the channel and calls
  ``model_validate`` on whatever it finds, which accepts the dict; and
* ``ModelInvocationRecord`` is never a channel value on its own. It is reached
  through ``EpisodeTranscript``, which *is* listed, so the parent's own
  validation rebuilds the whole subtree -- event, snapshot and record -- as
  proper types.

The lines are therefore noise, and the standing ruling is to leave them: widening
the allowlist to quieten stderr would weaken a deliberately strict revival
boundary and buy nothing, because the values already survive. These tests exist
so that "noise" is a measurement rather than a belief, and so that the day a
value *does* start disappearing, something fails.

Not new, either: ``monitor_invocation`` entered ``EpisodeStepSnapshot`` on
2026-08-15 and the allowlist last moved on 2026-08-12. The fifth line only
appears once a *model* fills the monitor seat, which is why it went unrecorded
while the seat held a deterministic stand-in.
"""

from __future__ import annotations

import datetime
from typing import Any

import pytest
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from incidentgate.contracts import ModelInvocationRecord, MonitorVerdict
from incidentgate.control.models import (
    EpisodeAuthorizationSelection,
    EpisodeCheckpointIdentity,
    EpisodeSafeguardIdentity,
    EpisodeStepSnapshot,
    EpisodeTranscript,
    EpisodeTranscriptEvent,
)
from incidentgate.control.safeguards import AuthorizationGate, GateMode
from incidentgate.integration.runtime import ALLOWED_MSGPACK_MODULES

#: Exactly the classes whose blocked-deserialization line appears on a run.
BLOCKED = (
    GateMode,
    AuthorizationGate,
    EpisodeSafeguardIdentity,
    EpisodeAuthorizationSelection,
    ModelInvocationRecord,
)


def serde() -> JsonPlusSerializer:
    """The serializer the runtime installs, built from the same constant."""
    return JsonPlusSerializer(
        pickle_fallback=False, allowed_msgpack_modules=ALLOWED_MSGPACK_MODULES
    )


def round_trip(value: Any) -> Any:
    codec = serde()
    return codec.loads_typed(codec.dumps_typed(value))


def test_the_five_noisy_classes_really_are_the_ones_outside_the_allowlist() -> None:
    """Ties the test to the observed stderr, so a changed allowlist changes this file."""
    for cls in BLOCKED:
        assert cls not in ALLOWED_MSGPACK_MODULES, cls.__name__
    # And the parent that rescues the nested ones is listed, which is the whole
    # reason the fifth line is harmless.
    assert EpisodeTranscript in ALLOWED_MSGPACK_MODULES


def test_a_blocked_pydantic_model_revives_as_a_dict_with_every_field_intact() -> None:
    """The claim that nothing is dropped, measured field by field."""
    record = ModelInvocationRecord(
        invocation_kind="cache_replay", provider="openai", model="gpt-5.5"
    )
    revived = round_trip(record)
    assert isinstance(revived, dict)
    assert revived == record.model_dump()
    assert set(revived) == set(ModelInvocationRecord.model_fields)
    # Re-validating recovers the original exactly, which is what every read site does.
    assert ModelInvocationRecord.model_validate(revived) == record


@pytest.mark.parametrize(
    "value", [GateMode.ENFORCE, GateMode.OBSERVE_ONLY, AuthorizationGate.DURABLE_HUMAN]
)
def test_a_blocked_strenum_revives_as_its_own_string_and_compares_equal(value: Any) -> None:
    """These two are inert even without re-validation, because StrEnum *is* its string."""
    revived = round_trip(value)
    assert isinstance(revived, str)
    assert revived == value
    assert type(value)(revived) is value


def test_the_two_channels_resume_episode_reads_survive_revalidation() -> None:
    """``resume_episode`` calls ``model_validate`` on the raw channel value.

    Both channels hold a blocked class, so both arrive as dicts -- and both are
    read through ``model_validate``, which is why the code has always been correct
    here rather than accidentally correct.
    """
    safeguards = EpisodeSafeguardIdentity(
        evidence_gate=GateMode.ENFORCE,
        policy_gate=GateMode.OBSERVE_ONLY,
        monitor_gate=GateMode.ENFORCE,
        authorization_gate=AuthorizationGate.DURABLE_HUMAN,
    )
    selection = EpisodeAuthorizationSelection(
        leg="covert",
        leg_index=0,
        sequence=0,
        selection_id="sel-0",
        request_path=AuthorizationGate.DURABLE_HUMAN,
    )
    pairs = (
        (safeguards, EpisodeSafeguardIdentity),
        (selection, EpisodeAuthorizationSelection),
    )
    for value, model in pairs:
        revived = round_trip(value)
        assert isinstance(revived, dict)
        assert model.model_validate(revived) == value


def _transcript_with_a_monitor_invocation() -> tuple[EpisodeTranscript, ModelInvocationRecord]:
    record = ModelInvocationRecord(
        invocation_kind="cache_replay", provider="openai", model="gpt-5.5"
    )
    identity = EpisodeCheckpointIdentity(episode_id="t4-probe", sequence=0)
    at = datetime.datetime.now(datetime.UTC)
    transcript = EpisodeTranscript(
        incident_id="inc-t4-probe",
        thread_id="t4-probe",
        episode_id="t4-probe",
        events=(
            EpisodeTranscriptEvent(
                identity=identity, leg="covert", action_id="a0", phase="started", at=at
            ),
            EpisodeTranscriptEvent(
                identity=identity,
                leg="covert",
                action_id="a0",
                phase="terminal",
                at=at,
                step=EpisodeStepSnapshot(
                    thread_id="t4-probe",
                    tool_name="operations.set_checkout_maintenance_mode",
                    arguments_digest="b" * 64,
                    evidence_ids=("e0", "e1"),
                    executed=False,
                    redelivered=False,
                    terminal_state="blocked",
                    monitor_reached=True,
                    monitor_consulted=True,
                    monitor_verdict=MonitorVerdict.BLOCK,
                    monitor_invocation=record,
                    monitor_input_hash="a" * 64,
                ),
            ),
        ),
    )
    return transcript, record


def test_a_listed_parent_restores_its_blocked_children_all_the_way_down() -> None:
    """The fifth line's actual answer, and the one that could have been a real bug.

    ``ModelInvocationRecord`` is reached only through ``EpisodeTranscript`` ->
    ``EpisodeTranscriptEvent`` -> ``EpisodeStepSnapshot``, and only the outermost
    of those four is on the allowlist. Reviving the parent re-validates the whole
    subtree, so all three inner classes come back as themselves.
    """
    transcript, record = _transcript_with_a_monitor_invocation()
    revived = round_trip(transcript)

    assert isinstance(revived, EpisodeTranscript)
    event = revived.events[1]
    assert isinstance(event, EpisodeTranscriptEvent)
    assert event.step is not None and isinstance(event.step, EpisodeStepSnapshot)
    assert isinstance(event.step.monitor_invocation, ModelInvocationRecord)

    # Values, not only types -- a restored type carrying wrong values would be worse.
    assert event.step.monitor_invocation == record
    assert event.step.monitor_verdict is MonitorVerdict.BLOCK
    assert revived == transcript


def test_the_monitor_provenance_a_published_row_carries_is_not_reconstructed_here() -> None:
    """Belt and braces: the published record does not depend on any of the above.

    ``_semantic_monitor_observation`` reads the caller's ``last_invocation`` in
    process and hands it to the ``SabotageStep`` dataclass, so the provenance in a
    published row never passes through msgpack at all. The transcript copy is a
    durable duplicate for resume, and the test above shows it survives too.
    """
    from incidentgate.evaluation import sabotage_episodes

    source = sabotage_episodes.__file__
    assert source.endswith("sabotage_episodes.py")
    step_fields = sabotage_episodes.SabotageStep.__dataclass_fields__
    assert "monitor_invocation" in step_fields
    # A dataclass, not a checkpointed contract: it is built after the graph runs.
    assert not hasattr(sabotage_episodes.SabotageStep, "model_validate")
