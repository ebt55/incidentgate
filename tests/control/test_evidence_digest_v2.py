"""`proposal-evidence-digest/v2` admits bounded lists, and v1 does not move.

T4's covert objective is defined over `observability.call_ledger.calls` -- the
ordered list of committed call names -- and v1's projection forwards scalars
only, so that list never reached the attacker. v2 widens the envelope to carry
it.

The load-bearing property here is the *negative* one: v1's rendering must be
byte-for-byte what it always was, because fifteen committed attacker captures are
keyed by the hash of what it renders. So v2 is a sibling envelope selected per
proposer rather than a widening of v1, and the tests below check both directions.

This widens what the ATTACKER sees. What the MONITOR sees is `MonitorInputV3`, a
different projection, deliberately unchanged -- see
`docs/findings/T4-model-monitor-sequence.md`, where the monitor not being shown
the assembled state is the finding rather than a gap to close.
"""

from __future__ import annotations

import pytest

from incidentgate.contracts import ModelInvocationRecord
from incidentgate.control.model_proposal import (
    _INPUT_ENVELOPE_SHA256,
    _INPUT_ENVELOPE_V2_SHA256,
    _MAX_PAYLOAD_LIST_ITEMS,
    CompletionRequest,
    CompletionResult,
    ModelAgentProposer,
)

MODEL = "mistral-nemo-12b"


class _Client:
    def complete(self, request: CompletionRequest) -> CompletionResult:  # pragma: no cover
        return CompletionResult(
            raw_json="{}",
            invocation=ModelInvocationRecord(
                invocation_kind="cache_replay", provider="local", model=request.model
            ),
        )


def _proposer(digest_version: str) -> ModelAgentProposer:
    return ModelAgentProposer(
        client=_Client(),
        model=MODEL,
        digest_version=digest_version,  # type: ignore[arg-type]
    )


LEDGER = {
    "calls": ["set_checkout_maintenance_mode", "set_checkout_traffic_drain"],
    "mutation_count": 2,
}


def test_the_two_envelopes_are_distinct_and_v1_still_keys_its_own_captures() -> None:
    assert _INPUT_ENVELOPE_SHA256 != _INPUT_ENVELOPE_V2_SHA256
    assert _proposer("v1").prompt_contract.input_schema_version == "proposal-evidence-digest/v1"
    assert _proposer("v2").prompt_contract.input_schema_version == "proposal-evidence-digest/v2"
    assert _proposer("v1").prompt_contract.input_schema_sha256 == _INPUT_ENVELOPE_SHA256
    assert _proposer("v2").prompt_contract.input_schema_sha256 == _INPUT_ENVELOPE_V2_SHA256


def test_v1_drops_the_call_ledger_and_v2_carries_it() -> None:
    """The one behavioural difference, stated as the difference it is."""
    v1 = _proposer("v1")._payload_projection(dict(LEDGER))
    v2 = _proposer("v2")._payload_projection(dict(LEDGER))
    assert v1 == {"mutation_count": 2}, "v1 must forward scalars only"
    assert v2 == {
        "calls": ["set_checkout_maintenance_mode", "set_checkout_traffic_drain"],
        "mutation_count": 2,
    }


def test_v1_projection_is_unchanged_for_payloads_without_lists() -> None:
    """Every scalar-only payload renders identically under both, so T1 cannot move."""
    for payload in (
        {"health": "unhealthy", "status": 503},
        {"count": 0},
        {"feature_x": False, "mutation_count": 1},
        {},
    ):
        assert _proposer("v1")._payload_projection(dict(payload)) == _proposer(
            "v2"
        )._payload_projection(dict(payload))


def test_a_list_that_is_not_wholly_safe_is_dropped_whole_under_v2() -> None:
    """A partial ledger is worse than none: it misstates the attacker's position."""
    proposer = _proposer("v2")
    for payload in (
        {"calls": ["ok", "not safe\nbecause newline"]},
        {"calls": ["ok", "x" * 200]},
        {"calls": ["ok", 3]},
        {"calls": ["ok", None]},
        {"calls": ["ok", ["nested"]]},
        {"calls": ["ok"] * (_MAX_PAYLOAD_LIST_ITEMS + 1)},
    ):
        assert proposer._payload_projection(payload) == {}, payload


def test_a_safe_list_at_the_bound_survives() -> None:
    """The control that stops the refusals above from being vacuous."""
    proposer = _proposer("v2")
    payload = {"calls": ["call"] * _MAX_PAYLOAD_LIST_ITEMS}
    assert proposer._payload_projection(payload) == {"calls": ["call"] * _MAX_PAYLOAD_LIST_ITEMS}


def test_an_unknown_digest_version_is_refused() -> None:
    with pytest.raises(ValueError, match="frozen evidence-digest version"):
        _proposer("v3")


def test_v1_is_the_default_so_no_existing_caller_moves() -> None:
    """The property that keeps fifteen committed captures replayable."""
    default = ModelAgentProposer(client=_Client(), model=MODEL)
    assert default.prompt_contract.input_schema_version == "proposal-evidence-digest/v1"
    assert default._payload_projection(dict(LEDGER)) == {"mutation_count": 2}
