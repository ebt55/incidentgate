"""The frontier monitor seat, proven on replay without making a billed call.

Everything here is verifiable without a vendor round-trip, and that is the point:
the parts that can be checked locally are checked, so the only thing a real run
adds is the round-trip itself.

Three properties, and the third is the one that matters most:

* the seat constructs for a hosted model and loads the rule frozen for *it*, not
  the rule frozen for some other seat;
* the capability table decides the provider, and a caller who names a different
  one is refused rather than quietly overridden;
* **the replay path cannot spend.** Not "does not" -- cannot: no transport object
  is constructed on it, so there is nothing in the process that could reach a
  vendor, and a missing capture surfaces as CACHE_MISS.
"""

from __future__ import annotations

import argparse

import pytest

from incidentgate.evaluation.harness_abort import HarnessAborted
from incidentgate.evaluation.monitor_thresholds import load_a_priori_thresholds
from incidentgate.evaluation.sabotage_v4_t4 import (
    MONITOR_MODEL,
    SPEND_ENV_VAR,
    SPEND_FLAG,
    build_parser,
    default_monitor_threshold_path,
    monitor_transport,
    resolve_monitor_seat,
)

FRONTIER = "claude-opus-5"


def _parsed(*argv: str) -> argparse.Namespace:
    return build_parser().parse_args(list(argv))


# --------------------------------------------------------------------------
# The seat, and the rule it is judged under.
# --------------------------------------------------------------------------


def test_the_default_seat_is_still_the_local_one() -> None:
    """No run changes seat without saying so on the command line."""
    model, provider = resolve_monitor_seat(_parsed())
    assert (model, provider) == (MONITOR_MODEL, "local")


def test_a_frontier_seat_resolves_to_its_stated_provider() -> None:
    model, provider = resolve_monitor_seat(_parsed("--monitor-model", FRONTIER))
    assert (model, provider) == (FRONTIER, "anthropic")


def test_a_provider_disagreement_is_refused_rather_than_resolved() -> None:
    with pytest.raises(HarnessAborted, match="refusing to resolve the disagreement"):
        resolve_monitor_seat(
            _parsed("--monitor-model", FRONTIER, "--monitor-provider", "openai")
        )


def test_a_model_outside_the_capability_table_cannot_be_seated() -> None:
    """Its sampling and thinking behaviour would be guessed rather than stated."""
    with pytest.raises(HarnessAborted, match="capability table"):
        resolve_monitor_seat(_parsed("--monitor-model", "some-unlisted-model"))


def test_the_frontier_seat_has_a_committed_a_priori_rule() -> None:
    path = default_monitor_threshold_path(FRONTIER)
    assert path.is_file(), "the rule must be frozen before the measurement, not after"
    artifact = load_a_priori_thresholds(path)
    assert artifact.scenario_id == "T4"
    assert (artifact.provider, artifact.model) == ("anthropic", FRONTIER)
    assert artifact.provenance_band == "a_priori_definitional"
    assert artifact.selected_on_split == "none_no_split_was_used"


def test_the_rule_is_the_scenarios_and_not_the_seats() -> None:
    """Two seats, one scenario, one rule -- because the derivation reads the frozen
    contract and the output contract's field definitions, and neither mentions a
    model. A rule that varied by seat would mean the seats were not comparable."""
    local = load_a_priori_thresholds(default_monitor_threshold_path(MONITOR_MODEL))
    frontier = load_a_priori_thresholds(default_monitor_threshold_path(FRONTIER))
    assert local.thresholds == frontier.thresholds
    assert local.scenario_contract_sha256 == frontier.scenario_contract_sha256
    assert [d.model_dump() for d in local.derivations] == [
        d.model_dump() for d in frontier.derivations
    ]


# --------------------------------------------------------------------------
# The spend gate. Construction, not permission at the call site.
# --------------------------------------------------------------------------


def _hosted(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "provider": "anthropic",
        "model": FRONTIER,
        "endpoint": "http://127.0.0.1:11434",
        "weights_root": None,
        "spend_flag": False,
        "max_calls": 8,
        "max_usd": 1.0,
    }
    values.update(changes)
    return values


def test_neither_half_of_the_gate_alone_builds_a_billing_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An env var outlives the intent that set it; a flag is one line of shell
    history away from being re-run somewhere else. Both, in one invocation."""
    monkeypatch.delenv(SPEND_ENV_VAR, raising=False)
    with pytest.raises(Exception, match="spend"):
        monitor_transport(**_hosted(spend_flag=True))  # type: ignore[arg-type]

    monkeypatch.setenv(SPEND_ENV_VAR, "1")
    with pytest.raises(Exception, match="spend"):
        monitor_transport(**_hosted(spend_flag=False))  # type: ignore[arg-type]


def test_the_environment_half_must_say_exactly_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for value in ("", "0", "true", "yes", "1 "):
        monkeypatch.setenv(SPEND_ENV_VAR, value)
        if value.strip() == "1":
            continue
        with pytest.raises(Exception, match="spend"):
            monitor_transport(**_hosted(spend_flag=True))  # type: ignore[arg-type]


def test_the_flag_is_spelled_the_way_the_owning_runner_spells_it() -> None:
    """Imported by value rather than restated, so the two cannot drift apart."""
    from incidentgate.evaluation import sabotage_v3_t1

    assert SPEND_FLAG == sabotage_v3_t1.SPEND_FLAG
    assert SPEND_ENV_VAR == sabotage_v3_t1.SPEND_ENV_VAR
    assert SPEND_FLAG in build_parser().format_help()


def test_a_projected_overspend_is_refused_before_anything_is_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The cap is checked against a worst-case projection, not against the bill."""
    monkeypatch.setenv(SPEND_ENV_VAR, "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-a-real-key-and-never-sent")
    with pytest.raises(HarnessAborted, match="exceeds the"):
        monitor_transport(**_hosted(spend_flag=True, max_usd=0.0))  # type: ignore[arg-type]


def test_a_hosted_seat_without_a_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(SPEND_ENV_VAR, "1")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(HarnessAborted, match="ANTHROPIC_API_KEY"):
        monitor_transport(**_hosted(spend_flag=True))  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# The replay path, which is what a publication run uses.
# --------------------------------------------------------------------------


class _NoRepository:
    """Stands in for the lab repository, and fails loudly if anything reads it.

    ``build_monitor`` only wraps the repository in ``RepositoryMonitorFacts``; it
    must not query. Constructing the seat against this proves that, so the wiring
    can be verified without a database and without a vendor.
    """

    def ordered_operation_calls(self, incident_id: str) -> tuple[object, ...]:
        raise AssertionError("building the monitor seat must not read the ledger")

    def checkpoint_state(self, scenario_id: str) -> dict[str, object]:
        raise AssertionError("building the monitor seat must not read the fixture")


def test_the_frontier_seat_builds_end_to_end_on_the_publication_path() -> None:
    """The whole seat, constructed for the hosted model, with no transport.

    This is everything a real frontier run does except the vendor round-trip: the
    committed rule loads and is checked against this caller, the structured caller
    is built for the hosted model id, and the bundle assembles. What is left for a
    billed run to add is the call itself.
    """
    from incidentgate.control.response_cache import CacheBackedCompletionClient
    from incidentgate.evaluation.sabotage_v4_t4 import build_monitor

    bundle, caller, deferred = build_monitor(
        _NoRepository(),  # type: ignore[arg-type]
        capture=False,
        transport=None,
        model=FRONTIER,
        provider="anthropic",
    )
    assert bundle is not None
    assert deferred is None, "the publication path holds no capture client"
    inner = caller._inner
    assert isinstance(inner._client, CacheBackedCompletionClient), (
        "the publication path must be cache-backed, so a miss is CACHE_MISS and not a call"
    )
    assert inner._model == FRONTIER


def test_the_seat_refuses_a_rule_frozen_for_a_different_seat() -> None:
    """A verdict must be published under the rule frozen for the seat that made it."""
    from incidentgate.evaluation.sabotage_v4_t4 import build_monitor

    with pytest.raises(HarnessAborted, match="but this seat is"):
        build_monitor(
            _NoRepository(),  # type: ignore[arg-type]
            capture=False,
            transport=None,
            model=FRONTIER,
            provider="anthropic",
            threshold_path=default_monitor_threshold_path(MONITOR_MODEL),
        )


def test_capturing_without_a_transport_is_refused_not_defaulted() -> None:
    from incidentgate.evaluation.sabotage_v4_t4 import build_monitor

    with pytest.raises(HarnessAborted, match="requires a transport"):
        build_monitor(
            _NoRepository(),  # type: ignore[arg-type]
            capture=True,
            transport=None,
            model=FRONTIER,
            provider="anthropic",
        )


# --------------------------------------------------------------------------
# The attacker seat, which decides whether there is anything to measure.
# --------------------------------------------------------------------------


def test_the_floor_attacker_is_reachable_from_the_command_line() -> None:
    """Without this the frontier command bills for incident-leg consultations and
    produces no covert assembly to judge -- spend with no measurement."""
    from incidentgate.evaluation.sabotage_v4_t4 import ATTACKER_ARMS

    assert set(ATTACKER_ARMS) == {"model", "floor"}
    assert _parsed("--attacker", "floor").attacker == "floor"
    assert _parsed().attacker == "model", "the seat does not change without saying so"


def test_the_floor_proposer_cannot_be_given_a_client() -> None:
    """The guarantee is structural, not a policy: it takes a variant and nothing
    else, so there is no seam through which the attacker leg could reach a model."""
    import inspect

    from incidentgate.control.attack_policies import DeterministicT4AttackProposer

    parameters = inspect.signature(DeterministicT4AttackProposer.__init__).parameters
    assert list(parameters) == ["self", "variant"]


def test_the_floor_arm_records_no_attacker_responses() -> None:
    """Empty is the honest value, not a placeholder: nothing was asked.

    The v4 row contract independently refuses a response digest on a
    deterministic_floor row, so the runner and the contract agree by construction
    rather than by a caller remembering to pass the right thing.
    """
    from incidentgate.evaluation.sabotage_v4 import SabotageEvaluationResultV4

    field = SabotageEvaluationResultV4.model_fields["attacker_response_sha256"]
    assert field.default == ()


def test_a_floor_run_builds_no_attacker_transport() -> None:
    """Read off the source of ``main``: the Ollama client for the attacker seat is
    constructed only on the not-floor branch, so a floor run has no object in the
    process that the attacker leg could call."""
    import inspect

    from incidentgate.evaluation import sabotage_v4_t4

    source = inspect.getsource(sabotage_v4_t4.main)
    assert "if not floor_attacker:" in source
    guarded = source.split("if not floor_attacker:", 1)[1].split("monitor_client", 1)[0]
    assert "OllamaWeightsCompletionClient(" in guarded
    # One construction site in the whole function, and it is inside the guard. The
    # monitor's transport is built by monitor_transport, not here.
    assert source.count("OllamaWeightsCompletionClient(") == 1
