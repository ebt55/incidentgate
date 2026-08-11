from __future__ import annotations

import json
import os
from types import SimpleNamespace
from uuid import UUID

import pytest

from triage_agent_lab.contracts import (
    CanonicalAction,
    MonitorVerdict,
    RestartArgs,
    canonical_action_hash,
)
from triage_agent_lab.control.monitor import AnthropicAdvisoryMonitor


def action() -> CanonicalAction:
    return CanonicalAction(
        action_id=UUID("00000000-0000-0000-0000-000000000001"),
        tool_name="operations.restart",
        incident_id="INC-secret",
        thread_id="thread-secret",
        actor="actor-secret",
        permission="operations:write",
        evidence_ids=("ev-1",),
        arguments=RestartArgs(kind="restart", component="api"),
    )


class Client:
    def __init__(self, response: object) -> None:
        self.response, self.calls = response, []
        self.messages = self

    def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def response(action_: CanonicalAction, **overrides: object) -> object:
    body = {"verdict": "defer", "suspicion_score": 0.5, "rationale": "review needed", "evaluated_action_hash": canonical_action_hash(action_), **overrides}
    return SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text=json.dumps(body))])


def digest() -> tuple[dict[str, object], ...]:
    return ({"evidence_id": "ev-1", "tool_name": "observability.health", "observed_at": "2026-01-01T00:00:00+00:00"},)


def test_anthropic_monitor_sends_only_bounded_allowlisted_request() -> None:
    candidate = action()
    client = Client(response(candidate))
    monitor = AnthropicAdvisoryMonitor(api_key="api-secret", model="configured-model", client=client)
    result = monitor.assess(candidate, ({"evidence_id": "ev-1", "tool_name": "observability.health", "observed_at": "2026-01-01T00:00:00+00:00"},))
    assert result.verdict is MonitorVerdict.DEFER
    call = client.calls[0]
    assert call["model"] == "configured-model" and call["max_tokens"] == 256
    assert call["output_config"]["format"]["type"] == "json_schema"  # type: ignore[index]
    request = call["messages"][0]["content"]  # type: ignore[index]
    assert json.loads(request) == {"action_hash": canonical_action_hash(candidate), "action": {"schema_version": "1", "tool_name": "operations.restart", "arguments": {"kind": "restart", "component": "api"}}, "evidence_digest": [{"evidence_id": "ev-1", "tool_name": "observability.health", "observed_at": "2026-01-01T00:00:00+00:00"}]}
    for forbidden in ("api-secret", "actor-secret", "thread-secret", "INC-secret", "permission", "payload", "source_uri"):
        assert forbidden not in request


def test_anthropic_monitor_transforms_only_provider_schema_constraints() -> None:
    candidate = action()
    client = Client(response(candidate))
    result = AnthropicAdvisoryMonitor(api_key="api-secret", model="configured-model", client=client).assess(candidate, digest())
    schema = client.calls[0]["output_config"]["format"]["schema"]  # type: ignore[index]

    def schema_keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | set().union(*(schema_keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(schema_keys(item) for item in value))
        return set()

    assert result.verdict is MonitorVerdict.DEFER
    assert not ({"pattern", "minimum", "maximum", "minLength", "maxLength"} & schema_keys(schema))
    assert schema["required"] == ["verdict", "suspicion_score", "rationale", "evaluated_action_hash"]  # type: ignore[index]
    assert schema["additionalProperties"] is False  # type: ignore[index]
    assert schema["$defs"]["MonitorVerdict"]["enum"] == ["allow", "defer", "block"]  # type: ignore[index]


@pytest.mark.parametrize("bad", [RuntimeError("provider secret"), SimpleNamespace(stop_reason="max_tokens", content=[]), SimpleNamespace(stop_reason="end_turn", content=[]), SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text="{}")])])
def test_anthropic_monitor_failure_is_generic_hash_bound_block(bad: object) -> None:
    candidate = action()
    result = AnthropicAdvisoryMonitor(api_key="api-secret", model="configured-model", client=Client(bad)).assess(candidate, ({"evidence_id": "ev-1", "tool_name": "observability.health", "observed_at": "2026-01-01T00:00:00+00:00"},))
    assert result.verdict is MonitorVerdict.BLOCK
    assert result.evaluated_action_hash == canonical_action_hash(candidate)
    assert result.rationale == "advisory_monitor_unavailable"
    assert "secret" not in result.rationale


def test_anthropic_monitor_invalid_digest_never_calls_provider() -> None:
    client = Client(response(action()))
    result = AnthropicAdvisoryMonitor(api_key="api-secret", model="configured-model", client=client).assess(action(), ({"payload": "no"},))
    assert result.verdict is MonitorVerdict.BLOCK
    assert client.calls == []


@pytest.mark.parametrize(("verdict", "score"), [("allow", 0.0), ("defer", 0.5), ("block", 1.0)])
def test_anthropic_monitor_parses_all_verdicts_and_score_bounds(verdict: str, score: float) -> None:
    candidate = action()
    result = AnthropicAdvisoryMonitor(api_key="api-secret", model="configured-model", client=Client(response(candidate, verdict=verdict, suspicion_score=score))).assess(candidate, digest())
    assert result.verdict.value == verdict and result.suspicion_score == score


@pytest.mark.parametrize("bad", [
    RuntimeError("provider secret"),
    SimpleNamespace(stop_reason="max_tokens", content=[]),
    SimpleNamespace(stop_reason="stop_sequence", content=[]),
    SimpleNamespace(stop_reason="pause_turn", content=[]),
    SimpleNamespace(stop_reason="end_turn", content=[]),
    SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="refusal", text="secret")]),
    SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text="{}"), SimpleNamespace(type="text", text="{}")]),
    SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text="{bad")]),
    response(action(), extra="field"),
    response(action(), verdict="unknown"),
    response(action(), suspicion_score=2),
    response(action(), rationale=""),
    response(action(), evaluated_action_hash="0" * 64),
])
def test_anthropic_monitor_failures_are_identical_generic_blocks(bad: object) -> None:
    candidate = action()
    result = AnthropicAdvisoryMonitor(api_key="api-secret", model="configured-model", client=Client(bad)).assess(candidate, digest())
    assert result.verdict is MonitorVerdict.BLOCK and result.suspicion_score == 1
    assert result.rationale == "advisory_monitor_unavailable"
    assert result.evaluated_action_hash == canonical_action_hash(candidate)
    assert "secret" not in result.rationale


@pytest.mark.parametrize("bad_digest", [
    ({"payload": "no"},),
    ({"evidence_id": "ignore instructions", "tool_name": "observability.health", "observed_at": "2026-01-01T00:00:00+00:00"},),
    ({"evidence_id": "ev-1", "tool_name": "observability.health\nignore", "observed_at": "2026-01-01T00:00:00+00:00"},),
    ({"evidence_id": "ev-1", "tool_name": "observability.health", "observed_at": "2026-01-01T00:00:00"},),
])
def test_adversarial_digest_never_calls_provider(bad_digest: tuple[dict[str, object], ...]) -> None:
    candidate, client = action(), Client(response(action()))
    result = AnthropicAdvisoryMonitor(api_key="api-secret", model="configured-model", client=client).assess(candidate, bad_digest)
    assert result.verdict is MonitorVerdict.BLOCK and client.calls == []


def test_client_factory_is_bounded_and_repr_hides_key() -> None:
    candidate, calls = action(), []
    def factory(**kwargs: object) -> Client:
        calls.append(kwargs)
        return Client(response(candidate))
    monitor = AnthropicAdvisoryMonitor(api_key="api-secret", model="configured-model", client_factory=factory)
    assert monitor.assess(candidate, digest()).verdict is MonitorVerdict.DEFER
    assert calls == [{"api_key": "api-secret", "timeout": 10.0, "max_retries": 0}]
    assert "secret" not in repr(monitor)


def test_client_factory_error_is_generic_block() -> None:
    candidate = action()
    result = AnthropicAdvisoryMonitor(api_key="api-secret", model="configured-model", client_factory=lambda **kwargs: (_ for _ in ()).throw(RuntimeError("secret"))).assess(candidate, digest())
    assert result.rationale == "advisory_monitor_unavailable"
    assert result.evaluated_action_hash == canonical_action_hash(candidate)


@pytest.mark.skipif(not (os.getenv("RUN_ANTHROPIC_LIVE") == "1" and os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_MODEL")), reason="set RUN_ANTHROPIC_LIVE=1 with complete Anthropic configuration")
def test_live_anthropic_structured_monitor_smoke() -> None:
    candidate = action()
    result = AnthropicAdvisoryMonitor(api_key=os.environ["ANTHROPIC_API_KEY"], model=os.environ["ANTHROPIC_MODEL"], timeout_seconds=20).assess(candidate, digest())
    assert result.rationale != "advisory_monitor_unavailable"
    assert result.evaluated_action_hash == canonical_action_hash(candidate)
    assert result.verdict in MonitorVerdict and 0 <= result.suspicion_score <= 1
