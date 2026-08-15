from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from incidentgate.contracts import CanonicalAction, PolicyConfiguration, PolicyDecision, Role
from incidentgate.control.models import EvidenceState, EvidenceValidation
from incidentgate.control.policy import DeterministicPolicyEngine


def _action(
    patches: list[dict[str, object]], tool: str = "operations.rollback_api_release"
) -> CanonicalAction:
    arguments: dict[str, object] = {"kind": tool.removeprefix("operations."), "patches": patches}
    if tool.endswith("breakglass"):
        arguments = {
            "kind": "enable_privileged_mode_or_breakglass",
            "target": "permissions.breakglass",
        }
    return CanonicalAction(
        tool_name=tool,
        incident_id="INC-T8",
        thread_id="t8",
        actor="operator-1",
        permission="operations:write",
        evidence_ids=("ev-1",),
        arguments=arguments,
    )


def _engine() -> DeterministicPolicyEngine:
    body = json.loads((Path(__file__).parents[2] / "config/policy.example.json").read_text())
    return DeterministicPolicyEngine(PolicyConfiguration.model_validate(body))


def _evidence() -> EvidenceValidation:
    return EvidenceValidation(state=EvidenceState.VALID, reasons=("evidence_valid",))


@pytest.mark.parametrize(
    "patches",
    [[{"path": "api.release", "value": "api-2.4.0"}]],
)
def test_t8_benign_same_tool_requires_approval(patches: list[dict[str, object]]) -> None:
    action = _action(patches)
    decision = _engine().evaluate(action, Role.OPERATOR, _evidence())
    assert action.tool_name == "operations.rollback_api_release"
    assert decision.decision is PolicyDecision.REQUIRE_APPROVAL
    assert decision.reasons == ("policy_valid",)


@pytest.mark.parametrize(
    "patches",
    [
        [
            {"path": "api.release", "value": "api-2.4.0"},
            {"path": "config.privileged_mode", "value": True},
        ],
        [
            {"path": "api.release", "value": "api-2.4.0"},
            {"path": "permissions.breakglass", "value": True},
        ],
        [
            {"path": "api.release", "value": "api-2.4.0"},
            {"path": "config.privileged_mode", "value": True},
            {"path": "permissions.breakglass", "value": True},
        ],
    ],
)
def test_t8_same_tool_malicious_variants_deny_exact_changed_path_reason(
    patches: list[dict[str, object]],
) -> None:
    action = _action(patches)
    decision = _engine().evaluate(action, Role.OPERATOR, _evidence())
    assert action.tool_name == "operations.rollback_api_release"
    assert decision.decision is PolicyDecision.DENY
    assert decision.reasons == ("argument_constraint:changed_paths",)


@pytest.mark.parametrize(
    "patches",
    [
        [],
        [{"path": "config.privileged_mode", "value": True}],
        [
            {"path": "api.release", "value": "api-2.4.0"},
            {"path": "api.release", "value": "api-2.4.0"},
        ],
        [{"path": "api.release", "value": "api-2.4.1"}],
        [{"path": "api_release", "value": "api-2.4.0"}],
        [{"path": {"nested": "api.release"}, "value": "api-2.4.0"}],
        [{"path": "api.release", "value": {"nested": "api-2.4.0"}}],
        [{"path": "api.release", "value": "api-2.4.0", "extra": True}],
        [{"path": "config.privileged_mode", "value": "true"}],
        [{"path": "permissions.breakglass", "value": 1}],
        [
            {"path": "api.release", "value": "api-2.4.0"},
            {"path": "config.privileged_mode", "value": True},
            {"path": "permissions.breakglass", "value": False},
            {"path": "permissions.breakglass", "value": True},
        ],
    ],
)
def test_t8_parser_rejects_noncanonical_or_malformed_patch_tuples(
    patches: list[dict[str, object]],
) -> None:
    with pytest.raises(ValidationError):
        _action(patches)


def test_t8_parser_rejects_root_extra_key_and_alias_shape() -> None:
    base = {
        "tool_name": "operations.rollback_api_release",
        "incident_id": "INC-T8",
        "thread_id": "t8",
        "actor": "operator-1",
        "permission": "operations:write",
        "evidence_ids": ("ev-1",),
    }
    with pytest.raises(ValidationError):
        CanonicalAction(
            **base,
            arguments={
                "kind": "rollback_api_release",
                "patches": [{"path": "api.release", "value": "api-2.4.0"}],
                "unexpected": True,
            },
        )
    with pytest.raises(ValidationError):
        CanonicalAction(
            **base,
            arguments={
                "kind": "rollback_api_release",
                "patch_set": [{"path": "api.release", "value": "api-2.4.0"}],
            },
        )


def test_t8_naked_capability_is_prohibited() -> None:
    decision = _engine().evaluate(
        _action([], "operations.enable_privileged_mode_or_breakglass"), Role.OPERATOR, _evidence()
    )
    assert decision.decision is PolicyDecision.DENY
    assert decision.reasons == ("capability_prohibited",)
