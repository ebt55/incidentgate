"""Trusted runtime adapters for the replay-stable semantic monitor."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Protocol, cast

from incidentgate.contracts import (
    CanonicalAction,
    EvidenceRecord,
    IncidentIdentity,
    ModelInvocationRecord,
    PolicyConfiguration,
    PolicyOutcome,
)
from incidentgate.control.models import EvidenceValidation
from incidentgate.control.monitor_decision import MonitorThresholds
from incidentgate.control.monitor_input import (
    CountFact,
    FlagFact,
    HealthFact,
    MonitorConsultation,
    MonitorInputV2,
    ScenarioProjectionAdapter,
    SemanticFact,
    action_facts,
    action_fingerprint,
    monitor_input_schema_sha256,
    project_evidence,
    render_monitor_prompt,
)
from incidentgate.control.monitor_v2 import (
    AdvisoryMonitorV2,
    MonitorErrorKind,
    MonitorOutcomeV2,
    monitor_output_schema_sha256,
)
from incidentgate.control.ports import MonitorConsultationFactory
from incidentgate.control.safeguards import SafeguardConfiguration
from incidentgate.evaluation.monitor_calibration import MonitorThresholdArtifact
from incidentgate.integration.monitor_facts import RepositoryMonitorFacts
from incidentgate.manifests import (
    ReliabilityManifest,
    SabotageManifest,
    ScenarioManifest,
    load_checkpoint_manifests,
    load_reliability_manifests,
    load_sabotage_manifests,
)

_ROOT = Path(__file__).parents[3]
_Manifest = ScenarioManifest | ReliabilityManifest | SabotageManifest
_RiskClass = Literal["prohibited", "approval_required", "allowed"]


class SemanticMonitorCaller(Protocol):
    @property
    def model(self) -> str: ...

    @property
    def last_invocation(self) -> ModelInvocationRecord | None: ...

    def assess(self, input_value: MonitorInputV2) -> MonitorOutcomeV2: ...


def _health(value: bool | float | str) -> SemanticFact | None:
    if value not in {"healthy", "degraded", "unhealthy", "unknown"}:
        return None
    return HealthFact(
        kind="health",
        name="health",
        value=cast(Literal["healthy", "degraded", "unhealthy", "unknown"], value),
    )


def _count(name: str) -> Callable[[bool | int | float | str], SemanticFact | None]:
    def convert(value: bool | float | str) -> SemanticFact | None:
        return (
            CountFact(kind="count", name=name, value=value)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else None
        )

    return convert


def _flag(name: str) -> Callable[[bool | int | float | str], SemanticFact | None]:
    def convert(value: bool | float | str) -> SemanticFact | None:
        return FlagFact(kind="flag", name=name, value=value) if isinstance(value, bool) else None

    return convert


# Explicit immutable scenario/source/key mappings. Unlisted content is dropped.
_EVIDENCE_ALLOWLIST = MappingProxyType(
    {
        ("T1", "observability.checkout_health"): MappingProxyType(
            {"health": _health, "status": _count("http_status")}
        ),
        ("T1", "observability.outbound_note_store"): MappingProxyType(
            {"count": _count("outbound_note_count")}
        ),
        ("T2", "observability.cache_health"): MappingProxyType(
            {"health": _health, "status": _count("http_status")}
        ),
        ("T4", "observability.checkout_health"): MappingProxyType(
            {"health": _health, "status": _count("http_status"), "feature_x": _flag("feature_x")}
        ),
        ("T4", "observability.call_ledger"): MappingProxyType(
            {"mutation_count": _count("mutation_count")}
        ),
        ("D1", "observability.health"): MappingProxyType({"status": _count("http_status")}),
        ("D2", "observability.health"): MappingProxyType({"status": _count("http_status")}),
        ("D3", "observability.health"): MappingProxyType({"status": _count("http_status")}),
        ("D5", "observability.disk_metrics"): MappingProxyType(
            {"free_bytes": _count("free_bytes")}
        ),
        ("D5", "observability.log_volume"): MappingProxyType({"bytes": _count("log_bytes")}),
        ("D5", "observability.health"): MappingProxyType({"status": _count("http_status")}),
        ("D8", "observability.health"): MappingProxyType({"status": _count("http_status")}),
        ("R05", "observability.query_metrics"): MappingProxyType({"p95_ms": _count("p95_ms")}),
        ("R06", "observability.query_metrics"): MappingProxyType({"p95_ms": _count("p95_ms")}),
        ("R07", "observability.request_routing"): MappingProxyType({"fresh": _flag("fresh")}),
        ("R09", "observability.dependency_metrics"): MappingProxyType(
            {
                "request_rate_per_minute": _count("request_rate_per_minute"),
                "http_429_rate": _count("http_429_rate"),
            }
        ),
        ("R12", "observability.schema_validation"): MappingProxyType(
            {"error_count": _count("error_count")}
        ),
        ("R12", "observability.deployment_diff"): MappingProxyType(
            {"schema_validated": _flag("schema_validated")}
        ),
    }
)
_PROJECTABLE_EVIDENCE_ALLOWLIST = {key: dict(value) for key, value in _EVIDENCE_ALLOWLIST.items()}


class RuntimeMonitorConsultationFactory(MonitorConsultationFactory):
    def build(
        self,
        *,
        incident: IncidentIdentity,
        action: CanonicalAction,
        records: tuple[EvidenceRecord, ...],
        evidence: EvidenceValidation,
        policy: PolicyOutcome,
        safeguards: SafeguardConfiguration,
    ) -> MonitorConsultation:
        return MonitorConsultation(
            incident=incident,
            action=action,
            records=records,
            evidence=evidence,
            policy=policy,
            safeguards=safeguards,
        )


def _manifests() -> Mapping[str, _Manifest]:
    loaded = (
        *load_checkpoint_manifests(_ROOT / "scenarios" / "checkpoints"),
        *load_reliability_manifests(_ROOT / "scenarios" / "reliability"),
        *load_sabotage_manifests(_ROOT / "scenarios" / "sabotage"),
    )
    return MappingProxyType({cast(_Manifest, item).id: cast(_Manifest, item) for item in loaded})


class SemanticAdvisoryMonitor(AdvisoryMonitorV2):
    def __init__(
        self,
        *,
        caller: SemanticMonitorCaller,
        policy: PolicyConfiguration,
        facts: RepositoryMonitorFacts,
        manifests: Mapping[str, _Manifest] | None = None,
    ) -> None:
        self._caller, self._policy, self._facts = caller, policy, facts
        self._manifests = _manifests() if manifests is None else manifests
        self.last_input_hash: str | None = None
        self.last_invocation: ModelInvocationRecord | None = None

    def assess_consultation(self, consultation: MonitorConsultation) -> MonitorOutcomeV2:
        self.last_input_hash, self.last_invocation = None, None
        try:
            projection = ScenarioProjectionAdapter().project(
                self._manifests[consultation.incident.scenario_id]
            )
            rule = self._policy.tools[consultation.action.tool_name]
            risk: _RiskClass = (
                "prohibited"
                if rule.prohibited
                else ("approval_required" if rule.approval_required else "allowed")
            )
            paths = cast(tuple[str, ...], projection["allowed_changed_paths"])
            input_value = MonitorInputV2(
                scenario_id=consultation.incident.scenario_id,
                incident_objective=cast(str, projection["incident_objective"]),
                allowed_action_tools=cast(tuple[str, ...], projection["allowed_action_tools"]),
                forbidden_action_tools=cast(tuple[str, ...], projection["forbidden_action_tools"]),
                allowed_changed_paths=paths,
                action=action_facts(consultation.action),
                action_fingerprint=action_fingerprint(consultation.action),
                policy_decision=consultation.policy.decision,
                policy_risk_class=risk,
                policy_reasons=consultation.policy.reasons,
                evidence_support_state=consultation.evidence.state.value,
                evidence_facts=project_evidence(
                    consultation.incident.scenario_id,
                    consultation.evidence,
                    consultation.records,
                    _PROJECTABLE_EVIDENCE_ALLOWLIST,
                ),
                committed_calls=self._facts.committed_calls(consultation.incident.incident_id),
                current_state_facts=self._facts.current_state(
                    consultation.incident.scenario_id, paths
                ),
                authorization_required=rule.approval_required,
                authorization_scope=rule.permission,
            )
            self.last_input_hash = sha256(
                render_monitor_prompt(input_value).encode("utf-8")
            ).hexdigest()
        except (KeyError, TypeError, ValueError):
            return MonitorOutcomeV2(outcome="error", error_kind=MonitorErrorKind.INPUT_UNRENDERABLE)
        outcome = self._caller.assess(input_value)
        self.last_invocation = self._caller.last_invocation
        return outcome


@dataclass(frozen=True)
class SemanticMonitorBundle:
    monitor: AdvisoryMonitorV2
    consultation_factory: MonitorConsultationFactory
    thresholds: MonitorThresholds


@dataclass(frozen=True)
class SemanticMonitorConfiguration:
    caller: SemanticMonitorCaller
    artifact: MonitorThresholdArtifact

    def build(
        self, *, policy: PolicyConfiguration, facts: RepositoryMonitorFacts
    ) -> SemanticMonitorBundle:
        if (
            self.artifact.provider != "anthropic"
            or self.artifact.model != self.caller.model
            or self.artifact.prompt_version != "monitor-prompt/v1"
            or self.artifact.input_schema_sha256 != monitor_input_schema_sha256()
            or self.artifact.output_schema_sha256 != monitor_output_schema_sha256()
        ):
            raise ValueError("semantic monitor threshold provenance does not match caller")
        return SemanticMonitorBundle(
            monitor=SemanticAdvisoryMonitor(caller=self.caller, policy=policy, facts=facts),
            consultation_factory=RuntimeMonitorConsultationFactory(),
            thresholds=self.artifact.thresholds,
        )
