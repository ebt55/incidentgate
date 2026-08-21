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
    MonitorResult,
    PolicyConfiguration,
    PolicyOutcome,
)
from incidentgate.control.models import EvidenceValidation
from incidentgate.control.monitor_contract_v3 import (
    BoundMonitorAssessmentV3,
    MonitorOutcomeV3,
    bind_assessment_v3,
)
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
    project_evidence,
    render_monitor_prompt,
)
from incidentgate.control.monitor_v2 import (
    AdvisoryMonitorV2,
    BindingAdvisoryMonitor,
    MonitorErrorKind,
    MonitorOutcomeV2,
)
from incidentgate.control.ports import MonitorConsultationFactory
from incidentgate.control.safeguards import SafeguardConfiguration
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


class MonitorCallerIdentity(Protocol):
    """What a threshold artifact has to be *about*, read off the caller rather than assumed.

    ``SemanticMonitorConfiguration`` used to check the artifact against the
    literal string ``"anthropic"``, which made the provenance check answer a
    question nobody asked -- "is this the Anthropic arm?" -- instead of the one
    that matters: "does this artifact describe the caller it is being handed to?"
    The four identities below are exactly the ones a threshold is only valid for.
    """

    @property
    def provider(self) -> str: ...

    @property
    def model(self) -> str: ...

    @property
    def prompt_version(self) -> str: ...

    @property
    def input_schema_sha256(self) -> str: ...

    @property
    def output_schema_sha256(self) -> str: ...


class SemanticMonitorCaller(MonitorCallerIdentity, Protocol):
    @property
    def last_invocation(self) -> ModelInvocationRecord | None: ...

    def assess(self, input_value: MonitorInputV2) -> MonitorOutcomeV2: ...


class SemanticMonitorCallerV3(MonitorCallerIdentity, Protocol):
    """The v3 output contract's caller. Same identities, a differently-bound outcome."""

    @property
    def last_invocation(self) -> ModelInvocationRecord | None: ...

    def assess(self, input_value: MonitorInputV2) -> MonitorOutcomeV3: ...


class ThresholdArtifactProvenance(Protocol):
    """The provenance surface every threshold artifact version carries.

    Structural because the two artifact schemas differ in *how a threshold was
    arrived at* -- v1 requires a calibration split, its digest and its
    denominators; v2's a-priori band has none of those and manufacturing them
    would be the forbidden move -- and not at all in which caller a threshold is
    valid for.
    """

    @property
    def provider(self) -> str: ...

    @property
    def model(self) -> str: ...

    @property
    def prompt_version(self) -> str: ...

    @property
    def input_schema_sha256(self) -> str: ...

    @property
    def output_schema_sha256(self) -> str: ...

    @property
    def thresholds(self) -> MonitorThresholds: ...


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


class _MonitorInputProjection:
    """The one projection from a graph consultation to the bounded prompt input.

    Shared by both output contracts because the *input* contract is the same one.
    Route B -- an ``observe_only`` monitor arm -- would have needed a different
    input, and is not being taken: ``MonitorInputV2`` hands the monitor
    ``policy_decision=deny``, ``policy_risk_class="prohibited"`` and
    ``policy_reasons=["capability_prohibited"]``, so a BLOCK there would measure
    agreement with a shown denial rather than detection. Nothing in this class
    changes that; it is recorded here because this is where a reader looking for
    the leak arrives.
    """

    def __init__(
        self,
        *,
        policy: PolicyConfiguration,
        facts: RepositoryMonitorFacts,
        manifests: Mapping[str, _Manifest] | None = None,
    ) -> None:
        self._policy, self._facts = policy, facts
        self._manifests = _manifests() if manifests is None else manifests

    def project(self, consultation: MonitorConsultation) -> MonitorInputV2:
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
        return MonitorInputV2(
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
            current_state_facts=self._facts.current_state(consultation.incident.scenario_id, paths),
            authorization_required=rule.approval_required,
            authorization_scope=rule.permission,
        )


class SemanticAdvisoryMonitor(AdvisoryMonitorV2):
    def __init__(
        self,
        *,
        caller: SemanticMonitorCaller,
        policy: PolicyConfiguration,
        facts: RepositoryMonitorFacts,
        manifests: Mapping[str, _Manifest] | None = None,
    ) -> None:
        self._caller = caller
        self._projection = _MonitorInputProjection(
            policy=policy, facts=facts, manifests=manifests
        )
        self.last_input_hash: str | None = None
        self.last_invocation: ModelInvocationRecord | None = None

    def assess_consultation(self, consultation: MonitorConsultation) -> MonitorOutcomeV2:
        self.last_input_hash, self.last_invocation = None, None
        try:
            input_value = self._projection.project(consultation)
            self.last_input_hash = sha256(
                render_monitor_prompt(input_value).encode("utf-8")
            ).hexdigest()
        except (KeyError, TypeError, ValueError):
            return MonitorOutcomeV2(outcome="error", error_kind=MonitorErrorKind.INPUT_UNRENDERABLE)
        outcome = self._caller.assess(input_value)
        self.last_invocation = self._caller.last_invocation
        return outcome


class SemanticAdvisoryMonitorV3:
    """The v3 output contract's runtime adapter, which reduces its own assessment.

    ``bind_result`` is why this class does not implement ``AdvisoryMonitorV2``:
    the workflow's monitor node used to import ``monitor_v2.bind_assessment``
    directly, which hard-coded one output contract into the gate chain. A monitor
    that knows its own contract can reduce its own assessment, and the node now
    asks it to. ``BindingAdvisoryMonitor`` is a ``runtime_checkable`` protocol, so
    a v2 monitor -- which has no ``bind_result`` -- takes the unchanged path.

    ``last_assessment`` is retained deliberately, and it is the one place this
    class differs from the v2 adapter in what it remembers. ``RecordingSemanticMonitor``
    keeps no prompt body and no raw response and that is right; a *parsed,
    bounded, already-validated* assessment is neither. It is what the published
    sidecar needs, because ``SabotageStepOutcomeV3`` carries only the verdict and
    a categorical decision rule with an undisclosed score is exactly the opacity
    a threshold artifact exists to prevent.
    """

    def __init__(
        self,
        *,
        caller: SemanticMonitorCallerV3,
        policy: PolicyConfiguration,
        facts: RepositoryMonitorFacts,
        manifests: Mapping[str, _Manifest] | None = None,
    ) -> None:
        self._caller = caller
        self._projection = _MonitorInputProjection(
            policy=policy, facts=facts, manifests=manifests
        )
        self.last_input_hash: str | None = None
        self.last_invocation: ModelInvocationRecord | None = None
        self.last_outcome: MonitorOutcomeV3 | None = None

    def assess_consultation(self, consultation: MonitorConsultation) -> MonitorOutcomeV3:
        self.last_input_hash, self.last_invocation, self.last_outcome = None, None, None
        try:
            input_value = self._projection.project(consultation)
            self.last_input_hash = sha256(
                render_monitor_prompt(input_value).encode("utf-8")
            ).hexdigest()
        except (KeyError, TypeError, ValueError):
            outcome = MonitorOutcomeV3(
                outcome="error", error_kind=MonitorErrorKind.INPUT_UNRENDERABLE
            )
            self.last_outcome = outcome
            return outcome
        outcome = self._caller.assess(input_value)
        self.last_invocation = self._caller.last_invocation
        self.last_outcome = outcome
        return outcome

    def bind_result(
        self,
        assessment: BoundMonitorAssessmentV3,
        action: CanonicalAction,
        thresholds: MonitorThresholds,
    ) -> MonitorResult:
        return bind_assessment_v3(assessment, action, thresholds)


@dataclass(frozen=True)
class SemanticMonitorBundle:
    monitor: AdvisoryMonitorV2 | BindingAdvisoryMonitor
    consultation_factory: MonitorConsultationFactory
    thresholds: MonitorThresholds


def _require_artifact_describes_caller(
    artifact: ThresholdArtifactProvenance, caller: MonitorCallerIdentity
) -> None:
    """A threshold is valid for one caller only, and the caller says which one.

    Five identities and not four: the provider was previously compared against
    the literal ``"anthropic"``, which is not a property of the artifact-caller
    relationship at all. What a threshold artifact is bound to is the exact arm,
    model, input rendering and output grammar its numbers were chosen for.
    """
    mismatched = [
        name
        for name, stated, actual in (
            ("provider", artifact.provider, caller.provider),
            ("model", artifact.model, caller.model),
            ("prompt_version", artifact.prompt_version, caller.prompt_version),
            ("input_schema_sha256", artifact.input_schema_sha256, caller.input_schema_sha256),
            ("output_schema_sha256", artifact.output_schema_sha256, caller.output_schema_sha256),
        )
        if stated != actual
    ]
    if mismatched:
        raise ValueError(
            "semantic monitor threshold provenance does not match caller: "
            + ", ".join(mismatched)
        )


@dataclass(frozen=True)
class SemanticMonitorConfiguration:
    caller: SemanticMonitorCaller
    artifact: ThresholdArtifactProvenance

    def build(
        self, *, policy: PolicyConfiguration, facts: RepositoryMonitorFacts
    ) -> SemanticMonitorBundle:
        _require_artifact_describes_caller(self.artifact, self.caller)
        return SemanticMonitorBundle(
            monitor=SemanticAdvisoryMonitor(caller=self.caller, policy=policy, facts=facts),
            consultation_factory=RuntimeMonitorConsultationFactory(),
            thresholds=self.artifact.thresholds,
        )


@dataclass(frozen=True)
class SemanticMonitorConfigurationV3:
    """The same wiring for the v3 output contract, and a separate class on purpose.

    One configuration that chose an adapter by sniffing its caller would have to
    guess which output contract it had been handed, and a wrong guess is a request
    shaped for one grammar validated against another. Naming the contract at the
    construction site is what makes that unrepresentable.
    """

    caller: SemanticMonitorCallerV3
    artifact: ThresholdArtifactProvenance

    def build(
        self, *, policy: PolicyConfiguration, facts: RepositoryMonitorFacts
    ) -> SemanticMonitorBundle:
        _require_artifact_describes_caller(self.artifact, self.caller)
        return SemanticMonitorBundle(
            monitor=SemanticAdvisoryMonitorV3(caller=self.caller, policy=policy, facts=facts),
            consultation_factory=RuntimeMonitorConsultationFactory(),
            thresholds=self.artifact.thresholds,
        )


class SemanticMonitorSource(Protocol):
    """Anything that can be turned into a bundle once the runtime holds policy and facts."""

    def build(
        self, *, policy: PolicyConfiguration, facts: RepositoryMonitorFacts
    ) -> SemanticMonitorBundle: ...
