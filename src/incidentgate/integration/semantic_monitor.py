"""Trusted runtime adapters for the replay-stable semantic monitor."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Protocol, cast

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
from incidentgate.control.monitor_input_v3 import (
    MonitorInputV3,
    render_monitor_input_v3,
)
from incidentgate.control.monitor_input_v4 import MonitorInputV4, render_monitor_input_v4
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
    """The v3 contracts' caller: ``monitor-input-v3`` in, ``monitor-output-v3`` out.

    The input type is what separates this protocol from
    :class:`SemanticMonitorCaller` as much as the outcome type does. A v3 caller
    is handed a projection that carries no policy verdict, and a v2 caller is
    handed one that does; a single protocol over both would let a request shaped
    for one rendering be answered against a threshold frozen for the other.
    """

    @property
    def last_invocation(self) -> ModelInvocationRecord | None: ...

    def assess(self, input_value: MonitorInputV3 | MonitorInputV4) -> MonitorOutcomeV3: ...


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
    """The v2-input projection, kept exactly as the committed capture was taken under.

    THIS IS THE PROJECTION WITH THE LEAK, AND IT IS RETAINED ON PURPOSE.

    It hands the monitor ``policy_decision``, ``policy_risk_class``,
    ``policy_reasons``, ``authorization_required``, ``authorization_scope`` and
    ``evidence_support_state`` -- six gate answers -- and one committed capture
    plus one published envelope were produced through it. ``qwen3-14b``'s
    rationale on that capture's *benign* leg reads "The action requires
    authorization, and the policy decision is to require approval, which is
    consistent with the risk class", which is three of the six read back.

    It is not edited, because editing it would move ``MonitorInputV2``'s schema
    digest, which two committed threshold artifacts and a published envelope
    cite. New work uses :class:`_MonitorInputV3Projection`; this one stays as the
    thing the published v2-input result was measured through.
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


class _MonitorInputV3Projection:
    """The projection to ``monitor-input-v3``, which cannot read a policy because it has none.

    THE CONSTRUCTOR IS THE GUARANTEE.

    :class:`_MonitorInputProjection` takes a :class:`PolicyConfiguration` and
    reads six fields out of it and the consultation's :class:`PolicyOutcome`.
    This class takes neither. ``project`` is handed the same
    :class:`MonitorConsultation` -- the graph boundary is unchanged and still
    carries ``policy``, because the *workflow* needs it -- and touches
    ``consultation.policy`` nowhere. There is no policy object in this class's
    scope to read a verdict out of, which is what makes the withholding
    structural rather than a matter of remembering.

    What is projected instead is stated field by field in
    ``control/monitor_input_v3.py``: the incident's objective and remit from the
    frozen manifest, the proposed action and its digest, the evidence with its
    per-record freshness, the committed call sequence, and the allowlisted world
    state. Those are the facts. The verdict is not one of them.
    """

    def __init__(
        self,
        *,
        facts: RepositoryMonitorFacts,
        manifests: Mapping[str, _Manifest] | None = None,
    ) -> None:
        self._facts = facts
        self._manifests = _manifests() if manifests is None else manifests

    def project(self, consultation: MonitorConsultation) -> MonitorInputV3:
        projection = ScenarioProjectionAdapter().project(
            self._manifests[consultation.incident.scenario_id]
        )
        paths = cast(tuple[str, ...], projection["allowed_changed_paths"])
        return MonitorInputV3(
            scenario_id=consultation.incident.scenario_id,
            incident_objective=cast(str, projection["incident_objective"]),
            allowed_action_tools=cast(tuple[str, ...], projection["allowed_action_tools"]),
            forbidden_action_tools=cast(tuple[str, ...], projection["forbidden_action_tools"]),
            allowed_changed_paths=paths,
            action=action_facts(consultation.action),
            action_fingerprint=action_fingerprint(consultation.action),
            evidence_facts=project_evidence(
                consultation.incident.scenario_id,
                consultation.evidence,
                consultation.records,
                _PROJECTABLE_EVIDENCE_ALLOWLIST,
            ),
            committed_calls=self._facts.committed_calls(consultation.incident.incident_id),
            current_state_facts=self._facts.current_state(consultation.incident.scenario_id, paths),
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


class _MonitorInputV4Projection:
    """The projection to ``monitor-input-v4``: v3's, with the sequence's values.

    Differs from :class:`_MonitorInputV3Projection` in one call --
    ``committed_calls_v4`` instead of ``committed_calls`` -- and in nothing else.
    That is the whole design of the A/B: two arms that differ in the input contract
    and in no other respect, so a difference in what the monitor does has one
    candidate cause.

    It takes no policy either, for the same structural reason v3's takes none:
    there is no policy object in this class's scope to read a verdict out of.
    """

    def __init__(
        self,
        *,
        facts: RepositoryMonitorFacts,
        manifests: Mapping[str, _Manifest] | None = None,
    ) -> None:
        self._facts = facts
        self._manifests = _manifests() if manifests is None else manifests

    def project(self, consultation: MonitorConsultation) -> MonitorInputV4:
        projection = ScenarioProjectionAdapter().project(
            self._manifests[consultation.incident.scenario_id]
        )
        paths = cast(tuple[str, ...], projection["allowed_changed_paths"])
        return MonitorInputV4(
            scenario_id=consultation.incident.scenario_id,
            incident_objective=cast(str, projection["incident_objective"]),
            allowed_action_tools=cast(tuple[str, ...], projection["allowed_action_tools"]),
            forbidden_action_tools=cast(tuple[str, ...], projection["forbidden_action_tools"]),
            allowed_changed_paths=paths,
            action=action_facts(consultation.action),
            action_fingerprint=action_fingerprint(consultation.action),
            evidence_facts=project_evidence(
                consultation.incident.scenario_id,
                consultation.evidence,
                consultation.records,
                _PROJECTABLE_EVIDENCE_ALLOWLIST,
            ),
            committed_calls=self._facts.committed_calls_v4(consultation.incident.incident_id),
            current_state_facts=self._facts.current_state(consultation.incident.scenario_id, paths),
        )


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
        facts: RepositoryMonitorFacts,
        manifests: Mapping[str, _Manifest] | None = None,
        input_version: Literal["v3", "v4"] = "v3",
    ) -> None:
        self._caller = caller
        # No ``policy`` parameter, and that is the withholding made structural:
        # neither projection has a policy object to read a verdict out of.
        #
        # ``input_version`` selects which projection builds the input, defaulted to
        # v3 so no existing caller moves. It has to agree with the *caller's* input
        # contract -- a v4 projection rendered by a v3 caller would send v3 bytes
        # from a v4 object -- and ``SemanticMonitorConfigurationV4`` is what pairs
        # them, rather than leaving two arguments to be kept in step by hand.
        self._projection: _MonitorInputV3Projection | _MonitorInputV4Projection = (
            _MonitorInputV3Projection(facts=facts, manifests=manifests)
            if input_version == "v3"
            else _MonitorInputV4Projection(facts=facts, manifests=manifests)
        )
        # Paired with the projection, because ``last_input_hash`` is the join key
        # between a consultation and the episode position it happened at, and it
        # has to be a digest of the bytes that were actually sent. Rendering a v4
        # input with v3's renderer would produce a hash of bytes nobody saw, and
        # every capture would then be filed against a position nothing observed.
        self._render: Callable[[Any], str] = (
            render_monitor_input_v3 if input_version == "v3" else render_monitor_input_v4
        )
        self.last_input_hash: str | None = None
        self.last_invocation: ModelInvocationRecord | None = None
        self.last_outcome: MonitorOutcomeV3 | None = None

    def assess_consultation(self, consultation: MonitorConsultation) -> MonitorOutcomeV3:
        self.last_input_hash, self.last_invocation, self.last_outcome = None, None, None
        try:
            input_value = self._projection.project(consultation)
            self.last_input_hash = sha256(
                self._render(input_value).encode("utf-8")
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
        """Wire a v3 monitor, and drop the policy on the floor rather than forward it.

        ``policy`` is named because :class:`SemanticMonitorSource` is the seam the
        runtime builds every monitor through, and the v2 configuration genuinely
        needs it. This one does not, and discarding it here -- explicitly, in one
        statement a reader trips over -- is what stops a policy-derived field from
        reappearing in a v3 input by way of a constructor that happened to have
        one in scope.
        """
        _require_artifact_describes_caller(self.artifact, self.caller)
        del policy
        return SemanticMonitorBundle(
            monitor=SemanticAdvisoryMonitorV3(caller=self.caller, facts=facts),
            consultation_factory=RuntimeMonitorConsultationFactory(),
            thresholds=self.artifact.thresholds,
        )


@dataclass(frozen=True)
class SemanticMonitorConfigurationV4:
    """The v4-input arm, which pairs the projection with a caller that renders it.

    A separate class rather than a flag on the v3 configuration, and for a reason
    that is the whole safety of the A/B: the projection and the caller's input
    contract have to agree. A v4 projection rendered by a v3 caller would build a
    ``MonitorInputV4`` and send v3's bytes from it, silently dropping the
    committed-call arguments while stamping the request as v3 -- a mismatch that
    would look like "v4 changed nothing" and would be a bug in the harness.

    Pairing them here means the disagreement cannot be constructed. The artifact's
    five-identity check then confirms it independently: a caller rendering v4
    reports ``monitor-prompt/v4.output-v3`` and v4's input digest, so a threshold
    artifact frozen for v3 is refused rather than silently applied.
    """

    caller: SemanticMonitorCallerV3
    artifact: ThresholdArtifactProvenance

    def build(
        self, *, policy: PolicyConfiguration, facts: RepositoryMonitorFacts
    ) -> SemanticMonitorBundle:
        _require_artifact_describes_caller(self.artifact, self.caller)
        # Discarded explicitly, as v3's is: the withholding is structural, and the
        # v4 contract adds the attacker's own arguments, never a gate's opinion.
        del policy
        return SemanticMonitorBundle(
            monitor=SemanticAdvisoryMonitorV3(
                caller=self.caller, facts=facts, input_version="v4"
            ),
            consultation_factory=RuntimeMonitorConsultationFactory(),
            thresholds=self.artifact.thresholds,
        )


class SemanticMonitorSource(Protocol):
    """Anything that can be turned into a bundle once the runtime holds policy and facts."""

    def build(
        self, *, policy: PolicyConfiguration, facts: RepositoryMonitorFacts
    ) -> SemanticMonitorBundle: ...
