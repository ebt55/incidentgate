from __future__ import annotations

import json
from argparse import Namespace
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

import incidentgate.evaluation.capture_model_outputs as capture_module
from incidentgate.contracts import EvaluationMode, ModelInvocationRecord
from incidentgate.control.model_proposal import CompletionRequest, CompletionResult, PricingSnapshot
from incidentgate.control.response_cache import ResponseCache
from incidentgate.evaluation.capture_model_outputs import (
    CaptureContext,
    CapturePlan,
    CaptureWorkItem,
    HoldoutArtifactInspection,
    HoldoutThresholdContract,
    capture_requests,
    main,
    preflight,
    request_schema_sha256,
)
from incidentgate.evaluation.monitor_thresholds import MonitorThresholdArtifact


def _args(tmp_path: Path, **changes: object) -> Namespace:
    base: dict[str, object] = {
        "i_will_spend_real_money": True,
        "max_calls": 1,
        "max_estimated_usd": 1.0,
        "model": "claude-opus-5",
        "max_tokens": 2048,
        "split": "development",
        "pricing_snapshot": Path(__file__).resolve().parents[2]
        / "config/pricing/anthropic-2026-08-14.json",
        "threshold_artifact": None,
        "threshold_provider": None,
        "threshold_prompt_version": None,
        "threshold_input_schema_sha256": None,
        "threshold_output_schema_sha256": None,
    }
    base.update(changes)
    return Namespace(**base)


@pytest.mark.parametrize(
    ("changes", "env", "message"),
    [
        ({"i_will_spend_real_money": False}, {"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"}, "i-will"),
        ({}, {}, "ALLOW_PROVIDER"),
        ({"max_calls": 0}, {"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"}, "max-calls"),
        ({"max_estimated_usd": 0.0000001}, {"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"}, "estimate"),
    ],
)
def test_each_spend_gate_fails_before_any_client_construction(
    tmp_path: Path, changes: dict[str, object], env: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        preflight(_args(tmp_path, **changes), env=env, now=datetime(2026, 8, 15, tzinfo=UTC))


def test_stale_pricing_fails(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="expired"):
        preflight(
            _args(tmp_path),
            env={"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"},
            now=datetime(2026, 10, 1, tzinfo=UTC),
        )


def test_holdout_requires_threshold_and_clean_tree(tmp_path: Path) -> None:
    args = _args(tmp_path, split="holdout")
    env = {"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"}
    with pytest.raises(ValueError, match="threshold"):
        preflight(
            args,
            env=env,
            now=datetime(2026, 8, 15, tzinfo=UTC),
            git_clean=lambda: True,
        )
    with pytest.raises(ValueError, match="threshold"):
        preflight(
            args,
            env=env,
            now=datetime(2026, 8, 15, tzinfo=UTC),
            git_clean=lambda: False,
        )


def test_estimate_uses_full_max_tokens(tmp_path: Path) -> None:
    plan = preflight(
        _args(tmp_path, max_calls=2, max_tokens=1000),
        env={"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"},
        now=datetime(2026, 8, 15, tzinfo=UTC),
    )
    assert plan.estimated_usd == pytest.approx(0.06)


def _threshold(frozen_at: datetime) -> MonitorThresholdArtifact:
    return MonitorThresholdArtifact(
        threshold_id="capture-test",
        frozen_at=frozen_at,
        provider="anthropic",
        model="claude-opus-5",
        prompt_version="monitor/v2",
        input_schema_sha256="a" * 64,
        output_schema_sha256="b" * 64,
        defer_at=0.4,
        block_at=0.8,
        calibration_cells_digest="c" * 64,
        calibration_denominators={"benign": 1, "malicious": 1},
        selection_rule="fixed before holdout",
    )


def test_holdout_requires_exact_frozen_clean_tracked_artifact(tmp_path: Path) -> None:
    root = tmp_path
    path = root / "config" / "monitor-thresholds" / "threshold.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    before = datetime(2026, 8, 14, tzinfo=UTC)
    args = _args(
        tmp_path,
        split="holdout",
        threshold_artifact=path,
        threshold_provider="anthropic",
        threshold_prompt_version="monitor/v2",
        threshold_input_schema_sha256="a" * 64,
        threshold_output_schema_sha256="b" * 64,
    )
    inspection = HoldoutArtifactInspection(_threshold(before), True, True, True)
    plan = preflight(
        args,
        env={"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"},
        now=datetime(2026, 8, 15, tzinfo=UTC),
        git_clean=lambda: True,
        holdout_inspector=lambda _: inspection,
        root=root,
    )
    assert plan.split == "holdout"


@pytest.mark.parametrize(
    "inspection",
    [
        HoldoutArtifactInspection(_threshold(datetime(2026, 8, 14, tzinfo=UTC)), False, True, True),
        HoldoutArtifactInspection(_threshold(datetime(2026, 8, 14, tzinfo=UTC)), True, False, True),
        HoldoutArtifactInspection(_threshold(datetime(2026, 8, 15, tzinfo=UTC)), True, True, True),
    ],
)
def test_holdout_rejects_untracked_dirty_or_unfrozen_artifact(
    tmp_path: Path, inspection: HoldoutArtifactInspection
) -> None:
    path = tmp_path / "config" / "monitor-thresholds" / "threshold.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    args = _args(
        tmp_path,
        split="holdout",
        threshold_artifact=path,
        threshold_provider="anthropic",
        threshold_prompt_version="monitor/v2",
        threshold_input_schema_sha256="a" * 64,
        threshold_output_schema_sha256="b" * 64,
    )
    with pytest.raises(ValueError, match="artifact"):
        preflight(
            args,
            env={"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"},
            now=datetime(2026, 8, 15, tzinfo=UTC),
            git_clean=lambda: True,
            holdout_inspector=lambda _: inspection,
            root=tmp_path,
        )


def test_holdout_rejects_index_dirty_and_overall_dirty_tree(tmp_path: Path) -> None:
    path = tmp_path / "config" / "monitor-thresholds" / "threshold.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    args = _args(tmp_path, split="holdout", threshold_artifact=path,
                 threshold_provider="anthropic", threshold_prompt_version="monitor/v2",
                 threshold_input_schema_sha256="a" * 64, threshold_output_schema_sha256="b" * 64)
    inspection = HoldoutArtifactInspection(
        _threshold(datetime(2026, 8, 14, tzinfo=UTC)), True, True, False
    )
    with pytest.raises(ValueError, match="tracked and clean"):
        preflight(args, env={"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"},
                  now=datetime(2026, 8, 15, tzinfo=UTC), git_clean=lambda: True,
                  holdout_inspector=lambda _: inspection, root=tmp_path)
    inspection = replace(inspection, index_clean=True)
    with pytest.raises(ValueError, match="clean git tree"):
        preflight(args, env={"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"},
                  now=datetime(2026, 8, 15, tzinfo=UTC), git_clean=lambda: False,
                  holdout_inspector=lambda _: inspection, root=tmp_path)


def test_holdout_rejects_malformed_or_contract_mismatched_artifact(tmp_path: Path) -> None:
    path = tmp_path / "config" / "monitor-thresholds" / "threshold.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    args = _args(
        tmp_path,
        split="holdout",
        threshold_artifact=path,
        threshold_provider="anthropic",
        threshold_prompt_version="monitor/v2",
        threshold_input_schema_sha256="a" * 64,
        threshold_output_schema_sha256="b" * 64,
    )
    with pytest.raises(ValueError):
        preflight(
            args,
            env={"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"},
            now=datetime(2026, 8, 15, tzinfo=UTC),
            git_clean=lambda: True,
            root=tmp_path,
        )
    wrong = _threshold(datetime(2026, 8, 14, tzinfo=UTC)).model_copy(
        update={"provider": "other"}
    )
    inspection = HoldoutArtifactInspection(wrong, True, True, True)
    with pytest.raises(ValueError, match="contract"):
        preflight(
            args,
            env={"INCIDENTGATE_ALLOW_PROVIDER_SPEND": "1"},
            now=datetime(2026, 8, 15, tzinfo=UTC),
            git_clean=lambda: True,
            holdout_inspector=lambda _: inspection,
            root=tmp_path,
        )


def _capture_item(prompt: str, *, variant: str = "v1") -> CaptureWorkItem:
    import hashlib

    canonical = json.dumps(
        {
            "system": "",
            "user": prompt,
            "model": "claude-opus-5",
            "max_tokens": 16,
            "temperature": None,
            "thinking": None, "input_schema_sha256": "d" * 64,
            "output_schema_sha256": request_schema_sha256_placeholder(),
            "prompt_version": "monitor/v2",
        }, sort_keys=True, separators=(",", ":")
    )
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    request = CompletionRequest(
        "claude-opus-5", "", prompt, 16, None, None, {"type": "object"}, canonical, digest
    )
    return CaptureWorkItem(
        request,
        CaptureContext(
            "monitor", "monitor-input-v2", "d" * 64, "monitor/v2", request_schema_sha256(request),
            "D1", variant, EvaluationMode.COMPLETE, "incident", 0, "development",
            "python -m incidentgate.evaluation.capture_model_outputs", "a" * 40,
        ),
    )


def request_schema_sha256_placeholder() -> str:
    return request_schema_sha256(
        CompletionRequest("", "", "", 0, None, None, {"type": "object"}, "", "")
    )


def _capture_plan() -> CapturePlan:
    snapshot = PricingSnapshot(
        "snap-test", "USD", {"claude-opus-5": 0.001}, {"claude-opus-5": 0.002}
    )
    return CapturePlan("claude-opus-5", 2, 1.0, "development", 0.1, snapshot)


class _CaptureClient:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, request: CompletionRequest) -> CompletionResult:
        self.calls += 1
        return CompletionResult(
            '{"risk_score":0.1}',
            ModelInvocationRecord(
                invocation_kind="provider_call", provider="anthropic", model=request.model,
                input_tokens=1, output_tokens=1, usage_source="provider_usage",
                cost=0.003, currency="USD", pricing_snapshot="snap-test",
            ),
        )


def test_capture_replays_existing_without_factory_and_dispatches_only_misses(
    tmp_path: Path,
) -> None:
    cache, plan = ResponseCache(tmp_path), _capture_plan()
    first, second = _capture_item("one"), _capture_item("two")
    client = _CaptureClient()
    capture_requests(plan, (first,), cache=cache, client_factory=lambda _: client)
    assert client.calls == 1
    factory_calls = 0

    def factory(_: PricingSnapshot) -> _CaptureClient:
        nonlocal factory_calls
        factory_calls += 1
        return client

    replayed = capture_requests(plan, (first,), cache=cache, client_factory=factory)
    assert replayed[0].invocation.invocation_kind == "cache_replay"
    assert factory_calls == 0
    mixed = capture_requests(plan, (first, second), cache=cache, client_factory=factory)
    assert len(mixed) == 2
    assert factory_calls == 1 and client.calls == 2


def test_capture_refuses_duplicate_hash_before_factory(tmp_path: Path) -> None:
    item = _capture_item("same")
    with pytest.raises(ValueError, match="duplicate"):
        capture_requests(
            _capture_plan(),
            (item, _capture_item("same", variant="v2")),
            cache=ResponseCache(tmp_path),
            client_factory=lambda _: pytest.fail("factory must not be called"),
        )


@pytest.mark.parametrize(
    "plan",
    [
        replace(_capture_plan(), max_estimated_usd=float("nan")),
        replace(_capture_plan(), estimated_usd=float("inf")),
        replace(_capture_plan(), estimated_usd=-1.0),
        replace(_capture_plan(), split="bogus"),
        replace(_capture_plan(), model="not a model"),
        replace(_capture_plan(), snapshot=PricingSnapshot("snap", "USD", {}, {})),
    ],
)
def test_invalid_capture_plan_never_constructs_provider(tmp_path: Path, plan: CapturePlan) -> None:
    with pytest.raises(ValueError):
        capture_requests(
            plan, (_capture_item("invalid"),), cache=ResponseCache(tmp_path),
            client_factory=lambda _: pytest.fail("factory must not be called"),
        )


@pytest.mark.parametrize("raw_json", ["not-json", "null", '"scalar"'])
def test_provider_failure_or_malformed_response_stores_nothing(
    tmp_path: Path, raw_json: str
) -> None:
    class BadClient(_CaptureClient):
        def complete(self, request: CompletionRequest) -> CompletionResult:
            self.calls += 1
            return CompletionResult(
                raw_json,
                ModelInvocationRecord(
                    invocation_kind="provider_call", provider="anthropic", model=request.model,
                    input_tokens=1, output_tokens=1, usage_source="provider_usage",
                    cost=0.003, currency="USD", pricing_snapshot="snap-test",
                ),
            )

    item = _capture_item("bad")
    with pytest.raises(ValueError):
        capture_requests(
            _capture_plan(), (item,), cache=ResponseCache(tmp_path),
            client_factory=lambda _: BadClient(),
        )
    assert not list(tmp_path.rglob("*.json"))


def test_provider_exception_stores_nothing(tmp_path: Path) -> None:
    class ExplodingClient:
        def complete(self, _: CompletionRequest) -> CompletionResult:
            raise RuntimeError("provider unavailable")

    with pytest.raises(RuntimeError, match="provider unavailable"):
        capture_requests(
            _capture_plan(), (_capture_item("exception"),), cache=ResponseCache(tmp_path),
            client_factory=lambda _: ExplodingClient(),
        )
    assert not list(tmp_path.rglob("*.json"))


@pytest.mark.parametrize("mutation", [
    lambda item: replace(item, request=replace(item.request, schema={})),
    lambda item: replace(item, context=replace(item.context, condition="runtime-string")),
    lambda item: replace(item, context=replace(item.context, step_index=True)),
    lambda item: replace(item, context=replace(item.context, capture_command="unsafe\ncommand")),
])
def test_invalid_work_item_is_rejected_before_factory(tmp_path: Path, mutation) -> None:
    item = mutation(_capture_item("invalid-work-item"))
    with pytest.raises((TypeError, ValueError)):
        capture_requests(
            _capture_plan(), (item,), cache=ResponseCache(tmp_path),
            client_factory=lambda _: pytest.fail("factory must not be called"),
        )


def test_runtime_string_equal_to_evaluation_mode_is_rejected_before_factory(tmp_path: Path) -> None:
    item = _capture_item("string-condition")
    assert item.context.condition == EvaluationMode.COMPLETE
    item = replace(item, context=replace(item.context, condition="policy_monitor_human"))
    with pytest.raises((TypeError, ValueError)):
        capture_requests(_capture_plan(), (item,), cache=ResponseCache(tmp_path),
                         client_factory=lambda _: pytest.fail("factory must not be called"))


@pytest.mark.parametrize("mutation", ["system", "extra"])
def test_monitor_canonical_envelope_drift_is_rejected_before_factory(
    tmp_path: Path, mutation: str
) -> None:
    import hashlib

    item = _capture_item("monitor-envelope")
    envelope = json.loads(item.request.canonical_prompt)
    if mutation == "system":
        envelope["system"] = "drifted"
    else:
        envelope["unexpected"] = True
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    request = replace(item.request, canonical_prompt=canonical,
                      prompt_sha256=hashlib.sha256(canonical.encode()).hexdigest())
    with pytest.raises(ValueError, match="monitor canonical"):
        capture_requests(_capture_plan(), (replace(item, request=request),),
                         cache=ResponseCache(tmp_path),
                         client_factory=lambda _: pytest.fail("factory must not be called"))


def _proposer_capture_item(prompt: str) -> CaptureWorkItem:
    import hashlib

    output_schema = "e" * 64
    envelope = {
        "system": "",
        "user": prompt,
        "model": "claude-opus-5",
        "max_tokens": 16,
        "temperature": None,
        "thinking": None,
        "schema_fingerprint": output_schema,
    }
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    request = CompletionRequest("claude-opus-5", "", prompt, 16, None, None,
                                {"type": "object"}, canonical,
                                hashlib.sha256(canonical.encode()).hexdigest())
    return CaptureWorkItem(request, CaptureContext(
        "proposer", "proposal-input-v1", "d" * 64, "proposal/v1", output_schema,
        "D1", "v1", EvaluationMode.COMPLETE, "incident", 0, "development",
        "python -m incidentgate.evaluation.capture_model_outputs", "a" * 40,
    ))


def test_proposer_schema_fingerprint_drift_rejected_and_valid_item_dispatches(
    tmp_path: Path,
) -> None:
    import hashlib

    item = _proposer_capture_item("proposer-envelope")
    envelope = json.loads(item.request.canonical_prompt)
    envelope["schema_fingerprint"] = "f" * 64
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    drifted = replace(item, request=replace(
        item.request, canonical_prompt=canonical,
        prompt_sha256=hashlib.sha256(canonical.encode()).hexdigest(),
    ))
    with pytest.raises(ValueError, match="proposer canonical"):
        capture_requests(_capture_plan(), (drifted,), cache=ResponseCache(tmp_path),
                         client_factory=lambda _: pytest.fail("factory must not be called"))
    cache = ResponseCache(tmp_path)
    result = capture_requests(_capture_plan(), (item,), cache=cache,
                              client_factory=lambda _: _CaptureClient())
    assert result[0].invocation.invocation_kind == "provider_call"
    assert cache.load(item.request.model, item.request.prompt_sha256).capture == "provider_call"


def test_wrong_holdout_provider_result_stores_nothing(tmp_path: Path) -> None:
    plan = replace(_capture_plan(), split="holdout", threshold_contract=HoldoutThresholdContract(
        "openai", "claude-opus-5", "monitor/v2", "d" * 64, request_schema_sha256(
            CompletionRequest("", "", "", 0, None, None, {"type": "object"}, "", "")
        )))
    item = _capture_item("holdout")
    item = replace(item, context=replace(item.context, split="holdout"))
    with pytest.raises(ValueError, match="provider disagrees"):
        capture_requests(plan, (item,), cache=ResponseCache(tmp_path),
                         client_factory=lambda _: _CaptureClient())
    assert not list(tmp_path.rglob("*.json"))


def test_oversized_provider_response_stores_nothing(tmp_path: Path) -> None:
    class OversizedClient(_CaptureClient):
        def complete(self, request: CompletionRequest) -> CompletionResult:
            result = super().complete(request)
            return replace(result, raw_json='{"x":"' + "a" * 1_000_001 + '"}')

    with pytest.raises(ValueError, match="size limit"):
        capture_requests(_capture_plan(), (_capture_item("oversized"),),
                         cache=ResponseCache(tmp_path), client_factory=lambda _: OversizedClient())
    assert not list(tmp_path.rglob("*.json"))


def test_preexisting_synthetic_or_conflicting_context_never_constructs_factory(
    tmp_path: Path,
) -> None:
    cache, plan = ResponseCache(tmp_path), _capture_plan()
    synthetic = _capture_item("synthetic")
    cache.store(synthetic.request.model, synthetic.request.prompt_sha256, "{}", capture="synthetic")
    with pytest.raises(ValueError, match="synthetic"):
        capture_requests(plan, (synthetic,), cache=cache,
                         client_factory=lambda _: pytest.fail("factory must not be called"))
    provider = _capture_item("provider")
    capture_requests(plan, (provider,), cache=cache, client_factory=lambda _: _CaptureClient())
    conflict = replace(provider, context=replace(provider.context, variant_id="v2"))
    with pytest.raises(ValueError, match="conflicts"):
        capture_requests(plan, (conflict,), cache=cache,
                         client_factory=lambda _: pytest.fail("factory must not be called"))


def test_ci_workflows_do_not_opt_into_provider_spend() -> None:
    root = Path(__file__).resolve().parents[2]
    for workflow in (root / ".github" / "workflows").glob("*"):
        if workflow.is_file():
            text = workflow.read_text(encoding="utf-8")
            assert "INCIDENTGATE_ALLOW_PROVIDER_SPEND" not in text


def test_main_no_work_path_does_not_claim_capture_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        capture_module,
        "preflight",
        lambda _args: CapturePlan(
            "claude-opus-5", 1, 1.0, "development", 0.01,
            PricingSnapshot("snap-test", "USD", {"claude-opus-5": 0.001},
                            {"claude-opus-5": 0.002}),
        ),
    )
    with pytest.raises(SystemExit, match="no capture work items were supplied"):
        main(["--i-will-spend-real-money", "--max-calls", "1", "--max-estimated-usd", "1",
              "--model", "claude-opus-5", "--max-tokens", "16", "--split", "development"])
