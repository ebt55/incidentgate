import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incidentgate.control.model_proposal import PricingSnapshot
from incidentgate.control.pricing import (
    PricingSnapshotDocument,
    load_pricing_snapshot,
    validate_capture_model_coverage,
)

ROOT = Path(__file__).parents[2]
SNAPSHOT = ROOT / "config" / "pricing" / "anthropic-2026-08-14.json"
OPENAI_SNAPSHOT = ROOT / "config" / "pricing" / "openai-2026-08-20.json"


def test_load_and_exact_opus_cost() -> None:
    snapshot = load_pricing_snapshot(SNAPSHOT)
    assert snapshot.cost("claude-opus-5", 2_000_000, 400_000) == 20.0


def test_unknown_and_mismatched_models_rejected() -> None:
    base = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    base["input_usd_per_token"]["unknown-model"] = 1e-6
    with pytest.raises(ValueError):
        PricingSnapshotDocument.model_validate(base)
    base = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    base["output_usd_per_token"]["claude-opus-4-6"] = 1e-6
    with pytest.raises(ValueError):
        PricingSnapshotDocument.model_validate(base)


def test_extra_malformed_and_timestamp_rejected() -> None:
    base = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    base["extra"] = True
    with pytest.raises(ValueError):
        PricingSnapshotDocument.model_validate(base)
    base = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    base["retrieved_at"] = "2026-08-14T00:00:00"
    with pytest.raises(ValueError):
        PricingSnapshotDocument.model_validate(base)
    base = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    base["valid_until"] = base["retrieved_at"]
    with pytest.raises(ValueError):
        PricingSnapshotDocument.model_validate(base)
    base = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    base["input_usd_per_token"]["claude-opus-5"] = -1e-6
    with pytest.raises(ValueError):
        PricingSnapshotDocument.model_validate(base)


def test_expiry_boundary_is_injected() -> None:
    before_expiry = datetime(2026, 9, 13, 23, 59, 59, tzinfo=UTC)
    assert load_pricing_snapshot(SNAPSHOT, as_of=before_expiry).snapshot_id == (
        "anthropic-2026-08-14"
    )
    at_expiry = datetime(2026, 9, 14, tzinfo=UTC)
    with pytest.raises(ValueError, match="expired"):
        load_pricing_snapshot(SNAPSHOT, as_of=at_expiry)


def test_capture_model_coverage() -> None:
    snapshot = load_pricing_snapshot(SNAPSHOT)
    validate_capture_model_coverage(snapshot, {"claude-opus-5"})
    with pytest.raises(ValueError, match="missing"):
        validate_capture_model_coverage(snapshot, {"claude-sonnet-5"})


def test_source_and_rates_are_pinned() -> None:
    document = PricingSnapshotDocument.model_validate_json(
        SNAPSHOT.read_text(encoding="utf-8")
    )
    assert document.source_url == "https://claude.com/platform/api"
    assert document.input_usd_per_token == {"claude-opus-5": 0.000005}
    assert document.output_usd_per_token == {"claude-opus-5": 0.000025}


def test_runtime_dataclass_remains_exact() -> None:
    assert isinstance(load_pricing_snapshot(SNAPSHOT), PricingSnapshot)


def test_openai_rates_are_the_published_ones_and_are_keyed_by_the_priced_id() -> None:
    """Pins the two numbers and the id they were published against.

    Both were retrieved from OpenAI's pricing page on 2026-08-20 -- $5.00 per
    million input tokens and $30.00 per million output tokens, listed under
    `gpt-5.5` -- rather than reconstructed. The id matters as much as the rates:
    the page prices `gpt-5.5`, so that is what this snapshot keys. Keying the
    dated snapshot `gpt-5.5-2026-04-23` instead would attach a retrieved rate to
    an id no retrieved source names, which is the failure the whole pricing
    contract exists to prevent.

    A rate edited without re-retrieving it fails here, which is the point: this
    project refuses to publish a provider result priced from memory.
    """
    document = PricingSnapshotDocument.model_validate_json(
        OPENAI_SNAPSHOT.read_text(encoding="utf-8")
    )
    assert document.source_url == "https://developers.openai.com/api/docs/pricing"
    assert document.input_usd_per_token == {"gpt-5.5": 0.000005}
    assert document.output_usd_per_token == {"gpt-5.5": 0.00003}
    # The published per-million figures, restated as the arithmetic a bill uses.
    snapshot = load_pricing_snapshot(OPENAI_SNAPSHOT)
    assert snapshot.cost("gpt-5.5", 1_000_000, 0) == 5.0
    assert snapshot.cost("gpt-5.5", 0, 1_000_000) == 30.0


def test_the_openai_snapshot_carries_a_thirty_day_validity_window() -> None:
    """A price list with no expiry is a price list nobody has to re-check."""
    document = PricingSnapshotDocument.model_validate_json(
        OPENAI_SNAPSHOT.read_text(encoding="utf-8")
    )
    assert document.valid_until - document.retrieved_at == timedelta(days=30)
    with pytest.raises(ValueError, match="expired"):
        load_pricing_snapshot(OPENAI_SNAPSHOT, as_of=document.valid_until)
    assert (
        load_pricing_snapshot(
            OPENAI_SNAPSHOT, as_of=document.valid_until - timedelta(seconds=1)
        ).snapshot_id
        == "openai-2026-08-20"
    )
