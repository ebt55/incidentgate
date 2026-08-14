"""Strict, injectable pricing snapshot loading for provider captures."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .model_capabilities import MODEL_CAPABILITIES
from .model_proposal import PricingSnapshot

_MODEL_ID = r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$"


class PricingSnapshotDocument(BaseModel):
    """On-disk pricing contract; deliberately stricter than the runtime dataclass."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["pricing-snapshot-v1"]
    snapshot_id: str = Field(min_length=3, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    currency: Literal["USD"]
    cost_basis: Literal["list_price_estimate"]
    retrieved_at: datetime
    source_url: str = Field(min_length=1, max_length=2048)
    valid_until: datetime
    input_usd_per_token: dict[str, float]
    output_usd_per_token: dict[str, float]

    @field_validator("retrieved_at", "valid_until")
    @classmethod
    def timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must be timezone-aware")
        return value

    @field_validator("source_url")
    @classmethod
    def https_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("source_url must be an HTTPS URL")
        return value

    @field_validator("input_usd_per_token", "output_usd_per_token", mode="before")
    @classmethod
    def valid_rates(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise TypeError("price mappings must be objects")
        if not value:
            raise ValueError("price mappings must not be empty")
        for model, rate in value.items():
            if not model or not re.fullmatch(_MODEL_ID, model):
                raise ValueError(f"invalid model id: {model!r}")
            if isinstance(rate, bool) or not isinstance(rate, (int, float)):
                raise TypeError("prices must be numeric")
            if not math.isfinite(rate) or rate < 0:
                raise ValueError("prices must be finite and nonnegative")
        return value

    @model_validator(mode="after")
    def coherent(self) -> PricingSnapshotDocument:
        if self.valid_until <= self.retrieved_at:
            raise ValueError("valid_until must be after retrieved_at")
        if set(self.input_usd_per_token) != set(self.output_usd_per_token):
            raise ValueError("input and output model mappings must have identical keys")
        unknown = set(self.input_usd_per_token) - set(MODEL_CAPABILITIES)
        if unknown:
            raise ValueError(f"unknown model capability: {sorted(unknown)!r}")
        return self


def load_pricing_snapshot(path: Path, *, as_of: datetime | None = None) -> PricingSnapshot:
    """Load and validate a UTF-8 snapshot, optionally enforcing its freshness bound."""

    document = PricingSnapshotDocument.model_validate_json(path.read_text(encoding="utf-8"))
    if as_of is not None:
        if as_of.tzinfo is None or as_of.utcoffset() is None:
            raise ValueError("as_of must be timezone-aware")
        if as_of >= document.valid_until:
            raise ValueError("pricing snapshot is expired")
    return PricingSnapshot(
        snapshot_id=document.snapshot_id,
        currency=document.currency,
        input_usd_per_token=dict(document.input_usd_per_token),
        output_usd_per_token=dict(document.output_usd_per_token),
    )


def validate_capture_model_coverage(
    snapshot: PricingSnapshot | PricingSnapshotDocument,
    model_ids: Mapping[str, str] | set[str] | tuple[str, ...] | list[str],
) -> None:
    """Raise when capture-eligible model ids are not priced by the snapshot."""

    ids = set(model_ids) if not isinstance(model_ids, Mapping) else set(model_ids.values())
    missing = ids - (
        set(snapshot.input_usd_per_token) & set(snapshot.output_usd_per_token)
    )
    if missing:
        raise ValueError(f"capture models missing from pricing snapshot: {sorted(missing)!r}")


def validate_capture_eligible_models(
    snapshot: PricingSnapshot | PricingSnapshotDocument,
    model_ids: Mapping[str, str] | set[str] | tuple[str, ...] | list[str],
) -> None:
    """Compatibility spelling for the capture eligibility gate."""

    validate_capture_model_coverage(snapshot, model_ids)
