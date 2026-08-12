"""OpenTelemetry runtime factory and W3C propagation utilities.

Importing this module never configures a process-global provider or performs I/O.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from inspect import signature
from typing import Any
from uuid import UUID

try:  # OTel is an optional runtime dependency.
    from opentelemetry import context, propagate, trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
except ImportError:  # pragma: no cover - exercised only in minimal installs
    context = propagate = trace = None  # type: ignore[assignment]
    TracerProvider = Any  # type: ignore[misc,assignment]
    SpanProcessor = Any  # type: ignore[misc,assignment]
    Resource = Any  # type: ignore[misc,assignment]

SPAN_NAMES = (
    *(f"d{scenario}.{phase}" for scenario in range(1, 4) for phase in ("workflow", "policy", "monitor", "approval", "verification")),
    *(f"d{scenario}.{phase}" for scenario in (5, 8) for phase in ("workflow", "policy", "monitor", "approval", "verification")),
    *(f"r{scenario:02d}.{phase}" for scenario in range(1, 5) for phase in ("workflow", "policy", "monitor", "approval", "verification")),
    *(f"r{scenario:02d}.{phase}" for scenario in range(6, 9) for phase in ("workflow", "policy", "monitor", "approval", "verification")),
    *(f"r{scenario:02d}.{phase}" for scenario in (9, 12) for phase in ("workflow", "policy", "monitor", "approval", "verification")),
    *(f"r{scenario:02d}.{phase}" for scenario in (5, 10, 11) for phase in ("workflow", "collection")),
    *(f"d{scenario}.{phase}" for scenario in (4, 7) for phase in ("workflow", "collection")),
    *(f"{scenario}.{phase}" for scenario in ("d6", "s1", "s2") for phase in ("workflow", "collection")),
    "mcp.observability",
    "mcp.operations",
    "mcp.tickets",
)
_ALLOWED = {
    "incident_id",
    "thread_id",
    "correlation_id",
    "actor",
    "permission",
    "action_hash",
    "idempotency_key",
}
_SECRET_WORDS = ("secret", "token", "api_key", "apikey", "password", "prompt", "raw_log", "ticket_body")
_MAX_LENGTH = 256
_TRACEPARENT = re.compile(r"^[\da-f]{2}-[\da-f]{32}-[\da-f]{16}-[\da-f]{2}$", re.IGNORECASE)
_CARRIER_KEYS = frozenset({"traceparent", "tracestate"})
_MAX_TRACESTATE_LENGTH = 512


def _safe_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) and not isinstance(value, (bytes, list, dict, tuple, set))


def sanitize_attributes(attributes: Mapping[str, Any] | None) -> dict[str, str | int | float | bool]:
    """Keep only bounded, known scalar attributes; silently drop sensitive data."""
    if not attributes:
        return {}
    safe: dict[str, str | int | float | bool] = {}
    for key, value in attributes.items():
        if key not in _ALLOWED or any(word in key.lower() for word in _SECRET_WORDS):
            continue
        if not _safe_scalar(value):
            continue
        if key == "action_hash" and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)):
            continue
        if key == "idempotency_key":
            if not isinstance(value, str) or len(value) > _MAX_LENGTH:
                continue
            try:
                UUID(value)
            except ValueError:
                continue
        if key in {"incident_id", "thread_id", "correlation_id", "actor", "permission"} and (not isinstance(value, str) or len(value) > _MAX_LENGTH):
            continue
        if isinstance(value, str):
            if len(value) > _MAX_LENGTH or any(word in value.lower() for word in _SECRET_WORDS):
                continue
            safe[key] = value
        else:
            safe[key] = value
    return safe


@dataclass(frozen=True)
class TelemetryConfig:
    """Configuration; external export requires all three Langfuse settings."""

    service_name: str = "incidentgate"
    external: bool = False
    langfuse_public_key: str | None = field(default=None, repr=False)
    langfuse_secret_key: str | None = field(default=None, repr=False)
    langfuse_base_url: str | None = None
    processors: tuple[SpanProcessor, ...] = field(default_factory=tuple)


class TelemetryRuntime:
    """Owns a provider and exposes explicit lifecycle operations."""

    def __init__(self, provider: TracerProvider, tracer: Any, processors: tuple[SpanProcessor, ...] = (), client: Any = None) -> None:
        self.provider = provider
        self.tracer = tracer
        self.processors = processors
        self.client = client

    def flush(self, timeout_millis: int = 30_000) -> bool:
        result = bool(self.provider.force_flush(timeout_millis))
        if self.client is not None and hasattr(self.client, "flush"):
            self.client.flush()
        return result

    def start_as_current_span(
        self, name: str, *, attributes: Mapping[str, Any] | None = None, parent_context: Any = None
    ) -> Any:
        """Start a span while applying the attribute allow-list."""
        if name not in SPAN_NAMES:
            raise ValueError(f"unknown telemetry span name: {name}")
        kwargs: dict[str, Any] = {"attributes": sanitize_attributes(attributes)}
        if parent_context is not None:
            kwargs["context"] = parent_context
        return self.tracer.start_as_current_span(name, **kwargs)

    def current_trace_id(self, parent_context: Any = None) -> str | None:
        """Return only the public hexadecimal trace ID, never propagation headers."""
        if trace is None:
            return None
        span = trace.get_current_span(parent_context)
        span_context = span.get_span_context()
        return f"{span_context.trace_id:032x}" if span_context.is_valid else None

    def trace_url(self, trace_id: str | None) -> str | None:
        """Use an owning export client URL helper when available; never construct URLs from keys."""
        if not trace_id or self.client is None:
            return None
        for name in ("get_trace_url", "trace_url"):
            helper = getattr(self.client, name, None)
            if callable(helper):
                value = _call_trace_url_helper(helper, trace_id)
                return value if isinstance(value, str) and len(value) <= _MAX_LENGTH else None
        return None

    def shutdown(self) -> None:
        if self.client is not None:
            if hasattr(self.client, "flush"):
                self.client.flush()
            if hasattr(self.client, "shutdown"):
                self.client.shutdown()
        self.provider.shutdown()


def _call_trace_url_helper(helper: Any, trace_id: str) -> Any:
    """Call supported trace URL helpers without masking errors raised by the helper."""
    try:
        helper_signature = signature(helper)
    except (TypeError, ValueError):
        # Keep compatibility with opaque callable fakes and older positional APIs.
        return helper(trace_id)
    try:
        helper_signature.bind(trace_id=trace_id)
    except TypeError:
        try:
            helper_signature.bind(trace_id)
        except TypeError:
            return None
        return helper(trace_id)
    return helper(trace_id=trace_id)


def create_tracer_runtime(
    config: TelemetryConfig | None = None,
    *,
    provider: TracerProvider | None = None,
    processors: tuple[SpanProcessor, ...] | None = None,
    langfuse_factory: Any | None = None,
) -> TelemetryRuntime:
    """Create an isolated tracer provider; never calls ``set_tracer_provider``.

    External export is enabled only when explicitly requested with all credentials.
    """
    if trace is None:
        raise RuntimeError("OpenTelemetry SDK is required to create a telemetry runtime")
    cfg = config or TelemetryConfig()
    selected = processors if processors is not None else cfg.processors
    if cfg.external and not all((cfg.langfuse_public_key, cfg.langfuse_secret_key, cfg.langfuse_base_url)):
        raise ValueError("external telemetry requires Langfuse public key, secret key, and base URL")
    sdk_provider = provider or TracerProvider(resource=Resource.create({"service.name": cfg.service_name}))
    for processor in selected:
        sdk_provider.add_span_processor(processor)
    client = None
    if cfg.external:
        factory = langfuse_factory
        if factory is None:
            from langfuse import Langfuse
            factory = Langfuse
        client = factory(public_key=cfg.langfuse_public_key, secret_key=cfg.langfuse_secret_key, base_url=cfg.langfuse_base_url, tracer_provider=sdk_provider)
    tracer = sdk_provider.get_tracer(cfg.service_name)
    return TelemetryRuntime(sdk_provider, tracer, tuple(selected), client)


def inject_trace_context(carrier: MutableMapping[str, str]) -> MutableMapping[str, str]:
    """Inject the current W3C trace context into an HTTP/header-like carrier."""
    if propagate is None:
        return carrier
    injected: dict[str, str] = {}
    propagate.inject(injected)
    carrier.clear()
    carrier.update(safe_trace_carrier(injected))
    return carrier


def extract_trace_context(carrier: Mapping[str, str] | None) -> Any:
    """Extract untrusted W3C context. It must never be used for authorization."""
    if propagate is None:
        return None
    return propagate.extract(safe_trace_carrier(carrier or {}))


def safe_trace_carrier(carrier: Mapping[str, str]) -> dict[str, str]:
    """Return the tiny, bounded W3C carrier permitted in durable D1 state."""
    result: dict[str, str] = {}
    traceparent = carrier.get("traceparent")
    if isinstance(traceparent, str) and _TRACEPARENT.fullmatch(traceparent):
        result["traceparent"] = traceparent.lower()
    tracestate = carrier.get("tracestate")
    if isinstance(tracestate, str) and 0 < len(tracestate) <= _MAX_TRACESTATE_LENGTH:
        result["tracestate"] = tracestate
    return result
