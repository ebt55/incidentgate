"""One row per provider: its credential, its transport, its envelope, its price list.

WHY THIS IS A TABLE AND NOT FOUR TERNARIES
==========================================

Four sites used to resolve a provider name by asking ``if provider == "anthropic"``
and taking the OpenAI answer otherwise -- the T1 attacker seat, the T1 monitor
seat, T4's ``monitor_transport``, and the envelope descriptor. Three of the four
had no ``else`` that could refuse: a third provider name would have been handed
``OPENAI_API_KEY`` and an :class:`OpenAICompletionClient`, and the run would have
worked. It would have produced a capture whose provenance named one vendor and
whose bytes came from another, which is the one class of error this project's
whole provenance discipline exists to make impossible.

So the mapping is stated once, here, and every site reads it. **Adding a provider
is an edit to :data:`PROVIDER_REGISTRY` and to nothing else that dispatches.** A
name with no row raises :class:`UnknownProvider` at every entry point rather than
resolving to whichever branch happened to be the fallthrough.

WHY THE TRANSPORT CLASS IS IN THE ROW AND A ``base_url`` IS NOT
===============================================================

Each provider brings its own transport module. It does not bring a URL for a
shared one -- see the argument at the top of ``local_weights``: a ``base_url``
parameter makes provider identity spoofable by editing a command line, while
provider identity is recorded in every capture's provenance. A registry row is
the cheap thing to add precisely so that a shared, re-pointable client never
looks like the cheaper one.

WHAT ``bills_vendor`` IS READ OFF, AND WHY IT IS NOT RESTATED HERE
==================================================================

Whether a provider can bill is not a field of the row. It is read off the
transport class's own :data:`BILLS_VENDOR_ATTRIBUTE` declaration, so the registry
and the spend gate cannot end up disagreeing about the same transport: they are
looking at the same statement. See :func:`transport_bills_a_vendor`, which is
what ``SpendMeter`` asks about an *injected* client -- including one that has no
registry row at all.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final, Protocol, get_args

from .local_weights import PROVIDER as LOCAL_PROVIDER
from .local_weights import ollama_envelope_descriptor
from .model_capabilities import ModelProvider
from .model_proposal import (
    ANTHROPIC_PROVIDER,
    AnthropicCompletionClient,
    CompletionClient,
    CompletionRequest,
    PricingSnapshot,
    anthropic_envelope_descriptor,
)
from .openai_completion import PROVIDER as OPENAI_PROVIDER
from .openai_completion import OpenAICompletionClient, openai_envelope_descriptor

_ROOT: Final = Path(__file__).resolve().parents[3]
_PRICING_DIR: Final = _ROOT / "config" / "pricing"

#: The class attribute a transport sets to declare that it cannot bill a vendor.
#:
#: Read by :func:`transport_bills_a_vendor`, which treats its *absence* as
#: "billing". That direction is the whole design: a new transport whose author
#: forgot to say anything is refused by the spend gate rather than waved through.
BILLS_VENDOR_ATTRIBUTE: Final = "bills_vendor"


class UnknownProvider(ValueError):
    """A provider name that no registry row states.

    A ``ValueError`` because that is what the four call sites already raised for
    an unknown provider where they raised anything at all, so the exception type
    a caller catches does not move.
    """


class ProviderCredentialMissing(LookupError):
    """The environment holds no credential for a provider whose transport needs one.

    Carries the variable name so a caller can phrase its own refusal in its own
    vocabulary -- T1 raises ``SpendRefused``, T4 raises ``HarnessAborted`` -- while
    the *fact* of which variable a provider reads is stated only in the registry.
    """

    def __init__(self, provider: str, env_var: str) -> None:
        super().__init__(f"{env_var} is required to capture from {provider}")
        self.provider = provider
        self.env_var = env_var


class BillingTransportFactory(Protocol):
    """Builds a credentialed transport for one provider.

    The transport *class* is what sits in this slot, not a wrapper around it,
    which is what lets :attr:`ProviderEntry.bills_vendor` read the class's own
    declaration instead of the row restating it.
    """

    def __call__(self, *, api_key: str, pricing: PricingSnapshot) -> CompletionClient: ...


def transport_bills_a_vendor(transport: object) -> bool:
    """Whether this transport must be treated as able to bill a vendor.

    FAIL CLOSED: ONLY A POSITIVE DECLARATION OF ``False`` EXEMPTS ANYTHING.

    The predecessor of this function was ``isinstance(inner, (Anthropic..., OpenAI...))``
    inside the spend gate -- an allowlist of the two billing transports that
    existed when it was written. Everything else, including a billing transport
    added later, was *not* an instance of either, so it was injected past the gate
    and could spend unauthorised. The check was a list of what to stop, and a list
    of what to stop is only ever as complete as the last person to edit it.

    Asking the transport, and reading silence as "yes", inverts that: forgetting
    to register a new billing transport now costs a refusal instead of a charge.
    The two outcomes of getting it wrong are not symmetric, and this is the
    direction the asymmetry points.

    A class object answers as well as an instance, because the declaration is a
    ``ClassVar``. Anything other than the exact value ``False`` -- a missing
    attribute, ``None``, a truthy value, a string -- reads as billing.

    Deliberately *not* declared by ``CacheBackedCompletionClient``: in record mode
    it forwards to whatever transport it was given, so it can reach a vendor. It
    is never wrapped in a meter today, and if it ever is, the fail-closed default
    is the answer that does not lose money.
    """
    return getattr(transport, BILLS_VENDOR_ATTRIBUTE, True) is not False


@dataclass(frozen=True)
class ProviderEntry:
    """Everything the harness needs to dispatch one provider name."""

    #: The name this provider is selected by on the command line and recorded as
    #: in every capture's provenance.
    provider: str
    #: The environment variable holding this provider's credential. ``None``
    #: exactly for a provider whose transport holds no credential at all.
    api_key_env_var: str | None
    #: The committed price list a billed capture's cost must be checkable
    #: against. ``None`` exactly for a provider that bills nobody -- deliberately
    #: absent rather than a zero-cost snapshot, because inventing one would make
    #: "we priced it at zero" indistinguishable from "there is nothing to price".
    pricing_snapshot: Path | None
    #: The published API envelope descriptor, built from the request that was
    #: actually sent rather than from this provider's name. A descriptor of what
    #: a transport *usually* does could stay reassuring while the request said
    #: something else.
    envelope: Callable[[CompletionRequest], dict[str, str]]
    #: The transport class for a provider that authenticates to a vendor.
    #: ``None`` for one that does not: the local arm is constructed from resolved
    #: weights and an endpoint rather than from a credential, so it has no
    #: uniform factory to offer and is built at its own call site.
    billing_transport: BillingTransportFactory | None

    def __post_init__(self) -> None:
        if self.bills_vendor != (self.api_key_env_var is not None):
            raise ValueError(
                f"{self.provider}: a provider that can bill needs exactly one credential "
                "variable, and one that cannot must name none"
            )
        if self.bills_vendor != (self.pricing_snapshot is not None):
            raise ValueError(
                f"{self.provider}: a provider that can bill needs a committed pricing "
                "snapshot, and one that cannot must not carry a fabricated one"
            )

    @property
    def bills_vendor(self) -> bool:
        """Whether a call through this provider can bill a vendor.

        Read off the transport class's own declaration rather than restated as a
        field, so this row and the spend gate cannot disagree about the same
        transport. A provider with no credentialed transport bills nobody; a
        registered transport that declared nothing reads as billing, which then
        makes the two checks in ``__post_init__`` demand a credential and a price
        list for it.
        """
        if self.billing_transport is None:
            return False
        return transport_bills_a_vendor(self.billing_transport)


#: THE ONE PLACE A PROVIDER IS ADDED.
#:
#: A new row needs: the name, its credential variable, its committed pricing
#: snapshot, its envelope descriptor, and its transport class. It also needs the
#: name added to ``model_capabilities.ModelProvider`` -- the check below refuses
#: an import where the two disagree, so neither half can be forgotten quietly.
#:
#: Insertion order is the order ``--provider`` offers on the command line and the
#: order an "expected one of ..." refusal names, so new rows go at the end.
PROVIDER_REGISTRY: Final[Mapping[str, ProviderEntry]] = MappingProxyType({
    ANTHROPIC_PROVIDER: ProviderEntry(
        provider=ANTHROPIC_PROVIDER,
        api_key_env_var="ANTHROPIC_API_KEY",
        pricing_snapshot=_PRICING_DIR / "anthropic-2026-08-14.json",
        envelope=lambda request: anthropic_envelope_descriptor(request.thinking),
        billing_transport=AnthropicCompletionClient,
    ),
    OPENAI_PROVIDER: ProviderEntry(
        provider=OPENAI_PROVIDER,
        api_key_env_var="OPENAI_API_KEY",
        pricing_snapshot=_PRICING_DIR / "openai-2026-08-20.json",
        envelope=lambda request: openai_envelope_descriptor(request.reasoning),
        billing_transport=OpenAICompletionClient,
    ),
    LOCAL_PROVIDER: ProviderEntry(
        provider=LOCAL_PROVIDER,
        api_key_env_var=None,
        pricing_snapshot=None,
        envelope=lambda request: ollama_envelope_descriptor(
            request.think, request.sampling, request.model
        ),
        billing_transport=None,
    ),
})


def _require_registry_names_the_stated_arms() -> None:
    """The registry and the capability table must name the same set of arms.

    Not a nicety. ``model_capabilities.model_provider`` is what decides which
    transport a monitor model is seated on, and this registry is what builds it.
    A provider stated in one and missing from the other is a run that resolves a
    seat it cannot construct, or a transport nothing can be seated on.
    """
    registered = set(PROVIDER_REGISTRY)
    stated = set(get_args(ModelProvider))
    if registered != stated:
        raise ValueError(
            "the provider registry and model_capabilities.ModelProvider must name the same "
            f"arms; unregistered {sorted(stated - registered)!r}, "
            f"unstated {sorted(registered - stated)!r}"
        )
    for name, entry in PROVIDER_REGISTRY.items():
        if name != entry.provider:
            raise ValueError(f"registry key {name!r} does not match its row's {entry.provider!r}")


_require_registry_names_the_stated_arms()

#: Every provider name this harness can serve, in registry order.
PROVIDERS: Final[tuple[str, ...]] = tuple(PROVIDER_REGISTRY)

#: Providers that cannot bill anyone, because there is no vendor on the other
#: end. Derived from the rows so it cannot drift out of step with them -- but a
#: name is still never what the spend gate keys on: see ``SpendMeter.complete``,
#: which verifies each result's absent cost before treating a call as free.
PROVIDERS_WITHOUT_VENDOR_COST: Final[frozenset[str]] = frozenset(
    name for name, entry in PROVIDER_REGISTRY.items() if not entry.bills_vendor
)

#: One committed snapshot per *billing* provider. A billing provider without one
#: cannot publish: contracts.py refuses a provider_call lacking a named pricing
#: snapshot, and the preflight refuses a model the snapshot cannot price.
PRICING_SNAPSHOTS: Final[dict[str, Path]] = {
    name: entry.pricing_snapshot
    for name, entry in PROVIDER_REGISTRY.items()
    if entry.pricing_snapshot is not None
}


def provider_entry(provider: str) -> ProviderEntry:
    """The registry row for this provider name, or a refusal naming the known ones."""
    entry = PROVIDER_REGISTRY.get(provider)
    if entry is None:
        raise UnknownProvider(f"{provider} is not a known provider; expected one of {PROVIDERS}")
    return entry


def bills_vendor(provider: str) -> bool:
    """Whether a call to this provider can bill a vendor. Refuses an unknown name."""
    return provider_entry(provider).bills_vendor


def pricing_snapshot_path(provider: str) -> Path:
    """The committed price list for a billing provider, or a refusal for one with none."""
    entry = provider_entry(provider)
    if entry.pricing_snapshot is None:
        raise UnknownProvider(
            f"{provider} bills no vendor, so it has no pricing snapshot to load"
        )
    return entry.pricing_snapshot


def api_key_env_var(provider: str) -> str:
    """Which environment variable holds this provider's credential."""
    entry = provider_entry(provider)
    if entry.api_key_env_var is None:
        raise UnknownProvider(f"{provider} holds no credential, so it reads no key variable")
    return entry.api_key_env_var


def provider_envelope_descriptor(
    provider: str, request: CompletionRequest
) -> dict[str, str]:
    """The API envelope descriptor for the request this provider was actually sent."""
    return provider_entry(provider).envelope(request)


def build_billing_transport(
    provider: str, *, pricing: PricingSnapshot, environ: Mapping[str, str] | None = None
) -> CompletionClient:
    """Read this provider's credential from the environment and construct its transport.

    The spend gate is **not** applied here and must be satisfied by the caller
    first. That split is deliberate: the gate governs whether this process may
    construct anything that can bill at all, which is a decision about the run,
    while this function is the mechanical part -- which variable, which class.
    Folding the gate in would put it one import away from a caller who wanted the
    class without the decision.

    Raises :class:`ProviderCredentialMissing` rather than a caller's own refusal
    type, so both seats keep their own exception and their own wording while the
    variable name is stated in exactly one place.
    """
    entry = provider_entry(provider)
    if entry.billing_transport is None or entry.api_key_env_var is None:
        raise UnknownProvider(
            f"{provider} bills no vendor, so it has no credentialed transport to build"
        )
    env = os.environ if environ is None else environ
    api_key = env.get(entry.api_key_env_var, "")
    if not api_key:
        raise ProviderCredentialMissing(provider, entry.api_key_env_var)
    return entry.billing_transport(api_key=api_key, pricing=pricing)
