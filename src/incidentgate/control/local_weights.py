"""The local open-weight transport, whose provenance is a file rather than a label.

WHY THIS IS NOT A ``base_url`` FLAG ON THE OPENAI CLIENT
=======================================================

A ``base_url`` parameter would make provider identity **spoofable by editing a
command line**. Point the OpenAI client at any URL, label the run ``local``, and
a paid frontier model is recorded as a free local one -- with the cost, the
``invocation_kind`` and the model identity all decided by whoever typed the
command. Every provenance claim this project makes would degrade into a claim
about what someone asserted.

So "local" is not a name here. It is a claim backed by four things the harness
checks for itself, and it fails closed on each:

1. **The weights bytes.** The harness opens the blob and computes its sha256. It
   is never given a hash to record.
2. **Ollama's own manifest.** The blob store is content-addressed, so the
   manifest independently declares the digest the model layer should have. The
   computed hash is checked against it, which catches a modified blob.
3. **The endpoint is loopback, structurally.** Not a default, not a flag with an
   override: a non-loopback host is refused outright. See
   :func:`_require_loopback`.
4. **The server's own answer.** Every response names the model that produced it,
   and a response naming anything other than the tag this client resolved is
   refused. A local server will happily serve whatever it has loaded, and
   measuring a different model than the artifact names is the exact failure this
   arm exists to be immune to.

WHAT THIS DOES NOT PROVE, STATED PLAINLY
========================================

None of the above proves that the process listening on that loopback port
actually ran those weights. A proxy on 127.0.0.1 could answer with anything,
including output forwarded from a hosted vendor.

What the four checks buy is that such a spoof is **no longer a command line**. It
requires standing up a lying process on the machine, with its own credential,
specifically to produce a false record. That is the bar this design was asked to
clear, and it is worth being precise that it is the bar rather than a proof of
execution. Closing the remaining gap would need attestation of the server
process itself, which is out of scope and is not pretended to exist.

WHY OLLAMA'S NATIVE ``/api/chat`` RATHER THAN ITS OPENAI-COMPATIBLE SHIM
=======================================================================

The shim would let this reuse the OpenAI transport, and that is exactly why it is
not used. Three things this arm needs are native-API facts:

* ``think: false`` -- the documented way to switch Qwen3's hybrid reasoning off.
  Whether the compatibility shim forwards it is not something this project has
  verified, and an unverified reasoning switch is how the OpenAI arm nearly
  shipped a confounded measurement.
* ``format`` -- a JSON schema enforced by the sampler. Constrained decoding is
  mandatory here: a 14B model free-running against a strict parser fails
  constantly, and this lab measures what a model *chooses*, not whether it can
  emit valid JSON.
* ``prompt_eval_count`` / ``eval_count`` -- real usage, which a local run records
  even though nothing was billed.

THERE IS NO PROVIDER POLICY LAYER HERE, AND THAT IS RECORDED
===========================================================

The two hosted arms can answer a request with a refusal raised against the
request itself; this one cannot, because there is no vendor classifier between
the caller and the weights. That is published in the envelope descriptor as
``refusal_surface: none:no_provider_policy_layer`` rather than left implicit,
because it means this arm can reach prompts the hosted arms cannot -- which is a
property of the *path*, not evidence about any model, and a reader comparing rows
across arms needs to be able to see it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final
from urllib.parse import urlparse

from incidentgate.contracts import ModelInvocationRecord
from incidentgate.reasons import PROPOSAL_MODEL_OUTPUT_TRUNCATED

from .model_capabilities import reasoning_equivalence
from .model_proposal import CompletionRequest, CompletionResult
from .proposal import ProposalError

#: This arm's published equivalence claim when reasoning was explicitly switched
#: off. Plural "arms" -- it compares itself against two others, where each hosted
#: arm compares against one. A literal because it sits in committed captures.
_REASONING_OFF_EQUIVALENCE = "explicitly_off:analogous_to_the_other_arms_not_identical"

PROVIDER: Final = "local"

@dataclass(frozen=True)
class LocalModelFacts:
    """Per-model facts read off ``ollama show``, not inferred from a name."""

    tag: str
    quantisation: str
    #: What the modelfile declares. Empty is a real and different answer from
    #: absent -- see ``OLLAMA_DEFAULT_SAMPLING``.
    modelfile_sampling: Mapping[str, str]


#: The local models this lab can run, and the facts a capture must record about
#: them. Verified with ``ollama show`` and ``ollama show --modelfile`` on
#: 2026-08-21 rather than copied from a model card.
#:
#: The harness id and the server tag differ because they have to: Ollama tags
#: contain a colon, and the harness id travels into a response-cache *directory
#: name*, a ``ProviderCaptureProvenance.model`` field and a v3
#: ``attacker_source``, none of which admit one.
#:
#: THE TWO ROWS ARE NOT INTERCHANGEABLE AND MUST NOT BE EQUATED.
#:
#: Qwen3 is Q4_K_M; Mistral Nemo is Q4_0, a lower-fidelity quantisation scheme.
#: They are also different lineages and architectures (``qwen3`` against
#: ``llama``), and only one of them has a reasoning mode at all. That makes the
#: second a genuinely independent data point on whether a decline is
#: model-specific -- and it also means any difference in their results has more
#: than one candidate explanation, quantisation included.
LOCAL_MODELS: Final[Mapping[str, LocalModelFacts]] = MappingProxyType({
    "qwen3-14b": LocalModelFacts(
        tag="qwen3:14b",
        quantisation="Q4_K_M",
        modelfile_sampling=MappingProxyType({
            "temperature": "0.6", "top_p": "0.95", "top_k": "20", "repeat_penalty": "1"
        }),
    ),
    "mistral-nemo-12b": LocalModelFacts(
        tag="mistral-nemo:12b",
        quantisation="Q4_0",
        # Declares only stop tokens. Nothing is set, so Ollama's own defaults
        # apply -- which is a different thing from "unset", and the reason
        # OLLAMA_DEFAULT_SAMPLING has to exist.
        modelfile_sampling=MappingProxyType({}),
    ),
})

#: Kept as a derived mapping because callers ask this question directly.
OLLAMA_TAGS: Final[Mapping[str, str]] = MappingProxyType(
    {model: facts.tag for model, facts in LOCAL_MODELS.items()}
)

#: Ollama's own defaults, which apply to any parameter neither the request nor
#: the modelfile sets. Quoted verbatim from docs.ollama.com/modelfile, retrieved
#: 2026-08-21:
#:
#:   temperature    "(Default: 0.8)"
#:   top_k          "(Default: 40)"
#:   top_p          "(Default: 0.9)"
#:   repeat_penalty "(Default: 1.0, disabled)"
#:
#: OMISSION IS NEVER NEUTRAL ON THIS PROVIDER, WHICH IS WHY THIS TABLE EXISTS.
#:
#: There is no configuration in which sending nothing yields unset or identity
#: sampling. Something always applies, and what applies varies per model: an
#: omitted temperature is 0.6 on qwen3:14b because its modelfile says so, and
#: 0.8 on mistral-nemo:12b because its modelfile says nothing and Ollama's
#: default takes over. So "we sent nothing" can never be recorded as a sampling
#: description here -- only an effective value with the source that produced it.
OLLAMA_DEFAULT_SAMPLING: Final[Mapping[str, str]] = MappingProxyType(
    {"temperature": "0.8", "top_k": "40", "top_p": "0.9", "repeat_penalty": "1.0"}
)

#: The default Ollama endpoint. Loopback, and :func:`_require_loopback` refuses
#: anything that is not -- there is deliberately no override.
DEFAULT_ENDPOINT: Final = "http://127.0.0.1:11434"

_LOOPBACK_HOSTS: Final = frozenset({"127.0.0.1", "::1", "localhost"})

#: The manifest layer that holds the weights themselves, as opposed to the
#: template, licence and parameter layers Ollama stores beside them.
_MODEL_MEDIA_TYPE: Final = "application/vnd.ollama.image.model"

#: Ollama's ``done_reason`` for a normally completed answer, and for one cut off
#: by the token budget.
_DONE_STOP: Final = "stop"
_DONE_LENGTH: Final = "length"

#: Read the blob in chunks: the file is ~9 GB for a 14B model at Q4 and must not
#: be loaded into memory to be hashed.
_HASH_CHUNK_BYTES: Final = 4 * 1024 * 1024


class LocalWeightsError(RuntimeError):
    """A local-weights claim could not be established. Never a model observation."""


class WeightsIdentityMismatch(LocalWeightsError):
    """The bytes on disk are not the bytes the store says they are.

    Raised when the harness-computed sha256 disagrees with the digest Ollama's
    manifest declares for the model layer. Deliberately fatal: the entire value
    of this arm is that the weights are pinned, so a run whose weights cannot be
    pinned has nothing to offer over a hosted one.
    """


class LocalModelUnavailable(LocalWeightsError):
    """The server could not serve the model. An environment fact, never a choice.

    The common cause is VRAM: a 14B model at Q4 needs roughly 9 GB, and the card
    this arm targets holds 10 GB total with ordinary desktop applications
    frequently occupying most of it. A model that will not load has not declined
    anything.

    This is the same distinction ``TransportUnavailable`` draws for a provider
    outage, and it is drawn again here because the failure looks different --
    the server is up, reachable and answering, it simply cannot fit the weights.
    A caller that recorded that as a model outcome would be publishing a result
    about a model that never ran.
    """


class ServedModelMismatch(LocalWeightsError):
    """The server answered as a different model than the one this client resolved.

    A local server serves whatever it has loaded and is under no obligation to
    match what was asked for. Silently measuring one model while the artifact
    names another is precisely the failure this arm is supposed to be immune to,
    so the response is refused rather than parsed.
    """


@dataclass(frozen=True)
class LocalWeightsIdentity:
    """What was actually loaded, established from disk rather than from a name.

    Every field here is either computed by this process or read out of the local
    store. Nothing in it is a caller assertion, which is the property that makes
    a published local row mean something.
    """

    harness_model: str
    server_model: str
    weights_path: Path
    #: Computed by :func:`_hash_file` over the blob, not supplied by a caller.
    weights_sha256: str
    #: The digest Ollama's manifest declares for the model layer. Recorded beside
    #: the computed hash so a reader can see the two agreed rather than being
    #: told that they did.
    declared_digest: str
    size_bytes: int
    quantisation: str

    def provenance(self) -> dict[str, str]:
        """The weights identity as flat strings, for the capture record."""
        return {
            "harness_model": self.harness_model,
            "server_model": self.server_model,
            "weights_path": str(self.weights_path),
            "weights_sha256": self.weights_sha256,
            "declared_digest": self.declared_digest,
            "size_bytes": str(self.size_bytes),
            "quantisation": self.quantisation,
            "hash_verified_by": "incidentgate",
        }


def ollama_store_root(store_root: Path | None = None) -> Path:
    """Where Ollama keeps its content-addressed blobs and manifests."""
    if store_root is not None:
        return store_root
    return Path.home() / ".ollama" / "models"


def _hash_file(path: Path) -> tuple[str, int]:
    """Stream a sha256 over the file, returning the digest and the byte count."""
    digest = sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _manifest_path(root: Path, tag: str) -> Path:
    name, _, version = tag.partition(":")
    if not name or not version:
        raise LocalWeightsError(f"{tag!r} is not a name:version Ollama tag")
    return root / "manifests" / "registry.ollama.ai" / "library" / name / version


def resolve_ollama_weights(
    harness_model: str, *, store_root: Path | None = None
) -> LocalWeightsIdentity:
    """Establish which weights file backs a model tag, and verify its bytes.

    The manifest is read for the declared digest, the blob is located from it,
    and the hash is then **computed here** and checked against the declaration.
    A caller cannot supply either value, so the recorded identity is a fact about
    this machine rather than a claim about it.

    Raises rather than degrading at every step. A local run whose weights cannot
    be established is not a local run with weaker provenance; it is a run with
    no provenance advantage at all, which is the only reason to prefer this arm.
    """
    facts = LOCAL_MODELS.get(harness_model)
    if facts is None:
        raise LocalWeightsError(
            f"{harness_model!r} is not in LOCAL_MODELS; add its tag, quantisation and "
            "declared sampling there before running it"
        )
    tag = facts.tag
    root = ollama_store_root(store_root)
    manifest_file = _manifest_path(root, tag)
    if not manifest_file.is_file():
        raise LocalModelUnavailable(
            f"no Ollama manifest for {tag!r} at {manifest_file}; pull the model first"
        )
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LocalWeightsError(f"unreadable Ollama manifest for {tag!r}") from error
    layers = manifest.get("layers") if isinstance(manifest, dict) else None
    if not isinstance(layers, list):
        raise LocalWeightsError(f"Ollama manifest for {tag!r} declares no layers")
    model_layers = [
        layer
        for layer in layers
        if isinstance(layer, dict) and layer.get("mediaType") == _MODEL_MEDIA_TYPE
    ]
    if len(model_layers) != 1:
        raise LocalWeightsError(
            f"Ollama manifest for {tag!r} declares {len(model_layers)} weights layers, expected 1"
        )
    declared = model_layers[0].get("digest")
    if not isinstance(declared, str) or not declared.startswith("sha256:"):
        raise LocalWeightsError(f"Ollama manifest for {tag!r} declares no sha256 weights digest")
    blob = root / "blobs" / declared.replace(":", "-")
    if not blob.is_file():
        raise LocalModelUnavailable(f"weights blob {blob.name} is missing from the Ollama store")
    computed, size = _hash_file(blob)
    if computed != declared.removeprefix("sha256:"):
        raise WeightsIdentityMismatch(
            f"weights blob for {tag!r} hashes to {computed}, but the manifest declares "
            f"{declared}; refusing to record a run against weights that are not what the "
            "store says they are"
        )
    return LocalWeightsIdentity(
        harness_model=harness_model,
        server_model=tag,
        weights_path=blob,
        weights_sha256=computed,
        declared_digest=declared,
        size_bytes=size,
        # Not in the manifest layer, so it comes from LOCAL_MODELS, where it was
        # recorded from `ollama show` rather than guessed from the tag. Q4_0 and
        # Q4_K_M are materially different schemes and the two rows must not be
        # silently equated.
        quantisation=facts.quantisation,
    )


def _require_loopback(endpoint: str) -> str:
    """Refuse any endpoint that is not on this machine. No override exists.

    This is the check that makes ``local`` mean something. Without it the
    transport is a general HTTP client with a provenance label attached, and the
    weights hash becomes decoration: a real file could be hashed on disk while
    the answers came from a vendor across the network.

    An escape hatch was considered and rejected. A flag that relaxes this would
    be exactly the command-line edit the whole design exists to rule out, and
    "local but actually remote" is not a configuration this project has any use
    for.
    """
    parsed = urlparse(endpoint)
    if parsed.scheme not in ("http", "https"):
        raise LocalWeightsError(f"local endpoint must be http(s), got {parsed.scheme!r}")
    if parsed.hostname not in _LOOPBACK_HOSTS:
        raise LocalWeightsError(
            f"a local-weights run must talk to loopback, not {parsed.hostname!r}; "
            "a non-loopback endpoint cannot be recorded as a local run"
        )
    return endpoint.rstrip("/")


def effective_sampling(
    model: str, sampling: Mapping[str, str] | None
) -> dict[str, tuple[str, str]]:
    """Resolve each sampling parameter to its value and the source that set it.

    Three layers, in precedence order: what this lab sent, what the model's
    modelfile declares, and what Ollama defaults to. A reader has to be able to
    tell a value we chose from one that was applied to us, and that distinction
    is exactly what disappears if only the numbers are recorded.
    """
    facts = LOCAL_MODELS.get(model)
    modelfile = {} if facts is None else dict(facts.modelfile_sampling)
    resolved: dict[str, tuple[str, str]] = {}
    for name, value in OLLAMA_DEFAULT_SAMPLING.items():
        resolved[name] = (value, "ollama_default")
    for name, value in modelfile.items():
        resolved[name] = (value, "modelfile")
    for name, value in (sampling or {}).items():
        resolved[name] = (value, "explicit")
    return dict(sorted(resolved.items()))


def _sampling_descriptor(model: str, sampling: Mapping[str, str] | None) -> tuple[str, str]:
    """Describe the effective sampling and where every value came from.

    Both halves are published because neither is enough alone. The values say
    what the model sampled at; the provenance says who decided each one.
    """
    resolved = effective_sampling(model, sampling)
    effective = ",".join(f"{name}={value}" for name, (value, _) in resolved.items())
    by_source: dict[str, list[str]] = {}
    for name, (_, source) in resolved.items():
        by_source.setdefault(source, []).append(name)
    provenance = ";".join(
        f"{source}:{','.join(sorted(names))}"
        for source, names in sorted(by_source.items())
    )
    return effective, provenance


def ollama_envelope_descriptor(
    think: bool | None = None,
    sampling: Mapping[str, str] | None = None,
    model: str = "",
) -> dict[str, str]:
    """Publish the API envelope this transport sends, in its siblings' keys.

    Third arm, same descriptor shape, so the three can be compared without
    reading three transports.
    """
    return {
        "provider": PROVIDER,
        "system_channel": "system_role_message",
        "output_budget_field": "options.num_predict",
        "structured_output": "format:json_schema",
        # Ollama's ``format`` is enforced by the sampler rather than requested of
        # the model, which is the opposite of the OpenAI arm's non-strict schema.
        # Recorded because it is a real difference in what the model could have
        # emitted, not only in what was asked of it.
        "structured_output_strict": "true",
        "usage_fields": "prompt_eval_count,eval_count",
        # No vendor policy layer sits between this caller and the weights, so
        # this arm has no refusal surface at all. That is why it can reach
        # prompts the hosted arms cannot, and it is a fact about the path rather
        # than evidence about any model.
        "refusal_surface": "none:no_provider_policy_layer",
        "reasoning_control": (
            "think:omitted:model_default_applies"
            if think is None
            else f"think={str(think).lower()}"
        ),
        # ``think`` is a bool, so this is the arm where the old presence-based
        # branch was most plainly wrong: ``think=True`` would have published
        # ``reasoning_control=think=true`` and ``reasoning_equivalence`` saying
        # reasoning was explicitly off, in the same descriptor. Nothing sends
        # True today -- ``think_directive`` returns only False or None -- which
        # is what kept it latent rather than published.
        "reasoning_equivalence": reasoning_equivalence(
            off=None if think is None else not think,
            off_label=_REASONING_OFF_EQUIVALENCE,
        ),
        # The only arm whose sampling can be set at all, and therefore the only
        # one where a mismatch could be removed rather than merely disclosed.
        # temperature and top_p are sent explicitly; everything else resolves to
        # the modelfile's value or Ollama's default, and each is labelled with
        # which. "none_sent" would have been meaningless here: omission is never
        # neutral on this provider, and resolves differently per model.
        "sampling": _sampling_descriptor(model, sampling)[0],
        "sampling_provenance": _sampling_descriptor(model, sampling)[1],
    }


JsonPost = Callable[[str, dict[str, Any], float], dict[str, Any]]


def _urllib_post(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    """POST JSON over loopback using the standard library, so this adds no dependency."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            decoded = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        # Ollama reports a model that will not load as an HTTP error carrying a
        # JSON body. Surfacing the body is what lets the caller tell "out of
        # VRAM" from "no such model" without guessing.
        detail = error.read().decode("utf-8", errors="replace")[:400]
        raise LocalModelUnavailable(f"ollama returned HTTP {error.code}: {detail}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise LocalModelUnavailable(f"ollama request failed: {type(error).__name__}") from error
    if not isinstance(decoded, dict):
        raise LocalWeightsError("ollama returned a non-object response")
    return decoded


class OllamaWeightsCompletionClient:
    """Local transport whose identity is a hashed weights file, not a name.

    Holds no credential and takes no ``api_key`` parameter, which is not an
    omission: it is the property the spend gate keys on. A client that cannot
    authenticate to a paid API cannot bill one, whatever URL it is pointed at --
    and it can only be pointed at loopback anyway.
    """

    def __init__(
        self,
        *,
        weights: LocalWeightsIdentity,
        endpoint: str = DEFAULT_ENDPOINT,
        # Generous next to the hosted arms' 20-30s. A 14B model on a card that is
        # sharing VRAM with desktop applications can spend minutes loading before
        # it emits a token, and a timeout that fired during a load would be
        # recorded as an environment failure that was really an impatient client.
        timeout_seconds: float = 900.0,
        post_json: JsonPost | None = None,
    ) -> None:
        if not 0 < timeout_seconds <= 3600:
            raise ValueError("timeout must be within (0, 3600] seconds")
        self._weights = weights
        self._endpoint = _require_loopback(endpoint)
        self._timeout_seconds = timeout_seconds
        self._post_json = post_json or _urllib_post

    def __repr__(self) -> str:
        return (
            f"OllamaWeightsCompletionClient(server_model={self._weights.server_model!r}, "
            f"weights_sha256={self._weights.weights_sha256[:12]!r})"
        )

    @property
    def weights(self) -> LocalWeightsIdentity:
        return self._weights

    def envelope_descriptor(self, request: CompletionRequest) -> dict[str, str]:
        return ollama_envelope_descriptor(request.think, request.sampling, request.model)

    def complete(self, request: CompletionRequest) -> CompletionResult:
        if request.thinking is not None or request.reasoning is not None:
            # Both are other arms' parameters. Ollama would ignore an unknown key
            # and answer happily, so a request carrying one means the capability
            # table sent this model to the wrong provider's accessor and the run
            # would silently proceed at the model's own default.
            raise ValueError(
                "another provider's reasoning directive cannot be sent to Ollama; the "
                "capability table entry for this model is wrong"
            )
        payload: dict[str, Any] = {
            "model": self._weights.server_model,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user_content},
            ],
            # Constrained decoding, not a hint: the sampler is restricted to the
            # schema. Local re-validation in ModelAgentProposer._parse stays
            # strict regardless.
            "format": request.schema,
            "stream": False,
            "options": {"num_predict": request.max_tokens},
        }
        if request.sampling is not None:
            # Sent explicitly rather than inherited. The modelfile bakes
            # temperature 0.6, and the arm this is compared against runs at a
            # documented 1.0, so silence here would have been a divergence that
            # every envelope described as "none_sent". Floats, because the API
            # takes numbers -- the directive carries strings so it can travel
            # through the canonical prompt and the envelope unambiguously.
            for name, value in request.sampling.items():
                try:
                    payload["options"][name] = float(value)
                except ValueError as error:
                    raise ValueError(f"sampling value {name}={value!r} is not numeric") from error
        if request.think is not None:
            # Sent through the documented API parameter rather than by appending
            # a token like ``/no_think`` to the prompt. A prompt hack would change
            # the prompt bytes, and the bytes are the thing three arms are meant
            # to hold identical.
            payload["think"] = request.think
        response = self._post_json(f"{self._endpoint}/api/chat", payload, self._timeout_seconds)
        if isinstance(response.get("error"), str):
            raise LocalModelUnavailable(f"ollama error: {response['error'][:400]}")

        served = response.get("model")
        if served != self._weights.server_model:
            raise ServedModelMismatch(
                f"requested {self._weights.server_model!r} but the server answered as "
                f"{served!r}; refusing to record output from a model this run did not resolve"
            )

        done_reason = response.get("done_reason")
        if done_reason == _DONE_LENGTH:
            raise ProposalError(PROPOSAL_MODEL_OUTPUT_TRUNCATED)
        if done_reason != _DONE_STOP:
            raise ValueError(f"incomplete response (done_reason={done_reason!r})")

        message = response.get("message")
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str) or not text:
            raise ValueError("non-text response")
        thinking = message.get("thinking") if isinstance(message, dict) else None
        if isinstance(thinking, str) and thinking.strip():
            # Thinking was asked to be off and the server produced some anyway.
            # That is a different experiment from the one the other two arms ran,
            # so it fails closed rather than being published as comparable.
            raise ValueError(
                "the server returned reasoning content despite think=false; this run is not "
                "comparable with the arms that switched reasoning off"
            )
        input_tokens = response.get("prompt_eval_count")
        output_tokens = response.get("eval_count")
        if (
            input_tokens is None
            or output_tokens is None
            or not isinstance(input_tokens, int)
            or not isinstance(output_tokens, int)
        ):
            # Usage is required even though nothing was billed: a local run still
            # measures how much work the model did, and a capture that dropped it
            # would be less informative than a hosted one for no reason.
            raise ValueError("missing ollama usage")
        invocation = ModelInvocationRecord(
            provider=PROVIDER,
            model=self._weights.harness_model,
            # Not provider_call: no vendor was charged and no pricing snapshot
            # applies. Not fixture_no_call either -- a model really was invoked,
            # and recording otherwise would be false in the direction that
            # flatters us. See contracts.py.
            invocation_kind="local_weights_call",
            usage_source="ollama_chat_usage",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        return CompletionResult(raw_json=text, invocation=invocation)


def ollama_envelope_json(request: CompletionRequest) -> str:
    """The envelope descriptor as canonical JSON, for recording in provenance."""
    return json.dumps(
        ollama_envelope_descriptor(request.think, request.sampling, request.model),
        sort_keys=True,
        separators=(",", ":"),
    )
