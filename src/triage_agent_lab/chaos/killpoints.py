"""Deterministic process-kill instrumentation for the chaos kill matrix.

The durable workflow, runtime and repository modules are never edited.  The
chaos worker installs these hooks inside its own short-lived process before it
builds any graph, and every hook is inert until a boundary is armed.

Two kinds of boundary exist:

``<node>:entry`` / ``<node>:exit``
    Wrapped around every node callable declared on a compiled scenario graph.
    An ``exit`` kill lands after the node's side effects but before LangGraph
    has checkpointed the node's completion, which is the hardest replay case.

pseudo-node boundaries
    ``approval:interrupt``       the interrupt is persisted, no approval exists
    ``approval_token:committed`` the approval row is committed, nothing consumed
    ``operation:committed``      the operation is committed, the result is lost
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
from inspect import Parameter, signature
from typing import Any

KILL_EXIT_CODE = 137
KILL_AT_ENV = "CHAOS_KILL_AT"
KILL_PHASE_ENV = "CHAOS_KILL_PHASE"

ENTRY = "entry"
EXIT = "exit"
INTERRUPT = "interrupt"
COMMITTED = "committed"

APPROVAL_NODE = "approval"
APPROVAL_TOKEN_PSEUDO_NODE = "approval_token"
OPERATION_PSEUDO_NODE = "operation"

PSEUDO_BOUNDARIES = (
    f"{APPROVAL_NODE}:{INTERRUPT}",
    f"{APPROVAL_TOKEN_PSEUDO_NODE}:{COMMITTED}",
    f"{OPERATION_PSEUDO_NODE}:{COMMITTED}",
)


@dataclass(frozen=True)
class BoundaryEvent:
    """One crossing of one instrumented boundary inside one worker process."""

    node: str
    position: str
    occurrence: int


def boundary_id(phase: str, event: BoundaryEvent) -> str:
    """Render the stable matrix row identity for a boundary crossing."""
    suffix = "" if event.occurrence == 1 else f"#{event.occurrence}"
    return f"{phase}/{event.node}:{event.position}{suffix}"


class BoundaryRecorder:
    """Records crossings and terminates the process at the armed boundary."""

    def __init__(self) -> None:
        self._phase = "unknown"
        self._armed: str | None = None
        self._counts: dict[tuple[str, str], int] = {}
        self._events: list[BoundaryEvent] = []

    def begin_phase(self, phase: str, armed: str | None) -> None:
        """Start counting a fresh worker phase; occurrences are per phase."""
        self._phase = phase
        self._armed = armed
        self._counts.clear()
        self._events.clear()

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def events(self) -> tuple[BoundaryEvent, ...]:
        return tuple(self._events)

    def boundary_ids(self) -> tuple[str, ...]:
        return tuple(boundary_id(self._phase, event) for event in self._events)

    def record(self, node: str, position: str) -> None:
        key = (node, position)
        occurrence = self._counts.get(key, 0) + 1
        self._counts[key] = occurrence
        event = BoundaryEvent(node=node, position=position, occurrence=occurrence)
        self._events.append(event)
        identifier = boundary_id(self._phase, event)
        if self._armed is not None and identifier == self._armed:
            _die(identifier)


def _die(identifier: str) -> None:
    """Terminate without unwinding: no flush, no close, no rollback."""
    os.write(2, f"chaos-kill {identifier}\n".encode())
    os._exit(KILL_EXIT_CODE)


RECORDER = BoundaryRecorder()
_INSTALLED = False


def _takes_single_positional(action: Callable[..., Any]) -> bool:
    """Only wrap the one-parameter node shape the workflow module declares."""
    try:
        parameters = list(signature(action).parameters.values())
    except (TypeError, ValueError):
        return False
    kinds = {Parameter.POSITIONAL_ONLY, Parameter.POSITIONAL_OR_KEYWORD}
    return len(parameters) == 1 and parameters[0].kind in kinds


def _instrument_node(name: str, action: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(action)
    def instrumented(state: Any) -> Any:
        RECORDER.record(name, ENTRY)
        result = action(state)
        RECORDER.record(name, EXIT)
        return result

    return instrumented


class InstrumentedGraphBuilder:
    """Forwards to a real ``StateGraph`` and wraps every declared node."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.instrumented_nodes: list[str] = []

    def add_node(self, node: Any, action: Any = None, **kwargs: Any) -> Any:
        if isinstance(node, str) and callable(action) and _takes_single_positional(action):
            self.instrumented_nodes.append(node)
            action = _instrument_node(node, action)
        return self._inner.add_node(node, action, **kwargs)

    def __getattr__(self, name: str) -> Any:
        if name == "_inner":
            raise AttributeError(name)
        return getattr(self._inner, name)


def _install_node_boundaries() -> None:
    from langgraph.graph import StateGraph

    from triage_agent_lab.control import workflow

    def factory(*args: Any, **kwargs: Any) -> Any:
        return InstrumentedGraphBuilder(StateGraph(*args, **kwargs))

    module: Any = workflow
    module.StateGraph = factory


def _install_approval_boundary() -> None:
    """Fire once the approval row is durably committed, before any resume."""
    from triage_agent_lab.lab import approval

    original: Any = approval.ApprovalService.approve

    def instrumented(self: Any, request: Any, principal: Any) -> Any:
        token = original(self, request, principal)
        RECORDER.record(APPROVAL_TOKEN_PSEUDO_NODE, COMMITTED)
        return token

    service: Any = approval.ApprovalService
    service.approve = instrumented


def _install_operation_boundary() -> None:
    """Fire once the operation transaction commits, before the graph sees it."""
    from triage_agent_lab.integration import adapters

    original: Any = adapters.LabOperationExecutor.execute

    def instrumented(self: Any, action: Any, context: Any, token: Any, **kwargs: Any) -> Any:
        operation = original(self, action, context, token, **kwargs)
        RECORDER.record(OPERATION_PSEUDO_NODE, COMMITTED)
        return operation

    executor: Any = adapters.LabOperationExecutor
    executor.execute = instrumented


def install() -> None:
    """Install every hook once, in this process only."""
    global _INSTALLED
    if _INSTALLED:
        return
    _INSTALLED = True
    _install_node_boundaries()
    _install_approval_boundary()
    _install_operation_boundary()


def declared_node_names(compiled: Any) -> tuple[str, ...]:
    """Read the node set straight off a compiled graph, never a hard-coded list."""
    return tuple(compiled.builder.nodes)


def armed_boundary(phase: str) -> str | None:
    """Arm only when this process' own chosen phase matches the request."""
    boundary = os.environ.get(KILL_AT_ENV) or None
    if boundary is None or os.environ.get(KILL_PHASE_ENV) != phase:
        return None
    return boundary
