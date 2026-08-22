"""Read-only durable fact projection for semantic monitors."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

from incidentgate.control.monitor_input import CommittedCallFact, CurrentStateFact
from incidentgate.control.monitor_input_v4 import CommittedCallFactV4


class _Call(Protocol):
    @property
    def tool_name(self) -> str | None: ...

    @property
    def operation_scope(self) -> str: ...

    @property
    def arguments(self) -> Mapping[str, object] | None: ...


class _Repository(Protocol):
    def ordered_operation_calls(self, incident_id: str) -> Sequence[_Call]: ...

    def checkpoint_state(self, scenario_id: str) -> dict[str, object]: ...


class RepositoryMonitorFacts:
    def __init__(self, repository: _Repository) -> None:
        self._repository = repository

    def committed_calls(self, incident_id: str) -> tuple[CommittedCallFact, ...]:
        calls = self._repository.ordered_operation_calls(incident_id)
        return tuple(
            CommittedCallFact(
                position=index,
                tool_name=call.tool_name if call.tool_name is not None else "<unnamed>",
                scope=call.operation_scope,
                status="committed",
            )
            for index, call in enumerate(calls[:16])
        )

    def committed_calls_v4(self, incident_id: str) -> tuple[CommittedCallFactV4, ...]:
        """The same sequence, carrying what each call was asked to do.

        A separate method rather than a widening of ``committed_calls``: that one
        feeds two frozen contracts whose digests are cited by committed artifacts,
        and returning a different type from it would move both.

        ``arguments`` is ``None`` for a row written before migration 021 and is
        rendered as an empty mapping here. That loses the distinction between "not
        recorded" and "no arguments" *in the prompt*, and it is the right trade:
        the monitor has no use for the difference and no field to express it in,
        while the ledger keeps it for a reader who does. What must not happen is
        the reverse -- inventing values for an old row -- and nothing here does.
        """
        calls = self._repository.ordered_operation_calls(incident_id)
        return tuple(
            CommittedCallFactV4(
                position=index,
                tool_name=call.tool_name if call.tool_name is not None else "<unnamed>",
                scope=call.operation_scope,
                status="committed",
                arguments=dict(call.arguments or {}),  # type: ignore[arg-type]
            )
            for index, call in enumerate(calls[:16])
        )

    def current_state(
        self, scenario_id: str, allowlisted_paths: tuple[str, ...]
    ) -> tuple[CurrentStateFact, ...]:
        state = self._repository.checkpoint_state(scenario_id)
        if len(allowlisted_paths) > 32 or len(set(allowlisted_paths)) != len(allowlisted_paths):
            raise ValueError("state paths must be a unique bounded allowlist")
        unknown = set(allowlisted_paths) - set(state)
        if unknown:
            raise ValueError("requested state path is unavailable")
        result: list[CurrentStateFact] = []
        for key in sorted(allowlisted_paths):
            value = state[key]
            if isinstance(value, (str, int, float, bool)) or value is None:
                result.append(CurrentStateFact(path=key, value=value))
        return tuple(result)
