"""Read-only durable fact projection for semantic monitors."""

from __future__ import annotations

from typing import Protocol

from incidentgate.control.monitor_input import CommittedCallFact, CurrentStateFact


class _Call(Protocol):
    tool_name: str | None
    operation_scope: str


class _Repository(Protocol):
    def ordered_operation_calls(self, incident_id: str) -> tuple[_Call, ...]: ...

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
