"""Regression coverage for purging reusable LangGraph checkpoint threads."""

from __future__ import annotations

import os
from typing import Any, TypedDict, cast

import psycopg
import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.graph import END, START, StateGraph
from psycopg.rows import dict_row

from incidentgate.evaluation.identity import purge_checkpoint_threads


class CounterState(TypedDict, total=False):
    count: int


def _checkpoint_counts(dsn: str, thread_id: str) -> dict[str, int]:
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as connection:
        return {
            table: int(
                cast(dict[str, Any], connection.execute(
                    f"SELECT count(*) AS total FROM {table} WHERE thread_id = %s",
                    (thread_id,),
                ).fetchone())["total"]
            )
            for table in ("checkpoints", "checkpoint_blobs", "checkpoint_writes")
        }


@pytest.mark.integration
def test_purge_checkpoint_threads_removes_target_graph_state_only() -> None:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("checkpoint purge regression requires DATABASE_URL")

    target_thread = "ac03-purge-target-root"
    sentinel_thread = "ac03-purge-sentinel-root"
    tables = ("checkpoints", "checkpoint_blobs", "checkpoint_writes")

    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as connection:
        saver = PostgresSaver(connection)
        saver.setup()
        for table in tables:
            connection.execute(
                f"DELETE FROM {table} WHERE thread_id IN (%s, %s)",
                (target_thread, sentinel_thread),
            )

        def increment(state: CounterState) -> CounterState:
            return {"count": state.get("count", 0) + 1}

        graph = StateGraph(CounterState)
        graph.add_node("increment", increment)
        graph.add_edge(START, "increment")
        graph.add_edge("increment", END)
        compiled = graph.compile(checkpointer=saver)

        def config(thread: str) -> RunnableConfig:
            return {"configurable": {"thread_id": thread}}

        assert cast(CounterState, compiled.invoke({}, config=config(target_thread))) == {
            "count": 1
        }
        assert cast(CounterState, compiled.invoke({}, config=config(sentinel_thread))) == {
            "count": 1
        }

    before_target = _checkpoint_counts(dsn, target_thread)
    before_sentinel = _checkpoint_counts(dsn, sentinel_thread)
    assert all(before_target[table] > 0 for table in tables)
    assert all(before_sentinel[table] > 0 for table in tables)

    purge_checkpoint_threads(dsn, (target_thread,))

    assert _checkpoint_counts(dsn, target_thread) == {table: 0 for table in tables}
    assert _checkpoint_counts(dsn, sentinel_thread) == before_sentinel

    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as connection:
        saver = PostgresSaver(connection)
        compiled = graph.compile(checkpointer=saver)
        fresh = cast(CounterState, compiled.invoke({}, config=config(target_thread)))
    assert fresh == {"count": 1}
    assert _checkpoint_counts(dsn, sentinel_thread) == before_sentinel
