"""Real-process chaos harness for the durable incident runtime.

This package never runs as part of the product.  It builds the kill matrix:
every node boundary of every compiled scenario graph is crossed by a real OS
process that is then killed hard, and the durable end state is diffed against a
golden no-kill run of the same scenario.
"""

from psycopg.conninfo import make_conninfo

from .killpoints import BoundaryEvent, BoundaryRecorder, boundary_id

# Every backend the harness opens is stamped with this, and the reaper terminates
# only backends carrying it. Without the stamp the reaper's only filters are
# "same database" and "idle a while", which also describes a developer's psql
# session, a pgAdmin window, and the compose containers' pools.
CHAOS_APPLICATION_NAME = "incidentgate-chaos"


def chaos_dsn(dsn: str) -> str:
    """Stamp a DSN so every connection opened from it is reapable by the harness.

    Tagging the DSN rather than each ``psycopg.connect`` call is what makes this
    reachable: the worker subprocess, its IncidentRuntime checkpointer, and every
    LabRepository connection all derive from one DSN string, so one stamp covers
    connections opened by code that knows nothing about chaos.
    """
    return make_conninfo(dsn, application_name=CHAOS_APPLICATION_NAME)


__all__ = [
    "CHAOS_APPLICATION_NAME",
    "BoundaryEvent",
    "BoundaryRecorder",
    "boundary_id",
    "chaos_dsn",
]
