"""Real-process chaos harness for the durable incident runtime.

This package never runs as part of the product.  It builds the kill matrix:
every node boundary of every compiled scenario graph is crossed by a real OS
process that is then killed hard, and the durable end state is diffed against a
golden no-kill run of the same scenario.
"""

from .killpoints import BoundaryEvent, BoundaryRecorder, boundary_id

__all__ = ["BoundaryEvent", "BoundaryRecorder", "boundary_id"]
