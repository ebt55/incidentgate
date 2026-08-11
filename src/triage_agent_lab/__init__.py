"""Shared, implementation-independent contracts for Triage Agent Lab."""

from .contracts import CanonicalAction, canonical_action_hash

__all__ = ["CanonicalAction", "canonical_action_hash"]
