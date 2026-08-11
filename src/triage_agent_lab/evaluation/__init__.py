"""Replayable, mock-only Checkpoint-B evaluation support."""

from typing import Any

__all__ = [
    "CheckpointBEvaluationRunner",
    "ReliabilityEvaluationResultV2",
    "ReliabilityEvaluationRunnerV2",
    "ReliabilityRawEnvelopeV2",
    "compare_reliability_semantics",
    "run_checkpoint_b",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        if name.startswith("Reliability") or name == "compare_reliability_semantics":
            from .reliability_v2 import (
                ReliabilityEvaluationResultV2,
                ReliabilityEvaluationRunnerV2,
                ReliabilityRawEnvelopeV2,
                compare_reliability_semantics,
            )

            return {
                "ReliabilityEvaluationRunnerV2": ReliabilityEvaluationRunnerV2,
                "ReliabilityEvaluationResultV2": ReliabilityEvaluationResultV2,
                "ReliabilityRawEnvelopeV2": ReliabilityRawEnvelopeV2,
                "compare_reliability_semantics": compare_reliability_semantics,
            }[name]
        from .runner import CheckpointBEvaluationRunner, run_checkpoint_b

        return {
            "CheckpointBEvaluationRunner": CheckpointBEvaluationRunner,
            "run_checkpoint_b": run_checkpoint_b,
        }[name]
    raise AttributeError(name)
