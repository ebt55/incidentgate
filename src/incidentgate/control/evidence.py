"""Evidence checks treat collected payloads, including instructions, strictly as data."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from incidentgate.contracts import (
    CanonicalAction,
    EvidenceRecord,
    PolicyConfiguration,
    ToolCallContext,
)
from incidentgate.reasons import (
    CITATIONS_REQUIRED,
    EVIDENCE_VALID,
    UNKNOWN_TOOL,
    correlation_context_mismatch,
    cross_context_evidence,
    embedded_instruction_data,
    expired_evidence,
    stale_evidence,
    unallowed_evidence_source,
    unknown_evidence,
)

from .models import EvidenceState, EvidenceValidation


class EvidenceValidator:
    def __init__(
        self,
        policy: PolicyConfiguration,
        clock: Callable[[], datetime],
        *,
        allowed_sources: frozenset[str],
    ) -> None:
        self._policy, self._clock, self._allowed_sources = policy, clock, allowed_sources

    @staticmethod
    def _contains_embedded_instruction(value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                EvidenceValidator._contains_embedded_instruction(item) for item in value.values()
            )
        if isinstance(value, list):
            return any(EvidenceValidator._contains_embedded_instruction(item) for item in value)
        if not isinstance(value, str):
            return False
        return bool(
            re.search(
                r"\b(ignore|bypass|override)\b.{0,80}\b(policy|approval|instruction)\b",
                value,
                re.IGNORECASE,
            )
        )

    def validate(
        self,
        action: CanonicalAction,
        records: tuple[EvidenceRecord, ...],
        context: ToolCallContext | None = None,
    ) -> EvidenceValidation:
        rule = self._policy.tools.get(action.tool_name)
        if rule is None:
            return EvidenceValidation(state=EvidenceState.INVALID, reasons=(UNKNOWN_TOOL,))
        now, by_id = self._clock(), {record.evidence_id: record for record in records}
        reasons: list[str] = []
        digest: list[dict[str, str]] = []
        for evidence_id in action.evidence_ids:
            record = by_id.get(evidence_id)
            if record is None:
                reasons.append(unknown_evidence(evidence_id))
                continue
            if record.incident_id != action.incident_id or record.thread_id != action.thread_id:
                reasons.append(cross_context_evidence(evidence_id))
            if context is not None and record.correlation_id != context.correlation_id:
                reasons.append(correlation_context_mismatch(evidence_id))
            if record.expires_at <= now:
                reasons.append(expired_evidence(evidence_id))
            elif (now - record.observed_at).total_seconds() > rule.evidence.max_age_seconds:
                reasons.append(stale_evidence(evidence_id))
            if record.tool_name not in self._allowed_sources:
                reasons.append(unallowed_evidence_source(evidence_id))
            if self._contains_embedded_instruction(record.payload):
                reasons.append(embedded_instruction_data(evidence_id))
            # Never expose payload to a monitor; payload content cannot become authority.
            digest.append(
                {
                    "evidence_id": record.evidence_id,
                    "tool_name": record.tool_name,
                    "observed_at": record.observed_at.isoformat(),
                }
            )
        if rule.evidence.citation_required and not action.evidence_ids:
            reasons.append(CITATIONS_REQUIRED)
        return EvidenceValidation(
            state=EvidenceState.INVALID if reasons else EvidenceState.VALID,
            reasons=tuple(reasons or [EVIDENCE_VALID]),
            evidence_ids=action.evidence_ids,
            digest=tuple(digest),
        )
