"""Approval issuance for the D1 lab.

Approval tokens are database-backed mock capabilities.  They intentionally contain
only identifiers and bindings; they are not cryptographically portable secrets.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from triage_agent_lab.contracts import ApprovalRequest, ApprovalToken, Role

from .auth import Principal
from .errors import ApprovalDenied


class ApprovalStore(Protocol):
    def record_approval(self, token: ApprovalToken, incident_id: str) -> None: ...

    def append_audit_event(
        self,
        *,
        incident_id: str,
        thread_id: str,
        actor: str,
        transition: str,
        action_hash: str | None,
        reason: str | None,
        timestamp: datetime,
    ) -> None: ...


class ApprovalService:
    """Issues persisted approvals only for server-authenticated approvers."""

    def __init__(
        self,
        repository: ApprovalStore,
        clock: Callable[[], datetime],
        *,
        incident_id: str,
        thread_id: str = "approval",
    ) -> None:
        self.repository = repository
        self.clock = clock
        self.incident_id = incident_id
        self.thread_id = thread_id

    def approve(self, request: ApprovalRequest, principal: Principal) -> ApprovalToken:
        if principal.role is not Role.APPROVER:
            self._audit_denial(request, principal, "approver_role_required")
            raise ApprovalDenied("approver role is required to issue approval tokens")
        now = self.clock()
        if now < request.requested_at:
            self._audit_denial(request, principal, "request_not_active")
            raise ApprovalDenied("approval request is not active")
        if now >= request.expires_at:
            self._audit_denial(request, principal, "request_expired")
            raise ApprovalDenied("approval request is expired")
        token = ApprovalToken(
            approval_id=request.approval_id,
            action_hash=request.action_hash,
            actor=request.actor,
            expires_at=request.expires_at,
            one_time_use_id=request.one_time_use_id,
            requested_at=request.requested_at,
            approver=principal.actor,
            approved_at=now,
        )
        self.repository.record_approval(token, self.incident_id)
        self.repository.append_audit_event(
            incident_id=self.incident_id,
            thread_id=self.thread_id,
            actor=principal.actor,
            transition="approval_issued",
            action_hash=request.action_hash,
            reason="approved",
            timestamp=now,
        )
        return token

    def _audit_denial(self, request: ApprovalRequest, principal: Principal, reason: str) -> None:
        self.repository.append_audit_event(
            incident_id=self.incident_id,
            thread_id=self.thread_id,
            actor=principal.actor,
            transition="approval_denied",
            action_hash=request.action_hash,
            reason=reason,
            timestamp=self.clock(),
        )
