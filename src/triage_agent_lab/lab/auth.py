"""Server-side mock identities; MCP metadata is never an identity source."""

from dataclasses import dataclass

from triage_agent_lab.contracts import Role, ToolCallContext

from .errors import PermissionDenied


@dataclass(frozen=True)
class Principal:
    actor: str
    role: Role


def require_context(context: ToolCallContext, principal: Principal, permission: str) -> None:
    if context.actor != principal.actor or context.permission != permission:
        raise PermissionDenied("context actor or permission does not match authenticated principal")
    if not context.incident_id or not context.thread_id or not context.correlation_id:
        raise PermissionDenied("incident, thread, and correlation context are required")


def require_read(context: ToolCallContext, principal: Principal) -> None:
    require_context(context, principal, "observability:read")
    if principal.role not in {Role.OBSERVER, Role.OPERATOR, Role.APPROVER}:
        raise PermissionDenied("principal cannot read evidence")


def require_operation(context: ToolCallContext, principal: Principal) -> None:
    require_context(context, principal, "operations:write")
    if principal.role is not Role.OPERATOR or context.idempotency_key is None:
        raise PermissionDenied("operator role and idempotency key are required")
