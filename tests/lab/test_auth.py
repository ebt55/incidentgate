from uuid import uuid4

import pytest

from incidentgate.contracts import Role, ToolCallContext
from incidentgate.lab.auth import Principal, require_operation, require_read
from incidentgate.lab.errors import PermissionDenied


def context(permission: str, include_key: bool = False) -> ToolCallContext:
    return ToolCallContext(
        incident_id="INC-D1",
        thread_id="thread-d1",
        correlation_id="corr-d1",
        actor="operator-1",
        permission=permission,
        idempotency_key=uuid4() if include_key else None,
    )


def test_read_requires_server_authenticated_actor_and_permission() -> None:
    operator = Principal("operator-1", Role.OPERATOR)
    require_read(context("observability:read"), operator)
    with pytest.raises(PermissionDenied):
        require_read(context("observability:read"), Principal("observer-1", Role.OBSERVER))


def test_operation_requires_operator_role_and_idempotency_key() -> None:
    require_operation(
        context("operations:write", include_key=True), Principal("operator-1", Role.OPERATOR)
    )
    with pytest.raises(PermissionDenied):
        require_operation(context("operations:write"), Principal("operator-1", Role.OPERATOR))
    with pytest.raises(PermissionDenied):
        require_operation(
            context("operations:write", include_key=True), Principal("operator-1", Role.APPROVER)
        )
