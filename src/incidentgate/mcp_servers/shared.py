from incidentgate.contracts import ToolCallContext
from incidentgate.lab.auth import Principal


def context_from_payload(payload: dict[str, object]) -> ToolCallContext:
    """Parse only explicit request data; do not inspect MCP `_meta` for identity."""
    return ToolCallContext.model_validate(payload)


LOCALHOST_HOST = "127.0.0.1"


def principal_from_authenticated_actor(actor: str, role: str) -> Principal:
    from incidentgate.contracts import Role

    return Principal(actor=actor, role=Role(role))
