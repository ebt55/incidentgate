from incidentgate.contracts import ToolCallContext
from incidentgate.lab.auth import Principal
from incidentgate.lab.service import TicketsService


class TicketsAdapter:
    def __init__(self, service: TicketsService) -> None:
        self.service = service

    def read(self, context: ToolCallContext, principal: Principal) -> dict[str, object]:
        return self.service.read(context, principal)

    def append(self, context: ToolCallContext, principal: Principal, body: str) -> None:
        self.service.append_disabled(context, principal, body)
