class LabError(Exception):
    """Base error for explicit, safe D1 control-plane failures."""


class PermissionDenied(LabError):
    pass


class ApprovalDenied(LabError):
    pass


class ApprovalConflict(LabError):
    """An approval identity has already been recorded."""


class UnsupportedOperation(LabError):
    pass


class ResponseLost(LabError):
    """Raised after a transaction commits to simulate lost response delivery."""
