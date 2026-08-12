class LabError(Exception):
    """Base error for explicit, safe D1 control-plane failures."""


class PermissionDenied(LabError):
    pass


class ApprovalDenied(LabError):
    """A capability call was refused at the approval boundary.

    ``reason`` names the refusal in the frozen vocabulary when the refusal is
    one an end-state checker must be able to see: a token that does not bind to
    the action it was presented for, or an idempotency key already bound to
    different operation semantics.  It stays ``None`` for the argument-scope and
    fixture-precondition refusals, which say nothing about an approval and are
    deliberately not recorded as approval refusals.

    The message text is unchanged and load-bearing -- ``evaluation/runner.py``
    matches on it -- so the reason travels beside the message, never inside it.
    """

    def __init__(self, message: str, *, reason: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason


class ApprovalConflict(LabError):
    """An approval identity has already been recorded."""


class UnsupportedOperation(LabError):
    pass


class ResponseLost(LabError):
    """Raised after a transaction commits to simulate lost response delivery."""
