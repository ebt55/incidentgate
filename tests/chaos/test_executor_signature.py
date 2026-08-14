"""The executor signature is a chaos instrument, not just an interface.

``chaos/killpoints.py`` installs the ``operation:committed`` boundary by
monkey-patching :meth:`LabOperationExecutor.execute` with a replacement declared
as ``def instrumented(self, action, context, token, **kwargs)``. The patch binds
by *shape*: it forwards the first three arguments positionally and everything
else through ``**kwargs``.

That makes the signature load-bearing in a way no type checker sees. Reorder the
three positionals and the patch still installs, still runs, and still returns --
it just passes the wrong values, or raises inside a subprocess whose failure the
matrix records as ``ERR``. Rename one to keyword-only and every caller that
passes it positionally breaks at once, which is the *good* failure. The bad one
is silent: if the boundary stops firing, the affected chaos cells go from
"process killed after the operation committed" to "nothing was killed", and a
published table would report a kill that never happened.

The boundary set itself is derived from the compiled graphs and needs no pin
(``tests/chaos/test_kill_matrix.py`` asserts that). This is the one boundary
whose identity rests on a Python signature instead.
"""

from __future__ import annotations

import ast
import inspect
from inspect import Parameter, signature
from pathlib import Path

from incidentgate.chaos import killpoints
from incidentgate.integration.adapters import LabOperationExecutor

#: Exactly what ``killpoints._install_operation_boundary`` forwards positionally.
POSITIONAL = ("self", "action", "context", "token")


def test_the_executor_keeps_the_positional_shape_the_kill_hook_binds_to() -> None:
    parameters = list(signature(LabOperationExecutor.execute).parameters.values())
    leading = parameters[: len(POSITIONAL)]
    assert tuple(parameter.name for parameter in leading) == POSITIONAL
    assert all(parameter.kind is Parameter.POSITIONAL_OR_KEYWORD for parameter in leading)
    assert all(parameter.default is Parameter.empty for parameter in leading)


def test_everything_after_the_first_three_is_reachable_through_kwargs() -> None:
    """The hook forwards the rest as ``**kwargs``, so nothing may be positional-only."""
    parameters = list(signature(LabOperationExecutor.execute).parameters.values())
    for parameter in parameters[len(POSITIONAL) :]:
        assert parameter.kind in {Parameter.KEYWORD_ONLY, Parameter.VAR_KEYWORD}


def test_the_replacement_the_hook_installs_declares_the_same_shape() -> None:
    """Read the replacement's own parameters instead of restating them here.

    The replacement is a closure and is never importable, so its declared shape
    is read out of ``killpoints``' source. Comparing the two is what makes this
    fail on a change to *either* side: an executor whose positionals moved, or
    a hook that stopped forwarding them.
    """
    replacement = _replacement_parameters()
    declared = tuple(signature(LabOperationExecutor.execute).parameters)
    assert replacement[: len(POSITIONAL)] == declared[: len(POSITIONAL)]
    assert replacement[-1] == "kwargs"


def _replacement_parameters() -> tuple[str, ...]:
    tree = ast.parse(Path(inspect.getsourcefile(killpoints) or "").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "instrumented":
            arguments = node.args
            if arguments.kwarg is None:
                continue
            return tuple(
                [argument.arg for argument in arguments.args] + [arguments.kwarg.arg]
            )
    raise AssertionError("the operation-boundary hook no longer declares a replacement")
