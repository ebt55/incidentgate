from __future__ import annotations

import ast
from pathlib import Path


def test_capture_and_contract_loader_import_closures_cannot_reach_freeze_writer() -> None:
    package_root = Path(__file__).parents[2] / "src" / "incidentgate"
    start_modules = {
        "incidentgate.evaluation.capture_model_outputs",
        "incidentgate.evaluation.proposer_contracts",
    }
    forbidden_module = "incidentgate.evaluation.proposer_contract_freeze"
    forbidden_names = {"build_proposer_capture_contract", "write_proposer_capture_contract"}

    def module_path(module: str) -> Path | None:
        relative = Path(*module.removeprefix("incidentgate.").split("."))
        candidate = package_root / f"{relative}.py"
        return candidate if candidate.is_file() else None

    def visit(module: str, seen: set[str]) -> None:
        if module in seen:
            return
        path = module_path(module)
        if path is None:
            return
        seen.add(module)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported = node.module or ""
                assert imported != forbidden_module
                assert not imported.startswith(forbidden_module + ".")
                assert not ({alias.name for alias in node.names} & forbidden_names)
                if imported.startswith("incidentgate."):
                    visit(imported, seen)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != forbidden_module
                    assert not alias.name.startswith(forbidden_module + ".")
                    if alias.name.startswith("incidentgate."):
                        visit(alias.name, seen)

    for start in start_modules:
        seen: set[str] = set()
        visit(start, seen)
        assert forbidden_module not in seen
