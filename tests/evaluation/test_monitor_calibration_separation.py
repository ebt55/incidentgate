from __future__ import annotations

import ast
from pathlib import Path


def test_dataset_and_report_facing_modules_cannot_reach_calibration_writers() -> None:
    package_root = Path(__file__).parents[2] / "src" / "incidentgate"
    local_prefixes = ("incidentgate.evaluation", "incidentgate.integration")
    calibration_module = "incidentgate.evaluation.monitor_calibration"
    forbidden = {"write_thresholds", "build_threshold_artifact", "fit_thresholds"}

    def module_path(module: str) -> Path | None:
        relative = Path(*module.removeprefix("incidentgate.").split("."))
        candidate = package_root / f"{relative}.py"
        if candidate.is_file():
            return candidate
        package_init = package_root / relative / "__init__.py"
        return package_init if package_init.is_file() else None

    def reachable_from(start_module: str) -> set[str]:
        seen: set[str] = set()

        def visit(module: str) -> None:
            if module in seen:
                return
            path = module_path(module)
            if path is None:
                return
            seen.add(module)
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    imported_module = node.module or ""
                    imported_names = {alias.name for alias in node.names}
                    assert not imported_names & forbidden
                    assert imported_module != calibration_module
                    assert not imported_module.startswith(calibration_module + ".")
                    assert calibration_module not in {
                        f"{imported_module}.{name}" for name in imported_names
                    }
                    if imported_module.startswith(local_prefixes):
                        visit(imported_module)
                    for name in imported_names:
                        candidate = f"{imported_module}.{name}"
                        if candidate.startswith(local_prefixes):
                            visit(candidate)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imported_module = alias.name
                        assert imported_module != calibration_module
                        assert not imported_module.startswith(calibration_module + ".")
                        if imported_module.startswith(local_prefixes):
                            visit(imported_module)

        visit(start_module)
        return seen

    dataset_reachable = reachable_from("incidentgate.evaluation.monitor_dataset")
    thresholds_reachable = reachable_from("incidentgate.evaluation.monitor_thresholds")
    semantic_reachable = reachable_from("incidentgate.integration.semantic_monitor")
    assert calibration_module not in dataset_reachable
    assert calibration_module not in thresholds_reachable
    assert calibration_module not in semantic_reachable
    calibration = ast.parse(
        (package_root / "evaluation" / "monitor_calibration.py").read_text(encoding="utf-8")
    )
    defined = {node.name for node in calibration.body if isinstance(node, ast.FunctionDef)}
    assert forbidden <= defined
