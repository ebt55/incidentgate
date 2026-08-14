from __future__ import annotations

import ast
from pathlib import Path


def test_dataset_and_report_facing_modules_cannot_reach_calibration_writers() -> None:
    root = Path(__file__).parents[2] / "src" / "incidentgate" / "evaluation"
    forbidden = {"write_thresholds", "build_threshold_artifact", "fit_thresholds"}
    def reachable_from(start: Path) -> set[str]:
        seen: set[str] = set()

        def visit(path: Path) -> None:
            if path.stem in seen:
                return
            seen.add(path.stem)
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            names = {
                alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
                for alias in node.names
            }
            assert not names & forbidden
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    prefix = "incidentgate.evaluation."
                    if node.module.startswith(prefix):
                        visit(root / f"{node.module.removeprefix(prefix).split('.')[0]}.py")

        visit(start)
        return seen

    dataset_reachable = reachable_from(root / "monitor_dataset.py")
    thresholds_reachable = reachable_from(root / "monitor_thresholds.py")
    assert "monitor_calibration" not in dataset_reachable
    assert "monitor_calibration" not in thresholds_reachable
    calibration = ast.parse((root / "monitor_calibration.py").read_text(encoding="utf-8"))
    defined = {node.name for node in calibration.body if isinstance(node, ast.FunctionDef)}
    assert forbidden <= defined
