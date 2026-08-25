"""The README's test command must be the form that actually collects.

This README carried `uv run pytest` until 2026-08-25 while `docs/verification.md`
recorded suite after suite as green — so the command that produced those green
runs was never the command written down. That is this project's recurring defect
shape wearing different clothes: the record not matching what produced it.

**What a test can honestly cover, and what it cannot.**

It *cannot* establish that the historical green runs used the `-m` form. Nothing
in the repository records which shell invocation produced a past result, and no
assertion written now can reach backwards to find out. That half stays uncovered,
and the README says so.

What it *can* cover is everything that makes the documented command correct going
forward — the instruction itself, and the three structural facts the README cites
as the reason `-m` is load-bearing. If any of those three stopped being true (say
someone added a root `conftest.py`, or a `pythonpath` setting), the README's
explanation would silently become false while still reading persuasively. These
tests fail instead.
"""

from __future__ import annotations

import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"


def readme() -> str:
    return README.read_text(encoding="utf-8")


def test_the_readme_tells_the_reader_to_run_the_form_that_collects() -> None:
    """The instruction itself: `python -m pytest`, never the bare console script."""
    text = readme()
    assert "uv run python -m pytest" in text

    # The bare form may be *discussed* -- the README explains why it fails -- but
    # it must never appear as a command inside a fenced block a reader would copy.
    for block in re.findall(r"```(?:bash|sh|console)?\n(.*?)```", text, re.DOTALL):
        for line in block.splitlines():
            stripped = line.strip()
            assert not re.fullmatch(r"uv run pytest\b.*", stripped), (
                f"a copyable block tells the reader to run the broken form: {stripped!r}"
            )


def test_there_is_no_root_conftest_to_put_the_repository_on_the_path() -> None:
    """The first of the three reasons the README gives for `-m` being load-bearing."""
    assert not (ROOT / "conftest.py").exists(), (
        "a root conftest.py would put the repository root on sys.path, which would "
        "make the README's explanation of why `-m` is required false"
    )


def test_pytest_declares_no_pythonpath_that_would_supply_the_root() -> None:
    """The second reason. A `pythonpath` setting would also make `-m` unnecessary."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        config = tomllib.load(handle)
    options = config.get("tool", {}).get("pytest", {}).get("ini_options", {})
    assert not options.get("pythonpath"), (
        "pyproject now sets pythonpath, so the README's stated reason for `-m` is "
        "stale even though the command still works"
    )


def test_some_test_really_does_import_its_fixtures_as_a_tests_package() -> None:
    """The third reason, and the one that makes the other two bite.

    Without at least one `tests.<package>` import, the bare console script would
    collect fine and the README's warning would be describing a failure that no
    longer happens.
    """
    importers = [
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "tests").rglob("*.py")
        if re.search(
            r"^\s*(?:from|import)\s+tests\.", path.read_text(encoding="utf-8"), re.MULTILINE
        )
    ]
    assert importers, (
        "no test imports its fixtures as tests.<package> any more, so `uv run pytest` "
        "may now collect cleanly and the README's warning needs re-checking"
    )


def test_the_readme_still_discloses_the_half_that_cannot_be_covered() -> None:
    """The honest note must survive, because the gap it names is still real.

    Deleting it would leave a reader thinking the agreement between the documented
    command and the recorded suites is checked. It is not, and cannot be.
    """
    text = readme()
    assert "was never the command written down here" in text
    assert "cannot be asserted retroactively" in text
