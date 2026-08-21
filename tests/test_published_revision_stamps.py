"""Every git revision a published artifact stamps must still be reachable from a ref.

WHY THIS EXISTS
===============

Three times now a published artifact has stamped a revision that no reference
reaches. ``src/incidentgate/scenario_registry.py`` records the first repair and
states the rule:

    A stamp that cannot be re-derived is not provenance, and the honest repair
    is a new run rather than an edited SHA.

The rule was right and it recurred anyway, twice, because it lived in a comment
and nothing asserted it. The T8 instance was found by reading; the chaos
kill-matrix instance was found by sweeping. Neither was found by a red test,
because there was no test. This module is the missing half of that repair -- the
regeneration is the smaller half.

WHY EXISTENCE IS NOT THE TEST, AND REACHABILITY IS
==================================================

``git cat-file -e de8958245b…`` **succeeded** in the clone where the defect
lived. The commit was a real object in the local store, orphaned when its branch
was deleted and surviving only because nothing had garbage-collected it. A guard
written on object existence would therefore have passed on the broken tree and
gone red only in a fresh clone -- certifying the defect as fine in exactly the
place someone would look, and failing in the place nobody runs tests.

So the question this asks is the one a reader actually has: *can I check this
revision out?* That is ancestry from a ref, and :func:`is_reachable` answers it
with ``git merge-base --is-ancestor`` against every branch, remote and tag tip. A
revision whose object is missing entirely fails the same call, so a fresh clone
gets the same verdict for the same reason.

WHAT THIS COVERS, AND WHAT IT DELIBERATELY DOES NOT
====================================================

**Covered:** revision stamps inside published artifacts under ``artifacts/``.
Those are provenance -- a claim that these bytes were produced at that revision
-- and a claim that cannot be checked is not one.

**Not covered, on purpose: prose anywhere else, including ``docs/``.**
``docs/verification.md`` deliberately records unreachable revisions *as
historical fact*: ``b21be983…`` in the superseded T8 entry, the checkpoint-B
commits ``3c19e74``, ``57daaa0`` and ``0321265`` -- all three unreachable, on a
branch that no longer exists -- and ``de8958245b…`` itself, in the entry
explaining this repair. A guard that scanned prose would go red on *correct*
documentation, and a guard that is red for being right gets silenced or deleted
within a week.

The named consequence, so nobody has to infer it: **a green run here does not
mean every revision named anywhere in this repository is reachable.** The
checkpoint-B trio is a live, known, uncovered instance of the same class. It is
recorded in ``docs/verification.md`` (2026-08-20) and is prose rather than a
stamp, which is why it is out of scope rather than merely unfixed.

WHY THE NON-VACUITY TEST IS NOT DECORATION
===========================================

The scan keys on the four shapes the two renderers emit today. Rename a stamp
key and the scan quietly matches nothing, and a guard that finds nothing passes.
:func:`test_the_scan_finds_the_stamps_that_are_actually_there` fails on an empty
result for that reason -- the same shape as
``test_every_runnable_sabotage_scenario_declares_a_covert_store_query`` in
``tests/chaos/test_kill_matrix.py``, which asserts its own population is
non-empty before asserting anything about it.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"

#: A git revision as it is stamped: full 40-hex, never abbreviated.
#:
#: Anchoring on the full length is what keeps ``"revision": "v1"`` -- a payload
#: field inside scenario evidence, not provenance -- out of the scan. There is
#: exactly one such field under ``artifacts/`` today and it must stay unmatched.
_SHA = "[0-9a-f]{40}"

#: The four renderings a stamp reaches disk in. Two JSON keys and two prose
#: labels, from two independent writers, which is why this is a tuple of
#: patterns rather than one clever regex:
#:
#: * ``"revision"``      -- ``chaos/matrix.py``'s ``git_revision()`` payload
#: * ``"git_revision"``  -- every ``evaluation/`` envelope and provider capture
#: * ``- git revision: `…` `` -- ``chaos/matrix.py`` markdown
#: * ``Git revision: `…` ``   -- ``evaluation/artifacts.py`` markdown
#: * ``git_revision=…``       -- ``evaluation/artifacts.py`` CSV header comment
STAMP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(rf'"(?:git_)?revision"\s*:\s*"({_SHA})"'),
    re.compile(rf"[Gg]it revision: `({_SHA})`"),
    re.compile(rf"git_revision=({_SHA})\b"),
)

#: Read as text, so a stamp cannot hide in a format nothing here parses.
TEXT_SUFFIXES = frozenset({".json", ".md", ".csv", ".txt"})


@dataclass(frozen=True)
class Stamp:
    """One revision claim, and the file making it."""

    path: str
    revision: str


def stamped_revisions(text: str, path: str) -> tuple[Stamp, ...]:
    """Every revision stamp in one file's text, de-duplicated, in sorted order."""
    found = {
        Stamp(path=path, revision=match)
        for pattern in STAMP_PATTERNS
        for match in pattern.findall(text)
    }
    return tuple(sorted(found, key=lambda stamp: (stamp.path, stamp.revision)))


def scan(root: Path) -> tuple[Stamp, ...]:
    """Walk the artifact tree for stamps, rather than listing the known families.

    Derived rather than enumerated so a new artifact family inherits this guard
    at birth instead of when someone remembers to add it here.
    """
    stamps: list[Stamp] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):  # pragma: no cover -- committed text is readable
            continue
        stamps.extend(stamped_revisions(text, path.relative_to(ROOT).as_posix()))
    return tuple(stamps)


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    # Fixed argv, no shell, repository-local, and never checked: every caller
    # reads the return code itself, because a non-zero exit is an answer here
    # rather than an error.
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def ref_tips() -> tuple[str, ...]:
    """Every branch, remote-tracking and tag tip, as object names."""
    completed = _git(
        "for-each-ref", "--format=%(objectname)", "refs/heads", "refs/remotes", "refs/tags"
    )
    if completed.returncode != 0:
        return ()
    return tuple(dict.fromkeys(line.strip() for line in completed.stdout.splitlines() if line))


def is_reachable(revision: str, tips: Sequence[str]) -> bool:
    """Whether ``revision`` is an ancestor of any ref tip -- i.e. can be checked out.

    ``merge-base --is-ancestor`` exits non-zero both for a commit that exists and
    is orphaned and for one that is not in the object store at all. Both answers
    are the same answer to the question a reader is asking, which is why this
    does not distinguish them.
    """
    return any(_git("merge-base", "--is-ancestor", revision, tip).returncode == 0 for tip in tips)


def undecidable_reason() -> str | None:
    """Why reachability cannot be decided here, or ``None`` when it can.

    THE ONLY LEGITIMATE REASONS TO SKIP, AND A MISSING REVISION IS NOT ONE.

    Each of these is a fact about the environment rather than about the
    artifacts: without git, without a repository, or with a shallow clone whose
    history is truncated by design, the question has no answer. A revision that
    cannot be found is a different thing entirely -- that is the failure this
    module exists to report, and it must never reach this function.
    """
    try:
        inside = _git("rev-parse", "--is-inside-work-tree")
    except (OSError, subprocess.SubprocessError):
        return "git is not available"
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return "not a git repository"
    shallow = _git("rev-parse", "--is-shallow-repository")
    if shallow.returncode == 0 and shallow.stdout.strip() == "true":
        return "a shallow clone's history is truncated, so ancestry is not decidable"
    if not ref_tips():
        # A repository with no branch, tag or remote at all. Pathological rather
        # than expected, and genuinely undecidable: there is nothing to be
        # reachable *from*. Distinct from "this revision is not reachable".
        return "this repository has no refs to measure reachability against"
    return None


def test_the_scan_finds_the_stamps_that_are_actually_there() -> None:
    """Non-vacuity. An empty scan is a broken scan, not a clean bill of health.

    Rename ``git_revision`` in a renderer and every other test in this module
    would pass over an empty set. This is what turns that into a red test.
    """
    stamps = scan(ARTIFACTS)
    shapes = [pattern.pattern for pattern in STAMP_PATTERNS]
    assert stamps, (
        "no revision stamps found under artifacts/ -- either the tree is empty or a renderer "
        f"changed shape and STAMP_PATTERNS no longer matches it: {shapes}"
    )
    assert len({stamp.revision for stamp in stamps}) > 1, (
        "expected several distinct stamped revisions across the artifact families"
    )
    # The family this guard was written for, named so that "the scan silently
    # stopped covering the chaos matrix" is a failure rather than a quiet pass.
    covered = {stamp.path for stamp in stamps}
    for required in (
        "artifacts/chaos-matrix/kill-matrix.json",
        "artifacts/chaos-matrix/kill-matrix.md",
    ):
        assert required in covered, f"{required} stamps a revision and must be in the scan"


def test_every_stamped_revision_is_reachable_from_a_ref() -> None:
    """The guard proper: every provenance claim under artifacts/ can be checked out.

    Reported as one list rather than one failure at a time, because the two known
    historical instances of this defect each spanned a whole artifact family and
    a per-file failure would have shown one of them.
    """
    reason = undecidable_reason()
    if reason is not None:
        pytest.skip(f"reachability is undecidable here: {reason}")
    stamps = scan(ARTIFACTS)
    assert stamps, "the scan must be non-vacuous before its result means anything"
    tips = ref_tips()
    unreachable = sorted(
        {(stamp.revision, stamp.path) for stamp in stamps if not is_reachable(stamp.revision, tips)}
    )
    assert not unreachable, (
        "a published artifact stamps a revision that is reachable from no branch, tag or "
        "remote, so its bytes cannot be re-derived at the revision it claims. The repair is a "
        "fresh run on a clean, reachable tree -- never an edited SHA:\n"
        + "\n".join(f"  {revision}  {path}" for revision, path in unreachable)
    )


def test_the_scan_matches_every_shape_it_claims_and_nothing_else() -> None:
    """Parse-level control: each renderer's shape is found, and a payload field is not."""
    payload = "\n".join(
        (
            '{"revision": "' + "a" * 40 + '",',
            ' "git_revision": "' + "b" * 40 + '",',
            ' "revision": "v1",',
            ' "prompt_sha256": "' + "c" * 64 + '"}',
            "- git revision: `" + "d" * 40 + "`",
            "Git revision: `" + "e" * 40 + "`",
            "# raw_sha256=" + "f" * 64 + " git_revision=" + "1" * 40,
        )
    )
    found = {stamp.revision for stamp in stamped_revisions(payload, "synthetic")}
    assert found == {"a" * 40, "b" * 40, "d" * 40, "e" * 40, "1" * 40}
    # The two that must not match: a non-git "revision" payload field, and a
    # 64-hex content digest that is not a revision at all.
    assert "v1" not in found
    assert not any(len(revision) != 40 for revision in found)


def test_the_reachability_check_reports_an_unreachable_revision() -> None:
    """A negative control, because a checker that never fires certifies nothing.

    Three probes. ``HEAD`` must come back reachable, or the checker is answering
    ``False`` to everything and the guard above is vacuous. The all-zeros object
    is syntactically a revision and is in nobody's object store. And
    ``de8958245b…`` is the real thing: the revision the chaos kill-matrix stamped
    until it was regenerated -- present in some clones as an orphaned object,
    absent in a fresh one, reachable in neither.
    """
    reason = undecidable_reason()
    if reason is not None:
        pytest.skip(f"reachability is undecidable here: {reason}")
    tips = ref_tips()
    head = _git("rev-parse", "HEAD").stdout.strip()
    assert is_reachable(head, tips), "HEAD must be reachable, or this checker answers False always"
    assert not is_reachable("0" * 40, tips)
    assert not is_reachable("de8958245b00122e606c336baddac2940c6a8f1f", tips)
