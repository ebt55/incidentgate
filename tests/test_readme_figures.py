"""The README's figures and diagrams have to be real, paired, and well formed.

The README now leads with generated SVGs and two Mermaid diagrams. Three ways
that goes quietly wrong, each pinned here:

A figure path can rot. GitHub renders a missing image as a broken icon and the
page still reads as if the evidence were there, so every relative image target
must resolve to a file that exists.

A `<picture>` can lose half of its pair. The dark variant is a second file, and
a rename that touches one and not the other leaves a block that renders in one
theme and breaks in the other. The two files must differ only by `-dark`.

A ```mermaid fence can be empty or headless. GitHub renders a fence whose first
line names no diagram type as an error box rather than a diagram, which again
leaves the README claiming a picture it does not have.
"""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

MERMAID_TYPES = ("flowchart", "graph", "sequenceDiagram")


def readme() -> str:
    return README.read_text(encoding="utf-8")


def image_targets(text: str) -> list[tuple[str, str]]:
    """Every image reference in the README, as (kind, target) pairs."""
    found: list[tuple[str, str]] = []
    for match in re.finditer(r"!\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", text):
        found.append(("markdown image", match.group(1)))
    for match in re.finditer(r"<img\b[^>]*\bsrc=\"([^\"]+)\"", text):
        found.append(("img src", match.group(1)))
    for match in re.finditer(r"<source\b[^>]*\bsrcset=\"([^\"]+)\"", text):
        found.append(("source srcset", match.group(1)))
    return found


def test_every_relative_image_path_in_the_readme_resolves_to_a_file() -> None:
    """Badges are remote and skipped. Everything local has to be on disk."""
    targets = image_targets(readme())
    assert targets, "the README references no images at all any more"

    missing = [
        f"{kind} -> {target}"
        for kind, target in targets
        if not target.startswith(("https://", "http://", "data:"))
        and not (ROOT / target).exists()
    ]
    assert not missing, "README image paths that do not exist: " + ", ".join(missing)


def test_every_picture_block_pairs_one_dark_source_with_one_light_image() -> None:
    """A `<picture>` is only useful if both halves of the pair are present."""
    blocks = re.findall(r"<picture>(.*?)</picture>", readme(), re.DOTALL)
    assert blocks, "the README has no <picture> blocks, so the figures lost their dark variants"

    for block in blocks:
        sources = re.findall(
            r"<source\b[^>]*\bmedia=\"\(prefers-color-scheme: dark\)\"[^>]*\bsrcset=\"([^\"]+)\"",
            block,
        )
        images = re.findall(r"<img\b[^>]*\bsrc=\"([^\"]+)\"", block)
        assert len(sources) == 1, (
            f"a <picture> block has {len(sources)} dark <source> elements, expected 1: {block!r}"
        )
        assert len(images) == 1, (
            f"a <picture> block has {len(images)} <img> elements, expected 1: {block!r}"
        )

        dark, light = sources[0], images[0]
        stem, dot, extension = light.rpartition(".")
        assert dot, f"the light image has no file extension: {light!r}"
        assert dark == f"{stem}-dark.{extension}", (
            f"the dark source {dark!r} is not the -dark sibling of the light image {light!r}"
        )


def test_every_mermaid_fence_is_non_empty_and_names_a_diagram_type() -> None:
    """An empty or headless fence renders as an error box, not a diagram."""
    fences = re.findall(r"```mermaid\n(.*?)```", readme(), re.DOTALL)
    assert fences, "the README has no mermaid diagrams any more"

    for fence in fences:
        lines = [line for line in fence.splitlines() if line.strip()]
        assert lines, "a ```mermaid fence is empty"
        first = lines[0].strip()
        assert first.startswith(MERMAID_TYPES), (
            f"a mermaid fence opens with {first!r}, which names no diagram type; "
            f"expected one of {MERMAID_TYPES}"
        )
