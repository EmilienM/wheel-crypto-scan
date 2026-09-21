"""The repository's prose states the current design, and its cross-references resolve.

AGENTS.md's "Write down the current design, not its history" is a rule about prose, and
prose fails nothing when it breaks it. These tests hold the parts of it a machine can
check: no issue or PR citation and no review framing in code, tests, the ruleset or the
docs, and every `DESIGN.md` heading that something quotes or links to still exists.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "DESIGN.md"

# Every tracked text file a reader of the design reads: code, tests, the ruleset and
# schema, and the Markdown. This file is left out because it spells the patterns, and a
# symlink (`CLAUDE.md` is one to `AGENTS.md`) because its target is already read.
_SOURCES = sorted(
    path
    for pattern in (
        "src/**/*.py",
        "src/**/*.toml",
        "src/**/*.json",
        "tests/**/*.py",
        "docs/**/*.md",
        "*.md",
        "pyproject.toml",
        "mkdocs.yml",
    )
    for path in ROOT.glob(pattern)
    if not path.is_symlink()
    and path.resolve() != Path(__file__).resolve()
    and "__pycache__" not in path.parts
)

# A citation is `#` and digits standing alone: after whitespace, an opening bracket or
# a separator, and not followed by `/`. That leaves out the spellings that are data
# rather than citations -- BSD ar's `#1/<N>` name field, an ar duplicate-member suffix
# written in backticks or inside an f-string, `PKCS#11`, and a PE forwarder's
# `SOMEDLL.#123`. A number after the word "issue" or "PR" is a citation whether or not
# it carries the `#`.
_CITATION = re.compile(
    r"(?:^|[\s(\[,;])#[0-9]{1,4}\b(?!/)|\b(?:PR|[Ii]ssue)\s?#?[0-9]", re.MULTILINE
)
_TRACKER_LINK = re.compile(r"wheel-crypto-scan/(?:issues|pull)/[0-9]")
# "found by review" in quotes is the rule naming the phrase, not a use of it.
_REVIEW_FRAMING = re.compile(
    r"adversarial (?:review|probe|sweep)|independent review|\bBLOCKING [0-9]"
    r"|rounds? of review|(?<!\")found by review|DECISIONS\.md|docs/decisions/",
    re.IGNORECASE,
)


def _hits(pattern: re.Pattern[str]) -> list[str]:
    hits = []
    for path in _SOURCES:
        text = path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            hits.append(f"{path.relative_to(ROOT)}:{line}: {match.group(0).strip()}")
    return hits


def test_the_sources_are_found() -> None:
    """A glob that silently matched nothing would make every test below pass."""
    names = {path.relative_to(ROOT).as_posix() for path in _SOURCES}
    assert {"DESIGN.md", "AGENTS.md", "src/wheel_crypto_scan/linkage.py"} <= names
    assert "src/wheel_crypto_scan/data/ruleset.toml" in names
    assert any(name.startswith("docs/design/") for name in names)
    assert any(name.startswith("tests/") for name in names)


@pytest.mark.parametrize(
    "pattern",
    [_CITATION, _TRACKER_LINK, _REVIEW_FRAMING],
    ids=["issue-citation", "tracker-link", "review-framing"],
)
def test_no_history_in_the_prose(pattern: re.Pattern[str]) -> None:
    assert _hits(pattern) == []


@pytest.mark.parametrize(
    ("text", "cited"),
    [
        ("# Found in #57, see there.", True),
        ("(see #88)", True),
        ("[#4](https://example.invalid)", True),
        ("### #103: the message", True),
        ("see issue 57", True),
        ("(PR#58)", True),
        ("BSD's `#1/<N>` name field", False),
        ("a `#2`, `#3` suffix", False),
        ('f"pkg/lib.a({long_name}#2)"', False),
        ("PKCS#11 tokens", False),
        ("SOMEDLL.#123", False),
    ],
)
def test_the_citation_pattern_tells_a_citation_from_data(text: str, cited: bool) -> None:
    assert bool(_CITATION.search(text)) is cited


def _headings() -> set[str]:
    return {
        _normalise(match.group(1))
        for match in re.finditer(r"^#{2,6} (.+)$", DESIGN.read_text(encoding="utf-8"), re.M)
    }


def _normalise(title: str) -> str:
    return " ".join(title.split()).rstrip(".")


def _github_slug(title: str) -> str:
    return re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")


def _unwrapped(path: Path) -> str:
    """The file with its line breaks, and the comment marker that starts each wrapped
    comment line, folded into single spaces, so a quote wrapped across lines reads as
    one."""
    return re.sub(r"\s*\n\s*(?:#+ ?(?!#))?", " ", path.read_text(encoding="utf-8"))


def _quoted_titles() -> list[tuple[str, str]]:
    quoted = []
    for path in _SOURCES:
        text = _unwrapped(path)
        for match in re.finditer(r"DESIGN\.md`?(?:'s|,)\s+\"([^\"]+)\"", text):
            quoted.append((path.relative_to(ROOT).as_posix(), _normalise(match.group(1))))
    return quoted


def test_every_quoted_design_heading_exists() -> None:
    """Code and docs point into `DESIGN.md` by quoting a heading, not by a line number
    or an anchor; a heading renamed without its quotes leaves them pointing nowhere."""
    quoted = _quoted_titles()
    assert quoted, "no DESIGN.md heading quotes found; the pattern has gone stale"
    headings = _headings()
    assert [(path, title) for path, title in quoted if title not in headings] == []


def test_every_design_anchor_link_exists() -> None:
    """`docs/design/` links each summary to its full entry by GitHub's heading anchor,
    which `mkdocs build --strict` cannot check because the target is outside the site."""
    slugs = {_github_slug(title) for title in _headings()}
    links = [
        (path.relative_to(ROOT).as_posix(), match.group(1))
        for path in _SOURCES
        for match in re.finditer(
            r"blob/main/DESIGN\.md#([\w\-]+)", path.read_text(encoding="utf-8")
        )
    ]
    assert links, "no DESIGN.md anchor links found; the pattern has gone stale"
    assert [(path, slug) for path, slug in links if slug not in slugs] == []
