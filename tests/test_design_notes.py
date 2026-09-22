"""The repository's prose states the current design, and its cross-references resolve.

AGENTS.md's "Write down the current design, not its history" is a rule about prose, and
prose fails nothing when it breaks it. These tests hold the parts of it a machine can
check: no issue or PR citation and no review framing in code, tests, the ruleset or the
docs, every `DESIGN.md` heading that something quotes still exists, no
Markdown heading wraps onto a second source line, and the design index lists every
entry of every `docs/design-summaries/` page, in page order.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs" / "DESIGN.md"

# The modules allowed a module-local `too-many-lines` disable. DESIGN.md's
# "`binfmt/elf.py` and `binfmt/macho.py` carry module-local line-count exemptions"
# gives the reason for each; adding a module here means adding its reason there.
_LINE_LIMIT_EXEMPT = {
    "src/wheel_crypto_scan/binfmt/elf.py",
    "src/wheel_crypto_scan/binfmt/macho.py",
}
_LINE_LIMIT_DISABLE = re.compile(r"#\s*pylint:\s*disable\s*=[^\n]*\b(?:too-many-lines|C0302)\b")

# Every tracked text file a reader of the design reads: code, tests, the ruleset and
# schema, and the Markdown. This file is left out because it spells the patterns.
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
    if path.resolve() != Path(__file__).resolve() and "__pycache__" not in path.parts
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
_FENCE = re.compile(r"^\s*(?:```|~~~)")
_HEADING = re.compile(r"^#{1,6} ")


def _wrapped_headings(text: str) -> list[int]:
    """1-based line numbers of ATX headings, outside fenced code, whose next line is
    not blank: Markdown ends a heading at the newline, so a wrapped one renders cut
    short and its anchor is built from the truncated text."""
    lines = text.split("\n")
    hits = []
    fenced = False
    for number, line in enumerate(lines, start=1):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if fenced or not _HEADING.match(line):
            continue
        if number < len(lines) and lines[number].strip():
            hits.append(number)
    return hits


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
    assert {"docs/DESIGN.md", "AGENTS.md", "src/wheel_crypto_scan/linkage.py"} <= names
    assert "src/wheel_crypto_scan/data/ruleset.toml" in names
    assert any(name.startswith("docs/design-summaries/") for name in names)
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
    return " ".join(title.split())


def _unwrapped(path: Path) -> str:
    """The file with its line breaks, and the comment marker that starts each wrapped
    comment line, folded into single spaces, so a quote wrapped across lines reads as
    one."""
    return re.sub(r"\s*\n\s*(?:#+ ?(?!#))?", " ", path.read_text(encoding="utf-8"))


_QUOTE_PATTERNS = (
    # DESIGN.md, "..." / DESIGN.md's "..."
    re.compile(r"DESIGN\.md`?(?:'s|,)\s+\"([^\"]+)\""),
    # See "..." in DESIGN.md.
    re.compile(r"\"([^\"]+)\"\s+in\s+`?DESIGN\.md"),
)


def _quoted_titles() -> list[tuple[str, str]]:
    quoted = []
    for path in _SOURCES:
        text = _unwrapped(path)
        for pattern in _QUOTE_PATTERNS:
            for match in pattern.finditer(text):
                quoted.append((path.relative_to(ROOT).as_posix(), _normalise(match.group(1))))
    return quoted


def test_every_quoted_design_heading_exists() -> None:
    """Code and docs point into `DESIGN.md` by quoting a heading, not by a line number
    or an anchor; a heading renamed without its quotes leaves them pointing nowhere.
    The quote must match the heading verbatim apart from line wrapping, so a period
    inside the closing quote counts as a mismatch."""
    quoted = _quoted_titles()
    assert quoted, "no DESIGN.md heading quotes found; the pattern has gone stale"
    headings = _headings()
    assert [(path, title) for path, title in quoted if title not in headings] == []


def test_no_markdown_heading_wraps_onto_a_second_line() -> None:
    """A heading wrapped in the source renders cut short, and a quote of its full
    title or a link to its full anchor resolves to nothing."""
    markdown = [path for path in _SOURCES if path.suffix == ".md"]
    assert any(path.name == "DESIGN.md" for path in markdown)
    hits = [
        f"{path.relative_to(ROOT)}:{number}"
        for path in markdown
        for number in _wrapped_headings(path.read_text(encoding="utf-8"))
    ]
    assert hits == []


@pytest.mark.parametrize(
    ("text", "wrapped"),
    [
        ("## A heading\n\nbody", []),
        ("## A heading that\ncontinues here\n", [1]),
        ("text\n### Deep heading\n- a list item\n", [2]),
        ("## Last line", []),
        ("```bash\n# a shell comment\necho hi\n```\n", []),
        ("#1/<N> is not a heading\nnext", []),
        ("# Top\nnext", [1]),
        ("###### Six\nnext", [1]),
    ],
)
def test_the_heading_check_tells_a_wrapped_heading_from_a_fenced_comment(
    text: str, wrapped: list[int]
) -> None:
    assert _wrapped_headings(text) == wrapped


# A code span whose content opens a closing tag and never closes it: Python-Markdown's
# HTML tokenizer treats `</tag` as the start of real markup even inside a code span, and
# silently drops everything in the rendered page from that point to EOF. `docs/DESIGN.md`
# hit this with `` `</script` ``, a code span describing the literal bytes rather than
# real markup, and lost its last four entries with no build warning. `[^`>]*` stops at
# either delimiter: a `>` before the closing backtick closes the tag and clears the span.
_UNCLOSED_TAG_IN_CODE_SPAN = re.compile(r"`</[A-Za-z][^`>]*`")


def _unclosed_tags_in_code_spans(text: str) -> list[int]:
    """1-based line numbers of a code span that opens a closing tag it never closes,
    outside fenced code."""
    hits = []
    fenced = False
    for number, line in enumerate(text.split("\n"), start=1):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced and _UNCLOSED_TAG_IN_CODE_SPAN.search(line):
            hits.append(number)
    return hits


def test_no_code_span_opens_an_html_tag_it_never_closes() -> None:
    """Close the tag (`` `</script>` ``) or drop the code span for raw HTML with an
    entity (`<code>&lt;/script</code>`) instead -- either survives markdown-to-HTML
    conversion; a bare `` `</script` `` does not, and `mkdocs build --strict` does not
    catch it, since nothing about the loss breaks a link or an anchor."""
    markdown = [path for path in _SOURCES if path.suffix == ".md"]
    hits = [
        f"{path.relative_to(ROOT)}:{number}"
        for path in markdown
        for number in _unclosed_tags_in_code_spans(path.read_text(encoding="utf-8"))
    ]
    assert hits == []


@pytest.mark.parametrize(
    ("text", "hit"),
    [
        ("the literal bytes `</script`, never for character references", True),
        ("the literal bytes `</script>` closes cleanly", False),
        ("`<script>` opens a tag, not a closing one", False),
        ("no code span here at all", False),
        ("```text\nthe literal bytes `</script`\n```\n", False),
    ],
)
def test_the_unclosed_tag_check_tells_the_bug_from_a_closed_or_fenced_span(
    text: str, hit: bool
) -> None:
    assert bool(_unclosed_tags_in_code_spans(text)) is hit


DESIGN_PAGES = ROOT / "docs" / "design-summaries"


def _mkdocs_slug(title: str) -> str:
    """The anchor MkDocs' `toc` extension gives a heading: code-span backticks and other
    punctuation dropped, lowercased, and each run of spaces or hyphens made one `-`."""
    text = re.sub(r"[^\w\s-]", "", title).strip().lower()
    return re.sub(r"[-\s]+", "-", text)


def _page_entries() -> dict[str, list[str]]:
    """Each subsystem page's `## ` headings, as anchors, in page order. Fenced blocks are
    skipped, so a `## ` line inside an example is not taken for an entry."""
    entries = {}
    for page in sorted(DESIGN_PAGES.glob("*.md")):
        if page.name == "index.md":
            continue
        anchors, fenced = [], False
        for line in page.read_text(encoding="utf-8").splitlines():
            if line.startswith("```"):
                fenced = not fenced
            elif not fenced and line.startswith("## "):
                anchors.append(_mkdocs_slug(line[3:]))
        entries[page.name] = anchors
    return entries


def _index_entries() -> dict[str, list[str]]:
    """The design index's rows, by the page each section heading links to, in row order.
    A row linking into a page other than its section's is recorded under that page, so
    it shows up as a mismatch rather than being dropped."""
    entries: dict[str, list[str]] = {}
    for line in (DESIGN_PAGES / "index.md").read_text(encoding="utf-8").splitlines():
        section = re.match(r"^## \[[^\n]*\]\(([\w-]+\.md)\)$", line)
        if section:
            entries.setdefault(section.group(1), [])
            continue
        for page, anchor in re.findall(r"\]\(([\w-]+\.md)#([\w-]+)\)", line):
            entries.setdefault(page, []).append(anchor)
    return entries


_NUMBER_WORDS = {
    "One": 1,
    "Two": 2,
    "Three": 3,
    "Four": 4,
    "Five": 5,
    "Six": 6,
    "Seven": 7,
    "Eight": 8,
    "Nine": 9,
    "Ten": 10,
}
_STATED_ENTRY_COUNT = re.compile(r"^(" + "|".join(_NUMBER_WORDS) + r") entr(?:y|ies)\b")


def _stated_entry_count(text: str) -> int | None:
    """A page's opening line sometimes states its entry count as a number word, e.g.
    "Three entries about `binfmt/elf.py`." A page that phrases it without a leading
    number word (`policy.md`, `tooling.md`) or as a subset ("The first two entries
    below") is left alone; this only catches a stated total a heading count can
    contradict outright."""
    lines = text.split("\n", 3)
    if len(lines) < 3 or not lines[0].startswith("# "):
        return None
    match = _STATED_ENTRY_COUNT.match(lines[2])
    return _NUMBER_WORDS[match.group(1)] if match else None


def test_the_stated_entry_count_matches_the_page_headings() -> None:
    """A page's opening line says how many `## ` entries follow; a heading added,
    removed or merged without updating that sentence leaves a reader trusting a count
    that no longer matches what is on the page."""
    pages = _page_entries()
    mismatches = [
        f"{page.name}: stated {stated}, has {len(pages[page.name])}"
        for page in sorted(DESIGN_PAGES.glob("*.md"))
        if page.name != "index.md"
        for stated in [_stated_entry_count(page.read_text(encoding="utf-8"))]
        if stated is not None and stated != len(pages[page.name])
    ]
    assert mismatches == []


@pytest.mark.parametrize(
    ("text", "count"),
    [
        ("# ELF\n\nThree entries about `binfmt/elf.py`. More text.\n", 3),
        ("# PE\n\nOne entry about `binfmt/pe.py` here.\n", 1),
        ("# Policy\n\nEntries about the shape of the data.\n", None),
        ("# Linkage\n\nThe first two entries below are about X.\n", None),
        ("# Title\n\nToo few lines", None),
    ],
)
def test_the_stated_entry_count_reader_only_matches_a_leading_number_word(
    text: str, count: int | None
) -> None:
    assert _stated_entry_count(text) == count


def test_the_design_index_lists_every_entry_in_page_order() -> None:
    """`docs/design-summaries/index.md` is the table of contents for the design pages. An entry
    added to a page without a row is invisible to anyone reading the index, and nothing
    else fails: `mkdocs build --strict` checks that an anchor exists, not that every
    heading has a link."""
    pages = _page_entries()
    assert pages and all(pages.values()), "no design page headings found"
    assert _index_entries() == pages


def _index_row_sections() -> list[tuple[str, str | None]]:
    """Each index row's (linked page, enclosing section's page), in row order. A row can
    link to the right page while sitting under the wrong section heading; the page-keyed
    dict in `_index_entries` groups by link target and cannot see that."""
    pairs: list[tuple[str, str | None]] = []
    section: str | None = None
    for line in (DESIGN_PAGES / "index.md").read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^## \[[^\n]*\]\(([\w-]+\.md)\)$", line)
        if heading:
            section = heading.group(1)
            continue
        for page, _anchor in re.findall(r"\]\(([\w-]+\.md)#([\w-]+)\)", line):
            pairs.append((page, section))
    return pairs


def test_every_design_index_row_sits_under_its_own_section() -> None:
    """A row misfiled under the wrong section heading still links to the page its entry
    belongs to, so `test_the_design_index_lists_every_entry_in_page_order`'s page-keyed
    comparison cannot catch it; this pins each row to the section it is listed under."""
    pairs = _index_row_sections()
    assert pairs, "no design index rows found; the pattern has gone stale"
    assert [(page, section) for page, section in pairs if page != section] == []


def test_the_line_limit_exemption_list_names_real_files() -> None:
    """A stale path in `_LINE_LIMIT_EXEMPT` would make the test below fail on a path
    that no longer exists, or pass vacuously if the glob it compares against also
    missed it."""
    assert _LINE_LIMIT_EXEMPT
    assert all((ROOT / path).is_file() for path in _LINE_LIMIT_EXEMPT)


def test_only_the_listed_modules_exempt_themselves_from_the_line_limit() -> None:
    """A new module taking the disable without the doc changing, or a listed module
    dropping it while the doc still claims it, both show up here."""
    exempted = {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.glob("src/**/*.py")
        if _LINE_LIMIT_DISABLE.search(path.read_text(encoding="utf-8"))
    }
    assert exempted == _LINE_LIMIT_EXEMPT


def _disabled_codes(pylint_tables: list[dict]) -> set[str]:
    """pylint accepts `disable` as either a TOML list or a single comma-separated
    string; either encoding names the same codes and must read the same way here."""
    disabled: set[str] = set()
    for table in pylint_tables:
        raw = table.get("disable", [])
        codes = raw.split(",") if isinstance(raw, str) else raw
        disabled |= {code.strip() for code in codes}
    return disabled


def test_the_project_wide_line_limit_stays_at_the_default() -> None:
    """Guards against both shapes of the global bump the design entry rejects: raising
    `max-module-lines` in any `[tool.pylint.*]` table, not just `[tool.pylint.format]`,
    and turning the check off everywhere by disabling `too-many-lines`/`C0302` in
    `messages control` (or any other pylint table's `disable` list)."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pylint_tables = [table for table in data["tool"]["pylint"].values() if isinstance(table, dict)]
    assert not any("max-module-lines" in table for table in pylint_tables)
    assert not _disabled_codes(pylint_tables) & {"too-many-lines", "C0302"}


@pytest.mark.parametrize(
    ("toml_text", "flagged"),
    [
        ('disable = ["too-many-lines"]', True),
        ('disable = "too-many-lines"', True),
        ('disable = "unused-import, too-many-lines"', True),
        ('disable = ["C0302"]', True),
        ('disable = "C0302"', True),
        ('disable = ["unused-import"]', False),
        ('disable = "unused-import"', False),
    ],
    ids=[
        "list-form",
        "string-form",
        "string-form-with-other-codes",
        "list-form-numeric-code",
        "string-form-numeric-code",
        "list-form-unrelated",
        "string-form-unrelated",
    ],
)
def test_the_disable_normaliser_catches_both_toml_forms(toml_text: str, flagged: bool) -> None:
    """A comma-separated string is as valid a pylint config as a TOML list; the guard
    above must not walk a string one character at a time and miss it."""
    table = tomllib.loads(f"[table]\n{toml_text}\n")["table"]
    assert bool(_disabled_codes([table]) & {"too-many-lines", "C0302"}) is flagged


def test_every_exempt_module_is_named_in_the_design_entry() -> None:
    """The list in the doc and the set in the test must not fall out of step in either
    direction: a module in `_LINE_LIMIT_EXEMPT` missing from the doc's bullet list, or a
    bullet naming a module that isn't exempt, both fail here."""
    text = DESIGN.read_text(encoding="utf-8")
    heading = "## `binfmt/elf.py` and `binfmt/macho.py` carry module-local line-count exemptions"
    start = text.index(heading)
    end = re.search(r"\n#{2,3} ", text[start + len(heading) :])
    entry = text[start : start + len(heading) + (end.start() if end else len(text))]
    named = {match.group(1) for match in re.finditer(r"^- `([^`]+)`", entry, re.MULTILINE)}
    exempt = {path.removeprefix("src/wheel_crypto_scan/") for path in _LINE_LIMIT_EXEMPT}
    assert named == exempt
