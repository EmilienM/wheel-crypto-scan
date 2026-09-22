"""Human-readable views of the records: the Markdown table and the self-contained HTML page."""

from __future__ import annotations

import dataclasses
import html
import inspect
import json
import re
import shutil
import socket
import subprocess
from importlib.resources import files
from pathlib import Path

import pytest
from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan import report
from wheel_crypto_scan.report import (
    CLASS_HELP,
    FAMILY_HELP,
    LINKAGE_HELP,
    RELATION_HELP,
    render_html,
    render_markdown,
)
from wheel_crypto_scan.ruleset import FAMILIES, LINKAGE_VALUES, RELATIONS
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.scan import ScanContext, scan_wheel

_DATA_SCRIPT = re.compile(
    r'<script type="application/json" id="wcs-data">(.*?)</script>', re.DOTALL
)

_CHROME_CANDIDATES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")


def _chrome_binary() -> str | None:
    for name in _CHROME_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def _render_in_browser(
    tmp_path: Path,
    page: str,
    *,
    fragment: str = "",
    extra_script: str = "",
    window_size: str = "",
    virtual_time_budget: int = 0,
) -> str:
    """Render `page` in headless Chrome (or Chromium) and return the DOM it
    produces after load.

    Self-skips when no such browser is on the host, the same shape
    `test_hostbin_libcrypto_soname_and_evp_digestinit_ex_defined` skips without a
    system `libcrypto.so.3`: an opt-in check of real behaviour that degrades to
    "not run" rather than "failed" when the host cannot support it, and needs no
    network and no new Python dependency. `extra_script` is test-authored
    JavaScript, appended after the page's own script; both are synchronous, so
    both have run before Chrome's load event fires and `--dump-dom` reads the
    page back. `fragment` becomes the URL's `#...` before the page loads, so the
    page's own hash-routing sees it the same way it would a link to one wheel.
    `window_size` is Chrome's `WIDTH,HEIGHT`, for a test that measures layout;
    left empty, the page lays out in Chrome's default headless window.

    `virtual_time_budget` is milliseconds of Chrome's simulated time to run
    before `--dump-dom` reads the page back; left at 0 (the default), no
    `--virtual-time-budget` flag is passed and Chrome dumps as soon as the load
    event fires, which is enough for every test whose `extra_script` runs
    synchronously. A native `<dialog>`'s "close" event fires as a queued task
    rather than inline with the call that closes it (confirmed against a real
    browser, not only reasoned from the spec), so a test whose `extra_script`
    depends on that event having already run -- the intro dialog's storage
    write on close, or a chain of reopen/close cycles driven by it -- passes an
    explicit budget instead."""
    binary = _chrome_binary()
    if binary is None:
        pytest.skip("no headless-capable browser (google-chrome/chromium) on this host")
    if extra_script:
        page = page.replace("</body>", f"<script>{extra_script}</script></body>")
    path = tmp_path / "page.html"
    path.write_text(page, encoding="utf-8")
    url = f"file://{path}#{fragment}" if fragment else f"file://{path}"
    size = [f"--window-size={window_size}"] if window_size else []
    budget = [f"--virtual-time-budget={virtual_time_budget}"] if virtual_time_budget else []
    result = subprocess.run(
        [
            binary,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            *size,
            *budget,
            "--dump-dom",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return result.stdout


_TAB_ORDER = ("findings", "binaries", "wheel", "errors", "raw")


def _click_tab(tab: str) -> str:
    """JS that clicks the detail view's tab button for `tab`, test-authored code
    to append after the page's own script through `extra_script`.

    Scoped to `#tabs`, the detail panel's own tablist, rather than a bare
    `.tabs button`: the page reuses the `.tabs` styling for the top-level
    Wheels/Rules switch and the Help dialog's Intro/Reference switch too, and a
    document-wide query would count buttons across all three."""
    index = _TAB_ORDER.index(tab)
    return f'document.querySelectorAll("#tabs button")[{index}].click();'


def _tab(dom: str, tab: str) -> str:
    """The rendered content of one detail-view tab panel, by its `id="tab-<tab>"`.

    Sliced between the start of this tab panel's own `<div id="tab-...">` and the
    start of the next one's (or `#popover`, after the last tab), rather than by
    matching a closing `</div>`: a tab's own content nests further `<div>`s (the
    Binaries tab's per-object boxes), so a "first closing tag" match would cut the
    slice short.
    """
    index = _TAB_ORDER.index(tab)
    start = dom.index(f'<div id="tab-{tab}"')
    if index + 1 < len(_TAB_ORDER):
        end_marker = f'<div id="tab-{_TAB_ORDER[index + 1]}"'
    else:
        end_marker = '<div id="popover"'
    end = dom.index(end_marker, start)
    return dom[start:end]


# A plausible `relation` for a synthetic record's class, mirroring `RELATION_CLASSES`
# in `ruleset.py`: `OPAQUE` and `NO_CRYPTO_DETECTED` never carry one, every other
# class here maps to one relation consistent with it.
_RELATION_FOR_CLASS = {
    "NON_APPROVED_CRYPTO": "outside_module",
    "FIPS_BREAKING": "runtime_refusal",
    "CONDITIONAL": "boundary_unresolved",
    "CONTEXT_DEPENDENT": "use_unresolved",
}


def record(name: str, klass: str, linkage: str, review: bool = True) -> dict:
    libraries = [] if linkage == "none" else [{"name": "openssl", "linkage": linkage}]
    relation = _RELATION_FOR_CLASS.get(klass)
    return {
        "wheel": {"filename": f"{name}-1.0-py3-none-any.whl", "name": name, "version": "1.0"},
        "verdict": {
            "class": klass,
            "classes": [klass],
            "conditions": {"openssl_linkage": linkage},
            "relations": [relation] if relation else [],
            "needs_human_review": review,
            "reasons": [f"RULE_{klass}: {name}"],
            "rule_ids": [f"RULE_{klass}"],
        },
        # `families` stays empty here: it is derived from `findings[].family`, and
        # this bare fixture carries no findings. `html_record` below recomputes it
        # once it adds one.
        "crypto": {"families": [], "libraries": libraries},
        "findings": [],
    }


def html_record(
    name: str,
    klass: str,
    linkage: str,
    *,
    review: bool = True,
    rule_id: str = "BIN_BUNDLED_OPENSSL",
    evidence_level: str = "standard",
) -> dict:
    """A record carrying every top-level key `render_html` reads, for the tests that
    exercise more than the columns `render_markdown` also draws on."""
    base = record(name, klass, linkage, review)
    base["verdict"]["rule_ids"] = [rule_id]
    base["verdict"]["reasons"] = [f"{rule_id}: {name}"]
    base["schema_version"] = 1
    base["tool"] = {
        "name": "wheel-crypto-scan",
        "version": "1.2.3",
        "ruleset_version": "1",
        "analyzer_version": 1,
        "evidence_level": evidence_level,
    }
    relation = _RELATION_FOR_CLASS.get(klass)
    base["findings"] = [
        {
            "rule_id": rule_id,
            "subject": name,
            "subject_kind": "library",
            "severity": "high",
            "category": "bundled-crypto",
            "layer": "binary",
            "confidence": "high",
            "verdict": klass,
            "relation": relation,
            "basis": ["FIPS-140-3"] if relation else [],
            "family": "library",
            "needs_human_review": review,
            "occurrences": 1,
            "truncated": False,
            "locations": [{"path": f"{name}/_native.so", "line": None, "evidence": name}],
        }
    ]
    # `crypto.families` is derived from `findings[].family` in a real record; the
    # bare `record()` fixture above has no findings yet to derive it from, so this
    # recomputes it now that one exists, the same way `record.py._crypto_block` does.
    base["crypto"]["families"] = sorted(
        {finding["family"] for finding in base["findings"] if finding.get("family")}
    )
    base["artifacts"] = {
        "py_files": 1,
        "pyc_files": 0,
        "py_files_unparsed": 0,
        "source_available": True,
        "binaries_truncated": False,
        "record_entries": 3,
        "total_uncompressed_bytes": 100,
        "extensions": [{"path": f"{name}/_native.so", "format": "elf"}],
        "bundled_libs": [f"{name}.libs/libcrypto.so"],
        "bundled_libs_truncated": False,
        "sboms": [],
        "symlinks": [],
        "symlinks_truncated": False,
        "skipped": [],
        "skipped_truncated": False,
    }
    base["binaries"] = [
        {
            "path": f"{name}/_native.so",
            "format": "elf",
            "vendored_path": None,
            "machine": "x86_64",
            "bits": 64,
            "endian": "little",
            "elf_type": "ET_DYN",
            "soname": None,
            "needed": [],
            "rpath": [],
            "runpath": [],
            "stripped": False,
            "symbol_counts": {"dynsym": 1, "symtab": 0},
            "matched_symbols": [],
            "matched_strings": [],
            "rust_crates": [],
            "go": None,
            "truncated": {"symbols": False, "strings": False},
            "partial_analysis": False,
            "partial_reasons": [],
        }
    ]
    base["errors"] = []
    base["errors_truncated"] = False
    return base


def _extract_payload(page: str) -> dict:
    match = _DATA_SCRIPT.search(page)
    assert match is not None, "no #wcs-data script found in the rendered page"
    return json.loads(match.group(1))


def _css(page: str) -> str:
    match = re.search(r"<style>(.*?)</style>", page, re.DOTALL)
    assert match is not None
    return match.group(1)


def _js(page: str) -> str:
    """The plain `<script>...</script>` block (the page's own logic): the exact
    literal `<script>` tag with no attributes, which only the page's own script
    carries -- the `wcs-data` block next to it (untrusted, wheel-derived data) opens
    with `<script type="application/json" id="wcs-data">` instead."""
    match = re.search(r"<script>(.*)</script>", page, re.DOTALL)
    assert match is not None
    return match.group(1)


# --- Markdown -----------------------------------------------------------------------


def test_markdown_has_a_row_per_wheel() -> None:
    table = render_markdown([record("a", "CONDITIONAL", "bundled"), record("b", "OPAQUE", "none")])
    assert table.count("\n| ") >= 2
    assert "a-1.0-py3-none-any.whl" in table
    assert "b-1.0-py3-none-any.whl" in table


def test_markdown_shows_the_class_and_the_openssl_linkage() -> None:
    table = render_markdown([record("cryptography", "CONDITIONAL", "bundled")])
    assert "CONDITIONAL" in table
    assert "bundled" in table


def test_markdown_marks_wheels_needing_review() -> None:
    table = render_markdown([record("a", "CONDITIONAL", "bundled", review=True)])
    assert "yes" in table


def test_markdown_rows_are_sorted_by_filename() -> None:
    table = render_markdown([record("z", "OPAQUE", "none"), record("a", "OPAQUE", "none")])
    assert table.index("a-1.0") < table.index("z-1.0")


def test_markdown_handles_an_empty_run() -> None:
    assert "no wheels" in render_markdown([]).lower()


def test_markdown_never_claims_compliance() -> None:
    table = render_markdown([record("a", "NO_CRYPTO_DETECTED", "none", review=False)])
    assert "compliant" not in table.lower()
    assert "compatible" not in table.lower()


def test_markdown_shows_the_crypto_inventory_before_the_fips_lens() -> None:
    """Acceptance criterion 1: each wheel's own detail carries its crypto inventory
    first, then what the FIPS compatibility lens makes of the same evidence."""
    rec = html_record("cryptography", "CONDITIONAL", "bundled")
    table = render_markdown([rec])
    inventory_index = table.index("### Cryptography in this wheel")
    compat_index = table.index("### FIPS compatibility")
    assert inventory_index < compat_index
    assert "openssl:bundled" in table
    assert "boundary_unresolved" in table
    assert "FIPS-140-3" in table


def test_markdown_gives_a_no_crypto_wheel_an_explicit_empty_inventory() -> None:
    """Acceptance criterion 1: a `NO_CRYPTO_DETECTED` wheel still gets an inventory
    section -- empty, and saying so -- rather than the section disappearing."""
    table = render_markdown([record("a", "NO_CRYPTO_DETECTED", "none", review=False)])
    assert "### Cryptography in this wheel" in table
    assert "No cryptography detected." in table


def test_markdown_empty_inventory_survives_an_informational_finding() -> None:
    """The empty-inventory message must not depend on `findings` being empty, only on
    `crypto.families`/`crypto.libraries` being empty: a `NO_CRYPTO_DETECTED` wheel
    that still carries a family-less, verdict-less informational finding (the shape
    `WHEEL_GENERATOR` takes on every real wheel) must read exactly the same as one
    with no findings at all, not silently list that finding under a synthetic
    grouping bucket instead of saying the inventory is empty."""
    rec = record("a", "NO_CRYPTO_DETECTED", "none", review=False)
    rec["findings"] = [
        {
            "rule_id": "WHEEL_GENERATOR",
            "subject": "bdist_wheel",
            "family": None,
            "relation": None,
            "basis": [],
            "severity": "info",
            "verdict": None,
            "occurrences": 1,
        }
    ]
    table = render_markdown([rec])
    assert "No cryptography detected." in table


def test_markdown_opaque_wheel_inventory_does_not_claim_no_cryptography() -> None:
    """An `OPAQUE` wheel also has empty `crypto.families`/`crypto.libraries` --
    nothing unreadable carries a `family` either -- but "no families, no libraries"
    means something different for it than for a `NO_CRYPTO_DETECTED` wheel: the tool
    could not read enough to have an opinion, not that it read the wheel in full and
    found nothing. `CLASS_HELP["NO_CRYPTO_DETECTED"]`'s own text ("absence of
    evidence, not evidence of absence") is exactly the distinction this guards."""
    table = render_markdown([record("a", "OPAQUE", "none")])
    assert "could not be read well enough" in table
    assert "No cryptography detected." not in table


def test_markdown_shows_family_and_relation_less_findings_as_other_evidence() -> None:
    """A finding with neither `family` (excluded from the crypto inventory) nor
    `relation` (excluded from the FIPS compatibility lens) -- coverage and
    wheel-hygiene evidence such as `WHEEL_GENERATOR` -- is not simply dropped from
    the wheel's own detail; it shows under a third "Other evidence" section."""
    rec = record("a", "CONDITIONAL", "bundled")
    rec["findings"] = [
        {
            "rule_id": "WHEEL_GENERATOR",
            "subject": "bdist_wheel",
            "family": None,
            "relation": None,
            "basis": [],
            "severity": "info",
            "verdict": None,
            "occurrences": 1,
        }
    ]
    table = render_markdown([rec])
    assert "### Other evidence" in table
    assert "WHEEL_GENERATOR" in table


def test_markdown_shows_dependency_only_crypto_in_the_inventory_not_as_absence(
    tmp_path: Path,
) -> None:
    """A wheel whose only crypto evidence is `Requires-Dist` on crypto packages must
    not have it both ways: the headline inventory used to say `No cryptography
    detected.` while `DIST_DEPENDS_ON_CRYPTO` findings for `bcrypt`, `pynacl` and
    `cryptography` sat in "Other evidence" right below it, naming exactly the
    cryptography the headline denied. `relation` stays withheld (a dependency edge
    is not the dependency's own risk), but `family` is descriptive evidence, not a
    risk statement, so it belongs in "Cryptography in this wheel"."""
    wheel = build_wheel(
        tmp_path / "depsonly-1.0-py3-none-any.whl",
        name="depsonly",
        version="1.0",
        requires_dist=("bcrypt", "pynacl", "cryptography"),
    )
    ruleset = load_ruleset(None)
    rec = scan_wheel(wheel, ScanContext.build(ruleset))
    assert {finding["rule_id"] for finding in rec["findings"]} >= {"DIST_DEPENDS_ON_CRYPTO"}
    table = render_markdown([rec])
    assert "No cryptography detected." not in table
    inventory_start = table.index("### Cryptography in this wheel")
    compatibility_start = table.index("### FIPS compatibility")
    inventory = table[inventory_start:compatibility_start]
    assert ruleset.distributions["bcrypt"].family in inventory
    assert ruleset.distributions["pynacl"].family in inventory
    assert ruleset.distributions["cryptography"].family in inventory


# --- HTML ---------------------------------------------------------------------------


def test_html_is_byte_stable_across_input_order() -> None:
    ruleset = load_ruleset(None)
    a = html_record("a", "CONDITIONAL", "bundled")
    b = html_record("b", "OPAQUE", "none")
    first = render_html([a, b], ruleset)
    second = render_html([b, a], ruleset)
    assert first == second


def test_html_has_no_timestamp_or_host_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guards more than one wall-clock source, not only `time.time`, and checks the
    rendered bytes directly for a date-shaped string, rather than only comparing two
    renders that could happen to land on the same day. `datetime.date.today` is not
    patched here: it is a C-immutable type whose classmethod pytest's `monkeypatch`
    cannot reassign, so the direct date-pattern scan below is what would catch a
    `datetime`-based generated-at line instead."""
    ruleset = load_ruleset(None)
    rec = html_record("a", "CONDITIONAL", "bundled")

    monkeypatch.setattr("time.time", lambda: 1_000_000.0)
    monkeypatch.setattr("time.strftime", lambda *a, **k: "2024-01-01")
    first = render_html([rec], ruleset)

    monkeypatch.setattr("time.time", lambda: 2_000_000.0)
    monkeypatch.setattr("time.strftime", lambda *a, **k: "2030-12-31")
    second = render_html([rec], ruleset)

    assert first == second
    assert socket.gethostname() not in first
    assert re.search(r"\b\d{4}-\d{2}-\d{2}\b", first) is None

    # The page must equal the shipped template with only the data token substituted:
    # anything else -- a banner spliced in before the substitution, a host path, a
    # generated-at line -- would show up as a difference here even if it never touches
    # a clock this test patches.
    template = files("wheel_crypto_scan").joinpath("data/report.html").read_text(encoding="utf-8")
    embedded = _DATA_SCRIPT.search(first)
    assert embedded is not None
    assert first == template.replace("/*WCS_DATA*/", embedded.group(1))


def test_html_embedded_data_round_trips() -> None:
    ruleset = load_ruleset(None)
    records = [html_record("b", "OPAQUE", "none"), html_record("a", "CONDITIONAL", "bundled")]
    page = render_html(records, ruleset)
    payload = _extract_payload(page)
    assert payload["records"] == sorted(records, key=lambda r: r["wheel"]["filename"])


def test_html_cannot_be_closed_by_a_wheel_string() -> None:
    ruleset = load_ruleset(None)
    dangerous = "</script><script>alert(1)</script><!--"
    rec = html_record(dangerous, "OPAQUE", "none")
    rec["verdict"]["reasons"] = [f"BIN_BUNDLED_OPENSSL: {dangerous}"]
    rec["findings"][0]["locations"][0]["evidence"] = dangerous

    page = render_html([rec], ruleset)

    template = files("wheel_crypto_scan").joinpath("data/report.html").read_text(encoding="utf-8")
    assert page.count("</script>") == template.count("</script>")
    assert "<script>alert" not in page

    # Directly on the embedded payload: no literal "<" survives at all, which is what
    # actually keeps "</script" and "<script" from ever forming, regardless of whether
    # a ">" happens to follow one in the wheel's own string.
    embedded = _DATA_SCRIPT.search(page)
    assert embedded is not None
    assert "<" not in embedded.group(1)


def test_html_never_claims_compliance() -> None:
    ruleset = load_ruleset(None)
    rec = html_record("a", "NO_CRYPTO_DETECTED", "none", review=False)
    rec["verdict"]["reasons"] = []
    rec["verdict"]["rule_ids"] = []
    rec["findings"] = []

    page = render_html([rec], ruleset)
    lowered = page.lower()

    assert "compliant" not in lowered
    assert "compatible" not in lowered
    assert re.search(r"\bpass(ed|es)?\b", lowered) is None
    assert "✓" not in page
    assert "&check;" not in lowered
    assert "not flagged" in lowered
    assert "absence of evidence" in lowered


def test_report_surfaces_never_spell_a_passing_verdict() -> None:
    """No rendered or source surface of the report module may spell out a passing
    verdict, in any of the three forms the taxonomy must never acquire: "compliant",
    "compliance" or "compatible". "compatible" is not a substring of "compatibility",
    so a wording that only ever discusses FIPS compatibility as a lens, never a status,
    still passes this check untouched."""
    forbidden = ("compliant", "compliance", "compatible")

    template = files("wheel_crypto_scan").joinpath("data/report.html").read_text(encoding="utf-8")
    module_source = inspect.getsource(report)
    table = render_markdown([record("a", "NO_CRYPTO_DETECTED", "none", review=False)])

    for word in forbidden:
        assert word not in template.lower(), word
        assert word not in module_source.lower(), word
        assert word not in table.lower(), word


def test_html_gives_no_class_a_success_colour() -> None:
    """Every precedence class must have a `[data-class=...]` rule, that rule must
    resolve to exactly one of the three named colour tokens (never a bare hex value a
    reviewer would have to eyeball), the two "nothing decided" classes must share the
    neutral token while every other class must not, and none of the tokens themselves
    -- in either theme -- may actually render as green. Pinning the token *name* a
    class maps to is not enough on its own: a hex literal is what a reader sees, so a
    warn or danger token that was quietly redefined green must fail too."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    css = _css(page)

    rules = dict(re.findall(r'\[data-class="(\w+)"\]\s*\{([^}]*)\}', css))
    for cls in ruleset.precedence:
        assert cls in rules, f"no [data-class={cls!r}] rule in the template CSS"

    tokens: dict[str, str] = {}
    for cls, body in rules.items():
        match = re.search(r"var\((--class-\w+)\)", body)
        assert match is not None, f"[data-class={cls!r}] does not use a named class token: {body!r}"
        tokens[cls] = match.group(1)

    neutral_classes = {"NO_CRYPTO_DETECTED", "OPAQUE"}
    for cls in ruleset.precedence:
        if cls in neutral_classes:
            assert tokens[cls] == "--class-neutral", cls
        else:
            assert tokens[cls] != "--class-neutral", cls

    # Every definition of every class token, in both themes, must stay out of the
    # green range: green being the clear maximum channel is what "reads as green",
    # regardless of which token or theme carries it.
    for name, hexvalue in re.findall(r"(--class-\w+):\s*(#[0-9a-fA-F]{6})", css):
        red, green, blue = (int(hexvalue[i : i + 2], 16) for i in (1, 3, 5))
        assert not (green > red + 20 and green > blue + 20), f"{name} is {hexvalue}, too green"

    assert "--success" not in css
    assert "--ok" not in css
    assert "green" not in css.lower()


def test_html_unknown_class_falls_back_to_a_warning_colour_not_neutral() -> None:
    """A class from a custom ruleset that carries no `[data-class=...]` rule of its
    own reads through the `.badge`/`.swatch` CSS fallback, `var(--class-color,
    ...)`. That default must not be `--class-neutral`: a class a custom ruleset put
    at the top of its own precedence would otherwise read the same grey as
    `NO_CRYPTO_DETECTED`, repeating on the page the exact confusion the
    OPAQUE-vs-NO_CRYPTO_DETECTED distinction exists to prevent. The two classes
    that do mean "nothing decided" are unaffected: each carries its own explicit
    `[data-class=...]` rule, so the fallback never applies to them."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    css = _css(page)
    fallbacks = re.findall(r"var\(--class-color,\s*var\((--class-\w+)\)\)", css)
    assert fallbacks, "no var(--class-color, var(--class-X)) fallback found in the template CSS"
    assert all(token != "--class-neutral" for token in fallbacks), fallbacks


def test_every_precedence_class_has_help() -> None:
    """Reads `LINKAGE_VALUES`, the vocabulary the loader itself validates a ruleset's
    `openssl_linkage` against, rather than a hardcoded copy of it: a value added to the
    vocabulary without a matching `LINKAGE_HELP` entry must fail this, the way a rule
    naming an unknown token already fails at load time."""
    ruleset = load_ruleset(None)
    assert set(ruleset.precedence) <= set(CLASS_HELP)
    assert LINKAGE_VALUES <= set(LINKAGE_HELP)


def test_every_relation_and_family_has_help() -> None:
    """`RELATION_HELP` and `FAMILY_HELP` held to `RELATIONS` and `FAMILIES`, the
    loader's own closed vocabularies, the same way `test_every_precedence_class_has_help`
    holds `LINKAGE_HELP` to `LINKAGE_VALUES`: a value added to either vocabulary
    without a matching help entry must fail this, the way a rule naming an unknown
    relation or family already fails at load time."""
    assert RELATIONS <= set(RELATION_HELP)
    assert FAMILIES <= set(FAMILY_HELP)


def test_class_help_matches_the_output_schema_verdict_table() -> None:
    """`CLASS_HELP` claims (in its own comment) to be verbatim from SCHEMA.md's
    "Verdict classes" table. Parse that table directly, rather than asserting the
    claim only in prose, so the two cannot drift apart silently the way `record.py`
    and `data/schema.json` are already held to."""
    schema = Path(__file__).parent.parent / "docs" / "SCHEMA.md"
    text = schema.read_text(encoding="utf-8")
    section = text.split("### Verdict classes", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"\|\s*`(\w+)`\s*\|\s*(.+?)\s*\|\s*\n", section)
    documented = {cls: meaning.replace("**", "").replace("`", "") for cls, meaning in rows}
    assert documented, "no verdict-class rows parsed from SCHEMA.md"
    assert documented == CLASS_HELP


def test_linkage_help_follows_the_output_schema_linkage_table() -> None:
    """`LINKAGE_HELP` is a short form of SCHEMA.md's `conditions.openssl_linkage` table,
    not a verbatim copy: several of that table's rows run to a paragraph, too long for
    a tooltip. What a short form cannot lose is an input the field is read from, because
    a tooltip that omits one sends the reader looking in the wrong place -- a wheel that
    reads `unknown` only because its own SBOM names the library has nothing to find in
    its binaries. Parse the table directly and check each value's short form names the
    SBOM exactly when its SCHEMA.md row does, the same drift-detection approach as
    `test_class_help_matches_the_output_schema_verdict_table` above."""
    schema = Path(__file__).parent.parent / "docs" / "SCHEMA.md"
    text = schema.read_text(encoding="utf-8")
    section = text.split("### `conditions.openssl_linkage`", 1)[1].split("\n### ", 1)[0]
    rows = re.findall(r"^\|\s*`(\w+)`\s*\|\s*(.+)\s*\|\s*$", section, re.MULTILINE)
    documented = dict(rows)
    assert documented, "no linkage rows parsed from SCHEMA.md"
    assert set(documented) == set(LINKAGE_HELP)
    for value, meaning in documented.items():
        assert ("SBOM" in meaning) == ("SBOM" in LINKAGE_HELP[value]), value


def test_html_is_self_contained() -> None:
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    assert "<link" not in page
    assert "@import" not in page
    assert re.search(r'(?:src|href)\s*=\s*"https?://', page) is None


def test_html_embeds_only_referenced_rules() -> None:
    ruleset = load_ruleset(None)
    rec = html_record("a", "CONDITIONAL", "bundled", rule_id="BIN_BUNDLED_OPENSSL")
    page = render_html([rec], ruleset)
    payload = _extract_payload(page)
    assert set(payload["rules"]) == {"BIN_BUNDLED_OPENSSL"}
    assert payload["rules"]["BIN_BUNDLED_OPENSSL"]["why"] == ruleset.rule("BIN_BUNDLED_OPENSSL").why


def test_html_embeds_only_referenced_standards() -> None:
    """The `standards` payload narrows to only the standard ids some embedded
    finding's own `basis` cites, mirroring how `_referenced_rules` narrows to only
    the rule ids in use, and carries the subset of `Standard` fields the detail
    panel's basis-chip tooltip reads (title, edition, status, successor, url)."""
    ruleset = load_ruleset(None)
    rec = html_record("a", "CONDITIONAL", "bundled", rule_id="BIN_BUNDLED_OPENSSL")
    page = render_html([rec], ruleset)
    payload = _extract_payload(page)
    assert set(payload["standards"]) == {"FIPS-140-3"}
    standard = ruleset.standards["FIPS-140-3"]
    assert payload["standards"]["FIPS-140-3"] == {
        "title": standard.title,
        "edition": standard.edition,
        "status": standard.status,
        "successor": standard.successor,
        "url": standard.url,
    }


def test_html_standards_payload_is_empty_with_no_basis_cited() -> None:
    ruleset = load_ruleset(None)
    rec = html_record("a", "OPAQUE", "none")
    rec["findings"][0]["basis"] = []
    rec["findings"][0]["relation"] = None
    page = render_html([rec], ruleset)
    payload = _extract_payload(page)
    assert payload["standards"] == {}


def test_html_handles_an_empty_run() -> None:
    ruleset = load_ruleset(None)
    page = render_html([], ruleset)
    assert "No wheels scanned" in page
    payload = _extract_payload(page)
    assert payload["records"] == []


def test_html_unreadable_inventory_note_matches_the_markdown_one() -> None:
    """`report.py`'s `_UNREADABLE_INVENTORY_NOTE` and `data/report.html`'s
    `UNREADABLE_INVENTORY_NOTE` are the same sentence written twice, because the HTML
    report's inventory section is JS, not filled from this Python string. Pins the two
    copies together so one edited without the other fails here rather than only being
    noticed by a reader comparing the Markdown and HTML output of the same wheel."""
    page = render_html([], load_ruleset(None))
    match = re.search(r'var UNREADABLE_INVENTORY_NOTE = ((?:"[^"]*"\s*\+?\s*)+);', page)
    assert match is not None
    js_note = "".join(re.findall(r'"([^"]*)"', match.group(1)))
    assert js_note == report._UNREADABLE_INVENTORY_NOTE


def test_html_is_ascii() -> None:
    """`--format html` to a redirected stdout must not crash on a non-UTF-8 locale:
    the template, and therefore every render of it, must stay pure ASCII."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    assert page.isascii()


def test_html_drilldown_is_not_keyed_by_filename() -> None:
    """Two records can share a filename -- a cpu and a cuda build of the same wheel
    name, for instance -- and both stay independently reachable from the table. The
    script holds no `{filename: record}` map, so a collision cannot drop one; the
    embedded data keeps both, distinctly. `test_browser_drilldown_uses_position_not_filename`
    below exercises the actual click/hash behaviour this data shape backs, in a real
    browser."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = _js(page)
    assert "recordsByFilename" not in script
    assert re.search(r"\[\s*wheel\.filename\s*\]\s*=\s*record\b", script) is None

    # Two records that share a filename must both still be present, and distinct, in
    # the embedded data the drill-down reads from.
    dup_a = html_record("dup", "FIPS_BREAKING", "static")
    dup_b = html_record("dup", "OPAQUE", "none")
    page = render_html([dup_a, dup_b], ruleset)
    payload = _extract_payload(page)
    assert len(payload["records"]) == 2
    assert payload["records"][0]["wheel"]["filename"] == payload["records"][1]["wheel"]["filename"]
    assert payload["records"][0]["verdict"]["class"] != payload["records"][1]["verdict"]["class"]


def test_html_classes_payload_covers_classes_outside_precedence() -> None:
    """The class filter and legend read `classes` straight off the embedded
    payload, with no union of their own left to get wrong: the loader requires a
    ruleset's `[verdict] precedence` to list every class `classify()` can emit, but
    `render_html` takes any `Ruleset`, including one built without the loader, so
    `render_html` folds in any class a record actually carries that a given
    ruleset's own precedence leaves out.
    `test_browser_class_filter_covers_a_class_outside_precedence` below checks the
    same case end to end, in a real browser."""
    ruleset = load_ruleset(None)
    narrowed = dataclasses.replace(
        ruleset,
        precedence=tuple(cls for cls in ruleset.precedence if cls != "NO_CRYPTO_DETECTED"),
    )
    rec = html_record("a", "NO_CRYPTO_DETECTED", "none")
    payload = _extract_payload(render_html([rec], narrowed))
    assert "NO_CRYPTO_DETECTED" not in narrowed.precedence
    assert "NO_CRYPTO_DETECTED" in payload["classes"]


def test_html_binaries_tab_shows_go_and_truncated_fields() -> None:
    """`go` (go_version, boring_crypto, markers), `truncated` (symbols, strings) and
    `symbol_counts` (dynsym, symtab) are all emitted by `record.py` and documented in
    SCHEMA.md, and the Binaries tab shows all three: a capped sample of matched
    symbols or strings reads as a sample, and a Go build's evidence is visible
    without opening the Raw JSON tab. The `test_browser_binaries_tab_shows_go_...`
    test below renders the tab in a real browser and reads the values back."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = _js(page)
    assert "binary.go" in script
    assert "binary.truncated" in script or "truncated.symbols" in script
    assert "symbol_counts" in script


def test_html_detail_view_has_a_verdict_section() -> None:
    """The detail view's Verdict section shows `verdict.classes` (every class that
    fired, not only the headline), the full `reasons` list (the table caps it at
    three plus a chip with no way to expand it), and `conditions`.
    `test_browser_detail_view_shows_verdict_section` below renders the section in a
    real browser and reads the values back."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = _js(page)
    assert "verdict.classes" in script
    assert "verdict.conditions" in script
    assert "verdict.reasons" in script


# --- HTML rendered in a real browser -------------------------------------------------
#
# The tests above check the source: what the page is built out of. They pass just as
# well when the JavaScript that reads that source is wrong, because nothing in them
# runs it. The tests below render the page in headless Chrome (or Chromium) instead,
# and read the DOM it actually produces, so a regression in what the script *does*
# with the data -- not just what it mentions -- fails one of these. Each self-skips
# without a browser on the host; see `_render_in_browser`.


def test_browser_detail_view_shows_verdict_section(tmp_path: Path) -> None:
    """Opening a wheel's detail view renders its FIPS compatibility section: the
    class badge, the openssl_linkage condition, and the reason text -- not just the
    inventory above it."""
    ruleset = load_ruleset(None)
    rec = html_record("a", "FIPS_BREAKING", "static", rule_id="RULE_FIPS")
    page = render_html([rec], ruleset)

    dom = _render_in_browser(tmp_path, page, fragment="wheel=0")
    findings_tab = _tab(dom, "findings")

    assert "FIPS compatibility" in findings_tab
    assert 'data-class="FIPS_BREAKING"' in findings_tab
    assert "static" in findings_tab
    assert "RULE_FIPS: a" in findings_tab


def test_browser_detail_view_shows_inventory_before_compatibility(tmp_path: Path) -> None:
    """The detail view's crypto inventory -- families and libraries, findings
    grouped by family -- renders before its FIPS compatibility section -- the class
    badge as that section's own summary, findings grouped by relation with basis
    chips -- the same order `report.py`'s `_HEADERS` gives the list view."""
    ruleset = load_ruleset(None)
    rec = html_record("a", "CONDITIONAL", "bundled", rule_id="BIN_BUNDLED_OPENSSL")
    page = render_html([rec], ruleset)

    dom = _render_in_browser(tmp_path, page, fragment="wheel=0")
    findings_tab = _tab(dom, "findings")

    inventory_index = findings_tab.index("Cryptography in this wheel")
    compat_index = findings_tab.index("FIPS compatibility")
    assert inventory_index < compat_index
    assert "openssl: bundled" in findings_tab
    assert "boundary_unresolved" in findings_tab
    assert "FIPS-140-3" in findings_tab


def test_browser_no_crypto_wheel_gets_an_explicit_empty_inventory(tmp_path: Path) -> None:
    """Acceptance criterion 1, rendered: a `NO_CRYPTO_DETECTED` wheel's detail view
    still shows a crypto inventory section, and it says explicitly that it is
    empty, rather than the section disappearing."""
    ruleset = load_ruleset(None)
    rec = html_record("a", "NO_CRYPTO_DETECTED", "none", review=False)
    rec["findings"] = []
    rec["crypto"] = {"families": [], "libraries": []}
    rec["verdict"]["relations"] = []
    rec["verdict"]["reasons"] = []
    rec["verdict"]["rule_ids"] = []
    page = render_html([rec], ruleset)

    dom = _render_in_browser(tmp_path, page, fragment="wheel=0")
    findings_tab = _tab(dom, "findings")

    assert "Cryptography in this wheel" in findings_tab
    assert "No cryptography detected in this wheel." in findings_tab


def test_browser_opaque_wheel_inventory_does_not_claim_no_cryptography(tmp_path: Path) -> None:
    """An `OPAQUE` wheel also has empty `crypto.families`/`crypto.libraries` --
    nothing unreadable carries a `family` either -- but the inventory section must
    not say "No cryptography detected" for it: that is the `NO_CRYPTO_DETECTED`
    claim (read in full, found nothing), and `OPAQUE` means the opposite (could not
    read enough to have an opinion)."""
    ruleset = load_ruleset(None)
    rec = html_record("a", "OPAQUE", "none", rule_id="WHEEL_UNREADABLE")
    rec["findings"][0]["family"] = None
    rec["findings"][0]["relation"] = None
    rec["findings"][0]["basis"] = []
    rec["crypto"] = {"families": [], "libraries": []}
    page = render_html([rec], ruleset)

    dom = _render_in_browser(tmp_path, page, fragment="wheel=0")
    findings_tab = _tab(dom, "findings")

    assert "could not be read well enough" in findings_tab
    assert "No cryptography detected in this wheel." not in findings_tab


def test_browser_detail_view_shows_other_evidence_section(tmp_path: Path) -> None:
    """A finding with neither `family` (excluded from the crypto inventory) nor
    `relation` (excluded from the FIPS compatibility lens) -- coverage and
    wheel-hygiene evidence such as `WHEEL_GENERATOR` -- is not simply invisible
    outside the Raw JSON tab; it shows under a third "Other evidence" section, after
    the two named ones."""
    ruleset = load_ruleset(None)
    rec = html_record("a", "CONDITIONAL", "bundled", rule_id="BIN_BUNDLED_OPENSSL")
    rec["findings"].append(
        {
            "rule_id": "WHEEL_GENERATOR",
            "subject": "bdist_wheel",
            "subject_kind": "generator",
            "severity": "info",
            "category": "provenance",
            "layer": "metadata",
            "confidence": "high",
            "verdict": None,
            "relation": None,
            "basis": [],
            "family": None,
            "needs_human_review": False,
            "occurrences": 1,
            "truncated": False,
            "locations": [],
        }
    )
    page = render_html([rec], ruleset)

    dom = _render_in_browser(tmp_path, page, fragment="wheel=0")
    findings_tab = _tab(dom, "findings")

    inventory_index = findings_tab.index("Cryptography in this wheel")
    compat_index = findings_tab.index("FIPS compatibility")
    other_index = findings_tab.index("Other evidence")
    assert inventory_index < compat_index < other_index
    assert "WHEEL_GENERATOR" in findings_tab


def test_browser_drilldown_uses_position_not_filename(tmp_path: Path) -> None:
    """Two records that share a filename -- a cpu and a cuda build of the same wheel
    name, for instance -- stay independently reachable: opening the wheel at one
    table position shows that record's own evidence, never the other one's, even
    though both carry the same `wheel.filename`."""
    ruleset = load_ruleset(None)
    dup_a = html_record("dup", "FIPS_BREAKING", "static", rule_id="RULE_FIPS")
    dup_b = html_record("dup", "OPAQUE", "none", rule_id="RULE_OPAQUE")
    page = render_html([dup_a, dup_b], ruleset)
    payload = _extract_payload(page)
    # Which of the two lands at position 0 is the JSON tiebreak's own business (see
    # `_html_sort_key`), not this test's: what matters is that the two positions
    # disagree, and each shows only its own record's evidence.
    first_class = payload["records"][0]["verdict"]["class"]
    second_class = payload["records"][1]["verdict"]["class"]
    assert sorted([first_class, second_class]) == ["FIPS_BREAKING", "OPAQUE"]

    first = _tab(_render_in_browser(tmp_path, page, fragment="wheel=0"), "findings")
    second = _tab(_render_in_browser(tmp_path, page, fragment="wheel=1"), "findings")

    assert f'data-class="{first_class}"' in first
    assert f'data-class="{second_class}"' not in first
    assert f'data-class="{second_class}"' in second
    assert f'data-class="{first_class}"' not in second


def test_browser_class_filter_covers_a_class_outside_precedence(tmp_path: Path) -> None:
    """A wheel whose class a given `Ruleset`'s own `[verdict] precedence` leaves out
    still shows in the table: the class filter's default state, and the legend,
    both cover it. `render_html` takes any `Ruleset`, including one built without
    the loader that requires precedence to name every class `classify()` can emit,
    so this is a case `render_html` must still cover."""
    ruleset = load_ruleset(None)
    narrowed = dataclasses.replace(
        ruleset,
        precedence=tuple(cls for cls in ruleset.precedence if cls != "NO_CRYPTO_DETECTED"),
    )
    rec = html_record("a", "NO_CRYPTO_DETECTED", "none")
    page = render_html([rec], narrowed)

    dom = _render_in_browser(tmp_path, page)

    assert "1 of 1 wheels" in dom
    assert 'data-class="NO_CRYPTO_DETECTED"' in dom


def test_browser_binaries_tab_shows_go_truncated_and_symbol_counts(tmp_path: Path) -> None:
    """The Binaries tab shows `go`, `truncated` and `symbol_counts` with their
    actual values, not only their labels: a capped sample reads as a sample, and a
    Go build's evidence is visible without switching to the Raw JSON tab."""
    ruleset = load_ruleset(None)
    rec = html_record("a", "OPAQUE", "none")
    rec["binaries"][0]["go"] = {
        "go_version": "go1.22.3",
        "boring_crypto": True,
        "markers": ["+boringcrypto"],
    }
    rec["binaries"][0]["truncated"] = {"symbols": True, "strings": False}
    rec["binaries"][0]["symbol_counts"] = {"dynsym": 42, "symtab": 7}
    rec["binaries"][0]["matched_symbols"] = [
        {"name": "EVP_DigestInit", "group": "digest", "binding": "defined"}
    ]
    page = render_html([rec], ruleset)

    dom = _render_in_browser(
        tmp_path, page, fragment="wheel=0", extra_script=_click_tab("binaries")
    )
    binaries_tab = _tab(dom, "binaries")

    assert "go1.22.3" in binaries_tab
    assert "boringcrypto" in binaries_tab
    assert re.search(r"truncated\.symbols</dt><dd>true</dd>", binaries_tab)
    assert re.search(r"symbol_counts\.dynsym</dt><dd>42</dd>", binaries_tab)
    assert re.search(r"symbol_counts\.symtab</dt><dd>7</dd>", binaries_tab)
    assert "sample" in binaries_tab


def test_browser_wheel_tab_shows_artifact_entries_and_generator_raw(tmp_path: Path) -> None:
    """The Wheel and artifacts tab lists the evidence behind its counts -- bundled
    library names, skipped paths with their reasons, symlink targets, extension
    paths with their format, sbom paths -- and the wheel's `generator.raw`, not
    only the summary counts the Raw JSON tab already carries."""
    ruleset = load_ruleset(None)
    rec = html_record("a", "OPAQUE", "none")
    rec["wheel"]["generator"] = {
        "name": "bdist_wheel",
        "version": "0.42.0",
        "raw": "bdist_wheel (0.42.0)",
    }
    rec["artifacts"]["skipped"] = [{"path": "a/big.bin", "reason": "size_limit_exceeded"}]
    rec["artifacts"]["symlinks"] = [{"path": "a/lib.so", "target": "lib.so.1.2.3"}]
    rec["artifacts"]["sboms"] = ["a/sbom.spdx.json"]
    page = render_html([rec], ruleset)

    dom = _render_in_browser(tmp_path, page, fragment="wheel=0", extra_script=_click_tab("wheel"))
    wheel_tab = _tab(dom, "wheel")

    assert "bdist_wheel (0.42.0)" in wheel_tab
    assert "a.libs/libcrypto.so" in wheel_tab
    assert "a/big.bin: size_limit_exceeded" in wheel_tab
    assert "a/lib.so -&gt; lib.so.1.2.3" in wheel_tab or "a/lib.so -> lib.so.1.2.3" in wheel_tab
    assert "a/sbom.spdx.json" in wheel_tab
    assert "a/_native.so (elf)" in wheel_tab


# A token with no break opportunity in it, far wider than the detail panel: the shape
# a wheel filename, an object path or a matched string takes.
_UNBREAKABLE = "a" * 400


def _detail_layout(tab: str) -> str:
    """JS that records, as JSON in `document.title`, the open detail panel's layout
    on `tab`: `panel` is `[scrollWidth, clientWidth]` of the panel; `boxes` is that
    same pair for **every** `.table-scroll` box on the tab, not just the first --
    the Findings tab can hold up to three (the inventory table, the compatibility
    table and, when present, the other-evidence table), and a regression confined to
    one of the later ones would pass unnoticed if only the first were measured;
    `wrap` is the narrowest free-text cell's width and `em` its font size (both null
    without one)."""
    return (
        "var panel = document.getElementById('detail-panel');"
        f"var tabPanel = document.getElementById('tab-{tab}');"
        "var boxes = Array.prototype.slice.call(tabPanel.querySelectorAll('.table-scroll'));"
        "var cells = Array.prototype.slice.call(tabPanel.querySelectorAll('td.wrap'));"
        "document.title = JSON.stringify({"
        " panel: [panel.scrollWidth, panel.clientWidth],"
        " boxes: boxes.map(function (b) { return [b.scrollWidth, b.clientWidth]; }),"
        " wrap: cells.length ? Math.min.apply(null,"
        "  cells.map(function (cell) { return cell.offsetWidth; })) : null,"
        " em: cells.length ? parseFloat(getComputedStyle(cells[0]).fontSize) : null"
        "});"
    )


def _measure_detail_view(tmp_path: Path, rec: dict, tab: str, window_size: str = "") -> dict:
    """Open `rec`'s detail view on `tab` and return what `_detail_layout` records.
    Asserts the panel is showing: a hidden one measures zero everywhere, which would
    pass every width comparison while checking nothing."""
    page = render_html([rec], load_ruleset(None))
    script = (_click_tab(tab) if tab != "findings" else "") + _detail_layout(tab)
    dom = _render_in_browser(
        tmp_path, page, fragment="wheel=0", extra_script=script, window_size=window_size
    )
    match = re.search(r"<title>([^<]*)</title>", dom)
    assert match is not None
    layout = json.loads(match.group(1))
    assert layout["panel"][1] > 0
    return layout


@pytest.mark.parametrize("tab", _TAB_ORDER)
def test_browser_detail_view_never_paints_outside_the_panel(tmp_path: Path, tab: str) -> None:
    """No tab of the detail view draws past the panel's edge, over the dimmed page
    behind it, whatever length its text runs to. Every free-form field here carries
    an unbreakable token, including the columns of a table that do not wrap, so
    wrapping the free-text columns cannot rescue a table: only its own scroll box
    keeps it within the panel. `FIPS_BREAKING`, not `OPAQUE`: the class carries a
    `relation`, so the Findings tab renders its compatibility table -- with an
    unbreakable basis chip -- alongside the inventory one, stressing both rather
    than only the first."""
    rec = html_record("a", "FIPS_BREAKING", "static")
    rec["wheel"]["filename"] = _UNBREAKABLE
    rec["verdict"]["reasons"] = [_UNBREAKABLE]
    rec["findings"][0]["subject"] = _UNBREAKABLE
    rec["findings"][0]["locations"][0]["path"] = _UNBREAKABLE
    rec["findings"][0]["basis"] = [_UNBREAKABLE]
    rec["binaries"][0]["path"] = _UNBREAKABLE
    rec["binaries"][0]["matched_strings"] = [{"group": "go_fips140", "value": _UNBREAKABLE}]
    rec["artifacts"]["bundled_libs"] = [_UNBREAKABLE]
    rec["artifacts"]["skipped"] = [{"path": _UNBREAKABLE, "reason": "size_limit_exceeded"}]
    rec["errors"] = [
        {
            "stage": _UNBREAKABLE,
            "kind": _UNBREAKABLE,
            "path": _UNBREAKABLE,
            "message": _UNBREAKABLE,
        }
    ]

    scroll_width, client_width = _measure_detail_view(tmp_path, rec, tab)["panel"]

    assert scroll_width <= client_width


def _long_free_text_record() -> dict:
    """A record whose finding location, finding basis, error path and error message
    are each one unbreakable token: the columns a wheel filename or an object path
    lands in. `FIPS_BREAKING`, not `OPAQUE`, so the Findings tab's compatibility
    table -- and its basis-chip column -- is exercised here too, not only the
    inventory table."""
    rec = html_record("a", "FIPS_BREAKING", "static")
    rec["findings"][0]["locations"][0]["path"] = _UNBREAKABLE
    rec["findings"][0]["basis"] = [_UNBREAKABLE]
    rec["errors"] = [
        {
            "stage": "binary",
            "kind": "elf_parse_error",
            "path": _UNBREAKABLE,
            "message": _UNBREAKABLE,
        }
    ]
    return rec


@pytest.mark.parametrize("tab", ["findings", "errors"])
def test_browser_detail_table_wraps_long_paths_to_fit(tmp_path: Path, tab: str) -> None:
    """On a desktop-width window, a long location, basis id, error path or error
    message wraps within its cell, so every table on the tab fits its own box
    without a horizontal scrollbar -- checked for each `.table-scroll` box present,
    not only the first."""
    layout = _measure_detail_view(tmp_path, _long_free_text_record(), tab, window_size="1600,1000")

    assert layout["boxes"], "no .table-scroll box found on this tab"
    for scroll_width, client_width in layout["boxes"]:
        assert scroll_width <= client_width


@pytest.mark.parametrize("tab", ["findings", "errors"])
def test_browser_detail_table_keeps_free_text_columns_readable(tmp_path: Path, tab: str) -> None:
    """On a window too narrow for the table, a free-text column holds its 16em floor
    and the table scrolls in its box, rather than the column shrinking to a few
    characters a line."""
    layout = _measure_detail_view(tmp_path, _long_free_text_record(), tab, window_size="600,1000")

    assert layout["wrap"] is not None
    assert layout["wrap"] >= 16 * layout["em"]


def test_browser_theme_toggle_cycles_without_storage(tmp_path: Path) -> None:
    """The theme toggle still reaches every state -- system, light, dark -- when
    `localStorage` throws on every access, the private-browsing/disabled-storage
    case the page's own try/catch is written for. Reading the current preference
    back from storage on every click, instead of holding it in memory, would make
    every click see "system" and never advance past "light"."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)

    block_storage = (
        "<script>Object.defineProperty(window, 'localStorage', "
        "{ get: function () { throw new DOMException('blocked'); } });</script>"
    )
    # Storage must be blocked before the page's own script runs -- it reads the
    # theme preference at boot -- so this goes in ahead of the data block, not
    # appended at the end the way `extra_script` runs.
    rigged = page.replace(
        '<script type="application/json" id="wcs-data">',
        block_storage + '<script type="application/json" id="wcs-data">',
        1,
    )

    click_and_record = (
        "var out = [];"
        "var btn = document.getElementById('theme-toggle');"
        "out.push(btn.textContent);"
        "btn.click(); out.push(btn.textContent);"
        "btn.click(); out.push(btn.textContent);"
        "btn.click(); out.push(btn.textContent);"
        "document.title = out.join('|');"
    )
    dom = _render_in_browser(tmp_path, rigged, extra_script=click_and_record)

    match = re.search(r"<title>([^<]*)</title>", dom)
    assert match is not None
    assert match.group(1).split("|") == [
        "Theme: system",
        "Theme: light",
        "Theme: dark",
        "Theme: system",
    ]


# --- HTML rendered in a real browser: onboarding dialog, columns, filters -----------
#
# Same shape as the browser tests above: each self-skips without a browser on the
# host. `_seed_script` mirrors `test_browser_theme_toggle_cycles_without_storage`'s
# `block_storage` rig -- test-authored JavaScript that must run before the page's own
# script (which reads storage and builds the DOM at boot), so it goes in ahead of the
# data block rather than through `extra_script`, which only runs after.


def _seed_script(page: str, script: str) -> str:
    return page.replace(
        '<script type="application/json" id="wcs-data">',
        f"<script>{script}</script>" + '<script type="application/json" id="wcs-data">',
        1,
    )


_INTRO_OPEN_SCRIPT = "document.title = String(document.getElementById('intro').open);"

_FILENAME_COL_WIDTH_SCRIPT = (
    "document.title = document.getElementById('wheel-colgroup').children[0].style.width;"
)


def _find_chip_js(class_name: str) -> str:
    """JS expression (no trailing `;`) for the class chip whose text names
    `class_name`, for a test to append `.click()` or a property read to."""
    return (
        "Array.prototype.find.call(document.querySelectorAll('.class-chip'), "
        f"function (c) {{ return c.textContent.indexOf('{class_name}') !== -1; }})"
    )


def _title(dom: str) -> str:
    """Unescaped: `--dump-dom` serialises the title element's text back to HTML, so
    a literal `&` a test put there (the hash's own param separator, among other
    things) comes back as `&amp;`."""
    match = re.search(r"<title>([^<]*)</title>", dom)
    assert match is not None
    return html.unescape(match.group(1))


def _three_records() -> list[dict]:
    """Three wheels spanning three classes and both review states, named so their
    sorted order (by filename) is a, b, c: enough spread to exercise the class chip
    counts, the review-only filter, and Previous/Next stepping through a filtered
    set that skips the excluded middle record. Each carries a rule id the real
    ruleset actually defines (`BIN_BUNDLED_OPENSSL`, `WHEEL_UNREADABLE`,
    `PY_WEAK_HASH_CALL`), not a placeholder one: `render_html`'s `rules` payload
    only ever carries a rule the given `Ruleset` defines, so a fixture rule id the
    Rules tab is meant to list has to be one of those."""
    a = html_record("a", "CONDITIONAL", "bundled", review=True, rule_id="BIN_BUNDLED_OPENSSL")
    b = html_record("b", "OPAQUE", "none", review=False, rule_id="WHEEL_UNREADABLE")
    c = html_record("c", "FIPS_BREAKING", "static", review=True, rule_id="PY_WEAK_HASH_CALL")
    return [a, b, c]


def _finding(
    rule_id: str,
    subject: str | None,
    *,
    verdict: str | None = None,
    relation: str | None = None,
    family: str | None = None,
    basis: list[str] | None = None,
) -> dict:
    """A single finding dict, the shape `record.py._finding_block` emits, for a
    test that wants more than one finding on a record or a finding with no
    `verdict` at all (a purely informational rule such as WHEEL_GENERATOR) --
    `html_record` always builds exactly one, verdict-bearing finding, which
    cannot exercise either case."""
    return {
        "rule_id": rule_id,
        "subject": subject,
        "subject_kind": "library",
        "severity": "medium",
        "category": "bundled-crypto",
        "layer": "binary",
        "confidence": "high",
        "verdict": verdict,
        "relation": relation,
        "basis": basis or [],
        "family": family,
        "needs_human_review": False,
        "occurrences": 1,
        "truncated": False,
        "locations": [{"path": str(subject), "line": None, "evidence": subject}],
    }


# --- onboarding dialog ---------------------------------------------------------


def test_html_has_intro_dialog_and_no_legacy_legend_accordion() -> None:
    """The onboarding dialog sits in the static markup, covered by the same
    ASCII/no-compliance-language scans that already cover the whole page, and the
    accordion it replaces is gone rather than left as dead markup beside it."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    assert '<dialog id="intro" aria-labelledby="intro-title">' in page
    assert 'id="intro-dismiss" checked' in page
    assert 'id="help-open"' in page
    assert "<details" not in page
    assert "Legend and column help" not in page


def test_browser_intro_auto_opens_on_first_visit_with_records(tmp_path: Path) -> None:
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    dom = _render_in_browser(tmp_path, page, extra_script=_INTRO_OPEN_SCRIPT)
    assert _title(dom) == "true"


def test_browser_intro_does_not_auto_open_with_a_wheel_hash(tmp_path: Path) -> None:
    """Someone was sent a link straight to a wheel's evidence; the onboarding
    dialog must not cover it up."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    dom = _render_in_browser(
        tmp_path,
        page,
        fragment="wheel=0",
        extra_script="document.title = String(document.getElementById('intro').open);",
    )
    assert _title(dom) == "false"


def test_browser_intro_does_not_auto_open_on_an_empty_run(tmp_path: Path) -> None:
    ruleset = load_ruleset(None)
    page = render_html([], ruleset)
    dom = _render_in_browser(tmp_path, page, extra_script=_INTRO_OPEN_SCRIPT)
    assert _title(dom) == "false"


def test_browser_intro_checkbox_defaults_to_checked_on_a_first_visit(tmp_path: Path) -> None:
    """Never decided (no stored preference at all) defaults to showing the checkbox
    checked, matching the static markup's own `checked` attribute -- reading it back
    needs no wait, since `openIntro` sets it synchronously within the same click
    handler that opens the dialog."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "document.getElementById('help-open').click();"
        "document.title = String(document.getElementById('intro-dismiss').checked);"
    )
    dom = _render_in_browser(tmp_path, page, fragment="wheel=0", extra_script=script)
    assert _title(dom) == "true"


def test_browser_intro_checking_and_closing_stores_dismissed(tmp_path: Path) -> None:
    """Checking the box and closing writes "dismissed" to storage.

    A native `<dialog>`'s "close" event fires as a queued task, not inline with
    the call that closes it (confirmed against a real browser, not only reasoned
    from the spec), so this waits on the page's own listener -- the one that
    writes storage -- via a second listener on the same event rather than
    reading storage right after the closing click. `localStorage.getItem` itself
    is a synchronous read once that listener has run, so no further wait is
    needed to observe what it wrote."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "var intro = document.getElementById('intro');"
        "intro.addEventListener('close', function () {"
        "  document.title = String(window.localStorage.getItem('wcs-intro'));"
        "});"
        "document.getElementById('help-open').click();"
        "document.getElementById('intro-dismiss').checked = true;"
        "document.getElementById('intro-close').click();"
    )
    dom = _render_in_browser(
        tmp_path, page, fragment="wheel=0", extra_script=script, virtual_time_budget=1000
    )
    assert _title(dom) == "dismissed"


def test_browser_intro_reopens_checked_when_stored_choice_is_dismissed(tmp_path: Path) -> None:
    """A dialog reopened with `wcs-intro` already "dismissed" in storage shows the
    checkbox checked -- reflecting the currently stored preference, not a fixed
    default -- and unchecking it and closing stores "keep" instead, in the same
    render (one close event, not chained off a prior one)."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    rigged = _seed_script(page, "window.localStorage.setItem('wcs-intro', 'dismissed');")
    script = (
        "var out = {};"
        "var intro = document.getElementById('intro');"
        "intro.addEventListener('close', function () {"
        "  out.stored = window.localStorage.getItem('wcs-intro');"
        "  document.title = JSON.stringify(out);"
        "});"
        "document.getElementById('help-open').click();"
        "out.checkedOnOpen = document.getElementById('intro-dismiss').checked;"
        "document.getElementById('intro-dismiss').checked = false;"
        "document.getElementById('intro-close').click();"
    )
    dom = _render_in_browser(
        tmp_path, rigged, fragment="wheel=0", extra_script=script, virtual_time_budget=1000
    )
    out = json.loads(_title(dom))
    assert out == {"checkedOnOpen": True, "stored": "keep"}


def test_browser_intro_reopens_unchecked_when_stored_choice_is_keep(tmp_path: Path) -> None:
    """A dialog reopened with `wcs-intro` already "keep" in storage shows the
    checkbox unchecked, needing no wait since reading it back is synchronous."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    rigged = _seed_script(page, "window.localStorage.setItem('wcs-intro', 'keep');")
    script = (
        "document.getElementById('help-open').click();"
        "document.title = String(document.getElementById('intro-dismiss').checked);"
    )
    dom = _render_in_browser(tmp_path, rigged, fragment="wheel=0", extra_script=script)
    assert _title(dom) == "false"


def test_browser_intro_survives_blocked_storage(tmp_path: Path) -> None:
    """A blocked `localStorage` (private browsing, a data: origin) must not stop the
    dialog from auto-opening, or stop the rest of the page from booting: `wcs-intro`
    is read and written through the same try/catch pattern as the theme toggle."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    rigged = _seed_script(
        page,
        "Object.defineProperty(window, 'localStorage', "
        "{ get: function () { throw new DOMException('blocked'); } });",
    )
    script = (
        "var out = {};"
        "out.introOpen = document.getElementById('intro').open;"
        "document.getElementById('intro-dismiss').checked = true;"
        "document.getElementById('intro-close').click();"
        "out.count = document.getElementById('count').textContent;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, rigged, extra_script=script)
    out = json.loads(_title(dom))
    assert out["introOpen"] is True
    assert out["count"] == "1 of 1 wheels"


def test_browser_help_button_reopens_the_last_viewed_tab(tmp_path: Path) -> None:
    """`.click()` on the Reference tab button synthesises a click at (0, 0) -- the
    same coordinates a keyboard activation (Enter/Space) produces in every major
    browser -- so this also stands in for the keyboard case the P0 keyboard-trap
    regression is about: `out.introOpenAfterTabClick` is the guard that fails if
    the dialog's outside-click handler goes back to reading (0, 0) as "outside"
    and closes the dialog on every keyboard interaction inside it."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "var out = {};"
        "document.getElementById('help-open').click();"
        "out.introVisibleFirst = !document.getElementById('intro-panel-intro').hidden;"
        "document.getElementById('intro-tab-reference').click();"
        "out.introOpenAfterTabClick = document.getElementById('intro').open;"
        "out.referenceVisible = !document.getElementById('intro-panel-reference').hidden;"
        "document.getElementById('intro-close').click();"
        "document.getElementById('help-open').click();"
        "out.referenceVisibleOnReopen = !document.getElementById('intro-panel-reference').hidden;"
        "out.introHiddenOnReopen = document.getElementById('intro-panel-intro').hidden;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, fragment="wheel=0", extra_script=script)
    out = json.loads(_title(dom))
    assert out == {
        "introVisibleFirst": True,
        "introOpenAfterTabClick": True,
        "referenceVisible": True,
        "referenceVisibleOnReopen": True,
        "introHiddenOnReopen": True,
    }


def test_browser_intro_backdrop_click_still_closes_the_dialog(tmp_path: Path) -> None:
    """A genuine backdrop click -- `event.target` is the dialog element itself,
    never a child -- still closes the dialog: the P0 fix (`event.target !==
    els.intro`) narrows what counts as "outside", but must not stop recognising
    the one case that always was."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "var intro = document.getElementById('intro');"
        "document.getElementById('help-open').click();"
        "var out = { openBefore: intro.open };"
        "intro.dispatchEvent(new MouseEvent('click', { bubbles: true, clientX: 5, clientY: 5 }));"
        "out.openAfter = intro.open;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, fragment="wheel=0", extra_script=script)
    out = json.loads(_title(dom))
    assert out == {"openBefore": True, "openAfter": False}


def test_browser_reference_tab_carries_the_legend_content(tmp_path: Path) -> None:
    """The Reference tab is the legend's new home: it lists the verdict classes and
    the columns the accordion used to, now inside the Help dialog."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "CONDITIONAL", "bundled")], ruleset)
    dom = _render_in_browser(
        tmp_path,
        page,
        extra_script="document.getElementById('intro-tab-reference').click();",
    )
    assert "Verdict classes" in dom
    assert "OpenSSL linkage" in dom


# --- toolbar help buttons -------------------------------------------------------


def test_browser_toolbar_help_buttons_show_expected_text(tmp_path: Path) -> None:
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "var out = [];"
        "function open(sel) {"
        "  document.querySelector(sel).click();"
        "  out.push(document.getElementById('popover').textContent);"
        "}"
        "open('#class-filter legend .help-btn');"
        "open('#review-group .help-btn');"
        "open('label[for=\"linkage-filter\"] .help-btn');"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, fragment="wheel=0", extra_script=script)
    texts = json.loads(_title(dom))
    assert texts[0].startswith("Keep only wheels whose class badge is one of the ticked")
    assert texts[1].startswith("Keep only wheels a rule flagged for a human look")
    assert texts[2].startswith("Keep only wheels whose conditions.openssl_linkage is this value")


# --- resizable wheel-table columns -----------------------------------------------


def _parse_columns(page: str) -> list[dict]:
    """The COLUMNS array's `key`/`width`/`min` fields, parsed straight out of the
    page's own script rather than restated in the test: the source both
    `test_browser_wheel_table_min_width_matches_the_columns_default_widths` and a
    test that wants to reason about a specific column's default or floor compare
    against, so a COLUMNS edit cannot silently leave the test asserting stale
    arithmetic."""
    script = _js(page)
    match = re.search(r"var COLUMNS = \[(.*?)\];", script, re.DOTALL)
    assert match is not None
    columns = []
    for entry in re.findall(r"\{[^{}]*\}", match.group(1)):
        key_match = re.search(r'key:\s*"(\w+)"', entry)
        width_match = re.search(r"width:\s*(\d+)", entry)
        min_match = re.search(r"min:\s*(\d+)", entry)
        assert key_match is not None and min_match is not None
        columns.append(
            {
                "key": key_match.group(1),
                "width": int(width_match.group(1)) if width_match else None,
                "min": int(min_match.group(1)),
            }
        )
    return columns


def test_html_wheel_table_layout_is_fixed_with_no_static_min_width() -> None:
    """`table-layout: fixed` is static CSS; `min-width` is not -- it is computed at
    view time from COLUMNS (see the browser test below), so the static rule never
    carries a second number that could drift from what the script actually
    computes."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    css = _css(page)
    match = re.search(r"#wheel-table\s*\{([^}]*)\}", css)
    assert match is not None
    assert "table-layout: fixed" in match.group(1)
    assert "min-width" not in match.group(1)


def test_browser_wheel_table_min_width_matches_the_columns_default_widths(
    tmp_path: Path,
) -> None:
    """The table's computed `min-width` at boot is the sum of every fixed column's
    own default `width` plus the flex column's (`reasons`) `min`: self-consistent
    with COLUMNS, the way a number restated by hand in a test could drift from it
    without either one failing to parse."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    columns = _parse_columns(page)
    expected = sum(
        column["width"] if column["width"] is not None else column["min"] for column in columns
    )
    dom = _render_in_browser(
        tmp_path,
        page,
        extra_script="document.title = document.getElementById('wheel-table').style.minWidth;",
    )
    assert _title(dom) == f"{expected}px"


def test_browser_wheel_table_fits_a_1280px_wide_window_with_no_horizontal_scroll(
    tmp_path: Path,
) -> None:
    """A common 1280px-wide laptop window shows the table with no horizontal
    scrollbar before any user resizing -- parity with the table this feature
    replaced, which fit the same width.

    Measured against `.table-scroll`, the element the wheel table's own
    horizontal scrollbar actually appears on, not `document.documentElement`:
    `.table-scroll` has its own `overflow-x: auto`, so an over-wide table gets
    contained there and never widens the outer page at all -- confirmed
    empirically (`document.documentElement.scrollWidth` reads equal to
    `clientWidth` at this window size both before and after this fix, while
    `.table-scroll`'s own `scrollWidth` reads 1310 (over) before it and 1246 (at
    or under) after -- the real signal the reviewer's own repro was pointing at."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    dom = _render_in_browser(
        tmp_path,
        page,
        window_size="1280,900",
        extra_script=(
            "var scroll = document.querySelector('.table-scroll');"
            "document.title = JSON.stringify({"
            " scrollWidth: scroll.scrollWidth,"
            " clientWidth: scroll.clientWidth"
            "});"
        ),
    )
    out = json.loads(_title(dom))
    assert out["scrollWidth"] <= out["clientWidth"]


def test_browser_column_resize_via_pointer_updates_the_col_width(tmp_path: Path) -> None:
    """A pointer drag on the filename column's resize handle updates that column's
    `<col>` width live, by the pointer's movement from the drag's start, and shows
    `Reset columns` once a width no longer matches the default. Native pointer
    capture requires a trusted, hardware-originated pointer that headless Chrome
    never creates for a scripted `PointerEvent`, so this stands in a same-origin
    polyfill that tracks capture the way the browser would, letting the handler's
    own `hasPointerCapture` check pass the way it does for a real drag."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "Element.prototype.setPointerCapture = function (id) { this._captured = id; };"
        "Element.prototype.hasPointerCapture = function (id) { return this._captured === id; };"
        "Element.prototype.releasePointerCapture = function (id) { this._captured = null; };"
        "var handle = document.querySelectorAll('.col-resize-handle')[0];"
        "var down = new PointerEvent('pointerdown', { clientX: 100, pointerId: 1, bubbles: true });"
        "var move = new PointerEvent('pointermove', { clientX: 220, pointerId: 1, bubbles: true });"
        "var up = new PointerEvent('pointerup', { clientX: 220, pointerId: 1, bubbles: true });"
        "handle.dispatchEvent(down);"
        "handle.dispatchEvent(move);"
        "var mid = document.getElementById('wheel-colgroup').children[0].style.width;"
        "handle.dispatchEvent(up);"
        "document.title = JSON.stringify({"
        " mid: mid,"
        " resetHidden: document.getElementById('reset-columns').hidden"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, fragment="wheel=0", extra_script=script)
    out = json.loads(_title(dom))
    assert out["mid"] == "360px"
    assert out["resetHidden"] is False


def test_browser_column_resize_via_keyboard_respects_the_minimum(tmp_path: Path) -> None:
    """Shift+ArrowLeft resizes by 64px per press without any pointer at all, and
    clamps at the column's own minimum rather than going negative: the version
    column defaults to 70px with a 60px floor, so two presses (70 - 64, then
    6 - 64) both land on 60."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "var handle = document.querySelectorAll('.col-resize-handle')[1];"
        "handle.focus();"
        "var press = function () {"
        "  handle.dispatchEvent(new KeyboardEvent('keydown', {"
        "    key: 'ArrowLeft', shiftKey: true, bubbles: true, cancelable: true"
        "  }));"
        "};"
        "press(); press();"
        "document.title = document.getElementById('wheel-colgroup').children[1].style.width;"
    )
    dom = _render_in_browser(tmp_path, page, fragment="wheel=0", extra_script=script)
    assert _title(dom) == "60px"


def test_browser_column_resize_clamps_at_the_ceiling_and_survives_a_reload(
    tmp_path: Path,
) -> None:
    """A drag past 2000px clamps live, during the drag itself, not only once
    persisted: the write path (`setWidth`) shares the same `MAX_COLUMN_WIDTH` the
    storage read path already validated against, so a width the UI lets a user
    create can never fail that validation on the next load and silently revert to
    the default with no indication why."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "Element.prototype.setPointerCapture = function (id) { this._captured = id; };"
        "Element.prototype.hasPointerCapture = function (id) { return this._captured === id; };"
        "Element.prototype.releasePointerCapture = function (id) { this._captured = null; };"
        "var handle = document.querySelectorAll('.col-resize-handle')[0];"
        "var down = new PointerEvent('pointerdown', { clientX: 100, pointerId: 1, bubbles: true });"
        "var move = new PointerEvent('pointermove', { clientX: 5e3, pointerId: 1, bubbles: true });"
        "var up = new PointerEvent('pointerup', { clientX: 5e3, pointerId: 1, bubbles: true });"
        "handle.dispatchEvent(down);"
        "handle.dispatchEvent(move);"
        "var duringDrag = document.getElementById('wheel-colgroup').children[0].style.width;"
        "handle.dispatchEvent(up);"
        "document.title = JSON.stringify({"
        " duringDrag: duringDrag,"
        " stored: window.localStorage.getItem('wcs-column-widths')"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, fragment="wheel=0", extra_script=script)
    out = json.loads(_title(dom))
    assert out["duringDrag"] == "2000px"
    assert json.loads(out["stored"]) == {"filename": 2000}

    # The value the drag actually saved -- at the ceiling, not above it -- boots
    # back at the same width rather than failing the storage read's own
    # validation and silently resetting to the default.
    seed = f"window.localStorage.setItem('wcs-column-widths', {out['stored']!r});"
    rigged = _seed_script(page, seed)
    reloaded = _render_in_browser(tmp_path, rigged, extra_script=_FILENAME_COL_WIDTH_SCRIPT)
    assert _title(reloaded) == "2000px"


def test_browser_column_width_restored_from_storage_at_boot(tmp_path: Path) -> None:
    """A valid stored width is applied to its column at boot; an out-of-range value
    (below that column's minimum) and an unrecognised column key are both ignored,
    falling back to the default -- validated per SPEC, not merely parsed."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    rigged = _seed_script(
        page,
        "window.localStorage.setItem('wcs-column-widths', "
        "JSON.stringify({ filename: 400, version: 5, bogus: 999 }));",
    )
    dom = _render_in_browser(
        tmp_path,
        rigged,
        extra_script=(
            "document.title = JSON.stringify(["
            " document.getElementById('wheel-colgroup').children[0].style.width,"
            " document.getElementById('wheel-colgroup').children[1].style.width"
            "]);"
        ),
    )
    widths = json.loads(_title(dom))
    assert widths == ["400px", "70px"]


def test_browser_column_widths_garbage_storage_does_not_throw(tmp_path: Path) -> None:
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    rigged = _seed_script(page, "window.localStorage.setItem('wcs-column-widths', 'not json{{');")
    dom = _render_in_browser(tmp_path, rigged, extra_script=_FILENAME_COL_WIDTH_SCRIPT)
    assert _title(dom) == "240px"


def test_browser_reset_columns_restores_defaults_and_hides_itself(tmp_path: Path) -> None:
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    rigged = _seed_script(
        page, "window.localStorage.setItem('wcs-column-widths', JSON.stringify({ filename: 400 }));"
    )
    script = (
        "var out = {};"
        "out.widthBefore = document.getElementById('wheel-colgroup').children[0].style.width;"
        "out.resetHiddenBefore = document.getElementById('reset-columns').hidden;"
        "document.getElementById('reset-columns').click();"
        "out.widthAfter = document.getElementById('wheel-colgroup').children[0].style.width;"
        "out.resetHiddenAfter = document.getElementById('reset-columns').hidden;"
        "out.storedAfter = window.localStorage.getItem('wcs-column-widths');"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, rigged, fragment="wheel=0", extra_script=script)
    out = json.loads(_title(dom))
    assert out["widthBefore"] == "400px"
    assert out["resetHiddenBefore"] is False
    assert out["widthAfter"] == "240px"
    assert out["resetHiddenAfter"] is True
    assert out["storedAfter"] is None


def test_browser_resize_handle_hit_area_spans_its_full_declared_width(tmp_path: Path) -> None:
    """The handle is `right: -5px; width: 10px` on a `th` with `position:
    relative`, straddling the column boundary -- the trailing half of that box
    falls inside the next `<th>`, which (by normal DOM paint order, absent a
    `z-index`) would otherwise win hit-testing there, shrinking the effective
    target to about half its declared width. Checked the way the reviewer who
    found the regression did: `elementFromPoint` across the handle's full
    `getBoundingClientRect()`, at both ends, not only its centre."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "var handle = document.querySelectorAll('.col-resize-handle')[0];"
        "var rect = handle.getBoundingClientRect();"
        "var y = rect.top + rect.height / 2;"
        "var leftEdge = document.elementFromPoint(rect.left + 1, y) === handle;"
        "var rightEdge = document.elementFromPoint(rect.right - 1, y) === handle;"
        "document.title = JSON.stringify({ leftEdge: leftEdge, rightEdge: rightEdge });"
    )
    # A recognised, harmless hash param so the onboarding dialog does not auto-open
    # and intercept every point on the page for elementFromPoint.
    dom = _render_in_browser(tmp_path, page, fragment="review=0", extra_script=script)
    out = json.loads(_title(dom))
    assert out["leftEdge"] is True
    assert out["rightEdge"] is True


# --- class summary strip and the "needs review" indicator -------------------------


def test_browser_class_chips_show_counts_and_toggle_the_table(tmp_path: Path) -> None:
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        # Toggling a chip re-renders the whole strip (renderClassChips() rebuilds
        # #class-chips from scratch), so the chip element itself is looked up fresh
        # after every click rather than reused: the pre-click node stays in memory
        # with its old attributes but is no longer in the document.
        "var findChip = function () {"
        "  return Array.prototype.find.call(document.querySelectorAll('.class-chip'), "
        "    function (c) { return c.textContent.indexOf('FIPS_BREAKING') !== -1; });"
        "};"
        "var chip = findChip();"
        "out.countText = chip.querySelector('.count-badge').textContent;"
        "out.pressedBefore = chip.getAttribute('aria-pressed');"
        "out.resetHiddenBefore = document.getElementById('class-reset').hidden;"
        "chip.click();"
        "chip = findChip();"
        "out.pressedAfter = chip.getAttribute('aria-pressed');"
        "out.countAfterToggle = document.getElementById('count').textContent;"
        "out.resetHiddenAfter = document.getElementById('class-reset').hidden;"
        "document.getElementById('class-reset').click();"
        "chip = findChip();"
        "out.pressedAfterReset = chip.getAttribute('aria-pressed');"
        "out.countAfterReset = document.getElementById('count').textContent;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["countText"] == "1"
    assert out["pressedBefore"] == "true"
    assert out["resetHiddenBefore"] is True
    assert out["pressedAfter"] == "false"
    assert out["countAfterToggle"] == "2 of 3 wheels"
    assert out["resetHiddenAfter"] is False
    assert out["pressedAfterReset"] == "true"
    assert out["countAfterReset"] == "3 of 3 wheels"


def test_browser_needs_review_indicator_counts_the_whole_run(tmp_path: Path) -> None:
    """The "needs review" indicator counts every record in the run, not the
    filtered set: it stays put while the class chips above change what the table
    shows."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        "out.before = document.getElementById('review-count').textContent;"
        f"{_find_chip_js('OPAQUE')}.click();"
        "out.countAfterToggle = document.getElementById('count').textContent;"
        "out.after = document.getElementById('review-count').textContent;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["before"] == "needs review: 2"
    # The chip toggle actually changed what the table shows -- otherwise this
    # would hold even if "needs review" secretly counted the filtered set too.
    assert out["countAfterToggle"] == "2 of 3 wheels"
    assert out["after"] == "needs review: 2"


# --- URL hash: filter state and Clear filters --------------------------------------


def test_browser_hash_round_trips_toolbar_filters(tmp_path: Path) -> None:
    """Search, linkage, review-only and an untoggled class all land in the hash as
    `state` changes, and loading a fresh page with that same hash reproduces the
    identical filter state -- a shared or reloaded link shows the same view."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    set_filters = (
        "document.getElementById('search').value = 'openssl';"
        "document.getElementById('search').dispatchEvent(new Event('input'));"
        "document.getElementById('linkage-filter').value = 'bundled';"
        "document.getElementById('linkage-filter').dispatchEvent(new Event('change'));"
        "document.getElementById('review-only').checked = true;"
        "document.getElementById('review-only').dispatchEvent(new Event('change'));"
        f"{_find_chip_js('OPAQUE')}.click();"
        "document.title = window.location.hash;"
    )
    hash_value = _title(_render_in_browser(tmp_path, page, extra_script=set_filters))
    assert hash_value.startswith("#")
    assert "q=openssl" in hash_value
    assert "linkage=bundled" in hash_value
    assert "review=1" in hash_value
    assert "class=" in hash_value
    assert "OPAQUE" not in hash_value.split("class=", 1)[1].split("&", 1)[0]

    fragment = hash_value[1:]
    read_back = (
        "document.title = JSON.stringify({"
        " search: document.getElementById('search').value,"
        " linkage: document.getElementById('linkage-filter').value,"
        " review: document.getElementById('review-only').checked,"
        f" opaquePressed: {_find_chip_js('OPAQUE')}.getAttribute('aria-pressed')"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, fragment=fragment, extra_script=read_back)
    out = json.loads(_title(dom))
    expected = {"search": "openssl", "linkage": "bundled", "review": True, "opaquePressed": "false"}
    assert out == expected


def test_browser_stale_class_token_in_hash_still_filters_and_says_so(tmp_path: Path) -> None:
    """`#class=<5 real classes>,UNKNOWN_TOKEN` -- one real class (OPAQUE) swapped
    for a bogus token, so the hash still names as many tokens as `DATA.classes`
    holds -- must still hide the OPAQUE wheel (`b`) *and* show "Clear filters" and
    the class-strip's "all" reset chip, so nothing on screen tells the reader a
    filter is silently active. Checking count alone against `DATA.classes.length`
    (rather than membership) reads this as "every class ticked" and hides both
    affordances even though a class is actively excluded."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    dom = _render_in_browser(
        tmp_path,
        page,
        fragment="class=NON_APPROVED_CRYPTO,FIPS_BREAKING,CONDITIONAL,CONTEXT_DEPENDENT,NO_CRYPTO_DETECTED,UNKNOWN_TOKEN",
        extra_script=(
            "document.title = JSON.stringify({"
            " count: document.getElementById('count').textContent,"
            " clearHidden: document.getElementById('clear-filters').hidden,"
            " classResetHidden: document.getElementById('class-reset').hidden"
            "});"
        ),
    )
    out = json.loads(_title(dom))
    assert out["count"] == "2 of 3 wheels"
    assert out["clearHidden"] is False
    assert out["classResetHidden"] is False


def test_browser_unknown_class_token_is_dropped_not_counted_toward_default(
    tmp_path: Path,
) -> None:
    """`#class=<all 6 real classes>,UNKNOWN_TOKEN` -- every real class ticked, plus
    one bogus token along for the ride -- must read as the default (every class
    shown, "Clear filters" and the reset chip both hidden), since the bogus token
    names nothing this report actually classifies. Keeping an un-intersected token
    in `state.classes` inflates its size past `DATA.classes.length` and misreads a
    fully-default filter as active."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    dom = _render_in_browser(
        tmp_path,
        page,
        fragment=(
            "class=NON_APPROVED_CRYPTO,FIPS_BREAKING,CONDITIONAL,CONTEXT_DEPENDENT,"
            "OPAQUE,NO_CRYPTO_DETECTED,UNKNOWN_TOKEN"
        ),
        extra_script=(
            "document.title = JSON.stringify({"
            " count: document.getElementById('count').textContent,"
            " clearHidden: document.getElementById('clear-filters').hidden,"
            " classResetHidden: document.getElementById('class-reset').hidden"
            "});"
        ),
    )
    out = json.loads(_title(dom))
    assert out["count"] == "3 of 3 wheels"
    assert out["clearHidden"] is True
    assert out["classResetHidden"] is True


def test_browser_wheel_param_merges_with_existing_filter_params(tmp_path: Path) -> None:
    """Opening a wheel from a filtered table adds `wheel=` to the hash's existing
    filter params rather than overwriting them, and closing the panel again strips
    only `wheel=`, leaving the filters in place."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "document.getElementById('search').value = 'openssl';"
        "document.getElementById('search').dispatchEvent(new Event('input'));"
        "document.querySelectorAll('#wheel-rows tr')[0].click();"
        "var withWheel = window.location.hash;"
        "document.getElementById('detail-close').click();"
        "var afterClose = window.location.hash;"
        "document.title = JSON.stringify({ withWheel: withWheel, afterClose: afterClose });"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert "q=openssl" in out["withWheel"]
    assert re.search(r"(?:^|&)wheel=\d+", out["withWheel"].lstrip("#"))
    assert "q=openssl" in out["afterClose"]
    assert "wheel=" not in out["afterClose"]


def test_browser_clear_filters_resets_state_and_hash(tmp_path: Path) -> None:
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        "document.getElementById('search').value = 'a';"
        "document.getElementById('search').dispatchEvent(new Event('input'));"
        "out.clearHiddenBefore = document.getElementById('clear-filters').hidden;"
        "document.getElementById('clear-filters').click();"
        "out.searchAfter = document.getElementById('search').value;"
        "out.hashAfter = window.location.hash;"
        "out.clearHiddenAfter = document.getElementById('clear-filters').hidden;"
        "out.countAfter = document.getElementById('count').textContent;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["clearHiddenBefore"] is False
    assert out["searchAfter"] == ""
    assert out["hashAfter"] in ("", "#")
    assert out["clearHiddenAfter"] is True
    assert out["countAfter"] == "3 of 3 wheels"


def test_browser_hashchange_resets_a_filter_the_new_hash_omits(tmp_path: Path) -> None:
    """Applying a hash is total, not a merge: a search set through the toolbar
    (`q=openssl`), then navigating (via `hashchange`, not a fresh boot) to a plain
    `#wheel=1` link that never mentions `q=` at all, clears the search rather than
    keeping it active under a URL that no longer claims it is."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        "document.getElementById('search').value = 'openssl';"
        "document.getElementById('search').dispatchEvent(new Event('input'));"
        "out.hashBefore = window.location.hash;"
        "window.addEventListener('hashchange', function () {"
        "  out.searchAfter = document.getElementById('search').value;"
        "  out.countAfter = document.getElementById('count').textContent;"
        "  out.detailTitleAfter = document.getElementById('detail-title').textContent;"
        "  document.getElementById('detail-close').click();"
        "  out.hashAfterClose = window.location.hash;"
        "  document.title = JSON.stringify(out);"
        "});"
        "window.location.hash = 'wheel=1';"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["hashBefore"] == "#q=openssl"
    assert out["searchAfter"] == ""
    assert out["countAfter"] == "3 of 3 wheels"
    assert out["detailTitleAfter"] == "b-1.0-py3-none-any.whl"
    # Closing the panel resyncs the hash from `state`: the search the colleague's
    # link never carried must not reappear in it now either.
    assert "q=" not in out["hashAfterClose"]


def test_browser_view_hash_round_trips_the_rules_tab(tmp_path: Path) -> None:
    """Switching to the Rules tab writes `view=rules` into the hash -- the one
    piece of top-level page state (Wheels vs Rules) the hash grammar otherwise
    leaves uncovered -- and a fresh load with that hash opens directly to the
    Rules view, no click needed, the same shareable-link behaviour the toolbar's
    own filter params already get."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "document.getElementById('view-tab-rules').click();document.title = window.location.hash;"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    assert _title(dom) == "#view=rules"

    reloaded = _render_in_browser(
        tmp_path,
        page,
        fragment="view=rules",
        extra_script=(
            "document.title = JSON.stringify({"
            " wheelsHidden: document.getElementById('view-wheels').hidden,"
            " rulesHidden: document.getElementById('view-rules').hidden,"
            " rulesTabSelected: "
            "   document.getElementById('view-tab-rules').getAttribute('aria-selected')"
            "});"
        ),
    )
    out = json.loads(_title(reloaded))
    assert out == {"wheelsHidden": True, "rulesHidden": False, "rulesTabSelected": "true"}


def test_browser_hashchange_resets_the_view_the_new_hash_omits(tmp_path: Path) -> None:
    """Total, not a merge, the same discipline the toolbar's filter params get:
    switching to Rules, then navigating (via `hashchange`) to a hash that never
    mentions `view=` at all, falls back to Wheels rather than staying on Rules
    under a URL that no longer claims it."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "document.getElementById('view-tab-rules').click();"
        "window.addEventListener('hashchange', function () {"
        "  document.title = JSON.stringify({"
        "    wheelsHidden: document.getElementById('view-wheels').hidden,"
        "    rulesHidden: document.getElementById('view-rules').hidden"
        "  });"
        "});"
        "window.location.hash = 'q=openssl';"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out == {"wheelsHidden": False, "rulesHidden": True}


def test_browser_all_classes_unticked_round_trips_through_the_hash(tmp_path: Path) -> None:
    """Every class chip unticked is a real, reachable, intentional state -- the
    table shows "0 of N wheels" and "Clear filters" -- whose `class` value happens
    to be the empty string. The hash must carry `class=` (present, empty) rather
    than omit the param entirely and have a reload silently re-tick every class."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    untick_all = (
        "var chip = document.querySelector('.class-chip[aria-pressed=\"true\"]');"
        "while (chip) {"
        "  chip.click();"
        "  chip = document.querySelector('.class-chip[aria-pressed=\"true\"]');"
        "}"
    )
    script = (
        f"{untick_all}"
        "document.title = JSON.stringify({"
        " hash: window.location.hash,"
        " count: document.getElementById('count').textContent"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["hash"] == "#class="
    assert out["count"] == "0 of 3 wheels"

    # Reloading that exact hash must reproduce zero classes selected, not silently
    # fall back to "no filter" and re-tick every class.
    reloaded = _render_in_browser(
        tmp_path,
        page,
        fragment="class=",
        extra_script=(
            "document.title = JSON.stringify({"
            " count: document.getElementById('count').textContent,"
            " anyPressed: !!document.querySelector('.class-chip[aria-pressed=\"true\"]')"
            "});"
        ),
    )
    reloaded_out = json.loads(_title(reloaded))
    assert reloaded_out["count"] == "0 of 3 wheels"
    assert reloaded_out["anyPressed"] is False


# --- detail panel Previous/Next navigation -----------------------------------------


def test_browser_prev_next_step_through_the_filtered_set_and_disable_at_ends(
    tmp_path: Path,
) -> None:
    """Filtering to "needs review only" excludes the OPAQUE middle record (`b`,
    `needs_human_review: false`); stepping Next from `a` lands on `c`, skipping over
    it, and each end disables the button that would step past it."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        "document.getElementById('review-only').checked = true;"
        "document.getElementById('review-only').dispatchEvent(new Event('change'));"
        "document.querySelectorAll('#wheel-rows tr')[0].click();"
        "out.firstTitle = document.getElementById('detail-title').textContent;"
        "out.firstPosition = document.getElementById('detail-position').textContent;"
        "out.prevDisabledFirst = document.getElementById('detail-prev').disabled;"
        "out.nextDisabledFirst = document.getElementById('detail-next').disabled;"
        "document.getElementById('detail-next').click();"
        "out.secondTitle = document.getElementById('detail-title').textContent;"
        "out.secondPosition = document.getElementById('detail-position').textContent;"
        "out.prevDisabledSecond = document.getElementById('detail-prev').disabled;"
        "out.nextDisabledSecond = document.getElementById('detail-next').disabled;"
        "document.getElementById('detail-prev').click();"
        "out.thirdTitle = document.getElementById('detail-title').textContent;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["firstTitle"] == "a-1.0-py3-none-any.whl"
    assert out["firstPosition"] == "1 of 2"
    assert out["prevDisabledFirst"] is True
    assert out["nextDisabledFirst"] is False
    assert out["secondTitle"] == "c-1.0-py3-none-any.whl"
    assert out["secondPosition"] == "2 of 2"
    assert out["prevDisabledSecond"] is False
    assert out["nextDisabledSecond"] is True
    assert out["thirdTitle"] == "a-1.0-py3-none-any.whl"


def test_browser_prev_next_hides_when_the_open_record_leaves_the_filtered_set(
    tmp_path: Path,
) -> None:
    """Opening `b` (not flagged for review) and then turning on "needs review
    only" drops `b` out of the visible set the nav steps through; the nav hides
    rather than showing a position or Next/Previous that no longer means anything."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        "out.navHiddenBefore = document.getElementById('detail-nav').hidden;"
        "document.getElementById('review-only').checked = true;"
        "document.getElementById('review-only').dispatchEvent(new Event('change'));"
        "out.navHiddenAfter = document.getElementById('detail-nav').hidden;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, fragment="wheel=1", extra_script=script)
    out = json.loads(_title(dom))
    assert out["navHiddenBefore"] is False
    assert out["navHiddenAfter"] is True


def test_browser_arrow_key_on_a_detail_tab_button_does_not_step_the_wheel(
    tmp_path: Path,
) -> None:
    """ArrowRight/Left are reserved by the ARIA tab pattern for moving between the
    detail panel's own tab buttons (`role="tab"` inside `role="tablist"`): the
    document-level Previous/Next handler must skip a press while one of those
    buttons is focused, rather than stepping to the next wheel record and
    rebuilding the tab strip out from under the very button that had focus."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        "var tabBtn = document.querySelectorAll('#tabs button')[1];"
        "tabBtn.focus();"
        "out.positionBefore = document.getElementById('detail-position').textContent;"
        "tabBtn.dispatchEvent(new KeyboardEvent('keydown', {"
        "  key: 'ArrowRight', bubbles: true, cancelable: true"
        "}));"
        "out.positionAfter = document.getElementById('detail-position').textContent;"
        "out.activeIsSameTabButton = document.activeElement === tabBtn;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, fragment="wheel=0", extra_script=script)
    out = json.loads(_title(dom))
    assert out["positionBefore"] == "1 of 3"
    assert out["positionAfter"] == "1 of 3"
    assert out["activeIsSameTabButton"] is True


def test_browser_arrow_key_on_a_focused_resize_handle_does_not_also_step_the_wheel(
    tmp_path: Path,
) -> None:
    """A resize handle can hold focus while the detail panel is open at the same
    time -- the panel is not a native modal and does not trap focus -- so an
    ArrowRight press there must only resize the column, not also advance the
    detail panel to the next wheel: the two handlers must not both act on the
    same key press."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        "var handle = document.querySelectorAll('.col-resize-handle')[0];"
        "handle.focus();"
        "out.positionBefore = document.getElementById('detail-position').textContent;"
        "out.widthBefore = document.getElementById('wheel-colgroup').children[0].style.width;"
        "handle.dispatchEvent(new KeyboardEvent('keydown', {"
        "  key: 'ArrowRight', bubbles: true, cancelable: true"
        "}));"
        "out.positionAfter = document.getElementById('detail-position').textContent;"
        "out.widthAfter = document.getElementById('wheel-colgroup').children[0].style.width;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, fragment="wheel=0", extra_script=script)
    out = json.loads(_title(dom))
    assert out["positionBefore"] == "1 of 3"
    assert out["positionAfter"] == "1 of 3"
    assert out["widthBefore"] == "240px"
    assert out["widthAfter"] == "256px"


def test_browser_pointercancel_mid_drag_persists_the_width_and_shows_reset(
    tmp_path: Path,
) -> None:
    """A `pointercancel` (an OS gesture, a context menu, a touch sequence getting
    interrupted) releases pointer capture without `pointerup` ever firing: the
    visual resize already happened through `pointermove`, so without a
    `pointercancel` listener of its own the width is never saved, and "Reset
    columns" -- whose visibility only `persistColumnWidths` recomputes -- stays
    hidden even though the table is no longer at its defaults."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "Element.prototype.setPointerCapture = function (id) { this._captured = id; };"
        "Element.prototype.hasPointerCapture = function (id) { return this._captured === id; };"
        "Element.prototype.releasePointerCapture = function (id) { this._captured = null; };"
        "var handle = document.querySelectorAll('.col-resize-handle')[0];"
        "var down = new PointerEvent('pointerdown', { clientX: 100, pointerId: 1, bubbles: true });"
        "var move = new PointerEvent('pointermove', { clientX: 180, pointerId: 1, bubbles: true });"
        "var cancel = new PointerEvent('pointercancel', { pointerId: 1, bubbles: true });"
        "handle.dispatchEvent(down);"
        "handle.dispatchEvent(move);"
        "handle.dispatchEvent(cancel);"
        "document.title = JSON.stringify({"
        " width: document.getElementById('wheel-colgroup').children[0].style.width,"
        " stored: window.localStorage.getItem('wcs-column-widths'),"
        " resetHidden: document.getElementById('reset-columns').hidden"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["width"] == "320px"
    assert json.loads(out["stored"]) == {"filename": 320}
    assert out["resetHidden"] is False


# --- Rules view -----------------------------------------------------------------


def test_browser_rules_tab_lists_a_known_rule_and_clicking_it_filters_wheels(
    tmp_path: Path,
) -> None:
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        "document.getElementById('view-tab-rules').click();"
        "out.wheelsHiddenOnRules = document.getElementById('view-wheels').hidden;"
        "out.rulesTableText = document.getElementById('rules-rows').textContent;"
        "var link = Array.prototype.find.call(document.querySelectorAll('.rule-link'), "
        "  function (b) { return b.textContent === 'PY_WEAK_HASH_CALL'; });"
        "link.click();"
        "var wheelsTab = document.getElementById('view-tab-wheels');"
        "out.viewAfterClick = wheelsTab.getAttribute('aria-selected');"
        "out.rulesHiddenAfterClick = document.getElementById('view-rules').hidden;"
        "out.searchAfterClick = document.getElementById('search').value;"
        "out.countAfterClick = document.getElementById('count').textContent;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["wheelsHiddenOnRules"] is True
    assert "PY_WEAK_HASH_CALL" in out["rulesTableText"]
    assert "WHEEL_UNREADABLE" in out["rulesTableText"]
    assert "BIN_BUNDLED_OPENSSL" in out["rulesTableText"]
    assert out["viewAfterClick"] == "true"
    assert out["rulesHiddenAfterClick"] is True
    assert out["searchAfterClick"] == "PY_WEAK_HASH_CALL"
    assert out["countAfterClick"] == "1 of 3 wheels"


def test_browser_rules_tab_shows_fired_counts_and_basis_chips(tmp_path: Path) -> None:
    """The "fired" count is distinct wheels, not distinct reasons, and counts a
    rule whose finding carries no `verdict` at all (informational, such as
    WHEEL_GENERATOR) the same as any other -- neither is true of a count built by
    scanning `verdict.reasons`, which never lists a verdict-less rule and lists a
    rule once per `(rule_id, subject)` pair rather than once per wheel."""
    ruleset = load_ruleset(None)

    # Two findings, same rule, two different subjects on one wheel: fired once,
    # not twice, since "fired" means "this wheel", not "this reason".
    two_subjects = html_record("d", "CONDITIONAL", "bundled")
    two_subjects["verdict"]["rule_ids"] = ["BIN_BUNDLED_OPENSSL"]
    two_subjects["verdict"]["reasons"] = [
        "BIN_BUNDLED_OPENSSL: libcrypto.so",
        "BIN_BUNDLED_OPENSSL: libssl.so",
    ]
    two_subjects["findings"] = [
        _finding(
            "BIN_BUNDLED_OPENSSL",
            "libcrypto.so",
            verdict="CONDITIONAL",
            relation="boundary_unresolved",
            family="library",
            basis=["FIPS-140-3"],
        ),
        _finding(
            "BIN_BUNDLED_OPENSSL",
            "libssl.so",
            verdict="CONDITIONAL",
            relation="boundary_unresolved",
            family="library",
            basis=["FIPS-140-3"],
        ),
    ]

    # A purely informational finding: no `verdict`, so `classify()` never puts its
    # rule id in `verdict.rule_ids` or a reason string in `verdict.reasons` --
    # `findings[].rule_id` is the only place this wheel's fired rule shows up.
    informational_only = html_record("e", "NO_CRYPTO_DETECTED", "none", review=False)
    informational_only["verdict"]["rule_ids"] = []
    informational_only["verdict"]["reasons"] = []
    informational_only["findings"] = [_finding("WHEEL_GENERATOR", "maturin")]

    # A plain, single-finding control: fired count should read 1, the same as
    # every other row here, so a broken counter that always reads 0 or always
    # reads the same wrong number for every rule cannot pass by accident.
    control = html_record("f", "NON_APPROVED_CRYPTO", "static", rule_id="PY_WEAK_HASH_CALL")

    page = render_html([two_subjects, informational_only, control], ruleset)
    script = (
        "function ruleRowCount(id) {"
        "  var link = Array.prototype.find.call(document.querySelectorAll('.rule-link'), "
        "    function (b) { return b.textContent === id; });"
        "  var tr = link.closest('tr');"
        "  return tr.children[tr.children.length - 1].textContent;"
        "}"
        "document.getElementById('view-tab-rules').click();"
        "document.title = JSON.stringify({"
        " bundled: ruleRowCount('BIN_BUNDLED_OPENSSL'),"
        " generator: ruleRowCount('WHEEL_GENERATOR'),"
        " weakHash: ruleRowCount('PY_WEAK_HASH_CALL')"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["bundled"] == "1"
    assert out["generator"] == "1"
    assert out["weakHash"] == "1"

    rows_html = dom[dom.index('<tbody id="rules-rows"') :]
    assert "FIPS-140-3" in rows_html


def test_browser_rules_click_through_is_exact_not_a_prefix_substring_match(
    tmp_path: Path,
) -> None:
    """`BIN_AWS_LC` is a prefix of `BIN_AWS_LC_FIPS`, a real pair the shipped
    ruleset defines: clicking the `BIN_AWS_LC` row must show only the wheel that
    actually fired `BIN_AWS_LC`, not one that only ever fired `BIN_AWS_LC_FIPS`,
    which a search box doing substring matching against `reasons.join(" ")` would
    also match."""
    ruleset = load_ruleset(None)
    plain = html_record("g", "NON_APPROVED_CRYPTO", "static", rule_id="BIN_AWS_LC")
    fips_build = html_record("h", "CONDITIONAL", "static", rule_id="BIN_AWS_LC_FIPS")
    page = render_html([plain, fips_build], ruleset)
    script = (
        "document.getElementById('view-tab-rules').click();"
        "var link = Array.prototype.find.call(document.querySelectorAll('.rule-link'), "
        "  function (b) { return b.textContent === 'BIN_AWS_LC'; });"
        "link.click();"
        "document.title = JSON.stringify({"
        " count: document.getElementById('count').textContent,"
        " filenames: Array.prototype.map.call("
        "   document.querySelectorAll('#wheel-rows td.wheel-cell'), "
        "   function (td) { return td.textContent; })"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["count"] == "1 of 2 wheels"
    assert out["filenames"] == ["g-1.0-py3-none-any.whl"]


def test_browser_rules_table_columns_have_help_buttons(tmp_path: Path) -> None:
    """The intro dialog's own copy claims "Every column and filter has a '?'
    beside it" -- true only once the Rules table's columns carry one too, the
    same `makeHelpButton`/popover pattern the wheel table already uses."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "document.getElementById('view-tab-rules').click();"
        "var buttons = document.querySelectorAll('#rules-header-row .help-btn');"
        "var out = { buttonCount: buttons.length };"
        "buttons[0].click();"
        "out.firstPopoverText = document.getElementById('popover').textContent;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["buttonCount"] == len(
        ["id", "title", "why", "verdict", "severity", "family", "relation", "basis", "count"]
    )
    assert out["firstPopoverText"] != ""
