"""Human-readable views of the records: the Markdown table and the self-contained HTML page."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import html
import inspect
import json
import os
import re
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
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
    allow_network: bool = False,
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
    explicit budget instead.

    `allow_network` defaults to False: `--host-resolver-rules=MAP * ~NOTFOUND` sends
    every hostname Chrome tries to resolve, the report's pinned DataTables script
    included, to an address nothing answers, immediately and without a real lookup,
    the same view of the page a browser with no connection gets. Every test but the
    ones marked `network` renders this way, so the report's own DataTables
    enhancement -- which only ever runs once that script has loaded -- never runs
    during the offline suite, and a test proving the native-table fallback needs no
    real network outage to do it. A `network`-marked test passes True to reach the
    real, pinned script instead. On that path, a missing browser fails rather than
    skips when WCS_REQUIRE_NETWORK is set too: the flag exists to turn a `network`
    test silently not running into a red CI job, and a host with the CDN reachable
    but no browser at all would otherwise still report those tests as skipped."""
    binary = _chrome_binary()
    if binary is None:
        message = "no headless-capable browser (google-chrome/chromium) on this host"
        if allow_network and os.environ.get("WCS_REQUIRE_NETWORK"):
            pytest.fail(message + " and WCS_REQUIRE_NETWORK is set")
        pytest.skip(message)
    if extra_script:
        page = page.replace("</body>", f"<script>{extra_script}</script></body>")
    path = tmp_path / "page.html"
    path.write_text(page, encoding="utf-8")
    url = f"file://{path}#{fragment}" if fragment else f"file://{path}"
    size = [f"--window-size={window_size}"] if window_size else []
    budget = [f"--virtual-time-budget={virtual_time_budget}"] if virtual_time_budget else []
    network = [] if allow_network else ["--host-resolver-rules=MAP * ~NOTFOUND"]
    result = subprocess.run(
        [
            binary,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            *size,
            *budget,
            *network,
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


def test_html_loads_only_the_pinned_datatables_script() -> None:
    """The page's one external asset is one pinned, integrity-checked CDN script for
    DataTables: no stylesheet `<link`, no `@import`, and no other `src`/`href` names a
    network URL at all."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    assert "<link" not in page
    assert "@import" not in page

    urls = re.findall(r'(?:src|href)\s*=\s*"(https?://[^"]*)"', page)
    assert len(urls) == 1, urls
    assert re.fullmatch(
        r"https://cdn\.jsdelivr\.net/npm/datatables\.net@\d+\.\d+\.\d+/js/dataTables\.min\.js",
        urls[0],
    ), urls[0]

    match = re.search(r'<script\b[^>]*\bsrc="' + re.escape(urls[0]) + r'"[^>]*>', page)
    assert match is not None
    tag = match.group(0)
    assert re.search(r'integrity="sha384-[A-Za-z0-9+/]{64}"', tag), tag
    assert 'crossorigin="anonymous"' in tag
    assert 'referrerpolicy="no-referrer"' in tag
    assert re.search(r"(?<!-)\bdefer\b", tag), tag


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
    assert "EVP_DigestInit (digest; binding: defined)" in binaries_tab


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


def _many_records(count: int) -> list[dict]:
    """`count` distinct wheels, named `wheel-000`, `wheel-001`, ... so their sorted
    order is their index, spread across a few classes and OpenSSL linkages: enough
    rows to force the wheel table into a second page, for a test that checks paging
    or DataTables' own enhancement against a table too big to read by eye."""
    classes = ["CONDITIONAL", "OPAQUE", "FIPS_BREAKING", "NO_CRYPTO_DETECTED"]
    linkages = ["bundled", "none", "static", "system"]
    return [
        record(
            f"wheel-{i:03d}",
            classes[i % len(classes)],
            linkages[i % len(linkages)],
            review=(i % 2 == 0),
        )
        for i in range(count)
    ]


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


def _parse_rules_column_keys(page: str) -> list[str]:
    """`RULES_COLUMNS`' own `key` fields, parsed the same way `_parse_columns`
    parses `COLUMNS`: `extra_script` runs outside the page's own IIFE and cannot
    read `RULES_COLUMNS` itself, so a test script that wants every column key
    needs them handed in from here."""
    script = _js(page)
    match = re.search(r"var RULES_COLUMNS = \[(.*?)\];", script, re.DOTALL)
    assert match is not None
    return re.findall(r'key:\s*"(\w+)"', match.group(1))


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
    assert out["mid"] == "340px"
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
    assert _title(dom) == "220px"


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
    assert out["widthAfter"] == "220px"
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
    """Clear filters must not only empty the visible inputs: typing into a column
    filter again afterwards has to keep working. `state.columnFilters` is a fresh
    object after Clear filters, not the one `renderFilterRow`'s input listeners
    were built against at boot -- if those listeners captured the original object
    instead of reading `state.columnFilters` fresh, a keystroke here would write
    to an object nothing reads any more, and the table would silently stop
    responding to this filter for the rest of the session."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        "document.getElementById('search').value = 'a';"
        "document.getElementById('search').dispatchEvent(new Event('input'));"
        "var librariesFilter = document.querySelector("
        "  '#filter-row .col-filter[data-key=\"libraries\"]');"
        "librariesFilter.value = 'bundled';"
        "librariesFilter.dispatchEvent(new Event('input'));"
        "out.clearHiddenBefore = document.getElementById('clear-filters').hidden;"
        "document.getElementById('clear-filters').click();"
        "out.searchAfter = document.getElementById('search').value;"
        "out.librariesFilterAfter = librariesFilter.value;"
        "out.hashAfter = window.location.hash;"
        "out.clearHiddenAfter = document.getElementById('clear-filters').hidden;"
        "out.countAfter = document.getElementById('count').textContent;"
        "librariesFilter.value = 'static';"
        "librariesFilter.dispatchEvent(new Event('input'));"
        "out.countAfterRetype = document.getElementById('count').textContent;"
        "out.hashAfterRetype = window.location.hash;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["clearHiddenBefore"] is False
    assert out["searchAfter"] == ""
    assert out["librariesFilterAfter"] == ""
    assert out["hashAfter"] in ("", "#")
    assert "f." not in out["hashAfter"]
    assert out["clearHiddenAfter"] is True
    assert out["countAfter"] == "3 of 3 wheels"
    assert out["countAfterRetype"] == "1 of 3 wheels"
    assert "f.libraries=static" in out["hashAfterRetype"]


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
    assert out["widthBefore"] == "220px"
    assert out["widthAfter"] == "236px"


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
    assert out["width"] == "300px"
    assert json.loads(out["stored"]) == {"filename": 300}
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


def test_browser_rules_tab_shows_wheel_counts_and_basis_chips(tmp_path: Path) -> None:
    """The `wheels` count is distinct wheels, not distinct reasons, and counts a
    rule whose finding carries no `verdict` at all (informational, such as
    WHEEL_GENERATOR) the same as any other -- neither is true of a count built by
    scanning `verdict.reasons`, which never lists a verdict-less rule and lists a
    rule once per `(rule_id, subject)` pair rather than once per wheel."""
    ruleset = load_ruleset(None)

    # Two findings, same rule, two different subjects on one wheel: counted once,
    # not twice, since the `wheels` column means "this wheel", not "this reason".
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

    # A plain, single-finding control: the wheels count should read 1, the same as
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


# --- per-column filters, the openssl column and the class legend ----------------


def test_browser_column_filter_narrows_rows_and_composes_with_toolbar(tmp_path: Path) -> None:
    """A per-column filter narrows the table on its own, matches
    case-insensitively, shows `Clear filters` on its own (with no other filter
    active), and combines with the toolbar's own filters (here, review-only) the
    same way every other filter already does -- a combination that leaves zero
    rows is a reachable state, not a bug."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var out = {};"
        "out.clearHiddenBefore = document.getElementById('clear-filters').hidden;"
        "var filter = document.querySelector('#filter-row .col-filter[data-key=\"filename\"]');"
        "filter.value = 'B-1.0';"
        "filter.dispatchEvent(new Event('input'));"
        "out.afterFilter = document.getElementById('count').textContent;"
        "out.clearHiddenAfterFilter = document.getElementById('clear-filters').hidden;"
        "document.getElementById('review-only').checked = true;"
        "document.getElementById('review-only').dispatchEvent(new Event('change'));"
        "out.afterReviewOnly = document.getElementById('count').textContent;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["clearHiddenBefore"] is True
    assert out["clearHiddenAfterFilter"] is False
    # Record "b" is the only one whose filename starts "b-1.0", and it is the
    # only one of the three not flagged for review.
    assert out["afterFilter"] == "1 of 3 wheels"
    assert out["afterReviewOnly"] == "0 of 3 wheels"


def test_browser_every_column_filter_matches_its_own_cell_text(tmp_path: Path) -> None:
    """Filtering a column by its own full cell text must still show that row: this
    catches drift between `columnText` (what a column filter matches against) and
    `renderRow` (what the cell actually shows), for every filterable column at
    once, over a record with two families, two libraries and two relations so a
    format difference between the two -- a separator `columnText` inserts that the
    cell's own chips do not, say -- cannot hide behind a fixture where "two things
    joined" and "one thing shown" happen to read the same. `reasons` is excluded:
    its own filter deliberately matches the full `verdict.reasons` list rather
    than only the cell's three visible chips, and has its own test. `class`,
    `review` and `openssl` are excluded too, by having no `.col-filter` input to
    find in the first place: they carry `filter: false`. Each filterable column's
    `td` is found by its `<th>`'s own position, not by a position counted only
    across the filterable columns: `renderFilterRow` and `renderRow` both give
    every column, filter or not, exactly one cell, so `class`/`review`/`openssl`
    leave gaps the filterable-only count would not account for, and the two stay
    aligned only by true column position."""
    ruleset = load_ruleset(None)
    rec = html_record("multi", "NON_APPROVED_CRYPTO", "bundled", review=True)
    rec["crypto"]["families"] = ["aead", "hash"]
    rec["crypto"]["libraries"] = [
        {"name": "openssl", "linkage": "bundled"},
        {"name": "boringssl", "linkage": "static"},
    ]
    rec["verdict"]["relations"] = ["boundary_unresolved", "runtime_refusal"]
    page = render_html([rec], ruleset)
    script = (
        "var results = {};"
        "Array.prototype.forEach.call(document.querySelectorAll('#filter-row th'), "
        "  function (th, index) {"
        "    var input = th.querySelector('.col-filter');"
        "    if (!input) return;"
        "    var key = input.getAttribute('data-key');"
        "    if (key === 'reasons') return;"
        "    Array.prototype.forEach.call(document.querySelectorAll('#filter-row .col-filter'), "
        "      function (inp) {"
        "        if (inp.value) { inp.value = ''; inp.dispatchEvent(new Event('input')); }"
        "      });"
        "    var row = document.querySelectorAll('#wheel-rows tr')[0];"
        "    var td = row.children[index];"
        "    input.value = td.textContent;"
        "    input.dispatchEvent(new Event('input'));"
        "    results[key] = document.querySelectorAll('#wheel-rows tr').length === 1;"
        "  }"
        ");"
        "document.title = JSON.stringify(results);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    # Guards against a selector drift that finds zero filter inputs: the loop
    # above would then pass vacuously with nothing checked.
    assert len(out) == 5
    for key, still_shown in out.items():
        assert still_shown, f"the {key!r} column's own full cell text does not match its own filter"


def test_browser_every_rules_column_filter_matches_its_own_cell_text(tmp_path: Path) -> None:
    """The Rules table's own drift guard, the same shape as the Wheels table's:
    filtering a column by its own full cell text must still show that row, for
    every column at once. `_three_records()`'s `PY_WEAK_HASH_CALL` rule carries
    two basis standards in the shipped ruleset (asserted below, so a ruleset edit
    that drops it to one fails loudly here instead of quietly stopping this test
    from covering the multi-value case), so this also catches drift between
    `ruleColumnText`'s `basis` and `appendBasisChips`'s own chip-per-id rendering,
    the same way the Wheels table's guard catches it for `libraries`. Each
    filterable column's `td` is found by its `<th>`'s own position, the same as
    the Wheels table's guard, rather than a position counted only across the
    filterable columns, so a future `RULES_COLUMNS` entry with `filter: false`
    could not misalign a lookup here the way `filter: false` already does on the
    Wheels side."""
    ruleset = load_ruleset(None)
    rule = next(r for r in ruleset.rules if r.id == "PY_WEAK_HASH_CALL")
    assert len(rule.basis) >= 2
    page = render_html(_three_records(), ruleset)
    script = (
        "document.getElementById('view-tab-rules').click();"
        "var results = {};"
        "Array.prototype.forEach.call(document.querySelectorAll('#rules-filter-row th'), "
        "  function (th, index) {"
        "    var input = th.querySelector('.col-filter');"
        "    if (!input) return;"
        "    var key = input.getAttribute('data-key');"
        "    Array.prototype.forEach.call("
        "      document.querySelectorAll('#rules-filter-row .col-filter'), "
        "      function (inp) {"
        "        if (inp.value) { inp.value = ''; inp.dispatchEvent(new Event('input')); }"
        "      });"
        "    var row = Array.prototype.find.call(document.querySelectorAll('#rules-rows tr'), "
        "      function (tr) {"
        "        var link = tr.querySelector('.rule-link');"
        "        return link && link.textContent === 'PY_WEAK_HASH_CALL';"
        "      });"
        "    var td = row.children[index];"
        "    input.value = td.textContent;"
        "    input.dispatchEvent(new Event('input'));"
        "    results[key] = Array.prototype.some.call("
        "      document.querySelectorAll('#rules-rows .rule-link'),"
        "      function (b) { return b.textContent === 'PY_WEAK_HASH_CALL'; }"
        "    );"
        "  }"
        ");"
        "document.title = JSON.stringify(results);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert len(out) == 9
    for key, still_shown in out.items():
        assert still_shown, f"the {key!r} column's own full cell text does not match its own filter"


def test_browser_column_filters_round_trip_through_the_hash(tmp_path: Path) -> None:
    """`f.<column>=<text>` round-trips through a reload in `COLUMNS` order
    regardless of the order the filters were set in; a `hashchange` to a hash that
    omits them clears them, since applying a hash is total, not a merge; and an
    unknown `f.bogus=` is dropped on read the same way a stale `class` token is,
    leaving `Clear filters` hidden -- and so is `f.openssl=`, a real column that
    just has no column filter of its own (`filter: false`), the same as `f.bogus`
    even though the column itself is real."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)

    set_filters = (
        "var relations = document.querySelector('#filter-row .col-filter[data-key=\"relations\"]');"
        "relations.value = 'boundary_unresolved';"
        "relations.dispatchEvent(new Event('input'));"
        "var filename = document.querySelector('#filter-row .col-filter[data-key=\"filename\"]');"
        "filename.value = 'a';"
        "filename.dispatchEvent(new Event('input'));"
        "document.title = window.location.hash;"
    )
    hash_value = _title(_render_in_browser(tmp_path, page, extra_script=set_filters))
    assert "f.filename=a" in hash_value
    assert "f.relations=boundary_unresolved" in hash_value
    assert hash_value.index("f.filename=") < hash_value.index("f.relations=")

    fragment = hash_value[1:]
    read_back = (
        "document.title = JSON.stringify({"
        " filename: document.querySelector('#filter-row .col-filter[data-key=\"filename\"]').value,"
        " relations: document.querySelector("
        "   '#filter-row .col-filter[data-key=\"relations\"]').value,"
        " count: document.getElementById('count').textContent"
        "});"
    )
    reloaded = _render_in_browser(tmp_path, page, fragment=fragment, extra_script=read_back)
    out = json.loads(_title(reloaded))
    assert out == {"filename": "a", "relations": "boundary_unresolved", "count": "1 of 3 wheels"}

    # A `hashchange` replaces `state.columnFilters` with a fresh object (see
    # `applyHashParams`); typing into a filter afterwards must still work, not
    # write to the object the boot-time listener was originally handed.
    hashchange_script = (
        "var out = {};"
        "window.addEventListener('hashchange', function () {"
        "  out.filename = document.querySelector("
        "    '#filter-row .col-filter[data-key=\"filename\"]').value;"
        "  var relations = document.querySelector("
        "    '#filter-row .col-filter[data-key=\"relations\"]');"
        "  out.relations = relations.value;"
        "  out.count = document.getElementById('count').textContent;"
        "  relations.value = 'runtime_refusal';"
        "  relations.dispatchEvent(new Event('input'));"
        "  out.countAfterRetype = document.getElementById('count').textContent;"
        "  out.hashAfterRetype = window.location.hash;"
        "  document.title = JSON.stringify(out);"
        "});"
        "window.location.hash = 'wheel=0';"
    )
    cleared = _render_in_browser(tmp_path, page, fragment=fragment, extra_script=hashchange_script)
    cleared_out = json.loads(_title(cleared))
    assert cleared_out["filename"] == ""
    assert cleared_out["relations"] == ""
    assert cleared_out["count"] == "3 of 3 wheels"
    assert cleared_out["countAfterRetype"] == "1 of 3 wheels"
    assert "f.relations=runtime_refusal" in cleared_out["hashAfterRetype"]

    unknown = _render_in_browser(
        tmp_path,
        page,
        fragment="f.bogus=x&f.openssl=none",
        extra_script=(
            "document.title = JSON.stringify({"
            " clearHidden: document.getElementById('clear-filters').hidden,"
            " count: document.getElementById('count').textContent"
            "});"
        ),
    )
    unknown_out = json.loads(_title(unknown))
    assert unknown_out == {"clearHidden": True, "count": "3 of 3 wheels"}


def test_browser_sorting_does_not_rebuild_or_clear_the_column_filter_input(
    tmp_path: Path,
) -> None:
    """A sort click rebuilds the header row (`renderHeader`) but must never touch
    the filter row: `renderFilterRow` runs once at boot, never from inside a
    header re-render, so a column filter's input stays the same DOM node with its
    typed value intact across a sort click -- rebuilding it there would drop
    whatever the reader was mid-typing."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var filter = document.querySelector('#filter-row .col-filter[data-key=\"relations\"]');"
        "filter.value = 'runtime_refusal';"
        "filter.dispatchEvent(new Event('input'));"
        "document.querySelectorAll('#header-row .sort-btn')[0].click();"
        "var after = document.querySelector('#filter-row .col-filter[data-key=\"relations\"]');"
        "document.title = JSON.stringify({"
        " sameNode: after === filter,"
        " value: after.value"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out == {"sameNode": True, "value": "runtime_refusal"}


def test_browser_rules_column_filter_narrows_rules(tmp_path: Path) -> None:
    """The Rules table's own per-column filters narrow its rows the same way the
    Wheels table's do, and stay out of the URL hash: neither the Rules view's sort
    nor its column filters describe the Wheels view the hash grammar carries."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "document.getElementById('view-tab-rules').click();"
        "var filter = document.querySelector('#rules-filter-row .col-filter[data-key=\"id\"]');"
        "filter.value = 'WEAK';"
        "filter.dispatchEvent(new Event('input'));"
        "document.title = JSON.stringify({"
        " ids: Array.prototype.map.call(document.querySelectorAll('.rule-link'), "
        "   function (b) { return b.textContent; }),"
        " hash: window.location.hash"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["ids"] == ["PY_WEAK_HASH_CALL"]
    assert "f." not in out["hash"]


def test_browser_rules_count_column_is_labelled_wheels(tmp_path: Path) -> None:
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "document.getElementById('view-tab-rules').click();"
        "document.title = JSON.stringify(Array.prototype.map.call("
        " document.querySelectorAll('#rules-header-row .sort-btn'),"
        " function (b) { return b.textContent; }));"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    labels = json.loads(_title(dom))
    assert any(label.startswith("wheels") for label in labels)


def test_browser_openssl_column_shows_linkage_with_help(tmp_path: Path) -> None:
    """The `openssl` column shows `conditions.openssl_linkage` for the wheel as a
    whole -- including `none`, a real value, not a blank cell -- with the same
    `LINKAGE_HELP` tooltip the Reference tab's own linkage table uses, and sorts
    like every other column."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var cell = document.querySelectorAll('#wheel-rows tr')[1].children[4];"
        "var span = cell.querySelector('.linkage-value');"
        "var opensslBtn = Array.prototype.find.call("
        "  document.querySelectorAll('#header-row .sort-btn'),"
        "  function (b) { return b.textContent === 'openssl'; });"
        "opensslBtn.click();"
        "var ascFilenames = Array.prototype.map.call("
        "  document.querySelectorAll('#wheel-rows td.wheel-cell'), "
        "  function (td) { return td.textContent; });"
        "opensslBtn.click();"
        "var descFilenames = Array.prototype.map.call("
        "  document.querySelectorAll('#wheel-rows td.wheel-cell'), "
        "  function (td) { return td.textContent; });"
        "document.title = JSON.stringify({"
        " text: span.textContent,"
        " title: span.title,"
        " ascFilenames: ascFilenames,"
        " descFilenames: descFilenames"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["text"] == "none"
    assert out["title"] == LINKAGE_HELP["none"]
    assert out["ascFilenames"] == [
        "a-1.0-py3-none-any.whl",
        "b-1.0-py3-none-any.whl",
        "c-1.0-py3-none-any.whl",
    ]
    assert out["descFilenames"] == list(reversed(out["ascFilenames"]))


def test_browser_class_legend_lists_present_classes_with_class_help(tmp_path: Path) -> None:
    """The always-visible class legend lists exactly the classes present in this
    run, in the same precedence order the embedded `DATA.classes` payload gives,
    each with its own `CLASS_HELP` text -- and the table's own class badge carries
    that same text as a tooltip too."""
    ruleset = load_ruleset(None)
    records = _three_records()
    page = render_html(records, ruleset)
    payload = _extract_payload(page)
    present_classes = {rec["verdict"]["class"] for rec in records}
    expected_order = [cls for cls in payload["classes"] if cls in present_classes]

    script = (
        "var badges = document.querySelectorAll('#class-legend .badge');"
        "var descriptions = document.querySelectorAll('#class-legend .class-legend-text');"
        "document.title = JSON.stringify({"
        " classes: Array.prototype.map.call(badges, "
        "   function (b) { return b.getAttribute('data-class'); }),"
        " helps: Array.prototype.map.call(descriptions, "
        "   function (d) { return d.textContent; }),"
        " tableBadgeTitle: document.querySelector('#wheel-rows .badge').title"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["classes"] == expected_order
    assert out["helps"] == [CLASS_HELP[cls] for cls in expected_order]
    assert out["tableBadgeTitle"] == CLASS_HELP[records[0]["verdict"]["class"]]


def test_browser_openssl_cell_and_a_column_filter_never_execute_wheel_controlled_html(
    tmp_path: Path,
) -> None:
    """`conditions.openssl_linkage` and a wheel's own filename are untrusted,
    wheel-controlled text like any other field this report renders: an `<img
    onerror=...>` payload in either must never become a real DOM element, whether
    it reaches the page through a cell or through a column filter's own value.
    The `openssl` cell has no column filter of its own (`filter: false`); the
    `libraries` column carries the same payload, since `conditions.openssl_linkage`
    is also this record's one library's own `linkage`, so it exercises the same
    filter-to-DOM path a per-column filter on `openssl` itself would have."""
    ruleset = load_ruleset(None)
    payload = "<img src=x onerror=alert(1)>"
    rec = html_record(payload, "OPAQUE", payload, review=False)
    page = render_html([rec], ruleset)

    script = (
        "var out = {};"
        "out.imgInDocument = !!document.querySelector('img');"
        "var filter = document.querySelector('#filter-row .col-filter[data-key=\"libraries\"]');"
        f"filter.value = {json.dumps(payload)};"
        "filter.dispatchEvent(new Event('input'));"
        "out.imgAfterFilter = !!document.querySelector('img');"
        "out.count = document.getElementById('count').textContent;"
        "document.title = JSON.stringify(out);"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["imgInDocument"] is False
    assert out["imgAfterFilter"] is False
    assert out["count"] == "1 of 1 wheels"


def test_browser_reasons_column_filter_matches_the_full_reasons_list(tmp_path: Path) -> None:
    """The `reasons` cell shows only the first 3 rule ids plus a "+N more" chip,
    but its column filter matches the record's full `verdict.reasons` list (see
    `columnText`'s own comment on why): filtering by the 4th reason's rule id must
    still show the row, not hide it as though only the visible chips were
    searched."""
    ruleset = load_ruleset(None)
    rec = html_record("many", "NON_APPROVED_CRYPTO", "bundled", review=True)
    rec["verdict"]["reasons"] = ["RULE_ONE: a", "RULE_TWO: b", "RULE_THREE: c", "RULE_FOUR: d"]
    page = render_html([rec], ruleset)
    script = (
        "var filter = document.querySelector('#filter-row .col-filter[data-key=\"reasons\"]');"
        "filter.value = 'RULE_FOUR';"
        "filter.dispatchEvent(new Event('input'));"
        "document.title = document.getElementById('count').textContent;"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    assert _title(dom) == "1 of 1 wheels"


def test_browser_class_chip_titles_match_class_help(tmp_path: Path) -> None:
    """Every class-strip chip's tooltip is `CLASS_HELP[cls]`, the same text the
    always-visible legend and the table's own class badges already carry."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "document.title = JSON.stringify(Array.prototype.map.call("
        "  document.querySelectorAll('.class-chip'),"
        "  function (chip) {"
        "    return {"
        "      cls: chip.querySelector('.swatch').getAttribute('data-class'),"
        "      title: chip.title"
        "    };"
        "  }"
        "));"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out
    for entry in out:
        assert entry["title"] == CLASS_HELP[entry["cls"]]


def test_browser_rules_column_filter_empty_state_says_no_rules_match(tmp_path: Path) -> None:
    """Filtering the Rules table down to nothing shows the "No rules match the
    column filters." note, not the "No rules referenced by any scanned wheel."
    one `renderRulesTable` falls back to when no filter is active at all."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "document.getElementById('view-tab-rules').click();"
        "var filter = document.querySelector('#rules-filter-row .col-filter[data-key=\"id\"]');"
        "filter.value = 'zzz';"
        "filter.dispatchEvent(new Event('input'));"
        "document.title = document.querySelector('#rules-rows .note').textContent;"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    assert _title(dom) == "No rules match the column filters."


def test_browser_linkage_filter_unfiltered_option_reads_all(tmp_path: Path) -> None:
    """The OpenSSL linkage dropdown's unfiltered option reads "all", not "any":
    "all" keeps it from reading like a linkage value the field could actually
    carry, or the ruleset's own `binding = "any"` match spec. It matches the
    class filter's own reset button, which reads "all" too."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = "document.title = document.getElementById('linkage-filter').options[0].textContent;"
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    assert _title(dom) == "all"


# --- class legend layout ---------------------------------------------------------


def test_browser_class_legend_lays_out_as_a_horizontal_row_on_desktop(tmp_path: Path) -> None:
    """The always-visible class legend is a horizontal, wrapping row, not one class
    per line: at a normal desktop width, the first two present classes' items sit
    on the same line, sharing `offsetTop`."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var items = document.querySelectorAll('#class-legend .class-legend-item');"
        "document.title = JSON.stringify({"
        " first: items[0].offsetTop, second: items[1].offsetTop"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, window_size="1280,900", extra_script=script)
    out = json.loads(_title(dom))
    assert out["first"] == out["second"]


def test_browser_class_legend_wraps_without_widening_the_page_on_a_phone(tmp_path: Path) -> None:
    """At a phone width, the legend wraps inside its own box instead of forcing a
    horizontal scrollbar on the page: `flex-wrap: wrap` keeps the row's own width
    bounded the way a one-class-per-line layout would."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    script = (
        "var legend = document.getElementById('class-legend');"
        "var doc = document.documentElement;"
        "document.title = JSON.stringify({"
        " legendFits: legend.scrollWidth <= legend.clientWidth,"
        " pageFits: doc.scrollWidth <= doc.clientWidth"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, window_size="375,800", extra_script=script)
    out = json.loads(_title(dom))
    assert out["legendFits"] is True
    assert out["pageFits"] is True


def test_browser_help_dialog_legend_grid_stays_a_two_column_grid(
    tmp_path: Path,
) -> None:
    """`.legend-grid` lays out the Help dialog's own Families/Classes/
    Relations/OpenSSL-linkage/Columns grids as a two-column grid: the
    always-visible class legend's own flex row (`.class-legend`) is a separate
    class on a separate element, not a redefinition of this one."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        "document.getElementById('intro-tab-reference').click();"
        "var grid = document.querySelector('#legend-body .legend-grid');"
        "document.title = getComputedStyle(grid).display;"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    assert _title(dom) == "grid"


# --- DataTables enhancement -------------------------------------------------------


def _cdn_reachable(url: str) -> bool:
    try:
        urllib.request.urlopen(url, timeout=10)  # noqa: S310 -- the one deliberate network test
        return True
    except (urllib.error.URLError, OSError):
        return False


def _require_cdn(url: str) -> None:
    """Skips a `network`-marked test when `url` is unreachable -- or fails it when
    WCS_REQUIRE_NETWORK is set, which CI does so that a runner with no route to
    jsdelivr turns these checks red instead of silently off, mirroring
    `_host_libcrypto`'s own WCS_REQUIRE_HOSTBIN switch in test_binfmt_elf.py."""
    if _cdn_reachable(url):
        return
    message = f"{url} is not reachable"
    if os.environ.get("WCS_REQUIRE_NETWORK"):
        pytest.fail(message + " and WCS_REQUIRE_NETWORK is set")
    pytest.skip(message)


def _datatables_url(page: str) -> str:
    match = re.search(r'<script[^>]*\bsrc="(https://[^"]*dataTables\.min\.js)"', page)
    assert match is not None, "no DataTables script tag found in the rendered page"
    return match.group(1)


def test_browser_uses_the_native_table_when_datatables_is_unreachable(tmp_path: Path) -> None:
    """With no network at all (`_render_in_browser`'s own default), the pinned
    DataTables script never loads, so `enhanceTables` returns before touching
    anything: the page stays on the native table it already rendered, complete."""
    ruleset = load_ruleset(None)
    page = render_html(_many_records(60), ruleset)
    script = (
        "window.addEventListener('load', function () {"
        "  document.title = JSON.stringify({"
        "    dataTableUndefined: typeof window.DataTable === 'undefined',"
        "    dtContainer: !!document.querySelector('.dt-container'),"
        "    enhanced: document.getElementById('wheel-table').hasAttribute('data-enhanced'),"
        "    rows: document.querySelectorAll('#wheel-rows tr').length,"
        "    count: document.getElementById('count').textContent"
        "  });"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["dataTableUndefined"] is True
    assert out["dtContainer"] is False
    assert out["enhanced"] is False
    assert out["rows"] == 60
    assert out["count"] == "60 of 60 wheels"


# A hand-written stand-in for `window.DataTable`, not a Proxy over a single shared
# target: every construction gets its own `record` (keyed by the table element's own
# `id`) so the wheel table's and the Rules table's own options, `search.fixed` calls
# and `order.listener` calls -- both tables carry nine columns -- are never confused
# with each other. Every property access or call the page makes beyond the ones this
# stub names explicitly (`search`, `search.fixed`, `order.listener`, `column().search`,
# `rows.add`, `draw`, `page.len`) resolves to the same self-returning proxy, so an
# unnamed chain this stub was not told about returns something chainable instead of
# throwing `undefined is not a function`.
_DT_STUB_PREAMBLE = """
window.__dtLog = { constructions: [] };
(function () {
  function makeProxy(overrides) {
    var proxy = new Proxy(function () {}, {
      get: function (target, prop) {
        if (overrides && Object.prototype.hasOwnProperty.call(overrides, prop)) {
          return overrides[prop];
        }
        if (prop === "toArray") return function () { return []; };
        if (prop === "count") return function () { return 0; };
        if (prop === "len") return function () { return 50; };
        return proxy;
      },
      apply: function () { return proxy; }
    });
    return proxy;
  }
  function StubDataTable(el, options) {
    var record = {
      el: el.id, options: options, searchFixedCalls: [], orderListenerCalls: []
    };
    window.__dtLog.constructions.push(record);
    var instance;
    var searchFn = function () { return instance; };
    searchFn.fixed = function (name) {
      record.searchFixedCalls.push(name);
      return instance;
    };
    var order = { listener: function (node, index) {
      record.orderListenerCalls.push(index);
      return instance;
    } };
    instance = makeProxy({ search: searchFn, order: order });
    return instance;
  }
  StubDataTable.ext = { order: {} };
  window.DataTable = StubDataTable;
})();
"""


def test_browser_datatables_init_receives_the_expected_wheel_table_options(
    tmp_path: Path,
) -> None:
    """A stub `window.DataTable` records exactly what `enhanceWheelTable` hands it,
    with no real DataTables machinery involved: the options that keep a
    wheel-controlled string from ever being handed back to the DOM
    (`searchable: false`, an explicit `type`, no `data`/`render`), the options that
    keep the header click and its arrow this page's own (`ordering.handler`,
    `titleRow`, `orderDescReverse`), `orderMulti: false` on both tables (native has
    no multi-column sort), the toolbar's own fixed search, and one
    `order.listener` call per wheel-table column."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    column_count = len(_parse_columns(page))
    script = (
        _DT_STUB_PREAMBLE + "document.addEventListener('DOMContentLoaded', function () {"
        "  var wheelRecord = window.__dtLog.constructions.filter(function (c) {"
        "    return c.el === 'wheel-table';"
        "  })[0];"
        "  var rulesRecord = window.__dtLog.constructions.filter(function (c) {"
        "    return c.el === 'rules-table';"
        "  })[0];"
        "  var options = wheelRecord.options;"
        "  var columns = options.columns;"
        "  document.title = JSON.stringify({"
        "    searching: options.searching,"
        "    handler: options.ordering.handler,"
        "    titleRow: options.titleRow,"
        "    orderDescReverse: options.orderDescReverse,"
        "    orderMulti: options.orderMulti,"
        "    rulesOrderMulti: rulesRecord.options.orderMulti,"
        "    autoWidth: options.autoWidth,"
        "    columnCount: columns.length,"
        "    columnsOk: columns.every(function (c) {"
        "      return c.searchable === false && c.type === 'wcs' &&"
        "        !('data' in c) && !('render' in c) && !('createdCell' in c) &&"
        "        !('title' in c);"
        "    }),"
        "    wheelsOrder: typeof DataTable.ext.order['wcs-wheels'],"
        "    rulesOrder: typeof DataTable.ext.order['wcs-rules'],"
        "    searchFixedCalls: wheelRecord.searchFixedCalls,"
        "    orderListenerCalls: wheelRecord.orderListenerCalls.length"
        "  });"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["searching"] is True
    assert out["handler"] is False
    assert out["titleRow"] == 0
    assert out["orderDescReverse"] is False
    assert out["orderMulti"] is False
    assert out["rulesOrderMulti"] is False
    assert out["autoWidth"] is False
    assert out["columnCount"] == column_count
    assert out["columnsOk"] is True
    assert out["wheelsOrder"] == "function"
    assert out["rulesOrder"] == "function"
    assert out["searchFixedCalls"] == ["toolbar"]
    assert out["orderListenerCalls"] == column_count


def test_browser_datatables_constructor_exception_falls_back_to_the_native_table(
    tmp_path: Path,
) -> None:
    """`enhanceTables`' own `try` around each table's setup catches a real
    DataTables failure the same way: a stub whose constructor throws proves the
    `catch` branch restores the native table, with every row rendered and the
    arrow that marks the active sort still on the `filename` column's button."""
    ruleset = load_ruleset(None)
    page = render_html(_many_records(5), ruleset)
    script = (
        "window.DataTable = function () { throw new Error('boom'); };"
        "window.DataTable.ext = { order: {} };"
        "window.addEventListener('load', function () {"
        "  document.title = JSON.stringify({"
        "    rows: document.querySelectorAll('#wheel-rows tr').length,"
        "    enhanced: document.getElementById('wheel-table').hasAttribute('data-enhanced'),"
        "    arrow: document.querySelectorAll('#header-row .sort-btn')[0].textContent"
        "  });"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["rows"] == 5
    assert out["enhanced"] is False
    assert "↑" in out["arrow"]


def test_browser_datatables_constructor_exception_after_registration_still_destroys(
    tmp_path: Path,
) -> None:
    """A `new DT(...)` call can register a table in DataTables' own internal
    settings list, and remove the page's own `<colgroup>`, before throwing: the
    pinned library does exactly that (`table.children('colgroup').remove()` then
    `allSettings.push(settings)`, in that order, well before the constructor
    returns), so `dt`/`rulesDt` here can still be null when `enhanceTables`' own
    `catch` runs even though DataTables has already mutated the DOM.
    `recoverDataTableInstance` finds and destroys that instance through
    `DT.isDataTable`/`DT.Api` instead of this page's own (unset) `dt`/`rulesDt`; a
    stub that registers a table id and then throws, with its own minimal
    `isDataTable`/`Api`, proves it runs for both tables."""
    ruleset = load_ruleset(None)
    page = render_html(_many_records(5), ruleset)
    script = (
        "window.__recoverLog = { destroyed: [] };"
        "(function () {"
        "  var registered = {};"
        "  function StubDataTable(el) {"
        "    registered[el.id] = true;"
        "    throw new Error('boom-mid-construction');"
        "  }"
        "  StubDataTable.ext = { order: {} };"
        "  StubDataTable.isDataTable = function (table) { return !!registered[table.id]; };"
        "  StubDataTable.Api = function (table) {"
        "    return { destroy: function () { window.__recoverLog.destroyed.push(table.id); } };"
        "  };"
        "  window.DataTable = StubDataTable;"
        "})();"
        "window.addEventListener('load', function () {"
        "  document.title = JSON.stringify({"
        "    destroyed: window.__recoverLog.destroyed,"
        "    enhanced: document.getElementById('wheel-table').hasAttribute('data-enhanced'),"
        "    rows: document.querySelectorAll('#wheel-rows tr').length"
        "  });"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert sorted(out["destroyed"]) == ["rules-table", "wheel-table"]
    assert out["enhanced"] is False
    assert out["rows"] == 5


def test_browser_datatables_setup_strips_the_native_sort_arrow(tmp_path: Path) -> None:
    """A sort clicked before the pinned script answers leaves a text arrow in that
    header button's own label (`renderSortableHeader`'s native rendering); once a
    (stubbed) DataTable owns the table, `enhanceWheelTable` strips that text so
    only DataTables' own CSS draws the sort arrow from here on -- confirmed again
    after a click on a different column's button, since the page's own click
    handler no-ops (`sortState.enhanced`) rather than restoring one."""
    ruleset = load_ruleset(None)
    page = render_html(_many_records(5), ruleset)
    script = (
        "document.querySelectorAll('#header-row .sort-btn')[1].click();"
        + _DT_STUB_PREAMBLE
        + "window.addEventListener('load', function () {"
        "  function labels(buttons) {"
        "    return Array.prototype.map.call(buttons, function (b) { return b.textContent; });"
        "  }"
        "  var buttons = document.querySelectorAll('#header-row .sort-btn');"
        "  var afterEnhance = labels(buttons);"
        "  buttons[2].click();"
        "  var afterClick = labels(buttons);"
        "  document.title = JSON.stringify({ afterEnhance: afterEnhance, afterClick: afterClick });"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert all("↑" not in t and "↓" not in t for t in out["afterEnhance"])
    assert all("↑" not in t and "↓" not in t for t in out["afterClick"])


def test_browser_datatables_errmode_is_set_to_throw(tmp_path: Path) -> None:
    """`enhanceTables` sets `DataTable.ext.errMode = "throw"` before constructing
    either table: the default, `"alert"`, would pop a dialog and swallow the
    exception the page's own `try`/`catch` needs to see in order to fall back."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    script = (
        _DT_STUB_PREAMBLE + "window.addEventListener('load', function () {"
        "  document.title = JSON.stringify({ errMode: DataTable.ext.errMode });"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script)
    out = json.loads(_title(dom))
    assert out["errMode"] == "throw"


# --- network: the real, pinned DataTables script ----------------------------------


@pytest.mark.network
def test_network_datatables_sri_matches_the_cdn_file() -> None:
    """The pinned `integrity` hash is exactly `sha384` of the file jsdelivr serves
    at that URL, base64-encoded: an SRI mismatch means the browser never executes
    the script at all, which every other `network` test would then read as an
    unreachable CDN rather than a broken pin, so this one checks the pin directly."""
    ruleset = load_ruleset(None)
    page = render_html([html_record("a", "OPAQUE", "none")], ruleset)
    url = _datatables_url(page)
    match = re.search(r'\bintegrity="sha384-([A-Za-z0-9+/]{64})"', page)
    assert match is not None
    expected = match.group(1)

    _require_cdn(url)
    body = urllib.request.urlopen(url, timeout=10).read()  # noqa: S310
    actual = base64.b64encode(hashlib.sha384(body).digest()).decode("ascii")
    assert actual == expected


_PARITY_RULE_IDS = {
    "CONDITIONAL": "BIN_BUNDLED_OPENSSL",
    "OPAQUE": "WHEEL_UNREADABLE",
    "FIPS_BREAKING": "PY_WEAK_HASH_CALL",
    "NON_APPROVED_CRYPTO": "BIN_LIBSODIUM",
    "CONTEXT_DEPENDENT": "PY_INSECURE_RNG",
    "NO_CRYPTO_DETECTED": "BIN_BUNDLED_OPENSSL",
}


def _parity_records() -> list[dict]:
    """Twelve wheels for the DataTables/native parity harness: two ties per class
    (a class-sorted tie falls back to filename, the tiebreak both paths share),
    mixed-case filenames (a case-sensitive sort catches a DataTables
    auto-detected type the page's own explicit `type: "wcs"` is meant to
    prevent), two versions that would invert under a numeric sort but not a
    plain string one, several distinct classes and OpenSSL linkages, both review
    states, and one wheel with four reasons so its fourth sits behind the reasons
    cell's own "+1 more" chip. Every rule id is one the shipped ruleset actually
    defines, since `render_html`'s `rules` payload only ever carries one of those."""
    names = [
        "Alpha",
        "beta",
        "Charlie",
        "delta",
        "Echo",
        "foxtrot",
        "Golf",
        "hotel",
        "India",
        "juliet",
        "Kilo",
        "lima",
    ]
    classes = [
        "CONDITIONAL",
        "CONDITIONAL",
        "OPAQUE",
        "OPAQUE",
        "FIPS_BREAKING",
        "NON_APPROVED_CRYPTO",
        "CONTEXT_DEPENDENT",
        "NO_CRYPTO_DETECTED",
        "CONDITIONAL",
        "OPAQUE",
        "NON_APPROVED_CRYPTO",
        "CONTEXT_DEPENDENT",
    ]
    linkages = [
        "bundled",
        "none",
        "static",
        "system",
        "unknown",
        "mixed",
        "bundled",
        "none",
        "static",
        "system",
        "unknown",
        "mixed",
    ]
    versions = ["9.0", "10.0"] * 6
    records = []
    for i, (name, klass, linkage, version) in enumerate(
        zip(names, classes, linkages, versions, strict=True)
    ):
        rec = html_record(
            name, klass, linkage, review=(i % 2 == 0), rule_id=_PARITY_RULE_IDS[klass]
        )
        rec["wheel"]["version"] = version
        records.append(rec)
    records[0]["verdict"]["reasons"] = [
        "BIN_BUNDLED_OPENSSL: a",
        "BIN_LIBSODIUM: b",
        "PY_INSECURE_RNG: c",
        "RULE_FOUR: d",
    ]
    return records


_WHEEL_PARITY_SCRIPT_TEMPLATE = """
window.addEventListener('load', async function () {
  var columnKeys = __COLUMN_KEYS__;
  var transcript = [];
  function snapshot(step) {
    var cells = document.querySelectorAll('#wheel-rows .wheel-cell');
    transcript.push({
      step: step,
      filenames: Array.prototype.map.call(cells, function (c) { return c.textContent; }),
      count: document.getElementById('count').textContent
    });
  }
  function fireInput(el, value) {
    el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }
  // DataTables' own header-click handler (bound through `order.listener`, never
  // this page's own click handler, which steps aside once enhanced) redraws on a
  // deferred task rather than inline with the click, unlike this page's own
  // `renderTable`, which calls `dt.draw()` synchronously. Getting a fresh handle
  // on the already-initialised table (`new DataTable` on a table DataTables
  // already owns returns that same instance, never a second one) and awaiting its
  // next `draw` event is what a real click waits for too; natively, `DataTable` is
  // never defined at all, so every click is already synchronous with nothing to
  // await.
  function clickAndWaitDraw(button) {
    return new Promise(function (resolve) {
      if (typeof window.DataTable !== 'function') {
        button.click();
        resolve();
        return;
      }
      new DataTable('#wheel-table').one('draw', resolve);
      button.click();
    });
  }

  snapshot('initial');

  var headerButtons = document.querySelectorAll('#header-row .sort-btn');
  for (var i = 0; i < columnKeys.length; i++) {
    await clickAndWaitDraw(headerButtons[i]);
    snapshot('sort-' + columnKeys[i] + '-asc');
    await clickAndWaitDraw(headerButtons[i]);
    snapshot('sort-' + columnKeys[i] + '-desc');
  }

  var filterInputs = document.querySelectorAll('#filter-row .col-filter');
  Array.prototype.forEach.call(filterInputs, function (input) {
    var key = input.getAttribute('data-key');
    fireInput(input, 'a');
    snapshot('colfilter-' + key);
    fireInput(input, '');
  });

  fireInput(document.getElementById('search'), 'a');
  snapshot('search');
  fireInput(document.getElementById('search'), '');

  document.getElementById('view-tab-rules').click();
  var ruleButton = document.querySelector('#rules-rows .rule-link');
  ruleButton.click();
  snapshot('rule-click');
  fireInput(document.getElementById('search'), '');

  var chip = document.querySelector('.class-chip');
  chip.click();
  snapshot('class-untick');
  chip.click();

  var linkageSelect = document.getElementById('linkage-filter');
  linkageSelect.value = linkageSelect.options[1].value;
  linkageSelect.dispatchEvent(new Event('change', { bubbles: true }));
  snapshot('linkage');
  linkageSelect.value = '';
  linkageSelect.dispatchEvent(new Event('change', { bubbles: true }));

  var reviewCheckbox = document.getElementById('review-only');
  reviewCheckbox.checked = true;
  reviewCheckbox.dispatchEvent(new Event('change', { bubbles: true }));
  snapshot('review');

  var reasonsFilter = document.querySelector('#filter-row .col-filter[data-key="reasons"]');
  fireInput(reasonsFilter, 'RULE_FOUR');
  snapshot('reasons-rule-four');
  fireInput(reasonsFilter, '');

  document.getElementById('clear-filters').click();
  snapshot('clear');

  document.title = JSON.stringify({
    transcript: transcript,
    enhanced: document.getElementById('wheel-table').hasAttribute('data-enhanced')
  });
});
"""


def _wheel_parity_script(column_keys: list[str]) -> str:
    """`extra_script` runs in the top-level scope, outside the page's own IIFE, so
    it cannot read `COLUMNS` itself -- every key the scenario needs is handed in
    from here instead, parsed out of this same rendered page by `_parse_columns`."""
    return _WHEEL_PARITY_SCRIPT_TEMPLATE.replace("__COLUMN_KEYS__", json.dumps(column_keys))


@pytest.mark.network
def test_network_datatables_sort_and_search_match_the_native_table(tmp_path: Path) -> None:
    """DataTables' own sort, global search and per-column filtering read back
    exactly the same filenames and count the native path already computes, at
    every step of a script that exercises every column's sort (twice, asc then
    desc), every column filter, the global search, a Rules-tab rule click, a
    class-chip untick, the linkage filter, the review checkbox, the `reasons`
    column's own full-list match, and Clear filters -- rendered once with the
    network blocked and once with it open, diffed step by step."""
    ruleset = load_ruleset(None)
    records = _parity_records()
    page = render_html(records, ruleset)
    payload = _extract_payload(page)
    url = _datatables_url(page)
    _require_cdn(url)

    script = _wheel_parity_script([column["key"] for column in _parse_columns(page)])
    offline_dir = tmp_path / "offline"
    offline_dir.mkdir()
    online_dir = tmp_path / "online"
    online_dir.mkdir()
    offline = json.loads(
        _title(_render_in_browser(offline_dir, page, extra_script=script, virtual_time_budget=5000))
    )
    online = json.loads(
        _title(
            _render_in_browser(
                online_dir,
                page,
                extra_script=script,
                allow_network=True,
                virtual_time_budget=5000,
            )
        )
    )

    assert offline["enhanced"] is False
    assert online["enhanced"] is True
    assert online["transcript"] == offline["transcript"]

    filename_to_class = {r["wheel"]["filename"]: r["verdict"]["class"] for r in records}
    class_asc = next(s for s in online["transcript"] if s["step"] == "sort-class-asc")
    ranks = [payload["classes"].index(filename_to_class[name]) for name in class_asc["filenames"]]
    assert ranks == sorted(ranks)
    assert payload["classes"] != sorted(payload["classes"])

    reasons_step = next(s for s in online["transcript"] if s["step"] == "reasons-rule-four")
    assert reasons_step["filenames"] == [records[0]["wheel"]["filename"]]
    assert reasons_step["count"] == "1 of 12 wheels"


_RULES_PARITY_SCRIPT_TEMPLATE = """
window.addEventListener('load', async function () {
  document.getElementById('view-tab-rules').click();
  var columnKeys = __COLUMN_KEYS__;
  var transcript = [];
  function snapshot(step) {
    var idCells = document.querySelectorAll('#rules-rows .rule-link');
    transcript.push({
      step: step,
      ids: Array.prototype.map.call(idCells, function (c) { return c.textContent; })
    });
  }
  function fireInput(el, value) {
    el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }
  // See `_wheel_parity_script`'s own comment: DataTables' own header-click
  // handler redraws on a deferred task, so this waits for its next `draw` event
  // the way a real click's own visible update would.
  function clickAndWaitDraw(button) {
    return new Promise(function (resolve) {
      if (typeof window.DataTable !== 'function') {
        button.click();
        resolve();
        return;
      }
      new DataTable('#rules-table').one('draw', resolve);
      button.click();
    });
  }

  snapshot('initial');

  var headerButtons = document.querySelectorAll('#rules-header-row .sort-btn');
  for (var i = 0; i < columnKeys.length; i++) {
    await clickAndWaitDraw(headerButtons[i]);
    snapshot('sort-' + columnKeys[i] + '-1');
    await clickAndWaitDraw(headerButtons[i]);
    snapshot('sort-' + columnKeys[i] + '-2');
  }

  var idFilter = document.querySelector('#rules-filter-row .col-filter[data-key="id"]');
  fireInput(idFilter, 'BIN');
  snapshot('id-filter');
  fireInput(idFilter, '');

  document.title = JSON.stringify({
    transcript: transcript,
    enhanced: document.getElementById('rules-table').hasAttribute('data-enhanced')
  });
});
"""


def _rules_parity_script(column_keys: list[str]) -> str:
    return _RULES_PARITY_SCRIPT_TEMPLATE.replace("__COLUMN_KEYS__", json.dumps(column_keys))


@pytest.mark.network
def test_network_datatables_rules_table_sort_and_search_match_the_native_table(
    tmp_path: Path,
) -> None:
    """The same parity harness over the Rules table: every column's sort, twice
    each, then the `id` column's own filter, rendered once offline and once with
    the real script, diffed step by step."""
    ruleset = load_ruleset(None)
    page = render_html(_parity_records(), ruleset)
    url = _datatables_url(page)
    _require_cdn(url)

    script = _rules_parity_script(_parse_rules_column_keys(page))
    offline_dir = tmp_path / "offline"
    offline_dir.mkdir()
    online_dir = tmp_path / "online"
    online_dir.mkdir()
    offline = json.loads(
        _title(_render_in_browser(offline_dir, page, extra_script=script, virtual_time_budget=5000))
    )
    online = json.loads(
        _title(
            _render_in_browser(
                online_dir,
                page,
                extra_script=script,
                allow_network=True,
                virtual_time_budget=5000,
            )
        )
    )

    assert offline["enhanced"] is False
    assert online["enhanced"] is True
    assert online["transcript"] == offline["transcript"]


@pytest.mark.network
def test_network_datatables_renders_wheel_text_as_text(tmp_path: Path) -> None:
    """The same XSS-shaped payload
    `test_browser_openssl_cell_and_a_column_filter_never_execute_wheel_controlled_html`
    proves against the native table, proved again against the real, enhanced one:
    every cell stays the node `renderRow` already built, since DataTables is never
    handed `data`, `render`, `title` or `createdCell` for a column to write into it
    -- the reason sorting and filtering by every column with the payload live in
    every field never executes it or corrupts the cell's own text. `searchable:
    false` on every column is defence in depth: it also keeps DataTables from ever
    building the per-cell search-text cache that would decode a `&` through a
    detached element's `innerHTML`."""
    ruleset = load_ruleset(None)
    payload = "a&<img src=x onerror=\"document.title='pwned'\">"
    rec = html_record(payload, "OPAQUE", payload, review=False)
    rec["verdict"]["reasons"] = [f"BIN_BUNDLED_OPENSSL: {payload}"]
    page = render_html([rec], ruleset)
    url = _datatables_url(page)
    _require_cdn(url)

    script = (
        "window.addEventListener('load', async function () {"
        "  function clickAndWaitDraw(button) {"
        "    return new Promise(function (resolve) {"
        "      new DataTable('#wheel-table').one('draw', resolve);"
        "      button.click();"
        "    });"
        "  }"
        "  var headerButtons = document.querySelectorAll('#header-row .sort-btn');"
        "  for (var i = 0; i < headerButtons.length; i++) {"
        "    await clickAndWaitDraw(headerButtons[i]);"
        "    await clickAndWaitDraw(headerButtons[i]);"
        "  }"
        "  var filter = document.querySelector('#filter-row .col-filter[data-key=\"filename\"]');"
        "  filter.value = '&';"
        "  filter.dispatchEvent(new Event('input', { bubbles: true }));"
        "  var cell = document.querySelector('#wheel-rows .wheel-cell');"
        "  document.title = JSON.stringify({"
        "    imgInDocument: !!document.querySelector('img'),"
        "    titlePwned: document.title === 'pwned',"
        "    cellText: cell ? cell.textContent : null,"
        "    enhanced: document.getElementById('wheel-table').hasAttribute('data-enhanced')"
        "  });"
        "});"
    )
    dom = _render_in_browser(
        tmp_path, page, extra_script=script, allow_network=True, virtual_time_budget=5000
    )
    out = json.loads(_title(dom))
    assert out["enhanced"] is True
    assert out["imgInDocument"] is False
    assert out["titlePwned"] is False
    assert out["cellText"] == rec["wheel"]["filename"]


@pytest.mark.network
def test_network_datatables_paging_detail_and_resize(tmp_path: Path) -> None:
    """DataTables' own paging keeps working once it owns the wheel table, and so
    does everything this page's own code layers on top of it: the detail panel's
    Previous/Next (reading DataTables' applied search and order back through
    `visibleRecords`), the colgroup the resize handles and `buildColgroup` still
    read and write, and a keyboard-driven sort through the same `.sort-btn`
    DataTables' own `order.listener` is bound to."""
    ruleset = load_ruleset(None)
    records = _many_records(60)
    page = render_html(records, ruleset)
    url = _datatables_url(page)
    _require_cdn(url)

    script = (
        "window.addEventListener('load', async function () {"
        "  var out = {};"
        "  out.enhanced = document.getElementById('wheel-table').hasAttribute('data-enhanced');"
        "  out.rowsOnFirstPage = document.querySelectorAll('#wheel-rows tr').length;"
        "  out.count = document.getElementById('count').textContent;"
        "  function pageButton(label) {"
        "    return Array.prototype.filter.call("
        "      document.querySelectorAll('.dt-paging-button'),"
        "      function (b) { return b.textContent.trim() === label; }"
        "    )[0];"
        "  }"
        # DataTables' own paging and header-click handling both redraw on a
        # deferred task; getting a fresh handle on the table it already owns and
        # awaiting its next `draw` event is what a real interaction waits for too.
        "  function actAndWaitDraw(act) {"
        "    return new Promise(function (resolve) {"
        "      new DataTable('#wheel-table').one('draw', resolve);"
        "      act();"
        "    });"
        "  }"
        "  await actAndWaitDraw(function () { pageButton('2').click(); });"
        "  out.rowsOnSecondPage = document.querySelectorAll('#wheel-rows tr').length;"
        "  await actAndWaitDraw(function () { pageButton('1').click(); });"
        "  document.querySelectorAll('#wheel-rows tr')[0].click();"
        "  out.detailOpen = !document.getElementById('detail').hidden;"
        "  out.position = document.getElementById('detail-position').textContent;"
        "  document.getElementById('detail-next').click();"
        "  out.positionAfterNext = document.getElementById('detail-position').textContent;"
        "  document.getElementById('detail-close').click();"
        "  var colgroup = document.getElementById('wheel-colgroup');"
        "  out.colgroupInTable = document.getElementById('wheel-table').contains(colgroup);"
        "  out.col0Before = colgroup.children[0].style.width;"
        "  var handle = document.querySelectorAll('.col-resize-handle')[0];"
        "  handle.focus();"
        "  handle.dispatchEvent(new KeyboardEvent('keydown', {"
        "    key: 'ArrowRight', bubbles: true, cancelable: true"
        "  }));"
        "  out.col0After = colgroup.children[0].style.width;"
        "  var filenameTh = document.querySelectorAll('#header-row th')[0];"
        "  out.filenameThBeforeEnter = filenameTh.className;"
        "  var filenameButton = filenameTh.querySelector('.sort-btn');"
        "  filenameButton.focus();"
        # DataTables' own key listener reads the legacy `keyCode`/`which` fields
        # on a `keypress` event, not `key` on a `keydown`.
        "  await actAndWaitDraw(function () {"
        "    filenameButton.dispatchEvent(new KeyboardEvent('keypress', {"
        "      key: 'Enter', code: 'Enter', keyCode: 13, which: 13,"
        "      bubbles: true, cancelable: true"
        "    }));"
        "  });"
        "  out.filenameThAfterEnter = filenameTh.className;"
        "  document.title = JSON.stringify(out);"
        "});"
    )
    dom = _render_in_browser(
        tmp_path, page, extra_script=script, allow_network=True, virtual_time_budget=5000
    )
    out = json.loads(_title(dom))
    assert out["enhanced"] is True
    assert out["rowsOnFirstPage"] == 50
    assert out["count"] == "60 of 60 wheels"
    assert out["rowsOnSecondPage"] == 10
    assert out["detailOpen"] is True
    assert out["position"] != out["positionAfterNext"]
    assert out["colgroupInTable"] is True
    assert out["col0After"] != out["col0Before"]
    assert "dt-ordering-asc" in out["filenameThBeforeEnter"]
    assert "dt-ordering-desc" in out["filenameThAfterEnter"]


@pytest.mark.network
def test_network_datatables_throw_after_construction_falls_back_cleanly(tmp_path: Path) -> None:
    """`enhanceWheelTable`'s own exception can land well after `new DT(...)` has
    already succeeded -- DataTables has added its `.dt-container` wrapper, replaced
    the `<colgroup>` and populated every row by the time `els.headerRow
    .querySelectorAll(".sort-btn")` runs -- and `enhanceTables`'s own `catch` still
    leaves the page clean: `dt.destroy()` removes what DataTables added,
    `restoreNativeColgroup` re-inserts the exact `<colgroup id="wheel-colgroup">`
    node the page shipped with (marked here before any of this runs, so the check
    is by identity, not only by a matching id), and the native table renders every
    row with its own working resize handles. The throw is forced by monkeypatching
    `querySelectorAll` to fail the one call `enhanceWheelTable` makes after
    `dt.rows.add`, `dt.search`/`search.fixed` and every column's own `.search()`
    call have all already run against the real library."""
    ruleset = load_ruleset(None)
    page = render_html(_many_records(60), ruleset)
    url = _datatables_url(page)
    _require_cdn(url)

    script = (
        "document.getElementById('wheel-colgroup').setAttribute('data-original', '1');"
        "window.addEventListener('DOMContentLoaded', function () {"
        "  var orig = Element.prototype.querySelectorAll;"
        "  var fired = false;"
        "  Element.prototype.querySelectorAll = function (sel) {"
        "    if (!fired && this.id === 'header-row' && sel === '.sort-btn') {"
        "      fired = true;"
        "      throw new Error('boom');"
        "    }"
        "    return orig.call(this, sel);"
        "  };"
        "}, true);"
        "window.addEventListener('load', function () {"
        "  var colgroup = document.querySelector('#wheel-table colgroup');"
        "  var col0Before = colgroup ? colgroup.children[0].style.width : null;"
        "  var handle = document.querySelectorAll('.col-resize-handle')[0];"
        "  handle.focus();"
        "  handle.dispatchEvent(new KeyboardEvent('keydown', {"
        "    key: 'ArrowRight', bubbles: true, cancelable: true"
        "  }));"
        "  document.title = JSON.stringify({"
        "    wheelWrapped: !!document.getElementById('wheel-table').closest('.dt-container'),"
        "    enhancedAttr: document.getElementById('wheel-table').hasAttribute('data-enhanced'),"
        "    colgroupCount: document.querySelectorAll('#wheel-table > colgroup').length,"
        "    colgroupIsOriginal: colgroup ? colgroup.hasAttribute('data-original') : false,"
        "    colgroupId: colgroup ? colgroup.id : null,"
        "    col0Before: col0Before,"
        "    col0After: colgroup ? colgroup.children[0].style.width : null,"
        "    rows: document.querySelectorAll('#wheel-rows tr').length"
        "  });"
        "});"
    )
    dom = _render_in_browser(
        tmp_path, page, extra_script=script, allow_network=True, virtual_time_budget=5000
    )
    out = json.loads(_title(dom))
    assert out["wheelWrapped"] is False
    assert out["enhancedAttr"] is False
    assert out["colgroupCount"] == 1
    assert out["colgroupIsOriginal"] is True
    assert out["colgroupId"] == "wheel-colgroup"
    assert out["col0After"] != out["col0Before"]


@pytest.mark.network
def test_network_datatables_throw_after_colgroup_id_assigned_leaves_no_stray_colgroup(
    tmp_path: Path,
) -> None:
    """The same fallback, forced to throw later than the test above: after
    `enhanceWheelTable` has already given DataTables' own colgroup the id
    `wheel-colgroup` (`colgroup.id = "wheel-colgroup"`, right before
    `buildColgroup()`), so a check keyed on that id alone could find DataTables'
    colgroup instead of the page's own original and stop there, leaving both in
    the table. `restoreNativeColgroup` strips every colgroup that is not
    `originalColgroup` by identity first, so only one -- the original -- is left
    either way. The throw is forced by monkeypatching `setAttribute` to fail the
    `data-enhanced` marker `enhanceWheelTable` sets right after that point."""
    ruleset = load_ruleset(None)
    page = render_html(_many_records(60), ruleset)
    url = _datatables_url(page)
    _require_cdn(url)

    script = (
        "document.getElementById('wheel-colgroup').setAttribute('data-original', '1');"
        "window.addEventListener('DOMContentLoaded', function () {"
        "  var orig = Element.prototype.setAttribute;"
        "  var fired = false;"
        "  Element.prototype.setAttribute = function (name, value) {"
        "    if (!fired && this.id === 'wheel-table' && name === 'data-enhanced') {"
        "      fired = true;"
        "      throw new Error('boom');"
        "    }"
        "    return orig.call(this, name, value);"
        "  };"
        "}, true);"
        "window.addEventListener('load', function () {"
        "  var colgroups = document.querySelectorAll('#wheel-table > colgroup');"
        "  document.title = JSON.stringify({"
        "    wheelWrapped: !!document.getElementById('wheel-table').closest('.dt-container'),"
        "    enhancedAttr: document.getElementById('wheel-table').hasAttribute('data-enhanced'),"
        "    colgroupCount: colgroups.length,"
        "    colgroupIsOriginal: colgroups[0] ? colgroups[0].hasAttribute('data-original') : false,"
        "    rows: document.querySelectorAll('#wheel-rows tr').length"
        "  });"
        "});"
    )
    dom = _render_in_browser(
        tmp_path, page, extra_script=script, allow_network=True, virtual_time_budget=5000
    )
    out = json.loads(_title(dom))
    assert out["wheelWrapped"] is False
    assert out["enhancedAttr"] is False
    assert out["colgroupCount"] == 1
    assert out["colgroupIsOriginal"] is True
    assert out["rows"] == 60


@pytest.mark.network
def test_network_datatables_rules_table_throw_after_construction_falls_back_cleanly(
    tmp_path: Path,
) -> None:
    """The Rules table's own `catch` in `enhanceTables` runs the same cleanup the
    wheel table's does, over `rulesDt`: forcing a throw after `enhanceRulesTable`'s
    own construction has already succeeded (the same shape the wheel table's own
    `test_network_datatables_throw_after_construction_falls_back_cleanly` forces)
    proves `rulesDt.destroy()` runs, not only that the wheel table's own recovery
    does."""
    ruleset = load_ruleset(None)
    page = render_html(_parity_records(), ruleset)
    url = _datatables_url(page)
    _require_cdn(url)

    script = (
        "window.addEventListener('DOMContentLoaded', function () {"
        "  var orig = Element.prototype.querySelectorAll;"
        "  var fired = false;"
        "  Element.prototype.querySelectorAll = function (sel) {"
        "    if (!fired && this.id === 'rules-header-row' && sel === '.sort-btn') {"
        "      fired = true;"
        "      throw new Error('boom');"
        "    }"
        "    return orig.call(this, sel);"
        "  };"
        "}, true);"
        "window.addEventListener('load', function () {"
        "  document.getElementById('view-tab-rules').click();"
        "  document.title = JSON.stringify({"
        "    rulesWrapped: !!document.getElementById('rules-table').closest('.dt-container'),"
        "    enhancedAttr: document.getElementById('rules-table').hasAttribute('data-enhanced'),"
        "    wheelEnhanced: document.getElementById('wheel-table').hasAttribute('data-enhanced'),"
        "    rows: document.querySelectorAll('#rules-rows tr').length"
        "  });"
        "});"
    )
    dom = _render_in_browser(
        tmp_path, page, extra_script=script, allow_network=True, virtual_time_budget=5000
    )
    out = json.loads(_title(dom))
    assert out["rulesWrapped"] is False
    assert out["enhancedAttr"] is False
    assert out["wheelEnhanced"] is True
    assert out["rows"] > 0


@pytest.mark.network
def test_network_datatables_next_from_last_row_of_a_page_turns_the_page(tmp_path: Path) -> None:
    """Stepping past the last row shown on page 1 (`detail-next`, from the 50th of
    60 wheels at the default `pageLength` of 50) turns DataTables to page 2, the
    page the next row is actually on: `showDetail`'s own `turnDtToRecord`, which
    every path that opens a record's detail runs through."""
    ruleset = load_ruleset(None)
    page = render_html(_many_records(60), ruleset)
    url = _datatables_url(page)
    _require_cdn(url)

    script = (
        "window.addEventListener('load', function () {"
        "  var rows = document.querySelectorAll('#wheel-rows tr');"
        "  rows[rows.length - 1].click();"
        "  document.getElementById('detail-next').click();"
        "  var current = Array.prototype.filter.call("
        "    document.querySelectorAll('.dt-paging-button'),"
        "    function (b) { return b.className.indexOf('current') !== -1; }"
        "  )[0];"
        "  document.title = JSON.stringify({"
        "    currentPage: current ? current.textContent.trim() : null,"
        "    position: document.getElementById('detail-position').textContent"
        "  });"
        "});"
    )
    dom = _render_in_browser(tmp_path, page, extra_script=script, allow_network=True)
    out = json.loads(_title(dom))
    assert out["currentPage"] == "2"
    assert out["position"] == "51 of 60"


@pytest.mark.network
def test_network_datatables_sort_while_detail_open_refreshes_the_nav(tmp_path: Path) -> None:
    """Sorting the table (a DataTables-driven header click) while the detail panel
    is open still updates Previous/Next: `drawCallback` -- which every DataTables
    redraw runs, a sort included -- calls `updateDetailNav` again, over the newly
    sorted `visibleRecords()`. Reversing the already-ascending `filename` sort
    moves the open row ("a", the alphabetically first of three) from first to
    last."""
    ruleset = load_ruleset(None)
    page = render_html(_three_records(), ruleset)
    url = _datatables_url(page)
    _require_cdn(url)

    script = (
        "window.addEventListener('load', async function () {"
        "  document.querySelectorAll('#wheel-rows tr')[0].click();"
        "  var before = document.getElementById('detail-position').textContent;"
        "  var filenameButton = document.querySelectorAll('#header-row .sort-btn')[0];"
        "  await new Promise(function (resolve) {"
        "    new DataTable('#wheel-table').one('draw', resolve);"
        "    filenameButton.click();"
        "  });"
        "  document.title = JSON.stringify({"
        "    before: before,"
        "    after: document.getElementById('detail-position').textContent"
        "  });"
        "});"
    )
    dom = _render_in_browser(
        tmp_path, page, extra_script=script, allow_network=True, virtual_time_budget=5000
    )
    out = json.loads(_title(dom))
    assert out["before"] == "1 of 3"
    assert out["after"] == "3 of 3"


@pytest.mark.network
def test_network_datatables_sort_while_detail_open_on_a_paginated_table_turns_the_page(
    tmp_path: Path,
) -> None:
    """The same sort-while-open case as the test above, but over enough rows
    (`_many_records(60)`, `pageLength` 50) that the open row's new position lands
    on a different page than the one on screen: the wheel table's own
    `drawCallback` calls `turnDtToRecord`, not only `updateDetailNav`, so the page
    turns along with the nav rather than leaving the open row's own page hidden
    behind whichever page the sort happened to leave on screen."""
    ruleset = load_ruleset(None)
    page = render_html(_many_records(60), ruleset)
    url = _datatables_url(page)
    _require_cdn(url)

    script = (
        "window.addEventListener('load', async function () {"
        "  document.querySelectorAll('#wheel-rows tr')[0].click();"
        "  var filenameButton = document.querySelectorAll('#header-row .sort-btn')[0];"
        "  await new Promise(function (resolve) {"
        "    new DataTable('#wheel-table').one('draw', resolve);"
        "    filenameButton.click();"
        "  });"
        "  var current = Array.prototype.filter.call("
        "    document.querySelectorAll('.dt-paging-button'),"
        "    function (b) { return b.className.indexOf('current') !== -1; }"
        "  )[0];"
        "  document.title = JSON.stringify({"
        "    currentPage: current ? current.textContent.trim() : null,"
        "    position: document.getElementById('detail-position').textContent"
        "  });"
        "});"
    )
    dom = _render_in_browser(
        tmp_path, page, extra_script=script, allow_network=True, virtual_time_budget=5000
    )
    out = json.loads(_title(dom))
    assert out["position"] == "60 of 60"
    assert out["currentPage"] == "2"


@pytest.mark.network
def test_network_datatables_wheel_hash_on_a_later_page_turns_dataTables_to_it(
    tmp_path: Path,
) -> None:
    """A `#wheel=N` link naming a row DataTables' own paging would put on a later
    page turns DataTables to that page as the table is handed to it: the same
    page-turn `showDetail`'s own `turnDtToRecord` runs for Previous/Next, called
    again by `enhanceWheelTable` once its own `dt.draw()` has made
    `visibleRecords()`'s DataTables branch authoritative, so the detail panel and
    the row it names are never left on different pages on first load."""
    ruleset = load_ruleset(None)
    records = _many_records(60)
    page = render_html(records, ruleset)
    url = _datatables_url(page)
    _require_cdn(url)

    script = (
        "window.addEventListener('load', function () {"
        "  var current = Array.prototype.filter.call("
        "    document.querySelectorAll('.dt-paging-button'),"
        "    function (b) { return b.className.indexOf('current') !== -1; }"
        "  )[0];"
        "  document.title = JSON.stringify({"
        "    currentPage: current ? current.textContent.trim() : null,"
        "    detailOpen: !document.getElementById('detail').hidden,"
        "    title: document.getElementById('detail-title').textContent"
        "  });"
        "});"
    )
    dom = _render_in_browser(
        tmp_path,
        page,
        fragment="wheel=55",
        extra_script=script,
        allow_network=True,
        virtual_time_budget=5000,
    )
    out = json.loads(_title(dom))
    assert out["detailOpen"] is True
    assert out["title"] == "wheel-055-1.0-py3-none-any.whl"
    assert out["currentPage"] == "2"
