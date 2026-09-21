"""Printable-string extraction, string-group matching, and the shared pass."""

from __future__ import annotations

import dataclasses
import random
import re
import time

from wheel_crypto_scan.binfmt.strings import (
    PRINTABLE,
    RUN_SEPARATOR,
    ExtractedStrings,
    extract_printable,
    match_string_groups,
    sanitize,
    scan_strings,
)
from wheel_crypto_scan.ruleset import StringGroup
from wheel_crypto_scan.ruleset_loader import load_ruleset

PATTERNS = load_ruleset().compile_patterns().binary


def _group(name: str, *substrings: str) -> StringGroup:
    return StringGroup(
        name=name,
        substrings=tuple(substrings),
        pattern=re.compile("|".join(re.escape(s) for s in substrings)),
    )


def test_extract_printable_finds_runs_at_or_above_min_length() -> None:
    data = b"\x00\x01ab\x00hello world\x00\x02cd\x00"
    extracted = extract_printable(data, min_length=4, max_bytes=1024)
    assert extracted.text == "hello world"
    assert extracted.truncated is False


def test_extract_printable_drops_runs_shorter_than_min_length() -> None:
    data = b"\x00ab\x00cccc\x00"
    extracted = extract_printable(data, min_length=4, max_bytes=1024)
    assert extracted.text == "cccc"


def test_extract_printable_truncates_input_and_flags_it() -> None:
    data = b"a" * 10
    extracted = extract_printable(data, min_length=1, max_bytes=4)
    assert extracted.text == "aaaa"
    assert extracted.truncated is True


def test_extract_printable_joins_multiple_runs_with_newline() -> None:
    data = b"hello\x00world"
    extracted = extract_printable(data, min_length=3, max_bytes=1024)
    assert extracted.text == "hello\nworld"


def test_match_string_groups_reports_the_whole_enclosing_run() -> None:
    extracted = ExtractedStrings(text="junk\nOpenSSL 3.0.14 4 Jun 2024\nmore junk", truncated=False)
    group = _group("openssl_banner", "OpenSSL 3.")
    matches, truncated = match_string_groups(extracted, (group,), max_matches=64)
    assert truncated is False
    assert len(matches) == 1
    assert matches[0].group == "openssl_banner"
    assert matches[0].value == "OpenSSL 3.0.14 4 Jun 2024"


def test_match_string_groups_dedupes_and_sorts() -> None:
    extracted = ExtractedStrings(text="zzz\nAWS-LC\nAWS-LC\naaa", truncated=False)
    group = _group("aws_lc", "AWS-LC")
    matches, truncated = match_string_groups(extracted, (group,), max_matches=64)
    assert truncated is False
    assert matches == (matches[0],)  # only one distinct value survives dedup


def test_match_string_groups_many_hits_in_one_run_still_dedupe_to_one() -> None:
    """Repeated hits inside a single run must not multiply the survivors.

    Re-slicing the whole run once per hit would produce the same value every time,
    which the set collapses anyway. Skipping the re-slicing must still produce the same
    result -- one match, the whole run.
    """
    run = "OpenSSL 3." * 50  # 50 hits for the same group, all inside one run
    extracted = ExtractedStrings(text="junk\n" + run + "\nmore junk", truncated=False)
    group = _group("openssl_banner", "OpenSSL 3.")
    matches, truncated = match_string_groups(extracted, (group,), max_matches=64)
    assert truncated is False
    assert len(matches) == 1
    assert matches[0].value == run


def test_match_string_groups_resets_the_claimed_run_per_group() -> None:
    """Each group claims its own run independently, even inside the same text.

    If the claimed-run tracking were hoisted above the per-group loop instead of
    reset for each group, `boringssl`'s hit -- which starts inside the span
    `openssl_banner` already claimed -- would be wrongly skipped.
    """
    extracted = ExtractedStrings(text="junk\nOpenSSL 3.0 and BoringSSL\ntail", truncated=False)
    groups = (_group("openssl_banner", "OpenSSL 3."), _group("boringssl", "BoringSSL"))
    matches, truncated = match_string_groups(extracted, groups, max_matches=64)
    assert truncated is False
    assert {m.group for m in matches} == {"openssl_banner", "boringssl"}


def test_run_separator_is_outside_printable() -> None:
    """The one fact `match_string_groups`'s optimization depends on, named and pinned.

    `RUN_SEPARATOR` has to stay outside `PRINTABLE`, or a group's pattern built from
    printable-ASCII-only substrings could match across it, breaking the assumption
    that a later hit inside a previously claimed run is always the same run.
    """
    assert ord(RUN_SEPARATOR) not in PRINTABLE


def test_no_shipped_string_group_pattern_can_match_across_the_run_separator() -> None:
    """`match_string_groups`'s optimization depends on this property directly, not on
    the substrings-are-printable-ASCII check `ruleset_loader` enforces as a proxy for it.

    Pinned against the shipped ruleset rather than trusted from the proxy alone: a
    future group kind (a regex escape hatch, a case-insensitive flag) could keep that
    check green while letting a pattern match text containing `RUN_SEPARATOR`, which
    would silently drop evidence the way `test_match_string_groups_resets_the_claimed_
    run_per_group` guards for the per-group case.
    """
    for group in PATTERNS.string_groups:
        for substring in group.substrings:
            for split in range(1, len(substring)):
                text = f"pad{substring[:split]}{RUN_SEPARATOR}{substring[split:]}pad"
                for m in group.pattern.finditer(text):
                    assert RUN_SEPARATOR not in m.group()


def test_match_string_groups_does_not_go_quadratic_in_hits_per_run() -> None:
    """A crafted run with many hits for one group must stay roughly linear.

    Re-slicing the whole enclosing run for each hit costs O(k * run_length) for a run
    with `k` hits. At this shape (200,000 hits in a ~2 MB run), re-slicing per hit
    measures ~3.5s and skipping hits inside the claimed run measures ~0.01s; the 0.5s
    budget keeps a comfortable margin from both, rather than sitting close enough to
    either that host noise could flip the result.
    """
    run = "OpenSSL 3." * 200_000
    extracted = ExtractedStrings(text=run, truncated=False)
    group = _group("openssl_banner", "OpenSSL 3.")
    start = time.perf_counter()
    matches, truncated = match_string_groups(extracted, (group,), max_matches=64)
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f"match_string_groups took {elapsed:.2f}s"
    assert truncated is False
    assert len(matches) == 1
    assert matches[0].value == run


def test_match_string_groups_caps_after_sorting_deterministically() -> None:
    text = "\n".join(f"BLAKE2-{i:02d}" for i in range(5))
    extracted = ExtractedStrings(text=text, truncated=False)
    group = _group("blake", "BLAKE2")
    matches, truncated = match_string_groups(extracted, (group,), max_matches=2)
    assert truncated is True
    assert [m.value for m in matches] == ["BLAKE2-00", "BLAKE2-01"]


def test_match_string_groups_empty_input_yields_empty_tuple() -> None:
    extracted = ExtractedStrings(text="", truncated=False)
    group = _group("openssl_banner", "OpenSSL 3.")
    matches, truncated = match_string_groups(extracted, (group,), max_matches=64)
    assert matches == ()
    assert truncated is False


# --- sanitize ----------------------------------------------------------------


def test_sanitize_keeps_printable_ascii_unchanged() -> None:
    assert sanitize("EVP_DigestInit_ex") == "EVP_DigestInit_ex"


def test_sanitize_drops_control_bytes_and_non_ascii() -> None:
    """A corrupt string table must not be able to reach the JSON record."""
    assert sanitize("EVP\x00_Digest\x1b[31m\u00e9\x7f") == "EVP_Digest[31m"


def _sanitize_reference(text: str) -> str:
    """A per-character generator definition of `sanitize`, kept only so the two can't
    silently drift.

    `sanitize` itself is a compiled-regex `.sub`; this is the plain
    character-by-character definition it must agree with, pinned here so a future edit
    to one without the other is caught rather than assumed equivalent.
    """
    return "".join(ch for ch in text if ord(ch) in PRINTABLE)


def test_sanitize_matches_the_reference_generator_over_a_random_corpus() -> None:
    """A compiled regex must stay byte-identical to `_sanitize_reference`, the
    generator-based implementation kept here for comparison.

    The random sample spans the full `str` code-point range, not just 0x00-0x1ff,
    so it also covers the lone-surrogate and astral-plane
    code points that are the only place a code-point-wise `re` class could plausibly
    diverge from the generator's `ord()` check.
    """
    rng = random.Random(0xC0FFEE)
    cases = [
        "",
        "\x00" * 8,
        "".join(chr(c) for c in PRINTABLE),
        "A\ud800B",  # a lone surrogate, not a valid encodable code point on its own
        chr(0x10FFFF),  # the highest code point `str` can hold
        "EVP\U0001f600Digest",  # astral-plane (emoji)
    ]
    cases.extend(
        "".join(chr(rng.randint(0x00, 0x1FF)) for _ in range(rng.randint(0, 200)))
        for _ in range(200)
    )
    cases.extend(
        "".join(chr(rng.randint(0x00, 0x10FFFF)) for _ in range(rng.randint(0, 200)))
        for _ in range(200)
    )
    for text in cases:
        assert sanitize(text) == _sanitize_reference(text), repr(text)


# --- scan_strings ------------------------------------------------------------


def test_scan_strings_finds_banners_and_crates_in_one_pass() -> None:
    raw = (
        b"\x00OpenSSL 3.0.14 4 Jun 2024\x00"
        b"/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs\x00"
    )
    found = scan_strings(raw, PATTERNS, 1 << 20)
    assert found.truncated is False
    assert [(m.group, m.value) for m in found.matched_strings] == [
        ("openssl_banner", "OpenSSL 3.0.14 4 Jun 2024")
    ]
    assert [(c.name, c.version) for c in found.rust_crates] == [("ring", "0.17.8")]


def test_scan_strings_wires_the_registry_pattern_ahead_of_the_vendor_one() -> None:
    """A `vendor/` tree inside a registry crate's directory must read as part of that
    crate, which only holds if `scan_strings` passes `cargo_path_regex` as `registry`
    and `cargo_vendor_path_regex` as `vendor` -- swapping the two keywords would treat
    the vendor pattern as the one that claims a directory and misread this case."""
    raw = b"\x00/r/cargo/registry/src/idx/bar-1.0.0/vendor/ring/src/x.rs\x00"
    found = scan_strings(raw, PATTERNS, 1 << 20)
    assert [(c.name, c.version) for c in found.rust_crates] == [("bar", "1.0.0")]


def test_scan_strings_keeps_the_joined_text_for_the_go_reader() -> None:
    """All three structural readers hand `text` to `build_go_info`; it is not spare."""
    found = scan_strings(b"\x00alpha\x00beta\x00", PATTERNS, 1 << 20)
    assert found.text == "alpha\nbeta"


def test_scan_strings_flags_truncation_from_its_own_bound() -> None:
    raw = b"OpenSSL 3.0.14 4 Jun 2024"
    found = scan_strings(raw, PATTERNS, 4)
    assert found.truncated is True
    assert found.matched_strings == ()


def _with_limits(**overrides):
    return dataclasses.replace(PATTERNS, limits=dataclasses.replace(PATTERNS.limits, **overrides))


def test_scan_strings_flags_a_capped_string_match_list() -> None:
    """A capped list is evidence we did not report, so it has to reach the record.

    Without this the term can be deleted and the suite stays green, which ships a
    wheel whose evidence was silently cut short under a record saying it was complete.
    """
    raw = b"\x00OpenSSL 3.0.14 4 Jun 2024\x00BoringSSL and AWS-LC live here too\x00"
    found = scan_strings(raw, _with_limits(max_strings_per_binary=1), 1 << 20)
    assert len(found.matched_strings) == 1
    assert found.truncated is True


def test_scan_strings_flags_a_capped_rust_crate_list() -> None:
    base = b"/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/"
    raw = (
        b"\x00" + base + b"ring-0.17.8/src/lib.rs\x00" + base + b"aws-lc-sys-0.12.0/src/lib.rs\x00"
    )
    found = scan_strings(raw, _with_limits(max_rust_crates_per_binary=1), 1 << 20)
    assert len(found.rust_crates) == 1
    assert found.truncated is True


def test_scan_strings_truncates_a_match_value_to_max_evidence_chars() -> None:
    raw = b"\x00OpenSSL 3.0.14 4 Jun 2024 and a great deal more text besides\x00"
    found = scan_strings(raw, _with_limits(max_evidence_chars=11), 1 << 20)
    assert [m.value for m in found.matched_strings] == ["OpenSSL 3.0"]


def test_printable_range_and_the_extraction_regex_agree() -> None:
    """One definition, two expressions. A second spelling is a thing that drifts."""
    for code in range(0x00, 0x120):
        in_range = code in PRINTABLE
        # `sanitize` works on text, so it sees code points past one byte too.
        assert (sanitize(chr(code)) != "") is in_range, hex(code)
        if code < 0x100:
            extracted = extract_printable(bytes([code]) * 4, min_length=4, max_bytes=1024)
            assert (extracted.text != "") is in_range, hex(code)


def test_scan_strings_on_empty_input_is_empty_not_an_error() -> None:
    found = scan_strings(b"", PATTERNS, 1 << 20)
    assert found.matched_strings == ()
    assert found.rust_crates == ()
    assert found.text == ""
    assert found.truncated is False


def test_aws_lc_fips_group_needs_a_version_after_fips() -> None:
    """`AWS-LC FIPS failure caused by:` is compiled from both builds' source, so a bare
    `AWS-LC FIPS` would match a stock build that happened to keep it, and a digit with
    nothing else is still too loose: it also matches prose such as `AWS-LC FIPS 140-3
    validated` and `AWS-LC FIPS 3's legacy provider failed to load`, neither of which
    names a build. The group mirrors `openssl_banner` and requires a dot after the digit
    for the same reason. No AWS-LC FIPS release has shipped a two-digit major -- the
    measured build is 4.2.0 -- so the dot costs nothing today; every leading digit is
    still listed the same way `openssl_banner`'s are, which is what lets
    `test_every_version_anchored_group_names_every_major` police this group too.
    """
    group = next(g for g in PATTERNS.string_groups if g.name == "aws_lc_fips")
    extracted = ExtractedStrings(
        text="\n".join(
            (
                "AWS-LC FIPS 4.2.0",
                "AWS-LC FIPS failure caused by:",
                "AWS-LC FIPS 140-3 validated",
                "AWS-LC FIPS 3's legacy provider failed to load",
                "AWS-LC 5.9.0",
            )
        ),
        truncated=False,
    )
    matches, truncated = match_string_groups(extracted, (group,), max_matches=64)
    assert truncated is False
    assert {m.value for m in matches} == {"AWS-LC FIPS 4.2.0"}
