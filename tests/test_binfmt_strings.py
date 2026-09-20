"""Printable-string extraction, string-group matching, and the shared pass."""

from __future__ import annotations

import dataclasses
import re

from wheel_crypto_scan.binfmt.strings import (
    PRINTABLE,
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
