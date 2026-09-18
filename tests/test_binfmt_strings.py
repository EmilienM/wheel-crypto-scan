"""Printable-string extraction and string-group matching."""

from __future__ import annotations

import re

from wheel_crypto_scan.binfmt.strings import (
    ExtractedStrings,
    extract_printable,
    match_string_groups,
)
from wheel_crypto_scan.ruleset import StringGroup


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
