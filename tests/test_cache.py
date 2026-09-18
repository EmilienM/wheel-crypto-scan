"""The content-addressed record cache: what invalidates it, and what it guarantees."""

from __future__ import annotations

from pathlib import Path

import pytest

from wheel_crypto_scan.cache import RecordCache

LINE = '{"schema_version":1}\n'
SHA = "a" * 64
NAME = "demo-1.0-py3-none-any.whl"


@pytest.fixture
def cache(tmp_path: Path) -> RecordCache:
    return RecordCache(root=tmp_path, ruleset_version="1", evidence_level="standard")


def test_a_miss_returns_nothing(cache: RecordCache) -> None:
    assert cache.get(SHA, NAME) is None


def test_a_stored_record_comes_back_byte_identical(cache: RecordCache) -> None:
    cache.put(SHA, NAME, LINE)
    assert cache.get(SHA, NAME) == LINE


def test_a_different_wheel_is_a_different_entry(cache: RecordCache) -> None:
    cache.put(SHA, NAME, LINE)
    assert cache.get("b" * 64, NAME) is None


def test_a_new_ruleset_version_invalidates_the_entry(tmp_path: Path) -> None:
    """Bumping ruleset_version is how a policy edit gets the index rescanned."""
    RecordCache(root=tmp_path, ruleset_version="1", evidence_level="standard").put(SHA, NAME, LINE)
    later = RecordCache(root=tmp_path, ruleset_version="2", evidence_level="standard")
    assert later.get(SHA, NAME) is None


def test_a_new_analyzer_version_invalidates_the_entry(tmp_path: Path) -> None:
    """Otherwise an extraction bugfix would keep serving the records it was fixing."""
    first = RecordCache(root=tmp_path, ruleset_version="1", evidence_level="standard")
    first.put(SHA, NAME, LINE)
    later = RecordCache(
        root=tmp_path, ruleset_version="1", evidence_level="standard", analyzer_version=99
    )
    assert later.get(SHA, NAME) is None


def test_a_different_evidence_level_is_a_different_entry(tmp_path: Path) -> None:
    RecordCache(root=tmp_path, ruleset_version="1", evidence_level="standard").put(SHA, NAME, LINE)
    minimal = RecordCache(root=tmp_path, ruleset_version="1", evidence_level="minimal")
    assert minimal.get(SHA, NAME) is None


def test_a_new_tool_version_invalidates_the_entry(tmp_path: Path) -> None:
    first = RecordCache(root=tmp_path, ruleset_version="1", evidence_level="standard")
    first.put(SHA, NAME, LINE)
    later = RecordCache(
        root=tmp_path, ruleset_version="1", evidence_level="standard", tool_version="9.9.9"
    )
    assert later.get(SHA, NAME) is None


def test_a_disabled_cache_stores_nothing(tmp_path: Path) -> None:
    cache = RecordCache(
        root=tmp_path, ruleset_version="1", evidence_level="standard", enabled=False
    )
    cache.put(SHA, NAME, LINE)
    assert cache.get(SHA, NAME) is None
    assert list(tmp_path.iterdir()) == []


def test_entries_are_fanned_out_so_one_directory_does_not_hold_thirty_thousand_files(
    cache: RecordCache, tmp_path: Path
) -> None:
    cache.put(SHA, NAME, LINE)
    stored = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert len(stored) == 1
    assert stored[0].parent != tmp_path


def test_an_unreadable_entry_is_a_miss_not_a_crash(cache: RecordCache, tmp_path: Path) -> None:
    """A half-written cache file from an interrupted run must not poison a rescan."""
    cache.put(SHA, NAME, LINE)
    stored = next(p for p in tmp_path.rglob("*") if p.is_file())
    stored.write_bytes(b"\xff\xfe not valid")
    assert cache.get(SHA, NAME) is None


def test_writing_an_entry_twice_is_stable(cache: RecordCache) -> None:
    cache.put(SHA, NAME, LINE)
    cache.put(SHA, NAME, LINE)
    assert cache.get(SHA, NAME) == LINE


def test_a_missing_cache_root_is_created_on_demand(tmp_path: Path) -> None:
    cache = RecordCache(
        root=tmp_path / "does" / "not" / "exist", ruleset_version="1", evidence_level="standard"
    )
    cache.put(SHA, NAME, LINE)
    assert cache.get(SHA, NAME) == LINE


def test_the_same_bytes_under_a_different_name_is_a_different_entry(cache: RecordCache) -> None:
    """The record's name, version and tags all come from the filename."""
    cache.put(SHA, NAME, LINE)
    assert cache.get(SHA, "other-9.9-py3-none-any.whl") is None


def test_different_scan_limits_are_different_entries(tmp_path: Path) -> None:
    """A constrained run skips the binary layer; that record must not be reused."""
    RecordCache(
        root=tmp_path, ruleset_version="1", evidence_level="standard", limits="100:200"
    ).put(SHA, NAME, LINE)
    unconstrained = RecordCache(
        root=tmp_path, ruleset_version="1", evidence_level="standard", limits=""
    )
    assert unconstrained.get(SHA, NAME) is None
