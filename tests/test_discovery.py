"""Turning inputs into a deterministic, ordered list of wheels."""

from __future__ import annotations

from pathlib import Path

import pytest

from wheel_crypto_scan.discovery import discover, parse_simple_index


def touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"PK\x03\x04")
    return path


def test_an_explicit_wheel_is_returned(tmp_path: Path) -> None:
    wheel = touch(tmp_path / "demo-1.0-py3-none-any.whl")
    assert discover([str(wheel)]) == [wheel]


def test_a_directory_is_searched_recursively(tmp_path: Path) -> None:
    touch(tmp_path / "a-1.0-py3-none-any.whl")
    touch(tmp_path / "nested" / "b-1.0-py3-none-any.whl")
    found = [path.name for path in discover([str(tmp_path)])]
    assert found == ["a-1.0-py3-none-any.whl", "b-1.0-py3-none-any.whl"]


def test_non_wheel_files_are_ignored(tmp_path: Path) -> None:
    touch(tmp_path / "a-1.0-py3-none-any.whl")
    touch(tmp_path / "notes.txt")
    touch(tmp_path / "demo-1.0.tar.gz")
    assert [path.name for path in discover([str(tmp_path)])] == ["a-1.0-py3-none-any.whl"]


def test_results_are_sorted_by_filename_not_by_directory_walk_order(tmp_path: Path) -> None:
    """Directory order varies between filesystems; the scan order must not."""
    touch(tmp_path / "zzz" / "a-1.0-py3-none-any.whl")
    touch(tmp_path / "aaa" / "z-1.0-py3-none-any.whl")
    touch(tmp_path / "m-1.0-py3-none-any.whl")
    names = [path.name for path in discover([str(tmp_path)])]
    assert names == ["a-1.0-py3-none-any.whl", "m-1.0-py3-none-any.whl", "z-1.0-py3-none-any.whl"]


def test_the_same_wheel_named_twice_is_scanned_once(tmp_path: Path) -> None:
    wheel = touch(tmp_path / "demo-1.0-py3-none-any.whl")
    assert discover([str(wheel), str(wheel)]) == [wheel]


def test_a_list_file_is_read(tmp_path: Path) -> None:
    wheel = touch(tmp_path / "demo-1.0-py3-none-any.whl")
    listing = tmp_path / "wheels.txt"
    listing.write_text(f"{wheel}\n\n# a comment\n", encoding="utf-8")
    assert discover([], from_file=listing) == [wheel]


def test_a_missing_input_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        discover([str(tmp_path / "nope.whl")])


def test_an_empty_directory_yields_nothing(tmp_path: Path) -> None:
    assert discover([str(tmp_path)]) == []


# --- simple index parsing (offline; downloading is a separate, opt-in step) ---


def test_wheel_links_are_extracted_from_a_simple_index_page() -> None:
    page = """
    <!DOCTYPE html><html><body>
      <a href="https://example.invalid/demo-1.0-py3-none-any.whl#sha256=abc">demo-1.0</a>
      <a href="demo-1.0.tar.gz">sdist</a>
      <a href="/packages/demo-2.0-py3-none-any.whl">demo-2.0</a>
    </body></html>
    """
    links = parse_simple_index(page, "https://example.invalid/simple/demo/")
    assert links == [
        "https://example.invalid/demo-1.0-py3-none-any.whl",
        "https://example.invalid/packages/demo-2.0-py3-none-any.whl",
    ]


def test_index_links_are_sorted_and_deduplicated() -> None:
    page = '<a href="b-1.0-py3-none-any.whl">b</a><a href="a-1.0-py3-none-any.whl">a</a>'
    page += '<a href="a-1.0-py3-none-any.whl">a again</a>'
    links = parse_simple_index(page, "https://example.invalid/simple/x/")
    assert links == [
        "https://example.invalid/simple/x/a-1.0-py3-none-any.whl",
        "https://example.invalid/simple/x/b-1.0-py3-none-any.whl",
    ]


def test_a_page_with_no_wheels_yields_nothing() -> None:
    assert parse_simple_index("<html><body>nothing here</body></html>", "https://x.invalid/") == []
