"""Behaviour of the shared test wheel builder itself.

`read_metadata`'s determinism tests only mean something if the builder is itself
deterministic; this file is the direct check on that guarantee, plus a couple of
structural sanity checks so a bug here does not silently invalidate every other
layer's fixtures.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from helpers.wheelbuilder import build_wheel


def test_same_arguments_produce_byte_identical_archives(tmp_path: Path) -> None:
    first = build_wheel(
        tmp_path / "a.whl",
        name="sample",
        version="1.0",
        requires_dist=("cffi>=1.12",),
        files={"sample/__init__.py": b"# pkg\n"},
    )
    second = build_wheel(
        tmp_path / "b.whl",
        name="sample",
        version="1.0",
        requires_dist=("cffi>=1.12",),
        files={"sample/__init__.py": b"# pkg\n"},
    )
    assert first.read_bytes() == second.read_bytes()


def test_dist_info_directory_matches_name_and_version(tmp_path: Path) -> None:
    wheel = build_wheel(tmp_path / "sample-1.0-py3-none-any.whl", name="sample", version="1.0")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    assert names == {
        "sample-1.0.dist-info/METADATA",
        "sample-1.0.dist-info/WHEEL",
        "sample-1.0.dist-info/RECORD",
    }


def test_second_dist_info_knob_adds_an_unrelated_directory(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        second_dist_info=True,
    )
    with zipfile.ZipFile(wheel) as archive:
        top_level_dirs = {name.split("/", 1)[0] for name in archive.namelist()}
    assert top_level_dirs == {"sample-1.0.dist-info", "other-0.0.dist-info"}


def test_metadata_bytes_knob_overrides_metadata_content_verbatim(tmp_path: Path) -> None:
    raw = b"Metadata-Version: 2.1\nName: sample\nVersion: 1.0\nbad \xff\xfe byte\n\n"
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        metadata_bytes=raw,
    )
    with zipfile.ZipFile(wheel) as archive:
        assert archive.read("sample-1.0.dist-info/METADATA") == raw


def test_record_false_omits_record_entirely(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl", name="sample", version="1.0", record=False
    )
    with zipfile.ZipFile(wheel) as archive:
        assert "sample-1.0.dist-info/RECORD" not in archive.namelist()
