"""Behaviour of the wheel archive reader: access, limits and safety guards.

Fixtures here are built with raw `zipfile` rather than the shared wheel builder,
because these tests are about archive handling rather than about wheels.
"""

from __future__ import annotations

import hashlib
import io
import warnings
import zipfile
from pathlib import Path

import pytest

from wheel_crypto_scan import errors
from wheel_crypto_scan.wheelfile import ArchiveLimits, SeekableZipMember, WheelArchive

FIXED_DATE = (1980, 1, 1, 0, 0, 0)


def write_zip(path: Path, members: dict[str, bytes], *, compress: bool = True) -> Path:
    mode = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    with zipfile.ZipFile(path, "w", mode) as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.compress_type = mode
            archive.writestr(info, data)
    return path


@pytest.fixture
def simple_wheel(tmp_path: Path) -> Path:
    return write_zip(
        tmp_path / "demo-1.0-py3-none-any.whl",
        {
            "demo/__init__.py": b"x = 1\n",
            "demo/_ext.so": b"\x7fELF" + b"\x00" * 60,
            "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n",
        },
    )


# --- identity ---------------------------------------------------------------


def test_reports_its_own_filename_not_its_host_path(simple_wheel: Path) -> None:
    """No host path may reach the record; only the basename is carried."""
    with WheelArchive.open(simple_wheel) as archive:
        assert archive.filename == "demo-1.0-py3-none-any.whl"


def test_computes_the_sha256_of_the_file(simple_wheel: Path) -> None:
    expected = hashlib.sha256(simple_wheel.read_bytes()).hexdigest()
    with WheelArchive.open(simple_wheel) as archive:
        assert archive.sha256 == expected


def test_reports_the_file_size(simple_wheel: Path) -> None:
    with WheelArchive.open(simple_wheel) as archive:
        assert archive.size_bytes == simple_wheel.stat().st_size


# --- membership -------------------------------------------------------------


def test_names_are_sorted(tmp_path: Path) -> None:
    path = write_zip(tmp_path / "w.whl", {"z.py": b"", "a.py": b"", "m.py": b""})
    with WheelArchive.open(path) as archive:
        assert archive.names == ("a.py", "m.py", "z.py")


def test_reads_a_member(simple_wheel: Path) -> None:
    with WheelArchive.open(simple_wheel) as archive:
        assert archive.read("demo/__init__.py") == b"x = 1\n"


def test_directory_entries_are_excluded_from_members(tmp_path: Path) -> None:
    path = tmp_path / "w.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(zipfile.ZipInfo("pkg/", date_time=FIXED_DATE), b"")
        archive.writestr(zipfile.ZipInfo("pkg/a.py", date_time=FIXED_DATE), b"x=1")
    with WheelArchive.open(path) as wheel:
        assert [member.name for member in wheel.members] == ["pkg/a.py"]


def test_total_uncompressed_size_is_reported(tmp_path: Path) -> None:
    path = write_zip(tmp_path / "w.whl", {"a": b"a" * 100, "b": b"b" * 50})
    with WheelArchive.open(path) as archive:
        assert archive.total_uncompressed_bytes == 150


# --- symlinks ---------------------------------------------------------------


def test_symlink_members_are_flagged_and_not_followed(tmp_path: Path) -> None:
    """torch-style wheels carry symlinks; treating the target path as an ELF is noise."""
    path = tmp_path / "w.whl"
    with zipfile.ZipFile(path, "w") as archive:
        info = zipfile.ZipInfo("lib/libfoo.so.1", date_time=FIXED_DATE)
        info.create_system = 3
        info.external_attr = (0o120777 << 16) | 0o20
        archive.writestr(info, b"libfoo.so")
        archive.writestr(zipfile.ZipInfo("lib/libfoo.so", date_time=FIXED_DATE), b"\x7fELF")
    with WheelArchive.open(path) as wheel:
        links = {member.name: member.is_symlink for member in wheel.members}
        assert links == {"lib/libfoo.so.1": True, "lib/libfoo.so": False}


def test_symlink_target_is_available(tmp_path: Path) -> None:
    path = tmp_path / "w.whl"
    with zipfile.ZipFile(path, "w") as archive:
        info = zipfile.ZipInfo("lib/libfoo.so.1", date_time=FIXED_DATE)
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        archive.writestr(info, b"libfoo.so")
    with WheelArchive.open(path) as wheel:
        assert wheel.symlink_target("lib/libfoo.so.1") == "libfoo.so"


# --- limits and guards ------------------------------------------------------


def test_a_member_over_the_size_limit_is_refused(tmp_path: Path) -> None:
    path = write_zip(tmp_path / "w.whl", {"big.so": b"\x00" * 5000})
    limits = ArchiveLimits(max_member_bytes=1000)
    with WheelArchive.open(path, limits=limits) as archive:
        assert archive.is_within_limits("big.so") is False
        with pytest.raises(errors.WheelReadError):
            archive.read("big.so")


def test_refusing_an_oversized_member_records_an_error(tmp_path: Path) -> None:
    path = write_zip(tmp_path / "w.whl", {"big.so": b"\x00" * 5000})
    limits = ArchiveLimits(max_member_bytes=1000)
    with WheelArchive.open(path, limits=limits) as archive:
        archive.is_within_limits("big.so")
        kinds = {error.kind for error in archive.errors}
    assert errors.BINARY_TOO_LARGE in kinds


def test_an_absurd_compression_ratio_is_refused(tmp_path: Path) -> None:
    """A zip bomb declares a huge member that costs almost nothing to store."""
    path = write_zip(tmp_path / "bomb.whl", {"bomb": b"\x00" * 2_000_000})
    limits = ArchiveLimits(max_compression_ratio=10, max_member_bytes=10_000_000)
    with WheelArchive.open(path, limits=limits) as archive:
        assert archive.is_within_limits("bomb") is False
        assert any(error.kind == errors.COMPRESSION_RATIO_EXCEEDED for error in archive.errors)


def test_a_normal_member_is_within_limits(simple_wheel: Path) -> None:
    with WheelArchive.open(simple_wheel) as archive:
        assert archive.is_within_limits("demo/__init__.py") is True
        assert archive.errors == ()


def test_total_size_over_the_limit_is_recorded(tmp_path: Path) -> None:
    path = write_zip(tmp_path / "w.whl", {"a": b"a" * 10_000})
    with WheelArchive.open(path, limits=ArchiveLimits(max_total_uncompressed_bytes=100)) as w:
        assert any(error.kind == errors.SIZE_LIMIT_EXCEEDED for error in w.errors)


def test_duplicate_member_names_are_recorded(tmp_path: Path) -> None:
    path = tmp_path / "w.whl"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(zipfile.ZipInfo("dup.py", date_time=FIXED_DATE), b"first")
            archive.writestr(zipfile.ZipInfo("dup.py", date_time=FIXED_DATE), b"second")
    with WheelArchive.open(path) as wheel:
        assert any(error.kind == errors.DUPLICATE_MEMBER for error in wheel.errors)
        assert wheel.names.count("dup.py") == 1


def test_a_file_that_is_not_a_zip_raises_wheel_read_error(tmp_path: Path) -> None:
    path = tmp_path / "not-a-wheel.whl"
    path.write_bytes(b"this is not a zip file at all")
    with pytest.raises(errors.WheelReadError):
        WheelArchive.open(path)


def test_a_truncated_zip_raises_wheel_read_error(tmp_path: Path) -> None:
    path = write_zip(tmp_path / "w.whl", {"a.py": b"x" * 1000})
    data = path.read_bytes()
    path.write_bytes(data[: len(data) // 2])
    with pytest.raises(errors.WheelReadError):
        WheelArchive.open(path)


def test_a_corrupt_member_is_recorded_not_raised(tmp_path: Path) -> None:
    """One unreadable member must not cost us the rest of the wheel."""
    path = write_zip(
        tmp_path / "w.whl", {"good.py": b"x=1", "bad.py": b"y=2" * 100}, compress=False
    )
    data = bytearray(path.read_bytes())
    offset = data.find(b"y=2")
    data[offset : offset + 20] = b"\xff" * 20
    path.write_bytes(bytes(data))
    with WheelArchive.open(path) as archive:
        assert archive.read("good.py") == b"x=1"
        with pytest.raises(errors.WheelReadError):
            archive.read("bad.py")


# --- streaming access -------------------------------------------------------


def test_small_members_open_as_an_in_memory_stream(simple_wheel: Path) -> None:
    with WheelArchive.open(simple_wheel) as archive:
        with archive.open_member("demo/_ext.so") as stream:
            assert stream.read(4) == b"\x7fELF"


def test_an_opened_member_is_seekable_both_ways(tmp_path: Path) -> None:
    payload = bytes(range(256)) * 40
    path = write_zip(tmp_path / "w.whl", {"blob.bin": payload})
    with WheelArchive.open(path) as archive:
        with archive.open_member("blob.bin") as stream:
            stream.seek(100)
            first = stream.read(10)
            stream.seek(0)
            assert stream.read(4) == payload[:4]
            stream.seek(100)
            assert stream.read(10) == first


def test_large_members_stream_without_loading_the_whole_file(tmp_path: Path) -> None:
    """Multi-gigabyte extensions must not be held in memory or written to disk."""
    payload = bytes(range(256)) * 400
    path = write_zip(tmp_path / "w.whl", {"big.bin": payload})
    limits = ArchiveLimits(max_in_memory_bytes=100)
    with WheelArchive.open(path, limits=limits) as archive:
        with archive.open_member("big.bin") as stream:
            assert isinstance(stream.raw, SeekableZipMember)
            stream.seek(len(payload) - 8)
            assert stream.read(8) == payload[-8:]
            stream.seek(0)
            assert stream.read(8) == payload[:8]


def test_seekable_member_reports_its_position(tmp_path: Path) -> None:
    payload = b"0123456789" * 10
    path = write_zip(tmp_path / "w.whl", {"blob.bin": payload})
    with WheelArchive.open(path, limits=ArchiveLimits(max_in_memory_bytes=1)) as archive:
        with archive.open_member("blob.bin") as stream:
            stream.seek(25)
            assert stream.tell() == 25
            stream.read(5)
            assert stream.tell() == 30
            assert stream.seek(-10, io.SEEK_END) == len(payload) - 10


def test_streamed_and_buffered_reads_agree(tmp_path: Path) -> None:
    payload = bytes(range(256)) * 50
    path = write_zip(tmp_path / "w.whl", {"blob.bin": payload})
    with WheelArchive.open(path, limits=ArchiveLimits(max_in_memory_bytes=1)) as streamed:
        with streamed.open_member("blob.bin") as stream:
            assert stream.read() == payload


# --- determinism ------------------------------------------------------------


def test_the_same_archive_yields_the_same_member_order(simple_wheel: Path) -> None:
    with WheelArchive.open(simple_wheel) as first, WheelArchive.open(simple_wheel) as second:
        assert first.names == second.names
        assert first.members == second.members


def test_errors_are_sorted(tmp_path: Path) -> None:
    path = write_zip(tmp_path / "w.whl", {"b.so": b"\x00" * 5000, "a.so": b"\x00" * 5000})
    with WheelArchive.open(path, limits=ArchiveLimits(max_member_bytes=10)) as archive:
        archive.is_within_limits("b.so")
        archive.is_within_limits("a.so")
        keys = [error.sort_key() for error in archive.errors]
    assert keys == sorted(keys)
