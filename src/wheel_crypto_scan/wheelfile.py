"""Safe, in-memory access to a wheel archive. Owns every zip-level limit and guard.

Wheels are untrusted input. This module is the only place that touches the zip, so
every decision about what is too big, too dense or too strange to read lives here and
the layers above can assume whatever they are handed is safe to parse.

Nothing is ever extracted to disk. Small members are read into memory; large ones are
streamed through `SeekableZipMember`, which re-opens the member to seek backwards. That
matters for wheels like torch, whose extensions are measured in gigabytes.
"""

from __future__ import annotations

import hashlib
import io
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import IO, BinaryIO

from . import errors
from .evidence import STAGE_ARCHIVE, ScanError

_SKIP_CHUNK = 1 << 20
_HASH_CHUNK = 1 << 20


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    """Bounds on what we are willing to read out of an untrusted archive.

    `max_in_memory_bytes` is what this module itself holds: a member no larger than
    that is read into `bytes` outright, and anything larger is streamed instead
    through `SeekableZipMember`. That bounds only this module's own choice, not the
    total memory reading one member costs -- a reader built on top of the stream adds
    its own overhead pulling bytes through it, so "roughly `jobs * max_in_memory_bytes`"
    undercounts the real worst case rather than stating it. Measured end to end, a
    real per-worker peak runs closer to `max_in_memory_bytes` plus a small multiple of
    `binfmt.strings.MAX_STRINGS_BYTES` -- each `binfmt.macho` object can hold up to
    three such budgets at once (a strings prefix, a symbol table, a string table).

    A reader built on top of a streamed member has to bound what it pulls through the
    stream itself, or streaming a member buys nothing. `binfmt.macho` bounds
    `sizeofcmds` and `LC_SYMTAB`'s `nsyms` and `strsize` against
    `binfmt.strings.MAX_STRINGS_BYTES`, not just against the member's own bytes, so a
    streamed member is never read close to whole regardless of `max_in_memory_bytes`.
    `binfmt.elf` bounds every eligible section the same way: a *compressed* or
    `SHT_NOBITS` section is refused before it is inflated past the budget, and an
    ordinary, uncompressed section over budget keeps only its in-budget prefix
    (`strings_bytes_unread`, no error) rather than reading in full -- except
    `.dynsym`/`.dynstr`, which are refused outright when over budget
    (`elf_dynsym_unread`), because a symbol table's count and a string table's
    contents cannot be trusted from a partial read the way a strings-only section's
    prefix can.
    """

    max_total_uncompressed_bytes: int = 8 * 1024**3
    max_member_bytes: int = 1024**3
    max_in_memory_bytes: int = 256 * 1024**2
    max_compression_ratio: int = 1000
    # Below this size a dense member is uninteresting, however good its ratio is.
    ratio_check_floor_bytes: int = 1024**2
    # A symlink target is a path. Anything larger is not a symlink, it is an attempt
    # to make us decompress an arbitrary amount of data outside the member limits.
    max_symlink_target_bytes: int = 4096
    # How much recently-read data a streamed member keeps so that a backward seek can
    # be served without re-decompressing from the start. See SeekableZipMember.
    read_back_window_bytes: int = 16 * 1024**2


@dataclass(frozen=True, slots=True)
class MemberInfo:
    """One file inside the archive. Directories are not members."""

    name: str
    size: int
    compressed_size: int
    is_symlink: bool
    mode: int


class SeekableZipMember(io.RawIOBase):
    """A seekable, read-only view of one zip member that never touches the disk.

    Zip streams only move forward, so seeking backwards re-opens the member and skips
    forward again. That costs a second decompression pass and is the price of reading a
    multi-gigabyte extension without holding it in memory. Forward seeks are cheap.
    """

    def __init__(
        self,
        archive: zipfile.ZipFile,
        name: str,
        size: int,
        window_bytes: int = 16 * 1024**2,
    ) -> None:
        super().__init__()
        self._archive = archive
        self._name = name
        self._size = size
        self._window_bytes = max(window_bytes, 0)
        self._stream: IO[bytes] | None = None
        self._position = 0
        # Everything decompressed within the trailing window, so that a short backward
        # seek costs a memory copy instead of a full re-decompression. ELF readers walk
        # .dynsym and .dynstr alternately, which without this turns every symbol lookup
        # into another pass over the whole member.
        self._window = bytearray()
        self._window_start = 0
        self.reopens = 0
        self._reopen()

    def _reopen(self) -> None:
        if self._stream is not None:
            self._stream.close()
        self._stream = self._archive.open(self._name)
        self._position = 0
        self._window.clear()
        self._window_start = 0
        self.reopens += 1

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[no-untyped-def]
        wanted = len(buffer)
        cached = self._read_from_window(wanted)
        if cached:
            buffer[: len(cached)] = cached
            return len(cached)
        assert self._stream is not None
        data = self._stream.read(wanted)
        buffer[: len(data)] = data
        self._remember(data)
        self._position += len(data)
        return len(data)

    def _read_from_window(self, wanted: int) -> bytes:
        """Serve a read that falls inside the retained window, if it does."""
        end = self._window_start + len(self._window)
        if self._position < self._window_start or self._position >= end:
            return b""
        offset = self._position - self._window_start
        data = bytes(self._window[offset : offset + wanted])
        self._position += len(data)
        return data

    def _remember(self, data: bytes) -> None:
        if not self._window_bytes or not data:
            return
        self._window += data
        excess = len(self._window) - self._window_bytes
        if excess > 0:
            del self._window[:excess]
            self._window_start += excess

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            target = offset
        elif whence == io.SEEK_CUR:
            target = self._position + offset
        elif whence == io.SEEK_END:
            target = self._size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if target < 0:
            raise OSError("negative seek position")
        if target < self._position:
            if self._window_start <= target < self._window_start + len(self._window):
                # Inside the retained window: no re-decompression needed. The upper
                # bound matters: without it an empty window would satisfy the test for
                # any target and silently desynchronise us from the real stream.
                self._position = target
                return self._position
            self._reopen()
        self._skip_forward(target - self._position)
        return self._position

    def _skip_forward(self, count: int) -> None:
        assert self._stream is not None
        while count > 0:
            cached = self._read_from_window(min(count, _SKIP_CHUNK))
            if cached:
                count -= len(cached)
                continue
            chunk = self._stream.read(min(count, _SKIP_CHUNK))
            if not chunk:
                return
            self._remember(chunk)
            self._position += len(chunk)
            count -= len(chunk)

    def tell(self) -> int:
        return self._position

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        super().close()


class WheelArchive:
    """A wheel opened for reading, with its identity and its guards."""

    def __init__(
        self, path: Path, limits: ArchiveLimits | None = None, sha256: str | None = None
    ) -> None:
        self._path = Path(path)
        self.limits = limits or ArchiveLimits()
        self.filename = self._path.name
        self.size_bytes = self._path.stat().st_size
        # Callers that already hashed the file (the cache lookup does) pass it back in
        # rather than paying for a second full read of every wheel in the index.
        self.sha256 = sha256 if sha256 is not None else hash_wheel(self._path)
        self._errors: dict[tuple[str, str, str], ScanError] = {}
        try:
            self._zip = zipfile.ZipFile(self._path)
            infos = self._zip.infolist()
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            raise errors.WheelReadError(f"{self.filename}: not a readable zip: {exc}") from None

        self._members: dict[str, MemberInfo] = {}
        self._infos: dict[str, zipfile.ZipInfo] = {}
        for info in infos:
            if info.is_dir():
                continue
            if info.filename in self._members:
                self._record(errors.DUPLICATE_MEMBER, info.filename, "member name appears twice")
            mode = info.external_attr >> 16
            self._members[info.filename] = MemberInfo(
                name=info.filename,
                size=info.file_size,
                compressed_size=info.compress_size,
                is_symlink=stat.S_ISLNK(mode),
                mode=mode,
            )
            self._infos[info.filename] = info

        self.total_uncompressed_bytes = sum(member.size for member in self._members.values())
        if self.total_uncompressed_bytes > self.limits.max_total_uncompressed_bytes:
            self._record(
                errors.SIZE_LIMIT_EXCEEDED,
                None,
                f"archive expands to {self.total_uncompressed_bytes} bytes",
            )

    @classmethod
    def open(
        cls, path: str | Path, limits: ArchiveLimits | None = None, sha256: str | None = None
    ) -> WheelArchive:
        return cls(Path(path), limits, sha256)

    # --- membership ---------------------------------------------------------

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._members))

    @property
    def members(self) -> tuple[MemberInfo, ...]:
        return tuple(self._members[name] for name in sorted(self._members))

    def member(self, name: str) -> MemberInfo:
        return self._members[name]

    def __contains__(self, name: str) -> bool:
        return name in self._members

    # --- errors -------------------------------------------------------------

    @property
    def errors(self) -> tuple[ScanError, ...]:
        return tuple(sorted(self._errors.values(), key=ScanError.sort_key))

    def _record(self, kind: str, path: str | None, message: str) -> None:
        key = (STAGE_ARCHIVE, path or "", kind)
        if key not in self._errors:
            self._errors[key] = ScanError(
                stage=STAGE_ARCHIVE, kind=kind, message=message, path=path
            )

    # --- limits -------------------------------------------------------------

    def is_within_limits(self, name: str) -> bool:
        """Whether this member may be read. Records why not, so refusal is visible."""
        member = self._members[name]
        if member.size > self.limits.max_member_bytes:
            self._record(
                errors.BINARY_TOO_LARGE,
                name,
                f"member is {member.size} bytes, over the {self.limits.max_member_bytes} limit",
            )
            return False
        if member.size >= self.limits.ratio_check_floor_bytes and member.compressed_size > 0:
            ratio = member.size // member.compressed_size
            if ratio > self.limits.max_compression_ratio:
                self._record(
                    errors.COMPRESSION_RATIO_EXCEEDED,
                    name,
                    f"member expands {ratio}x, over the {self.limits.max_compression_ratio} limit",
                )
                return False
        return True

    # --- reading ------------------------------------------------------------

    def read(self, name: str) -> bytes:
        """Read one member fully. Raises WheelReadError rather than returning junk."""
        if not self.is_within_limits(name):
            raise errors.WheelReadError(f"{name}: refused by archive limits")
        try:
            return self._zip.read(name)
        except (zipfile.BadZipFile, OSError, EOFError, ValueError) as exc:
            self._record(errors.MEMBER_READ_ERROR, name, f"unreadable member: {exc}")
            raise errors.WheelReadError(f"{name}: unreadable member: {exc}") from None

    def open_member(self, name: str) -> BinaryIO:
        """A seekable stream over one member, in memory when small, streamed when not."""
        if not self.is_within_limits(name):
            raise errors.WheelReadError(f"{name}: refused by archive limits")
        member = self._members[name]
        if member.size <= self.limits.max_in_memory_bytes:
            return io.BytesIO(self.read(name))
        member_stream = SeekableZipMember(
            self._zip, name, member.size, self.limits.read_back_window_bytes
        )
        return io.BufferedReader(member_stream)  # type: ignore[return-value]

    def symlink_target(self, name: str) -> str | None:
        """The path a symlink member points at. Recorded, never followed.

        A symlink target is a path, so anything larger than a few kilobytes is not a
        symlink. Reading it anyway would decompress an arbitrary amount of data outside
        every other limit in this class, which is a cheap way to exhaust memory from a
        two megabyte archive.
        """
        member = self._members[name]
        if not member.is_symlink:
            return None
        if member.size > self.limits.max_symlink_target_bytes:
            self._record(
                errors.SIZE_LIMIT_EXCEEDED,
                name,
                f"symlink target is {member.size} bytes, refusing to read it",
            )
            return None
        try:
            with self._zip.open(name) as stream:
                raw = stream.read(self.limits.max_symlink_target_bytes)
        except (zipfile.BadZipFile, OSError, EOFError, ValueError, MemoryError):
            self._record(errors.MEMBER_READ_ERROR, name, "unreadable symlink target")
            return None
        return raw.decode("utf-8", errors="replace")

    # --- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        self._zip.close()

    def __enter__(self) -> WheelArchive:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def hash_wheel(path: str | Path) -> str:
    """The sha256 of the wheel file, which is half of the scan cache key."""
    path = Path(path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()
