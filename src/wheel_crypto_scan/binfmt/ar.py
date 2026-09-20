"""Reads `ar`-format static archives (`.a` on Linux/macOS, `.lib` on Windows,
produced by GNU `ar`, LLVM's `llvm-ar`/`llvm-lib`, or a BSD `ar`) as a container of
native objects, one member handed to `read_binary` at a time.

Every other reader in this package answers to `binfmt.read_binary`'s contract: one
stream in, one `BinaryEvidence` out. An archive cannot: it holds many relocatable
objects (`.o`/`.obj`), and each one is separate evidence a consumer wants told apart
-- which member defines a crypto symbol matters as much as whether one does. So this
module is not registered in `binfmt._READERS` and is never reached through
`read_binary`'s own dispatch; `layers.binaries.scan_binaries` calls it directly, in
place of `read_binary`, once it has sniffed the archive magic for itself.

The container format is simple and stable across implementations: an 8-byte magic,
then a sequence of 60-byte member headers (name, mtime, uid, gid, mode, size, a
2-byte end marker), each followed by that many bytes of data, padded to an even
offset. Two extensions matter here, both read-only conventions rather than policy:
GNU's long-name table (a pseudo-member named `//` holding every long name back to
back, referenced by later members as `/<offset>`) and BSD's extended name (`#1/<N>`,
meaning the real name is the first `N` bytes of the member's own data). Verified
against real `ar`-produced archives (GNU `ar` 2.46, this module's development
host); the BSD `#1/N` path is implemented from the documented format and has not
been checked against a real BSD `ar`.

Every member header is visited by seeking, never by reading the archive into one
buffer: an `ar` file can legitimately be as large as any other member this tool
streams, and materialising the whole thing (worse, slicing every member out of a
second full copy) would spend exactly the memory `wheelfile.ArchiveLimits` streams a
large member specifically to avoid. A real member's own bytes are handed to
`read_binary` through `_Window`, a view onto the *original* stream rather than a
copy, so a structural reader still sees the object's true, untruncated bytes and
applies its own `max_strings_bytes` budget the way it already does for anything
else -- artificially truncating a member's bytes at the archive layer would risk
misreading a section table that legitimately sits past an arbitrary cut as corrupt,
which is a bug this module does not want to introduce for the sake of one.

A member whose name cannot be resolved -- a `#1/<N>` claiming more bytes than the
member holds, a `/<offset>` past the end of the long-name table or into a run that
never closes -- is still read, under a synthetic path that says so, with an error
naming the offset. Dropping it instead, which an earlier version of this module did,
loses the object's evidence to what is only a labelling failure: "unreadable means
`OPAQUE`, never `NO_CRYPTO_DETECTED`" applies to a name exactly as much as to a
structure. See #99's adversarial review.

This module needed no change to close #117, for an ELF member: a `.o`'s own symbol
table is `.symtab`, not `.dynsym`, and `binfmt.elf` now matches crypto symbol groups
against `.symtab` whenever `.dynsym` is genuinely absent -- exactly the shape every
relocatable ELF archive member has. Once `read_binary` (called on each member above)
picked that up, this module inherited the fix for free, the same as every earlier
`binfmt.elf` improvement. Left open: a Windows `.lib`'s `.obj` members are COFF, not
ELF, and `binfmt.pe` deliberately does not read the COFF symbol table at all (every
modern linker strips it in favour of a PDB); such a member is read as `FORMAT_UNKNOWN`,
strings-only, and #117 does nothing for it.

Archive-derived evidence never confirms another object's `needed` entry as resolving
inside the wheel: `BinaryEvidence.from_archive` marks every member this module
produces, and `linkage.member_stem_counts` excludes them for exactly that reason --
a relocatable object inside a static archive was never a file any real dynamic
loader could resolve a `DT_NEEDED` entry to, so a same-named `SONAME` on one, bytes
this module reads exactly as written and does not invent, must not be able to make
a genuinely system-linked sibling extension read as bundled.
"""

from __future__ import annotations

import io
from dataclasses import replace as dataclasses_replace

from .. import evidence
from ..errors import AR_PARSE_ERROR
from ..evidence import BinaryEvidence, ScanError
from ..ruleset import BinaryPatterns
from . import read_binary
from .fallback import read_strings_only
from .strings import MAX_STRINGS_BYTES

MAGIC = b"!<arch>\n"

_HEADER_SIZE = 60
_NAME_FIELD = slice(0, 16)
_SIZE_FIELD = slice(48, 58)
_END_FIELD = slice(58, 60)
_END_MAGIC = b"\x60\x0a"

# GNU's own symbol index (bare `/`) and every index/padding convention a real
# toolchain writes that is not a real object: BSD/Apple `ar`'s ranlib index
# (`__.SYMDEF`, `__.SYMDEF SORTED` on newer toolchains, `__.SYMDEF_64` for a 64-bit
# archive) and GNU's own 64-bit index (`/SYM64/`, no long-name reference needed
# since it is short enough to write inline). Not dispatched as objects: their
# content is `ar`'s own bookkeeping, not something `read_binary` has any use for,
# and misreading one as an unrecognised object used to cost the *whole archive* a
# spurious `partial_analysis`/`BIN_PARTIAL_FORMAT` verdict hit for every ordinary
# macOS or `.lib` import archive, not just a crafted one. See #99's adversarial
# review.
_PSEUDO_MEMBERS = frozenset(
    {b"/", b"//", b"/SYM64/", b"/SYM64", b"__.SYMDEF", b"__.SYMDEF SORTED", b"__.SYMDEF_64"}
)

# A cap on how many members one archive can hand to `read_binary`, independent of
# `max_binaries_per_record`'s cap on the record as a whole: that cap is applied once,
# after every binary member in the wheel (archive-contained or not) has already been
# read, so it bounds the record's *size* but not the *work* a crafted archive can
# demand before ever reaching it -- ten thousand one-byte members, each a full
# `read_binary` dispatch, would cost that regardless of how few of the results
# survive the later cap. Checked in the table-walking loop itself, which stops
# rather than merely stops dispatching once it is reached, so a crafted archive with
# far more headers than this cannot make the walk itself the unbounded part.
_MAX_MEMBERS = 4096


class _Window(io.RawIOBase):
    """A read-only, seekable view of `[start, start + length)` in `stream`, with its
    own position `0` meaning `start`.

    Exists so a member's bytes can be handed to `read_binary` without copying them
    out of the archive first, and without truncating them to a budget: the object
    stays exactly as large as it really is, and whichever structural reader gets it
    applies `max_strings_bytes` the same way it would for a member that was not
    inside an archive at all.
    """

    def __init__(self, stream, start: int, length: int) -> None:
        super().__init__()
        self._stream = stream
        self._start = start
        self._length = length
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            target = offset
        elif whence == io.SEEK_CUR:
            target = self._pos + offset
        elif whence == io.SEEK_END:
            target = self._length + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        self._pos = max(0, target)
        return self._pos

    def tell(self) -> int:
        return self._pos

    def readinto(self, b) -> int:
        remaining = self._length - self._pos
        if remaining <= 0:
            return 0
        self._stream.seek(self._start + self._pos)
        chunk = self._stream.read(min(len(b), remaining))
        b[: len(chunk)] = chunk
        self._pos += len(chunk)
        return len(chunk)


def _error(path: str, message: str) -> ScanError:
    return ScanError(stage=evidence.STAGE_BINARY, kind=AR_PARSE_ERROR, message=message, path=path)


def _bsd_extended_name_length(field: bytes) -> int | None:
    """The `N` in a BSD `#1/<N>` name field, or `None` when `field` is not one."""
    if field.startswith(b"#1/") and field[3:].isdigit():
        return int(field[3:])
    return None


def _resolve_name(field: bytes, member_prefix: bytes, long_names: bytes) -> str | None:
    """The member's real name, past GNU's and BSD's own conventions.

    `field` is the 16-byte name field with trailing spaces already stripped.
    `member_prefix` is read by the caller only for a BSD `#1/<N>` field -- empty for
    every other shape, since none of them need the member's own data to name it.
    Returns `None` when the name cannot be resolved at all: a `/<offset>`
    referencing a table that never appeared, pointing past its end, or into an entry
    that never closes with `/\\n`; or a `#1/<N>` claiming more bytes than the caller
    could read. `None` here means "could not be read", never "read as empty" -- the
    caller's fallback is a synthetic path, not silence, exactly because dropping the
    member would cost real, already-read evidence over nothing worse than its own
    label.
    """
    if field.startswith(b"/") and field[1:].isdigit():
        start = int(field[1:])
        if start >= len(long_names):
            return None
        end = long_names.find(b"/\n", start)
        if end == -1:
            return None
        name = long_names[start:end].decode("utf-8", errors="replace")
        return name or None
    length = _bsd_extended_name_length(field)
    if length is not None:
        if length > len(member_prefix):
            return None
        name = member_prefix[:length].rstrip(b"\x00").decode("utf-8", errors="replace")
        return name or None
    if field.endswith(b"/"):
        field = field[:-1]
    name = field.decode("utf-8", errors="replace")
    return name or None


def _dedupe(name: str, seen: dict[str, int]) -> str:
    """`name`, or `name` with a disambiguating suffix if this archive has already
    used it. Duplicate member names are ordinary in `ar` (two different object
    files legitimately named the same thing, vendored from different source
    directories); `binaries[].path` was unique before this module existed, and
    `record._cap_by_findings` keys a dict on it, so two members silently sharing one
    path would let the second's evidence overwrite the first's even when the cap had
    room for both.
    """
    seen[name] = seen.get(name, 0) + 1
    count = seen[name]
    return name if count == 1 else f"{name}#{count}"


def read_ar_members(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    max_strings_bytes: int = MAX_STRINGS_BYTES,
) -> tuple[tuple[BinaryEvidence, ...], tuple[ScanError, ...]]:
    """Walk one `ar` archive's member table and read every real object it holds.

    Never raises: a member table that cannot be walked to completion keeps whatever
    real members were found before the point of failure, each already read in full
    through `read_binary` and carrying its own evidence -- a structure that does not
    parse costs that structure, never the evidence already gathered. One error is
    recorded for the table itself when the walk stops early; a member whose own name
    could not be resolved is still read and dispatched, under a synthetic path, with
    its own error naming why. An archive holding no real object at all -- the magic
    alone, or nothing but index/padding pseudo-members -- still produces exactly one
    record, a strings-only pass over the whole archive, the same way every other
    reader here always produces something rather than nothing.
    """
    stream.seek(0, io.SEEK_END)
    total = stream.tell()
    stream.seek(0)
    if stream.read(len(MAGIC)) != MAGIC:
        # Only reachable if a caller other than `layers.binaries` (which already
        # sniffed this) calls in directly -- `tests/test_partial_reasons.py` does,
        # deliberately, to reach the fallback path below without a real archive.
        result, _no_errors = read_strings_only(
            stream,
            path,
            patterns,
            vendored=vendored,
            fmt=evidence.FORMAT_UNKNOWN,
            max_strings_bytes=max_strings_bytes,
            reason=evidence.PARTIAL_AR_MEMBER_TABLE_UNREAD,
        )
        return (result,), (_error(path, "not an ar-format archive"),)

    long_names = b""
    seen_names: dict[str, int] = {}
    real: list[tuple[str, int, int]] = []  # (resolved-or-synthetic name, start, size)
    table_errors: list[ScanError] = []
    member_errors: list[ScanError] = []
    truncated = False
    offset = len(MAGIC)
    while offset < total:
        if offset + _HEADER_SIZE > total:
            table_errors.append(_error(path, f"member header at offset {offset} is truncated"))
            break
        stream.seek(offset)
        header = stream.read(_HEADER_SIZE)
        if header[_END_FIELD] != _END_MAGIC:
            table_errors.append(
                _error(path, f"member header at offset {offset} has no end-of-header marker")
            )
            break
        size_text = header[_SIZE_FIELD].decode("ascii", errors="replace").strip()
        if not size_text.isdigit():
            table_errors.append(
                _error(path, f"member header at offset {offset} has a non-numeric size field")
            )
            break
        size = int(size_text, 10)
        member_start = offset + _HEADER_SIZE
        member_end = member_start + size
        if member_end > total:
            table_errors.append(
                _error(
                    path,
                    f"member at offset {offset} declares {size} bytes, past the end of the archive",
                )
            )
            break

        field = header[_NAME_FIELD].rstrip(b" ")
        if field == b"//":
            stream.seek(member_start)
            long_names = stream.read(min(size, max_strings_bytes))
        elif field in _PSEUDO_MEMBERS:
            pass
        elif len(real) >= _MAX_MEMBERS:
            truncated = True
            offset = member_end + (size % 2)
            break
        else:
            # Only BSD's `#1/<N>` needs the member's own leading bytes to name it;
            # every other shape resolves from the header field or the long-name
            # table alone, so the read below is skipped for the common case. Capped
            # the same way everything else here is, so a member claiming an absurd
            # `N` does not force a large read just to fail `_resolve_name`'s own
            # bounds check a moment later.
            prefix_length = _bsd_extended_name_length(field)
            member_prefix = b""
            if prefix_length is not None:
                stream.seek(member_start)
                member_prefix = stream.read(min(size, max_strings_bytes))
            name = _resolve_name(field, member_prefix, long_names)
            # BSD's `#1/<N>` embeds the name in the member's own leading bytes, so a
            # *successfully resolved* one has real content starting `N` bytes later
            # than every other naming convention's -- the window handed to
            # `read_binary` has to skip past the name to avoid handing it a
            # mangled, name-prefixed object. An unresolved name (the length claimed
            # more bytes than the member holds) cannot be trusted to mean anything
            # about where content starts, so it is not applied: the synthetic-name
            # fallback below reads the member's bytes exactly as they are.
            if name is not None and prefix_length is not None:
                content_start = member_start + prefix_length
                content_size = size - prefix_length
            else:
                content_start, content_size = member_start, size
            if name is None:
                member_errors.append(
                    _error(path, f"member at offset {offset} has an unresolvable name")
                )
                name = f"member@{offset}"
            real.append((_dedupe(name, seen_names), content_start, content_size))

        offset = member_end + (size % 2)

    if not real:
        stream.seek(0)
        result, _no_errors = read_strings_only(
            stream,
            path,
            patterns,
            vendored=vendored,
            fmt=evidence.FORMAT_AR,
            max_strings_bytes=max_strings_bytes,
            reason=evidence.PARTIAL_AR_MEMBER_TABLE_UNREAD,
        )
        return (result,), tuple(table_errors)

    binaries: list[BinaryEvidence] = []
    errors: list[ScanError] = [*table_errors, *member_errors]
    for name, member_start, size in real:
        # Wrapped in `BufferedReader` for the same reason `wheelfile.open_member`
        # wraps `SeekableZipMember`: a bare `RawIOBase` only promises one underlying
        # `read()` call per request, which can return fewer bytes than asked for even
        # mid-stream, and every structural reader here assumes an ordinary buffered
        # stream that fills the request or hits real EOF.
        window = io.BufferedReader(_Window(stream, member_start, size))
        member_evidence, read_errors = read_binary(
            window,
            f"{path}({name})",
            patterns,
            vendored=vendored,
            max_strings_bytes=max_strings_bytes,
        )
        binaries.append(dataclasses_replace(member_evidence, from_archive=True))
        errors.extend(read_errors)

    if truncated:
        errors.append(_error(path, f"more than {_MAX_MEMBERS} members; the rest were not read"))

    return tuple(binaries), tuple(sorted(errors, key=lambda err: err.sort_key()))
