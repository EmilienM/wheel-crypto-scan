"""Mach-O reading: header and load commands only, hand-rolled with `struct`.

Deliberately medium depth. `LC_ID_DYLIB`, `LC_LOAD_DYLIB` and `LC_RPATH` cover the same
"does it depend on the system library or carry its own" question that `binfmt.elf`
answers for ELF, and they are cheap to parse correctly. Symbol tables (`LC_SYMTAB`) are
not implemented: resolving them needs the string and symbol tables' file offsets from
a command we do parse, but also correct handling of indirect symbols and two-level
namespaces to say anything as precise as ELF's imported/defined split, which is out of
scope here. Every Mach-O result is therefore returned with `partial_analysis=True`,
so a wheel can never look clean merely because this reader cannot fully see into it.
"""

from __future__ import annotations

import struct
from dataclasses import replace

from .. import evidence
from ..errors import MACHO_PARSE_ERROR
from ..evidence import BinaryEvidence, ScanError
from ..ruleset import BinaryPatterns
from .golang import build_go_info
from .rust import find_rust_crates
from .strings import extract_printable, match_string_groups

_MH_MAGIC_32 = 0xFEEDFACE
_MH_CIGAM_32 = 0xCEFAEDFE
_MH_MAGIC_64 = 0xFEEDFACF
_MH_CIGAM_64 = 0xCFFAEDFE
_FAT_MAGIC = 0xCAFEBABE
_FAT_CIGAM = 0xBEBAFECA

_LC_LOAD_DYLIB = 0x0C
_LC_ID_DYLIB = 0x0D
_LC_RPATH = 0x8000001C

_CPU_TYPE_NAMES = {
    0x00000007: "CPU_TYPE_X86",
    0x01000007: "CPU_TYPE_X86_64",
    0x0000000C: "CPU_TYPE_ARM",
    0x0100000C: "CPU_TYPE_ARM64",
    0x00000012: "CPU_TYPE_POWERPC",
    0x01000012: "CPU_TYPE_POWERPC64",
}

_PRINTABLE = range(0x20, 0x7F)


def _sanitize(text: str) -> str:
    return "".join(ch for ch in text if ord(ch) in _PRINTABLE)


def _error(path: str, message: str) -> ScanError:
    return ScanError(
        stage=evidence.STAGE_BINARY, kind=MACHO_PARSE_ERROR, message=message, path=path
    )


def _empty(path: str, *, vendored: bool) -> BinaryEvidence:
    return BinaryEvidence(
        path=path, format=evidence.FORMAT_MACHO, vendored_path=vendored, partial_analysis=True
    )


def read_macho(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    max_strings_bytes: int = 64 * 1024 * 1024,
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
    """Read one Mach-O object (thin or fat) and return its evidence.

    Strings are extracted from the whole object rather than from individual
    segments: unlike ELF, this reader does not parse `LC_SEGMENT[_64]`, so there is
    no section list to filter by allocation or executability. That is a coarser
    signal than the ELF reader's, but it still catches the banners and cargo paths
    this tool looks for.
    """
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(0)
    head = stream.read(4)
    if len(head) < 4:
        return _empty(path, vendored=vendored), (_error(path, "object is too short to sniff"),)
    magic = int.from_bytes(head, "big")

    slice_offset = 0
    slice_size = size
    if magic in (_FAT_MAGIC, _FAT_CIGAM):
        try:
            stream.seek(0)
            found = _find_fat_slice(stream, size)
        except Exception:
            return _empty(path, vendored=vendored), (_error(path, "failed to read the fat header"),)
        if found is None:
            return _empty(path, vendored=vendored), (
                _error(path, "no readable slice in fat binary"),
            )
        slice_offset, slice_size = found
        stream.seek(slice_offset)
        head = stream.read(4)
        magic = int.from_bytes(head, "big")

    if magic in (_MH_MAGIC_32, _MH_CIGAM_32):
        is64, big_endian = False, magic == _MH_MAGIC_32
    elif magic in (_MH_MAGIC_64, _MH_CIGAM_64):
        is64, big_endian = True, magic == _MH_MAGIC_64
    else:
        return _empty(path, vendored=vendored), (_error(path, "not a recognisable Mach-O object"),)

    try:
        stream.seek(slice_offset)
        header_evidence = _read_thin(stream, slice_offset, slice_size, is64, big_endian)
    except struct.error:
        return _empty(path, vendored=vendored), (_error(path, "mach-o header is truncated"),)
    except Exception:
        return _empty(path, vendored=vendored), (
            _error(path, "failed to parse mach-o load commands"),
        )

    cputype, soname, needed, rpath = header_evidence

    stream.seek(0)
    raw = stream.read(min(size, max_strings_bytes))
    truncated_read = size > max_strings_bytes
    extracted = extract_printable(raw, patterns.limits.min_string_length, max_strings_bytes)
    string_matches, string_match_truncated = match_string_groups(
        extracted, patterns.string_groups, patterns.limits.max_strings_per_binary
    )
    matched_strings = tuple(
        replace(match, value=match.value[: patterns.limits.max_evidence_chars])
        for match in string_matches
    )
    rust_crates, rust_truncated = find_rust_crates(
        extracted.text, patterns.cargo_path_regex, patterns.limits.max_rust_crates_per_binary
    )
    go = build_go_info(None, extracted.text, patterns)

    machine = _CPU_TYPE_NAMES.get(cputype, f"0x{cputype & 0xFFFFFFFF:08x}")
    result = BinaryEvidence(
        path=path,
        format=evidence.FORMAT_MACHO,
        vendored_path=vendored,
        machine=machine,
        bits=64 if is64 else 32,
        endian="big" if big_endian else "little",
        soname=soname,
        needed=needed,
        rpath=rpath,
        matched_strings=matched_strings,
        rust_crates=rust_crates,
        go=go,
        strings_truncated=truncated_read
        or extracted.truncated
        or string_match_truncated
        or rust_truncated,
        partial_analysis=True,
    )
    return result, ()


def _find_fat_slice(stream, size: int) -> tuple[int, int] | None:
    """Return (offset, size) of the first slice this reader can parse a header from.

    Fat headers and `fat_arch` entries are always big-endian on disk, regardless of
    host or slice byte order, so this part never needs an endianness switch.
    """
    header = stream.read(8)
    if len(header) < 8:
        return None
    _, nfat_arch = struct.unpack(">II", header)
    for _ in range(nfat_arch):
        entry = stream.read(20)
        if len(entry) < 20:
            return None
        _cputype, _cpusubtype, offset, arch_size, _align = struct.unpack(">iiIII", entry)
        if offset + 4 <= size:
            return offset, arch_size
    return None


def _read_thin(
    stream, base: int, slice_size: int, is64: bool, big_endian: bool
) -> tuple[int, str | None, tuple[str, ...], tuple[str, ...]]:
    """Parse one thin Mach-O header and its load commands, from the current position."""
    end = ">" if big_endian else "<"
    if is64:
        raw = stream.read(32)
        if len(raw) < 32:
            raise struct.error("mach_header_64 truncated")
        _magic, cputype, _subtype, _filetype, ncmds, sizeofcmds, _flags, _reserved = struct.unpack(
            end + "IIIIIIII", raw
        )
    else:
        raw = stream.read(28)
        if len(raw) < 28:
            raise struct.error("mach_header truncated")
        _magic, cputype, _subtype, _filetype, ncmds, sizeofcmds, _flags = struct.unpack(
            end + "IIIIIII", raw
        )

    commands = stream.read(sizeofcmds)
    if len(commands) < sizeofcmds:
        raise struct.error("load commands truncated")

    soname: str | None = None
    needed: list[str] = []
    rpaths: list[str] = []
    pos = 0
    for _ in range(ncmds):
        if pos + 8 > len(commands):
            break
        cmd, cmdsize = struct.unpack_from(end + "II", commands, pos)
        if cmdsize < 8 or pos + cmdsize > len(commands):
            break
        body = commands[pos : pos + cmdsize]
        if cmd in (_LC_LOAD_DYLIB, _LC_ID_DYLIB) and len(body) >= 12:
            (name_offset,) = struct.unpack_from(end + "I", body, 8)
            name = _read_cstring(body, name_offset)
            if name is not None:
                if cmd == _LC_ID_DYLIB:
                    soname = name
                else:
                    needed.append(name)
        elif cmd == _LC_RPATH and len(body) >= 12:
            (path_offset,) = struct.unpack_from(end + "I", body, 8)
            path = _read_cstring(body, path_offset)
            if path is not None:
                rpaths.append(path)
        pos += cmdsize

    return (
        cputype,
        soname,
        tuple(sorted(set(needed))),
        tuple(sorted(set(rpaths))),
    )


def _read_cstring(body: bytes, offset: int) -> str | None:
    if offset < 0 or offset >= len(body):
        return None
    end = body.find(b"\x00", offset)
    if end == -1:
        end = len(body)
    try:
        return _sanitize(body[offset:end].decode("ascii"))
    except UnicodeDecodeError:
        return None
