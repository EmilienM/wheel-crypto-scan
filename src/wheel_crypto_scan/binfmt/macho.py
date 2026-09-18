"""Mach-O reading: header, load commands and `LC_SYMTAB`, hand-rolled with `struct`.

`LC_ID_DYLIB`, `LC_LOAD_DYLIB` and `LC_RPATH` answer the same "does it depend on the
system library or carry its own" question that `binfmt.elf` answers for ELF, and
`LC_SYMTAB` draws the imported-versus-defined line the rest of the tool turns on: an
undefined `_EVP_DigestInit_ex` means the wheel calls an OpenSSL it does not carry, the
same name defined means it carries one. Darwin's C ABI prefixes every C symbol with an
underscore, which is stripped back off so a Mach-O record names a symbol the way an ELF
record names the same symbol.

Still not read: the indirect symbol table and the two-level namespace ordinals in
`LC_DYSYMTAB`, which would say which dependency each import is expected to resolve
against. ELF offers no such attribution either, so leaving it out costs nothing against
the ELF path and does not make the read a partial one.

Also not read, and a real blind spot: `LC_DYLD_INFO`, `LC_DYLD_CHAINED_FIXUPS` and
`LC_DYLD_EXPORTS_TRIE`, which on modern macOS are the authoritative import and export
tables. `LC_SYMTAB` is normally kept beside them, but an object that carries one with
`nsyms == 0` is read here as a complete read of an empty table, so its imports are
missed rather than reported as unread.

`partial_analysis` survives for two cases: a `LC_SYMTAB` that could not be read in
full, whether it is absent, unreachable or names nothing we could resolve, so the
imported/defined split is missing or incomplete; and a fat binary, where only the
first slice is examined and the other slices are left unread pending the follow-up
work to walk all of them.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass

from .. import evidence
from ..errors import MACHO_PARSE_ERROR
from ..evidence import BinaryEvidence, ScanError, SymbolMatch
from ..ruleset import BinaryPatterns
from .golang import build_go_info
from .strings import MAX_STRINGS_BYTES, sanitize, scan_strings

_MH_MAGIC_32 = 0xFEEDFACE
_MH_CIGAM_32 = 0xCEFAEDFE
_MH_MAGIC_64 = 0xFEEDFACF
_MH_CIGAM_64 = 0xCFFAEDFE
_FAT_MAGIC = 0xCAFEBABE
_FAT_CIGAM = 0xBEBAFECA

_LC_SYMTAB = 0x02
_LC_LOAD_DYLIB = 0x0C
_LC_ID_DYLIB = 0x0D
_LC_RPATH = 0x8000001C

# `struct symtab_command` is cmd, cmdsize and the four offsets below.
_SYMTAB_COMMAND_SIZE = 24

# nlist flags. N_STAB marks a debug entry rather than a symbol; N_TYPE is the field that
# says where the symbol lives, and N_UNDF in it means "not in this object".
_N_STAB = 0xE0
_N_TYPE = 0x0E
_N_UNDF = 0x00

# nlist is n_strx(4) n_type(1) n_sect(1) n_desc(2) n_value(4), nlist_64 the same with an
# 8-byte n_value. Only the first three fields are read, so the size is the only
# difference that matters here.
_NLIST_SIZE = {False: 12, True: 16}

_CPU_TYPE_NAMES = {
    0x00000007: "CPU_TYPE_X86",
    0x01000007: "CPU_TYPE_X86_64",
    0x0000000C: "CPU_TYPE_ARM",
    0x0100000C: "CPU_TYPE_ARM64",
    0x00000012: "CPU_TYPE_POWERPC",
    0x01000012: "CPU_TYPE_POWERPC64",
}


@dataclass(frozen=True, slots=True)
class _Symtab:
    """`LC_SYMTAB`: where the symbol and string tables sit, measured from the slice."""

    symoff: int
    nsyms: int
    stroff: int
    strsize: int


def _strip_abi_prefix(name: str) -> str:
    """Strip Darwin's leading underscore, so a symbol reads as it does in ELF.

    The Mach-O C ABI prefixes every C symbol with `_`, so the OpenSSL entry point an ELF
    object calls `EVP_DigestInit_ex` appears here as `_EVP_DigestInit_ex`, and a ruleset
    written once for both would match neither. Removing exactly one underscore inverts
    that prefixing and nothing else: a C++ symbol `__Z3foov` becomes the `_Z3foov` its ELF
    counterpart carries, still mangled. This is not demangling.

    It runs on the raw name, before `sanitize`, because the ABI prefix is a property of
    the bytes the linker wrote: a `\\x01`-escaped name means "no ABI prefix was added",
    and sanitising first would drop the escape and invite this to strip an underscore
    that belongs to the symbol.
    """
    return name[1:] if name.startswith("_") else name


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
    max_strings_bytes: int = MAX_STRINGS_BYTES,
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

    is_fat = magic in (_FAT_MAGIC, _FAT_CIGAM)
    slice_offset = 0
    slice_size = size
    if is_fat:
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

    cputype, soname, needed, rpath, symtab = header_evidence

    stream.seek(0)
    raw = stream.read(min(size, max_strings_bytes))
    truncated_read = size > max_strings_bytes
    strings_found = scan_strings(raw, patterns, max_strings_bytes)
    go = build_go_info(None, strings_found.text, patterns)

    errors: list[ScanError] = []
    matched_symbols: tuple[SymbolMatch, ...] = ()
    symbols_truncated = False
    symtab_count = 0
    # Absent until proven otherwise: the flag this drives must never be cleared by a
    # table we failed to read.
    symbols_complete = False
    if symtab is not None:
        try:
            matched_symbols, symbols_truncated, symtab_count, symbols_complete = _read_symbols(
                stream,
                raw,
                symtab,
                patterns,
                base=slice_offset,
                end=min(size, slice_offset + slice_size),
                is64=is64,
                big_endian=big_endian,
            )
        except Exception:
            errors.append(_error(path, "failed to read the mach-o symbol table"))
        else:
            if not symbols_complete:
                errors.append(_error(path, "mach-o symbol table could not be read in full"))

    machine = _CPU_TYPE_NAMES.get(cputype, f"0x{cputype & 0xFFFFFFFF:08x}")
    # The Mach-O spelling of `binfmt.elf`'s "no `.symtab`": no `LC_SYMTAB` at all, or one
    # that declares no entries. Both are what `strip` leaves behind, and both are normal
    # for a release wheel, so this is recorded rather than treated as a finding.
    stripped = symtab is None or symtab.nsyms == 0
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
        stripped=stripped,
        # `LC_SYMTAB` is the Mach-O counterpart of both ELF tables, so its entry count
        # lands here. `BinaryEvidence.is_opaque` deliberately tests only `dynsym_count`,
        # which no Mach-O ever sets: widening it would also flip every ELF object that
        # has a `.symtab` but no `.dynsym`, which is not this reader's call to make.
        symtab_count=symtab_count,
        matched_symbols=matched_symbols,
        matched_strings=strings_found.matched_strings,
        rust_crates=strings_found.rust_crates,
        go=go,
        symbols_truncated=symbols_truncated,
        strings_truncated=truncated_read or strings_found.truncated,
        partial_analysis=not symbols_complete or is_fat,
    )
    return result, tuple(sorted(set(errors), key=lambda err: err.sort_key()))


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
) -> tuple[int, str | None, tuple[str, ...], tuple[str, ...], _Symtab | None]:
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
    symtab: _Symtab | None = None
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
        elif cmd == _LC_SYMTAB and len(body) >= _SYMTAB_COMMAND_SIZE:
            symoff, nsyms, stroff, strsize = struct.unpack_from(end + "IIII", body, 8)
            symtab = _Symtab(symoff=symoff, nsyms=nsyms, stroff=stroff, strsize=strsize)
        pos += cmdsize

    return (
        cputype,
        soname,
        tuple(sorted(set(needed))),
        tuple(sorted(set(rpaths))),
        symtab,
    )


def _read_symbols(
    stream,
    raw: bytes,
    symtab: _Symtab,
    patterns: BinaryPatterns,
    *,
    base: int,
    end: int,
    is64: bool,
    big_endian: bool,
) -> tuple[tuple[SymbolMatch, ...], bool, int, bool]:
    """Return the matches, whether they were capped, the entry count, and completeness.

    `symoff` and `stroff` are measured from the start of the slice, not the start of the
    file, so `base` is what makes a fat binary's tables resolve to the architecture whose
    header we just read rather than to the fat header.

    Each table is read exactly once, in file order, the way `binfmt.elf._iter_symbols`
    reads its own and for the reason given there: in a zip member too large to hold in
    memory, a backwards seek costs a fresh decompression of everything before it.
    """
    entry_size = _NLIST_SIZE[is64]
    sym_start = base + symtab.symoff
    str_start = base + symtab.stroff
    sym_wanted = symtab.nsyms * entry_size
    sym_length = _available(sym_start, sym_wanted, end)
    str_length = _available(str_start, symtab.strsize, end)
    if sym_start <= str_start:
        table = _region(stream, raw, sym_start, sym_length)
        strings = _region(stream, raw, str_start, str_length)
    else:
        strings = _region(stream, raw, str_start, str_length)
        table = _region(stream, raw, sym_start, sym_length)

    matches: set[SymbolMatch] = set()
    named = 0
    unresolved = 0
    for name, undefined, resolved, debug in _iter_symbols(table, strings, entry_size, big_endian):
        if not resolved:
            unresolved += 1
            continue
        if not name:
            continue
        named += 1
        # A debug entry describes a source file or a line number. Its N_TYPE bits are
        # not a section index, so reading one as a symbol turns a stabs record into a
        # claim that this object defines the code. Its name was still read, though,
        # which is why it counts above.
        if debug:
            continue
        groups = patterns.symbol_groups_for(name)
        if not groups:
            continue
        binding = evidence.BINDING_IMPORTED if undefined else evidence.BINDING_DEFINED
        for group in groups:
            matches.add(SymbolMatch(name=name, group=group, binding=binding))

    ordered = tuple(sorted(matches, key=lambda match: match.sort_key()))
    limit = patterns.limits.max_symbols_per_binary
    # "We read every name and none of them was crypto" has to be earned, because it is
    # indistinguishable in the record from "this object has no crypto". An entry naming
    # a string we could not resolve, and a table whose entries name nothing readable at
    # all, are both unread symbols: a hidden string table, indices past its end and
    # indices all left at zero are the cheap ways to make a wheel look clean, and each
    # of them lands here.
    complete = (
        len(table) == sym_wanted
        and len(strings) == symtab.strsize
        and not unresolved
        and (not symtab.nsyms or (bool(strings) and bool(named)))
    )
    return ordered[:limit], len(ordered) > limit, len(table) // entry_size, complete


def _available(start: int, wanted: int, end: int) -> int:
    """How much of a declared table actually exists inside the slice.

    `nsyms` and `strsize` are 32-bit fields the object declares about itself, so a
    200-byte file is free to promise a 64 GiB symbol table. What gets read is measured
    against the bytes that are there, never against the bytes that were promised.
    """
    if start > end:
        return 0
    return max(0, min(wanted, end - start))


def _region(stream, raw: bytes, start: int, length: int) -> bytes:
    """Bytes [start, start + length) of the object, preferring the copy already in hand.

    `raw` is the prefix read for string extraction; serving from it spares a second pass
    over every object whose symbol table sits inside that prefix, which is all of them
    below the string limit.

    A table that starts inside `raw` and runs past its end is served from both: the part
    already held, then a forward read of the remainder. Re-reading the whole table from
    `start` would be a backwards seek, and through a zip member that is one more full
    decompression pass of everything before it.
    """
    if length <= 0:
        return b""
    if start + length <= len(raw):
        return raw[start : start + length]
    if start < len(raw):
        held = raw[start:]
        stream.seek(len(raw))
        return held + stream.read(length - len(held))
    stream.seek(start)
    return stream.read(length)


def _iter_symbols(
    table: bytes, strings: bytes, entry_size: int, big_endian: bool
) -> Iterator[tuple[str, bool, bool, bool]]:
    """Yield (name, is_undefined, name_resolved, is_debug) for every entry in the table.

    Every entry is reported, including the ones with nothing usable in them: an entry
    whose `n_strx` points past the end of the string table is the difference between
    "no crypto here" and "we could not read the names", and only the caller can tell
    those two apart. `name` is empty for index 0, which is how nlist spells "this entry
    has no name", and for an entry whose name sanitises away to nothing.
    """
    head = struct.Struct((">" if big_endian else "<") + "IBB")
    for base in range(0, len(table) - entry_size + 1, entry_size):
        n_strx, n_type, _n_sect = head.unpack_from(table, base)
        undefined = (n_type & _N_TYPE) == _N_UNDF
        debug = bool(n_type & _N_STAB)
        if n_strx >= len(strings):
            yield "", undefined, False, debug
            continue
        stop = strings.find(b"\x00", n_strx)
        text = strings[n_strx:stop] if stop != -1 else strings[n_strx:]
        name = sanitize(_strip_abi_prefix(text.decode("utf-8", "replace")))
        yield name, undefined, True, debug


def _read_cstring(body: bytes, offset: int) -> str | None:
    if offset < 0 or offset >= len(body):
        return None
    end = body.find(b"\x00", offset)
    if end == -1:
        end = len(body)
    try:
        return sanitize(body[offset:end].decode("ascii"))
    except UnicodeDecodeError:
        return None
