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

`partial_analysis` survives for three cases: a `LC_SYMTAB` that could not be read in
full, whether it is absent, unreachable or names nothing we could resolve, so the
imported/defined split is missing or incomplete; a slice of a fat binary that could not
be read, or that the fat header placed outside the object, so one architecture is
unknown rather than clean; and a header or set of load commands that would not parse at
all, which costs the structural read but not the strings already found.

A universal binary is read slice by slice and merged into one record. Every slice
reading cleanly is what clears the flag, which matters because most macOS wheels are
universal2: while only the first slice was read, every fat object was partial, and a
universal2 wheel with no crypto in it came out `OPAQUE` rather than
`NO_CRYPTO_DETECTED`.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, replace

from .. import evidence
from ..errors import MACHO_PARSE_ERROR
from ..evidence import BinaryEvidence, ScanError, SymbolMatch
from ..ruleset import BinaryPatterns
from .fallback import read_strings_only
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

# A real universal binary carries a handful of architectures: Apple has never shipped
# more than four at once. Past that it is a way to make one small object cost a pass over
# itself per entry, so the declared count is capped and the excess reported as unread.
_MAX_FAT_SLICES = 32

_CPU_TYPE_NAMES = {
    0x00000007: "CPU_TYPE_X86",
    0x01000007: "CPU_TYPE_X86_64",
    0x0000000C: "CPU_TYPE_ARM",
    0x0100000C: "CPU_TYPE_ARM64",
    0x00000012: "CPU_TYPE_POWERPC",
    0x01000012: "CPU_TYPE_POWERPC64",
}


@dataclass(frozen=True, slots=True)
class _Slice:
    """Where one architecture's Mach-O object sits inside the file.

    A thin object is one slice at offset zero; a universal binary is one per
    architecture. `size` is what the fat header declares, and like every other
    self-declared length here it is measured against the bytes that exist.
    """

    offset: int
    size: int


class _Unreadable(Exception):
    """A slice this reader cannot make sense of. Its text is what the record carries.

    Spelled the way `binfmt.pe._Malformed` is, so the two hand-rolled readers answer
    "this structure is not what it claims" the same way.
    """


@dataclass(frozen=True, slots=True)
class _SliceHeader:
    """One slice's header and load commands, before its symbol table is reached."""

    slice_: _Slice
    cputype: int
    is64: bool
    big_endian: bool
    soname: str | None
    needed: tuple[str, ...]
    rpath: tuple[str, ...]
    symtab: _Symtab | None


@dataclass(frozen=True, slots=True)
class _SliceEvidence:
    """What one slice yielded, before the slices are merged into one record."""

    cputype: int
    is64: bool
    big_endian: bool
    soname: str | None
    needed: tuple[str, ...]
    rpath: tuple[str, ...]
    matches: frozenset[SymbolMatch]
    symtab_count: int
    stripped: bool
    has_symtab: bool
    symbols_complete: bool
    symbols_failed: bool


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


def _unparsed(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    max_strings_bytes: int,
    messages: tuple[str, ...],
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
    """Evidence for a Mach-O whose structure we could not read, plus the error saying so.

    A fat header that will not parse, or load commands that run off the end, cost the
    header fields and the symbol table. They do not cost the banner a statically linked
    OpenSSL left in the object, which is sometimes the only evidence there is.

    This re-reads from the start, which the happy path is careful never to do. That is
    affordable precisely here: this object is being abandoned, so nothing later pays for
    the reopen this forces.
    """
    result, _ = read_strings_only(
        stream,
        path,
        patterns,
        vendored=vendored,
        fmt=evidence.FORMAT_MACHO,
        max_strings_bytes=max_strings_bytes,
    )
    result = replace(result, partial_reasons=("macho_structure_incomplete",))
    return result, tuple(
        sorted({_error(path, why) for why in messages}, key=lambda e: e.sort_key())
    )


def read_macho(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    max_strings_bytes: int = MAX_STRINGS_BYTES,
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
    """Read one Mach-O object, thin or fat, and return one record for it.

    A universal binary is read slice by slice and merged into a single
    `BinaryEvidence`, because the thing being described is the member of the wheel,
    not the architecture: `path` is what `own_base` and the vendored-path matching key
    on, and one record per slice would duplicate it. `needed`, `rpath` and
    `matched_symbols` merge as sorted unions and `symtab_count` as a sum, so a symbol
    defined in only one architecture is still a symbol this object defines.

    `machine`, `bits` and `endian` come from the first slice that parsed, which is what
    they meant before every slice was read. They describe one architecture and cannot
    describe several; the merged fields above are the ones that answer the question
    this tool asks. `soname` follows a third rule, the first one any slice declared: it
    is `LC_ID_DYLIB`, the install name, and every slice of a real universal binary
    carries the same one. It is called out because `linkage` reads it first of all, so
    a wrong answer here is a wrong posture.

    Strings are extracted from the whole object rather than from individual segments:
    unlike ELF, this reader does not parse `LC_SEGMENT[_64]`, so there is no section
    list to filter by allocation or executability. For a universal binary that means
    one pass over every slice at once, which is also why it is done here rather than
    per slice.
    """
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(0)
    head = stream.read(4)
    if len(head) < 4:
        return _unparsed(
            stream,
            path,
            patterns,
            vendored=vendored,
            max_strings_bytes=max_strings_bytes,
            messages=("object is too short to sniff",),
        )
    magic = int.from_bytes(head, "big")

    slices: tuple[_Slice, ...] = (_Slice(offset=0, size=size),)
    header_reasons: tuple[str, ...] = ()
    if magic in (_FAT_MAGIC, _FAT_CIGAM):
        try:
            stream.seek(0)
            slices, header_reasons = _list_fat_slices(stream, size)
        except Exception:
            return _unparsed(
                stream,
                path,
                patterns,
                vendored=vendored,
                max_strings_bytes=max_strings_bytes,
                messages=("failed to read the fat header",),
            )
        if not slices:
            return _unparsed(
                stream,
                path,
                patterns,
                vendored=vendored,
                max_strings_bytes=max_strings_bytes,
                messages=("no readable slice in fat binary",),
            )

    # Headers first, then the strings buffer, then the symbol tables. The order is the
    # point: every read here runs forward, and the one rewind to zero happens while the
    # stream is still only as far in as the last slice's load commands. Reading `raw`
    # first would put that rewind after a pass over the whole object, and through a
    # `wheelfile.SeekableZipMember` a rewind past the retained window is a second full
    # decompression of the member.
    headers: list[_SliceHeader] = []
    unread: list[str] = []
    for slice_ in slices:
        try:
            headers.append(_read_slice_header(stream, slice_))
        except _Unreadable as bad:
            unread.append(str(bad))

    if not headers:
        # Nothing parsed. For a thin object that is its own header; for a fat one it is
        # every architecture it declared. Either way the strings survive it.
        return _unparsed(
            stream,
            path,
            patterns,
            vendored=vendored,
            max_strings_bytes=max_strings_bytes,
            messages=tuple(unread),
        )

    stream.seek(0)
    raw = stream.read(min(size, max_strings_bytes))
    truncated_read = size > max_strings_bytes

    read = [_read_slice_symbols(stream, raw, header, patterns, size=size) for header in headers]

    errors: list[ScanError] = []
    partial_reasons: set[str] = set()
    if header_reasons:
        partial_reasons.add("macho_fat_slices_unread")
    if unread:
        partial_reasons.add(
            "macho_fat_slices_unread" if len(slices) > 1 else "macho_structure_incomplete"
        )
    # One per distinct reason. `ScanError` is deduplicated and sorted on the way out, so
    # two slices failing the same way is one message rather than two identical ones.
    errors.extend(_error(path, why) for why in unread)
    errors.extend(_error(path, why) for why in header_reasons)
    if any(slice_evidence.symbols_failed for slice_evidence in read):
        errors.append(_error(path, "failed to read the mach-o symbol table"))
        partial_reasons.add("macho_symtab_incomplete")
    # A slice with no `LC_SYMTAB` at all is incomplete but not an error: that is what
    # `strip` leaves behind and it is normal for a release wheel. Only a table that
    # was there and could not be read in full earns a message.
    if any(
        slice_evidence.has_symtab
        and not slice_evidence.symbols_failed
        and not slice_evidence.symbols_complete
        for slice_evidence in read
    ):
        errors.append(_error(path, "mach-o symbol table could not be read in full"))
        partial_reasons.add("macho_symtab_incomplete")

    first = read[0]
    merged: set[SymbolMatch] = set()
    needed: set[str] = set()
    rpath: set[str] = set()
    soname: str | None = None
    symtab_count = 0
    for slice_evidence in read:
        merged |= slice_evidence.matches
        needed |= set(slice_evidence.needed)
        rpath |= set(slice_evidence.rpath)
        symtab_count += slice_evidence.symtab_count
        if soname is None:
            soname = slice_evidence.soname

    ordered = tuple(sorted(merged, key=lambda match: match.sort_key()))
    limit = patterns.limits.max_symbols_per_binary

    found = scan_strings(raw, patterns, max_strings_bytes)
    go = build_go_info(None, found.text, patterns)

    result = BinaryEvidence(
        path=path,
        format=evidence.FORMAT_MACHO,
        vendored_path=vendored,
        machine=_CPU_TYPE_NAMES.get(first.cputype, f"0x{first.cputype & 0xFFFFFFFF:08x}"),
        bits=64 if first.is64 else 32,
        endian="big" if first.big_endian else "little",
        soname=soname,
        needed=tuple(sorted(needed)),
        rpath=tuple(sorted(rpath)),
        # The Mach-O spelling of `binfmt.elf`'s "no `.symtab`": no `LC_SYMTAB` at all,
        # or one that declares no entries. Both are what `strip` leaves behind, and
        # both are normal for a release wheel, so this is recorded rather than treated
        # as a finding. A universal binary is stripped only when every slice is: one
        # architecture that kept its symbols is an object that has symbols.
        stripped=all(slice_evidence.stripped for slice_evidence in read),
        # `LC_SYMTAB` is the Mach-O counterpart of both ELF tables, so its entry count
        # lands here, summed over the slices. `BinaryEvidence.is_opaque` deliberately
        # tests only `dynsym_count`, which no Mach-O ever sets: widening it would also
        # flip every ELF object that has a `.symtab` but no `.dynsym`, which is not
        # this reader's call to make.
        symtab_count=symtab_count,
        matched_symbols=ordered[:limit],
        matched_strings=found.matched_strings,
        rust_crates=found.rust_crates,
        go=go,
        symbols_truncated=len(ordered) > limit,
        strings_truncated=truncated_read or found.truncated,
        # Every architecture has to have been read, and read in full, before this
        # object can claim it was examined. An unread slice is an unread object.
        partial_analysis=bool(unread)
        or bool(header_reasons)
        or not all(slice_evidence.symbols_complete for slice_evidence in read),
        partial_reasons=tuple(sorted(partial_reasons)),
    )
    return result, tuple(sorted(set(errors), key=lambda err: err.sort_key()))


def _list_fat_slices(stream, size: int) -> tuple[tuple[_Slice, ...], tuple[str, ...]]:
    """Return every slice a fat header declares, plus what it declared and we did not read.

    Fat headers and `fat_arch` entries are always big-endian on disk, regardless of
    host or slice byte order, so this part never needs an endianness switch.

    `nfat_arch` is a 32-bit field the object declares about itself, in the same family
    as Mach-O's `nsyms` and PE's `NumberOfNames`, and it is capped rather than believed.
    Reading every slice is what made it worth attacking: a few hundred bytes of arch
    table can name one symbol table ten thousand times over, and each entry would be a
    full parse of it.

    Duplicate offsets collapse to one slice, and that is not a shortfall: two entries
    naming one slice describe one slice, and counting it twice would inflate
    `symtab_count` for bytes that exist once.

    Each reason returned is an architecture that was named and not examined, which is
    not the same as having examined it, so the caller records the object as partial.
    """
    header = stream.read(8)
    if len(header) < 8:
        return (), ("fat header is truncated",)
    _, nfat_arch = struct.unpack(">II", header)
    slices: list[_Slice] = []
    seen: set[int] = set()
    reasons: set[str] = set()
    if nfat_arch > _MAX_FAT_SLICES:
        reasons.add("fat header declares more architectures than this reader walks")
    for _ in range(min(nfat_arch, _MAX_FAT_SLICES)):
        entry = stream.read(20)
        if len(entry) < 20:
            reasons.add("fat arch table is truncated")
            break
        _cputype, _cpusubtype, offset, arch_size, _align = struct.unpack(">iiIII", entry)
        if offset + 4 > size:
            reasons.add("fat header places a slice outside the object")
        elif offset not in seen:
            seen.add(offset)
            slices.append(_Slice(offset=offset, size=arch_size))
    return tuple(slices), tuple(sorted(reasons))


def _read_slice_header(stream, slice_: _Slice) -> _SliceHeader:
    """Parse one slice's header and load commands, from the stream, reading forward.

    Raises `_Unreadable` when the slice's magic is not one this reader knows, or when
    its header or load commands will not parse. The reason travels with the exception
    the way `binfmt.pe._Malformed` carries its own: "this is not a Mach-O at all" and
    "this is a Mach-O that was cut short" are different facts about the object, and a
    reader of the record can act on the difference.
    """
    stream.seek(slice_.offset)
    head = stream.read(4)
    if len(head) < 4:
        raise _Unreadable("object is too short to sniff")
    magic = int.from_bytes(head, "big")
    if magic in (_MH_MAGIC_32, _MH_CIGAM_32):
        is64, big_endian = False, magic == _MH_MAGIC_32
    elif magic in (_MH_MAGIC_64, _MH_CIGAM_64):
        is64, big_endian = True, magic == _MH_MAGIC_64
    else:
        raise _Unreadable("not a recognisable Mach-O object")

    try:
        stream.seek(slice_.offset)
        cputype, soname, needed, rpath, symtab = _read_thin(
            stream, slice_.offset, slice_.size, is64, big_endian
        )
    except struct.error as bad:
        raise _Unreadable("mach-o header is truncated") from bad
    except Exception as bad:
        raise _Unreadable("failed to parse mach-o load commands") from bad

    return _SliceHeader(
        slice_=slice_,
        cputype=cputype,
        is64=is64,
        big_endian=big_endian,
        soname=soname,
        needed=needed,
        rpath=rpath,
        symtab=symtab,
    )


def _read_slice_symbols(
    stream, raw: bytes, header: _SliceHeader, patterns: BinaryPatterns, *, size: int
) -> _SliceEvidence:
    """Read one slice's symbol table, once its header has already been parsed."""
    matches: set[SymbolMatch] = set()
    symtab_count = 0
    # Absent until proven otherwise: the flag this drives must never be cleared by a
    # table we failed to read.
    symbols_complete = False
    symbols_failed = False
    if header.symtab is not None:
        try:
            matches, symtab_count, symbols_complete = _read_symbols(
                stream,
                raw,
                header.symtab,
                patterns,
                base=header.slice_.offset,
                end=min(size, header.slice_.offset + header.slice_.size),
                is64=header.is64,
                big_endian=header.big_endian,
            )
        except Exception:
            symbols_failed = True

    return _SliceEvidence(
        cputype=header.cputype,
        is64=header.is64,
        big_endian=header.big_endian,
        soname=header.soname,
        needed=header.needed,
        rpath=header.rpath,
        matches=frozenset(matches),
        symtab_count=symtab_count,
        stripped=header.symtab is None or header.symtab.nsyms == 0,
        has_symtab=header.symtab is not None,
        symbols_complete=symbols_complete,
        symbols_failed=symbols_failed,
    )


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
) -> tuple[set[SymbolMatch], int, bool]:
    """Return this slice's matches, its entry count, and whether it was read in full.

    The matches come back uncapped and unordered. A universal binary merges the
    slices before sorting and capping, so capping here would let which symbols
    survive depend on which slice they came from.

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
    return matches, len(table) // entry_size, complete


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
