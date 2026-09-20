"""Mach-O reading: header, load commands and `LC_SYMTAB`, hand-rolled with `struct`.

`LC_ID_DYLIB`, `LC_LOAD_DYLIB` and `LC_RPATH` answer the same "does it depend on the
system library or carry its own" question that `binfmt.elf` answers for ELF, and
`LC_SYMTAB` draws the imported-versus-defined line the rest of the tool turns on: an
undefined `_EVP_DigestInit_ex` means the wheel calls an OpenSSL it does not carry, the
same name defined means it carries one. Darwin's C ABI prefixes every C symbol with an
underscore, which is stripped back off so a Mach-O record names a symbol the way an ELF
record names the same symbol.

`LC_LOAD_DYLIB` is not the only load command the dynamic linker resolves as a real
dependency at load time. `LC_LOAD_WEAK_DYLIB` (tolerates the library being absent),
`LC_LAZY_LOAD_DYLIB` and `LC_LOAD_UPWARD_DYLIB` (both ordinary dependencies, only the
load timing differs) share `LC_LOAD_DYLIB`'s `dylib_command` layout byte for byte and
all three join `needed` the same way it does. `LC_REEXPORT_DYLIB` does too, for a
different reason: it makes the target's exports part of this object's own API surface,
the direct analogue of a PE forwarder (#54) -- a shim that re-exports libcrypto is
itself an OpenSSL API surface in the sense `linkage._binary_posture` cares about, and
`needed` is the field it reads first. #59 is what closed this: previously only
`LC_LOAD_DYLIB` and `LC_ID_DYLIB` were read and the other four were silently skipped,
so a weak, lazy, upward or re-exported libcrypto dropped out of `needed` without a
trace and a re-exporting shim read clean. The same issue closed two narrower gaps in
the same walk: a dylib-loading, `LC_ID_DYLIB` or `LC_RPATH` command whose string
offset could not be trusted -- outside the command's own body, below where a string
could legitimately start, or a run the body never closes -- used to be skipped rather
than flagged, and a non-ASCII byte inside an otherwise-readable name used to drop the
whole name instead of being sanitized the way `binfmt.elf` and `binfmt.pe` already
sanitize theirs.

Still not read: the indirect symbol table and the two-level namespace ordinals in
`LC_DYSYMTAB`, which would say which dependency each import is expected to resolve
against. ELF offers no such attribution either, so leaving it out costs nothing against
the ELF path and does not make the read a partial one.

Also not read, and a real blind spot: `LC_DYLD_INFO`, `LC_DYLD_CHAINED_FIXUPS` and
`LC_DYLD_EXPORTS_TRIE`, which on modern macOS are the authoritative import and export
tables. `LC_SYMTAB` is normally kept beside them, and an object carrying one that
declares nothing is reported as unread rather than clean. What is still missed is a
symbol reachable only through those tables, whose name is nowhere in the string table
either.

`partial_analysis` survives for six cases: a strings read that stopped before the end
of the object, so a region of it was never looked at; a `LC_SYMTAB` that could not be read in
full, whether it is absent, unreachable, names nothing we could resolve, holds nothing
but debug records, or declares fewer entries than it carries names for, so the
imported/defined split is missing or incomplete; a slice of a fat binary that could not
be read, or that the fat header placed outside the object, so one architecture is
unknown rather than clean; a header or set of load commands that would not parse at
all, which costs the structural read but not the strings already found; a
dylib-loading, `LC_ID_DYLIB` or `LC_RPATH` command whose string could not be read, so
a dependency, the object's own install name, or an rpath entry may be missing rather
than absent; and a load command's own `cmd`/`cmdsize` header that could not be
trusted, which stops the walk rather than guessing where the next one starts, so
every later command -- an honest `LC_LOAD_DYLIB` included -- is unaccounted for
rather than absent. #84.

A universal binary is read slice by slice and merged into one record, in both the
`FAT_MAGIC` and `FAT_MAGIC_64` forms, which differ only in the width of the arch table's
offset and size fields. Every slice reading cleanly is what clears the flag, which
matters because most macOS wheels are universal2: while only the first slice was read,
every fat object was partial, and a universal2 wheel with no crypto in it came out
`OPAQUE` rather than `NO_CRYPTO_DETECTED`.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass

from .. import evidence
from ..errors import MACHO_PARSE_ERROR
from ..evidence import BinaryEvidence, ScanError, SymbolMatch
from ..ruleset import BinaryPatterns
from .caps import cap
from .fallback import read_strings_only
from .golang import build_go_info
from .strings import MAX_STRINGS_BYTES, sanitize, scan_strings
from .symtab import BoundedNames, holds_a_name_not_read

_MH_MAGIC_32 = 0xFEEDFACE
_MH_CIGAM_32 = 0xCEFAEDFE
_MH_MAGIC_64 = 0xFEEDFACF
_MH_CIGAM_64 = 0xCFFAEDFE
_FAT_MAGIC = 0xCAFEBABE
_FAT_CIGAM = 0xBEBAFECA
# The 64-bit variants differ only in the arch table: `fat_arch_64` widens `offset` and
# `size` to 64 bits and adds a reserved word, so an entry is 32 bytes rather than 20.
# The magic is one bit away from the 32-bit one, which is exactly how an object of this
# shape gets missed.
_FAT_MAGIC_64 = 0xCAFEBABF
_FAT_CIGAM_64 = 0xBFBAFECA

# `fat_arch` is cputype, cpusubtype, offset, size, align. `fat_arch_64` is the same with
# 64-bit offset and size, plus a reserved word. The entry size sits beside the format
# rather than being derived at every use, and is asserted against it so the two cannot
# drift.
_FAT_ARCH = {False: (20, ">iiIII"), True: (32, ">iiQQII")}
assert all(struct.calcsize(fmt) == size for size, fmt in _FAT_ARCH.values())

_LC_SYMTAB = 0x02
_LC_LOAD_DYLIB = 0x0C
_LC_ID_DYLIB = 0x0D
_LC_LAZY_LOAD_DYLIB = 0x20
_LC_LOAD_WEAK_DYLIB = 0x80000018
_LC_RPATH = 0x8000001C
_LC_REEXPORT_DYLIB = 0x8000001F
_LC_LOAD_UPWARD_DYLIB = 0x80000023

# `dylib_command` -- offset, timestamp, current_version, compatibility_version -- is
# the identical struct behind every one of these, differing only in what the dynamic
# linker does with the name it holds. `LC_LOAD_DYLIB` is the ordinary case; the three
# below are the same dependency with different load-time tolerance or timing (absent
# is fine, resolved lazily, resolved after the things that depend on it); and
# `LC_REEXPORT_DYLIB` folds the target's exports into this object's own surface, the
# Mach-O analogue of a PE forwarder (#54). All five are read into `needed` the same
# way: the loader treats every one of them as a real dependency it must resolve.
_LC_DYLIB_DEPENDENCIES = frozenset(
    {
        _LC_LOAD_DYLIB,
        _LC_LOAD_WEAK_DYLIB,
        _LC_LAZY_LOAD_DYLIB,
        _LC_LOAD_UPWARD_DYLIB,
        _LC_REEXPORT_DYLIB,
    }
)

# The fixed header every `dylib_command` or `rpath_command` carries before its string
# can legitimately start. An offset inside that range names one of the fixed integer
# fields, not something the object spells out, and trusting it would let a crafted
# object announce a dependency or path it never named -- the decoy shape #56's ELF
# work is the precedent for guarding against.
_DYLIB_COMMAND_HEADER_SIZE = 24
_RPATH_COMMAND_HEADER_SIZE = 12

# `struct symtab_command` is cmd, cmdsize and the four offsets below.
_SYMTAB_COMMAND_SIZE = 24

# nlist flags. N_STAB marks a debug entry rather than a symbol; N_TYPE is the field that
# says where the symbol lives, and N_UNDF in it means "not in this object".
_N_STAB = 0xE0
_N_TYPE = 0x0E
_N_UNDF = 0x00
# An indirect symbol is an alias: its `n_value` is a string-table index naming the
# symbol it redirects to, the one place a name is referenced by something other than an
# entry's own `n_strx`.
_N_INDR = 0x0A

# nlist is n_strx(4) n_type(1) n_sect(1) n_desc(2) n_value(4), nlist_64 the same with an
# 8-byte n_value. Only the first three fields are read, so the size is the only
# difference that matters here.
_NLIST_SIZE = {False: 12, True: 16}

# A real universal binary carries a handful of architectures: Apple has never shipped
# more than four at once. Past that it is a way to make one small object cost a pass over
# itself per entry, so the declared count is capped and the excess reported as unread.
_MAX_FAT_SLICES = 32

# `sizeofcmds` is a 32-bit field the header declares about itself, the same shape as
# `nsyms` and `strsize` below: nothing before this checked it against anything but a
# short read. Real load commands are low tens of KiB; past a generous 1 MiB a streamed
# member paid a read proportional to what the header claimed rather than to what
# `ncmds` real commands could possibly need, up to the whole member. #63.
_MAX_SIZEOFCMDS = 1024 * 1024

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
class _SymbolRead:
    """What one `LC_SYMTAB` yielded, and how far short of its own promise it fell."""

    matches: frozenset[SymbolMatch]
    entries: int
    # How many entries resolved to a name that is a symbol rather than a debug record.
    # Zero means the table declared nothing we could check, which is what `stripped`
    # reports and is not the same as a table we failed on.
    named: int
    # Why the table was there and could not be used, or `None` when nothing about it
    # was left unexplained. A cause carries a message and records an error.
    shortfall: str | None
    # One cause is not about this format: a count that understates the rows is the same
    # lie ELF tells with `sh_size`, so it carries a token both readers emit and a
    # consumer can filter an index on. Carried rather than inferred from `shortfall`,
    # because matching on a message is how a message becomes a contract.
    understated: bool = False

    @property
    def complete(self) -> bool:
        """Every name this object carries was read, and the caller may say so."""
        return self.shortfall is None and bool(self.named)

    @property
    def stripped(self) -> bool:
        """The table was read and offered no symbol name, which is what `strip` leaves.

        Derived here rather than by the caller so it cannot disagree with `complete`:
        exactly one of `shortfall`, `complete` and `stripped` holds for any table, and
        "this object names no symbols" is a claim only a table with nothing left
        unexplained can support. Read off what the table yielded rather than off
        `nsyms`, which is a field the object fills in about itself: a count of zero
        over rows holding names is a cause, and a cause is not a stripped object.
        """
        return self.shortfall is None and not self.named


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
    # A dylib-loading, LC_ID_DYLIB or LC_RPATH command's string could not be read, so
    # a dependency, the object's own install name, or an rpath entry was lost rather
    # than absent.
    load_command_string_unread: bool
    # A command's own `cmd`/`cmdsize` header could not be trusted, so the walk
    # stopped early: everything after is unaccounted for, not absent. #84.
    load_command_walk_truncated: bool


@dataclass(frozen=True, slots=True)
class _SliceEvidence:
    """What one slice yielded, before the slices are merged into one record."""

    cputype: int
    is64: bool
    big_endian: bool
    soname: str | None
    needed: tuple[str, ...]
    rpath: tuple[str, ...]
    load_command_string_unread: bool
    load_command_walk_truncated: bool
    matches: frozenset[SymbolMatch]
    symtab_count: int
    stripped: bool
    symbols_complete: bool
    # The message saying why the table fell short, or `None` when it declared no entries
    # at all, which is not a failure and records no error.
    symbols_shortfall: str | None
    # The shortfall was a count that understates the rows, which is a cause both readers
    # name the same way.
    symbols_understated: bool
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
        reason=evidence.PARTIAL_MACHO_HEADER_UNREAD,
    )
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
    if magic in (_FAT_MAGIC, _FAT_CIGAM, _FAT_MAGIC_64, _FAT_CIGAM_64):
        try:
            stream.seek(0)
            slices, header_reasons = _list_fat_slices(
                stream, size, wide=magic in (_FAT_MAGIC_64, _FAT_CIGAM_64)
            )
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

    read = [
        _read_slice_symbols(
            stream, raw, header, patterns, size=size, max_strings_bytes=max_strings_bytes
        )
        for header in headers
    ]

    errors: list[ScanError] = []
    # One per distinct reason. `ScanError` is deduplicated and sorted on the way out, so
    # two slices failing the same way is one message rather than two identical ones.
    errors.extend(_error(path, why) for why in unread)
    errors.extend(_error(path, why) for why in header_reasons)
    if any(slice_evidence.symbols_failed for slice_evidence in read):
        errors.append(_error(path, "failed to read the mach-o symbol table"))
    # A table declaring no entries is incomplete but not an error: it tells us what an
    # absent `LC_SYMTAB` tells us, which is what `strip` leaves behind and normal for a
    # release wheel, and that has always been recorded without a message. A table that
    # declared entries and could not be used earns one, saying which way it fell short.
    errors.extend(
        _error(path, slice_evidence.symbols_shortfall)
        for slice_evidence in read
        if slice_evidence.symbols_shortfall is not None
    )
    if any(slice_evidence.load_command_string_unread for slice_evidence in read):
        message = "a dylib-loading, LC_ID_DYLIB or LC_RPATH command's string could not be read"
        errors.append(_error(path, message))
    if any(slice_evidence.load_command_walk_truncated for slice_evidence in read):
        message = "a load command's cmd/cmdsize header could not be trusted, cutting the walk short"
        errors.append(_error(path, message))

    # Every architecture has to have been read, and read in full, before this object
    # can claim it was examined. An unread slice is an unread object.
    partial: set[str] = set()
    if truncated_read:
        partial.add(evidence.PARTIAL_STRINGS_BYTES_UNREAD)
    if unread or header_reasons:
        partial.add(evidence.PARTIAL_MACHO_FAT_SLICE_UNREAD)
    if not all(slice_evidence.symbols_complete for slice_evidence in read):
        partial.add(evidence.PARTIAL_MACHO_SYMTAB_INCOMPLETE)
    if any(slice_evidence.symbols_understated for slice_evidence in read):
        partial.add(evidence.PARTIAL_SYMTAB_UNDERSTATES_ROWS)
    if any(slice_evidence.load_command_string_unread for slice_evidence in read):
        partial.add(evidence.PARTIAL_MACHO_LOAD_COMMAND_STRING_UNREAD)
    if any(slice_evidence.load_command_walk_truncated for slice_evidence in read):
        partial.add(evidence.PARTIAL_MACHO_LOAD_COMMAND_WALK_TRUNCATED)

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

    ordered, symbols_truncated = cap(merged, patterns.limits.max_symbols_per_binary)

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
        # lands here, summed over the slices. `BinaryEvidence.is_opaque` reads this
        # field for Mach-O and `dynsym_count` for ELF, rather than one field for every
        # format: no Mach-O sets `dynsym_count`, so keying on it alone called every
        # Mach-O opaque however much of it was read.
        symtab_count=symtab_count,
        matched_symbols=ordered,
        matched_strings=found.matched_strings,
        rust_crates=found.rust_crates,
        go=go,
        symbols_truncated=symbols_truncated,
        strings_truncated=truncated_read or found.truncated,
        partial_analysis=bool(partial),
        partial_reasons=tuple(sorted(partial)),
    )
    return result, tuple(sorted(set(errors), key=lambda err: err.sort_key()))


def _list_fat_slices(
    stream, size: int, *, wide: bool
) -> tuple[tuple[_Slice, ...], tuple[str, ...]]:
    """Return every slice a fat header declares, plus what it declared and we did not read.

    Fat headers and their arch entries are always big-endian on disk, regardless of host
    or slice byte order, so this part never needs an endianness switch. `wide` selects
    the `fat_arch_64` layout, which is the only thing `FAT_MAGIC_64` changes.

    `wide` is about the table's stride, not its byte order, and the two are independent.
    `FAT_CIGAM_64` is grouped with `FAT_MAGIC_64` because that is where real support
    would start if it were ever added, but the grouping changes no real object's record:
    a genuinely byte-swapped header has a little-endian table, which this reads
    big-endian, so `nfat_arch` comes out huge, the cap fires and every entry is garbage
    at either stride. The only input the choice changes is a byte-swapped magic in front
    of a big-endian table, which no toolchain emits.

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
    entry_size, entry_format = _FAT_ARCH[wide]
    slices: list[_Slice] = []
    seen: set[int] = set()
    reasons: set[str] = set()
    if nfat_arch > _MAX_FAT_SLICES:
        reasons.add("fat header declares more architectures than this reader walks")
    for _ in range(min(nfat_arch, _MAX_FAT_SLICES)):
        entry = stream.read(entry_size)
        if len(entry) < entry_size:
            reasons.add("fat arch table is truncated")
            break
        _cputype, _cpusubtype, offset, arch_size, *_rest = struct.unpack(entry_format, entry)
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

    `_read_thin` also raises `_Unreadable` directly, for `sizeofcmds` over
    `_MAX_SIZEOFCMDS`: that message is caught and re-raised here rather than being
    rewritten by the generic `except Exception` below, the same way `struct.error`
    already gets its own, more specific text instead of the catch-all one. #63.
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
        (
            cputype,
            soname,
            needed,
            rpath,
            symtab,
            load_command_string_unread,
            load_command_walk_truncated,
        ) = _read_thin(stream, slice_.offset, slice_.size, is64, big_endian)
    except struct.error as bad:
        raise _Unreadable("mach-o header is truncated") from bad
    except _Unreadable:
        raise
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
        load_command_string_unread=load_command_string_unread,
        load_command_walk_truncated=load_command_walk_truncated,
    )


def _read_slice_symbols(
    stream,
    raw: bytes,
    header: _SliceHeader,
    patterns: BinaryPatterns,
    *,
    size: int,
    max_strings_bytes: int,
) -> _SliceEvidence:
    """Read one slice's symbol table, once its header has already been parsed."""
    matches: set[SymbolMatch] = set()
    symtab_count = 0
    # An absent `LC_SYMTAB` is a stripped object and an incomplete read, the same two
    # answers `_SymbolRead` gives for a table that declared no entries. A read that
    # raised is neither: a table we failed on supports no claim about the object.
    stripped = header.symtab is None
    symbols_complete = False
    symbols_shortfall: str | None = None
    symbols_understated = False
    symbols_failed = False
    if header.symtab is not None:
        try:
            read = _read_symbols(
                stream,
                raw,
                header.symtab,
                patterns,
                base=header.slice_.offset,
                end=min(size, header.slice_.offset + header.slice_.size),
                is64=header.is64,
                big_endian=header.big_endian,
                max_strings_bytes=max_strings_bytes,
            )
        except Exception:
            symbols_failed = True
        else:
            matches, symtab_count = set(read.matches), read.entries
            stripped, symbols_complete = read.stripped, read.complete
            symbols_shortfall, symbols_understated = read.shortfall, read.understated

    return _SliceEvidence(
        cputype=header.cputype,
        is64=header.is64,
        big_endian=header.big_endian,
        soname=header.soname,
        needed=header.needed,
        rpath=header.rpath,
        load_command_string_unread=header.load_command_string_unread,
        load_command_walk_truncated=header.load_command_walk_truncated,
        matches=frozenset(matches),
        symtab_count=symtab_count,
        stripped=stripped,
        symbols_complete=symbols_complete,
        symbols_shortfall=symbols_shortfall,
        symbols_understated=symbols_understated,
        symbols_failed=symbols_failed,
    )


def _read_thin(
    stream, base: int, slice_size: int, is64: bool, big_endian: bool
) -> tuple[int, str | None, tuple[str, ...], tuple[str, ...], _Symtab | None, bool, bool]:
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

    if sizeofcmds > _MAX_SIZEOFCMDS:
        # Checked before the read, not after: `stream.read(sizeofcmds)` below costs
        # exactly what `sizeofcmds` claims, through a streamed zip member as much as an
        # in-memory one, so refusing here is what keeps a 300 MiB member with a lying
        # header from being read whole just to find out it lied. #63.
        raise _Unreadable(
            f"sizeofcmds is {sizeofcmds} bytes, over the {_MAX_SIZEOFCMDS}-byte cap on "
            "load commands"
        )
    commands = stream.read(sizeofcmds)
    if len(commands) < sizeofcmds:
        raise struct.error("load commands truncated")

    soname: str | None = None
    needed: list[str] = []
    rpaths: list[str] = []
    symtab: _Symtab | None = None
    load_command_string_unread = False
    load_command_walk_truncated = False
    pos = 0
    for _ in range(ncmds):
        if pos + 8 > len(commands):
            # Not even a `cmd`/`cmdsize` pair left to read. #84.
            load_command_walk_truncated = True
            break
        cmd, cmdsize = struct.unpack_from(end + "II", commands, pos)
        if cmdsize < 8 or pos + cmdsize > len(commands):
            # `cmdsize` lies about its own extent, so `pos` past here is a guess,
            # not a fact: stop rather than resync on a value that already lied. #84.
            load_command_walk_truncated = True
            break
        body = commands[pos : pos + cmdsize]
        if cmd in _LC_DYLIB_DEPENDENCIES or cmd == _LC_ID_DYLIB:
            # `dylib_command` is identical across all six of these: cmd, cmdsize, then
            # the `dylib` struct itself (name.offset, timestamp, current_version,
            # compatibility_version). Only what the loader does with the name differs,
            # which is a `ruleset`-shaped question this reader has no business asking.
            name = _read_command_string(body, header_size=_DYLIB_COMMAND_HEADER_SIZE, end=end)
            if name is not None:
                if cmd == _LC_ID_DYLIB:
                    soname = name
                else:
                    needed.append(name)
            else:
                load_command_string_unread = True
        elif cmd == _LC_RPATH:
            # `linkage._looks_vendored` reads `rpath` to decide whether a
            # `@rpath`-relative dependency resolves inside the wheel, so a lost rpath
            # can misread a bundled library's posture the same way a lost dependency
            # name can.
            path = _read_command_string(body, header_size=_RPATH_COMMAND_HEADER_SIZE, end=end)
            if path is not None:
                rpaths.append(path)
            else:
                load_command_string_unread = True
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
        load_command_string_unread,
        load_command_walk_truncated,
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
    max_strings_bytes: int,
) -> _SymbolRead:
    """Return the matches, the entry count, completeness, and why it fell short.

    The last element is a message when the table could not be read, and `None` when it
    simply declared nothing -- which is not a failure and records no error.

    The matches come back uncapped and unordered. A universal binary merges the
    slices before sorting and capping, so capping here would let which symbols
    survive depend on which slice they came from.

    `symoff` and `stroff` are measured from the start of the slice, not the start of the
    file, so `base` is what makes a fat binary's tables resolve to the architecture whose
    header we just read rather than to the fat header.

    Each table is read exactly once, in file order, the way `binfmt.elf._iter_symbols`
    reads its own and for the reason given there: in a zip member too large to hold in
    memory, a backwards seek costs a fresh decompression of everything before it.

    `nsyms` and `strsize` are 32-bit fields the object declares about itself, and
    `_available` alone only measures them against the slice: for a slice smaller than
    `max_strings_bytes` that already bounds them, but for one larger -- a streamed
    member well past the in-memory threshold -- it does not, and a lying `nsyms` buys a
    read, and a walk over every row of it, proportional to the slice rather than to any
    fixed budget. `max_strings_bytes` is threaded through and taken as a second,
    fixed ceiling on what either table's *declared* size is allowed to ask `_available`
    for. `binfmt.elf._symbol_bytes` takes the same parameter as its own
    `max_table_bytes` for `.dynsym`/`.dynstr`, but only enforces it through
    `_bounded_section_data`'s `compressed or SHT_NOBITS` guard (#62) -- an ordinary,
    uncompressed `.dynsym`/`.dynstr` still reads through unbounded today (#95). This
    cap is unconditional on `nsyms`/`strsize` themselves, so it is stricter than that
    ELF path, not a mirror of it: nothing here depends on how the table is stored, only
    on what it declares. `sym_wanted` and `symtab.strsize` themselves stay uncapped
    below, in the `truncated` check: reading less than they declare -- whether the
    slice ran out or the budget did -- is exactly what `truncated` already means, so a
    table over budget falls into the read this function already had for one that is
    merely short, no new branch needed. #63.
    """
    entry_size = _NLIST_SIZE[is64]
    sym_start = base + symtab.symoff
    str_start = base + symtab.stroff
    sym_wanted = symtab.nsyms * entry_size
    sym_length = _available(sym_start, min(sym_wanted, max_strings_bytes), end)
    str_length = _available(str_start, min(symtab.strsize, max_strings_bytes), end)
    if sym_start <= str_start:
        table = _region(stream, raw, sym_start, sym_length)
        strings = _region(stream, raw, str_start, str_length)
    else:
        strings = _region(stream, raw, str_start, str_length)
        table = _region(stream, raw, sym_start, sym_length)

    matches: set[SymbolMatch] = set()
    # Only the crypto names read, which is what the cross-check below compares against.
    # Remembering every name instead cost 24 MiB on a half-million-symbol table, for a
    # question that is only ever asked about the handful the ruleset claims.
    read_crypto: set[str] = set()
    named = 0
    unresolved = 0
    for name, undefined, resolved, debug, alias in _iter_symbols(
        table, strings, entry_size, big_endian
    ):
        if not resolved:
            unresolved += 1
            continue
        if alias is not None:
            # An alias names its target through `n_value`, so the target is a name no
            # entry's own index points at and the cross-check below would otherwise
            # find it left over in the string table. `_iter_symbols` already resolved,
            # stripped and sanitised it through the same `BoundedNames` ordinary names
            # go through, so there is nothing left to decode here.
            #
            # It goes through the matcher rather than straight into `read_crypto`, for
            # the same reason the debug rows below do not: a name counted as read has
            # to be a name the matcher saw, or one `N_INDR` row aliasing the symbol it
            # hides is enough to account for the name and silence the check. It is also
            # evidence in its own right -- the object reaches that symbol through the
            # indirection -- and `imported`, because an alias resolves to code this
            # object does not carry under that name.
            groups = patterns.symbol_groups_for(alias) if alias else ()
            if groups:
                read_crypto.add(alias)
                for group in groups:
                    matches.add(
                        SymbolMatch(name=alias, group=group, binding=evidence.BINDING_IMPORTED)
                    )
        if not name:
            continue
        # A debug entry describes a source file or a line number. Its N_TYPE bits are
        # not a section index, so reading one as a symbol turns a stabs record into a
        # claim that this object defines the code.
        #
        # It counts as neither named nor read, and both halves matter.
        #
        # Not named, because `complete` means "this object declared symbols, we read all
        # of them, and none was crypto", and a table of nothing but debug records
        # declared nothing. Counting it made one crafted record the difference between
        # `OPAQUE` and a clean verdict.
        #
        # Not read, because the name never reaches the group matching below. Treating it
        # as read let an object launder a hidden symbol: put the crypto name on a stabs
        # row inside the declared window and the real undefined row outside it, and the
        # cross-check found nothing left over.
        if debug:
            continue
        named += 1
        groups = patterns.symbol_groups_for(name)
        if not groups:
            continue
        read_crypto.add(name)
        binding = evidence.BINDING_IMPORTED if undefined else evidence.BINDING_DEFINED
        for group in groups:
            matches.add(SymbolMatch(name=name, group=group, binding=binding))

    # "We read every name and none of them was crypto" has to be earned, because it is
    # indistinguishable in the record from "this object has no crypto". A hidden string
    # table, indices past its end, indices all left at zero, a table of nothing but
    # debug records, and a count that understates the rows are the cheap ways to make a
    # wheel look clean, and each of them lands here.
    #
    # `shortfall` is the one place that decision is made: `None` means nothing about
    # this table was left unexplained, and only then may the caller read "no symbols" or
    # "no crypto" off it. Anything else carries a message and records an error.
    #
    # Ordered so the cheapest question is asked first, and so the string-table walk --
    # the only one that costs a pass over the object -- is skipped for a table already
    # known to have fallen short.
    count = len(table) // entry_size
    truncated = len(table) != sym_wanted or len(strings) != symtab.strsize
    understated = False
    if truncated:
        shortfall = "mach-o symbol table is truncated"
    elif unresolved:
        shortfall = "mach-o symbol table names strings it does not hold"
    elif holds_a_name_not_read(strings, patterns, read_crypto, normalise=_strip_abi_prefix):
        shortfall = "mach-o symbol table declares fewer entries than it has names"
        understated = True
    elif not named and symtab.nsyms:
        # Rows were declared and not one of them is a symbol this object names. The
        # table was there and we could not use it, which is not what `strip` leaves
        # behind, so it records an error: dropping it would let `linkage` read the
        # object as declaring no OpenSSL rather than as not saying.
        shortfall = "mach-o symbol table declares entries but names no symbol"
    else:
        # An honest read, or `nsyms == 0`, which says what an absent `LC_SYMTAB` says
        # and records no error either. `_SymbolRead` tells the two apart by `named`:
        # one is a complete read, the other a stripped object.
        shortfall = None
    return _SymbolRead(frozenset(matches), count, named, shortfall, understated)


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
) -> Iterator[tuple[str, bool, bool, bool, str | None]]:
    """Yield (name, is_undefined, name_resolved, is_debug, alias) for each table entry.

    Every entry is reported, including the ones with nothing usable in them: an entry
    whose `n_strx` points past the end of the string table, into a run the table never
    closes, or past the per-name cap `binfmt.symtab.BoundedNames` enforces, is the
    difference between "no crypto here" and "we could not read the names", and only the
    caller can tell those two apart. `name` is empty for index 0, which is how nlist
    spells "this entry has no name", and for an entry whose name sanitises away to
    nothing.

    `alias` is already resolved, ABI-prefix-stripped and sanitised here -- the same
    `resolver` ordinary names go through, not a second, unguarded read of `strings`.
    An `N_INDR` row's target is a string table offset exactly like any `n_strx`, so a
    table pointing many rows' `n_value` at one enormous target had the identical
    unbounded cost #61 closed for `n_strx`, one call site over: `resolver` was already
    in scope here and simply was not being used for it. `alias` is `None` both when a
    row has none and when its target could not be resolved (over the cap, over the
    budget, past the table, or into a run it never closes) -- the caller cannot
    tell, and does not need to: a crypto name an unresolved alias hides is still a
    name `binfmt.symtab.holds_a_name_not_read`'s independent scan of `strings` finds
    left over and unaccounted for, the same safety net an ordinary unresolved name
    already relies on.

    `BoundedNames` is built fresh here, once per call, because its cache is only sound
    over the one string table this call was handed: `_read_symbols` makes one call per
    slice of a universal binary, never one shared across slices. #61.
    """
    order = ">" if big_endian else "<"
    head = struct.Struct(order + "IBB")
    value = struct.Struct(order + ("Q" if entry_size == _NLIST_SIZE[True] else "I"))
    resolver = BoundedNames(strings)
    for base in range(0, len(table) - entry_size + 1, entry_size):
        n_strx, n_type, _n_sect = head.unpack_from(table, base)
        undefined = (n_type & _N_TYPE) == _N_UNDF
        debug = bool(n_type & _N_STAB)
        name, resolved = resolver.resolve(n_strx, normalise=_strip_abi_prefix)
        if not resolved:
            yield "", undefined, False, debug, None
            continue
        # An alias names its target through `n_value`, so that target is a string no
        # entry's own index points at. Yielded so the caller can count it as read.
        alias: str | None = None
        if not debug and (n_type & _N_TYPE) == _N_INDR:
            (target,) = value.unpack_from(table, base + 8)
            aliased, alias_resolved = resolver.resolve(target, normalise=_strip_abi_prefix)
            if alias_resolved:
                alias = aliased
        yield name, undefined, True, debug, alias


def _read_command_string(body: bytes, *, header_size: int, end: str) -> str | None:
    """The string a load command's `lc_str` offset field names, or `None` if unreadable.

    `header_size` is the fixed part of the command (`_DYLIB_COMMAND_HEADER_SIZE` or
    `_RPATH_COMMAND_HEADER_SIZE`): it must exist before the offset field is even there
    to read, and it is the floor an honest offset can never fall below. The offset
    field itself always sits at byte 8, right after `cmd` and `cmdsize`.
    """
    if len(body) < header_size:
        return None
    (offset,) = struct.unpack_from(end + "I", body, 8)
    if offset < header_size:
        return None
    return _read_cstring(body, offset)


def _read_cstring(body: bytes, offset: int) -> str | None:
    """The NUL-terminated name at `offset`, sanitized.

    `None` means the name could not be read in full: the offset is negative or past
    the end of the command's own body, the run it starts never closes before the body
    ends, or every byte it does contain sanitizes to nothing. A non-ASCII byte inside
    an otherwise readable name is not that: `binfmt.elf` and `binfmt.pe` both decode
    permissively and sanitize rather than reject a name over one bad byte.
    """
    if offset < 0 or offset >= len(body):
        return None
    end = body.find(b"\x00", offset)
    if end == -1:
        # A run this command's own body never closes. The same failure
        # `_iter_symbols` above already guards against for the symbol string table.
        return None
    return sanitize(body[offset:end].decode("utf-8", "replace")) or None
