"""PE reading: the header chain, the import directory and the export directory.

`.pyd` and `.dll` members used to be read for printable strings alone, which left a
Windows wheel with no `needed`, no `soname` and no imported-versus-defined split: the
three things the rest of the tool reasons about. The import directory is the `DT_NEEDED`
equivalent and the reason this reader exists, because it is what says a `.pyd` depends
on `libcrypto-3-x64.dll` rather than carrying OpenSSL inside itself. The import lookup
table and the export directory draw the same line `binfmt.elf` draws from `.dynsym`.

Address translation is the part a PE reader gets quietly wrong. Every directory names an
address in the loaded image, never an offset in the file, and the difference is per
section: an address belongs to the section whose `[VirtualAddress, VirtualAddress +
VirtualSize)` contains it, is mapped through that section's `PointerToRawData`, and is
readable only as far as its `SizeOfRawData`. Bytes past that are zero-filled by the
loader and are not in the file at all. Translating with one global delta instead reads a
neighbouring section's bytes as names, which is worse than reading nothing.

Two kinds of evidence here have no name to record. An ordinal-only import names its
function by number, and an export the name table never points at is a definition with no
name. Both are evidence we could not read, so both leave `partial_analysis` set rather
than being dropped into a record that would then read as "we saw every name and none of
them was crypto".

So the flag clears only when the whole chain held: the section table was there, the
import directory was present and walked to its terminator with every DLL name and every
named entry resolved, at least one DLL was named, and nothing came in by ordinal alone.
An object with no import directory at all stays partial, because it named no dependency,
which is exactly what its record said before this reader existed.

An absent export directory is read differently, as a complete reading of an empty one:
an object the loader can resolve nothing against genuinely exports nothing. Read in
full, the export address table also separates a definition from a forwarder, whose
address points back inside the export directory because the "code" is a string naming
another DLL. A forwarded export is recorded as imported, which is what it is.

Not read, and a real blind spot: the delay-load import directory, whose descriptors name
libraries loaded on first call. It is not parsed, so an object carrying one stays
partial rather than reporting its declared dependencies as all of them. That directory
is recognised by its address alone: its `Size` is informational, because the descriptor
array is NUL-terminated and the Windows loader never reads the field, so a zero there
must not be allowed to mean "no delay-load imports". Also not read: the resource
directory, and the COFF symbol table, which every modern linker strips in favour of a
PDB.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .. import evidence
from ..errors import PE_PARSE_ERROR
from ..evidence import BinaryEvidence, ScanError, SymbolMatch
from ..ruleset import BinaryPatterns
from .golang import build_go_info
from .strings import MAX_STRINGS_BYTES, sanitize, scan_strings

_DOS_MAGIC = b"MZ"
_DOS_HEADER_SIZE = 0x40
_E_LFANEW_OFFSET = 0x3C
_PE_SIGNATURE = b"PE\x00\x00"
_COFF_HEADER_SIZE = 20
_SECTION_HEADER_SIZE = 40

_PE32_MAGIC = 0x10B
_PE32PLUS_MAGIC = 0x20B

# Where `NumberOfRvaAndSizes` sits inside the optional header, and where the data
# directories start after it. The two layouts differ because PE32+ drops `BaseOfData`
# and widens four fields to 64 bits, which is also why the magic has to be read before
# anything past it can be believed.
_DIRECTORY_LAYOUT = {_PE32_MAGIC: (92, 96), _PE32PLUS_MAGIC: (108, 112)}
_DIRECTORY_ENTRY_SIZE = 8
# The format defines sixteen. `NumberOfRvaAndSizes` is a 32-bit self-declared field, so
# it is capped rather than believed.
_MAX_DIRECTORIES = 16
_EXPORT_DIRECTORY = 0
_IMPORT_DIRECTORY = 1
_DELAY_IMPORT_DIRECTORY = 13

_IMPORT_DESCRIPTOR_SIZE = 20
_NULL_DESCRIPTOR = b"\x00" * _IMPORT_DESCRIPTOR_SIZE
_EXPORT_DIRECTORY_SIZE = 40
# A hint/name entry is a two-byte hint followed by the name itself.
_HINT_SIZE = 2
# The top bit of a thunk says "this one is by ordinal"; the rest of a named one is a
# 31-bit address in both widths.
_ORDINAL_FLAG = {4: 1 << 31, 8: 1 << 63}
_HINT_NAME_RVA_MASK = 0x7FFFFFFF

# Bounds on hostile input, not on real objects: the largest Windows DLLs import from a
# few dozen libraries and export a few thousand names.
_MAX_IMPORT_DESCRIPTORS = 4096
# One budget for the whole object, not one per DLL. Nothing stops every descriptor
# pointing its lookup table at the same thunk array, so a per-DLL cap multiplies with
# the descriptor cap instead of bounding anything: 4096 descriptors each walking 65,536
# thunks is 268 million iterations out of an object a few hundred kilobytes long, which
# is minutes of CPU and tens of gigabytes of names. Unlike ELF and Mach-O, where every
# table is clamped to the bytes actually present, a PE thunk array is a NUL-terminated
# walk with no declared length, so this is the only thing bounding it.
_MAX_THUNKS = 65536
_MAX_EXPORT_NAMES = 262144
_MAX_NAME_BYTES = 1024

_MACHINE_NAMES = {
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x0166: "IMAGE_FILE_MACHINE_R4000",
    0x01C0: "IMAGE_FILE_MACHINE_ARM",
    0x01C4: "IMAGE_FILE_MACHINE_ARMNT",
    0x0200: "IMAGE_FILE_MACHINE_IA64",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
}


class _Malformed(Exception):
    """A header field no object could mean. Its text is what the record will carry."""


@dataclass(frozen=True, slots=True)
class _Section:
    """One section header, reduced to what address translation needs."""

    virtual_address: int
    virtual_span: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True, slots=True)
class _Image:
    """The bytes in hand, and the section table that maps addresses onto them."""

    raw: bytes
    sections: tuple[_Section, ...]

    def locate(self, rva: int) -> tuple[int, int] | None:
        """(file offset, readable bytes from there) for `rva`, or None when it is nowhere.

        The first containing section wins, so an object with deliberately overlapping
        sections resolves the same way on every run instead of by table-order luck.
        """
        for section in self.sections:
            offset = rva - section.virtual_address
            if not 0 <= offset < section.virtual_span:
                continue
            if offset >= section.raw_size:
                # Inside the section as loaded, past what the file carries for it.
                return None
            return section.raw_offset + offset, section.raw_size - offset
        return None

    def read(self, rva: int, length: int) -> bytes | None:
        """Exactly `length` bytes at `rva`, or None when they are not all there."""
        found = self.locate(rva)
        if found is None:
            return None
        offset, available = found
        if available < length:
            return None
        return self.raw[offset : offset + length]

    def cstring(self, rva: int) -> str | None:
        """The NUL-terminated name at `rva`, sanitised, or None when there is none.

        A name with no terminator inside its own section is a name we did not read
        rather than a short one: reporting the bytes up to the section boundary would
        invent a symbol out of whatever happened to follow it.
        """
        found = self.locate(rva)
        if found is None:
            return None
        offset, available = found
        window = self.raw[offset : offset + min(available, _MAX_NAME_BYTES)]
        end = window.find(b"\x00")
        if end == -1:
            return None
        return sanitize(window[:end].decode("utf-8", "replace")) or None


@dataclass(frozen=True, slots=True)
class _Headers:
    """Everything the header chain yielded, and whether the section table was all there."""

    machine: int
    is64: bool
    directories: tuple[tuple[int, int], ...]
    sections: tuple[_Section, ...]
    sections_complete: bool

    def directory(self, index: int) -> tuple[int, int]:
        """The (address, size) of one data directory, or zeroes when it is absent."""
        if index >= len(self.directories):
            return (0, 0)
        return self.directories[index]


@dataclass(frozen=True, slots=True)
class _Imports:
    """What the import directory yielded, and whether it was read in full."""

    dlls: tuple[str, ...]
    names: tuple[str, ...]
    entries: int
    # Imports that named a function by ordinal, which carries no name at all.
    unnamed: int
    complete: bool


@dataclass(frozen=True, slots=True)
class _Thunks:
    """What one lookup table yielded, and whether it was walked to its terminator."""

    names: tuple[str, ...]
    entries: int
    # Entries that named a function by ordinal, which carries no name at all.
    unnamed: int
    complete: bool


@dataclass(frozen=True, slots=True)
class _Exports:
    """What the export directory yielded, and whether it was read in full."""

    dll_name: str | None
    defined: tuple[str, ...]
    forwarded: tuple[str, ...]
    entries: int
    # Addresses the name table never points at: definitions with no name to record.
    unnamed: int
    complete: bool


def _error(path: str, message: str) -> ScanError:
    return ScanError(stage=evidence.STAGE_BINARY, kind=PE_PARSE_ERROR, message=message, path=path)


def read_pe(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    max_strings_bytes: int = MAX_STRINGS_BYTES,
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
    """Read one PE object and return its evidence, plus any non-fatal errors.

    The object is read once, forward, into the same buffer the string pass uses, and
    every directory is resolved inside it. PE scatters its structures the way ELF does
    not: one hint/name entry per imported function, each at its own address. Chasing
    those through the stream would be a seek apiece, and through a zip member a seek
    backwards costs a fresh decompression of everything before it. A directory lying
    past that buffer is therefore unread, and reported as unread.

    Strings come from the whole object rather than from the data sections alone, the
    way `binfmt.macho` takes them: the section table is read here, but filtering by it
    would drop the banners in sections this reader has no reason to classify.
    """
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(0)
    raw = stream.read(min(size, max_strings_bytes))

    strings_found = scan_strings(raw, patterns, max_strings_bytes)
    strings_truncated = size > max_strings_bytes or strings_found.truncated
    go = build_go_info(None, strings_found.text, patterns)

    errors: list[ScanError] = []
    try:
        headers = _read_headers(raw)
    except _Malformed as bad:
        # Whatever the strings pass already found is real evidence and survives the
        # header that did not parse. Every exit writes the record out field by field
        # rather than splatting a shared mapping: the shape `record.py` and
        # `schema.json` are held to is worth seeing at each point it is produced.
        return BinaryEvidence(
            path=path,
            format=evidence.FORMAT_PE,
            vendored_path=vendored,
            matched_strings=strings_found.matched_strings,
            rust_crates=strings_found.rust_crates,
            go=go,
            strings_truncated=strings_truncated,
            partial_analysis=True,
        ), (_error(path, str(bad)),)
    except Exception:
        return BinaryEvidence(
            path=path,
            format=evidence.FORMAT_PE,
            vendored_path=vendored,
            matched_strings=strings_found.matched_strings,
            rust_crates=strings_found.rust_crates,
            go=go,
            strings_truncated=strings_truncated,
            partial_analysis=True,
        ), (_error(path, "failed to parse the pe headers"),)

    image = _Image(raw=raw, sections=headers.sections)
    if not headers.sections_complete:
        errors.append(_error(path, "pe section table is truncated"))

    entry_size = 8 if headers.is64 else 4
    import_rva, _import_size = headers.directory(_IMPORT_DIRECTORY)
    export_rva, export_size = headers.directory(_EXPORT_DIRECTORY)
    # Address alone, the way the import and export directories are keyed. The
    # delay-load `Size` is informational: the descriptor array is NUL-terminated and
    # the loader drives it from the descriptors, so a zero there says nothing about
    # whether the object delay-loads anything.
    delay_rva, _delay_size = headers.directory(_DELAY_IMPORT_DIRECTORY)

    # A directory that blows up is one more thing this object did not tell us, never a
    # reason to lose the strings and the header fields it already did.
    imports: _Imports | None = None
    if import_rva:
        try:
            imports = _read_imports(image, import_rva, entry_size)
        except Exception:
            errors.append(_error(path, "failed to read the pe import directory"))
        else:
            if not imports.complete:
                errors.append(_error(path, "pe import directory could not be read in full"))

    exports: _Exports | None = None
    if export_rva:
        try:
            exports = _read_exports(image, export_rva, export_size)
        except Exception:
            errors.append(_error(path, "failed to read the pe export directory"))
        else:
            if not exports.complete:
                errors.append(_error(path, "pe export directory could not be read in full"))

    matches: set[SymbolMatch] = set()
    if imports is not None:
        _record(matches, imports.names, evidence.BINDING_IMPORTED, patterns)
    if exports is not None:
        _record(matches, exports.defined, evidence.BINDING_DEFINED, patterns)
        _record(matches, exports.forwarded, evidence.BINDING_IMPORTED, patterns)
    ordered = tuple(sorted(matches, key=lambda match: match.sort_key()))
    limit = patterns.limits.max_symbols_per_binary

    # "We read every name and none of them was crypto" has to be earned. An absent
    # import directory, a chain that did not terminate, a name that resolved nowhere and
    # anything named by ordinal alone each mean some of this object's dependencies or
    # symbols are unknown, and a record that dropped them would be indistinguishable
    # from one for an object that genuinely has none.
    complete = (
        headers.sections_complete
        and imports is not None
        and imports.complete
        and bool(imports.dlls)
        and not imports.unnamed
        and (exports is None or (exports.complete and not exports.unnamed))
        and not delay_rva
    )
    entries = (imports.entries if imports else 0) + (exports.entries if exports else 0)
    result = BinaryEvidence(
        path=path,
        format=evidence.FORMAT_PE,
        vendored_path=vendored,
        matched_strings=strings_found.matched_strings,
        rust_crates=strings_found.rust_crates,
        go=go,
        strings_truncated=strings_truncated,
        machine=_MACHINE_NAMES.get(headers.machine, f"0x{headers.machine:04x}"),
        bits=64 if headers.is64 else 32,
        # Every machine PE is defined for is little-endian, so this is a property of
        # the format rather than something read out of this object.
        endian="little",
        soname=exports.dll_name if exports else None,
        needed=tuple(sorted(set(imports.dlls))) if imports else (),
        # Never set for PE. Its own symbol table is COFF debug information that every
        # modern linker drops in favour of a PDB, so there is no table whose absence
        # could mean what it means in ELF; and setting it from `entries` would let a
        # failed read of the export table assert that the object named nothing.
        # `symtab_count == 0` already says that, without claiming to know why.
        stripped=False,
        # Not a symbol table: PE has no equivalent, so this counts the named things
        # this object declared, one per import thunk and one per export slot.
        symtab_count=entries,
        matched_symbols=ordered[:limit],
        symbols_truncated=len(ordered) > limit,
        partial_analysis=not complete,
    )
    return result, tuple(sorted(set(errors), key=lambda err: err.sort_key()))


def _record(
    matches: set[SymbolMatch], names: tuple[str, ...], binding: str, patterns: BinaryPatterns
) -> None:
    for name in names:
        for group in patterns.symbol_groups_for(name):
            matches.add(SymbolMatch(name=name, group=group, binding=binding))


def _read_headers(raw: bytes) -> _Headers:
    """Walk MZ -> `e_lfanew` -> PE -> COFF -> optional header -> section table.

    Every hop is bounded against the bytes in hand rather than against what the
    previous hop claimed, because each one of those claims is a field an attacker
    writes.
    """
    if len(raw) < _DOS_HEADER_SIZE:
        raise _Malformed("object is too short to hold a dos header")
    if not raw.startswith(_DOS_MAGIC):
        raise _Malformed("not a recognisable pe object")
    (e_lfanew,) = struct.unpack_from("<I", raw, _E_LFANEW_OFFSET)
    # `e_lfanew` is a signed LONG on disk. Reading it unsigned turns a negative one into
    # a value larger than any object, which is the same refusal by a shorter route.
    if e_lfanew < _DOS_HEADER_SIZE or e_lfanew + 4 + _COFF_HEADER_SIZE > len(raw):
        raise _Malformed("pe header offset is outside the object")
    if raw[e_lfanew : e_lfanew + 4] != _PE_SIGNATURE:
        raise _Malformed("pe signature is missing")

    coff = e_lfanew + 4
    machine, section_count = struct.unpack_from("<HH", raw, coff)
    (size_of_optional,) = struct.unpack_from("<H", raw, coff + 16)
    optional = coff + _COFF_HEADER_SIZE
    if optional + 2 > len(raw):
        raise _Malformed("pe optional header is truncated")
    (magic,) = struct.unpack_from("<H", raw, optional)
    layout = _DIRECTORY_LAYOUT.get(magic)
    if layout is None:
        raise _Malformed("unrecognised pe optional header magic")
    count_offset, table_offset = layout
    if optional + count_offset + 4 > len(raw):
        raise _Malformed("pe optional header is truncated")

    (declared,) = struct.unpack_from("<I", raw, optional + count_offset)
    directories: list[tuple[int, int]] = []
    for index in range(min(declared, _MAX_DIRECTORIES)):
        at = optional + table_offset + index * _DIRECTORY_ENTRY_SIZE
        if at + _DIRECTORY_ENTRY_SIZE > len(raw):
            break
        directories.append(struct.unpack_from("<II", raw, at))

    sections: list[_Section] = []
    complete = True
    table = optional + size_of_optional
    for index in range(section_count):
        at = table + index * _SECTION_HEADER_SIZE
        if at + _SECTION_HEADER_SIZE > len(raw):
            # `NumberOfSections` is a 16-bit self-declared count, so a short object is
            # free to promise 65,535 of them. What exists is what gets read.
            complete = False
            break
        virtual_size, virtual_address, size_of_raw, pointer = struct.unpack_from(
            "<IIII", raw, at + 8
        )
        # `SizeOfRawData` counts the initialised bytes the file carries; past it the
        # loader zero-fills and there is nothing to read. Clamping to the bytes in hand
        # in the same step folds "and past the end of the object" into one answer.
        available = max(0, len(raw) - pointer) if pointer <= len(raw) else 0
        sections.append(
            _Section(
                virtual_address=virtual_address,
                # A linker that left `VirtualSize` at zero means "as big as its raw
                # data", which is how object files spell it.
                virtual_span=virtual_size or size_of_raw,
                raw_offset=pointer,
                raw_size=min(size_of_raw, available),
            )
        )

    return _Headers(
        machine=machine,
        is64=magic == _PE32PLUS_MAGIC,
        directories=tuple(directories),
        sections=tuple(sections),
        sections_complete=complete,
    )


def _read_imports(image: _Image, rva: int, entry_size: int) -> _Imports:
    """Walk the import descriptors, then each one's lookup table.

    The array ends at an all-zero descriptor. Running out of section before finding one
    is a chain that never terminates; arriving at bytes already read is a chain that
    loops, which overlapping sections make possible because two addresses can map onto
    one file offset. Both stop the walk and leave the read incomplete.

    One thunk budget is carried across every descriptor, because nothing stops them all
    naming the same lookup table: a per-DLL cap would multiply with the descriptor cap
    rather than bound the walk. Names are collected into a set for the same reason, so
    an array that repeats one name a million times costs one string. Running the budget
    out is an incomplete read like any other, and `complete=False` is the whole record
    of it.
    """
    dlls: list[str] = []
    names: set[str] = set()
    entries = 0
    unnamed = 0
    complete = True
    budget = _MAX_THUNKS
    seen: set[int] = set()
    at = rva
    for _ in range(_MAX_IMPORT_DESCRIPTORS):
        found = image.locate(at)
        if found is None or found[1] < _IMPORT_DESCRIPTOR_SIZE:
            complete = False
            break
        offset = found[0]
        if offset in seen:
            complete = False
            break
        seen.add(offset)
        descriptor = image.raw[offset : offset + _IMPORT_DESCRIPTOR_SIZE]
        if descriptor == _NULL_DESCRIPTOR:
            break
        lookup_rva, _stamp, _forwarder, name_rva, address_rva = struct.unpack("<IIIII", descriptor)
        name = image.cstring(name_rva)
        if name is None:
            complete = False
        else:
            dlls.append(name)
        # The lookup table is the authority, but a bound image can leave it at zero and
        # keep the same entries in the address table, which is then what to read.
        thunks = lookup_rva or address_rva
        if not thunks:
            complete = False
        else:
            walked = _read_thunks(image, thunks, entry_size, budget)
            names.update(walked.names)
            entries += walked.entries
            unnamed += walked.unnamed
            budget -= walked.entries
            complete = complete and walked.complete
        at += _IMPORT_DESCRIPTOR_SIZE
    else:
        # Only reached by exhausting the cap, i.e. an array that never ended.
        complete = False
    return _Imports(
        dlls=tuple(dlls),
        names=tuple(sorted(names)),
        entries=entries,
        unnamed=unnamed,
        complete=complete,
    )


def _read_thunks(image: _Image, rva: int, entry_size: int, budget: int) -> _Thunks:
    """Walk one lookup table, reading at most `budget` entries from it."""
    names: list[str] = []
    entries = 0
    unnamed = 0
    ordinal_flag = _ORDINAL_FLAG[entry_size]
    fmt = "<I" if entry_size == 4 else "<Q"
    at = rva
    for _ in range(budget):
        chunk = image.read(at, entry_size)
        if chunk is None:
            return _Thunks(tuple(names), entries, unnamed, False)
        (entry,) = struct.unpack(fmt, chunk)
        if entry == 0:
            return _Thunks(tuple(names), entries, unnamed, True)
        entries += 1
        if entry & ordinal_flag:
            unnamed += 1
        else:
            name = image.cstring((entry & _HINT_NAME_RVA_MASK) + _HINT_SIZE)
            if name is None:
                return _Thunks(tuple(names), entries, unnamed, False)
            names.append(name)
        at += entry_size
    return _Thunks(tuple(names), entries, unnamed, False)


def _read_exports(image: _Image, rva: int, size: int) -> _Exports:
    """Read the export directory: the object's own name, and what it defines.

    `NumberOfNames` and `NumberOfFunctions` are independent counts, and nothing makes
    them agree. The name table indexes the address table through the ordinal table, so
    an entry pointing outside the address table leaves a name whose address is unknown;
    it is still recorded, as a definition, but the read is not a complete one.
    """
    header = image.read(rva, _EXPORT_DIRECTORY_SIZE)
    if header is None:
        return _Exports(None, (), (), 0, 0, False)
    (
        name_rva,
        _ordinal_base,
        function_count,
        name_count,
        address_rva,
        name_pointer_rva,
        ordinal_rva,
    ) = struct.unpack_from("<IIIIIII", header, 12)

    dll_name = image.cstring(name_rva) if name_rva else None
    complete = dll_name is not None or not name_rva
    if name_count > _MAX_EXPORT_NAMES or function_count > _MAX_EXPORT_NAMES:
        return _Exports(dll_name, (), (), 0, 0, False)

    pointers = image.read(name_pointer_rva, name_count * 4) if name_count else b""
    ordinals = image.read(ordinal_rva, name_count * 2) if name_count else b""
    addresses = image.read(address_rva, function_count * 4) if function_count else b""
    if pointers is None or ordinals is None or addresses is None:
        complete = False
        pointers, ordinals, addresses = pointers or b"", ordinals or b"", addresses or b""

    defined: list[str] = []
    forwarded: list[str] = []
    named_slots: set[int] = set()
    for index in range(len(pointers) // 4):
        (entry_rva,) = struct.unpack_from("<I", pointers, index * 4)
        name = image.cstring(entry_rva)
        if name is None:
            complete = False
            continue
        if (index + 1) * 2 > len(ordinals):
            complete = False
            defined.append(name)
            continue
        (slot,) = struct.unpack_from("<H", ordinals, index * 2)
        if (slot + 1) * 4 > len(addresses):
            complete = False
            defined.append(name)
            continue
        named_slots.add(slot)
        (address,) = struct.unpack_from("<I", addresses, slot * 4)
        # A forwarder's "address" lands back inside the export directory, where it is a
        # string naming another DLL. The code is not here, so neither is the definition.
        if rva <= address < rva + size:
            forwarded.append(name)
        else:
            defined.append(name)

    unnamed = sum(
        1
        for slot in range(len(addresses) // 4)
        if slot not in named_slots and struct.unpack_from("<I", addresses, slot * 4)[0]
    )
    if len(pointers) // 4 != name_count or len(addresses) // 4 != function_count:
        complete = False
    return _Exports(
        dll_name=dll_name,
        defined=tuple(defined),
        forwarded=tuple(forwarded),
        entries=len(defined) + len(forwarded) + unnamed,
        unnamed=unnamed,
        complete=complete,
    )
