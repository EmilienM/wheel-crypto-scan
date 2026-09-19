"""ELF reading: the layer that separates "links the system OpenSSL" from "carries one".

Everything here funnels toward one distinction: whether a crypto symbol is imported
(undefined in this object, so the code lives in a library this wheel merely depends
on) or defined (the code is compiled into the object itself). An imported
`EVP_DigestInit_ex` next to `DT_NEEDED = libcrypto.so.3` means the wheel can pick up
whatever OpenSSL the host provides, FIPS provider included. The same symbol defined,
or a mangled `libcrypto-<hash>.so.3` SONAME, means it cannot: the wheel brought its
own copy and the host's provider is irrelevant to it.

Parsing uses `pyelftools` and never raises past `read_elf`: every failure becomes a
`ScanError` and whatever evidence was already gathered is still returned, because a
corrupt `.dynamic` section should not also cost us the strings we already pulled out
of `.rodata`.

One thing this reader still believes: `.dynsym`'s declared size. An object whose
`sh_size` covers fewer entries than it carries is read in full by its own account while
the rest go unlooked-at, and `stripped` is read off that same count. `binfmt.macho`
stopped taking the Mach-O spelling of that at face value in #34, cross-checking the
count against the string table every name must appear in, and `.dynstr` is the same
place for the same reason. The check has not been brought over here. Tracked in #38.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section

from .. import evidence
from ..errors import BINARY_TRUNCATED, BINARY_UNKNOWN_FORMAT, ELF_PARSE_ERROR
from ..evidence import BinaryEvidence, GoBuildInfo, ScanError, SymbolMatch
from ..ruleset import BinaryPatterns
from .fallback import read_strings_only
from .golang import build_go_info
from .strings import MAX_STRINGS_BYTES, sanitize, scan_strings

_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4


def _error(path: str, kind: str, message: str) -> ScanError:
    return ScanError(stage=evidence.STAGE_BINARY, kind=kind, message=message, path=path)


@dataclass(frozen=True, slots=True)
class _ElfHeader:
    """The four fields the ELF header alone yields, before any section is reached."""

    machine: str
    bits: int
    endian: str
    elf_type: str


def _unparsed(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    max_strings_bytes: int,
    kind: str,
    message: str,
    reason: str,
    header: _ElfHeader | None = None,
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
    """Evidence for an ELF whose structure we could not read, plus the error saying so.

    The structural read is gone, but the strings are not: a statically linked OpenSSL
    leaves its banner in read-only data whether or not `ELFFile` can make sense of the
    section headers, and that banner is sometimes the only evidence the object carries.
    This also marks the object `partial_analysis`, which the old empty record did not:
    an object we could not read has to say so, or nothing flags the record incomplete.

    `header` is passed when the ELF header itself parsed and only what it pointed at did
    not. Those four fields were read, so by the same contract they survive: a truncated
    object that still says it is 64-bit x86-64 has told us something.

    Note the strings here come from the whole file, not from the allocated non-executable
    sections the happy path filters to, because there is no section list to filter by.
    A match can therefore be a name out of `.dynstr` rather than a banner, which is why
    `engine` labels this evidence `string=` rather than naming a section.
    """
    result, _ = read_strings_only(
        stream,
        path,
        patterns,
        vendored=vendored,
        fmt=evidence.FORMAT_ELF,
        max_strings_bytes=max_strings_bytes,
        reason=reason,
    )
    if header is not None:
        result = replace(
            result,
            machine=header.machine,
            bits=header.bits,
            endian=header.endian,
            elf_type=header.elf_type,
        )
    return result, (_error(path, kind, message),)


# ELF symbol table entry layout: offsets of the two fields we need, by class.
# 64-bit: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
# 32-bit: st_name(4) st_value(4) st_size(4) st_info(1) st_other(1) st_shndx(2)
_SYM_LAYOUT = {64: (24, 0, 6), 32: (16, 0, 14)}
_SHN_UNDEF = 0


def _iter_symbols(elf, section) -> Iterator[tuple[str, bool]]:
    """Yield (name, is_undefined) for a symbol table, reading it in two passes total.

    pyelftools' `get_symbol()` seeks per symbol, alternating between the table and its
    string table. On a member too large to hold in memory those seeks run backwards
    through a zip stream, and a backwards seek costs a fresh decompression. A real
    example: pandoc ships a 400 MiB object with 497,040 dynamic symbols, which never
    finished. Reading both sections once turns that into two forward reads.
    """
    entry_size, name_offset, shndx_offset = _SYM_LAYOUT[elf.elfclass]
    data = section.data()
    strtab = elf.get_section(section["sh_link"])
    names = strtab.data() if strtab is not None else b""
    end = "<" if elf.little_endian else ">"
    u32 = struct.Struct(end + "I")
    u16 = struct.Struct(end + "H")

    for base in range(0, len(data) - entry_size + 1, entry_size):
        st_name = u32.unpack_from(data, base + name_offset)[0]
        if st_name == 0 or st_name >= len(names):
            continue
        stop = names.find(b"\x00", st_name)
        raw = names[st_name:stop] if stop != -1 else names[st_name:]
        name = sanitize(raw.decode("utf-8", "replace"))
        if not name:
            continue
        yield name, u16.unpack_from(data, base + shndx_offset)[0] == _SHN_UNDEF


def _find_section(sections: Sequence[Section], name: str) -> Section | None:
    for section in sections:
        if section.name == name:
            return section
    return None


def read_elf(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    max_strings_bytes: int = MAX_STRINGS_BYTES,
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
    """Read one ELF object and return its evidence, plus any non-fatal errors.

    Section access happens one index at a time rather than through pyelftools' own
    `iter_sections`, because that call builds every section wrapper up front: one
    corrupt section (a `.dynamic` whose `sh_link` names a string table that does not
    exist, say) would otherwise take out the whole section list, including the
    `.rodata` strings and `.dynsym` symbols that were perfectly readable.
    """
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(0)

    try:
        elf = ELFFile(stream)
        machine = str(elf.header["e_machine"])
        bits = int(elf.elfclass)
        endian = "little" if elf.little_endian else "big"
        elf_type = str(elf.header["e_type"])
    except Exception:
        return _unparsed(
            stream,
            path,
            patterns,
            vendored=vendored,
            max_strings_bytes=max_strings_bytes,
            kind=BINARY_UNKNOWN_FORMAT,
            message="not a recognisable ELF object",
            reason=evidence.PARTIAL_ELF_HEADER_UNREAD,
        )

    errors: list[ScanError] = []
    # Every error below is evidence this object has and we did not get, so each names
    # itself here too. The record used to say `partial_analysis: false` beside them: a
    # `.dynamic` that would not resolve emptied `needed` and the record then read as a
    # complete read of an object with no dependencies.
    reasons: set[str] = set()

    # A proactive truncation check, done before we attempt to read anything the
    # header points at: if the section header table itself does not fit in the
    # stream, every subsequent read is a symptom of that one fact, not a distinct
    # parse error worth its own message.
    try:
        shoff = int(elf.header["e_shoff"])
        shnum = int(elf.header["e_shnum"])
        shentsize = int(elf.header["e_shentsize"])
    except Exception:
        shoff = shnum = shentsize = 0
    if shnum and size < shoff + shnum * shentsize:
        return _unparsed(
            stream,
            path,
            patterns,
            vendored=vendored,
            max_strings_bytes=max_strings_bytes,
            kind=BINARY_TRUNCATED,
            message="elf section header table is truncated",
            # Not `elf_header_unread`: the header parsed, and its four fields are in the
            # record below. Only what it pointed at is missing, which is the same fact
            # `pe_section_table_truncated` names for PE.
            reason=evidence.PARTIAL_ELF_SECTION_TABLE_TRUNCATED,
            header=_ElfHeader(machine=machine, bits=bits, endian=endian, elf_type=elf_type),
        )

    sections: list[Section] = []
    try:
        num_sections = elf.num_sections()
    except Exception:
        num_sections = 0
        errors.append(_error(path, ELF_PARSE_ERROR, "failed to read the elf section count"))
        reasons.add(evidence.PARTIAL_ELF_SECTIONS_UNREAD)
    for index in range(num_sections):
        try:
            sections.append(elf.get_section(index))
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read an elf section header"))
            reasons.add(evidence.PARTIAL_ELF_SECTIONS_UNREAD)

    dynamic = _find_section(sections, ".dynamic")
    needed: tuple[str, ...] = ()
    soname: str | None = None
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()
    if dynamic is not None:
        try:
            needed = tuple(sorted(sanitize(tag.needed) for tag in dynamic.iter_tags("DT_NEEDED")))
            sonames = [sanitize(tag.soname) for tag in dynamic.iter_tags("DT_SONAME")]
            soname = sonames[0] if sonames else None
            rpath = tuple(sorted(sanitize(tag.rpath) for tag in dynamic.iter_tags("DT_RPATH")))
            runpath = tuple(
                sorted(sanitize(tag.runpath) for tag in dynamic.iter_tags("DT_RUNPATH"))
            )
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read the dynamic section"))
            reasons.add(evidence.PARTIAL_ELF_DYNAMIC_UNREAD)
            needed, soname, rpath, runpath = (), None, (), ()

    dynsym = _find_section(sections, ".dynsym")
    dynsym_count = 0
    symbol_matches: set[SymbolMatch] = set()
    if dynsym is not None:
        try:
            dynsym_count = dynsym.num_symbols()
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read the dynamic symbol table"))
            reasons.add(evidence.PARTIAL_ELF_DYNSYM_UNREAD)
            dynsym_count = 0
        try:
            for name, undefined in _iter_symbols(elf, dynsym):
                groups = patterns.symbol_groups_for(name)
                if not groups:
                    continue
                binding = evidence.BINDING_IMPORTED if undefined else evidence.BINDING_DEFINED
                for group in groups:
                    symbol_matches.add(SymbolMatch(name=name, group=group, binding=binding))
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read the dynamic symbol table"))
            reasons.add(evidence.PARTIAL_ELF_DYNSYM_UNREAD)

    symtab = _find_section(sections, ".symtab")
    symtab_count = 0
    if symtab is not None:
        try:
            symtab_count = symtab.num_symbols()
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read the symbol table"))
            reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)
            symtab_count = 0
    stripped = symtab is None or symtab_count == 0

    ordered_symbols = tuple(sorted(symbol_matches, key=lambda match: match.sort_key()))
    symbols_truncated = len(ordered_symbols) > patterns.limits.max_symbols_per_binary
    matched_symbols = ordered_symbols[: patterns.limits.max_symbols_per_binary]

    raw_bytes, sections_truncated, sections_unread = _collect_string_bytes(
        sections, max_strings_bytes
    )
    if sections_unread:
        errors.append(_error(path, ELF_PARSE_ERROR, "failed to read a section's bytes"))
        reasons.add(evidence.PARTIAL_ELF_SECTION_DATA_UNREAD)
    strings_found = scan_strings(raw_bytes, patterns, max_strings_bytes)

    buildinfo_section = _find_section(sections, ".go.buildinfo")
    buildinfo_bytes: bytes | None = None
    if buildinfo_section is not None:
        try:
            buildinfo_bytes = buildinfo_section.data()
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read .go.buildinfo"))
            reasons.add(evidence.PARTIAL_ELF_GO_BUILDINFO_UNREAD)
    has_buildid = _find_section(sections, ".note.go.buildid") is not None
    go = build_go_info(buildinfo_bytes, strings_found.text, patterns)
    if go is None and (buildinfo_section is not None or has_buildid):
        go = GoBuildInfo()

    result = BinaryEvidence(
        path=path,
        format=evidence.FORMAT_ELF,
        vendored_path=vendored,
        machine=machine,
        bits=bits,
        endian=endian,
        elf_type=elf_type,
        soname=soname,
        needed=needed,
        rpath=rpath,
        runpath=runpath,
        stripped=stripped,
        dynsym_count=dynsym_count,
        symtab_count=symtab_count,
        matched_symbols=matched_symbols,
        matched_strings=strings_found.matched_strings,
        rust_crates=strings_found.rust_crates,
        go=go,
        symbols_truncated=symbols_truncated,
        strings_truncated=sections_truncated or strings_found.truncated,
        partial_analysis=bool(reasons),
        partial_reasons=tuple(sorted(reasons)),
    )
    return result, tuple(sorted(set(errors), key=lambda err: err.sort_key()))


def _collect_string_bytes(
    sections: list[Section], max_strings_bytes: int
) -> tuple[bytes, bool, bool]:
    """Concatenate the read-only, non-executable data sections, in header order.

    A section qualifies when it is allocated `PROGBITS` data that is not executable
    code (so `.rodata`-like sections, not `.text`), plus `.comment` unconditionally:
    compilers and linkers do not always flag it `SHF_ALLOC`, but it is exactly where
    a static OpenSSL leaves its version banner.
    """
    buf = bytearray()
    truncated = False
    unread = False
    for section in sections:
        sh_type = section["sh_type"]
        sh_flags = section["sh_flags"]
        eligible = section.name == ".comment" or (
            sh_type == "SHT_PROGBITS"
            and (sh_flags & _SHF_ALLOC)
            and not (sh_flags & _SHF_EXECINSTR)
        )
        # SHT_NOBITS occupies no file space, so pyelftools materialises sh_size zero
        # bytes for it. sh_size is a 64-bit attacker-controlled field, which makes a
        # few hundred byte object able to demand gigabytes. It holds no strings anyway.
        if not eligible or sh_type == "SHT_NOBITS":
            continue
        remaining = max_strings_bytes - len(buf)
        if remaining <= 0:
            truncated = True
            break
        # Check the declared size before asking for the bytes, not after.
        if section["sh_size"] > remaining:
            truncated = True
        try:
            data = section.data()
        except Exception:
            # The one failure here that used to be silent: no error, no reason, and the
            # strings simply absent. A `.rodata` flagged `SHF_COMPRESSED` over bytes
            # that are not compressed reaches this, and a wheel whose only evidence was
            # the banner in it came back with no findings and nothing saying why.
            unread = True
            continue
        if not data and section["sh_size"]:
            # A short read rather than a raise: `sh_offset` past the end of the object
            # yields no bytes at all. Deliberately not `len(data) < sh_size`, because a
            # compressed section legitimately decompresses to a different length.
            unread = True
        if len(data) > remaining:
            buf.extend(data[:remaining])
            truncated = True
            break
        buf.extend(data)
    return bytes(buf), truncated, unread
