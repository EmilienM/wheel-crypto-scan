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

`.dynamic`, `.dynsym` and `.symtab` are found by section *type* (`SHT_DYNAMIC`,
`SHT_DYNSYM`, `SHT_SYMTAB`), not by name. The dynamic linker never reads section names
or the section header table at all -- it walks `PT_DYNAMIC` and the tags it points
at -- so a name is not what makes an object loadable, and a name-based lookup trusted a
label the loader itself never checks: renaming `.dynsym` to anything else in
`.shstrtab` left every dynamic symbol unread while the object still ran. `pyelftools`
already builds the right wrapper class from `sh_type` regardless of what a section is
called, so this is a lookup change, not a parsing change. `.go.buildinfo`,
`.note.go.buildid` and `.comment` stay name-based: they are plain `SHT_PROGBITS` or
`SHT_NOTE` sections with no type of their own, so name is the only signal there is.

Two shapes a type-based lookup can be handed are not treated as a clean single answer.
More than one section can share a type -- unusual, but not forbidden -- and picking the
first in section order, the way a name-based lookup already did for two sections
sharing a name, would let a decoy of the real section's type, inserted ahead of it,
hide the real one just as effectively as a rename did: `_find_section_by_type` reports
the ambiguity instead of guessing, and none of the candidates is trusted. And a section
can still be found *by name* -- `.dynamic`, `.dynsym`, `.symtab` -- while its `sh_type`
does not match what that name is supposed to mean: a forged `sh_type` alone, name left
untouched, used to make a name-based lookup pick the wrong wrapper class and (usually)
fail loudly, so treating "not found by type" as "absent" here would have made a
disguised section read as a clean one instead. `_type_mismatch` catches this and folds
it into the same partial cause a read failure on that section already carries, rather
than reading as though the section were never there. The check runs unconditionally,
never gated on the type-based lookup having come back empty: a single decoy of the
target type is enough to satisfy that lookup on its own, and a mismatch check that only
ran when nothing else had already answered would go uncalled for exactly the object
this exists to catch -- the real, still-correctly-named section, forged away from its
type, sitting beside an unrelated decoy that happens to carry the type being searched
for.

An object with no section header table at all (`e_shoff == 0`) is a third, different
failure from either: there is nothing to look up by type or by name, so `.dynamic`,
`.dynsym` and `.symtab` are unavailable rather than merely unread, and the whole file is
scanned for strings the way a header that would not parse already is. This is not the
same thing as `e_shnum == 0` on its own, which is the legal extended-numbering encoding
-- the real count lives in the first section's `sh_size` -- and such an object still has
a section header table to read.

`.dynsym`'s declared size is not believed, and neither is `.dynstr`'s. An object whose
`sh_size` covers fewer entries than it carries would be read in full by its own account
while the rest went unlooked-at, so the names read are cross-checked against `.dynstr`,
which is the one place every symbol name must appear. That check is only sound over a
string table we read through, so an index past its end, or into a run it never closes,
is a name we could not resolve rather than whatever bytes happen to be there.
`binfmt.symtab` holds the cross-check, shared with `binfmt.macho`, which makes both of
the same checks of `nsyms` and `strsize`.

`.symtab`'s size is still believed. It drives `stripped` and `symbol_counts.symtab` and
nothing else -- the imported-versus-defined split this reader exists to draw comes from
`.dynsym` alone -- so a lie there costs a field that is recorded rather than a finding.
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
from .caps import cap
from .fallback import read_strings_only
from .golang import build_go_info
from .strings import MAX_STRINGS_BYTES, sanitize, scan_strings
from .symtab import BoundedNames, holds_a_name_not_read

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


def _validated_strtab(elf, sh_link: int, dt_strtab_addr: int | None) -> Section | None:
    """The section `sh_link` names, only when it corroborates `.dynamic`'s own `DT_STRTAB`.

    `sh_link` is a section-header field the loader never reads: `.dynamic` and
    `.dynsym` both resolve names through `PT_DYNAMIC`'s `DT_STRTAB` tag, never through
    any section's `sh_link`. Trusting `sh_link` on its own is the same hazard
    `_find_section_by_type` and `_type_mismatch` already close for `.dynamic`,
    `.dynsym` and `.symtab` themselves, one level down: a section that is correctly
    typed `SHT_STRTAB` but is not the real `.dynstr` -- a decoy planted purely to be
    read through `sh_link`, with `sh_offset` pointing at fabricated or all-NUL bytes --
    is caught by neither. Appending `N` NUL bytes plus a header pointing at them, then
    repointing `.dynsym`'s `sh_link` there, resolves every symbol name to `""`: an
    empty name is not flagged unresolved, so the object read completely clean while a
    real `libcrypto.so.3` carried 64 crypto symbols. `.dynamic`'s own `sh_link` has the
    same hole and is worse: a decoy that happens to spell a real dependency name
    fabricates a `DT_NEEDED` entry the object never declared, rather than merely
    erasing one.

    `DT_STRTAB`'s `d_ptr` is data this reader already has in hand from reading
    `.dynamic` -- it needs no string resolution itself, so it is available even when
    the string table it points at cannot be trusted -- and this reconciles the two
    rather than parsing anything new: the resolved section's declared virtual address
    has to match what `.dynamic` independently says the real string table's address
    is. `dt_strtab_addr` is `None` when `.dynamic` itself could not be read or carries
    no `DT_STRTAB` tag at all, and there is then nothing to corroborate against --
    treated the same as a mismatch, fail closed, rather than trusting `sh_link`
    unwitnessed.

    Left open: `sh_addr` matching while `sh_offset` alone is forged, which would need
    program-header-based virtual-address-to-file-offset translation to close and is
    exactly the scope this issue's chain has repeatedly deferred. See `DECISIONS.md`.
    """
    if dt_strtab_addr is None:
        return None
    try:
        section = elf.get_section(sh_link)
    except Exception:
        return None
    if section is None or section["sh_type"] != "SHT_STRTAB":
        return None
    if section["sh_addr"] != dt_strtab_addr:
        return None
    return section


def _bounded_section_data(section: Section, max_bytes: int) -> tuple[bytes, bool]:
    """`section.data()`, refused before it would produce more than `max_bytes`.

    Two shapes make `data_size` -- the amount `.data()` is actually about to
    materialise -- larger than anything the object's own bytes on disk justify, and
    both are checked here rather than trusted to `sh_size`.

    A `SHF_COMPRESSED` section's `Chdr.ch_size` is the logical, decompressed size, and
    it is an attacker-controlled 64-bit field exactly like `sh_size` itself: pyelftools'
    `Section.__init__` already reads it eagerly (24 bytes for `Elf64_Chdr`, 12 for
    `Elf32_Chdr`; both fixed-size and cheap regardless of the section's declared
    length) and exposes it as `section.data_size`, well before `.data()` ever calls
    `zlib.decompressobj().decompress()` against however many bytes `ch_size` names.

    An `SHT_NOBITS` section is the same shape without any compression at all:
    `Section.data()` special-cases it first, ahead of the compressed branch, and
    returns `b"\\0" * self.data_size` with no file bytes read to justify the length --
    `data_size` there is just `sh_size` itself (pyelftools' `Section.__init__` sets
    `_decompressed_size = header['sh_size']` whenever `compressed` is false), which
    occupies no file space and so is never bounded by how big the object actually is.
    `_collect_string_bytes` already excludes `SHT_NOBITS` sections outright for its own
    `.rodata`/`.comment` sweep; this helper is used by callers (`.go.buildinfo`) that
    are found by name rather than by type and so never ran that exclusion, which makes
    it the one field-checked here rather than assumed: `not section.compressed` is not
    "ordinary and file-backed", it is "not compressed", and `SHT_NOBITS` is the case
    where that gap is real.

    Checking `data_size` first means an oversized section, compressed or `SHT_NOBITS`,
    is refused, not inflated: `.data()` is never called at all, so neither the
    decompression nor the zero-fill this guards against ever runs. A section declaring
    at most `max_bytes` is unaffected either way.

    Returns `(b"", True)` in the refused case, the same "unread" signal a `.data()`
    call that raises already produces one level up -- decompression failures that
    happen despite an honest declared size (garbage compression bytes, a truncated
    stream) are unchanged: they still reach `.data()` and still raise there.
    """
    if (section.compressed or section["sh_type"] == "SHT_NOBITS") and section.data_size > max_bytes:
        return b"", True
    return section.data(), False


def _symbol_bytes(
    elf, section, dt_strtab_addr: int | None, max_table_bytes: int
) -> tuple[bytes, bytes, bool]:
    """A symbol table and its string table, each read once, in that order.

    pyelftools' `get_symbol()` seeks per symbol, alternating between the two. On a
    member too large to hold in memory those seeks run backwards through a zip stream,
    and a backwards seek costs a fresh decompression. A real example: pandoc ships a
    400 MiB object with 497,040 dynamic symbols, which never finished. Reading each
    section once turns that into two forward reads -- and the caller holds both, so
    nothing reads either of them twice.

    In file order, not in the order the caller wants them: the linker usually puts
    `.dynsym` first, but this suite's own fixtures do not, and neither do some
    `objcopy` reorderings. Reading the later one first is a backwards seek, which
    through a zip member is one more full decompression pass. `binfmt.macho` sorts its
    two regions for the same reason.

    `dt_strtab_addr` is threaded through from `.dynamic`, and `_validated_strtab`
    reads `None` for it as "nothing to corroborate against" rather than "anything
    goes": an object whose `.dynamic` could not be read has no witness for `.dynsym`'s
    string table either, so this falls back to no names found, the same as any other
    unresolved `sh_link` -- never to trusting whatever `sh_link` names outright.

    `max_table_bytes` is `_bounded_section_data`'s ceiling for both reads: `.dynsym`
    and its string table are read through the identical `.data()` call `.rodata` is,
    so a `SHF_COMPRESSED` `.dynsym` or `.dynstr` is the same exposure one level over,
    and the caller's own budget (`max_strings_bytes`) is what already bounds how much
    of this object it is willing to inflate. The third return value is `True` when
    either read was refused for that reason; the caller folds it into
    `elf_dynsym_unread` the same way an actual decompression failure already does.
    """
    strtab = _validated_strtab(elf, section["sh_link"], dt_strtab_addr)
    if strtab is not None and strtab["sh_offset"] < section["sh_offset"]:
        names, names_unread = _bounded_section_data(strtab, max_table_bytes)
        data, data_unread = _bounded_section_data(section, max_table_bytes)
        return data, names, names_unread or data_unread
    data, data_unread = _bounded_section_data(section, max_table_bytes)
    names, names_unread = b"", False
    if strtab is not None:
        names, names_unread = _bounded_section_data(strtab, max_table_bytes)
    return data, names, data_unread or names_unread


def _iter_symbols(elf, data: bytes, names: bytes) -> Iterator[tuple[str, bool, bool]]:
    """Yield (name, is_undefined, name_resolved) for a symbol table already in hand.

    `names` has to be the same bytes the caller cross-checks against, or the two are
    asking about different string tables: `_symbol_bytes` returns both together for
    that reason.

    Every entry is reported, including the ones with nothing usable in them. An index
    past the end of the string table, into a run that never terminates, or past the
    per-name cap `binfmt.symtab.BoundedNames` enforces, is the difference between "no
    crypto here" and "we could not read the names", and only the caller can tell those
    apart. `name` is empty for index 0, which is how ELF spells "this entry has no
    name", and for a name that sanitises away to nothing.

    Index 0 is checked before `names` is asked about it at all, unconditionally: ELF
    defines index 0 as "no name" regardless of what byte actually sits there, the same
    guarantee a decoy table could otherwise spend effort forging. `BoundedNames` is
    built fresh here, once per call, because its cache is only sound over the one
    string table this call was handed -- see its docstring.
    """
    entry_size, name_offset, shndx_offset = _SYM_LAYOUT[elf.elfclass]
    end = "<" if elf.little_endian else ">"
    u32 = struct.Struct(end + "I")
    u16 = struct.Struct(end + "H")
    resolver = BoundedNames(names)

    for base in range(0, len(data) - entry_size + 1, entry_size):
        st_name = u32.unpack_from(data, base + name_offset)[0]
        undefined = u16.unpack_from(data, base + shndx_offset)[0] == _SHN_UNDEF
        if st_name == 0:
            yield "", undefined, True
            continue
        name, resolved = resolver.resolve(st_name)
        yield name, undefined, resolved


def _find_section(sections: Sequence[Section], name: str) -> Section | None:
    for section in sections:
        if section.name == name:
            return section
    return None


def _find_section_by_type(sections: Sequence[Section], sh_type: str) -> tuple[Section | None, bool]:
    """The section of `sh_type`, and whether more than one candidate exists.

    `sh_type` is what the dynamic linker actually keys on -- `pyelftools` builds the
    matching wrapper class (`DynamicSection`, `SymbolTableSection`) from it regardless
    of what `.shstrtab` calls the section, so a rename that fools a name-based lookup
    does not fool this one.

    Returns `(None, False)` when nothing matches, `(section, False)` when exactly one
    does, and `(None, True)` when more than one does. Picking the first match in
    section order -- the rule a name-based lookup already applied to two sections
    sharing a name -- would let a decoy of the real section's type, spliced in ahead of
    it, silently win: exactly the "renamed and now reads clean" shape this module
    exists to close, one level down. An ambiguous count is therefore never trusted;
    the caller reads the second return value and folds it into `partial_reasons`
    instead of guessing which candidate is real.
    """
    matches = [section for section in sections if section["sh_type"] == sh_type]
    if len(matches) > 1:
        return None, True
    return (matches[0] if matches else None), False


def _type_mismatch(sections: Sequence[Section], name: str, sh_type: str) -> bool:
    """True when a section named `name` exists but cannot be trusted to be `sh_type`.

    A type-based lookup that finds nothing is not always the same fact as a section
    that is genuinely absent: `.shstrtab` can still call something `.dynsym` while its
    four-byte `sh_type` field alone has been changed to something else, which makes a
    type-based lookup miss it the same way a rename made a name-based one miss the
    section entirely. The object is not clean; it carries a section claiming to be one
    this reader cannot trust as one, and the caller folds that into the same cause a
    section of this kind that failed to read already carries.

    Called unconditionally by `read_elf`, not only when the type-based lookup for
    `sh_type` came back empty: an unrelated section of the right type -- a decoy, or
    a real one belonging to a different, coincidentally-absent purpose -- can satisfy
    that lookup on its own, and a caller that only asked this question after finding
    nothing would never ask it at all in that case, leaving the real, still-named
    section invisible from both directions.

    More than one section can share `name` too, and picking the first the way
    `_find_section` always has is the identical hazard `_find_section_by_type` was
    changed to stop guessing about: a correctly-typed decoy sharing the real section's
    *name* -- rather than its type -- would sort first, report no mismatch, and hide a
    same-named real section sitting right behind it, still carrying its own forged
    `sh_type`. Ambiguous by name is therefore also untrusted, the same as ambiguous by
    type.
    """
    matches = [section for section in sections if section.name == name]
    if len(matches) > 1:
        return True
    return bool(matches) and matches[0]["sh_type"] != sh_type


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

    # `num_sections` came back zero with no exception on either read above: not a
    # section list we failed on, but a section header table that was never there.
    # `elf.num_sections()` already resolves the legal extended-numbering encoding
    # (`e_shnum == 0`, the real count in the first section's `sh_size`) to that real,
    # nonzero count, so reaching zero here means `e_shoff == 0` -- there truly is no
    # table, not merely a count of zero declared in the ordinary field. The dynamic
    # linker does not need one -- it loads this object from `PT_DYNAMIC` alone -- so
    # this is a loadable object, not a corrupt one, and it is a different fact from
    # `elf_sections_unread`: there is no `.dynamic`, `.dynsym` or `.symtab` to even
    # look for, by type or by name, so nothing past this point can produce anything
    # but empty defaults. Falling through would report that emptiness as a complete
    # read the same way a renamed section used to.
    if num_sections == 0 and not reasons:
        result, _ = read_strings_only(
            stream,
            path,
            patterns,
            vendored=vendored,
            fmt=evidence.FORMAT_ELF,
            max_strings_bytes=max_strings_bytes,
            reason=evidence.PARTIAL_ELF_SECTION_TABLE_ABSENT,
        )
        result = replace(
            result,
            machine=machine,
            bits=bits,
            endian=endian,
            elf_type=elf_type,
        )
        errors.append(_error(path, ELF_PARSE_ERROR, "elf has no section header table to read"))
        return result, tuple(sorted(set(errors), key=lambda err: err.sort_key()))

    dynamic, dynamic_ambiguous = _find_section_by_type(sections, "SHT_DYNAMIC")
    if dynamic_ambiguous:
        errors.append(
            _error(
                path,
                ELF_PARSE_ERROR,
                "more than one SHT_DYNAMIC section, which is real cannot be told",
            )
        )
        reasons.add(evidence.PARTIAL_ELF_SECTION_TYPE_AMBIGUOUS)
    elif _type_mismatch(sections, ".dynamic", "SHT_DYNAMIC"):
        errors.append(
            _error(path, ELF_PARSE_ERROR, ".dynamic exists but its sh_type is not SHT_DYNAMIC")
        )
        reasons.add(evidence.PARTIAL_ELF_DYNAMIC_UNREAD)
    needed: tuple[str, ...] = ()
    soname: str | None = None
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()
    dt_strtab_addr: int | None = None
    if dynamic is not None:
        try:
            needed = tuple(sorted(sanitize(tag.needed) for tag in dynamic.iter_tags("DT_NEEDED")))
            sonames = [sanitize(tag.soname) for tag in dynamic.iter_tags("DT_SONAME")]
            soname = sonames[0] if sonames else None
            rpath = tuple(sorted(sanitize(tag.rpath) for tag in dynamic.iter_tags("DT_RPATH")))
            runpath = tuple(
                sorted(sanitize(tag.runpath) for tag in dynamic.iter_tags("DT_RUNPATH"))
            )
            # `DT_NEEDED`/`DT_SONAME`/`DT_RPATH`/`DT_RUNPATH` above were just resolved
            # through whatever `.dynamic`'s own `sh_link` names, which pyelftools
            # accepted at face value the same way `_symbol_bytes` used to: a decoy
            # `SHT_STRTAB` planted there does not merely erase a name, it can
            # fabricate one -- a decoy spelling a real dependency name reports a
            # `DT_NEEDED` entry the object never declared. `d_ptr` needs no string
            # resolution itself, so it is available to check against regardless of
            # whether the strings above can be trusted.
            dt_strtab_addr, _ = dynamic.get_table_offset("DT_STRTAB")
            if _validated_strtab(elf, dynamic["sh_link"], dt_strtab_addr) is None:
                errors.append(
                    _error(
                        path,
                        ELF_PARSE_ERROR,
                        ".dynamic's sh_link does not corroborate its own DT_STRTAB",
                    )
                )
                reasons.add(evidence.PARTIAL_ELF_DYNAMIC_UNREAD)
                needed, soname, rpath, runpath = (), None, (), ()
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read the dynamic section"))
            reasons.add(evidence.PARTIAL_ELF_DYNAMIC_UNREAD)
            needed, soname, rpath, runpath = (), None, (), ()

    dynsym, dynsym_ambiguous = _find_section_by_type(sections, "SHT_DYNSYM")
    if dynsym_ambiguous:
        errors.append(
            _error(
                path,
                ELF_PARSE_ERROR,
                "more than one SHT_DYNSYM section, which is real cannot be told",
            )
        )
        reasons.add(evidence.PARTIAL_ELF_SECTION_TYPE_AMBIGUOUS)
    elif _type_mismatch(sections, ".dynsym", "SHT_DYNSYM"):
        errors.append(
            _error(path, ELF_PARSE_ERROR, ".dynsym exists but its sh_type is not SHT_DYNSYM")
        )
        reasons.add(evidence.PARTIAL_ELF_DYNSYM_UNREAD)
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
            # Only the crypto names, which is all the cross-check below compares
            # against: remembering every name costs 24 MiB on a half-million-symbol
            # table, for a question only ever asked about the handful a group claims.
            read_crypto: set[str] = set()
            unresolved = 0
            table, dynstr, symtab_bytes_unread = _symbol_bytes(
                elf, dynsym, dt_strtab_addr, max_strings_bytes
            )
            if symtab_bytes_unread:
                # A compressed .dynsym or .dynstr declaring more than the object's
                # own budget: refused before decompression by `_bounded_section_data`,
                # so `table`/`dynstr` are empty rather than however many bytes
                # `ch_size` named. Named explicitly rather than left to fall out of
                # `unresolved` below: an object whose .dynsym itself was refused has
                # no rows to iterate at all, so `unresolved` would stay zero with
                # nothing else to say this object was not read.
                errors.append(
                    _error(
                        path,
                        ELF_PARSE_ERROR,
                        ".dynsym or its string table declares more bytes than the budget allows",
                    )
                )
                reasons.add(evidence.PARTIAL_ELF_DYNSYM_UNREAD)
            for name, undefined, resolved in _iter_symbols(elf, table, dynstr):
                if not resolved:
                    unresolved += 1
                    continue
                groups = patterns.symbol_groups_for(name) if name else ()
                if not groups:
                    continue
                read_crypto.add(name)
                binding = evidence.BINDING_IMPORTED if undefined else evidence.BINDING_DEFINED
                for group in groups:
                    symbol_matches.add(SymbolMatch(name=name, group=group, binding=binding))
            # Both sizes are fields the object fills in about itself, and reading
            # exactly what they declare is not reading what the object carries. The same
            # two checks `binfmt.macho` makes of `nsyms` and `strsize`, in the same
            # order: a string table we could not read through is reported as that, and
            # the cross-check over one is worth nothing.
            #
            # A crypto name in `.dynstr` that no entry we read resolved to is a symbol
            # this object has and did not declare. Absence of evidence is not evidence
            # of absence, and here the evidence is present and pointed away from.
            if unresolved:
                errors.append(
                    _error(path, ELF_PARSE_ERROR, ".dynsym names strings .dynstr does not hold")
                )
                reasons.add(evidence.PARTIAL_ELF_DYNSYM_UNREAD)
            elif holds_a_name_not_read(dynstr, patterns, read_crypto):
                errors.append(
                    _error(
                        path,
                        ELF_PARSE_ERROR,
                        ".dynsym declares fewer entries than .dynstr holds names for",
                    )
                )
                reasons.add(evidence.PARTIAL_ELF_DYNSYM_UNREAD)
                reasons.add(evidence.PARTIAL_SYMTAB_UNDERSTATES_ROWS)
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read the dynamic symbol table"))
            reasons.add(evidence.PARTIAL_ELF_DYNSYM_UNREAD)

    symtab, symtab_ambiguous = _find_section_by_type(sections, "SHT_SYMTAB")
    if symtab_ambiguous:
        errors.append(
            _error(
                path,
                ELF_PARSE_ERROR,
                "more than one SHT_SYMTAB section, which is real cannot be told",
            )
        )
        reasons.add(evidence.PARTIAL_ELF_SECTION_TYPE_AMBIGUOUS)
    elif _type_mismatch(sections, ".symtab", "SHT_SYMTAB"):
        errors.append(
            _error(path, ELF_PARSE_ERROR, ".symtab exists but its sh_type is not SHT_SYMTAB")
        )
        reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)
    symtab_count = 0
    if symtab is not None:
        try:
            symtab_count = symtab.num_symbols()
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read the symbol table"))
            reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)
            symtab_count = 0
    stripped = symtab is None or symtab_count == 0

    matched_symbols, symbols_truncated = cap(symbol_matches, patterns.limits.max_symbols_per_binary)

    raw_bytes, sections_truncated, sections_unread = _collect_string_bytes(
        sections, max_strings_bytes
    )
    if sections_unread:
        errors.append(_error(path, ELF_PARSE_ERROR, "failed to read a section's bytes"))
        reasons.add(evidence.PARTIAL_ELF_SECTION_DATA_UNREAD)
    strings_found = scan_strings(raw_bytes, patterns, max_strings_bytes)
    # The bound this reader applies is to the concatenation, not to the file, so an
    # object is short of evidence here when an eligible section had no room left rather
    # than when the object is large. `elf_section_data_unread` is a different fact: a
    # section whose bytes would not read at all, which records an error where this
    # records none.
    if sections_truncated:
        reasons.add(evidence.PARTIAL_STRINGS_BYTES_UNREAD)

    buildinfo_section = _find_section(sections, ".go.buildinfo")
    buildinfo_bytes: bytes | None = None
    if buildinfo_section is not None:
        buildinfo_unread = False
        try:
            # Read through the same `.data()` call `.rodata` and `.dynsym` are, so a
            # `SHF_COMPRESSED` `.go.buildinfo` is the identical exposure: refused
            # before decompression rather than caught after, via
            # `_bounded_section_data`. An actual decompression failure despite an
            # honest declared size still reaches `.data()` and is still caught here.
            buildinfo_bytes, buildinfo_unread = _bounded_section_data(
                buildinfo_section, max_strings_bytes
            )
        except Exception:
            buildinfo_unread = True
        if buildinfo_unread:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read .go.buildinfo"))
            reasons.add(evidence.PARTIAL_ELF_GO_BUILDINFO_UNREAD)
            buildinfo_bytes = None
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

    `truncated` is what the caller turns into `strings_bytes_unread`, so it says what
    was actually dropped rather than what was declared. `sh_size` is a field the object
    fills in about itself: a section claiming a gigabyte and decompressing to forty
    bytes costs nothing and used to set this anyway, which was free while nothing read
    it and is a wheel on the triage list now that something does.
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
        # `_bounded_section_data` reads `section.data_size` -- `Chdr.ch_size` for a
        # `SHF_COMPRESSED` section, which pyelftools reads eagerly in
        # `Section.__init__` well before `.data()` would call
        # `zlib.decompressobj().decompress()` against however many bytes it names --
        # against `remaining`, the budget actually left, and refuses the section
        # before it is inflated rather than truncating it after. A section declaring
        # exactly `remaining` still reads normally below -- refused is strictly
        # "more than", not "at least" -- and this is the one call site in the module
        # that predicate is written, shared with `_symbol_bytes` and `.go.buildinfo`.
        #
        # A refusal here sets `unread`, not `truncated`: `truncated` is what a
        # section read in full and then cut to fit sets, and this section was never
        # read at all, so nothing here actually knows how many of its bytes -- if
        # any -- would have been genuine strings versus more of whatever made
        # `ch_size` this large in the first place. `ch_size` alone cannot tell an
        # honestly oversized declaration apart from a malformed header that happens
        # to decode to a huge number (see DECISIONS.md, "A compressed section is
        # checked before it is inflated" -- the existing "elf section data
        # unreadable" fixture in `tests/test_partial_reasons.py` is exactly that
        # shape), so `strings_truncated` can under-report for this cause: `true`
        # would claim a definite byte count was dropped for budget reasons
        # specifically, which is not a claim this branch is in a position to make.
        try:
            data, section_unread = _bounded_section_data(section, remaining)
        except Exception:
            # The one failure here that used to be silent: no error, no reason, and the
            # strings simply absent. A `.rodata` flagged `SHF_COMPRESSED` over bytes
            # that are not compressed reaches this, and a wheel whose only evidence was
            # the banner in it came back with no findings and nothing saying why.
            unread = True
            continue
        if section_unread:
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
