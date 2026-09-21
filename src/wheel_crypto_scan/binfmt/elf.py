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

`.symtab`'s size is still believed, and it always drives `stripped` and
`symbol_counts.symtab`. When `.dynsym` is present it is the authority on imports, and
`.symtab` is read for *definitions* alone (#127): a statically linked copy whose symbols
a version script kept local lives there and nowhere else, which is what cryptography
50.0.1 does with 776 `EVP_*` definitions beside a `.dynsym` exporting only its module
init. Imports are not taken from it in that mode, because a dynamically linked object
must declare every import in `.dynsym` to link at all, so `.symtab` can only restate
them under a second provenance or let a planted undefined entry read as a dependency
the object does not have. Of `.symtab`'s two cross-checks, the one that asks whether a
name the reader was *pointed at* could be read runs in both modes, because an honest
table never fails it; the one that compares `.symtab`'s rows against every `SHT_STRTAB`
in the object runs in both too, because it is the only thing that sees a `sh_link`
repointed at a decoy, and it is fed the names *both* tables resolved so an imported name
`.dynsym` accounted for does not read as one this object hid. When `.dynsym` is genuinely
absent -- a relocatable object (`ET_REL`, a `.o`/`.obj` before linking, the shape
every member of a `.a`/`.lib` static archive has, see `binfmt.ar`), or a statically
linked executable, neither of which has any dynamic linking information to carry --
`.symtab` is the object's only symbol table and is read and matched the same way, with
its own cross-check, because a symbol compiled straight into it with no accompanying
string banner was otherwise invisible to symbol-based detection. `.symtab`'s own
string table is trusted through its `sh_link` directly, unlike `.dynsym`'s: nothing
but a section-header-reading tool ever resolves a `.symtab` name, so there is no
`.dynamic`-equivalent authority to cross-check `sh_link` against, and `sh_link` naming
it is the ELF spec's own definition of what `.strtab` is -- which is cheaper to
attack, not safer, so the cross-check spans every `SHT_STRTAB` section in the object
rather than trusting the one `sh_link` names (`_any_strtab_holds_a_name_not_read`).
#117 gated `.symtab` matching on `.dynsym`'s absence, which left a dynamically linked
object unaffected *by construction* rather than by a corpus check this reader could not
run. That gate also left unread the case this tool exists for, so #127 narrowed it to
the definitions above and replaced the construction argument with a measurement: over 18
native wheels off PyPI, five verdict blocks change, three of them the `none`-to-`static`
this exists for, and no finding and no `(group, binding)` kind is lost from any object.
What the gate also bought was time, and a `symbol_locator` prefilter over `.strtab` was
tried to buy it back: it was measured at 0.32s against 0.55s on a 26.7 MiB object with
half a million symbols, and rejected, because a `.strtab` shrunk to hide a name is one
the prefilter reads as holding nothing. Every row is walked. `DECISIONS.md` records what
the narrower gate costs against a hostile object, and why imports stay behind it. See
#117 and #127.
"""

# This module documents every way an attacker-controlled label can win a lookup and
# every cross-check that closes one, by design (AGENTS.md: every policy entry carries
# a `why`), and #56's chain plus #117 each added more without shrinking any of the
# others. Disabled here rather than raising `max-module-lines` project-wide, which
# would quietly give every OTHER module the same headroom this one earns by being
# documentation-heavy. See DECISIONS.md, "A module-local line-count exemption instead
# of a third global bump" (#85), the precedent this follows.
# pylint: disable=too-many-lines

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
from ..caps import cap
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


# ELF symbol table entry layout: offsets of the fields we need, by class.
# 64-bit: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
# 32-bit: st_name(4) st_value(4) st_size(4) st_info(1) st_other(1) st_shndx(2)
_SYM_LAYOUT = {64: (24, 0, 4, 6), 32: (16, 0, 12, 14)}
_SHN_UNDEF = 0
# `ELF32_ST_TYPE(st_info)`: the low 4 bits, identical layout in both classes.
_STT_SECTION = 3
_STT_FILE = 4


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


def _bounded_section_data(
    section: Section, max_bytes: int, *, keep_prefix: bool = False
) -> tuple[bytes, bool]:
    """`section.data()`, refused before it would produce more than `max_bytes`.

    `data_size` is the amount `.data()` is actually about to materialise, and it is
    checked unconditionally here rather than trusted to `sh_size` -- #62 originally
    only checked it for a `SHF_COMPRESSED` or `SHT_NOBITS` section, on the strength of
    the two shapes its own reproduction measured, and left an ordinary, uncompressed,
    file-backed section reaching `.data()` with no check at all (#95).

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

    An ordinary section -- neither compressed nor `SHT_NOBITS` -- has `data_size` equal
    to `sh_size` too, the same field `Section.__init__` sets it from, but that size *is*
    file-backed: reading it is one honest `stream.read(sh_size)`. That still costs
    whatever `sh_size` names before this reader's own budget ever gets a say, which is
    exactly the exposure #62 closed for the other two shapes and left open here: an
    honestly large `.rodata`, `.comment`, or a real `.dynsym`/`.dynstr` from a genuine
    symbol table, all read through this same call, none of them checked. Checking
    `data_size` unconditionally closes it without changing anything for a section under
    budget, compressed, `SHT_NOBITS` or ordinary alike: `.data()` still runs and
    produces exactly what it always did.

    Checking `data_size` first means an oversized section, whatever shape it is,
    is refused, not inflated: `.data()` is never called at all, so neither the
    decompression, the zero-fill, nor the plain file read this guards against ever
    runs. A section declaring at most `max_bytes` is unaffected either way.

    `keep_prefix` decides what an over-budget ORDINARY section hands back. Default
    `False` refuses it outright, `(b"", True)`, the same as a compressed or
    `SHT_NOBITS` section always must regardless of this flag: a compressed section is
    an all-or-nothing `zlib` call with no cheap way to keep a prefix (#62's own "What
    was rejected" already declines a second, `max_length`-bounded decompression path
    for exactly this reason), and an `SHT_NOBITS` "prefix" is `b"\\0"` bytes carrying
    no evidence either way. `True` reads `max_bytes` bytes of the section's own real,
    file-backed content instead of refusing it -- one plain `stream.seek`/`.read()` at
    the section's own offset, no second reader or decompression needed, unlike the
    compressed case -- and returns that prefix still flagged unread. `.rodata`,
    `.comment` and `.go.buildinfo` pass `True` (#95): an honestly oversized section's
    first `max_bytes` are real, readable evidence -- an OpenSSL banner at offset 0 of
    an otherwise-oversized `.rodata`, say -- the same evidence `_collect_string_bytes`
    already kept for an ordinary section before this fix started refusing it outright,
    just bounded at the single-section read now rather than only at the accumulated
    buffer afterwards. `.dynsym`/`.dynstr`, via `_symbol_bytes`, do not pass it and
    keep the default: a byte-bounded prefix of a symbol table is not a set of complete
    rows, and an entry near the cut is as likely to point past a truncated string
    table as into it, so there is nothing here safe to keep without a further,
    row-aware cap this fix does not add.

    Returns `(b"", True)` in the refused case (`keep_prefix` false, or the section
    compressed or `SHT_NOBITS` regardless), or `(prefix, True)` when `keep_prefix` is
    honoured -- either way the same "unread" signal a `.data()` call that raises
    already produces one level up. Decompression failures that happen despite an
    honest declared size (garbage compression bytes, a truncated stream) are
    unchanged: they still reach `.data()` and still raise there.
    """
    if section.data_size > max_bytes:
        if keep_prefix and not section.compressed and section["sh_type"] != "SHT_NOBITS":
            section.stream.seek(section["sh_offset"])
            return section.stream.read(max_bytes), True
        return b"", True
    return section.data(), False


@dataclass(frozen=True, slots=True)
class _SymtabRead:
    """`.symtab` and its string table, read once each, with whether a read was refused."""

    table: bytes
    strings: bytes
    bytes_unread: bool


def _read_symtab(elf, symtab, max_strings_bytes: int) -> _SymtabRead:
    """Resolve `.symtab`'s string table and read both sections, bounded.

    The prologue both `.symtab` modes share: the sole-table one #117 added, and the
    supplementary one #127 added beside it. Their loops differ -- one cross-checks the
    table it is the only reader of, the other takes definitions beside an authoritative
    `.dynsym` -- and are deliberately not merged. This is the part that does not differ,
    and leaving it copied left the same budget message written twice.

    `_symtab_strtab` rather than `_validated_strtab`: `.symtab` trusts its own `sh_link`
    under rules of its own, documented there.
    """
    strtab_section = _symtab_strtab(elf, symtab["sh_link"])
    table, strings, bytes_unread = _symbol_bytes(elf, symtab, strtab_section, max_strings_bytes)
    return _SymtabRead(table=table, strings=strings, bytes_unread=bytes_unread)


def _symtab_strtab(elf, sh_link: int) -> Section | None:
    """The section `.symtab`'s own `sh_link` names, trusted once it really is one.

    No `_validated_strtab`-style *address* cross-check applies: nothing but a
    section-header-reading tool ever resolves a `.symtab` name, so there is no
    `.dynamic`-equivalent authority to corroborate `sh_link` against the way
    `DT_STRTAB` corroborates `.dynsym`'s. That does not make `sh_link` safe to trust
    outright, only cheaper to attack: a `sh_link` repointed at an appended, all-NUL
    `SHT_STRTAB` resolves every name to `""`, the identical decoy `_validated_strtab`
    exists to close for `.dynsym` -- this function alone cannot see it, because the
    real `.strtab` is simply never asked about. `_any_strtab_holds_a_name_not_read`,
    the caller's cross-check, is what actually closes it: it does not trust one
    resolved table, it asks every `SHT_STRTAB` section in the object, so the real
    `.strtab` still gets a chance to contradict the decoy. The one check kept here on
    its own: a `sh_link` resolving to a section that is not really `SHT_STRTAB` could
    not be `.strtab`.
    """
    try:
        section = elf.get_section(sh_link)
    except Exception:
        return None
    if section is None or section["sh_type"] != "SHT_STRTAB":
        return None
    return section


def _any_strtab_holds_a_name_not_read(
    sections: Sequence[Section], patterns: BinaryPatterns, read: set[str], max_bytes: int
) -> bool:
    """Whether any `SHT_STRTAB` section in the object -- not just the one `.symtab`'s
    `sh_link` names -- holds a crypto-group name no entry read from `.symtab` resolved
    to, or could not be fully checked for one.

    `_symtab_strtab` has no independent authority to confirm `sh_link` really names
    `.strtab`, unlike `.dynsym`'s `DT_STRTAB`-corroborated read, so a crafted object can
    repoint it at a decoy `SHT_STRTAB` -- appended, all-NUL, resolving every name to
    `""` -- and pass a check that only ever looks at the table `sh_link` claims. This
    closes it the way `holds_a_name_not_read` already closes the honest case: the real
    `.strtab`, wherever it sits in the section table, still spells the name out and is
    still read here, decoy or not.

    A section over `max_bytes` counts as a hit, not a skip: an earlier version treated
    it as nothing to worry about, which reopened the identical decoy under a second
    construction -- a small decoy `.symtab` is happy to point at, sitting beside the
    genuine `.strtab` with its own declared `sh_size` inflated past the budget, reads
    completely clean, because the one section that could have contradicted the decoy
    was silently skipped rather than flagged as unchecked. "Unreadable means `OPAQUE`,
    never `NO_CRYPTO_DETECTED`" applies to a string table this function could not fully
    examine exactly as it does to one that spelled a name out.
    """
    for section in sections:
        if section["sh_type"] != "SHT_STRTAB":
            continue
        data, unread = _bounded_section_data(section, max_bytes)
        if unread:
            return True
        if holds_a_name_not_read(data, patterns, read):
            return True
    return False


def _symbol_bytes(
    elf, section, strtab: Section | None, max_table_bytes: int
) -> tuple[bytes, bytes, bool]:
    """A symbol table and its already-resolved string table, each read once, in that order.

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

    `strtab` is resolved by the caller, not here: `.dynsym` and `.symtab` trust their
    own `sh_link` under different rules (`_validated_strtab` vs. `_symtab_strtab`), and
    mixing either's trust model into this function would apply the wrong one to the
    other's caller. `None` means no string table could be trusted at all.

    `max_table_bytes` is `_bounded_section_data`'s ceiling for both reads: the symbol
    table and its string table are read through the identical `.data()` call `.rodata`
    is, so a `SHF_COMPRESSED` one is the same exposure one level over, and the caller's
    own budget (`max_strings_bytes`) is what already bounds how much of this object it
    is willing to inflate. The third return value is `True` when either read was
    refused for that reason; the caller folds it into its own unread reason the same
    way an actual decompression failure already does.
    """
    if strtab is not None and strtab["sh_offset"] < section["sh_offset"]:
        names, names_unread = _bounded_section_data(strtab, max_table_bytes)
        data, data_unread = _bounded_section_data(section, max_table_bytes)
        return data, names, names_unread or data_unread
    data, data_unread = _bounded_section_data(section, max_table_bytes)
    names, names_unread = b"", False
    if strtab is not None:
        names, names_unread = _bounded_section_data(strtab, max_table_bytes)
    return data, names, data_unread or names_unread


def _iter_symbols(elf, data: bytes, names: bytes) -> Iterator[tuple[str, bool, bool, int]]:
    """Yield (name, is_undefined, name_resolved, symbol_type) for a table already in hand.

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

    `symbol_type` is `st_info`'s low four bits, `ELF32_ST_TYPE`, identical in both
    classes. `.dynsym` callers have never needed it: a dynamic symbol table does not
    normally carry `STT_FILE`/`STT_SECTION` entries. `.symtab` does -- a source-file
    pseudo-symbol or a per-section entry is a name, and one named `EVP_md5.c` or
    `blake3_dispatch.c` would otherwise match a group by nothing but coincidence of a
    filename with the code it happens to implement, in the one field this whole tool
    turns on. The caller decides what to do with it; this reads the byte regardless.
    """
    entry_size, name_offset, info_offset, shndx_offset = _SYM_LAYOUT[elf.elfclass]
    end = "<" if elf.little_endian else ">"
    u32 = struct.Struct(end + "I")
    u16 = struct.Struct(end + "H")
    resolver = BoundedNames(names)

    for base in range(0, len(data) - entry_size + 1, entry_size):
        st_name = u32.unpack_from(data, base + name_offset)[0]
        st_type = data[base + info_offset] & 0xF
        undefined = u16.unpack_from(data, base + shndx_offset)[0] == _SHN_UNDEF
        if st_name == 0:
            yield "", undefined, True, st_type
            continue
        name, resolved = resolver.resolve(st_name)
        yield name, undefined, resolved, st_type


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
    dynsym_type_mismatch = False
    if dynsym_ambiguous:
        errors.append(
            _error(
                path,
                ELF_PARSE_ERROR,
                "more than one SHT_DYNSYM section, which is real cannot be told",
            )
        )
        reasons.add(evidence.PARTIAL_ELF_SECTION_TYPE_AMBIGUOUS)
    else:
        dynsym_type_mismatch = _type_mismatch(sections, ".dynsym", "SHT_DYNSYM")
        if dynsym_type_mismatch:
            errors.append(
                _error(path, ELF_PARSE_ERROR, ".dynsym exists but its sh_type is not SHT_DYNSYM")
            )
            reasons.add(evidence.PARTIAL_ELF_DYNSYM_UNREAD)
    # `.symtab` matching (below) is gated on this: only genuinely absent, never
    # ambiguous, forged away from its type, or unreachable because a section header
    # failed to parse at all -- all three mean the object's own section table cannot
    # be trusted about whether `.dynsym` exists, not that it genuinely has none. A
    # `.dynsym` whose own header failed to read never reaches `sections` in the first
    # place, so `dynsym is None` alone cannot tell that case apart from real absence.
    dynsym_absent = (
        dynsym is None
        and not dynsym_ambiguous
        and not dynsym_type_mismatch
        and evidence.PARTIAL_ELF_SECTIONS_UNREAD not in reasons
    )
    dynsym_count = 0
    symbol_matches: set[SymbolMatch] = set()
    # Hoisted: the supplementary `.symtab` pass below cross-checks against every
    # string table in the object, and `.dynstr` is one of them. A crypto name in it
    # that `.dynsym` resolved is a name this object accounted for, so the two reads
    # have to share one set or an imported name reads as unclaimed.
    dynsym_read_crypto: set[str] = set()
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
            read_crypto = dynsym_read_crypto
            unresolved = 0
            dynstr_section = _validated_strtab(elf, dynsym["sh_link"], dt_strtab_addr)
            table, dynstr, symtab_bytes_unread = _symbol_bytes(
                elf, dynsym, dynstr_section, max_strings_bytes
            )
            if symtab_bytes_unread:
                # `.dynsym` or its string table (or both) declares more bytes than
                # the object's own budget: refused before decompression for a
                # compressed section, or (#95) before the plain file read for an
                # ordinary one, either way by `_bounded_section_data`, so `table`
                # and/or `dynstr` may be empty rather than however many bytes were
                # declared. Named explicitly rather than left to fall out of
                # `unresolved` below: an object whose `.dynsym` itself was refused has
                # no rows to iterate at all, so `unresolved` would stay zero with
                # nothing else to say this object was not read.
                #
                # `unresolved` and `holds_a_name_not_read` below both ask an honest
                # question of a table assumed to be the real, complete one -- "did
                # every entry resolve" and "does the string table hold a name no
                # entry claimed" -- and a refused read answers neither honestly:
                # `.dynsym` refused on its own means `table` is empty, so no row
                # exists to leave `dynstr`'s names unclaimed, and a real `dynstr`
                # otherwise holding "SSL_new" would fabricate `symtab_understates_rows`
                # against an object whose count was never wrong, only unread; `.dynstr`
                # refused on its own means every entry in an otherwise-honest `table`
                # fails to resolve against an empty string table, which is not the same
                # fact `unresolved` exists to name (the object lying about `.dynstr`'s
                # own contents) even though it produces the identical count. Skipped
                # entirely instead, the same ordering `binfmt.macho`'s `_SymbolRead`
                # already gives `truncated` ahead of its own `unresolved`/understated
                # checks: `elf_dynsym_unread` is the whole, sufficient answer once a
                # read was refused, and it is already set here.
                errors.append(
                    _error(
                        path,
                        ELF_PARSE_ERROR,
                        ".dynsym or its string table declares more bytes than the budget allows",
                    )
                )
                reasons.add(evidence.PARTIAL_ELF_DYNSYM_UNREAD)
            else:
                for name, undefined, resolved, _symtype in _iter_symbols(elf, table, dynstr):
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
                # exactly what they declare is not reading what the object carries. The
                # same two checks `binfmt.macho` makes of `nsyms` and `strsize`, in the
                # same order: a string table we could not read through is reported as
                # that, and the cross-check over one is worth nothing.
                #
                # A crypto name in `.dynstr` that no entry we read resolved to is a
                # symbol this object has and did not declare. Absence of evidence is not
                # evidence of absence, and here the evidence is present and pointed away
                # from.
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

    if symtab is not None and dynsym is not None:
        # Supplementary mode: `.dynsym` is present, so imports and exports are already
        # read off it above, and what it cannot show is a *local* definition -- a
        # statically linked copy whose symbols a version script kept out of the dynamic
        # table. cryptography 50.0.1 is the worked example: 776 `EVP_*` definitions,
        # every one local in `.symtab`, none in `.dynsym`. Only definitions are taken:
        # a dynamically linked object must declare every import in `.dynsym` to link at
        # all, so `.symtab` adds nothing about imports, and a planted undefined entry
        # would fabricate a dependency the object does not have.
        #
        # Every row is visited, including on a table holding nothing this ruleset
        # claims. A prefilter over `.strtab` -- the `symbol_locator` scan `.dynsym`'s
        # own matcher mirrors -- was measured at 0.32s against 0.55s on a 26.7 MiB
        # object with half a million symbols, and rejected for what it cost rather than
        # for what it saved: a `.strtab` shrunk to hide a name is a `.strtab` the
        # prefilter then reads as holding nothing, so the walk that would have found
        # the rows pointing past it never ran and the object read clean. See
        # DECISIONS.md.
        try:
            symtab_read = _read_symtab(elf, symtab, max_strings_bytes)
            if symtab_read.bytes_unread:
                errors.append(
                    _error(
                        path,
                        ELF_PARSE_ERROR,
                        ".symtab or its string table declares more bytes than the budget allows",
                    )
                )
                reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)
            else:
                symtab_unresolved = 0
                # Every crypto name read, before any skip: a name dropped for being an
                # import or a pseudo-symbol was still read and accounted for, and the
                # cross-check below must not see it as one the object hid.
                symtab_read_crypto: set[str] = set()
                for name, undefined, resolved, symtype in _iter_symbols(
                    elf, symtab_read.table, symtab_read.strings
                ):
                    if not resolved:
                        # A row pointed at a name this reader could not read: an index
                        # past the end of `.strtab`, or into a run it never closes. An
                        # honest table never produces one, and a `.strtab` shrunk
                        # beside an intact `.symtab` is exactly how a definition hides
                        # while every count and every structural check survives. This
                        # is not the understated-rows cross-check below, which asks
                        # whether a *sole* table under-declared itself and does not run
                        # here; this one asks whether a name we were pointed at could
                        # be read, and that question is the same in both modes.
                        symtab_unresolved += 1
                        continue
                    groups = patterns.symbol_groups_for(name) if name else ()
                    if groups:
                        symtab_read_crypto.add(name)
                    if undefined:
                        continue
                    if symtype in (_STT_FILE, _STT_SECTION):
                        # A source-file or per-section pseudo-symbol, not code: a
                        # translation unit called `EVP_md5.c` must not match a group by
                        # coincidence of a filename with what it implements. A linked
                        # shared object carries one per translation unit, so this matters
                        # more here than in the relocatable objects it was written for.
                        continue
                    for group in groups:
                        symbol_matches.add(
                            SymbolMatch(name=name, group=group, binding=evidence.BINDING_DEFINED)
                        )
                if symtab_unresolved:
                    errors.append(
                        _error(path, ELF_PARSE_ERROR, ".symtab names strings .strtab does not hold")
                    )
                    reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)
                elif not (
                    evidence.PARTIAL_ELF_DYNSYM_UNREAD in reasons
                    or evidence.PARTIAL_ELF_DYNAMIC_UNREAD in reasons
                ) and _any_strtab_holds_a_name_not_read(
                    sections,
                    patterns,
                    dynsym_read_crypto | symtab_read_crypto,
                    max_strings_bytes,
                ):
                    # The one thing `unresolved` cannot see. Point `.symtab`'s `sh_link`
                    # at a decoy `SHT_STRTAB` of nothing but NULs and every row resolves
                    # -- to the empty name -- so the count stays zero while the real
                    # names sit unread in the table the decoy displaced. Checked across
                    # every `SHT_STRTAB` in the object, against the names *both* tables
                    # resolved, because `.dynstr` is one of them and a name `.dynsym`
                    # accounted for is not a name this object hid.
                    #
                    # Skipped when `.dynsym` or `.dynamic` was not read through: then
                    # `.dynstr`'s own names were never claimed by anything, and every
                    # one of them would read as unaccounted for here.
                    errors.append(
                        _error(
                            path,
                            ELF_PARSE_ERROR,
                            ".symtab declares fewer entries than .strtab holds names for",
                        )
                    )
                    reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)
                    reasons.add(evidence.PARTIAL_SYMTAB_UNDERSTATES_ROWS)
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read the symbol table"))
            reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)

    # The third state nothing else names: `dynsym is None` while `dynsym_absent` is
    # false -- an ambiguous `SHT_DYNSYM`, one forged away from its type, or a section
    # table that would not parse. The object's own section table cannot be trusted
    # about whether `.dynsym` exists, so neither branch runs and `.symtab` is not read
    # to stand in for a table whose existence could not be established (#117). Already
    # recorded as partial by whichever cause put it in that state.

    if dynsym_absent and symtab is not None:
        # Reached only for a relocatable object with no `.dynsym` at all -- see the
        # module docstring and #117.
        try:
            symtab_read_crypto: set[str] = set()
            symtab_unresolved = 0
            sole = _read_symtab(elf, symtab, max_strings_bytes)
            table, strtab, strtab_bytes_unread = sole.table, sole.strings, sole.bytes_unread
            if strtab_bytes_unread:
                errors.append(
                    _error(
                        path,
                        ELF_PARSE_ERROR,
                        ".symtab or its string table declares more bytes than the budget allows",
                    )
                )
                reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)
            else:
                for name, undefined, resolved, symtype in _iter_symbols(elf, table, strtab):
                    if not resolved:
                        symtab_unresolved += 1
                        continue
                    groups = patterns.symbol_groups_for(name) if name else ()
                    if not groups:
                        continue
                    # Read and accounted for either way, so the understated-rows
                    # cross-check below must not see this name as missed -- only
                    # skipped from evidence, by type, below.
                    symtab_read_crypto.add(name)
                    if symtype in (_STT_FILE, _STT_SECTION):
                        # A source-file or per-section pseudo-symbol, not code: naming
                        # one `EVP_md5.c` must not match a group by coincidence of a
                        # filename with what it happens to implement. `.dynsym` never
                        # carries these, so this has no counterpart above.
                        continue
                    binding = evidence.BINDING_IMPORTED if undefined else evidence.BINDING_DEFINED
                    for group in groups:
                        symbol_matches.add(SymbolMatch(name=name, group=group, binding=binding))
                if symtab_unresolved:
                    errors.append(
                        _error(path, ELF_PARSE_ERROR, ".symtab names strings .strtab does not hold")
                    )
                    reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)
                elif _any_strtab_holds_a_name_not_read(
                    sections, patterns, symtab_read_crypto, max_strings_bytes
                ):
                    errors.append(
                        _error(
                            path,
                            ELF_PARSE_ERROR,
                            ".symtab declares fewer entries than .strtab holds names for",
                        )
                    )
                    reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)
                    reasons.add(evidence.PARTIAL_SYMTAB_UNDERSTATES_ROWS)
        except Exception:
            errors.append(_error(path, ELF_PARSE_ERROR, "failed to read the symbol table"))
            reasons.add(evidence.PARTIAL_ELF_SYMTAB_UNREAD)

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
    # section refused before or during its own read with nothing recovered --
    # compressed or `SHT_NOBITS` over budget, or a genuine read failure -- which
    # records an error where this records none. An ordinary section over budget does
    # NOT reach that cause since #95: `keep_prefix` reads back its own real, honest
    # first bytes up to the budget instead of refusing outright, and that recovered
    # prefix lands here, as `strings_bytes_unread`, the same as any other section this
    # accumulation ran out of room for.
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
            # `keep_prefix=True`, the same as `.rodata`/`.comment` (#95): an ordinary,
            # uncompressed `.go.buildinfo` over budget still hands back its own real
            # first `max_strings_bytes` rather than nothing, and the Go version string
            # sits at a fixed offset near the front of the section (#95: `golang.py`'s
            # own 32-byte header plus a short length-prefixed string), so a prefix this
            # small still parses when the section itself is not.
            buildinfo_bytes, buildinfo_unread = _bounded_section_data(
                buildinfo_section, max_strings_bytes, keep_prefix=True
            )
        except Exception:
            buildinfo_unread = True
        if buildinfo_unread:
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
        # `keep_prefix=True`: an ordinary, uncompressed section over `remaining` still
        # hands back its own real, honest first `remaining` bytes rather than nothing
        # (#95) -- a plain `stream.read`, not a decompression guess -- while a
        # compressed or `SHT_NOBITS` one is still refused outright regardless of this
        # flag, per `_bounded_section_data`'s own docstring.
        try:
            data, section_unread = _bounded_section_data(section, remaining, keep_prefix=True)
        except Exception:
            # The one failure here that used to be silent: no error, no reason, and the
            # strings simply absent. A `.rodata` flagged `SHF_COMPRESSED` over bytes
            # that are not compressed reaches this, and a wheel whose only evidence was
            # the banner in it came back with no findings and nothing saying why.
            unread = True
            continue
        if section_unread:
            if data:
                # An ordinary section refused only for being over `remaining`:
                # `keep_prefix` reads back its own real, honest first `remaining`
                # bytes rather than nothing, exactly what this loop would have kept
                # anyway had the budget instead run out mid-accumulation across
                # several smaller sections. That is `truncated`, the same fact
                # `strings_bytes_unread` already names, not `unread`: the object told
                # the truth about its bytes, this reader simply had no room left for
                # all of them, and refusing the *read past the budget* is not a claim
                # that anything about the bytes already produced up to it was itself
                # unreadable.
                #
                # `truncated` says what was actually dropped, not what the section
                # declared (the same contract this function's own docstring states for
                # the `len(data) > remaining` branch below) -- a malformed `sh_size`
                # far past the object's real end can make `keep_prefix`'s bounded read
                # come back shorter than `remaining` with nothing left unread, and
                # `data_size > remaining` alone cannot tell that apart from a read that
                # genuinely filled the budget with more bytes still beyond it.
                buf.extend(data)
                truncated = len(data) >= remaining
                continue
            # A compressed or `SHT_NOBITS` section refused with nothing recovered:
            # unlike the ordinary case above, `ch_size` alone cannot tell an honestly
            # oversized declaration apart from a malformed header that happens to
            # decode to a huge number (see DECISIONS.md, "A compressed section is
            # checked before it is inflated" -- the existing "elf section data
            # unreadable" fixture in `tests/test_partial_reasons.py` is exactly that
            # shape), so this is a stronger claim than budget alone explains and stays
            # `unread`.
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
