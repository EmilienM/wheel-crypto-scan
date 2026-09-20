"""Deterministic, dependency-free ELF writers for `binfmt.elf` tests.

Program headers, relocations and a real entry point are left out because nothing under
test looks at them. See `helpers.binfmt` for why these are real objects, not stubs.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace

# --- ELF constants (only the ones this builder emits or the reader consumes) -------

ET_REL = 1
ET_EXEC = 2
ET_DYN = 3

EM_X86_64 = 62
EM_386 = 3
EM_S390 = 22

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_DYNSYM = 11

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29

STB_GLOBAL = 1
STT_FUNC = 2

SHN_UNDEF = 0
_SHN_DEFINED_PLACEHOLDER = 1  # any non-reserved, non-zero section index

_EHDR_SIZE = {32: 52, 64: 64}
_SHDR_SIZE = {32: 40, 64: 64}
_SYM_SIZE = {32: 16, 64: 24}
_DYN_SIZE = {32: 8, 64: 16}

# Byte offset of `e_shnum` within the ELF header, for tests that corrupt the section
# count directly rather than through the builder's own (necessarily well-formed) API.
E_SHNUM_OFFSET = {32: 48, 64: 60}


class _StrTab:
    """An ELF string table under construction: interns strings, remembers offsets."""

    def __init__(self) -> None:
        self._buf = bytearray(b"\x00")
        self._offsets: dict[str, int] = {}

    def add(self, text: str) -> int:
        if text not in self._offsets:
            self._offsets[text] = len(self._buf)
            self._buf.extend(text.encode("ascii") + b"\x00")
        return self._offsets[text]

    @property
    def data(self) -> bytes:
        return bytes(self._buf)


@dataclass(frozen=True)
class DynSym:
    """One `.dynsym` (or `.symtab`) entry: a name and whether it is defined here."""

    name: str
    defined: bool
    value: int = 0
    size: int = 0
    info: int = (STB_GLOBAL << 4) | STT_FUNC


@dataclass(frozen=True)
class _Section:
    name: str
    sh_type: int
    flags: int
    data: bytes
    link: int = 0
    info: int = 0
    addralign: int = 1
    entsize: int = 0


@dataclass
class ElfBuilder:
    """Assembles a minimal, well-formed ELF object.

    Pass only what a given test cares about; everything else defaults to "absent",
    which is itself a case the reader has to survive (no `.dynamic`, no `.dynsym`, no
    `.symtab`).
    """

    elfclass: int = 64
    big_endian: bool = False
    machine: int = EM_X86_64
    e_type: int = ET_DYN
    needed: tuple[str, ...] = ()
    soname: str | None = None
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()
    dynsyms: tuple[DynSym, ...] = ()
    rodata: bytes = b""
    text: bytes = b""
    comment: bytes | None = None
    go_buildinfo: bytes | None = None
    go_buildid_note: bool = False
    with_symtab: bool = False
    symtab_syms: tuple[DynSym, ...] | None = None
    include_dynamic: bool = True
    # Points `.dynamic`'s sh_link at a nonexistent section, simulating a dynamic
    # section whose string table cannot be resolved.
    dynamic_strtab_broken: bool = False

    def __post_init__(self) -> None:
        self._end = ">" if self.big_endian else "<"

    # -- struct helpers, sized to elfclass ------------------------------------

    def _pack_ehdr(self, shoff: int, shstrndx: int, shnum: int) -> bytes:
        end = self._end
        ei_class = 2 if self.elfclass == 64 else 1
        ei_data = 2 if self.big_endian else 1
        e_ident = bytes([0x7F, 0x45, 0x4C, 0x46, ei_class, ei_data, 1, 0]) + b"\x00" * 8
        ehsize = _EHDR_SIZE[self.elfclass]
        shentsize = _SHDR_SIZE[self.elfclass]
        if self.elfclass == 64:
            rest = struct.pack(
                end + "HHIQQQIHHHHHH",
                self.e_type,
                self.machine,
                1,
                0,
                0,
                shoff,
                0,
                ehsize,
                0,
                0,
                shentsize,
                shnum,
                shstrndx,
            )
        else:
            rest = struct.pack(
                end + "HHIIIIIHHHHHH",
                self.e_type,
                self.machine,
                1,
                0,
                0,
                shoff,
                0,
                ehsize,
                0,
                0,
                shentsize,
                shnum,
                shstrndx,
            )
        return e_ident + rest

    def _pack_shdr(
        self,
        name: int,
        sh_type: int,
        flags: int,
        offset: int,
        size: int,
        link: int,
        info: int,
        addralign: int,
        entsize: int,
    ) -> bytes:
        end = self._end
        if self.elfclass == 64:
            return struct.pack(
                end + "IIQQQQIIQQ",
                name,
                sh_type,
                flags,
                0,
                offset,
                size,
                link,
                info,
                addralign,
                entsize,
            )
        return struct.pack(
            end + "IIIIIIIIII",
            name,
            sh_type,
            flags,
            0,
            offset,
            size,
            link,
            info,
            addralign,
            entsize,
        )

    def _pack_sym(
        self, name: int, info: int, other: int, shndx: int, value: int, size: int
    ) -> bytes:
        end = self._end
        if self.elfclass == 64:
            return struct.pack(end + "IBBHQQ", name, info, other, shndx, value, size)
        return struct.pack(end + "IIIBBH", name, value, size, info, other, shndx)

    def _pack_dyn(self, tag: int, val: int) -> bytes:
        end = self._end
        if self.elfclass == 64:
            return struct.pack(end + "QQ", tag, val)
        return struct.pack(end + "II", tag, val)

    # -- assembly ---------------------------------------------------------------

    def build(self) -> bytes:
        sections: list[_Section] = [_Section("", SHT_NULL, 0, b"")]

        wants_dynamic_strings = bool(
            self.needed or self.soname is not None or self.rpath or self.runpath
        )
        has_dynamic = self.include_dynamic and (wants_dynamic_strings or self.dynsyms)
        needs_dynstr = has_dynamic or bool(self.dynsyms)

        dynstr_index: int | None = None
        dynsym_index: int | None = None
        dynamic_index: int | None = None

        if needs_dynstr:
            dynstr_index = len(sections)
            sections.append(_Section(".dynstr", SHT_STRTAB, SHF_ALLOC, b"", addralign=1))

        if self.dynsyms:
            dynsym_index = len(sections)
            sections.append(
                _Section(
                    ".dynsym",
                    SHT_DYNSYM,
                    SHF_ALLOC,
                    b"",
                    info=1,
                    addralign=8 if self.elfclass == 64 else 4,
                    entsize=_SYM_SIZE[self.elfclass],
                )
            )

        if has_dynamic:
            dynamic_index = len(sections)
            sections.append(
                _Section(
                    ".dynamic",
                    SHT_DYNAMIC,
                    SHF_ALLOC | SHF_WRITE,
                    b"",
                    addralign=8 if self.elfclass == 64 else 4,
                    entsize=_DYN_SIZE[self.elfclass],
                )
            )

        if self.rodata:
            sections.append(_Section(".rodata", SHT_PROGBITS, SHF_ALLOC, self.rodata, addralign=1))

        if self.text:
            sections.append(
                _Section(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, self.text, addralign=16)
            )

        if self.comment is not None:
            sections.append(_Section(".comment", SHT_PROGBITS, 0, self.comment, addralign=1))

        if self.go_buildinfo is not None:
            sections.append(
                _Section(".go.buildinfo", SHT_PROGBITS, SHF_ALLOC, self.go_buildinfo, addralign=8)
            )

        if self.go_buildid_note:
            sections.append(
                _Section(".note.go.buildid", SHT_NOTE, SHF_ALLOC, b"\x00" * 4, addralign=4)
            )

        strtab_index: int | None = None
        symtab_index: int | None = None
        if self.with_symtab:
            strtab_index = len(sections)
            sections.append(_Section(".strtab", SHT_STRTAB, 0, b"", addralign=1))
            symtab_index = len(sections)
            sections.append(
                _Section(
                    ".symtab",
                    SHT_SYMTAB,
                    0,
                    b"",
                    info=1,
                    addralign=8 if self.elfclass == 64 else 4,
                    entsize=_SYM_SIZE[self.elfclass],
                )
            )

        shstrtab_index = len(sections)
        sections.append(_Section(".shstrtab", SHT_STRTAB, 0, b"", addralign=1))

        # -- fill in real data for the sections declared above --------------

        if dynstr_index is not None:
            dynstr = _StrTab()
            needed_offsets = [dynstr.add(name) for name in self.needed]
            soname_offset = dynstr.add(self.soname) if self.soname is not None else None
            rpath_offsets = [dynstr.add(path) for path in self.rpath]
            runpath_offsets = [dynstr.add(path) for path in self.runpath]
            dynsym_name_offsets = [dynstr.add(sym.name) if sym.name else 0 for sym in self.dynsyms]
            sections[dynstr_index] = replace(sections[dynstr_index], data=dynstr.data)
        else:
            needed_offsets = []
            soname_offset = None
            rpath_offsets = []
            runpath_offsets = []
            dynsym_name_offsets = []

        if dynsym_index is not None:
            symdata = bytearray(self._pack_sym(0, 0, 0, 0, 0, 0))
            for sym, name_off in zip(self.dynsyms, dynsym_name_offsets, strict=True):
                shndx = SHN_UNDEF if not sym.defined else _SHN_DEFINED_PLACEHOLDER
                symdata += self._pack_sym(name_off, sym.info, 0, shndx, sym.value, sym.size)
            sections[dynsym_index] = replace(
                sections[dynsym_index], data=bytes(symdata), link=dynstr_index or 0
            )

        if dynamic_index is not None:
            dyndata = bytearray()
            for off in needed_offsets:
                dyndata += self._pack_dyn(DT_NEEDED, off)
            if soname_offset is not None:
                dyndata += self._pack_dyn(DT_SONAME, soname_offset)
            for off in rpath_offsets:
                dyndata += self._pack_dyn(DT_RPATH, off)
            for off in runpath_offsets:
                dyndata += self._pack_dyn(DT_RUNPATH, off)
            if dynsym_index is not None:
                dyndata += self._pack_dyn(DT_SYMTAB, 0)
                dyndata += self._pack_dyn(DT_SYMENT, _SYM_SIZE[self.elfclass])
            dyndata += self._pack_dyn(DT_STRTAB, 0)
            dyndata += self._pack_dyn(DT_STRSZ, len(dynstr.data) if dynstr_index is not None else 0)
            dyndata += self._pack_dyn(DT_NULL, 0)
            link = 0xFFF if self.dynamic_strtab_broken else (dynstr_index or 0)
            sections[dynamic_index] = replace(
                sections[dynamic_index], data=bytes(dyndata), link=link
            )

        if self.with_symtab:
            symtab_syms = self.symtab_syms if self.symtab_syms is not None else self.dynsyms
            strtab = _StrTab()
            name_offs = [strtab.add(sym.name) if sym.name else 0 for sym in symtab_syms]
            symdata = bytearray(self._pack_sym(0, 0, 0, 0, 0, 0))
            for sym, name_off in zip(symtab_syms, name_offs, strict=True):
                shndx = SHN_UNDEF if not sym.defined else _SHN_DEFINED_PLACEHOLDER
                symdata += self._pack_sym(name_off, sym.info, 0, shndx, sym.value, sym.size)
            assert strtab_index is not None
            assert symtab_index is not None
            sections[strtab_index] = replace(sections[strtab_index], data=strtab.data)
            sections[symtab_index] = replace(
                sections[symtab_index], data=bytes(symdata), link=strtab_index
            )

        shstrtab = _StrTab()
        name_offsets = [shstrtab.add(sec.name) for sec in sections]
        sections[shstrtab_index] = replace(sections[shstrtab_index], data=shstrtab.data)

        # -- lay out the file: header, section data, section header table ---

        ehdr_size = _EHDR_SIZE[self.elfclass]
        blob = bytearray()
        section_offsets: list[int] = []
        for sec in sections:
            if sec.sh_type == SHT_NULL:
                section_offsets.append(0)
                continue
            align = sec.addralign or 1
            pad = (-len(blob)) % align
            blob.extend(b"\x00" * pad)
            section_offsets.append(ehdr_size + len(blob))
            blob.extend(sec.data)

        shoff = ehdr_size + len(blob)
        shdrs = bytearray()
        for sec, name_off, sec_offset in zip(sections, name_offsets, section_offsets, strict=True):
            shdrs.extend(
                self._pack_shdr(
                    name_off,
                    sec.sh_type,
                    sec.flags,
                    sec_offset,
                    len(sec.data),
                    sec.link,
                    sec.info,
                    sec.addralign,
                    sec.entsize,
                )
            )

        ehdr = self._pack_ehdr(shoff, shstrtab_index, len(sections))
        return bytes(ehdr) + bytes(blob) + bytes(shdrs)


def patch_u16(data: bytes, offset: int, value: int, *, big_endian: bool = False) -> bytes:
    """Overwrite a 2-byte field in an already-built object, for corruption tests."""
    end = ">" if big_endian else "<"
    buf = bytearray(data)
    buf[offset : offset + 2] = struct.pack(end + "H", value)
    return bytes(buf)


# Section header fields a test can rewrite after the fact, by byte offset within the
# header. Only the ones a fixture has a reason to lie about.
_SH_FIELDS = {
    "sh_type": (0x04, "<I"),
    "sh_flags": (0x08, "<Q"),
    "sh_addr": (0x10, "<Q"),
    "sh_offset": (0x18, "<Q"),
    "sh_size": (0x20, "<Q"),
    "sh_link": (0x28, "<I"),
}

SHF_COMPRESSED = 0x800


def patch_section_header(
    data: bytes, name: str, field: str, value: int, *, bitwise_or: bool = False, occurrence: int = 1
):
    """Rewrite one field of one named section header in a built 64-bit ELF.

    The builder only emits well-formed objects, which is the point of it. A test that
    needs a section whose bytes cannot be read has to corrupt one afterwards, and doing
    that by name rather than by offset keeps the test readable.

    `occurrence` is 1-based and picks which section to patch when more than one shares
    `name` -- `insert_bogus_section_before(..., same_name=True)` is the fixture that
    creates that shape, and the decoy it inserts always sorts before the real section,
    so `occurrence=2` reaches the real one.
    """
    buf = bytearray(data)
    (shoff,) = struct.unpack_from("<Q", buf, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", buf, 0x3A)
    (names_at,) = struct.unpack_from("<Q", buf, shoff + shstrndx * shentsize + 0x18)
    offset, fmt = _SH_FIELDS[field]
    seen = 0
    for index in range(shnum):
        header = shoff + index * shentsize
        (name_offset,) = struct.unpack_from("<I", buf, header)
        end = buf.index(b"\x00", names_at + name_offset)
        if bytes(buf[names_at + name_offset : end]).decode() != name:
            continue
        seen += 1
        if seen != occurrence:
            continue
        (current,) = struct.unpack_from(fmt, buf, header + offset)
        struct.pack_into(fmt, buf, header + offset, current | value if bitwise_or else value)
        return bytes(buf)
    raise AssertionError(f"no section named {name} (occurrence {occurrence})")


def patch_header_field(data: bytes, field: str, value: int) -> bytes:
    """Rewrite one field of the ELF header itself."""
    offset, fmt = {"e_shoff": (0x28, "<Q"), "e_shnum": (0x3C, "<H")}[field]
    buf = bytearray(data)
    struct.pack_into(fmt, buf, offset, value)
    return bytes(buf)


def insert_bogus_section_before(
    data: bytes, name: str, sh_type: int, *, same_name: bool = False
) -> bytes:
    """Insert a second, empty section of `sh_type` immediately before the one named `name`.

    Unlike appending at the end of the table, this splices a decoy in *ahead* of the
    real section in section order -- the shape a lookup that picks "the first match"
    would get wrong, and the one `append_duplicate_dynsym_section` cannot reach.  Every
    `sh_link` and `e_shstrndx` naming an index at or past the insertion point is bumped
    by one first, so every other cross-reference in the file still points at the
    section it used to: real toolchains never emit two sections of the same type, but a
    hand-crafted object that does is not otherwise malformed, and this fixture should
    not be either. `sh_link` points at `.shstrtab` (post-bump), always a valid
    `SHT_STRTAB`, so the decoy is harmless if it is read by mistake. Only defined for a
    built 64-bit ELF, like `patch_section_header`.

    `same_name` reuses `name`'s own `sh_name` offset for the decoy too, so the object
    ends up with two sections literally called `.dynsym` (or whichever name), rather
    than one named that and one named the empty string. This is the shape a name-based
    lookup's "first match wins" gets wrong the same way a type-based one did: a
    same-*named* decoy sorting first hides a same-named real section behind it just as
    effectively as a same-*typed* one hides a real section of that type.
    """
    buf = bytearray(data)
    (shoff,) = struct.unpack_from("<Q", buf, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", buf, 0x3A)
    (names_at,) = struct.unpack_from("<Q", buf, shoff + shstrndx * shentsize + 0x18)
    target_index = None
    target_name_offset = 0
    for index in range(shnum):
        header = shoff + index * shentsize
        (name_offset,) = struct.unpack_from("<I", buf, header)
        end = buf.index(b"\x00", names_at + name_offset)
        if bytes(buf[names_at + name_offset : end]).decode() == name:
            target_index = index
            target_name_offset = name_offset
            break
    if target_index is None:
        raise AssertionError(f"no section named {name}")

    # Bump every sh_link naming an index at or past the insertion point, read while
    # indices are still in their pre-insertion numbering: two sections that shift
    # together keep referring to each other correctly with no further adjustment.
    for index in range(shnum):
        header = shoff + index * shentsize
        (link,) = struct.unpack_from("<I", buf, header + 40)
        if link >= target_index:
            struct.pack_into("<I", buf, header + 40, link + 1)
    new_shstrndx = shstrndx + 1 if shstrndx >= target_index else shstrndx

    bogus = struct.pack(
        "<IIQQQQIIQQ",
        target_name_offset if same_name else 0,  # offset 0 is always the empty string
        sh_type,
        0,  # sh_flags
        0,  # sh_addr
        0,  # sh_offset
        0,  # sh_size: zero entries
        new_shstrndx,  # sh_link: .shstrtab, always a valid SHT_STRTAB
        0,  # sh_info
        8,  # sh_addralign
        _SYM_SIZE[64],  # sh_entsize: nonzero, so num_symbols() cannot divide by zero
    )
    insert_at = shoff + target_index * shentsize
    buf[insert_at:insert_at] = bogus
    struct.pack_into("<H", buf, 0x3C, shnum + 1)
    struct.pack_into("<H", buf, 0x3E, new_shstrndx)
    return bytes(buf)


def append_strtab_decoy(data: bytes, content: bytes, *, sh_addr: int = 0x1000) -> tuple[bytes, int]:
    """Append a new `SHT_STRTAB` section holding `content`, and return its index.

    `ElfBuilder` writes every section's `sh_addr`, and `DT_STRTAB`'s own `d_ptr`, as
    0, so `sh_addr` defaults away from that: a decoy has to be pointed at deliberately
    (`patch_section_header(..., "sh_link", index)` on the section under test) to be
    read at all, and this default alone is enough to fail the corroboration check
    #56 round 4 added, which only trusts a same-address `SHT_STRTAB`.

    `content` is inserted as raw bytes just ahead of the section header table, which
    only pushes the table itself later in the file -- no existing section's own
    `sh_offset` is before that point, so nothing else needs to move -- and the new
    section is appended as the last header, the same append-only shape
    `append_duplicate_dynsym_section` already uses.
    """
    buf = bytearray(data)
    (shoff,) = struct.unpack_from("<Q", buf, 0x28)
    shentsize, shnum, _shstrndx = struct.unpack_from("<HHH", buf, 0x3A)
    new_index = shnum
    header = struct.pack(
        "<IIQQQQIIQQ",
        0,  # sh_name: offset 0 is always the empty string
        SHT_STRTAB,
        0,  # sh_flags
        sh_addr,
        shoff,  # sh_offset: right where `content` is about to be inserted
        len(content),
        0,  # sh_link
        0,  # sh_info
        1,  # sh_addralign
        0,  # sh_entsize
    )
    buf[shoff:shoff] = content
    new_shoff = shoff + len(content)
    insert_at = new_shoff + shnum * shentsize
    buf[insert_at:insert_at] = header
    struct.pack_into("<Q", buf, 0x28, new_shoff)
    struct.pack_into("<H", buf, 0x3C, shnum + 1)
    return bytes(buf), new_index


def append_duplicate_dynsym_section(data: bytes) -> bytes:
    """Append a second, empty `SHT_DYNSYM` section header after every other one.

    Two sections sharing a type is unusual but not forbidden, and a lookup keyed on
    `sh_type` has to pick one deterministically rather than raise. This second one is
    harmless if it were picked by mistake instead of the real `.dynsym` -- zero
    entries, and `sh_link` points at `.shstrtab`, which is always a valid `SHT_STRTAB`
    -- so a test can tell which section actually won without either choice raising.
    Appending after the existing table, rather than splicing it in, needs no `sh_link`
    or `e_shstrndx` of any other header to shift. Only defined for a built 64-bit ELF,
    like `patch_section_header`.
    """
    buf = bytearray(data)
    (shoff,) = struct.unpack_from("<Q", buf, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", buf, 0x3A)
    header = struct.pack(
        "<IIQQQQIIQQ",
        0,  # sh_name: offset 0 is always the empty string
        SHT_DYNSYM,
        0,  # sh_flags
        0,  # sh_addr
        0,  # sh_offset
        0,  # sh_size: zero entries
        shstrndx,  # sh_link: .shstrtab, always a valid SHT_STRTAB
        0,  # sh_info
        8,  # sh_addralign
        _SYM_SIZE[64],  # sh_entsize: nonzero, so num_symbols() cannot divide by zero
    )
    insert_at = shoff + shnum * shentsize
    buf[insert_at:insert_at] = header
    struct.pack_into("<H", buf, 0x3C, shnum + 1)
    return bytes(buf)
