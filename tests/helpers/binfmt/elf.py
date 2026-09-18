"""Deterministic, dependency-free ELF writers for `binfmt.elf` tests.

Program headers, relocations and a real entry point are left out because nothing under
test looks at them. See `helpers.binfmt` for why these are real objects, not stubs.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace

# --- ELF constants (only the ones this builder emits or the reader consumes) -------

ET_DYN = 3
ET_EXEC = 2

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
