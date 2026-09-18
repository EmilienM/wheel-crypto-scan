"""Deterministic, dependency-free ELF and Mach-O writers for binfmt tests.

`binfmt.elf` and `binfmt.macho` are read against real object file formats, so the
fixtures that exercise them have to be real (if minimal) object files, not stubs. This
module builds them byte-for-byte with `struct`: no compiler, no network access, and
nothing committed as a binary blob. Every field the readers look at can be pinned
exactly, which is the point: a test can assert that a specific `DT_NEEDED` entry or a
specific symbol's binding comes back unchanged.

Only what `binfmt` reads is modelled. Program headers, relocations and a real entry
point are left out because nothing under test looks at them.
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


# --- Mach-O -------------------------------------------------------------------

MH_MAGIC_32 = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE

LC_SYMTAB = 0x02
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_RPATH = 0x8000001C

SYMTAB_COMMAND_SIZE = 24

N_UNDF = 0x00
N_SECT = 0x0E
N_EXT = 0x01
N_SO = 0x64  # a stabs source-file entry, i.e. debug information rather than a symbol

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_X86 = 7


@dataclass(frozen=True)
class MachOSym:
    """One `LC_SYMTAB` entry: a name, whether this object defines it, and its kind.

    `name` is written to the string table verbatim, so Darwin's leading underscore is
    the test's to supply: a real object spells the C function `EVP_DigestInit_ex` as
    `_EVP_DigestInit_ex`, and a fixture that left that out would not be one. It is
    encoded with `surrogateescape`, so a lone surrogate is a way to plant a byte that
    is not valid UTF-8 in the table.

    `stab` emits the entry as debug information, which a reader must skip rather than
    read as a definition.

    `strx` overwrites the entry's string-table index without touching the string table
    itself, which is how a test writes an object whose symbols are all still there but
    name nothing readable: 0 is nlist's "this entry has no name", and an index past the
    end of the table resolves to nothing at all.
    """

    name: str
    defined: bool
    stab: bool = False
    strx: int | None = None


@dataclass
class MachOBuilder:
    """Assembles a minimal Mach-O object: a header, load commands and a symbol table.

    No segments or sections are modelled (the reader under test does not look for
    them), so the object is not loadable, only parseable.

    The four `declared_*` fields overwrite what `LC_SYMTAB` claims about itself without
    changing the tables that were actually written, which is how a test says "this
    object lies about its own size".
    """

    is64: bool = True
    big_endian: bool = False
    cputype: int = CPU_TYPE_X86_64
    cpusubtype: int = 0x80000003
    filetype: int = 6  # MH_DYLIB
    id_dylib: str | None = None
    load_dylibs: tuple[str, ...] = ()
    rpaths: tuple[str, ...] = ()
    symbols: tuple[MachOSym, ...] = ()
    with_symtab: bool = False
    declared_symoff: int | None = None
    declared_nsyms: int | None = None
    declared_stroff: int | None = None
    declared_strsize: int | None = None
    trailing: bytes = b""

    def build(self) -> bytes:
        end = ">" if self.big_endian else "<"
        commands = bytearray()
        ncmds = 0
        if self.id_dylib is not None:
            commands += self._dylib_command(LC_ID_DYLIB, self.id_dylib, end)
            ncmds += 1
        for name in self.load_dylibs:
            commands += self._dylib_command(LC_LOAD_DYLIB, name, end)
            ncmds += 1
        for path in self.rpaths:
            commands += self._rpath_command(path, end)
            ncmds += 1

        has_symtab = self.with_symtab or bool(self.symbols)
        symtab_command_at = len(commands)
        if has_symtab:
            # Reserved now, filled in once the offsets it has to name are known.
            commands += b"\x00" * SYMTAB_COMMAND_SIZE
            ncmds += 1

        sizeofcmds = len(commands)
        magic = MH_MAGIC_64 if self.is64 else MH_MAGIC_32
        if self.is64:
            header = struct.pack(
                end + "IIIIIIII",
                magic,
                self.cputype,
                self.cpusubtype,
                self.filetype,
                ncmds,
                sizeofcmds,
                0,
                0,
            )
        else:
            header = struct.pack(
                end + "IIIIIII",
                magic,
                self.cputype,
                self.cpusubtype,
                self.filetype,
                ncmds,
                sizeofcmds,
                0,
            )

        body = bytearray(header) + commands + self.trailing
        if not has_symtab:
            return bytes(body)

        table, strtab = self._symbol_tables(end)
        # Offsets are relative to the start of this object, which for a slice of a fat
        # binary is not the start of the file.
        symoff = len(body)
        stroff = symoff + len(table)
        command = struct.pack(
            end + "IIIIII",
            LC_SYMTAB,
            SYMTAB_COMMAND_SIZE,
            symoff if self.declared_symoff is None else self.declared_symoff,
            len(self.symbols) if self.declared_nsyms is None else self.declared_nsyms,
            stroff if self.declared_stroff is None else self.declared_stroff,
            len(strtab) if self.declared_strsize is None else self.declared_strsize,
        )
        at = len(header) + symtab_command_at
        body[at : at + SYMTAB_COMMAND_SIZE] = command
        return bytes(body) + table + strtab

    def _symbol_tables(self, end: str) -> tuple[bytes, bytes]:
        """Pack the nlist array and the string table it indexes into."""
        strtab = bytearray(b"\x00")  # index 0 means "no name", so it is never a symbol's
        offsets = []
        for sym in self.symbols:
            offsets.append(len(strtab))
            strtab.extend(sym.name.encode("utf-8", "surrogateescape") + b"\x00")

        table = bytearray()
        for sym, offset in zip(self.symbols, offsets, strict=True):
            if sym.stab:
                n_type, n_sect = N_SO, 1
            elif sym.defined:
                n_type, n_sect = N_SECT | N_EXT, 1
            else:
                n_type, n_sect = N_UNDF | N_EXT, 0
            layout = "IBBHQ" if self.is64 else "IBBHI"
            n_strx = offset if sym.strx is None else sym.strx
            table += struct.pack(end + layout, n_strx, n_type, n_sect, 0, 0)
        return bytes(table), bytes(strtab)

    def table_offsets(self) -> tuple[int, int]:
        """Where `build()` really puts the nlist table and the string table.

        A test that makes `LC_SYMTAB` lie about one offset has to know the truth first:
        pointing `stroff` at the nlist table is only an overlap if that is where the
        nlist table actually is.
        """
        data = self.build()
        table, strtab = self._symbol_tables(">" if self.big_endian else "<")
        return len(data) - len(table) - len(strtab), len(data) - len(strtab)

    @staticmethod
    def _pad4(data: bytes) -> bytes:
        pad = (-len(data)) % 4
        return data + b"\x00" * pad

    def _dylib_command(self, cmd: int, name: str, end: str) -> bytes:
        name_bytes = self._pad4(name.encode("ascii") + b"\x00")
        header_len = 24
        cmdsize = header_len + len(name_bytes)
        return struct.pack(end + "IIIIII", cmd, cmdsize, header_len, 0, 0, 0) + name_bytes

    def _rpath_command(self, path: str, end: str) -> bytes:
        path_bytes = self._pad4(path.encode("ascii") + b"\x00")
        header_len = 12
        cmdsize = header_len + len(path_bytes)
        return struct.pack(end + "III", LC_RPATH, cmdsize, header_len) + path_bytes


def build_fat(slices: list[bytes], *, cputypes: list[int] | None = None) -> bytes:
    """Wrap thin Mach-O slices in a fat (universal) header, in the given order."""
    cputypes = cputypes if cputypes is not None else [CPU_TYPE_X86_64] * len(slices)
    header = struct.pack(">II", FAT_MAGIC, len(slices))
    arch_table = bytearray()
    offset = len(header) + 20 * len(slices)
    body = bytearray()
    for cputype, part in zip(cputypes, slices, strict=True):
        pad = (-len(body)) % 8
        body.extend(b"\x00" * pad)
        slice_offset = offset + len(body)
        arch_table.extend(struct.pack(">iiIII", cputype, 0, slice_offset, len(part), 3))
        body.extend(part)
    return bytes(header) + bytes(arch_table) + bytes(body)


__all__ = [
    "DynSym",
    "ElfBuilder",
    "MachOBuilder",
    "MachOSym",
    "build_fat",
    "patch_u16",
    "E_SHNUM_OFFSET",
    "EM_X86_64",
    "EM_386",
    "EM_S390",
    "ET_DYN",
    "ET_EXEC",
]
