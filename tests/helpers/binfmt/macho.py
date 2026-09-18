from __future__ import annotations

import struct
from dataclasses import dataclass



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


# --- PE -----------------------------------------------------------------------
