"""Deterministic, dependency-free PE writers for `binfmt.pe` tests.

Only the header chain and the directories `binfmt.pe` walks are emitted: the DOS stub,
the COFF and optional headers, the section table, and the import and export directories.
No relocations, no resources, no COFF symbol table. See `helpers.binfmt` for why these
are real objects, not stubs.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

PE32_MAGIC = 0x10B
PE32PLUS_MAGIC = 0x20B

DOS_HEADER_SIZE = 0x40
PE_SIGNATURE = b"PE\x00\x00"
COFF_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40
IMPORT_DESCRIPTOR_SIZE = 20
EXPORT_DIRECTORY_SIZE = 40
DATA_DIRECTORY_COUNT = 16
EXPORT_DIRECTORY_INDEX = 0
IMPORT_DIRECTORY_INDEX = 1
DELAY_IMPORT_DIRECTORY_INDEX = 13

_FILE_ALIGNMENT = 0x200
_SECTION_ALIGNMENT = 0x1000
# Where the optional header's data directories start, and how long the header is, by
# magic. PE32+ drops BaseOfData and widens four fields, which moves everything after it.
_DIRECTORY_TABLE_OFFSET = {PE32_MAGIC: 96, PE32PLUS_MAGIC: 112}


@dataclass(frozen=True)
class PEImport:
    """One imported DLL: the functions taken from it by name, and by ordinal.

    An ordinal import carries no name anywhere in the file, which is the whole point of
    having it here: it is evidence the reader can count but can never read.
    """

    dll: str
    names: tuple[str, ...] = ()
    ordinals: tuple[int, ...] = ()


@dataclass(frozen=True)
class PEExport:
    """One named export. With `forwarder`, the name resolves to another DLL instead.

    A forwarded export's address points back inside the export directory, where it is
    the string in `forwarder` rather than code. The object names the symbol without
    defining it.
    """

    name: str
    forwarder: str | None = None


@dataclass(frozen=True)
class _PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    data: bytes


@dataclass
class PEBuilder:
    """Assembles a minimal PE image: DOS stub, header chain, sections, directories.

    Sections are laid out at a 0x1000 virtual alignment and a 0x200 file alignment, so
    every section maps its addresses onto the file by a different delta. That is
    deliberate: a reader that translated addresses with one global delta, or not at all,
    reads a neighbouring section's bytes and has to fail these fixtures.

    The `declared_*` fields overwrite what a header claims without moving what was
    actually written, which is how a test says "this object lies about itself". The
    remaining flags build objects that are malformed by construction rather than by a
    single edited field.
    """

    is64: bool = True
    machine: int = IMAGE_FILE_MACHINE_AMD64
    imports: tuple[PEImport, ...] = ()
    exports: tuple[PEExport, ...] = ()
    dll_name: str | None = None
    # Export address table slots no name points at: definitions with no name to read.
    unnamed_exports: int = 0
    text: bytes = b"\xcc" * 16
    # Extra sections between `.text` and `.rdata`, which move both the addresses and the
    # file offsets of everything after them.
    filler_sections: int = 0
    trailing: bytes = b""
    signature: bytes = PE_SIGNATURE
    declared_e_lfanew: int | None = None
    declared_section_count: int | None = None
    declared_optional_magic: int | None = None
    declared_import_rva: int | None = None
    declared_export_rva: int | None = None
    declared_export_size: int | None = None
    declared_name_count: int | None = None
    declared_function_count: int | None = None
    declared_name_pointer_rva: int | None = None
    # Applied to every imported DLL's name pointer, and to every hint/name pointer.
    declared_dll_name_rva: int | None = None
    declared_hint_name_rva: int | None = None
    declared_rdata_raw_size: int | None = None
    declared_rdata_raw_offset: int | None = None
    # A linker that leaves VirtualSize at zero means "as big as the raw data", which is
    # how an object file spells it.
    declared_rdata_virtual_size: int | None = None
    # A bound image: the lookup table is zeroed and the same entries are in the address
    # table, which is then the only place the imported names can be read from.
    bound_imports: bool = False
    # Every descriptor points its lookup table at one shared array of this many entries,
    # all naming the same function. Nothing in the format forbids it, and it is what
    # makes a per-DLL thunk cap multiply with the descriptor cap instead of bounding
    # anything. `names` and `ordinals` on the imports are not written in this shape.
    shared_thunk_entries: int = 0
    # Drop the all-zero descriptor that ends the import array.
    unterminated_imports: bool = False
    # A second section header mapping `.rdata`'s bytes at the address the import array's
    # terminator would occupy, so walking the array arrives back at its first descriptor.
    aliased_rdata_section: bool = False
    delay_import_directory: bool = False
    # The delay-load directory's Size. The loader never reads it, so a zero here must
    # not be taken to mean the object delay-loads nothing.
    declared_delay_import_size: int = 32
    # Put the forwarded export's address at the export directory's own first byte: the
    # inclusive lower bound of the range that tells a forwarder from a definition.
    forwarder_at_directory_start: bool = False
    truncate_to: int | None = None

    # -- addresses ------------------------------------------------------------

    def _section_names(self) -> list[str]:
        fillers = (f".pad{index}" for index in range(self.filler_sections))
        return [".text", *fillers, ".rdata", ".edata"]

    # -- section contents -----------------------------------------------------

    def _import_blob(self, base_rva: int) -> bytes:
        """The import descriptors, every lookup table, and every name they point at."""
        fmt = "<Q" if self.is64 else "<I"
        ordinal_flag = 1 << (63 if self.is64 else 31)
        terminator = 0 if self.unterminated_imports else 1
        head_size = IMPORT_DESCRIPTOR_SIZE * (len(self.imports) + terminator)

        tail = bytearray()

        def place(data: bytes) -> int:
            rva = base_rva + head_size + len(tail)
            tail.extend(data)
            return rva

        shared_rva = 0
        if self.shared_thunk_entries:
            hint_name = struct.pack("<H", 0) + b"EVP_DigestInit_ex\x00"
            repeated = struct.pack(fmt, place(hint_name))
            shared_rva = place(repeated * self.shared_thunk_entries + struct.pack(fmt, 0))

        descriptors = bytearray()
        for entry in self.imports:
            thunks = []
            for name in entry.names:
                hint_name = bytearray(struct.pack("<H", 0))
                hint_name += name.encode("utf-8", "surrogateescape") + b"\x00"
                if len(hint_name) % 2:
                    hint_name += b"\x00"
                placed = place(bytes(hint_name))
                if self.declared_hint_name_rva is not None:
                    placed = self.declared_hint_name_rva
                thunks.append(placed)
            for ordinal in entry.ordinals:
                thunks.append(ordinal_flag | (ordinal & 0xFFFF))
            table = b"".join(struct.pack(fmt, value) for value in thunks) + struct.pack(fmt, 0)
            lookup_rva = shared_rva or place(table)
            name_rva = place(entry.dll.encode("utf-8", "surrogateescape") + b"\x00")
            if self.declared_dll_name_rva is not None:
                name_rva = self.declared_dll_name_rva
            if self.bound_imports:
                descriptors += struct.pack("<IIIII", 0, 0, 0, name_rva, lookup_rva)
            else:
                descriptors += struct.pack("<IIIII", lookup_rva, 0, 0, name_rva, 0)
        if not self.unterminated_imports:
            descriptors += b"\x00" * IMPORT_DESCRIPTOR_SIZE
        return bytes(descriptors) + bytes(tail)

    def _export_blob(self, base_rva: int, code_rva: int) -> bytes:
        """The export directory, its three tables, and the strings they point at."""
        name_count = len(self.exports)
        function_count = name_count + self.unnamed_exports
        address_rva = base_rva + EXPORT_DIRECTORY_SIZE
        name_pointer_rva = address_rva + function_count * 4
        ordinal_rva = name_pointer_rva + name_count * 4
        strings_at = ordinal_rva + name_count * 2 - base_rva

        strings = bytearray()

        def place(data: bytes) -> int:
            rva = base_rva + strings_at + len(strings)
            strings.extend(data)
            return rva

        name_rvas = [
            place(export.name.encode("utf-8", "surrogateescape") + b"\x00")
            for export in self.exports
        ]
        addresses = []
        for export in self.exports:
            if export.forwarder is None:
                addresses.append(code_rva)
            elif self.forwarder_at_directory_start:
                addresses.append(base_rva)
            else:
                addresses.append(place(export.forwarder.encode("ascii") + b"\x00"))
        addresses.extend([code_rva] * self.unnamed_exports)
        dll_rva = (
            place(self.dll_name.encode("utf-8", "surrogateescape") + b"\x00")
            if self.dll_name is not None
            else 0
        )

        functions = (
            function_count if self.declared_function_count is None else self.declared_function_count
        )
        names = name_count if self.declared_name_count is None else self.declared_name_count
        name_pointers = (
            name_pointer_rva
            if self.declared_name_pointer_rva is None
            else self.declared_name_pointer_rva
        )
        header = struct.pack(
            "<IIHHIIIIIII",
            0,
            0,
            0,
            0,
            dll_rva,
            1,
            functions,
            names,
            address_rva,
            name_pointers,
            ordinal_rva,
        )
        body = b"".join(struct.pack("<I", value) for value in addresses)
        body += b"".join(struct.pack("<I", value) for value in name_rvas)
        body += b"".join(struct.pack("<H", index) for index in range(name_count))
        return header + body + bytes(strings)

    # -- assembly -------------------------------------------------------------

    def _sections(self) -> list[_PESection]:
        """Lay every section out, assigning its address before building its contents.

        Addresses and file offsets advance on different alignments, so each section maps
        onto the file by a delta of its own. A section is only ever built once its own
        address is known, because the import and export blobs are full of addresses that
        point back into themselves.
        """
        magic = PE32PLUS_MAGIC if self.is64 else PE32_MAGIC
        optional_size = _DIRECTORY_TABLE_OFFSET[magic] + DATA_DIRECTORY_COUNT * 8
        count = len(self._section_names()) + (1 if self.aliased_rdata_section else 0)
        headers_end = (
            DOS_HEADER_SIZE + 4 + COFF_HEADER_SIZE + optional_size + count * SECTION_HEADER_SIZE
        )
        wants_exports = bool(self.exports) or self.dll_name is not None or self.unnamed_exports

        raw_at = _align(headers_end, _FILE_ALIGNMENT)
        address = _SECTION_ALIGNMENT
        sections: list[_PESection] = []
        for name in self._section_names():
            if name == ".text":
                data = self.text or b"\x00" * 4
            elif name == ".rdata":
                data = self._import_blob(address) if self.imports else b"\x00" * 4
            elif name == ".edata":
                data = (
                    self._export_blob(address, sections[0].virtual_address)
                    if wants_exports
                    else b"\x00" * 4
                )
            else:
                data = b"\x00" * 0x40
            raw_size = _align(len(data), _FILE_ALIGNMENT)
            sections.append(
                _PESection(
                    name=name,
                    virtual_address=address,
                    virtual_size=len(data),
                    raw_offset=raw_at,
                    raw_size=raw_size,
                    data=data,
                )
            )
            raw_at += raw_size
            address = _align(address + len(data), _SECTION_ALIGNMENT)
        return sections

    def section_offsets(self) -> dict[str, int]:
        """Where `build()` really puts each section's raw data.

        A test that makes a section header lie about its `PointerToRawData` has to know
        the truth first, the same way the Mach-O builder exposes its table offsets.
        """
        return {section.name: section.raw_offset for section in self._sections()}

    def section_addresses(self) -> dict[str, int]:
        return {section.name: section.virtual_address for section in self._sections()}

    def section_sizes(self) -> dict[str, int]:
        """How many bytes of content each section really has, before alignment padding.

        A test that clips a section to just short of a name's NUL terminator has to know
        where the content ends; the padding that follows it is full of terminators.
        """
        return {section.name: len(section.data) for section in self._sections()}

    def build(self) -> bytes:
        sections = self._sections()
        by_name = {section.name: section for section in sections}
        rdata = by_name[".rdata"]
        edata = by_name[".edata"]

        headers = [
            replace(
                section,
                raw_offset=(
                    self.declared_rdata_raw_offset
                    if section.name == ".rdata" and self.declared_rdata_raw_offset is not None
                    else section.raw_offset
                ),
                raw_size=(
                    self.declared_rdata_raw_size
                    if section.name == ".rdata" and self.declared_rdata_raw_size is not None
                    else section.raw_size
                ),
                virtual_size=(
                    self.declared_rdata_virtual_size
                    if section.name == ".rdata" and self.declared_rdata_virtual_size is not None
                    else section.virtual_size
                ),
            )
            for section in sections
        ]
        if self.aliased_rdata_section:
            # One descriptor wide, at the address the import array's terminator would
            # occupy, mapping `.rdata`'s first descriptor. Ahead of `.rdata` in the
            # table, so it wins that address and nothing else does.
            alias = replace(
                rdata,
                name=".alias",
                virtual_address=rdata.virtual_address + IMPORT_DESCRIPTOR_SIZE * len(self.imports),
                virtual_size=IMPORT_DESCRIPTOR_SIZE,
            )
            headers.insert([h.name for h in headers].index(".rdata"), alias)

        magic = PE32PLUS_MAGIC if self.is64 else PE32_MAGIC
        table_offset = _DIRECTORY_TABLE_OFFSET[magic]
        optional_size = table_offset + DATA_DIRECTORY_COUNT * 8

        directories = [(0, 0)] * DATA_DIRECTORY_COUNT
        if self.imports:
            directories[IMPORT_DIRECTORY_INDEX] = (rdata.virtual_address, rdata.virtual_size)
        if self.declared_import_rva is not None:
            directories[IMPORT_DIRECTORY_INDEX] = (self.declared_import_rva, rdata.virtual_size)
        if self.exports or self.dll_name is not None or self.unnamed_exports:
            directories[EXPORT_DIRECTORY_INDEX] = (edata.virtual_address, edata.virtual_size)
        if self.declared_export_rva is not None:
            directories[EXPORT_DIRECTORY_INDEX] = (
                self.declared_export_rva,
                directories[EXPORT_DIRECTORY_INDEX][1],
            )
        if self.declared_export_size is not None:
            directories[EXPORT_DIRECTORY_INDEX] = (
                directories[EXPORT_DIRECTORY_INDEX][0],
                self.declared_export_size,
            )
        if self.delay_import_directory:
            directories[DELAY_IMPORT_DIRECTORY_INDEX] = (
                rdata.virtual_address,
                self.declared_delay_import_size,
            )

        optional = bytearray(b"\x00" * optional_size)
        struct.pack_into(
            "<H",
            optional,
            0,
            magic if self.declared_optional_magic is None else self.declared_optional_magic,
        )
        struct.pack_into("<I", optional, table_offset - 4, DATA_DIRECTORY_COUNT)
        for index, (rva, size) in enumerate(directories):
            struct.pack_into("<II", optional, table_offset + index * 8, rva, size)

        coff = struct.pack(
            "<HHIIIHH",
            self.machine,
            len(headers) if self.declared_section_count is None else self.declared_section_count,
            0,
            0,
            0,
            optional_size,
            0x2102,  # DLL, executable image, 32-bit-machine
        )

        table = bytearray()
        for section in headers:
            table += struct.pack(
                "<8sIIIIIIHHI",
                section.name.encode("ascii")[:8],
                section.virtual_size,
                section.virtual_address,
                section.raw_size,
                section.raw_offset,
                0,
                0,
                0,
                0,
                0x40000040,  # initialised data, readable
            )

        dos = bytearray(b"\x00" * DOS_HEADER_SIZE)
        dos[0:2] = b"MZ"
        e_lfanew = DOS_HEADER_SIZE if self.declared_e_lfanew is None else self.declared_e_lfanew
        struct.pack_into("<I", dos, 0x3C, e_lfanew & 0xFFFFFFFF)

        blob = bytearray(dos)
        blob += self.signature + coff + bytes(optional) + bytes(table)
        for section in sections:
            blob.extend(b"\x00" * (section.raw_offset - len(blob)))
            blob.extend(section.data)
            blob.extend(b"\x00" * (section.raw_offset + section.raw_size - len(blob)))
        blob += self.trailing
        if self.truncate_to is not None:
            return bytes(blob[: self.truncate_to])
        return bytes(blob)


def _align(value: int, alignment: int) -> int:
    return -(-value // alignment) * alignment
