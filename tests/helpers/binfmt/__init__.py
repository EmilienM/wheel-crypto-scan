"""Deterministic, dependency-free ELF, Mach-O and PE writers for binfmt tests.

`binfmt.elf`, `binfmt.macho` and `binfmt.pe` are read against real object file formats,
so the fixtures that exercise them have to be real (if minimal) object files, not stubs.
These modules build them byte-for-byte with `struct`: no compiler, no network access, and
nothing committed as a binary blob. Every field the readers look at can be pinned
exactly, which is the point: a test can assert that a specific `DT_NEEDED` entry or a
specific symbol's binding comes back unchanged.

Only what `binfmt` reads is modelled. Each module says what it leaves out and why, and
that scope is deliberate: a field no reader looks at is not an omission to be filled in.

Re-exported here are the builders plus the constants tests actually pin. The structural
constants each format needs internally (`SHT_*`, `LC_*`, `PE32_MAGIC` and the rest) stay
in `helpers.binfmt.elf`, `.macho` and `.pe`; import them from there rather than
open-coding the offset, which is how `0x3C` ends up in a test.
"""

from .ar import MAGIC as AR_MAGIC
from .ar import ArMember, build_ar, gnu_symbol_table_member, pseudo_member
from .elf import (
    E_SHNUM_OFFSET,
    EM_386,
    EM_S390,
    EM_X86_64,
    ET_DYN,
    ET_EXEC,
    ET_REL,
    SHF_COMPRESSED,
    SHT_DYNAMIC,
    SHT_DYNSYM,
    SHT_PROGBITS,
    SHT_SYMTAB,
    STB_GLOBAL,
    DynSym,
    ElfBuilder,
    append_duplicate_dynsym_section,
    append_strtab_decoy,
    insert_bogus_section_before,
    patch_header_field,
    patch_section_header,
    patch_u16,
)
from .macho import FAT_MAGIC, FAT_MAGIC_64, MachOBuilder, MachOSym, build_fat
from .pe import (
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_I386,
    PEBuilder,
    PEExport,
    PEImport,
)

__all__ = [
    "AR_MAGIC",
    "ArMember",
    "build_ar",
    "gnu_symbol_table_member",
    "pseudo_member",
    "DynSym",
    "EM_386",
    "EM_S390",
    "EM_X86_64",
    "ET_DYN",
    "ET_EXEC",
    "ET_REL",
    "SHF_COMPRESSED",
    "SHT_DYNAMIC",
    "SHT_DYNSYM",
    "SHT_PROGBITS",
    "SHT_SYMTAB",
    "STB_GLOBAL",
    "E_SHNUM_OFFSET",
    "ElfBuilder",
    "append_duplicate_dynsym_section",
    "append_strtab_decoy",
    "insert_bogus_section_before",
    "FAT_MAGIC",
    "FAT_MAGIC_64",
    "IMAGE_FILE_MACHINE_AMD64",
    "IMAGE_FILE_MACHINE_ARM64",
    "IMAGE_FILE_MACHINE_I386",
    "MachOBuilder",
    "MachOSym",
    "PEBuilder",
    "PEExport",
    "PEImport",
    "build_fat",
    "patch_header_field",
    "patch_section_header",
    "patch_u16",
]
