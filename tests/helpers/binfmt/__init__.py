"""Binary-format fixture builders used by the tests."""

from .elf import (
    E_SHNUM_OFFSET,
    EM_386,
    EM_S390,
    EM_X86_64,
    ET_DYN,
    ET_EXEC,
    DynSym,
    ElfBuilder,
    patch_u16,
)
from .macho import MachOBuilder, MachOSym, build_fat
from .pe import (
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_I386,
    PEBuilder,
    PEExport,
    PEImport,
)

__all__ = [
    "DynSym",
    "ElfBuilder",
    "MachOBuilder",
    "MachOSym",
    "PEBuilder",
    "PEExport",
    "PEImport",
    "build_fat",
    "patch_u16",
    "E_SHNUM_OFFSET",
    "EM_X86_64",
    "EM_386",
    "EM_S390",
    "ET_DYN",
    "ET_EXEC",
    "IMAGE_FILE_MACHINE_AMD64",
    "IMAGE_FILE_MACHINE_ARM64",
    "IMAGE_FILE_MACHINE_I386",
]
