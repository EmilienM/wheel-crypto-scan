"""Layer 2 orchestration: decide which members are native objects, then read them.

Deciding what to look at matters as much as the reading. A wheel's extensions are
usually obvious from the suffix, but auditwheel-vendored libraries carry names like
`libcrypto-3a1f2b4c.so.3` and some wheels ship bare executables with no suffix at all,
so anything plausible in a library or binary directory is sniffed by magic number too.

Symlinks are recorded and never followed: their content is a path string, and handing
that to an ELF reader produces noise instead of evidence.
"""

from __future__ import annotations

import re

from ..binfmt import read_binary
from ..evidence import (
    FORMAT_UNKNOWN,
    STAGE_BINARY,
    ArtifactInventory,
    BinaryEvidence,
    ScanError,
)
from ..errors import MEMBER_READ_ERROR
from ..ruleset import Conventions, ScanPatterns
from ..wheelfile import MemberInfo, WheelArchive

# `.so`, `.so.3`, `.3.dylib`, `.pyd`, `.dll` and friends.
_BINARY_SUFFIX = re.compile(r"\.(so|dylib|pyd|dll)(\.\d+)*$", re.IGNORECASE)
_VERSIONED_DYLIB = re.compile(r"\.\d+(\.\d+)*\.dylib$", re.IGNORECASE)
_SOURCE_SUFFIXES = (".py",)
_BYTECODE_SUFFIXES = (".pyc", ".pyo")
# Directories where a suffix-less file is plausibly an executable or a library.
_SNIFF_DIRS = ("bin", "lib", "lib64", "scripts", "libexec")
_SNIFF_MIN_BYTES = 64


def is_binary_member(member: MemberInfo, conventions: Conventions) -> bool:
    """Whether this member is worth trying to read as a native object."""
    if member.is_symlink or member.size < _SNIFF_MIN_BYTES:
        return False
    name = member.name
    if _BINARY_SUFFIX.search(name) or _VERSIONED_DYLIB.search(name):
        return True
    if conventions.is_vendor_path(name):
        return True
    parts = name.split("/")
    if len(parts) > 1 and parts[-2].lower() in _SNIFF_DIRS and "." not in parts[-1]:
        return True
    return bool(member.mode & 0o111) and "." not in parts[-1]


def scan_binaries(
    archive: WheelArchive, patterns: ScanPatterns, conventions: Conventions
) -> tuple[tuple[BinaryEvidence, ...], tuple[ScanError, ...]]:
    """Read every native object in the wheel, in archive-name order."""
    binaries: list[BinaryEvidence] = []
    errors: list[ScanError] = []
    for member in archive.members:
        if not is_binary_member(member, conventions):
            continue
        if not archive.is_within_limits(member.name):
            # The refusal is already recorded on the archive; do not also guess at
            # what the member might have contained.
            continue
        try:
            stream = archive.open_member(member.name)
        except Exception as exc:  # noqa: BLE001 - one bad member never sinks the wheel
            errors.append(
                ScanError(
                    stage=STAGE_BINARY,
                    kind=MEMBER_READ_ERROR,
                    message=f"could not open member: {exc}",
                    path=member.name,
                )
            )
            continue
        try:
            evidence, member_errors = read_binary(
                stream,
                member.name,
                patterns,
                vendored=conventions.is_vendor_path(member.name),
            )
        finally:
            stream.close()
        if evidence.format != FORMAT_UNKNOWN or member_errors:
            binaries.append(evidence)
        errors.extend(member_errors)

    binaries.sort(key=lambda binary: binary.path)
    return tuple(binaries), tuple(sorted(errors, key=ScanError.sort_key))


def build_inventory(
    archive: WheelArchive,
    binaries: tuple[BinaryEvidence, ...],
    sbom_paths: tuple[str, ...],
    record_entries: int,
) -> ArtifactInventory:
    """Count what the wheel contains, independent of any rule."""
    py_files = 0
    pyc_files = 0
    symlinks: list[tuple[str, str]] = []
    for member in archive.members:
        if member.name.endswith(_SOURCE_SUFFIXES):
            py_files += 1
        elif member.name.endswith(_BYTECODE_SUFFIXES):
            pyc_files += 1
        if member.is_symlink:
            symlinks.append((member.name, archive.symlink_target(member.name) or ""))

    skipped = tuple(
        sorted((error.path, error.kind) for error in archive.errors if error.path is not None)
    )

    return ArtifactInventory(
        py_files=py_files,
        pyc_files=pyc_files,
        # Nothing to be opaque about when the wheel ships no Python at all.
        source_available=py_files > 0 or pyc_files == 0,
        extensions=tuple(sorted((binary.path, binary.format) for binary in binaries)),
        bundled_libs=tuple(sorted(b.path for b in binaries if b.vendored_path)),
        sboms=sbom_paths,
        symlinks=tuple(sorted(symlinks)),
        skipped=skipped,
        total_uncompressed_bytes=archive.total_uncompressed_bytes,
        record_entries=record_entries,
    )
