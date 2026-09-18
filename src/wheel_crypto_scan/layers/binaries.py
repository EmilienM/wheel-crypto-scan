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
from ..evidence import STAGE_BINARY, BinaryEvidence, ScanError
from ..errors import MEMBER_READ_ERROR
from ..ruleset import BinaryPatterns, Conventions
from ..wheelfile import MemberInfo, WheelArchive

# `.so`, `.so.3`, `.3.dylib`, `.pyd`, `.dll` and friends.
_BINARY_SUFFIX = re.compile(r"\.(so|dylib|pyd|dll)(\.\d+)*$", re.IGNORECASE)
_VERSIONED_DYLIB = re.compile(r"\.\d+(\.\d+)*\.dylib$", re.IGNORECASE)
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
    archive: WheelArchive, patterns: BinaryPatterns, conventions: Conventions
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
        except Exception as exc:  # noqa: BLE001 - one bad member never sinks the wheel
            # Above the in-memory threshold the member is decompressed lazily inside
            # the reader, so a CRC failure surfaces here rather than at open time.
            errors.append(
                ScanError(
                    stage=STAGE_BINARY,
                    kind=MEMBER_READ_ERROR,
                    message=f"could not read member: {type(exc).__name__}",
                    path=member.name,
                )
            )
            continue
        finally:
            stream.close()
        # Keep the record even for an unrecognised format. The strings-only fallback
        # exists so a wheel can never look clean merely because we cannot parse it,
        # and dropping the object here would throw away exactly that evidence.
        binaries.append(evidence)
        errors.extend(member_errors)

    binaries.sort(key=lambda binary: binary.path)
    return tuple(binaries), tuple(sorted(errors, key=ScanError.sort_key))
