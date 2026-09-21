"""Layer 2 orchestration: decide which members are native objects, then read them.

Deciding what to look at matters as much as the reading. A wheel's extensions are
usually obvious from the suffix, but auditwheel-vendored libraries carry names like
`libcrypto-3a1f2b4c.so.3` and some wheels ship bare executables with no suffix at all,
so anything plausible in a library or binary directory is sniffed by magic number too.

Symlinks are recorded and never followed: their content is a path string, and handing
that to an ELF reader produces noise instead of evidence.

A `.a`/`.lib` member is sniffed by magic, after opening, rather than trusted by suffix
alone: an older MSVC `.lib` (not `ar`-format) or a suffix collision reads as any other
unrecognised structure would, through `read_binary`'s own strings-only fallback, not
`binfmt.ar`'s. `binfmt.ar.read_ar_members` returns *several* `BinaryEvidence` entries
for one archive member, unlike every other reader here, because an archive holds many
separate objects a consumer wants told apart -- so it is called directly, in place of
`read_binary`, rather than through `read_binary`'s own one-in-one-out dispatch.
"""

from __future__ import annotations

import re

from ..binfmt import read_binary
from ..binfmt.ar import MAGIC as _AR_MAGIC
from ..binfmt.ar import read_ar_members
from ..evidence import STAGE_BINARY, BinaryEvidence, ScanError
from ..errors import MEMBER_READ_ERROR
from ..ruleset import BinaryPatterns, Conventions
from ..wheelfile import MemberInfo, WheelArchive

# `.so`, `.so.3`, `.3.dylib`, `.pyd`, `.dll`, `.exe`, `.a` and `.lib` (a static
# archive, or occasionally an import library -- either way worth opening and sniffing;
# `binfmt.ar` recognises the ones that are really `ar`-format, and anything else falls
# through to the same strings-only fallback an unrecognised suffix-matched file
# already gets) and friends.
_BINARY_SUFFIX = re.compile(r"\.(so|dylib|pyd|dll|exe|a|lib)(\.\d+)*$", re.IGNORECASE)
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
            stream.seek(0)
            is_archive = stream.read(len(_AR_MAGIC)) == _AR_MAGIC
            stream.seek(0)
            vendored = conventions.is_vendor_path(member.name)
            if is_archive:
                member_evidence, member_errors = read_ar_members(
                    stream, member.name, patterns, vendored=vendored
                )
            else:
                # `read_binary` returns one `(evidence, errors)` pair, not the
                # `(evidences, errors)` shape `read_ar_members` returns; wrap the
                # single evidence in a tuple so both branches feed `binaries.extend`
                # below identically.
                single_evidence, member_errors = read_binary(
                    stream, member.name, patterns, vendored=vendored
                )
                member_evidence = (single_evidence,)
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
        binaries.extend(member_evidence)
        errors.extend(member_errors)

    binaries.sort(key=lambda binary: binary.path)
    return tuple(binaries), tuple(sorted(errors, key=ScanError.sort_key))
