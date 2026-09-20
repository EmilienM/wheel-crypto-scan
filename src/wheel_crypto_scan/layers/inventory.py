"""What the archive contains, counted once and independently of any rule.

The numbers here belong to the zip rather than to any one layer: how much Python it
ships, what it symlinks, which members a limit refused. Layer 2's binary list is an
argument rather than a second traversal, so the record has one place that says what is
in the wheel instead of three that could disagree.
"""

from __future__ import annotations

from ..evidence import ArtifactInventory, BinaryEvidence
from ..wheelfile import WheelArchive

_SOURCE_SUFFIXES = (".py",)
_BYTECODE_SUFFIXES = (".pyc", ".pyo")


def build_inventory(
    archive: WheelArchive,
    binaries: tuple[BinaryEvidence, ...],
    sbom_paths: tuple[str, ...],
    record_entries: int,
    *,
    py_files_unparsed: int = 0,
    max_binaries: int = 256,
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
        py_files_unparsed=py_files_unparsed,
        binaries_truncated=len(binaries) > max_binaries,
        # True only when we actually read some Python. A wheel whose every source file
        # failed to parse is as opaque as one that ships no source at all, and must not
        # report the same empty Python findings as a genuinely clean wheel.
        source_available=(py_files - py_files_unparsed) > 0 or (py_files == 0 and pyc_files == 0),
        # The full, untruncated set, sorted by path: `record.py`'s `build_record` caps
        # this the same finding-aware way it caps `binaries[]`, which needs `findings`
        # this layer does not have yet. Capping here first would cap it blind, the
        # same mistake #55 fixed for `Evidence.binaries` itself.
        extensions=tuple(sorted((binary.path, binary.format) for binary in binaries)),
        bundled_libs=tuple(sorted(b.path for b in binaries if b.vendored_path)),
        sboms=sbom_paths,
        symlinks=tuple(sorted(symlinks)),
        skipped=skipped,
        total_uncompressed_bytes=archive.total_uncompressed_bytes,
        record_entries=record_entries,
    )
