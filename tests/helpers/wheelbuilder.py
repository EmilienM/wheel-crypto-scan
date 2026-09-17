"""Deterministic wheel construction for the offline test suite.

The metadata layer must produce identical evidence regardless of host, run order or
member order inside the archive. The only way to trust that is to build wheels
ourselves, byte for byte, so a test can assert on exactly what went in. Everything here
stays stdlib: this module is imported by tests for all three layers, so it must not grow
a dependency on `packaging` or anything else that isn't already guaranteed available.
"""

from __future__ import annotations

import re
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path

# Zip timestamps below 1980 are rejected by the format itself; pinning one is what makes
# two builds with the same arguments byte-identical.
_FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)

# PEP 427's escaping rule for the project name embedded in a dist-info directory name
# or a wheel filename: collapse each run of "-", "_" or "." into a single underscore.
_ESCAPE_RUN = re.compile(r"[-_.]+")


def _escape(name: str) -> str:
    return _ESCAPE_RUN.sub("_", name)


def _compress_tags(tags: Sequence[str]) -> str:
    """Fold expanded tags into the single dash-joined, dot-compressed filename segment.

    A real wheel filename carries one segment per axis (interpreter-abi-platform), each
    a dot-joined list when more than one value applies. That is only representable when
    the given tags are exactly the cartesian product of some set of interpreters, abis
    and platforms; anything else cannot appear in a single valid wheel filename, so
    callers needing that should pass one tag at a time.
    """
    if len(tags) == 1:
        return tags[0]
    interpreters: set[str] = set()
    abis: set[str] = set()
    platforms: set[str] = set()
    for tag in tags:
        interpreter, abi, platform = tag.split("-", 2)
        interpreters.add(interpreter)
        abis.add(abi)
        platforms.add(platform)
    expected = {
        f"{interpreter}-{abi}-{platform}"
        for interpreter in interpreters
        for abi in abis
        for platform in platforms
    }
    if expected != set(tags):
        raise ValueError(
            "build_wheel can only compress tags that form a full "
            "interpreter x abi x platform product"
        )
    return (
        f"{'.'.join(sorted(interpreters))}-{'.'.join(sorted(abis))}-{'.'.join(sorted(platforms))}"
    )


def _metadata_text(
    name: str,
    version: str,
    requires_python: str | None,
    requires_dist: Sequence[str],
) -> str:
    lines = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    if requires_python is not None:
        lines.append(f"Requires-Python: {requires_python}")
    lines.extend(f"Requires-Dist: {requirement}" for requirement in requires_dist)
    return "\n".join(lines) + "\n\n"


def _wheel_text(generator: str, tags: Sequence[str], root_is_purelib: bool) -> str:
    lines = [
        "Wheel-Version: 1.0",
        f"Generator: {generator}",
        f"Root-Is-Purelib: {'true' if root_is_purelib else 'false'}",
    ]
    lines.extend(f"Tag: {tag}" for tag in tags)
    return "\n".join(lines) + "\n\n"


def build_wheel(
    path: Path,
    *,
    name: str,
    version: str,
    tags: Sequence[str] = ("py3-none-any",),
    generator: str = "bdist_wheel (0.43.0)",
    requires_dist: Sequence[str] = (),
    requires_python: str | None = None,
    files: Mapping[str, bytes] | None = None,
    sboms: Mapping[str, bytes] | None = None,
    record: bool = True,
    root_is_purelib: bool = True,
    include_metadata: bool = True,
    include_wheel: bool = True,
    metadata_bytes: bytes | None = None,
    second_dist_info: bool = False,
    extra_unrecorded_files: Mapping[str, bytes] | None = None,
    record_phantom_paths: Sequence[str] = (),
) -> Path:
    """Write a wheel to exactly `path` and return it.

    `path` is caller-controlled and independent of `name`/`version`/`tags`: building a
    wheel with a filename that does not match its own metadata is deliberate, since
    that is exactly the fixture the wheel-filename-invalid-falls-back-to-METADATA test
    needs. The `.dist-info` directory name, by contrast, is always derived from `name`
    and `version` the way real build tools derive it.

    The extra keyword-only knobs exist to build deliberately broken wheels for the
    malformed-input tests: `metadata_bytes` overrides METADATA wholesale (for non-UTF-8
    content), `second_dist_info` adds an unrelated second `.dist-info` directory (for
    the ambiguous-dist-info case), `extra_unrecorded_files` adds archive members that
    RECORD never mentions, and `record_phantom_paths` adds RECORD rows for members that
    do not exist in the archive — both directions of a RECORD/archive mismatch.
    """
    dist_info = f"{_escape(name)}-{version}.dist-info"
    members: dict[str, bytes] = {}

    if metadata_bytes is not None:
        members[f"{dist_info}/METADATA"] = metadata_bytes
    elif include_metadata:
        members[f"{dist_info}/METADATA"] = _metadata_text(
            name, version, requires_python, requires_dist
        ).encode("utf-8")

    if include_wheel:
        members[f"{dist_info}/WHEEL"] = _wheel_text(generator, tags, root_is_purelib).encode(
            "utf-8"
        )

    for rel_path, content in sorted((sboms or {}).items()):
        members[f"{dist_info}/sboms/{rel_path}"] = content

    for rel_path, content in sorted((files or {}).items()):
        members[rel_path] = content

    if second_dist_info:
        other_dir = "other-0.0.dist-info"
        members[f"{other_dir}/METADATA"] = _metadata_text("other", "0.0", None, ()).encode("utf-8")

    if record:
        record_path = f"{dist_info}/RECORD"
        rows = [f"{member},," for member in sorted(members)]
        rows.extend(f"{phantom},," for phantom in record_phantom_paths)
        rows.append(f"{record_path},,")
        members[record_path] = ("\n".join(rows) + "\n").encode("utf-8")

    for rel_path, content in sorted((extra_unrecorded_files or {}).items()):
        members[rel_path] = content

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for member in sorted(members):
            info = zipfile.ZipInfo(member, date_time=_FIXED_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, members[member])
    return path
