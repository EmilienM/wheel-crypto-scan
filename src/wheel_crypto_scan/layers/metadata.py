"""Layer 1: what a wheel says about itself.

Everything here comes from the wheel's own declarations: its filename, its
`.dist-info/METADATA` and `WHEEL` files, its `RECORD`, and any PEP 770 SBOM it ships.
None of it is verified against the wheel's actual contents (that is what RECORD
reconciliation and the SBOM-vs-binary cross-check in later layers are for) and none of
it is judged; this layer only reads and normalises.

The archive itself is untrusted, so every read is treated as something that can fail
without taking the rest of the wheel down with it: a missing member is recorded and
skipped, a member that raises on read is recorded and skipped, and a member whose
content cannot be parsed is recorded and skipped. The only failures fatal to this layer
are not being able to find (or being unable to disambiguate) the `.dist-info` directory
itself, since without it there is nowhere to look for anything else.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser
from email.policy import compat32
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from .. import errors
from ..evidence import STAGE_METADATA, MetadataEvidence, SbomComponent, ScanError

# A build tool writes one `Generator:` value either as "name (version)" or as
# "name version"; a few (flit) write a bare name with no version at all.
_GENERATOR_WITH_PARENS = re.compile(r"^(?P<name>.+?)\s*\((?P<version>[^()]+)\)\s*$")


@dataclass(frozen=True, slots=True)
class _FilenameInfo:
    """What `packaging.utils.parse_wheel_filename` gave us, reduced to what we need."""

    canonical_name: str
    version: str
    tags: tuple[str, ...]


def read_metadata(
    names: Sequence[str],
    read: Callable[[str], bytes],
    wheel_filename: str,
) -> tuple[MetadataEvidence | None, tuple[ScanError, ...]]:
    """Extract Layer 1 evidence from one wheel's archive listing.

    `names` and `read` deliberately say nothing about zip files: this layer never opens
    an archive itself, so it can be exercised with any member list and any bytes source,
    real or synthetic.
    """
    found_errors: list[ScanError] = []
    name_index = frozenset(names)

    dist_info_dir, dist_info_errors = _find_dist_info_dir(names)
    found_errors.extend(dist_info_errors)
    if dist_info_dir is None:
        return None, _finalize_errors(found_errors)

    filename_info, filename_error = _parse_filename(wheel_filename)
    if filename_error is not None:
        found_errors.append(filename_error)

    metadata_msg, metadata_errors = _read_email_member(
        dist_info_dir, "METADATA", name_index, read, errors.METADATA_MISSING, check_utf8=True
    )
    found_errors.extend(metadata_errors)

    wheel_msg, wheel_errors = _read_email_member(
        dist_info_dir, "WHEEL", name_index, read, errors.WHEEL_MISSING, check_utf8=False
    )
    found_errors.extend(wheel_errors)

    meta_name = _header(metadata_msg, "Name")
    meta_version = _header(metadata_msg, "Version")
    requires_python = _header(metadata_msg, "Requires-Python")
    requires_dist_raw = _header_all(metadata_msg, "Requires-Dist")

    generator_raw = _header(wheel_msg, "Generator")
    root_is_purelib_raw = _header(wheel_msg, "Root-Is-Purelib")
    wheel_tags_raw = _header_all(wheel_msg, "Tag")

    name, canonical_name, version = _resolve_identity(filename_info, meta_name, meta_version)

    tags = (
        filename_info.tags
        if filename_info is not None and filename_info.tags
        else (tuple(sorted(set(wheel_tags_raw))))
    )
    platform_tags = _derive_platform_tags(tags)

    generator_name, generator_version = _split_generator(generator_raw)
    requires_dist = tuple(sorted(set(requires_dist_raw)))
    requires_dist_names = _requires_dist_names(requires_dist)
    root_is_purelib = (root_is_purelib_raw or "").strip().lower() == "true"

    record_entries, record_mismatches, record_errors = _read_record(dist_info_dir, name_index, read)
    found_errors.extend(record_errors)

    sbom_paths, sbom_components, sbom_errors = _read_sboms(dist_info_dir, name_index, read)
    found_errors.extend(sbom_errors)

    evidence = MetadataEvidence(
        name=name,
        canonical_name=canonical_name,
        version=version,
        tags=tags,
        platform_tags=platform_tags,
        generator_raw=generator_raw,
        generator_name=generator_name,
        generator_version=generator_version,
        requires_python=requires_python,
        requires_dist=requires_dist,
        requires_dist_names=requires_dist_names,
        root_is_purelib=root_is_purelib,
        dist_info_dir=dist_info_dir,
        record_entries=record_entries,
        record_mismatches=record_mismatches,
        sbom_paths=sbom_paths,
        sbom_components=sbom_components,
    )
    return evidence, _finalize_errors(found_errors)


# --- dist-info location -------------------------------------------------------------


def _find_dist_info_dir(names: Sequence[str]) -> tuple[str | None, list[ScanError]]:
    """Locate the single `*.dist-info` directory an archive is required to have.

    Directory entries never reach this function (the archive layer drops them), so a
    dist-info directory is recognised by any member living underneath it, not by a
    member name of its own.
    """
    candidates: set[str] = set()
    for member in names:
        head, sep, _rest = member.partition("/")
        if sep and head.endswith(".dist-info"):
            candidates.add(head)

    if not candidates:
        return None, [
            ScanError(
                stage=STAGE_METADATA,
                kind=errors.DIST_INFO_MISSING,
                message="no *.dist-info directory in archive",
            )
        ]
    if len(candidates) > 1:
        return None, [
            ScanError(
                stage=STAGE_METADATA,
                kind=errors.DIST_INFO_AMBIGUOUS,
                message=f"multiple dist-info directories: {', '.join(sorted(candidates))}",
            )
        ]
    return next(iter(candidates)), []


# --- wheel filename -------------------------------------------------------------------


def _parse_filename(wheel_filename: str) -> tuple[_FilenameInfo | None, ScanError | None]:
    try:
        canonical_name, version, _build, tags = parse_wheel_filename(wheel_filename)
    except InvalidWheelFilename:
        return None, ScanError(
            stage=STAGE_METADATA,
            kind=errors.WHEEL_FILENAME_INVALID,
            message="wheel filename does not parse",
            path=wheel_filename,
        )
    formatted_tags = tuple(sorted({f"{tag.interpreter}-{tag.abi}-{tag.platform}" for tag in tags}))
    return _FilenameInfo(
        canonical_name=canonical_name, version=str(version), tags=formatted_tags
    ), None


def _resolve_identity(
    filename_info: _FilenameInfo | None,
    meta_name: str | None,
    meta_version: str | None,
) -> tuple[str, str, str]:
    """Work out the declared name, its canonical form, and the version.

    `packaging.utils.parse_wheel_filename` canonicalises as it parses, so a valid
    filename is the primary, authoritative source for `canonical_name` and `version`.
    METADATA's `Name` header is the one place the project's declared, case-preserving
    spelling survives, so it is preferred for the human-facing `name` field whenever it
    is available; a `pyOpenSSL` wheel therefore reports `name="pyOpenSSL"` alongside
    `canonical_name="pyopenssl"`. When the filename cannot be parsed, METADATA becomes
    the only source for both.
    """
    if filename_info is not None:
        canonical_name = filename_info.canonical_name
        version = filename_info.version
    else:
        canonical_name = canonicalize_name(meta_name) if meta_name else ""
        version = meta_version or ""

    name = meta_name if meta_name else canonical_name
    return name, canonical_name, version


def _derive_platform_tags(tags: Iterable[str]) -> tuple[str, ...]:
    """Pull platform tags out of `tags`, expanding any dot-compressed segment."""
    platforms: set[str] = set()
    for tag in tags:
        parts = tag.split("-", 2)
        segment = parts[2] if len(parts) == 3 else tag
        platforms.update(segment.split("."))
    return tuple(sorted(platforms))


# --- generator ------------------------------------------------------------------------


def _split_generator(raw: str | None) -> tuple[str | None, str | None]:
    if raw is None:
        return None, None
    text = raw.strip()
    if not text:
        return None, None
    match = _GENERATOR_WITH_PARENS.match(text)
    if match:
        return match.group("name").strip(), match.group("version").strip()
    if " " in text:
        name, _sep, version = text.rpartition(" ")
        if name and _looks_like_version(version):
            return name, version
    return text, None


def _looks_like_version(candidate: str) -> bool:
    try:
        Version(candidate)
    except InvalidVersion:
        return False
    return True


# --- requires-dist ----------------------------------------------------------------------


def _requires_dist_names(requires_dist: Iterable[str]) -> tuple[str, ...]:
    resolved: set[str] = set()
    for raw in requires_dist:
        try:
            requirement = Requirement(raw)
        except InvalidRequirement:
            continue
        resolved.add(canonicalize_name(requirement.name))
    return tuple(sorted(resolved))


# --- METADATA / WHEEL (email-format) members --------------------------------------------


def _read_email_member(
    dist_info_dir: str,
    member_name: str,
    name_index: frozenset[str],
    read: Callable[[str], bytes],
    missing_kind: str,
    *,
    check_utf8: bool,
) -> tuple[Message | None, list[ScanError]]:
    path = f"{dist_info_dir}/{member_name}"
    if path not in name_index:
        return None, [
            ScanError(
                stage=STAGE_METADATA,
                kind=missing_kind,
                message=f"{member_name} not found in dist-info",
                path=path,
            )
        ]
    try:
        raw = read(path)
    except Exception:  # noqa: BLE001 - any read failure is this member's problem, not ours
        return None, [
            ScanError(
                stage=STAGE_METADATA,
                kind=errors.MEMBER_READ_ERROR,
                message=f"failed to read {member_name}",
                path=path,
            )
        ]

    decode_errors: list[ScanError] = []
    if check_utf8:
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            decode_errors.append(
                ScanError(
                    stage=STAGE_METADATA,
                    kind=errors.METADATA_DECODE_ERROR,
                    message=f"{member_name} is not valid UTF-8",
                    path=path,
                )
            )

    msg = BytesParser(policy=compat32).parsebytes(raw)
    return msg, decode_errors


def _header(msg: Message | None, name: str) -> str | None:
    if msg is None:
        return None
    value = msg.get(name)
    return None if value is None else str(value)


def _header_all(msg: Message | None, name: str) -> tuple[str, ...]:
    if msg is None:
        return ()
    values = msg.get_all(name)
    return tuple(str(value) for value in values) if values else ()


# --- RECORD -------------------------------------------------------------------------------


def _read_record(
    dist_info_dir: str,
    name_index: frozenset[str],
    read: Callable[[str], bytes],
) -> tuple[int, tuple[str, ...], list[ScanError]]:
    record_path = f"{dist_info_dir}/RECORD"
    if record_path not in name_index:
        return (
            0,
            (),
            [
                ScanError(
                    stage=STAGE_METADATA,
                    kind=errors.RECORD_MISSING,
                    message="RECORD not found in dist-info",
                    path=record_path,
                )
            ],
        )
    try:
        raw = read(record_path)
    except Exception:  # noqa: BLE001 - a read failure here is a record we cannot trust
        return (
            0,
            (),
            [
                ScanError(
                    stage=STAGE_METADATA,
                    kind=errors.MEMBER_READ_ERROR,
                    message="failed to read RECORD",
                    path=record_path,
                )
            ],
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return (
            0,
            (),
            [
                ScanError(
                    stage=STAGE_METADATA,
                    kind=errors.RECORD_PARSE_ERROR,
                    message="RECORD is not valid UTF-8",
                    path=record_path,
                )
            ],
        )
    try:
        rows = [row for row in csv.reader(io.StringIO(text)) if row]
    except csv.Error:
        return (
            0,
            (),
            [
                ScanError(
                    stage=STAGE_METADATA,
                    kind=errors.RECORD_PARSE_ERROR,
                    message="RECORD could not be parsed as CSV",
                    path=record_path,
                )
            ],
        )

    record_paths = {row[0] for row in rows if row[0] and not row[0].endswith("/")}
    record_paths.discard(record_path)
    archive_paths = {member for member in name_index if not member.endswith("/")}
    archive_paths.discard(record_path)

    mismatches = tuple(sorted((archive_paths - record_paths) | (record_paths - archive_paths)))
    return len(rows), mismatches, []


# --- PEP 770 SBOMs --------------------------------------------------------------------------


def _read_sboms(
    dist_info_dir: str,
    name_index: frozenset[str],
    read: Callable[[str], bytes],
) -> tuple[tuple[str, ...], tuple[SbomComponent, ...], list[ScanError]]:
    prefix = f"{dist_info_dir}/sboms/"
    sbom_paths = sorted(member for member in name_index if member.startswith(prefix))

    found_errors: list[ScanError] = []
    components: list[SbomComponent] = []
    for path in sbom_paths:
        try:
            raw = read(path)
        except Exception:  # noqa: BLE001 - one bad SBOM must not sink the others
            found_errors.append(
                ScanError(
                    stage=STAGE_METADATA,
                    kind=errors.MEMBER_READ_ERROR,
                    message="failed to read SBOM",
                    path=path,
                )
            )
            continue
        try:
            data = json.loads(raw.decode("utf-8"))
            found = list(_flatten_components(data, path))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            found_errors.append(
                ScanError(
                    stage=STAGE_METADATA,
                    kind=errors.SBOM_PARSE_ERROR,
                    message="SBOM is not a parseable CycloneDX document",
                    path=path,
                )
            )
            continue
        components.extend(found)

    components = sorted(set(components), key=SbomComponent.sort_key)
    return tuple(sbom_paths), tuple(components), found_errors


def _flatten_components(data: Any, source: str) -> Iterator[SbomComponent]:
    if not isinstance(data, dict):
        raise TypeError("SBOM root is not an object")
    components = data.get("components")
    if components is None:
        # A valid SBOM may legitimately declare no components.
        return
    yield from _walk_components(components, source)


def _walk_components(components: Any, source: str) -> Iterator[SbomComponent]:
    if not isinstance(components, list):
        # Do not quietly read this as "no bundled dependencies". An SBOM is the
        # highest-confidence evidence the tool gets, so an unreadable one has to be
        # recorded as unreadable rather than as empty.
        raise TypeError("SBOM components field is not a list")
    for entry in components:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if isinstance(name, str) and name:
            version = entry.get("version")
            purl = entry.get("purl")
            yield SbomComponent(
                name=name,
                version=version if isinstance(version, str) else None,
                purl=purl if isinstance(purl, str) else None,
                source=source,
            )
        nested = entry.get("components")
        if isinstance(nested, list):
            yield from _walk_components(nested, source)


# --- shared -----------------------------------------------------------------------------


def _finalize_errors(found_errors: list[ScanError]) -> tuple[ScanError, ...]:
    return tuple(sorted(set(found_errors), key=ScanError.sort_key))
