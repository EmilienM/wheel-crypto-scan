"""Behaviour of the distribution-metadata layer: what a wheel says about itself."""

from __future__ import annotations

import random
import zipfile
from pathlib import Path

from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan import errors
from wheel_crypto_scan.layers.metadata import read_metadata


def _reader(archive_path: Path):
    """Build a `read` callable over a real zip, exactly as the engine will call it."""
    archive = zipfile.ZipFile(archive_path)

    def read(name: str) -> bytes:
        return archive.read(name)

    return archive, read


def _scan(archive_path: Path, wheel_filename: str | None = None):
    archive, read = _reader(archive_path)
    try:
        names = archive.namelist()
        return read_metadata(names, read, wheel_filename or archive_path.name)
    finally:
        archive.close()


def _error_kinds(errs) -> set[str]:
    return {e.kind for e in errs}


# --- 1. round trip -----------------------------------------------------------


def test_name_version_tags_and_requires_python_round_trip(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.2.3-py3-none-any.whl",
        name="sample",
        version="1.2.3",
        tags=("py3-none-any",),
        requires_python=">=3.11",
    )
    meta, errs = _scan(wheel)
    assert errs == ()
    assert meta is not None
    assert meta.name == "sample"
    assert meta.version == "1.2.3"
    assert meta.tags == ("py3-none-any",)
    assert meta.requires_python == ">=3.11"


# --- 2. canonicalisation -------------------------------------------------------


def test_canonical_name_canonicalises_mixed_case_project_name(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "pyOpenSSL-24.0.0-py3-none-any.whl",
        name="pyOpenSSL",
        version="24.0.0",
    )
    meta, errs = _scan(wheel)
    assert errs == ()
    assert meta is not None
    assert meta.canonical_name == "pyopenssl"


# --- 3. generator splitting ----------------------------------------------------


def test_generator_splitting_real_world_forms(tmp_path: Path) -> None:
    cases = [
        ("bdist_wheel (0.43.0)", "bdist_wheel", "0.43.0"),
        ("maturin (1.7.0)", "maturin", "1.7.0"),
        ("setuptools (70.0.0)", "setuptools", "70.0.0"),
        ("scikit-build-core 0.9.3", "scikit-build-core", "0.9.3"),
        ("hatchling 1.25.0", "hatchling", "1.25.0"),
        ("flit", "flit", None),
    ]
    for index, (raw, expected_name, expected_version) in enumerate(cases):
        wheel = build_wheel(
            tmp_path / f"gen{index}-1.0-py3-none-any.whl",
            name=f"gen{index}",
            version="1.0",
            generator=raw,
        )
        meta, errs = _scan(wheel)
        assert errs == ()
        assert meta is not None
        assert meta.generator_raw == raw
        assert meta.generator_name == expected_name, raw
        assert meta.generator_version == expected_version, raw


# --- 4. requires_dist_names ----------------------------------------------------


def test_requires_dist_names_extracts_and_canonicalises(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        requires_dist=(
            'cffi>=1.12; platform_python_implementation != "PyPy"',
            'pytest[testing]>=7; extra == "test"',
        ),
    )
    meta, errs = _scan(wheel)
    assert errs == ()
    assert meta is not None
    assert meta.requires_dist_names == ("cffi", "pytest")


# --- 5. unparseable requirement --------------------------------------------------


def test_unparseable_requirement_kept_raw_and_skipped_from_names(tmp_path: Path) -> None:
    bogus = "this is not a valid requirement !!! ###"
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        requires_dist=(bogus, "cffi>=1.12"),
    )
    meta, errs = _scan(wheel)
    assert errs == ()
    assert meta is not None
    assert bogus in meta.requires_dist
    assert meta.requires_dist_names == ("cffi",)


# --- 6. RECORD entries and mismatches -------------------------------------------


def test_record_entries_and_mismatch_for_unrecorded_file(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        files={"sample/__init__.py": b"# package\n"},
        extra_unrecorded_files={"sample/_stray.py": b"# not in RECORD\n"},
    )
    meta, errs = _scan(wheel)
    assert errs == ()
    assert meta is not None
    assert meta.record_entries > 0
    assert meta.record_mismatches == ("sample/_stray.py",)


def test_record_mismatch_for_phantom_record_row(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        record_phantom_paths=("sample/ghost.py",),
    )
    meta, errs = _scan(wheel)
    assert errs == ()
    assert meta is not None
    assert meta.record_mismatches == ("sample/ghost.py",)


# --- 7. missing RECORD -----------------------------------------------------------


def test_missing_record_records_error_and_returns_rest(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        record=False,
    )
    meta, errs = _scan(wheel)
    assert _error_kinds(errs) == {errors.RECORD_MISSING}
    assert meta is not None
    assert meta.name == "sample"
    assert meta.version == "1.0"
    assert meta.record_entries == 0


# --- 8. SBOM parsing -------------------------------------------------------------


def _cyclonedx(components: list[dict]) -> bytes:
    import json

    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}
    ).encode("utf-8")


def test_cyclonedx_sbom_yields_sorted_flattened_components(tmp_path: Path) -> None:
    sbom = _cyclonedx(
        [
            {
                "name": "zlib-sys",
                "version": "1.1.0",
                "purl": "pkg:cargo/zlib-sys@1.1.0",
                "components": [{"name": "libz", "version": "1.3", "purl": "pkg:generic/libz@1.3"}],
            },
            {"name": "adler32", "version": "1.2.0", "purl": "pkg:cargo/adler32@1.2.0"},
        ]
    )
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        sboms={"sample-1.0.cdx.json": sbom},
    )
    meta, errs = _scan(wheel)
    assert errs == ()
    assert meta is not None
    assert meta.sbom_paths == ("sample-1.0.dist-info/sboms/sample-1.0.cdx.json",)
    names = [c.name for c in meta.sbom_components]
    assert names == sorted(names)
    assert {"zlib-sys", "libz", "adler32"} <= set(names)
    libz = next(c for c in meta.sbom_components if c.name == "libz")
    assert libz.version == "1.3"
    assert libz.purl == "pkg:generic/libz@1.3"
    assert libz.source == "sample-1.0.dist-info/sboms/sample-1.0.cdx.json"


# --- 9. malformed SBOM does not stop the others ---------------------------------


def test_malformed_sbom_records_error_and_others_still_parse(tmp_path: Path) -> None:
    good = _cyclonedx([{"name": "ring", "version": "0.17.0", "purl": "pkg:cargo/ring@0.17.0"}])
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        sboms={
            "a-broken.cdx.json": b"{not valid json",
            "b-good.cdx.json": good,
        },
    )
    meta, errs = _scan(wheel)
    assert _error_kinds(errs) == {errors.SBOM_PARSE_ERROR}
    assert meta is not None
    assert [c.name for c in meta.sbom_components] == ["ring"]


# --- 10. non-UTF-8 METADATA -------------------------------------------------------


def test_non_utf8_metadata_records_decode_error_and_returns_partial(tmp_path: Path) -> None:
    raw = b"Metadata-Version: 2.1\nName: sample\nVersion: 1.0\nSummary: bad \xff\xfe byte\n\n"
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        metadata_bytes=raw,
    )
    meta, errs = _scan(wheel)
    assert _error_kinds(errs) == {errors.METADATA_DECODE_ERROR}
    assert meta is not None
    assert meta.name == "sample"
    assert meta.version == "1.0"


# --- 11. ambiguous dist-info -------------------------------------------------------


def test_two_dist_info_directories_yield_ambiguous_and_none(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        second_dist_info=True,
    )
    meta, errs = _scan(wheel)
    assert meta is None
    assert _error_kinds(errs) == {errors.DIST_INFO_AMBIGUOUS}


# --- 12. missing dist-info -------------------------------------------------------


def test_no_dist_info_yields_missing_and_none(tmp_path: Path) -> None:
    archive_path = tmp_path / "empty.whl"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("sample/__init__.py", b"# no dist-info at all\n")
    meta, errs = _scan(archive_path)
    assert meta is None
    assert _error_kinds(errs) == {errors.DIST_INFO_MISSING}


# --- 13. invalid wheel filename falls back to METADATA ---------------------------


def test_invalid_wheel_filename_falls_back_to_metadata(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "not-a-valid-wheel-name.whl",
        name="sample",
        version="1.0",
        tags=("py3-none-any",),
    )
    meta, errs = _scan(wheel, wheel_filename="not-a-valid-wheel-name.whl")
    assert _error_kinds(errs) == {errors.WHEEL_FILENAME_INVALID}
    assert meta is not None
    assert meta.name == "sample"
    assert meta.version == "1.0"
    assert meta.tags == ("py3-none-any",)


# --- 14. a raising read() does not abort the whole parse --------------------------


def test_read_raising_for_one_member_does_not_abort_parse(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
    )
    archive, real_read = _reader(wheel)
    wheel_path = "sample-1.0.dist-info/WHEEL"

    def flaky_read(name: str) -> bytes:
        if name == wheel_path:
            raise OSError("disk went away")
        return real_read(name)

    try:
        names = archive.namelist()
        meta, errs = read_metadata(names, flaky_read, wheel.name)
    finally:
        archive.close()

    assert _error_kinds(errs) == {errors.MEMBER_READ_ERROR}
    assert meta is not None
    assert meta.name == "sample"
    assert meta.version == "1.0"


# --- 15. determinism ---------------------------------------------------------------


def test_determinism_same_wheel_parsed_twice_is_equal(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        requires_dist=("cffi>=1.12",),
        sboms={"s.cdx.json": _cyclonedx([{"name": "ring", "version": "1.0"}])},
    )
    first = _scan(wheel)
    second = _scan(wheel)
    assert first == second


def test_determinism_shuffled_member_order_is_equal(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        requires_dist=("cffi>=1.12", "pytest[testing]>=7"),
        files={"sample/__init__.py": b"", "sample/mod.py": b""},
        sboms={"s.cdx.json": _cyclonedx([{"name": "ring", "version": "1.0"}])},
    )
    archive, read = _reader(wheel)
    try:
        names = list(archive.namelist())
        ordered, ordered_errs = read_metadata(names, read, wheel.name)
        shuffled = names[:]
        random.Random(1234).shuffle(shuffled)
        shuffled_meta, shuffled_errs = read_metadata(shuffled, read, wheel.name)
    finally:
        archive.close()
    assert ordered == shuffled_meta
    assert ordered_errs == shuffled_errs


def test_determinism_building_the_same_wheel_twice_is_byte_identical(tmp_path: Path) -> None:
    first = build_wheel(tmp_path / "a.whl", name="sample", version="1.0")
    second = build_wheel(tmp_path / "b.whl", name="sample", version="1.0")
    assert first.read_bytes() == second.read_bytes()


# --- extra coverage: METADATA_MISSING and WHEEL_MISSING (named in the spec) --------


def test_missing_metadata_records_error_and_still_returns_partial(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        include_metadata=False,
    )
    meta, errs = _scan(wheel)
    assert _error_kinds(errs) == {errors.METADATA_MISSING}
    assert meta is not None
    # No METADATA at all: name/version fall back to what the (valid) filename gives.
    assert meta.name == "sample"
    assert meta.version == "1.0"


def test_missing_wheel_file_records_error_and_still_returns_partial(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "sample-1.0-py3-none-any.whl",
        name="sample",
        version="1.0",
        include_wheel=False,
    )
    meta, errs = _scan(wheel)
    assert _error_kinds(errs) == {errors.WHEEL_MISSING}
    assert meta is not None
    assert meta.name == "sample"
    assert meta.generator_raw is None


def test_an_sbom_with_a_malformed_components_field_is_an_error_not_an_empty_list(
    tmp_path: Path,
) -> None:
    """Silently reading a broken SBOM as "nothing bundled" is the worst failure mode."""
    wheel = build_wheel(
        tmp_path / "demo-1.0-py3-none-any.whl",
        name="demo",
        version="1.0",
        sboms={"broken.cdx.json": b'{"bomFormat": "CycloneDX", "components": "oops"}'},
    )
    metadata, found = _scan(wheel)
    assert metadata is not None
    assert metadata.sbom_components == ()
    assert any(error.kind == errors.SBOM_PARSE_ERROR for error in found)


def test_an_sbom_declaring_no_components_is_not_an_error(tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "demo-1.0-py3-none-any.whl",
        name="demo",
        version="1.0",
        sboms={"empty.cdx.json": b'{"bomFormat": "CycloneDX", "specVersion": "1.5"}'},
    )
    metadata, found = _scan(wheel)
    assert metadata is not None
    assert metadata.sbom_components == ()
    assert not any(error.kind == errors.SBOM_PARSE_ERROR for error in found)
