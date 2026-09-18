"""Regressions from the adversarial correctness review.

Every test here corresponds to a reproduced failure: a wheel that read as clean
because we could not examine it, an exception that escaped and destroyed a run, or a
cache that served the wrong record.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from helpers.elfbuilder import DynSym, ElfBuilder
from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan import errors
from wheel_crypto_scan.cli import main
from wheel_crypto_scan.evidence import SbomComponent
from wheel_crypto_scan.ruleset import load_ruleset
from wheel_crypto_scan.scan import ScanContext, scan_wheel
from wheel_crypto_scan.wheelfile import ArchiveLimits, WheelArchive

MANYLINUX = "cp39-abi3-manylinux_2_28_x86_64"
FIXED_DATE = (1980, 1, 1, 0, 0, 0)


@pytest.fixture(scope="module")
def context() -> ScanContext:
    return ScanContext.build(load_ruleset())


def read_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --- H1: an unreadable format must not take its own evidence with it --------


def test_an_unrecognised_binary_keeps_the_evidence_it_produced(context, tmp_path: Path) -> None:
    """A linker script or packed blob named .so still yields strings; keep them."""
    blob = b"\x01\x02not-an-elf\x00" + b"OpenSSL 3.0.14 4 Jun 2024\x00" + b"\x00" * 200
    wheel = build_wheel(
        tmp_path / f"fakeblob-1.0-{MANYLINUX}.whl",
        name="fakeblob",
        version="1.0",
        tags=(MANYLINUX,),
        files={"fakeblob/_speedups.so": blob},
    )
    record = scan_wheel(wheel, context)
    assert record["binaries"], "the object was dropped along with its evidence"
    assert record["binaries"][0]["partial_analysis"] is True
    assert record["verdict"]["class"] != "NO_CRYPTO_DETECTED"
    assert record["artifacts"]["extensions"]


# --- H3: symlink targets must obey the archive limits -----------------------


def test_a_huge_symlink_target_is_refused_rather_than_read(tmp_path: Path) -> None:
    """A 'symlink' whose target is 64 MiB is an attack, not a path."""
    path = tmp_path / "evil-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("lib/libfoo.so.1", date_time=FIXED_DATE)
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        archive.writestr(info, b"A" * (64 * 1024 * 1024))
    with WheelArchive.open(path, ArchiveLimits(max_member_bytes=4096)) as wheel:
        assert wheel.symlink_target("lib/libfoo.so.1") is None


def test_an_oversized_symlink_does_not_bloat_the_record(context, tmp_path: Path) -> None:
    path = tmp_path / "evil-1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("lib/libfoo.so.1", date_time=FIXED_DATE)
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        archive.writestr(info, b"A" * (8 * 1024 * 1024))
    line = json.dumps(scan_wheel(path, context))
    assert len(line) < 100_000, "the symlink target was copied into the record verbatim"


# --- H4: a corrupt streamed member must not raise ---------------------------


def test_a_corrupt_streamed_member_is_recorded_not_raised(tmp_path: Path) -> None:
    """Above the in-memory threshold the member is decompressed lazily, inside the reader."""
    payload = ElfBuilder(
        needed=("libcrypto.so.3",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
        rodata=b"padding" * 20000,
    ).build()
    path = tmp_path / f"bigext-1.0-{MANYLINUX}.whl"
    build_wheel(
        path,
        name="bigext",
        version="1.0",
        tags=(MANYLINUX,),
        files={"bigext/_ext.abi3.so": payload},
    )
    # The member is deflated, so corrupt the compressed stream directly. Stay well
    # clear of the central directory at the end so the archive still opens.
    raw = bytearray(path.read_bytes())
    start = len(raw) // 4
    raw[start : start + 64] = bytes((byte ^ 0xFF) for byte in raw[start : start + 64])
    path.write_bytes(bytes(raw))

    ruleset = load_ruleset()
    streamed = ScanContext.build(ruleset, archive_limits=ArchiveLimits(max_in_memory_bytes=1024))
    record = scan_wheel(path, streamed)
    assert record["errors"], "a corrupt streamed member produced no error record"
    # Whatever was read before the corruption is still real evidence, so a higher
    # precedence class may outrank OPAQUE. What matters is that opacity is recorded.
    assert "OPAQUE" in record["verdict"]["classes"]
    assert record["verdict"]["needs_human_review"] is True


# --- H5: two identical archives under different names are two wheels --------


def test_identical_archives_with_different_names_stay_distinct(tmp_path: Path) -> None:
    """The record's name, version and tags all come from the filename."""
    corpus = tmp_path / "wheels"
    corpus.mkdir()
    first = build_wheel(
        corpus / "alpha-1.0-py3-none-any.whl", name="alpha", version="1.0", files={}
    )
    second = corpus / "zeta-9.9-py3-none-any.whl"
    second.write_bytes(first.read_bytes())

    cache = tmp_path / "cache"
    cold, warm = tmp_path / "cold.jsonl", tmp_path / "warm.jsonl"
    main(["scan", str(corpus), "-o", str(cold), "--cache-dir", str(cache), "-q"])
    main(["scan", str(corpus), "-o", str(warm), "--cache-dir", str(cache), "-q"])

    names = [r["wheel"]["filename"] for r in read_records(cold)]
    assert names == ["alpha-1.0-py3-none-any.whl", "zeta-9.9-py3-none-any.whl"]
    assert cold.read_bytes() == warm.read_bytes()


# --- H8: one unreadable file must not destroy the run -----------------------


def test_an_unreadable_wheel_does_not_abort_the_whole_scan(tmp_path: Path) -> None:
    corpus = tmp_path / "wheels"
    corpus.mkdir()
    for name in ("aaa", "ccc"):
        build_wheel(corpus / f"{name}-1.0-py3-none-any.whl", name=name, version="1.0", files={})
    blocked = corpus / "bbb-1.0-py3-none-any.whl"
    blocked.write_bytes(b"PK\x03\x04")
    blocked.chmod(0o000)
    try:
        out = tmp_path / "out.jsonl"
        assert main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"]) == 0
        records = read_records(out)
        assert len(records) == 3, "the other wheels' work was lost"
        blocked_record = next(r for r in records if r["wheel"]["filename"].startswith("bbb"))
        assert blocked_record["errors"]
        assert blocked_record["verdict"]["class"] == "OPAQUE"
    finally:
        blocked.chmod(0o644)


def test_a_wheel_deleted_between_discovery_and_scan_is_recorded(context, tmp_path: Path) -> None:
    missing = tmp_path / "gone-1.0-py3-none-any.whl"
    record = scan_wheel(missing, context)
    assert record["verdict"]["class"] == "OPAQUE"
    assert record["errors"]


# --- M2: the limits that change a record belong in the cache key ------------


def test_a_constrained_run_does_not_poison_the_cache(tmp_path: Path) -> None:
    """A --max-binary-bytes run skips the binary layer; that record must not be reused."""
    corpus = tmp_path / "wheels"
    corpus.mkdir()
    build_wheel(
        corpus / f"demo-1.0-{MANYLINUX}.whl",
        name="demo",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "demo/_ext.abi3.so": ElfBuilder(
                needed=("libcrypto.so.3",),
                dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
            ).build()
        },
    )
    cache = tmp_path / "cache"
    constrained, normal, fresh = (tmp_path / f"{n}.jsonl" for n in ("c", "n", "f"))
    main(
        [
            "scan",
            str(corpus),
            "-o",
            str(constrained),
            "--cache-dir",
            str(cache),
            "--max-binary-bytes",
            "100",
            "-q",
        ]
    )
    main(["scan", str(corpus), "-o", str(normal), "--cache-dir", str(cache), "-q"])
    main(["scan", str(corpus), "-o", str(fresh), "--no-cache", "-q"])
    assert normal.read_bytes() == fresh.read_bytes()


# --- M3: a BOM must not silently discard every header -----------------------


def test_a_byte_order_mark_in_metadata_does_not_lose_the_headers(context, tmp_path: Path) -> None:
    """A BOM is valid UTF-8, so the decode guard passes and every header vanishes."""
    plain_dir, bom_dir = tmp_path / "plain", tmp_path / "bom"
    plain_dir.mkdir()
    bom_dir.mkdir()
    source = build_wheel(
        plain_dir / "bommed-1.0-py3-none-any.whl",
        name="bommed",
        version="1.0",
        requires_dist=["pycryptodome"],
        files={},
    )
    normal = scan_wheel(source, context)

    bommed = bom_dir / "bommed-1.0-py3-none-any.whl"
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(bommed, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename.endswith("METADATA"):
                data = b"\xef\xbb\xbf" + data
            dst.writestr(zipfile.ZipInfo(info.filename, date_time=FIXED_DATE), data)

    with_bom = scan_wheel(bommed, context)
    assert with_bom["wheel"]["requires_dist"] == normal["wheel"]["requires_dist"]
    assert "DIST_DEPENDS_ON_CRYPTO" in {f["rule_id"] for f in with_bom["findings"]}


def test_metadata_with_no_parseable_headers_is_recorded(context, tmp_path: Path) -> None:
    source = build_wheel(
        tmp_path / "junk-1.0-py3-none-any.whl", name="junk", version="1.0", files={}
    )
    broken = tmp_path / "broken-1.0-py3-none-any.whl"
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(broken, "w") as dst:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename.endswith("METADATA"):
                data = b"not headers at all, just prose\n"
            dst.writestr(zipfile.ZipInfo(info.filename, date_time=FIXED_DATE), data)
    record = scan_wheel(broken, context)
    assert any(e["kind"] == errors.METADATA_DECODE_ERROR for e in record["errors"])


# --- M4: a declared-huge NOBITS section must not allocate -------------------


def test_a_nobits_comment_section_does_not_allocate(context, tmp_path: Path) -> None:
    """sh_size is attacker controlled and SHT_NOBITS materialises it as zero bytes."""
    from helpers.elfbuilder import patch_u16  # noqa: F401  (kept for symmetry)

    payload = bytearray(ElfBuilder(comment=b"GCC: (GNU) 14.0\x00", needed=("libc.so.6",)).build())
    # Find the .comment section header and rewrite its type to SHT_NOBITS with a 3 GiB size.
    import struct

    e_shoff = struct.unpack_from("<Q", payload, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", payload, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", payload, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", payload, 0x3E)[0]
    strtab_off = struct.unpack_from("<Q", payload, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
    patched = False
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        name_off = struct.unpack_from("<I", payload, base)[0]
        end = payload.index(b"\x00", strtab_off + name_off)
        if bytes(payload[strtab_off + name_off : end]) == b".comment":
            struct.pack_into("<I", payload, base + 4, 8)  # sh_type = SHT_NOBITS
            struct.pack_into("<Q", payload, base + 0x20, 3 * 1024**3)  # sh_size
            patched = True
    assert patched, "fixture did not contain a .comment section"

    wheel = build_wheel(
        tmp_path / f"fakenobits-1.0-{MANYLINUX}.whl",
        name="fakenobits",
        version="1.0",
        tags=(MANYLINUX,),
        files={"fakenobits/_ext.abi3.so": bytes(payload)},
    )
    record = scan_wheel(wheel, context)  # must return promptly without 3 GiB of RSS
    assert record["wheel"]["name"] == "fakenobits"


# --- M6: record size must be bounded in member count too --------------------


def test_a_wheel_with_thousands_of_objects_produces_a_bounded_record(
    context, tmp_path: Path
) -> None:
    tiny = ElfBuilder(needed=("libc.so.6",)).build()
    files = {f"many/_ext{index:05d}.so": tiny for index in range(3000)}
    wheel = build_wheel(
        tmp_path / f"many-1.0-{MANYLINUX}.whl",
        name="many",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
    )
    record = scan_wheel(wheel, context)
    assert len(json.dumps(record)) < 2_000_000, "one record grew past two megabytes"
    assert record["artifacts"]["binaries_truncated"] is True


# --- L6: dedup and sort must agree -------------------------------------------


def test_sbom_component_sort_key_covers_every_field_dedup_uses() -> None:
    """Otherwise two components differing only by purl tie, and order leaks from a set."""
    first = SbomComponent(name="ring", version="0.17.8", purl="pkg:cargo/ring@0.17.8", source="s")
    second = SbomComponent(name="ring", version="0.17.8", purl="pkg:generic/ring", source="s")
    assert first != second
    assert first.sort_key() != second.sort_key()


# --- H7: a streamed member must not re-decompress per symbol ----------------


def test_a_streamed_member_serves_backward_seeks_from_its_window(tmp_path: Path) -> None:
    """ELF readers alternate between .dynsym and .dynstr; without a window that is
    one full decompression per symbol."""
    import io
    import zipfile as zf

    from wheel_crypto_scan.wheelfile import SeekableZipMember

    payload = bytes(range(256)) * 4096  # 1 MiB
    path = tmp_path / "w.zip"
    with zf.ZipFile(path, "w", zf.ZIP_DEFLATED) as archive:
        archive.writestr(zf.ZipInfo("blob.bin", date_time=FIXED_DATE), payload)

    with zf.ZipFile(path) as archive:
        member = SeekableZipMember(archive, "blob.bin", len(payload), 2 * 1024 * 1024)
        stream = io.BufferedReader(member)
        stream.read(len(payload))
        for offset in range(0, len(payload), 4096):
            stream.seek(offset)
            assert stream.read(8) == payload[offset : offset + 8]
        assert member.reopens == 1, f"re-decompressed {member.reopens} times"
        stream.close()


def test_a_backward_seek_outside_the_window_is_still_correct(tmp_path: Path) -> None:
    """Falling out of the window must re-open, not silently read the wrong offset."""
    import io
    import zipfile as zf

    from wheel_crypto_scan.wheelfile import SeekableZipMember

    payload = bytes(range(256)) * 4096
    path = tmp_path / "w.zip"
    with zf.ZipFile(path, "w", zf.ZIP_DEFLATED) as archive:
        archive.writestr(zf.ZipInfo("blob.bin", date_time=FIXED_DATE), payload)

    with zf.ZipFile(path) as archive:
        member = SeekableZipMember(archive, "blob.bin", len(payload), window_bytes=0)
        stream = io.BufferedReader(member)
        stream.seek(len(payload) - 16)
        assert stream.read(8) == payload[-16:-8]
        stream.seek(0)
        assert stream.read(8) == payload[:8]
        assert member.reopens > 1
        stream.close()


# --- H6: unparsed Python must not read as clean -----------------------------


def test_a_wheel_whose_only_source_fails_to_parse_is_opaque(context, tmp_path: Path) -> None:
    """Otherwise its verdict block is byte-identical to a genuinely clean wheel's."""
    wheel = build_wheel(
        tmp_path / "broken-1.0-py3-none-any.whl",
        name="broken",
        version="1.0",
        files={"broken/__init__.py": b"def f(:\n    pass\n"},
    )
    record = scan_wheel(wheel, context)
    assert record["artifacts"]["py_files"] == 1
    assert record["artifacts"]["py_files_unparsed"] == 1
    assert record["artifacts"]["source_available"] is False
    assert record["verdict"]["class"] == "OPAQUE"
    assert record["verdict"]["needs_human_review"] is True


def test_one_unparsed_file_among_many_does_not_make_the_wheel_opaque(
    context, tmp_path: Path
) -> None:
    files = {f"ok/mod{index}.py": b"VALUE = 1\n" for index in range(5)}
    files["ok/broken.py"] = b"def f(:\n"
    wheel = build_wheel(tmp_path / "ok-1.0-py3-none-any.whl", name="ok", version="1.0", files=files)
    record = scan_wheel(wheel, context)
    assert record["artifacts"]["py_files_unparsed"] == 1
    assert record["artifacts"]["source_available"] is True
    assert record["verdict"]["class"] == "NO_CRYPTO_DETECTED"
