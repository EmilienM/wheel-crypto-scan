"""Hardening against malformed and hostile input.

Every test here corresponds to a reproduced failure mode: a wheel that reads as clean
because it cannot be examined, an exception that escapes and destroys a run, or a
cache that serves the wrong record.
"""

from __future__ import annotations

import io
import json
import struct
import time
import tracemalloc
import warnings
import zipfile
import zlib
from pathlib import Path

import pytest
from helpers.binfmt import (
    SHF_COMPRESSED,
    DynSym,
    ElfBuilder,
    MachOBuilder,
    MachOSym,
    PEBuilder,
    PEExport,
    PEImport,
    STB_GLOBAL,
    append_strtab_decoy,
    patch_header_field,
    patch_section_header,
)
from helpers.wheelbuilder import build_wheel


from wheel_crypto_scan import errors
from wheel_crypto_scan.binfmt import pe, symtab
from wheel_crypto_scan.binfmt.elf import read_elf
from wheel_crypto_scan.binfmt.macho import read_macho
from wheel_crypto_scan.binfmt.rust import find_rust_crates
from wheel_crypto_scan.cli import main
from wheel_crypto_scan.evidence import SbomComponent
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.scan import ScanContext, scan_wheel
from wheel_crypto_scan.wheelfile import ArchiveLimits, WheelArchive

MANYLINUX = "cp39-abi3-manylinux_2_28_x86_64"
MACOS = "cp312-cp312-macosx_11_0_arm64"
WINDOWS = "cp312-cp312-win_amd64"
FIXED_DATE = (1980, 1, 1, 0, 0, 0)


@pytest.fixture(scope="module")
def context() -> ScanContext:
    return ScanContext.build(load_ruleset())


def read_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --- an unreadable format must not take its own evidence with it ----------


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


# --- symlink targets must obey the archive limits ---------------------------


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


# --- a corrupt streamed member must not raise -------------------------------


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


# --- two identical archives under different names are two wheels -----------


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


# --- one unreadable file must not destroy the run ---------------------------


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


# --- the limits that change a record belong in the cache key ----------------


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


# --- a BOM must not silently discard every header ---------------------------


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


# --- a declared-huge NOBITS section must not allocate ------------------------


def test_a_nobits_comment_section_does_not_allocate(context, tmp_path: Path) -> None:
    """sh_size is attacker controlled and SHT_NOBITS materialises it as zero bytes."""
    from helpers.binfmt import patch_u16  # noqa: F401  (kept for symmetry)

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

    tracemalloc.start()
    start = time.monotonic()
    record = scan_wheel(wheel, context)  # must return promptly without 3 GiB of RSS
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5, f"the scan took {elapsed:.1f}s"
    # Comfortably above the wheel-scan machinery's own bookkeeping, nowhere near the
    # 3 GiB a reader without this guard would have to materialise to honour the declared size.
    assert peak < 4 * 1024 * 1024, f"peaked at {peak} bytes"
    assert record["wheel"]["name"] == "fakenobits"
    # Pins the NOBITS skip itself, not just the budget check behind it: without it this
    # ordinary object reads OPAQUE with a spurious elf_parse_error.
    assert record["binaries"][0]["partial_analysis"] is False
    assert record["errors"] == []


# --- a SHF_COMPRESSED section's declared size is checked before it is inflated ---
#
# `Chdr.ch_size` is `SHT_NOBITS`'s `sh_size` one call deeper: an attacker-controlled
# 64-bit field, except `Section.data()` actually decompresses that many bytes rather
# than materialising zero ones. Reproduced directly, a 255 KiB object declaring
# 256 MiB peaks at 512 MiB without this guard. These two scale that down to a
# declared 8 MiB against a 64 KiB budget -- the same shape, sized so the mutation
# check (removing the guard and watching this fail) can actually decompress the path
# without the guard in a normal test run rather than skipping it.


def _compressed_chdr(ch_size: int, *, addralign: int = 1) -> bytes:
    """A `SHF_COMPRESSED` section's `Elf64_Chdr`: `ELFCOMPRESS_ZLIB`, declaring `ch_size`."""
    return struct.pack("<IIQQ", 1, 0, ch_size, addralign)


def _compressed_zero_run(size: int) -> bytes:
    """A real, honestly-declared `SHF_COMPRESSED` section of `size` zero bytes.

    All zero compresses to a few KiB regardless of `size`, so the fixture itself, and
    the honest compress/decompress this measures against, stay cheap -- only the
    *declared*, logical size drives what a reader without this guard would inflate.
    """
    return _compressed_chdr(size) + zlib.compress(b"\x00" * size, 9)


def test_a_compressed_elf_rodata_declaring_more_than_the_budget_does_not_allocate(
    context,
) -> None:
    body = _compressed_zero_run(8 * 1024 * 1024)
    data = patch_section_header(
        ElfBuilder(rodata=body).build(), ".rodata", "sh_flags", SHF_COMPRESSED, bitwise_or=True
    )

    tracemalloc.start()
    start = time.monotonic()
    ev, errs = read_elf(
        io.BytesIO(data),
        "mod.so",
        context.patterns.binary,
        vendored=False,
        max_strings_bytes=64 * 1024,
    )
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5, f"the read took {elapsed:.1f}s"
    # Comfortably above the budget's own bookkeeping, nowhere near the 8 MiB a
    # reader without this guard would have to inflate to reach the same declared size.
    assert peak < 2 * 1024 * 1024, f"peaked at {peak} bytes"
    assert ev.partial_analysis is True
    assert "elf_section_data_unread" in ev.partial_reasons
    assert errs != ()


def test_a_compressed_elf_dynstr_declaring_more_than_the_budget_does_not_allocate(
    context,
) -> None:
    """The symbol-table half of the same exposure: `.dynsym`'s string table, resolved
    through a corroborated decoy `SHT_STRTAB` the way the section-lookup tests build
    one, so the fixture can declare and (without the guard) genuinely inflate an 8 MiB
    `.dynstr` without the builder needing a raw-bytes hook for the real one.
    """
    honest = ElfBuilder(dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),)).build()
    body = _compressed_zero_run(8 * 1024 * 1024)
    with_decoy, decoy_index = append_strtab_decoy(honest, body, sh_addr=0)
    with_decoy = patch_section_header(
        with_decoy, "", "sh_flags", SHF_COMPRESSED, bitwise_or=True, occurrence=2
    )
    repointed = patch_section_header(with_decoy, ".dynsym", "sh_link", decoy_index)

    tracemalloc.start()
    start = time.monotonic()
    ev, errs = read_elf(
        io.BytesIO(repointed),
        "mod.so",
        context.patterns.binary,
        vendored=False,
        max_strings_bytes=64 * 1024,
    )
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5, f"the read took {elapsed:.1f}s"
    assert peak < 2 * 1024 * 1024, f"peaked at {peak} bytes"
    assert ev.partial_analysis is True
    assert "elf_dynsym_unread" in ev.partial_reasons
    assert ev.matched_symbols == ()
    assert errs != ()


def test_a_compressed_elf_go_buildinfo_declaring_more_than_the_budget_does_not_allocate(
    context,
) -> None:
    """`.go.buildinfo` is the third call site sharing `_bounded_section_data`, found
    while auditing every `.data()` call in `binfmt/elf.py` for the same exposure
    beyond `.rodata`/`.comment` and `.dynsym`/`.dynstr`. Unlike
    those, `ElfBuilder` accepts `.go.buildinfo`'s raw bytes directly, so no decoy or
    corroboration step is needed to control what it declares.
    """
    body = _compressed_zero_run(8 * 1024 * 1024)
    data = patch_section_header(
        ElfBuilder(go_buildinfo=body).build(),
        ".go.buildinfo",
        "sh_flags",
        SHF_COMPRESSED,
        bitwise_or=True,
    )

    tracemalloc.start()
    start = time.monotonic()
    ev, errs = read_elf(
        io.BytesIO(data),
        "mod.so",
        context.patterns.binary,
        vendored=False,
        max_strings_bytes=64 * 1024,
    )
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5, f"the read took {elapsed:.1f}s"
    assert peak < 2 * 1024 * 1024, f"peaked at {peak} bytes"
    assert ev.partial_analysis is True
    assert "elf_go_buildinfo_unread" in ev.partial_reasons
    assert errs != ()


def test_a_nobits_named_go_buildinfo_does_not_allocate(context) -> None:
    """A second, uncompressed exposure at the same call site: `Section.data()` checks
    `SHT_NOBITS` before it checks `compressed` at all, and for a `SHT_NOBITS` section
    returns `b"\\0" * data_size` with no file bytes read to justify the length --
    `sh_size` occupies no file space by definition, so nothing bounds it against the
    object's real size. `.dynsym`/`.dynstr` cannot be aimed at this: both are found by
    `sh_type` itself (`SHT_DYNSYM`/`SHT_STRTAB`), which a section cannot also be
    `SHT_NOBITS`. `.go.buildinfo` is found by name alone, with no `sh_type` check, so
    it is the one call site this is reachable through -- three orders of magnitude
    cheaper to build than the compressed reproduction above: 298 bytes, no zlib.
    """
    small = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16 + b"\x08go1.22.3"
    data = ElfBuilder(go_buildinfo=small).build()
    data = patch_section_header(data, ".go.buildinfo", "sh_type", 8)  # SHT_NOBITS
    data = patch_section_header(data, ".go.buildinfo", "sh_size", 2048 * 1024 * 1024)
    assert len(data) < 512, f"fixture itself is {len(data)} bytes"

    tracemalloc.start()
    start = time.monotonic()
    ev, errs = read_elf(
        io.BytesIO(data),
        "mod.so",
        context.patterns.binary,
        vendored=False,
        max_strings_bytes=64 * 1024,
    )
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5, f"the read took {elapsed:.1f}s"
    assert peak < 2 * 1024 * 1024, f"peaked at {peak} bytes"
    assert ev.partial_analysis is True
    assert "elf_go_buildinfo_unread" in ev.partial_reasons
    assert errs != ()


# --- an ordinary, uncompressed section is checked against the budget too -------
#
# A guard that only refuses before `.data()` runs when the section is `compressed` or
# `SHT_NOBITS` misses an ordinary, honest, uncompressed section -- an honestly large
# `.rodata`, or `.dynsym`/`.dynstr` from a real symbol table -- which falls through
# that `and` entirely and reaches `.data()` with no budget check at all: read in full
# regardless of size, with only the *accumulated* buffer cut afterwards. Reproduced
# directly with that narrower guard: an honest 8 MiB `.rodata` against a 64 KiB budget
# reads it whole (largest single `read()` 8388608 bytes, peak 8605805) and reports
# `strings_bytes_unread` -- truncated after the fact, not refused before it; an honest
# `.dynsym`/`.dynstr` from 200,000 real symbols (~4.8 MiB `.dynstr`) reads whole the
# same way and comes back `partial_analysis: False` -- a fully clean, complete record,
# paid for at the size of the honest table rather than the budget.


def test_an_ordinary_elf_rodata_declaring_more_than_the_budget_does_not_allocate(
    context,
) -> None:
    """The uncompressed counterpart of the compressed `.rodata` hardening test above,
    at the same scale: an honest 8 MiB `.rodata` against a 64 KiB budget, with
    an OpenSSL banner at offset 0 -- comfortably inside the budget -- the same shape
    reachable on a real host library
    (`libLLVM.so`, 68 MiB of eligible sections against the 64 MiB default budget):
    bounding the *read* must not cost the *evidence* a smaller, honest read would
    still recover.
    """
    banner = b"OpenSSL 3.0.14 4 Jun 2024\x00"
    body = banner + b"\x00" * (8 * 1024 * 1024 - len(banner))
    data = ElfBuilder(rodata=body).build()
    stream = _CountingReadStream(data)

    tracemalloc.start()
    start = time.monotonic()
    ev, errs = read_elf(
        stream,
        "mod.so",
        context.patterns.binary,
        vendored=False,
        max_strings_bytes=64 * 1024,
    )
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5, f"the read took {elapsed:.1f}s"
    # Comfortably above the budget's own bookkeeping, nowhere near the 8 MiB a
    # reader without this guard would have to read to reach the same declared size.
    assert peak < 2 * 1024 * 1024, f"peaked at {peak} bytes"
    assert stream.largest_read < 1024 * 1024, (
        f"largest single read() was {stream.largest_read} bytes"
    )
    assert errs == ()
    assert ev.partial_analysis is True
    assert ev.partial_reasons == ("strings_bytes_unread",)
    assert [m.value for m in ev.matched_strings] == ["OpenSSL 3.0.14 4 Jun 2024"]


def test_an_honest_large_dynsym_and_dynstr_does_not_allocate(context) -> None:
    """The `.dynsym`/`.dynstr` half of the same exposure, for an honest, real symbol
    table rather than a crafted lie -- the same reproduction as above, scaled down only
    in how the fixture is built (200,000 distinct real names, builds in well under a
    second).

    Correctness matters as much as cost here: without this guard, this reads in full
    regardless of `max_strings_bytes` and comes back `partial_analysis: false`, a fully
    clean, complete record -- silently losing the fact that a crypto-matching name in
    this table was never actually resolved. Refusing the read must not fall into the
    same silence from the other direction: it has to flag `elf_dynsym_unread`, not
    just cost less.
    """
    names = (DynSym("EVP_DigestInit_ex", defined=False),) + tuple(
        DynSym(f"sym_{i:07d}_padding_out_a_realistic_name", defined=False) for i in range(200_000)
    )
    data = ElfBuilder(dynsyms=names).build()
    stream = _CountingReadStream(data)

    tracemalloc.start()
    start = time.monotonic()
    ev, errs = read_elf(
        stream,
        "mod.so",
        context.patterns.binary,
        vendored=False,
        max_strings_bytes=64 * 1024,
    )
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5, f"the read took {elapsed:.1f}s"
    assert peak < 4 * 1024 * 1024, f"peaked at {peak} bytes"
    assert stream.largest_read < 1024 * 1024, (
        f"largest single read() was {stream.largest_read} bytes"
    )
    assert ev.partial_analysis is True
    assert "elf_dynsym_unread" in ev.partial_reasons
    # Refused, not silently shortened: no row from this table is reported as read,
    # crypto-matching or not, which is the honest answer for a table this reader
    # cannot walk.
    assert ev.matched_symbols == ()
    assert errs != ()


def test_a_mach_o_that_declares_a_giant_symbol_table_does_not_allocate(
    context, tmp_path: Path
) -> None:
    """`nsyms` is the Mach-O version of the same attack: a 32-bit count, self-declared.

    Four hundred bytes of object claiming four billion symbols is 64 GiB of nlist
    entries if the reader believes it, so the read is measured against the slice.
    """
    payload = MachOBuilder(
        id_dylib="@rpath/_ext.cpython-312-darwin.so",
        symbols=(MachOSym("_EVP_DigestInit_ex", defined=False),),
        declared_nsyms=0xFFFFFFFF,
        declared_strsize=0xFFFFFFFF,
    ).build()
    wheel = build_wheel(
        tmp_path / f"fatliar-1.0-{MACOS}.whl",
        name="fatliar",
        version="1.0",
        tags=(MACOS,),
        files={"fatliar/_ext.cpython-312-darwin.so": payload},
    )
    record = scan_wheel(wheel, context)  # must return promptly without 64 GiB of RSS
    assert any(e["kind"] == errors.MACHO_PARSE_ERROR for e in record["errors"])
    # The entry that was really there is still evidence, and the object stays partial.
    assert record["binaries"][0]["matched_symbols"]
    assert record["binaries"][0]["partial_analysis"] is True


class _CountingReadStream(io.BytesIO):
    """Remembers the largest single `read()` call it was ever asked to satisfy.

    Proving a read is bounded by a fixed cap, rather than by how large the object
    happens to be, is cheapest measured at the call the reader actually makes, not by
    building an object large enough to feel the difference in wall-clock time or
    `tracemalloc`.
    """

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.largest_read = 0

    def read(self, size: int | None = -1, /) -> bytes:  # type: ignore[override]
        chunk = super().read(size)
        self.largest_read = max(self.largest_read, len(chunk))
        return chunk


def test_a_mach_o_with_a_giant_sizeofcmds_does_not_read_it(context) -> None:
    """`sizeofcmds` is the load-command version of the same 32-bit self-declared-size
    attack `nsyms` has a test for above, handled the same way as a compressed ELF
    section: checked before the read, not clamped after it.

    Scaled down from the 300 MiB member DESIGN.md measures ("sizeofcmds and the symbol
    table are capped, not just clamped to the member"): the property under test is that
    the single `read()` call `_read_thin` makes for the load commands is bounded by
    `_MAX_SIZEOFCMDS`, not by how much padding follows the header, so a few MiB of
    padding proves the same shape at three hundred -- and with the cap in place that
    read is never attempted at all, so the largest read anywhere in the whole call is
    `max_strings_bytes`, from the strings fallback this failure falls back to.
    """
    budget = 64 * 1024
    base = MachOBuilder(load_dylibs=("libcrypto.3.dylib",)).build()
    buf = bytearray(base)
    struct.pack_into("<I", buf, 20, 0xFFFFFFFF)  # mach_header_64.sizeofcmds
    payload = bytes(buf) + b"\x00" * (8 * 1024 * 1024)

    stream = _CountingReadStream(payload)
    start = time.monotonic()
    ev, errs = read_macho(
        stream, "libfoo.dylib", context.patterns.binary, vendored=False, max_strings_bytes=budget
    )
    elapsed = time.monotonic() - start

    assert elapsed < 5, f"the read took {elapsed:.1f}s"
    assert stream.largest_read == budget, f"largest single read() was {stream.largest_read} bytes"
    assert ev.partial_analysis is True
    assert "macho_header_unread" in ev.partial_reasons
    assert any(e.kind == errors.MACHO_PARSE_ERROR for e in errs)


def test_a_mach_o_symbol_table_declaring_more_than_the_budget_does_not_allocate(context) -> None:
    """`nsyms` buys a read (and a walk) proportional to what the header claims when
    `_available` clamps it only to the slice, never to a fixed budget -- the symbol
    table's half of the Mach-O cap, sibling to the ELF `.dynsym`/`.dynstr` budget
    `_bounded_section_data` enforces above. `strsize` shares the same shape and is
    capped the same way.

    Scaled down from the 300 MiB member / 664 MiB peak DESIGN.md measures for the same
    cap: `nsyms` only has to clear a small budget, not 64 MiB, to prove the read is
    capped rather than clamped to the member -- and the member is padded well past that
    budget so the fixed cap, not the slice's own size, is what is doing the work.
    """
    budget = 64 * 1024
    entry_size = 16  # nlist_64
    over_budget_nsyms = (budget // entry_size) + (128 * 1024)  # ~2 MiB of declared rows
    payload = MachOBuilder(
        id_dylib="@rpath/_ext.cpython-312-darwin.so",
        symbols=(MachOSym("_EVP_DigestInit_ex", defined=False),),
        declared_nsyms=over_budget_nsyms,
    ).build()
    # Comfortably more than `over_budget_nsyms * entry_size`, so the slice's own size
    # alone would not bound this either.
    payload += b"\x00" * (4 * 1024 * 1024)

    tracemalloc.start()
    start = time.monotonic()
    ev, errs = read_macho(
        io.BytesIO(payload),
        "mod.so",
        context.patterns.binary,
        vendored=False,
        max_strings_bytes=budget,
    )
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5, f"the read took {elapsed:.1f}s"
    assert peak < 1024 * 1024, f"peaked at {peak} bytes"
    assert ev.partial_analysis is True
    assert "macho_symtab_incomplete" in ev.partial_reasons
    assert any(e.kind == errors.MACHO_PARSE_ERROR for e in errs)
    # The real symbol sits at the start of the table, well inside the budget, so the
    # cap costs the declared tail of the table, not the evidence that was reachable.
    assert ev.matched_symbols


def test_a_mach_o_string_table_declaring_more_than_the_budget_does_not_allocate(context) -> None:
    """`strsize` has the identical shape `nsyms` does above -- a 32-bit, self-declared
    byte count `_available` alone only measures against the slice -- and reading it
    unbounded costs exactly the same way: `_region` serves however many bytes
    `min(symtab.strsize, max_strings_bytes)` asks for, and without that `min` this
    would cost as much as `symtab.strsize` claims, up to the whole member.

    `str_length`'s own `min(symtab.strsize, max_strings_bytes)` needs a test as direct
    as `sym_length`'s: changing it alone to plain `symtab.strsize`, leaving
    `sym_length`'s cap untouched, must not leave the suite green.
    """
    budget = 64 * 1024
    over_budget_strsize = budget + (2 * 1024 * 1024)
    payload = MachOBuilder(
        id_dylib="@rpath/_ext.cpython-312-darwin.so",
        symbols=(MachOSym("_EVP_DigestInit_ex", defined=False),),
        declared_strsize=over_budget_strsize,
    ).build()
    # Comfortably more than `over_budget_strsize`, so the slice's own size alone
    # would not bound this either.
    payload += b"\x00" * (4 * 1024 * 1024)

    tracemalloc.start()
    start = time.monotonic()
    ev, errs = read_macho(
        io.BytesIO(payload),
        "mod.so",
        context.patterns.binary,
        vendored=False,
        max_strings_bytes=budget,
    )
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5, f"the read took {elapsed:.1f}s"
    assert peak < 1024 * 1024, f"peaked at {peak} bytes"
    assert ev.partial_analysis is True
    assert "macho_symtab_incomplete" in ev.partial_reasons
    assert any(e.kind == errors.MACHO_PARSE_ERROR for e in errs)
    # `nsyms` is honest here -- one real entry, well inside the budget -- so the real
    # symbol is still reachable; only the declared string-table tail costs anything.
    assert ev.matched_symbols


def test_a_pe_that_declares_a_giant_export_table_does_not_allocate(context, tmp_path: Path) -> None:
    """`NumberOfNames` is the PE spelling of the same attack: a 32-bit, self-declared count.

    Two kilobytes of object claiming four billion exported names is sixteen gigabytes of
    name pointers if the reader believes it, so every table is measured against the
    section that carries it.
    """
    payload = PEBuilder(
        imports=(PEImport("libcrypto-3-x64.dll", names=("EVP_DigestInit_ex",)),),
        exports=(PEExport("PyInit__ext"),),
        dll_name="_ext.pyd",
        declared_name_count=0xFFFFFFFF,
        declared_function_count=0xFFFFFFFF,
    ).build()
    wheel = build_wheel(
        tmp_path / f"peliar-1.0-{WINDOWS}.whl",
        name="peliar",
        version="1.0",
        tags=(WINDOWS,),
        files={"peliar/_ext.pyd": payload},
    )
    record = scan_wheel(wheel, context)  # must return promptly without 16 GiB of RSS
    assert any(e["kind"] == errors.PE_PARSE_ERROR for e in record["errors"])
    # The import directory that was really there is still evidence, and the object
    # stays partial because its exports were not read.
    assert record["binaries"][0]["needed"] == ["libcrypto-3-x64.dll"]
    assert record["binaries"][0]["partial_analysis"] is True


def test_a_pe_aiming_every_name_at_one_long_string_stays_bounded(context, tmp_path: Path) -> None:
    """The per-name bound multiplies with the name count, and neither factor bounds it.

    Nothing stops every export name pointer aiming at the same long string, so the cost
    is names times bytes: `_MAX_EXPORT_NAMES` is 262,144 and the per-name bound is
    8 KiB, which is two gigabytes of names out of an object that fits in a mail
    attachment. Measured on the reader with a 64 KiB per-name bound and no whole-object
    budget: 4096 names cost 16 s and 269 MB, growing linearly, so the reachable ceiling
    was minutes and gigabytes.

    What makes it expensive is `sanitize`, a per-character pass in Python, so it is the
    bytes resolved that have to be bounded rather than the lookups. `_MAX_NAME_TOTAL_BYTES`
    is that bound, and this test is here because raising a limit is how a limit quietly
    stops being one: the two tests beside this one exist for the same reason.
    """
    long_name = "EVP_x" + "A" * (pe._MAX_NAME_BYTES - 100)
    names = 8192
    exports = tuple(PEExport(f"n{index:06d}") for index in range(names - 1))
    payload = bytearray(
        PEBuilder(
            imports=(PEImport("libcrypto-3-x64.dll", names=("EVP_DigestInit_ex",)),),
            exports=exports + (PEExport(long_name),),
            dll_name="_ext.pyd",
        ).build()
    )
    # Re-aim every name pointer at the one long name, which no builder flag expresses.
    headers = pe._read_headers(bytes(payload))
    image = pe._Image(raw=bytes(payload), sections=headers.sections)
    rva, _size = headers.directories[0]
    directory = image.read(rva, pe._EXPORT_DIRECTORY_SIZE)
    name_count, pointers_rva = (
        struct.unpack_from("<I", directory, 24)[0],
        struct.unpack_from("<I", directory, 32)[0],
    )
    base = image.locate(pointers_rva)[0]
    (target,) = struct.unpack_from("<I", bytes(payload), base + (name_count - 1) * 4)
    for index in range(name_count):
        struct.pack_into("<I", payload, base + index * 4, target)

    wheel = build_wheel(
        tmp_path / f"penames-1.0-{WINDOWS}.whl",
        name="penames",
        version="1.0",
        tags=(WINDOWS,),
        files={"penames/_ext.pyd": bytes(payload)},
    )

    tracemalloc.start()
    start = time.monotonic()
    record = scan_wheel(wheel, context)
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 20, f"the walk took {elapsed:.1f}s"
    assert peak < 128 * 1024 * 1024, f"the walk peaked at {peak / 1024**2:.0f} MiB"
    # Bounded, not abandoned: the names it could afford are read, and the read that
    # stopped short says so rather than reporting an object with no exports.
    assert record["binaries"][0]["partial_analysis"] is True


def test_a_pe_whose_descriptors_share_one_thunk_array_stays_bounded(
    context, tmp_path: Path
) -> None:
    """Two per-scope caps do not bound a walk that can multiply them together.

    Nothing stops every import descriptor pointing its lookup table at the same thunk
    array, so a cap per descriptor and a cap per DLL multiply: 512 descriptors sharing
    one 65,536-entry table is 33.5 million iterations, each appending a fresh string to
    a list that nothing deduplicates. Measured on a reader with per-scope caps and no
    whole-object budget: 0.25 s and 5 MiB per descriptor, i.e. minutes of CPU and
    gigabytes of resident memory out of a wheel under two kilobytes.
    """
    payload = PEBuilder(
        imports=tuple(PEImport(f"d{index:04d}.dll") for index in range(512)),
        shared_thunk_entries=65536,
        exports=(PEExport("PyInit__ext"),),
        dll_name="_ext.pyd",
    ).build()
    wheel = build_wheel(
        tmp_path / f"peboom-1.0-{WINDOWS}.whl",
        name="peboom",
        version="1.0",
        tags=(WINDOWS,),
        files={"peboom/_ext.pyd": payload},
    )

    tracemalloc.start()
    start = time.monotonic()
    record = scan_wheel(wheel, context)
    elapsed = time.monotonic() - start
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 20, f"the walk took {elapsed:.1f}s"
    assert peak < 128 * 1024 * 1024, f"the walk peaked at {peak / 1024**2:.0f} MiB"
    # Exactly the whole-object budget, plus the one export. Deterministic, and the
    # number the wall clock and the memory both follow from.
    assert record["binaries"][0]["symbol_counts"]["symtab"] == 65536 + 1
    # Bounded, not abandoned: every DLL it named is still recorded, and the read that
    # stopped short says so.
    assert len(record["binaries"][0]["needed"]) == 512
    assert record["binaries"][0]["partial_analysis"] is True
    assert any(e["kind"] == errors.PE_PARSE_ERROR for e in record["errors"])


# --- the ELF and Mach-O symbol-name cap and budget ---------------------------


def test_an_elf_aiming_every_dynsym_at_one_over_cap_name_stays_bounded(
    context, tmp_path: Path
) -> None:
    """Every row pointing at the same enormous name would cost rows times its length
    without a per-name bound.

    `ElfBuilder` interns `.dynstr` by exact text, so `rows` symbols sharing one string
    already produce the shape with no manual re-aiming needed: every row's `st_name`
    pointing at the same one offset. Measured without this cap:
    243.7s for 2000 rows against a 2 MiB name. `binfmt.symtab.BoundedNames` bounds the
    per-name search to `_MAX_NAME_BYTES`, so an over-cap name costs one O(cap) search
    once (memoized thereafter) rather than one search per row proportional to its real
    length.
    """
    rows = 2000
    name = "X" * (2 * 1024 * 1024)
    payload = ElfBuilder(dynsyms=tuple(DynSym(name, False) for _ in range(rows))).build()
    wheel = build_wheel(
        tmp_path / f"elfnames-1.0-{MANYLINUX}.whl",
        name="elfnames",
        version="1.0",
        tags=(MANYLINUX,),
        files={"elfnames/_ext.abi3.so": payload},
    )

    start = time.monotonic()
    record = scan_wheel(wheel, context)
    elapsed = time.monotonic() - start

    assert elapsed < 20, f"the walk took {elapsed:.1f}s"
    # Over the cap: unresolved, not truncated into the record.
    assert record["binaries"][0]["matched_symbols"] == []
    assert record["binaries"][0]["partial_analysis"] is True
    assert "elf_dynsym_unread" in record["binaries"][0]["partial_reasons"]


def test_repeated_elf_dynsym_offsets_resolve_the_same_valid_name(context, tmp_path: Path) -> None:
    """The same shape, one name shorter: a table that legitimately repeats one index.

    Without memoizing by string-table offset, each of the 2000 rows below would spend
    its own share of `_MAX_NAME_TOTAL_BYTES` resolving the *same* already-known name,
    exhausting the whole-table budget partway through on an object with exactly one
    honest name in it -- turning a table that carries one valid, well-under-cap symbol
    into one `partial_analysis` reports as incomplete. `BoundedNames` resolves an
    offset once and returns the cached answer for every row after, so the budget is
    spent once, not `rows` times, and the object reads as the complete, non-partial
    read it is.
    """
    rows = 2000
    name = "EVP_" + "A" * (symtab._MAX_NAME_BYTES - 100)
    payload = ElfBuilder(dynsyms=tuple(DynSym(name, False) for _ in range(rows))).build()
    wheel = build_wheel(
        tmp_path / f"elfrepeat-1.0-{MANYLINUX}.whl",
        name="elfrepeat",
        version="1.0",
        tags=(MANYLINUX,),
        files={"elfrepeat/_ext.abi3.so": payload},
    )

    start = time.monotonic()
    record = scan_wheel(wheel, context)
    elapsed = time.monotonic() - start

    assert elapsed < 20, f"the walk took {elapsed:.1f}s"
    assert record["binaries"][0]["partial_analysis"] is False
    assert record["binaries"][0]["partial_reasons"] == []
    assert [m["name"] for m in record["binaries"][0]["matched_symbols"]] == [name]


def test_a_mach_o_aiming_every_symbol_at_one_over_cap_name_stays_bounded(
    context, tmp_path: Path
) -> None:
    """The Mach-O counterpart: `n_strx=1` on every row reproduces the shape.

    `MachOBuilder` writes every symbol's own name to the string table regardless of
    `strx`, so the placeholder rows below each add one byte for their own empty name
    and are then re-pointed at the first symbol's, the same "no builder flag expresses
    this" re-aiming `test_a_pe_aiming_every_name_at_one_long_string_stays_bounded` does
    by hand for PE.
    """
    rows = 2000
    name = "_" + "X" * (2 * 1024 * 1024)
    payload = MachOBuilder(
        symbols=(MachOSym(name, False),) + tuple(MachOSym("", False, strx=1) for _ in range(rows))
    ).build()
    wheel = build_wheel(
        tmp_path / f"machonames-1.0-{MACOS}.whl",
        name="machonames",
        version="1.0",
        tags=(MACOS,),
        files={"machonames/_ext.cpython-312-darwin.so": payload},
    )

    start = time.monotonic()
    record = scan_wheel(wheel, context)
    elapsed = time.monotonic() - start

    assert elapsed < 20, f"the walk took {elapsed:.1f}s"
    assert record["binaries"][0]["matched_symbols"] == []
    assert record["binaries"][0]["partial_analysis"] is True
    assert "macho_symtab_incomplete" in record["binaries"][0]["partial_reasons"]


def test_repeated_mach_o_symbol_offsets_resolve_the_same_valid_name(
    context, tmp_path: Path
) -> None:
    """The Mach-O counterpart of the ELF budget/memoization test above."""
    rows = 2000
    name = "_EVP_" + "A" * (symtab._MAX_NAME_BYTES - 100)
    payload = MachOBuilder(
        symbols=(MachOSym(name, False),) + tuple(MachOSym("", False, strx=1) for _ in range(rows))
    ).build()
    wheel = build_wheel(
        tmp_path / f"machorepeat-1.0-{MACOS}.whl",
        name="machorepeat",
        version="1.0",
        tags=(MACOS,),
        files={"machorepeat/_ext.cpython-312-darwin.so": payload},
    )

    start = time.monotonic()
    record = scan_wheel(wheel, context)
    elapsed = time.monotonic() - start

    assert elapsed < 20, f"the walk took {elapsed:.1f}s"
    assert record["binaries"][0]["partial_analysis"] is False
    assert [m["name"] for m in record["binaries"][0]["matched_symbols"]] == [name[1:]]


def test_a_mach_o_aiming_every_alias_at_one_over_cap_target_stays_bounded(
    context, tmp_path: Path
) -> None:
    """`N_INDR`'s target is a string-table offset too, so the per-name cap must bound
    it the same way it bounds `n_strx`.

    `MachOBuilder` interns `indirect_to` by exact text the same way `ElfBuilder` interns
    `.dynstr`, so `rows` symbols all aliasing one string already produce the shape: every
    row's `n_value` pointing at the same one offset, with no manual re-aiming needed.
    Measured without the bound at this call site: 200 rows against a 2 MiB target cost
    30.4s, linear in rows -- the identical shape the per-name cap bounds for `n_strx`,
    through the same `resolver` in scope for this function.
    """
    rows = 2000
    target = "_" + "X" * (2 * 1024 * 1024)
    symbols = tuple(
        MachOSym(f"_local_alias_{i}", defined=True, indirect_to=target) for i in range(rows)
    )
    payload = MachOBuilder(symbols=symbols).build()
    wheel = build_wheel(
        tmp_path / f"machoalias-1.0-{MACOS}.whl",
        name="machoalias",
        version="1.0",
        tags=(MACOS,),
        files={"machoalias/_ext.cpython-312-darwin.so": payload},
    )

    start = time.monotonic()
    record = scan_wheel(wheel, context)
    elapsed = time.monotonic() - start

    assert elapsed < 20, f"the walk took {elapsed:.1f}s"
    # Over the cap: not evidence (the target names nothing a rule claims), and correctly
    # not partial either -- an ordinary long non-crypto string costs nothing to leave
    # unresolved, the same as a huge non-crypto ordinary name would. See the paired test
    # below for a target that *is* crypto-relevant, where the object must not read clean.
    assert record["binaries"][0]["matched_symbols"] == []
    assert record["binaries"][0]["partial_analysis"] is False


def test_a_mach_o_aiming_every_alias_at_one_over_cap_crypto_target_is_not_read_clean(
    context, tmp_path: Path
) -> None:
    """The over-cap alias target is unaccounted evidence, not a name we quietly drop.

    Unlike an ordinary unresolved name, an unresolved alias target sets no `unresolved`
    counter of its own -- the row's own name is still fine -- but a crypto name sitting
    unaccounted for in `strings` is exactly what `holds_a_name_not_read`'s independent
    scan exists to catch, the same safety net an ordinary hidden name already relies on.
    """
    rows = 2000
    target = "_EVP_" + "A" * (2 * 1024 * 1024)
    symbols = tuple(
        MachOSym(f"_local_alias_{i}", defined=True, indirect_to=target) for i in range(rows)
    )
    payload = MachOBuilder(symbols=symbols).build()
    wheel = build_wheel(
        tmp_path / f"machoaliascrypto-1.0-{MACOS}.whl",
        name="machoaliascrypto",
        version="1.0",
        tags=(MACOS,),
        files={"machoaliascrypto/_ext.cpython-312-darwin.so": payload},
    )

    start = time.monotonic()
    record = scan_wheel(wheel, context)
    elapsed = time.monotonic() - start

    assert elapsed < 20, f"the walk took {elapsed:.1f}s"
    assert record["binaries"][0]["matched_symbols"] == []
    assert record["binaries"][0]["partial_analysis"] is True
    assert "macho_symtab_incomplete" in record["binaries"][0]["partial_reasons"]


def test_repeated_mach_o_alias_targets_resolve_the_same_valid_name(context, tmp_path: Path) -> None:
    """The alias-target counterpart of the ordinary-name memoization test above.

    Without memoizing by string-table offset, each of the 2000 aliases below would
    spend its own share of `_MAX_NAME_TOTAL_BYTES` resolving the *same* already-known
    target, exhausting the whole-table budget partway through an object that carries
    exactly one real, honest, well-under-cap target.
    """
    rows = 2000
    target = "_EVP_" + "A" * (symtab._MAX_NAME_BYTES - 100)
    symbols = tuple(
        MachOSym(f"_local_alias_{i}", defined=True, indirect_to=target) for i in range(rows)
    )
    payload = MachOBuilder(symbols=symbols).build()
    wheel = build_wheel(
        tmp_path / f"machoaliasrepeat-1.0-{MACOS}.whl",
        name="machoaliasrepeat",
        version="1.0",
        tags=(MACOS,),
        files={"machoaliasrepeat/_ext.cpython-312-darwin.so": payload},
    )

    start = time.monotonic()
    record = scan_wheel(wheel, context)
    elapsed = time.monotonic() - start

    assert elapsed < 20, f"the walk took {elapsed:.1f}s"
    assert record["binaries"][0]["partial_analysis"] is False
    assert [m["name"] for m in record["binaries"][0]["matched_symbols"]] == [target[1:]]


# --- record size must be bounded in member count too -------------------------


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


# --- a cap on the record must not cap what a rule sees -----------------------


def _crypto_past_the_cap_wheel(tmp_path: Path, filler_count: int = 256):
    """`filler_count` filler `.so` objects plus one static-OpenSSL object that sorts
    last by path, so it lands at index `filler_count` (the `filler_count + 1`th
    object)."""
    tiny = ElfBuilder(needed=("libc.so.6",)).build()
    crypto = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("EVP_DigestInit_ex", True),),
        rodata=b"\x00OpenSSL 3.0.14 4 Jun 2024\x00",
    ).build()
    files = {f"pkg/_ext{i:04d}.so": tiny for i in range(filler_count)}
    files["pkg/_zzz_crypto.so"] = crypto  # sorts last, past a 256-object cap
    return build_wheel(
        tmp_path / f"crypto257-1.0-{MANYLINUX}.whl",
        name="crypto257",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
    )


def test_an_object_past_the_binaries_cap_is_still_evaluated(context, tmp_path: Path) -> None:
    """256 filler objects plus one crypto object that sorts 257th must still read as
    crypto: the rules run over every object that was actually read, not just the
    ones that fit in the record's capped `binaries[]` list."""
    wheel = _crypto_past_the_cap_wheel(tmp_path)
    record = scan_wheel(wheel, context)

    assert record["verdict"]["class"] != "NO_CRYPTO_DETECTED"
    assert record["verdict"]["needs_human_review"] is True
    assert "BIN_STATIC_OPENSSL" in record["verdict"]["rule_ids"]
    assert record["verdict"]["conditions"]["openssl_linkage"] == "static"


def test_the_binaries_cap_still_bounds_the_serialised_record(context, tmp_path: Path) -> None:
    """Evaluation sees every object, but `binaries[]` itself
    still stops at `max_binaries_per_record` -- the record must not grow unbounded
    just because evaluation does not."""
    wheel = _crypto_past_the_cap_wheel(tmp_path)
    record = scan_wheel(wheel, context)

    assert len(record["binaries"]) == context.max_binaries_per_record
    assert record["artifacts"]["binaries_truncated"] is True
    # The crypto object sorts last, past a plain prefix, but a finding names it, so the
    # finding-aware selection keeps it -- at the cost of the one filler object that
    # would otherwise have been the last one in. See the tests below and DESIGN.md,
    # "`binaries[]` keeps what a finding points at, before filling the rest".
    assert any(binary["path"] == "pkg/_zzz_crypto.so" for binary in record["binaries"])
    symbol_finding = next(
        f for f in record["findings"] if f["rule_id"] == "BIN_OPENSSL_SYMBOLS_DEFINED"
    )
    assert symbol_finding["locations"][0]["path"] == "pkg/_zzz_crypto.so"


def test_binaries_truncated_becomes_a_finding_naming_the_full_count(
    context, tmp_path: Path
) -> None:
    """The transparency half of the cap: a human reading one JSON line must be able to
    see that `binaries[]` is a prefix, without knowing in advance to check
    `artifacts.binaries_truncated`."""
    wheel = _crypto_past_the_cap_wheel(tmp_path)
    record = scan_wheel(wheel, context)

    truncated = [f for f in record["findings"] if f["rule_id"] == "WHEEL_BINARIES_TRUNCATED"]
    assert len(truncated) == 1
    assert truncated[0]["verdict"] is None
    assert truncated[0]["needs_human_review"] is False
    assert "257" in truncated[0]["locations"][0]["evidence"]


def test_binaries_truncated_finding_does_not_fire_under_the_cap(context, tmp_path: Path) -> None:
    """The negative half of the same guard: a wheel that never hits the cap must not
    carry a WHEEL_BINARIES_TRUNCATED finding, or the rule is not actually reading the
    flag."""
    wheel = _crypto_past_the_cap_wheel(tmp_path, filler_count=10)
    record = scan_wheel(wheel, context)

    assert record["artifacts"]["binaries_truncated"] is False
    assert not any(f["rule_id"] == "WHEEL_BINARIES_TRUNCATED" for f in record["findings"])


# --- binaries[] keeps what a finding points at, before filling the rest ------


def _sorts_last_referenced_objects_wheel(tmp_path: Path, filler_count: int = 300):
    """`filler_count` inert filler objects, plus a partial ELF carrying an OpenSSL
    banner (`zz1_broken.so`) and an unparseable object (`zz2_opaque.so`), both sorting
    after every filler."""
    tiny = ElfBuilder(needed=("libc.so.6",)).build()
    broken = patch_header_field(
        patch_header_field(
            ElfBuilder(rodata=b"\x00OpenSSL 3.0.14 4 Jun 2024\x00").build(), "e_shnum", 0
        ),
        "e_shoff",
        0,
    )
    # Starts with the ELF magic, so it is sniffed as ELF, but has nothing past it for
    # `ELFFile` to read -- `binary_unknown_format`, not a truncation this reader can
    # name more specifically. Padded to the archive's own minimum binary-member size.
    opaque = b"\x7fELF" + b"\x00" * 60
    files = {f"pkg/_ext{i:04d}.so": tiny for i in range(filler_count)}
    files["pkg/zz1_broken.so"] = broken
    files["pkg/zz2_opaque.so"] = opaque
    return build_wheel(
        tmp_path / f"sortslast-1.0-{MANYLINUX}.whl",
        name="sortslast",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
    )


def test_finding_referenced_objects_sorting_last_still_appear_in_binaries(
    context, tmp_path: Path
) -> None:
    """Every object is evaluated regardless of the cap; this is the other half -- a
    human reading the record must be able to corroborate the verdict against the
    objects that actually earned it, not just whichever 256 objects happened to sort
    first. Mirrors what `caps.cap` does for the per-binary string/symbol/crate caps one
    layer down (DESIGN.md, "A cap bounds the record, it does not pick the evidence")."""
    wheel = _sorts_last_referenced_objects_wheel(tmp_path)
    record = scan_wheel(wheel, context)

    assert record["verdict"]["class"] == "CONDITIONAL"
    assert record["verdict"]["needs_human_review"] is True
    assert {"BIN_OPAQUE", "BIN_PARTIAL_FORMAT", "BIN_STATIC_OPENSSL", "BIN_UNPARSEABLE"} <= set(
        record["verdict"]["rule_ids"]
    )

    paths = {binary["path"] for binary in record["binaries"]}
    assert "pkg/zz1_broken.so" in paths
    assert "pkg/zz2_opaque.so" in paths
    # Still bounded: a cap that keeps the referenced objects must not stop being a
    # cap. The remaining room is filled with fillers, the same as a plain prefix.
    assert len(record["binaries"]) == context.max_binaries_per_record
    assert record["artifacts"]["binaries_truncated"] is True


def test_the_binaries_truncated_finding_still_fires_with_finding_aware_selection(
    context, tmp_path: Path
) -> None:
    """`WHEEL_BINARIES_TRUNCATED` and `artifacts.binaries_truncated` mean "the listing
    is a prefix of the whole set", never which objects that prefix keeps -- so a
    finding-aware selection must not change whether, or how, they fire."""
    wheel = _sorts_last_referenced_objects_wheel(tmp_path)
    record = scan_wheel(wheel, context)

    truncated = [f for f in record["findings"] if f["rule_id"] == "WHEEL_BINARIES_TRUNCATED"]
    assert len(truncated) == 1
    assert truncated[0]["verdict"] is None
    assert truncated[0]["needs_human_review"] is False
    assert "302" in truncated[0]["locations"][0]["evidence"]


def test_finding_referenced_selection_is_deterministic_across_repeated_scans(
    context, tmp_path: Path
) -> None:
    """The finding-aware selection must be exactly as deterministic as a plain prefix.
    `test_parallel_output_matches_serial_output` in test_cli.py pins this across
    `--jobs`; this pins it for the one wheel shaped to actually exercise the selection
    logic, independent of process scheduling."""
    wheel = _sorts_last_referenced_objects_wheel(tmp_path)
    first = scan_wheel(wheel, context)
    second = scan_wheel(wheel, context)

    assert first == second
    assert first["binaries"] == second["binaries"]


# --- L6: dedup and sort must agree -------------------------------------------


def test_sbom_component_sort_key_covers_every_field_dedup_uses() -> None:
    """Otherwise two components differing only by purl tie, and order leaks from a set."""
    first = SbomComponent(name="ring", version="0.17.8", purl="pkg:cargo/ring@0.17.8", source="s")
    second = SbomComponent(name="ring", version="0.17.8", purl="pkg:generic/ring", source="s")
    assert first != second
    assert first.sort_key() != second.sort_key()


# --- a streamed member must not re-decompress per symbol ---------------------


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


# --- unparsed Python must not read as clean -----------------------------------


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


# --- scanning untrusted source must stay silent -----------------------------


def test_parsing_source_with_invalid_escapes_emits_no_warnings(context, tmp_path: Path) -> None:
    """Third-party source is data. Its warnings are not ours to print.

    Scanning a real index leaked 592 SyntaxWarnings to stderr, which corrupts any
    pipeline reading the tool's output and buries genuine messages.
    """
    import warnings as warnings_module

    from wheel_crypto_scan.layers.python_ast import scan_python_source

    source = b'import re\nBAD = "\\420 octal"\nPAT = "\\d+"\n'
    with warnings_module.catch_warnings(record=True) as caught:
        warnings_module.simplefilter("always")
        sites, found = scan_python_source(source, "pkg/mod.py", context.patterns.python)
    assert [str(w.message) for w in caught] == []
    assert found == ()


def test_a_wheel_with_invalid_escapes_still_scans_normally(context, tmp_path: Path) -> None:
    """Silencing the warning must not silence the findings."""
    wheel = build_wheel(
        tmp_path / "noisy-1.0-py3-none-any.whl",
        name="noisy",
        version="1.0",
        files={"noisy/__init__.py": b'import hashlib\nP = "\\d+"\nh = hashlib.md5()\n'},
    )
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "FIPS_BREAKING"


def test_a_fat_binary_that_declares_a_giant_arch_count_does_not_reparse_itself(
    context, tmp_path: Path
) -> None:
    """`nfat_arch` is the third self-declared count, and reading every slice armed it.

    While only the first slice was examined, an over-declared arch table cost nothing.
    Walking all of them turns it into a work multiplier: a few hundred bytes of table
    can name one symbol table tens of thousands of times, each entry a full parse of
    it, on an object that grows by twenty bytes per entry (thirty-two in the 64-bit
    form, which is the cheaper of the two to defend). The count is capped and the
    excess is reported as unread rather than believed.
    """
    thin = MachOBuilder(
        id_dylib="@rpath/_ext.cpython-312-darwin.so",
        symbols=tuple(MachOSym(f"_EVP_Digest{i:05d}", defined=True) for i in range(2000)),
    ).build()
    declared = 60000
    body_at = 8 + declared * 20
    payload = (
        struct.pack(">II", 0xCAFEBABE, declared)
        # Every entry names the same slice, so believing the count is 60000 passes
        # over one symbol table.
        + struct.pack(">iiIII", 7, 0, body_at, len(thin), 0) * declared
        + thin
    )
    wheel = build_wheel(
        tmp_path / f"fatcount-1.0-{MACOS}.whl",
        name="fatcount",
        version="1.0",
        tags=(MACOS,),
        files={"fatcount/_ext.cpython-312-darwin.so": payload},
    )
    started = time.perf_counter()
    record = scan_wheel(wheel, context)  # must return promptly
    assert time.perf_counter() - started < 10
    binary = record["binaries"][0]
    assert binary["partial_analysis"] is True
    # Counted once, for bytes that exist once, rather than once per entry naming them.
    assert binary["symbol_counts"]["symtab"] == 2000


# --- bundled_libs and errors[] are capped too ---------------------------------


def test_a_wheel_vendoring_thousands_of_libraries_produces_a_bounded_bundled_libs_list(
    context, tmp_path: Path
) -> None:
    """`bundled_libs` is a *subset* of `binaries[]`/`extensions`, built from the full,
    untruncated object list independently of `max_binaries_per_record` -- without a cap
    of its own, a wheel vendoring thousands of small libraries under `*.libs/` produces
    a correspondingly unbounded array."""
    tiny = ElfBuilder(needed=("libc.so.6",)).build()
    files = {f"many.libs/libfoo{index:05d}-deadbeef.so": tiny for index in range(3000)}
    wheel = build_wheel(
        tmp_path / f"many-1.0-{MANYLINUX}.whl",
        name="many",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
    )
    record = scan_wheel(wheel, context)
    # A real bound, not a decorative one: without this cap, the same
    # reproduction measures at 274 KB for 5000 objects; this one, capped, is under a
    # third of that even at 3000.
    assert len(json.dumps(record)) < 200_000, "bundled_libs is not actually bounded"
    assert len(record["artifacts"]["bundled_libs"]) == context.max_binaries_per_record
    assert record["artifacts"]["bundled_libs_truncated"] is True


def test_a_small_bundle_does_not_report_bundled_libs_truncated(context, tmp_path: Path) -> None:
    """The negative half of the same guard: a wheel that never hits the cap must not
    claim it did."""
    tiny = ElfBuilder(needed=("libc.so.6",)).build()
    wheel = build_wheel(
        tmp_path / f"small-1.0-{MANYLINUX}.whl",
        name="small",
        version="1.0",
        tags=(MANYLINUX,),
        files={"small.libs/libfoo-deadbeef.so": tiny},
    )
    record = scan_wheel(wheel, context)
    assert record["artifacts"]["bundled_libs"] == ["small.libs/libfoo-deadbeef.so"]
    assert record["artifacts"]["bundled_libs_truncated"] is False
    assert record["errors_truncated"] is False


def test_exactly_the_cap_worth_of_libraries_is_not_reported_as_truncated(
    context, tmp_path: Path
) -> None:
    """The boundary the flag must get exactly right: a wheel landing precisely on
    `max_binaries_per_record` fits without being cut, so the flag must read `False`,
    not just "close to it"."""
    tiny = ElfBuilder(needed=("libc.so.6",)).build()
    count = context.max_binaries_per_record
    files = {f"exact.libs/libfoo{index:05d}-deadbeef.so": tiny for index in range(count)}
    wheel = build_wheel(
        tmp_path / f"exact-1.0-{MANYLINUX}.whl",
        name="exact",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
    )
    record = scan_wheel(wheel, context)
    assert len(record["artifacts"]["bundled_libs"]) == count
    assert record["artifacts"]["bundled_libs_truncated"] is False


def test_a_wheel_with_thousands_of_the_same_error_produces_a_bounded_errors_list(
    context, tmp_path: Path
) -> None:
    """`errors[]` needs its own cap -- a wheel that hits the same recordable failure on
    thousands of members produces a correspondingly unbounded JSON line. Measured at
    5000 vendored objects, a 274 KB line."""
    # Starts with the ELF magic, so it is sniffed as ELF, but has nothing past it for
    # `ELFFile` to read: one `binary_unknown_format` error per member, same (stage,
    # kind) pair three thousand times over.
    opaque = b"\x7fELF" + b"\x00" * 60
    files = {f"many/_ext{index:05d}.so": opaque for index in range(3000)}
    wheel = build_wheel(
        tmp_path / f"broken-1.0-{MANYLINUX}.whl",
        name="broken",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
    )
    record = scan_wheel(wheel, context)
    # A real bound, not a decorative one: without this cap, the same
    # reproduction measures at 274 KB for 5000 objects; this one, capped, is under a
    # third of that even at 3000.
    assert len(json.dumps(record)) < 200_000, "errors[] is not actually bounded"
    assert len(record["errors"]) == context.max_binaries_per_record
    assert record["errors_truncated"] is True


def test_a_rare_error_survives_a_flood_of_a_common_one(context, tmp_path: Path) -> None:
    """The representative-per-kind half of the cap (`ScanError.cap_key`): a wheel
    drowning in one kind of failure must not crowd a different, rarer one out of the
    capped `errors[]`, mirroring the per-binary string/symbol/crate caps and the
    finding-aware cap on `binaries[]` itself."""
    opaque = b"\x7fELF" + b"\x00" * 60
    flood = {f"many/_ext{index:05d}.so": opaque for index in range(3000)}
    # A distinct kind of error, sorting after every flooded path -- a plain
    # path-sorted prefix would drop it. Padded past _SNIFF_MIN_BYTES so it is
    # still opened as a candidate binary member at all.
    files = {**flood, "zzz_archive.a": b"!<arch>\n" + b"\x00" * 64}
    wheel = build_wheel(
        tmp_path / f"mixed-1.0-{MANYLINUX}.whl",
        name="mixed",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
    )
    record = scan_wheel(wheel, context)
    assert record["errors_truncated"] is True
    kinds = {error["kind"] for error in record["errors"]}
    assert kinds == {"binary_unknown_format", "ar_parse_error"}


def test_exactly_the_cap_worth_of_errors_is_not_reported_as_truncated(
    context, tmp_path: Path
) -> None:
    """The same boundary as `bundled_libs`, for `errors[]`: landing precisely on
    `max_binaries_per_record` errors must not read as truncated, even though every one
    of them shares the same `(stage, kind)` pair -- `cap` only reaches its per-key
    representative pass once `len(ordered) > limit`, so an exact fit must return
    everything untouched regardless of how many keys collide."""
    count = context.max_binaries_per_record
    opaque = b"\x7fELF" + b"\x00" * 60
    files = {f"many/_ext{index:05d}.so": opaque for index in range(count)}
    wheel = build_wheel(
        tmp_path / f"exact-1.0-{MANYLINUX}.whl",
        name="exact",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
    )
    record = scan_wheel(wheel, context)
    assert len(record["errors"]) == count
    assert record["errors_truncated"] is False


# --- skipped and symlinks are capped too ---------------------------------------


@pytest.fixture(scope="module")
def tiny_member_context() -> ScanContext:
    """A separate context, not the module's shared `context`: a `max_member_bytes` this
    small would make every other test's fixtures unreadable."""
    return ScanContext.build(load_ruleset(), archive_limits=ArchiveLimits(max_member_bytes=8))


def test_a_wheel_with_thousands_of_refused_members_produces_a_bounded_skipped_list(
    tiny_member_context, tmp_path: Path
) -> None:
    """`artifacts.skipped` needs a cap of its own too: without one, a wheel with 3000
    members refused by `ArchiveLimits.max_member_bytes` produces a correctly capped
    `errors: 256` beside an uncapped `artifacts.skipped: 3003`, a 220 KB record whose
    own `errors_truncated` gives no hint that `skipped` is also incomplete."""
    files = {f"many/_ext{index:05d}.so": b"x" * 100 for index in range(3000)}
    wheel = build_wheel(
        tmp_path / f"many-1.0-{MANYLINUX}.whl",
        name="many",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
        include_metadata=False,
        include_wheel=False,
        record=False,
    )
    record = scan_wheel(wheel, tiny_member_context)
    assert len(json.dumps(record)) < 200_000, "skipped is not actually bounded"
    assert len(record["artifacts"]["skipped"]) == tiny_member_context.max_binaries_per_record
    assert record["artifacts"]["skipped_truncated"] is True


def test_a_small_number_of_refused_members_does_not_report_skipped_truncated(
    tiny_member_context, tmp_path: Path
) -> None:
    """The negative half of the same guard: a wheel that never hits the cap must not
    claim it did."""
    wheel = build_wheel(
        tmp_path / f"small-1.0-{MANYLINUX}.whl",
        name="small",
        version="1.0",
        tags=(MANYLINUX,),
        files={"small/_ext.so": b"x" * 100},
        include_metadata=False,
        include_wheel=False,
        record=False,
    )
    record = scan_wheel(wheel, tiny_member_context)
    assert record["artifacts"]["skipped"] == [
        {"path": "small/_ext.so", "reason": "binary_too_large"}
    ]
    assert record["artifacts"]["skipped_truncated"] is False


def test_exactly_the_cap_worth_of_skipped_is_not_reported_as_truncated(
    tiny_member_context, tmp_path: Path
) -> None:
    """The same boundary as `bundled_libs`/`errors[]`: landing precisely on
    `max_binaries_per_record` refused members must not read as truncated."""
    count = tiny_member_context.max_binaries_per_record
    files = {f"exact/_ext{index:05d}.so": b"x" * 100 for index in range(count)}
    wheel = build_wheel(
        tmp_path / f"exact-1.0-{MANYLINUX}.whl",
        name="exact",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
        include_metadata=False,
        include_wheel=False,
        record=False,
    )
    record = scan_wheel(wheel, tiny_member_context)
    assert len(record["artifacts"]["skipped"]) == count
    assert record["artifacts"]["skipped_truncated"] is False


def _build_symlink_wheel(path: Path, count: int, *, target: bytes = b"libfoo.so.1") -> Path:
    """A wheel whose only members are symlinks -- no metadata needed, since only
    `artifacts.symlinks` is under test here, the same minimal shape
    `test_an_oversized_symlink_does_not_bloat_the_record` uses."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for index in range(count):
            info = zipfile.ZipInfo(f"many/lib{index:05d}.so", date_time=FIXED_DATE)
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, target)
    return path


def test_a_wheel_with_thousands_of_symlinks_produces_a_bounded_symlinks_list(
    context, tmp_path: Path
) -> None:
    """`artifacts.symlinks` needs the same bound `bundled_libs`/`errors[]` get: a
    wheel with thousands of symlinked members must not produce a correspondingly
    unbounded array."""
    wheel = _build_symlink_wheel(tmp_path / f"many-1.0-{MANYLINUX}.whl", 3000)
    record = scan_wheel(wheel, context)
    assert len(json.dumps(record)) < 200_000, "symlinks is not actually bounded"
    assert len(record["artifacts"]["symlinks"]) == context.max_binaries_per_record
    assert record["artifacts"]["symlinks_truncated"] is True


def test_a_small_number_of_symlinks_does_not_report_symlinks_truncated(
    context, tmp_path: Path
) -> None:
    wheel = _build_symlink_wheel(tmp_path / f"small-1.0-{MANYLINUX}.whl", 1)
    record = scan_wheel(wheel, context)
    assert record["artifacts"]["symlinks"] == [
        {"path": "many/lib00000.so", "target": "libfoo.so.1"}
    ]
    assert record["artifacts"]["symlinks_truncated"] is False


def test_exactly_the_cap_worth_of_symlinks_is_not_reported_as_truncated(
    context, tmp_path: Path
) -> None:
    count = context.max_binaries_per_record
    wheel = _build_symlink_wheel(tmp_path / f"exact-1.0-{MANYLINUX}.whl", count)
    record = scan_wheel(wheel, context)
    assert len(record["artifacts"]["symlinks"]) == count
    assert record["artifacts"]["symlinks_truncated"] is False


def test_a_rare_skipped_reason_survives_a_flood_of_a_common_one(
    tiny_member_context, tmp_path: Path
) -> None:
    """The representative-per-reason half of the cap: `skipped`'s `reason` is
    `ScanError.kind` projected onto `(path, kind)`, the same axis `ScanError.cap_key`
    already protects for `errors[]` -- a flood of one reason must not crowd a
    different, rarer one out of the capped `skipped`, mirroring
    `test_a_rare_error_survives_a_flood_of_a_common_one` one array over."""
    path = tmp_path / f"mixed-1.0-{MANYLINUX}.whl"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for index in range(3000):
                archive.writestr(
                    zipfile.ZipInfo(f"many/_ext{index:05d}.so", date_time=FIXED_DATE),
                    b"x" * 100,
                )
            # A distinct reason, sorting after every flooded path -- a plain
            # path-sorted prefix would drop it entirely.
            dup_info = zipfile.ZipInfo("zzz_dup.so", date_time=FIXED_DATE)
            archive.writestr(dup_info, b"x" * 100)
            archive.writestr(dup_info, b"x" * 100)
    record = scan_wheel(path, tiny_member_context)
    assert record["artifacts"]["skipped_truncated"] is True
    reasons = {entry["reason"] for entry in record["artifacts"]["skipped"]}
    assert reasons == {"binary_too_large", "duplicate_member"}


def test_a_rare_symlink_target_survives_a_flood_of_a_common_one(context, tmp_path: Path) -> None:
    """The representative-per-target half of the cap: `target` is the axis a consumer
    actually keys on (a bundled library can be reachable only through the one symlink
    naming it), so a flood of one boring target must not crowd a rare, crypto-relevant
    one out of the capped `symlinks`, mirroring `caps.py`'s own `ring`-behind-`anyhow`
    crate example one array over."""
    path = tmp_path / f"mixed-1.0-{MANYLINUX}.whl"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for index in range(3000):
            info = zipfile.ZipInfo(f"many/lib{index:05d}.so", date_time=FIXED_DATE)
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, b"libfoo.so.1")
        # A distinct, crypto-relevant target, sorting after every flooded path -- a
        # plain path-sorted prefix would drop it entirely.
        rare = zipfile.ZipInfo("zzz/openssl.so", date_time=FIXED_DATE)
        rare.create_system = 3
        rare.external_attr = 0o120777 << 16
        archive.writestr(rare, b"libcrypto.so.3")
    record = scan_wheel(path, context)
    assert record["artifacts"]["symlinks_truncated"] is True
    targets = {entry["target"] for entry in record["artifacts"]["symlinks"]}
    assert targets == {"libfoo.so.1", "libcrypto.so.3"}


def test_a_shrunken_strtab_cannot_hide_a_local_definition(context, tmp_path: Path) -> None:
    """The sole-table path's attack applies equally when `.dynsym` is present.

    `.symtab` keeps every row, every count and every structural check; `.strtab`'s
    `sh_size` is shrunk so the rows point past it. Nothing about the object looks
    wrong, and the definition the rows name is unreachable. Reading `.symtab` for
    local definitions on every dynamically linked object has to answer this the
    same way the `.symtab`-without-`.dynsym` path does, or a statically linked OpenSSL
    hides behind one edited field. Prefiltering the string table with `symbol_locator`
    before walking, to save the walk on tables holding nothing, must not read the
    shrunken `.strtab` as holding nothing and let the object come out
    NO_CRYPTO_DETECTED with `partial_analysis: false`: the prefilter saves
    0.32s against 0.55s on a 26.7 MiB object with half a million symbols, which is not
    worth a silent clean.
    """
    honest = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("PyInit__ext", defined=True),),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()
    shrunken = patch_section_header(honest, ".strtab", "sh_size", 1)

    def record_for(name: str, payload: bytes) -> dict:
        wheel = build_wheel(
            tmp_path / f"{name}-1.0-{MANYLINUX}.whl",
            name=name,
            version="1.0",
            tags=(MANYLINUX,),
            files={"pkg/_ext.abi3.so": payload},
        )
        return scan_wheel(wheel, context)

    intact = record_for("intact", honest)
    assert [m["name"] for m in intact["binaries"][0]["matched_symbols"]] == ["EVP_DigestInit_ex"]
    assert intact["binaries"][0]["partial_analysis"] is False

    hidden = record_for("hidden", shrunken)
    assert hidden["binaries"][0]["matched_symbols"] == []
    assert hidden["binaries"][0]["partial_analysis"] is True
    assert "elf_symtab_unread" in hidden["binaries"][0]["partial_reasons"]
    # The whole point: absence of evidence, recorded as such.
    assert hidden["verdict"]["class"] != "NO_CRYPTO_DETECTED"


def test_a_very_large_symtab_is_walked_in_reasonable_time(context, tmp_path: Path) -> None:
    """Every row of `.symtab` is visited on every dynamically linked object.

    The budget bounds the bytes, not the rows, so the walk is the thing to hold: half a
    million symbols is past anything a real wheel carries and well inside
    `MAX_STRINGS_BYTES`. Measured at 0.55s here, so the assertion has an order of
    magnitude of headroom and still fails a per-row cost ten times higher.
    """
    symbols = tuple(
        DynSym(f"unrelated_symbol_number_{index:07d}", defined=True) for index in range(500_000)
    )
    payload = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("PyInit__ext", defined=True),),
        with_symtab=True,
        symtab_syms=symbols,
    ).build()
    wheel = build_wheel(
        tmp_path / f"bigsymtab-1.0-{MANYLINUX}.whl",
        name="bigsymtab",
        version="1.0",
        tags=(MANYLINUX,),
        files={"pkg/_ext.abi3.so": payload},
    )

    start = time.monotonic()
    record = scan_wheel(wheel, context)
    elapsed = time.monotonic() - start

    assert elapsed < 5, f"the scan took {elapsed:.1f}s"
    assert record["binaries"][0]["matched_symbols"] == []


def test_a_decoy_strtab_cannot_hide_a_local_definition(context, tmp_path: Path) -> None:
    """The half `unresolved` cannot see.

    Point `.symtab`'s `sh_link` at an appended `SHT_STRTAB` of nothing but NULs and
    every row resolves -- to the empty name -- so no row is unresolved, nothing
    matches, and the real names sit unread in the table the decoy displaced. The
    sole-table path catches this through `_any_strtab_holds_a_name_not_read`; the
    supplementary mode runs the same check, or the same object would read clean
    depending only on whether it also has a `.dynsym`.
    """
    honest = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("PyInit__ext", defined=True),),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()
    decoyed, index = append_strtab_decoy(honest, b"\x00" * 64)
    decoyed = patch_section_header(decoyed, ".symtab", "sh_link", index)

    wheel = build_wheel(
        tmp_path / f"decoyed-1.0-{MANYLINUX}.whl",
        name="decoyed",
        version="1.0",
        tags=(MANYLINUX,),
        files={"pkg/_ext.abi3.so": decoyed},
    )
    record = scan_wheel(wheel, context)
    binary = record["binaries"][0]

    assert binary["matched_symbols"] == []
    assert binary["partial_analysis"] is True
    assert "symtab_understates_rows" in binary["partial_reasons"]
    assert record["verdict"]["class"] != "NO_CRYPTO_DETECTED"


def test_a_source_file_symbol_is_not_read_as_a_definition(context, tmp_path: Path) -> None:
    """`.symtab` names translation units, and a linked shared object carries one per
    unit. A file called `EVP_md5.c` must not match a symbol group by coincidence of a
    filename with the code it happens to implement -- which would read as a definition,
    i.e. as a statically linked copy. The sole-table path skips
    `STT_FILE`/`STT_SECTION`, and its tests build relocatable objects, so this is what
    holds the same skip in the supplementary path.
    """
    payload = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("PyInit__ext", defined=True),),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_md5.c", defined=True, info=(STB_GLOBAL << 4) | 4),),  # STT_FILE
    ).build()
    wheel = build_wheel(
        tmp_path / f"srcfile-1.0-{MANYLINUX}.whl",
        name="srcfile",
        version="1.0",
        tags=(MANYLINUX,),
        files={"pkg/_ext.abi3.so": payload},
    )
    record = scan_wheel(wheel, context)
    assert record["binaries"][0]["matched_symbols"] == []
    assert record["verdict"]["conditions"]["openssl_linkage"] == "none"


def test_a_symtab_over_the_budget_says_so(context) -> None:
    """The only place the supplementary mode says "I stopped short".

    A `.symtab` or `.strtab` declaring more bytes than the reader's budget is a table
    whose definitions were never looked at, and an object that carries one must not
    read as one that carries none. Read through `read_elf` directly, the way every
    other budget test here does, because the budget is the reader's argument rather
    than a scan-level setting.
    """
    payload = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("PyInit__ext", defined=True),),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()

    generous, errors = read_elf(
        io.BytesIO(payload),
        "mod.so",
        context.patterns.binary,
        vendored=False,
        max_strings_bytes=64 * 1024,
    )
    assert [match.name for match in generous.matched_symbols] == ["EVP_DigestInit_ex"]
    assert generous.partial_analysis is False

    refused, errors = read_elf(
        io.BytesIO(payload),
        "mod.so",
        context.patterns.binary,
        vendored=False,
        max_strings_bytes=8,
    )
    assert refused.matched_symbols == ()
    assert refused.partial_analysis is True
    assert "elf_symtab_unread" in refused.partial_reasons


# --- the cargo-vendor path pattern must stay linear, not quadratic ----------


def test_cargo_vendor_pattern_stays_linear_over_a_long_run_of_near_misses() -> None:
    """`vendor/a/` repeated with no `.rs` in sight is the pathological input for a
    path pattern that has to look ahead for a file extension: every occurrence of
    `vendor/` is a candidate start, and an unbounded repetition inside re-scans the
    remaining text from each one. The bounded pattern shipped keeps that linear; an
    unbounded version of the same pattern is quadratic here and fails the assert
    within a minute at this size, rather than needing an hour of near-misses to do so.
    """
    conventions = load_ruleset().conventions
    text = "vendor/a/" * 20_000

    start = time.monotonic()
    crates, _ = find_rust_crates(
        text, (conventions.cargo_vendor_path_regex,), max_crates=128, claimed=frozenset()
    )
    elapsed = time.monotonic() - start

    assert crates == ()
    assert elapsed < 2, f"the vendor pattern took {elapsed:.2f}s over 20,000 near-misses"


def test_cargo_vendor_pattern_stays_linear_over_digit_and_dot_near_misses() -> None:
    """`vendor/a/` alone does not exercise what keeps a digit-and-dot run cheap: there is
    nothing after `vendor/` for the name group to walk through, and no `-` to try the
    version group at. A run built from digits and dots is the shape that stresses the
    name class's `.` exclusion: with `.` in the name class, the name and version groups
    can split the same run several ways, which makes this case quadratic. This is a
    guard on that exclusion, not on the `{0,63}` repetition bounds: the same run stays
    linear even with those bounds removed, as long as `.` cannot appear in the name.
    """
    conventions = load_ruleset().conventions
    text = ("vendor/" + "1-1.1.1" * 9 + "/") * 10_000

    start = time.monotonic()
    crates, _ = find_rust_crates(
        text, (conventions.cargo_vendor_path_regex,), max_crates=128, claimed=frozenset()
    )
    elapsed = time.monotonic() - start

    assert crates == ()
    assert elapsed < 2, f"the vendor pattern took {elapsed:.2f}s over digit/dot near-misses"
