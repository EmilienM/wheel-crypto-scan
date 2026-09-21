"""End-to-end behaviour of the command line: output, parallelism, caching, resume."""

from __future__ import annotations

import itertools
import json
import os
import re
import threading
import warnings
import zipfile
from pathlib import Path

import pytest
from helpers.binfmt import DynSym, ElfBuilder, MachOBuilder, MachOSym, PEBuilder, PEImport
from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan import SCHEMA_VERSION, TOOL_NAME, cli, scan
from wheel_crypto_scan.binfmt import elf, macho, pe
from wheel_crypto_scan.cache import RecordCache
from wheel_crypto_scan.cli import main
from wheel_crypto_scan.evidence import PARTIAL_REASONS
from wheel_crypto_scan.layers import binaries as binaries_layer
from wheel_crypto_scan.layers import python_ast
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.scan import ScanContext

WEAK_HASH_SOURCE = b"import hashlib\n\ndigest = hashlib.md5()\n"
CLEAN_SOURCE = b"VALUES = [1, 2, 3]\n"
MANYLINUX = "cp39-abi3-manylinux_2_28_x86_64"
MACOSX = "cp312-cp312-macosx_11_0_arm64"
WIN_AMD64 = "cp312-cp312-win_amd64"


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    directory = tmp_path / "wheels"
    directory.mkdir()
    build_wheel(
        directory / "weakhash-1.0-py3-none-any.whl",
        name="weakhash",
        version="1.0",
        files={"weakhash/__init__.py": WEAK_HASH_SOURCE},
    )
    build_wheel(
        directory / "puredata-2.0-py3-none-any.whl",
        name="puredata",
        version="2.0",
        files={"puredata/__init__.py": CLEAN_SOURCE},
    )
    return directory


def read_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --- scanning ---------------------------------------------------------------


def test_one_record_per_wheel(corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    assert main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"]) == 0
    assert len(read_records(out)) == 2


def test_records_are_emitted_in_sorted_filename_order(corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"])
    names = [record["wheel"]["filename"] for record in read_records(out)]
    assert names == sorted(names)


def test_a_weak_hash_call_reaches_the_verdict(corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"])
    record = next(r for r in read_records(out) if r["wheel"]["name"] == "weakhash")
    assert record["verdict"]["class"] == "FIPS_BREAKING"
    assert "PY_WEAK_HASH_CALL" in record["verdict"]["rule_ids"]


def test_a_wheel_with_no_crypto_is_not_asked_to_be_reviewed(corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"])
    record = next(r for r in read_records(out) if r["wheel"]["name"] == "puredata")
    assert record["verdict"]["class"] == "NO_CRYPTO_DETECTED"
    assert record["verdict"]["needs_human_review"] is False


def test_a_corrupt_wheel_still_produces_a_record(tmp_path: Path) -> None:
    """A scan of thirty thousand wheels cannot stop on the first broken one."""
    directory = tmp_path / "wheels"
    directory.mkdir()
    (directory / "broken-1.0-py3-none-any.whl").write_bytes(b"not a zip")
    out = tmp_path / "out.jsonl"
    assert main(["scan", str(directory), "-o", str(out), "--no-cache", "-q"]) == 0
    record = read_records(out)[0]
    assert record["wheel"]["filename"] == "broken-1.0-py3-none-any.whl"
    assert record["verdict"]["class"] == "OPAQUE"
    assert record["errors"]


def test_scanning_nothing_is_an_error(tmp_path: Path) -> None:
    assert main(["scan", "-o", str(tmp_path / "out.jsonl")]) == 2


# --- determinism ------------------------------------------------------------


def test_the_same_corpus_scans_byte_identically(corpus: Path, tmp_path: Path) -> None:
    first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    main(["scan", str(corpus), "-o", str(first), "--no-cache", "-q"])
    main(["scan", str(corpus), "-o", str(second), "--no-cache", "-q"])
    assert first.read_bytes() == second.read_bytes()


def test_parallel_output_matches_serial_output(corpus: Path, tmp_path: Path) -> None:
    """Parallelism must not reorder or change a single byte of the output."""
    serial, parallel = tmp_path / "s.jsonl", tmp_path / "p.jsonl"
    main(["scan", str(corpus), "-o", str(serial), "--jobs", "1", "--no-cache", "-q"])
    main(["scan", str(corpus), "-o", str(parallel), "--jobs", "4", "--no-cache", "-q"])
    assert serial.read_bytes() == parallel.read_bytes()


def test_parallel_output_matches_serial_output_when_binaries_are_capped(tmp_path: Path) -> None:
    """The `binaries[]` cap picks which objects to keep based on `findings`, not just a
    path sort. `--jobs` must not be able to reach that choice -- each wheel is scanned
    end to end inside one worker, but this pins it directly for the one wheel shaped to
    actually exercise the finding-aware selection, rather than relying on the general
    corpus above happening to hit it."""
    directory = tmp_path / "wheels"
    directory.mkdir()
    tiny = ElfBuilder(needed=("libc.so.6",)).build()
    crypto = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("EVP_DigestInit_ex", True),),
        rodata=b"\x00OpenSSL 3.0.14 4 Jun 2024\x00",
    ).build()
    files = {f"pkg/_ext{i:04d}.so": tiny for i in range(260)}
    files["pkg/zzz_crypto.so"] = crypto  # sorts last, past the 256-object cap
    build_wheel(
        directory / f"capped-1.0-{MANYLINUX}.whl",
        name="capped",
        version="1.0",
        tags=(MANYLINUX,),
        files=files,
    )

    serial, parallel = tmp_path / "s.jsonl", tmp_path / "p.jsonl"
    main(["scan", str(directory), "-o", str(serial), "--jobs", "1", "--no-cache", "-q"])
    main(["scan", str(directory), "-o", str(parallel), "--jobs", "4", "--no-cache", "-q"])
    assert serial.read_bytes() == parallel.read_bytes()
    record = read_records(serial)[0]
    assert any(binary["path"] == "pkg/zzz_crypto.so" for binary in record["binaries"])


def test_a_warm_cache_produces_identical_output(corpus: Path, tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cold, warm = tmp_path / "cold.jsonl", tmp_path / "warm.jsonl"
    main(["scan", str(corpus), "-o", str(cold), "--cache-dir", str(cache), "-q"])
    main(["scan", str(corpus), "-o", str(warm), "--cache-dir", str(cache), "-q"])
    assert cold.read_bytes() == warm.read_bytes()
    assert any(cache.rglob("*.json"))


# --- resume -----------------------------------------------------------------


def test_resume_keeps_records_already_written(corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"])
    complete = out.read_bytes()
    partial = [line for line in complete.decode().splitlines() if "puredata" in line]
    out.write_text("\n".join(partial) + "\n", encoding="utf-8")
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "--resume", "-q"])
    assert len(read_records(out)) == 2


def test_resume_discards_a_truncated_final_line(corpus: Path, tmp_path: Path) -> None:
    """An interrupted run leaves half a record; trusting it would corrupt the output."""
    out = tmp_path / "out.jsonl"
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"])
    text = out.read_text(encoding="utf-8")
    out.write_text(text[: len(text) // 2], encoding="utf-8")
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "--resume", "-q"])
    assert len(read_records(out)) == 2


def test_resume_produces_the_same_bytes_as_a_full_scan(tmp_path: Path) -> None:
    """Parallelism is careful not to reorder output; resume must be too."""
    resume_corpus = tmp_path / "wheels"
    resume_corpus.mkdir()
    for name in ("alpha", "bravo", "charlie", "delta"):
        build_wheel(
            resume_corpus / f"{name}-1.0-py3-none-any.whl",
            name=name,
            version="1.0",
            files={f"{name}/__init__.py": b"import hashlib\nh = hashlib.md5()\n"},
        )
    full = tmp_path / "full.jsonl"
    main(["scan", str(resume_corpus), "-o", str(full), "--no-cache", "-q"])
    expected = full.read_bytes()

    partial = tmp_path / "partial.jsonl"
    lines = expected.decode().splitlines(keepends=True)
    partial.write_text("".join(lines[2:]), encoding="utf-8")
    main(["scan", str(resume_corpus), "-o", str(partial), "--no-cache", "--resume", "-q"])
    assert partial.read_bytes() == expected


# --- transient failures -----------------------------------------------------
#
# A `MemoryError` (or any exception `_collect` did not specifically anticipate) must
# read as `unexpected_error`, never `bad_zip`, and a record carrying it must never be
# treated as a final answer for that wheel -- not by the on-disk cache, and not by
# `--resume` reading its own prior output back. Both are exercised through
# `cli._scan_path` / `cli.main` directly rather than `scan_wheel` alone, because the
# risk is not in what `scan_wheel` returns for one call: it is in what the caller
# around it does with that record afterward.


def _flaky_collect(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Patches `scan._collect` to fail once with `MemoryError`, then behave normally."""
    real_collect = scan._collect
    calls = {"n": 0}

    def flaky(*args: object, **kwargs: object) -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            raise MemoryError("simulated transient failure")
        return real_collect(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(scan, "_collect", flaky)
    return calls


def test_a_transient_failure_is_retried_not_served_from_cache_forever(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One `MemoryError` must not calcify into a permanent stale `OPAQUE` record that a
    later, successful attempt never gets to override.
    """
    wheel = build_wheel(
        tmp_path / "flaky-1.0-py3-none-any.whl",
        name="flaky",
        version="1.0",
        files={"flaky/__init__.py": WEAK_HASH_SOURCE},
    )
    calls = _flaky_collect(monkeypatch)
    context = ScanContext.build(load_ruleset())
    monkeypatch.setattr(cli, "_CONTEXT", context)
    monkeypatch.setattr(
        cli,
        "_CACHE",
        RecordCache(
            root=tmp_path / "cache",
            ruleset_version=context.ruleset.version,
            evidence_level="standard",
        ),
    )

    first = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 1
    assert [error["kind"] for error in first["errors"]] == ["unexpected_error"]
    assert first["verdict"]["class"] == "OPAQUE"
    assert "WHEEL_SCAN_INTERRUPTED" in first["verdict"]["rule_ids"]

    second = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 2, "a cached record must not stop the second attempt from happening"
    assert second["errors"] == []
    assert second["verdict"]["class"] == "FIPS_BREAKING"
    assert "PY_WEAK_HASH_CALL" in second["verdict"]["rule_ids"]


def test_a_genuinely_corrupt_zip_is_bad_zip_and_is_not_cached_either(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A malformed zip is a specific, checked claim about the archive's own bytes, so
    it reads as `bad_zip` rather than `unexpected_error`. It is cheap to re-fail --
    nothing past `zipfile.ZipFile()` ever ran -- so it is not cached either, the same
    as an unexpected-error record.
    """
    wheel = tmp_path / "broken-1.0-py3-none-any.whl"
    wheel.write_bytes(b"not a zip")
    context = ScanContext.build(load_ruleset())
    monkeypatch.setattr(cli, "_CONTEXT", context)
    monkeypatch.setattr(
        cli,
        "_CACHE",
        RecordCache(
            root=tmp_path / "cache",
            ruleset_version=context.ruleset.version,
            evidence_level="standard",
        ),
    )

    record = json.loads(cli._scan_path(str(wheel)))
    assert [error["kind"] for error in record["errors"]] == ["bad_zip"]
    assert "WHEEL_UNREADABLE" in record["verdict"]["rule_ids"]
    assert cli._CACHE.get(record["wheel"]["sha256"], wheel.name) is None


def test_a_completed_scan_with_a_recorded_archive_error_is_still_cached(tmp_path: Path) -> None:
    """A duplicate member name is recorded *alongside* a scan that otherwise ran to
    completion, unlike `bad_zip`/`unexpected_error` where nothing past the open ever
    happened. There is a real answer here, and it is not cheap to re-derive, so this
    one must still be cached.
    """
    wheel = build_wheel(
        tmp_path / "dupmember-1.0-py3-none-any.whl",
        name="dupmember",
        version="1.0",
        files={"dupmember/__init__.py": WEAK_HASH_SOURCE},
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr(
                zipfile.ZipInfo("dupmember/__init__.py", date_time=(1980, 1, 1, 0, 0, 0)),
                WEAK_HASH_SOURCE,
            )

    cache_dir = tmp_path / "cache"
    out = tmp_path / "out.jsonl"
    args = ["scan", str(wheel.parent), "-o", str(out), "--cache-dir", str(cache_dir), "-q"]
    assert main(args) == 0
    record = read_records(out)[0]
    assert "duplicate_member" in {error["kind"] for error in record["errors"]}
    assert any(cache_dir.rglob("*.json"))


def test_resume_does_not_treat_an_aborted_scan_as_already_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--resume` reads its own prior output back to decide what to skip. A wheel
    whose only prior record is an aborted scan must be treated as still pending, the
    same way the cache treats it, or a transient failure sticks just as permanently
    through `--resume` as it would through a cache that stored it.
    """
    wheel = build_wheel(
        tmp_path / "flaky-1.0-py3-none-any.whl",
        name="flaky",
        version="1.0",
        files={"flaky/__init__.py": WEAK_HASH_SOURCE},
    )
    calls = _flaky_collect(monkeypatch)
    out = tmp_path / "out.jsonl"

    main(["scan", str(wheel.parent), "-o", str(out), "--no-cache", "-q"])
    first = read_records(out)
    assert len(first) == 1
    assert first[0]["verdict"]["class"] == "OPAQUE"
    assert calls["n"] == 1

    main(["scan", str(wheel.parent), "-o", str(out), "--no-cache", "--resume", "-q"])
    second = read_records(out)
    assert len(second) == 1
    assert calls["n"] == 2, "resume must re-attempt a wheel whose only record is an aborted scan"
    assert second[0]["verdict"]["class"] == "FIPS_BREAKING"


def test_a_transient_member_read_failure_is_retried_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`MEMBER_READ_ERROR` is produced by the same shape of broad catch as
    `UNEXPECTED_ERROR` -- just one layer deeper, around a single member instead of
    the whole archive (`layers/binaries.py` here) -- so it carries the same risk: a
    transient `MemoryError` reading one object must not calcify into a permanently
    missing finding for that object.
    """
    wheel = build_wheel(
        tmp_path / f"fakesodium-1.0-{MANYLINUX}.whl",
        name="fakesodium",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakesodium/_ext.abi3.so": ElfBuilder(
                needed=("libsodium.so.23", "libc.so.6"),
                dynsyms=(DynSym("some_internal_symbol", defined=True),),
            ).build()
        },
    )
    real_read_binary = binaries_layer.read_binary
    calls = {"n": 0}

    def flaky(*args: object, **kwargs: object) -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            raise MemoryError("simulated transient failure")
        return real_read_binary(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(binaries_layer, "read_binary", flaky)
    context = ScanContext.build(load_ruleset())
    monkeypatch.setattr(cli, "_CONTEXT", context)
    monkeypatch.setattr(
        cli,
        "_CACHE",
        RecordCache(
            root=tmp_path / "cache",
            ruleset_version=context.ruleset.version,
            evidence_level="standard",
        ),
    )

    first = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 1
    assert first["binaries"] == []
    assert [error["kind"] for error in first["errors"]] == ["member_read_error"]
    assert first["verdict"]["class"] == "OPAQUE"
    assert "WHEEL_MEMBER_UNREADABLE" in first["verdict"]["rule_ids"]

    second = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 2, "a cached record must not stop the second attempt from happening"
    assert second["errors"] == []
    assert len(second["binaries"]) == 1
    assert second["verdict"]["conditions"]["libsodium_linkage"] == "system"
    assert second["verdict"]["class"] != "NO_CRYPTO_DETECTED"


# `ELF_PARSE_ERROR`, `MACHO_PARSE_ERROR` and `PE_PARSE_ERROR` share the identical risk,
# one layer deeper still: `binfmt/elf.py`, `binfmt/macho.py` and `binfmt/pe.py` each
# catch broadly around their own parsing and record one of these kinds, below where
# `MEMBER_READ_ERROR` is produced.


def _flaky(monkeypatch: pytest.MonkeyPatch, module: object, name: str) -> dict[str, int]:
    """Patches `module.name` to fail once with `MemoryError`, then behave normally.

    A generalisation of `_flaky_collect` above, aimed one layer deeper: the transient
    failure has to be injected inside the binfmt reader itself, not around it, because
    `read_binary`'s own dispatch never sees an exception from `read_elf`/`read_macho`/
    `read_pe` -- each of those already turns a parse failure into a `ScanError` and
    returns normally rather than raising.
    """
    real = getattr(module, name)
    calls = {"n": 0}

    def flaky(*args: object, **kwargs: object) -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            raise MemoryError("simulated transient failure")
        return real(*args, **kwargs)  # type: ignore[misc]

    monkeypatch.setattr(module, name, flaky)
    return calls


def test_a_transient_elf_parse_failure_is_retried_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transient `MemoryError` inside `elf.py`'s own `.dynamic` reading (one layer
    below `MEMBER_READ_ERROR`) must not calcify a lost `DT_NEEDED` entry into a
    permanent record. `_validated_strtab` is on the path both `.dynamic`'s tags and
    `.dynsym`'s string table are read through, so one scan calls it twice -- once for
    each -- and the first of those two calls is the one this test makes fail, which is
    the `.dynamic` block (`read_elf` reads `.dynamic` before `.dynsym`): its own
    `except Exception` is what actually records `elf_parse_error` and loses `needed`
    here.
    """
    wheel = build_wheel(
        tmp_path / f"fakesodium-1.0-{MANYLINUX}.whl",
        name="fakesodium",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakesodium/_ext.abi3.so": ElfBuilder(
                needed=("libsodium.so.23", "libc.so.6"),
                dynsyms=(DynSym("some_internal_symbol", defined=True),),
            ).build()
        },
    )
    calls = _flaky(monkeypatch, elf, "_validated_strtab")
    context = ScanContext.build(load_ruleset())
    monkeypatch.setattr(cli, "_CONTEXT", context)
    monkeypatch.setattr(
        cli,
        "_CACHE",
        RecordCache(
            root=tmp_path / "cache",
            ruleset_version=context.ruleset.version,
            evidence_level="standard",
        ),
    )

    first = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 2, "one call for .dynamic (raises), one for .dynsym (recovers)"
    assert [error["kind"] for error in first["errors"]] == ["elf_parse_error"]
    assert len(first["binaries"]) == 1
    assert first["binaries"][0]["needed"] == []
    assert first["verdict"]["class"] == "OPAQUE"
    assert "BIN_UNPARSEABLE" in first["verdict"]["rule_ids"]

    second = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 4, "a cached record must not stop the second attempt from happening"
    assert second["errors"] == []
    assert second["binaries"][0]["needed"] == ["libc.so.6", "libsodium.so.23"]
    assert second["verdict"]["conditions"]["libsodium_linkage"] == "system"


def test_a_recursion_error_is_retried_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`python_recursion_limit_exceeded` is in `SCAN_ABORTED_KINDS`, unlike the
    `python_syntax_error` kind it shares with a real, permanent `SyntaxError` -- caching
    THAT kind wholesale would mean an ordinary syntax error gets re-scanned forever,
    which is why it stays out. This is the same reproduction shape
    `test_a_transient_elf_parse_failure_is_retried_not_cached` above uses for
    `elf_parse_error`, one layer up in the Python source reader instead of a binary one:
    `ast.parse` fails once with a `RecursionError`, and the second attempt must not be
    served the first attempt's stale, evidence-free record.
    """
    real_parse = python_ast.ast.parse
    calls = {"n": 0}

    def flaky_parse(*args: object, **kwargs: object) -> object:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RecursionError("simulated transient failure")
        return real_parse(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(python_ast.ast, "parse", flaky_parse)
    wheel = build_wheel(
        tmp_path / f"fakecrypto-1.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="1.0",
        files={"fakecrypto/__init__.py": WEAK_HASH_SOURCE},
    )
    context = ScanContext.build(load_ruleset())
    monkeypatch.setattr(cli, "_CONTEXT", context)
    monkeypatch.setattr(
        cli,
        "_CACHE",
        RecordCache(
            root=tmp_path / "cache",
            ruleset_version=context.ruleset.version,
            evidence_level="standard",
        ),
    )

    first = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 1
    assert [error["kind"] for error in first["errors"]] == ["python_recursion_limit_exceeded"]
    assert first["verdict"]["class"] == "OPAQUE"

    second = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 2, "a cached record must not stop the second attempt from happening"
    assert second["errors"] == []
    assert second["verdict"]["class"] != "OPAQUE"


def test_resume_does_not_treat_an_aborted_elf_scan_as_already_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mirrors `test_resume_does_not_treat_an_aborted_scan_as_already_done` for
    `elf_parse_error`: `--resume` must not read a record carrying it as a finished
    answer either.
    """
    wheel = build_wheel(
        tmp_path / f"fakesodium-1.0-{MANYLINUX}.whl",
        name="fakesodium",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakesodium/_ext.abi3.so": ElfBuilder(
                needed=("libsodium.so.23", "libc.so.6"),
                dynsyms=(DynSym("some_internal_symbol", defined=True),),
            ).build()
        },
    )
    calls = _flaky(monkeypatch, elf, "_validated_strtab")
    out = tmp_path / "out.jsonl"

    main(["scan", str(wheel.parent), "-o", str(out), "--no-cache", "-q"])
    first = read_records(out)
    assert len(first) == 1
    assert calls["n"] == 2, "one call for .dynamic (raises), one for .dynsym (recovers)"
    assert [error["kind"] for error in first[0]["errors"]] == ["elf_parse_error"]

    main(["scan", str(wheel.parent), "-o", str(out), "--no-cache", "--resume", "-q"])
    second = read_records(out)
    assert len(second) == 1
    assert calls["n"] == 4, "resume must re-attempt a wheel whose only record is an aborted scan"
    assert second[0]["errors"] == []
    assert second[0]["verdict"]["conditions"]["libsodium_linkage"] == "system"


def test_a_transient_macho_parse_failure_is_retried_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `macho_parse_error` sibling of the ELF reproduction above:
    `_read_slice_header`'s own `except Exception` falls through to the identical broad
    catch once `struct.error` and `_Unreadable` are ruled out, so a transient
    `MemoryError` reading a slice's load commands must not calcify a lost `LC_LOAD_DYLIB`
    dependency into a permanent record.
    """
    wheel = build_wheel(
        tmp_path / f"fakecrypto-1.0-{MACOSX}.whl",
        name="fakecrypto",
        version="1.0",
        tags=(MACOSX,),
        files={
            "fakecrypto/_ext.cpython-312-darwin.so": MachOBuilder(
                load_dylibs=("/usr/lib/libSystem.B.dylib", "/usr/lib/libcrypto.3.dylib"),
                symbols=(MachOSym("_EVP_DigestInit_ex", False),),
            ).build()
        },
    )
    calls = _flaky(monkeypatch, macho, "_read_thin")
    context = ScanContext.build(load_ruleset())
    monkeypatch.setattr(cli, "_CONTEXT", context)
    monkeypatch.setattr(
        cli,
        "_CACHE",
        RecordCache(
            root=tmp_path / "cache",
            ruleset_version=context.ruleset.version,
            evidence_level="standard",
        ),
    )

    first = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 1
    assert [error["kind"] for error in first["errors"]] == ["macho_parse_error"]
    assert len(first["binaries"]) == 1
    assert first["binaries"][0]["needed"] == []
    assert first["verdict"]["class"] == "OPAQUE"
    assert "BIN_UNPARSEABLE" in first["verdict"]["rule_ids"]

    second = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 2, "a cached record must not stop the second attempt from happening"
    assert second["errors"] == []
    assert second["binaries"][0]["needed"] == [
        "/usr/lib/libSystem.B.dylib",
        "/usr/lib/libcrypto.3.dylib",
    ]
    assert second["verdict"]["conditions"]["openssl_linkage"] == "system"


def test_a_transient_pe_parse_failure_is_retried_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `pe_parse_error` sibling: `read_pe`'s own `except Exception` around the
    import directory must not let a transient `MemoryError` calcify a lost DLL
    dependency into a permanent record.
    """
    wheel = build_wheel(
        tmp_path / f"fakecrypto-1.0-{WIN_AMD64}.whl",
        name="fakecrypto",
        version="1.0",
        tags=(WIN_AMD64,),
        files={
            "fakecrypto/_ext.pyd": PEBuilder(
                imports=(PEImport("libcrypto-3-x64.dll", names=("EVP_DigestInit_ex",)),),
                dll_name="_ext.pyd",
            ).build()
        },
    )
    calls = _flaky(monkeypatch, pe, "_read_imports")
    context = ScanContext.build(load_ruleset())
    monkeypatch.setattr(cli, "_CONTEXT", context)
    monkeypatch.setattr(
        cli,
        "_CACHE",
        RecordCache(
            root=tmp_path / "cache",
            ruleset_version=context.ruleset.version,
            evidence_level="standard",
        ),
    )

    first = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 1
    assert [error["kind"] for error in first["errors"]] == ["pe_parse_error"]
    assert len(first["binaries"]) == 1
    assert first["binaries"][0]["needed"] == []
    assert first["verdict"]["class"] == "OPAQUE"
    assert "BIN_UNPARSEABLE" in first["verdict"]["rule_ids"]

    second = json.loads(cli._scan_path(str(wheel)))
    assert calls["n"] == 2, "a cached record must not stop the second attempt from happening"
    assert second["errors"] == []
    assert second["binaries"][0]["needed"] == ["libcrypto-3-x64.dll"]
    assert second["verdict"]["conditions"]["openssl_linkage"] == "system"


def test_resume_skips_a_malformed_line_instead_of_crashing_the_run(
    corpus: Path, tmp_path: Path
) -> None:
    """`_scan_was_aborted` reads two levels deeper into a record (`errors[i]["kind"]`)
    than JSON parsing alone checks. A line that parses as JSON but not as a well-shaped
    record -- however that got into the output file -- must still be dropped and
    rescanned like any other malformed line, not raise out of `_run_scan` and take the
    rest of the wheels down with it.
    """
    out = tmp_path / "out.jsonl"
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"])
    lines = out.read_text(encoding="utf-8").splitlines()
    target = next(i for i, line in enumerate(lines) if "weakhash" in line)
    # A well-formed JSON object, wrong shape: "errors" is not a list of {"kind": ...}.
    lines[target] = json.dumps(
        {"wheel": {"filename": "weakhash-1.0-py3-none-any.whl"}, "errors": "x"}
    )
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert main(["scan", str(corpus), "-o", str(out), "--no-cache", "--resume", "-q"]) == 0
    records = read_records(out)
    assert len(records) == 2
    names = {record["wheel"]["name"] for record in records}
    assert names == {"weakhash", "puredata"}


# --- output targets -----------------------------------------------------------


def test_the_null_device_still_scans_every_wheel(
    corpus: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Opening `<path>.partial` before consuming the scan generator would leave
    `-o /dev/null` doing no work at all, so the progress line is what proves the
    wheels were really read.
    """
    assert main(["scan", str(corpus), "-o", "/dev/null", "--no-cache"]) == 0
    assert "2/2 wheels" in capsys.readouterr().err


def test_writing_to_a_fifo_writes_every_record(corpus: Path, tmp_path: Path) -> None:
    """A FIFO is readable back, unlike the null device, so it is what pins the
    records themselves landing on a target the rename dance cannot handle.
    """
    fifo = tmp_path / "out.fifo"
    os.mkfifo(fifo)
    collected: list[str] = []

    def read_fifo() -> None:
        with fifo.open("r", encoding="utf-8") as stream:
            collected.append(stream.read())

    # Daemon, because a regression writes the `.partial` and renames it over the FIFO
    # path, leaving this thread blocked on the old inode. A non-daemon thread would
    # then hold the interpreter open and hang the suite instead of failing it.
    reader = threading.Thread(target=read_fifo, daemon=True)
    reader.start()
    assert main(["scan", str(corpus), "-o", str(fifo), "--no-cache", "-q"]) == 0
    reader.join(timeout=30)
    assert not reader.is_alive()

    assert len(collected[0].splitlines()) == 2
    assert not fifo.with_name(fifo.name + ".partial").exists()


def test_a_symlinked_output_is_written_through_rather_than_replaced(
    corpus: Path, tmp_path: Path
) -> None:
    """`/dev/stdout` is a symlink onto fd 1, so resolving it decides the strategy from
    whatever the shell redirected to. Judge the link itself: write through it and
    leave it a link, rather than renaming a regular file over it.
    """
    real = tmp_path / "records.jsonl"
    real.touch()
    link = tmp_path / "out.jsonl"
    link.symlink_to(real)

    assert main(["scan", str(corpus), "-o", str(link), "--no-cache", "-q"]) == 0
    assert link.is_symlink()
    assert len(read_records(real)) == 2


def test_writing_to_a_regular_file_leaves_no_temporary_behind(corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    assert main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"]) == 0
    assert len(read_records(out)) == 2
    assert not out.with_name(out.name + ".partial").exists()


def test_resume_does_not_read_back_a_non_regular_output(corpus: Path, tmp_path: Path) -> None:
    """`--resume` reads the output file to find what it can skip. On a FIFO that read
    blocks for a writer that never comes, so the whole run hangs before it starts.
    """
    fifo = tmp_path / "out.fifo"
    os.mkfifo(fifo)
    collected: list[str] = []

    def read_fifo() -> None:
        with fifo.open("r", encoding="utf-8") as stream:
            collected.append(stream.read())

    reader = threading.Thread(target=read_fifo, daemon=True)
    reader.start()
    assert main(["scan", str(corpus), "-o", str(fifo), "--resume", "--no-cache", "-q"]) == 0
    reader.join(timeout=30)
    assert not reader.is_alive()
    assert len(collected[0].splitlines()) == 2


def test_a_failing_write_to_a_device_is_a_clean_error(
    corpus: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """/dev/full accepts an open and then refuses every byte. Unlike a chmod-based
    check this holds whatever uid the suite runs as.
    """
    assert main(["scan", str(corpus), "-o", "/dev/full", "--no-cache", "-q"]) == 1
    printed = capsys.readouterr().err
    assert printed.startswith(f"{TOOL_NAME}: ")
    assert "/dev/full" in printed


def test_an_unwritable_output_path_is_a_clean_error(
    corpus: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A regular target whose directory refuses the temporary file. The message has to
    name the output path, because the failure otherwise reads as a broken scan.
    """
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o555)
    out = locked / "out.jsonl"
    try:
        assert main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"]) == 1
        printed = capsys.readouterr().err
        assert printed.startswith(f"{TOOL_NAME}: ")
        assert str(out) in printed
        assert not out.with_name(out.name + ".partial").exists()
    finally:
        locked.chmod(0o755)


# --- formats and subcommands ------------------------------------------------


def test_markdown_output_is_a_table(corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.md"
    main(["scan", str(corpus), "-o", str(out), "--format", "md", "--no-cache", "-q"])
    text = out.read_text(encoding="utf-8")
    assert text.startswith("| wheel")
    assert "weakhash-1.0-py3-none-any.whl" in text


def test_html_output_is_a_page(corpus: Path, tmp_path: Path) -> None:
    first = tmp_path / "first.html"
    second = tmp_path / "second.html"
    parallel = tmp_path / "parallel.html"
    main(["scan", str(corpus), "-o", str(first), "--format", "html", "--no-cache", "-q"])
    main(["scan", str(corpus), "-o", str(second), "--format", "html", "--no-cache", "-q"])
    main(
        [
            "scan",
            str(corpus),
            "-o",
            str(parallel),
            "--format",
            "html",
            "--jobs",
            "2",
            "--no-cache",
            "-q",
        ]
    )
    text = first.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "weakhash-1.0-py3-none-any.whl" in text
    assert first.read_bytes() == second.read_bytes() == parallel.read_bytes()


def test_minimal_evidence_level_drops_binary_detail(corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.jsonl"
    main(["scan", str(corpus), "-o", str(out), "--evidence-level", "minimal", "--no-cache", "-q"])
    assert read_records(out)


def test_rules_prints_the_table_for_review(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 0
    printed = capsys.readouterr().out
    assert "BIN_BUNDLED_OPENSSL" in printed
    assert "wheel ships its own openssl" in printed.lower()


def test_rules_json_lists_every_rule(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["rules"]) > 20
    assert all(rule["why"] for rule in payload["rules"])


def test_schema_prints_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION


def test_the_schema_matches_what_the_scanner_actually_emits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Drift between record.py and schema.json would mislead every consumer."""
    directory = tmp_path / "drift"
    directory.mkdir()
    # Not the shared `corpus`: that is two pure-Python wheels, so `binaries` comes back
    # empty and the array half of this check would assert nothing.
    build_wheel(
        directory / "withext-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
        name="withext",
        version="1.0",
        tags=("cp312-cp312-manylinux_2_28_x86_64",),
        files={
            "withext/__init__.py": CLEAN_SOURCE,
            "withext/_ext.abi3.so": ElfBuilder(
                needed=("libcrypto.so.3",),
                dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
            ).build(),
        },
    )
    main(["schema"])
    schema = json.loads(capsys.readouterr().out)
    out = tmp_path / "out.jsonl"
    main(["scan", str(directory), "-o", str(out), "--no-cache", "-q"])
    record = read_records(out)[0]

    assert set(record) == set(schema["required"])
    for section in ("tool", "wheel", "artifacts", "verdict"):
        assert set(record[section]) == set(schema["properties"][section]["required"]), section

    # The arrays too. Checking only the object sections let a key be dropped from
    # `record.py` while `schema.json` still required it, with the suite staying green.
    binaries = [binary for found in read_records(out) for binary in found["binaries"]]
    assert binaries, "the corpus must carry a binary or this asserts nothing"
    required = set(schema["properties"]["binaries"]["items"]["required"])
    for binary in binaries:
        assert required <= set(binary)


def test_docs_output_schema_page_lists_every_partial_reason() -> None:
    """docs/output-schema.md is a human copy of SCHEMA.md's `partial_reasons` table; a
    token added to PARTIAL_REASONS without updating that page would go stale silently."""
    page = Path(__file__).parent.parent / "docs" / "output-schema.md"
    text = page.read_text(encoding="utf-8")
    missing = sorted(token for token in PARTIAL_REASONS if f"`{token}`" not in text)
    assert not missing, f"docs/output-schema.md is missing partial_reasons tokens: {missing}"


def _normalize_dash_and_links(text: str) -> str:
    """The ways the docs page renders SCHEMA.md's text differently, normalised away:
    ` -- ` is an em dash there; a cross-reference is a Markdown link there where
    SCHEMA.md instead spells out `DESIGN.md` followed by the heading in quotes, so
    once the link is stripped, that lead-in is stripped down to the same quoted
    text the link carries as its own text, which lets a schema paragraph and its page
    counterpart compare as the same words instead of needing a pass-through
    exception. The link text may itself hold one level of brackets, as `binaries[]`
    does in one link, so the pattern accepts a single nested `[...]` pair inside the
    link text instead of stopping at its first `]` -- which would leave the markup
    unstripped -- or matching past it to an unrelated later link -- which would
    swallow the real text in between as if it were the link's."""
    text = text.replace(" -- ", " — ")
    text = re.sub(r"\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\([^)]+\)", r"\1", text)
    return re.sub(r'DESIGN\.md, "([^"]+)"', r"\1", text)


def _schema_table_rows(path: Path) -> list[str]:
    """Every Markdown table row in `path`, minus separator rows, with
    `_normalize_dash_and_links` applied."""
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|") or re.fullmatch(r"\|[-| :]+\|", line):
            continue
        rows.append(_normalize_dash_and_links(line))
    return rows


def test_docs_output_schema_page_tables_match_schema_md() -> None:
    """docs/output-schema.md is the published copy of SCHEMA.md's tables, so every row
    on the page must match SCHEMA.md once its dash and link rendering are normalised
    away. SCHEMA.md is the contract: edit it first, then copy the changed rows."""
    root = Path(__file__).parent.parent
    schema = _schema_table_rows(root / "SCHEMA.md")
    page = _schema_table_rows(root / "docs" / "output-schema.md")

    assert any(row.startswith("| `elf_symtab_unread` |") for row in schema)

    if page != schema:
        # Positional, not a set difference: a set difference goes empty when two rows
        # are swapped or one is duplicated, since the same rows are present on both
        # sides, and the message would then name nothing to fix.
        changed = sorted(
            {
                s.split("|")[1].strip()
                for s, p in itertools.zip_longest(schema, page, fillvalue="| <missing> |")
                if s != p
            }
        )
        pytest.fail(f"docs/output-schema.md rows differ from SCHEMA.md: {changed}")


def _schema_prose_paragraphs(path: Path) -> list[str]:
    """Every non-table, non-heading paragraph in `path` as a single normalised line:
    blank-line-separated text, with table rows, headings and fenced code blocks left
    out, and `_normalize_dash_and_links` applied."""
    paragraphs = []
    current: list[str] = []
    in_code = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            continue
        if in_code or stripped.startswith("|") or stripped.startswith("#"):
            if current:
                paragraphs.append(" ".join(current))
                current = []
            continue
        if not stripped:
            if current:
                paragraphs.append(" ".join(current))
                current = []
            continue
        current.append(stripped)
    if current:
        paragraphs.append(" ".join(current))
    return [_normalize_dash_and_links(paragraph) for paragraph in paragraphs]


# Paragraphs the page states differently from SCHEMA.md on purpose, once the em-dash,
# link and DESIGN.md-aside normalisation above is applied. Each pair says these are
# the same design fact told twice: the page reworks the wording, or adds to it, but
# never drops the fact. Keyed by the SCHEMA.md wording, valued by the page's, so that
# if one side of a pair is deleted while the other survives, that is a real change to
# the contract and the check below still catches it.
_PROSE_ADAPTED_PAIRS: dict[str, str] = {
    # The page opens with an admonition instead of a bold lead-in sentence; the
    # second sentence, the only fact worth checking, is still its own paragraph.
    "**Nothing in this document asserts FIPS compatibility.** The verdict taxonomy "
    "has no passing class and will not acquire one. The tool reports evidence; a "
    "human decides.": (
        "The verdict taxonomy has no passing class and will not acquire one. The "
        "tool reports evidence; a human decides."
    ),
    # The page adds a pointer to the "Vocabularies" reference page, which is where it
    # sends a reader instead of the fenced "Triage recipes" section it drops.
    "A wheel that could not be read is `OPAQUE`, never `NO_CRYPTO_DETECTED`. Every "
    "error kind the scanner can record has a rule that turns it into a finding, "
    "and a test enforces that.": (
        "A wheel that could not be read is `OPAQUE`, never `NO_CRYPTO_DETECTED`. Every "
        "error kind the scanner can record has a rule that turns it into a finding, "
        "and a test enforces that. The full list of kinds is in Vocabularies."
    ),
    # The page names the cross-reference through the link text itself, which reads as
    # the sentence's subject, rather than through the bare "DESIGN.md" SCHEMA.md uses.
    "For a universal Mach-O that is one entry for the member rather than one per "
    "architecture, because the slices are merged. `matched_symbols` can therefore "
    "carry one name as both `imported` and `defined`, which no single slice can "
    "be, when the architectures disagree; `machine`, `bits` and `endian` describe "
    "the first slice alone. `DESIGN.md` records why they are merged anyway.": (
        "For a universal Mach-O that is one entry for the member rather than one per "
        "architecture, because the slices are merged. `matched_symbols` can therefore "
        "carry one name as both `imported` and `defined`, which no single slice can "
        "be, when the architectures disagree; `machine`, `bits` and `endian` describe "
        "the first slice alone. A universal binary is one record, and its slices are "
        "merged records why they are merged anyway."
    ),
}

# "Each reason:" leads into the `partial_reasons` table; the page turns it into a
# `### partial_reasons` heading instead, which the paragraph extraction above excludes
# along with every other heading, so there is no page-side paragraph to pair it with.
_PROSE_SCHEMA_ONLY = frozenset({"Each reason:"})
_PROSE_PAGE_ONLY = frozenset({'!!! warning "Nothing on this page asserts FIPS compatibility"'})


def test_docs_output_schema_page_prose_matches_schema_md() -> None:
    """The output contract is not only the tables: several paragraphs of prose in
    SCHEMA.md -- what `binaries_truncated`, `symlinks_truncated`/`skipped_truncated`,
    `py_files_unparsed` and the universal Mach-O merge mean -- are copied onto the
    docs page too, and drift there just as silently as a table row would. Every
    paragraph must match once dash and link rendering are normalised away, except the
    page's deliberate adaptations: an admonition and a heading with no page-side
    paragraph to compare against, and the pairs in `_PROSE_ADAPTED_PAIRS`, where
    either side vanishing while the other stays is still a failure."""
    root = Path(__file__).parent.parent
    schema = _schema_prose_paragraphs(root / "SCHEMA.md")
    page = _schema_prose_paragraphs(root / "docs" / "output-schema.md")

    assert any("py_files_unparsed" in paragraph for paragraph in schema)

    vanished = sorted(
        f"schema={schema_text in schema} page={page_text in page}: {schema_text!r}"
        for schema_text, page_text in _PROSE_ADAPTED_PAIRS.items()
        if (schema_text in schema) != (page_text in page)
    )
    paired_schema_text = set(_PROSE_ADAPTED_PAIRS)
    paired_page_text = set(_PROSE_ADAPTED_PAIRS.values())
    schema_only = sorted((set(schema) - set(page)) - _PROSE_SCHEMA_ONLY - paired_schema_text)
    page_only = sorted((set(page) - set(schema)) - _PROSE_PAGE_ONLY - paired_page_text)
    # The two exemptions are one-sided by definition, but each still names a real
    # paragraph. Without this, deleting one from its file would leave it out of both
    # `schema`/`page` and the `- _PROSE_*_ONLY` subtraction, so the test would stay
    # green while the fact it names -- the FIPS admonition title on the page, the
    # `partial_reasons` lead-in in SCHEMA.md -- silently disappeared.
    missing_exempt = sorted(
        f"schema-only exemption not found in SCHEMA.md: {text!r}"
        for text in _PROSE_SCHEMA_ONLY
        if text not in schema
    ) + sorted(
        f"page-only exemption not found on the page: {text!r}"
        for text in _PROSE_PAGE_ONLY
        if text not in page
    )
    if schema_only or page_only or vanished or missing_exempt:
        pytest.fail(
            "docs/output-schema.md prose differs from SCHEMA.md.\n"
            f"only in SCHEMA.md: {schema_only}\n"
            f"only on the page: {page_only}\n"
            f"one side of an adapted pair vanished: {vanished}\n"
            f"a one-sided exemption's own paragraph is missing: {missing_exempt}"
        )


def test_the_schema_has_no_passing_class(capsys: pytest.CaptureFixture[str]) -> None:
    """The enum is deliberately open, so assert on the documented values instead."""
    main(["schema"])
    described = json.loads(capsys.readouterr().out)["$defs"]["verdictClass"]["description"]
    listed = described.split("Current values:", 1)[1].split(".", 1)[0]
    classes = {name.strip() for name in listed.split(",")}
    assert "NO_CRYPTO_DETECTED" in classes
    assert (
        not {
            "COMPLIANT",
            "FIPS_COMPLIANT",
            "COMPATIBLE",
            "FIPS_COMPATIBLE",
            "APPROVED",
            "PASS",
            "CLEAN",
        }
        & classes
    )
