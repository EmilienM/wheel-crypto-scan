"""End-to-end behaviour of the command line: output, parallelism, caching, resume."""

from __future__ import annotations

import json
import os
import threading
import warnings
import zipfile
from pathlib import Path

import pytest
from helpers.binfmt import DynSym, ElfBuilder, MachOBuilder, MachOSym, PEBuilder, PEImport
from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan import TOOL_NAME, cli, scan
from wheel_crypto_scan.binfmt import elf, macho, pe
from wheel_crypto_scan.cache import RecordCache
from wheel_crypto_scan.cli import main
from wheel_crypto_scan.layers import binaries as binaries_layer
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
    """#75: the `binaries[]` cap now picks which objects to keep based on `findings`,
    not just a path sort. `--jobs` must not be able to reach that choice -- each
    wheel is still scanned end to end inside one worker, but this pins it directly for
    the one wheel shaped to actually exercise the new selection, rather than relying
    on the general corpus above happening to hit it."""
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


# --- transient failures (#64) ------------------------------------------------
#
# A `MemoryError` (or any exception `_collect` did not specifically anticipate) must
# read as `unexpected_error`, never `bad_zip`, and a record carrying it must never be
# treated as a final answer for that wheel -- not by the on-disk cache, and not by
# `--resume` reading its own prior output back. Both are exercised through
# `cli._scan_path` / `cli.main` directly rather than `scan_wheel` alone, because the
# bug was never in what `scan_wheel` returns for one call: it was in what the caller
# around it decided to do with that record afterward.


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
    """The reproduction from #64: one `MemoryError` must not calcify into a permanent
    stale `OPAQUE` record that a later, successful attempt never gets to override.
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
    it keeps `bad_zip` rather than the new kind. It is cheap to re-fail -- nothing
    past `zipfile.ZipFile()` ever ran -- so it is not cached either, the same as an
    unexpected-error record.
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
    through `--resume` as it did through the cache in #64.
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
# `MEMBER_READ_ERROR` is produced. #97.


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
    """The reproduction from #97: a transient `MemoryError` inside `elf.py`'s own
    `.dynamic` reading (one layer below `MEMBER_READ_ERROR`) must not calcify a lost
    `DT_NEEDED` entry into a permanent record. `_validated_strtab` is on the path both
    `.dynamic`'s tags and `.dynsym`'s string table are read through, so one scan calls
    it twice -- once for each -- and the first of those two calls is the one this test
    makes fail, which is the `.dynamic` block (`read_elf` reads `.dynamic` before
    `.dynsym`): its own `except Exception` is what actually records `elf_parse_error`
    and loses `needed` here.
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
    """`_scan_was_aborted` reads two levels deeper into a record than the surrounding
    try/except originally guarded (`errors[i]["kind"]`). A line that parses as JSON
    but not as a well-shaped record -- however that got into the output file -- must
    still be dropped and rescanned like any other malformed line, not raise out of
    `_run_scan` and take the rest of the wheels down with it.
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
    """The half of the bug that read as a scan failure. Opening `<path>.partial`
    before consuming the scan generator meant `-o /dev/null` did no work at all, so
    the progress line is what proves the wheels were really read.
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
    assert schema["properties"]["schema_version"]["const"] == 1


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
