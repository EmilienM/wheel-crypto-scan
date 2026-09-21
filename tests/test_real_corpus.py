"""The `real` marker's own gate.

`tox -e real` runs `pytest -m "real or hostbin"` with `WCS_CORPUS_DIR` in its
`passenv`, and the tests in this file are what carry the `real` marker and read that
variable. `tools/make_corpus.py` builds a corpus of *synthetic* wheels for a separate,
always-on determinism check; this is the real-wheel gate the `real` marker's own name
promises.

What is pinned here is exactly what DESIGN.md's own hand-verified measurements over
real corpora depend on being true, restated as an automated, re-runnable check rather
than a one-off note: every wheel scans without a Python exception escaping (the "one
bad wheel never aborts a run" invariant), the same corpus produces byte-identical
output at `--jobs 1` and `--jobs 8` (the ordering promise `cli.py` documents), and a
cache-warm run matches a cold one (the cache-key promise `AGENTS.md` documents). It
also prints -- never asserts, because corpus contents vary from one `WCS_CORPUS_DIR` to
the next -- the shapes DESIGN.md discusses from real wheels: `.exe` members, ELF
objects with no section header table at all (`e_shoff == 0`, the `cryptography`
static-OpenSSL exposure "Sections are found by type, not by a name nobody checks"
measures), and how many objects came back `partial_analysis`. Weak dylibs and
forwarders are not counted here: nothing in the output record surfaces them without
new extraction code this file does not add. `pytest`'s default capture hides that
output on a pass; run with `tox -e real -- -rP` to see it.

Every test needs no corpus at all to run: with `WCS_CORPUS_DIR` unset, or set to a
directory with no `.whl` files in it, each one skips outright, the same shape
`test_binfmt_elf.py`'s `hostbin` test skips on a host with no system `libcrypto.so.3`.
That is what keeps `tox -e real` a true opt-in gate rather than a failure waiting for a
corpus nobody mounted.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from wheel_crypto_scan.cli import main
from wheel_crypto_scan.discovery import discover
from wheel_crypto_scan.evidence import PARTIAL_ELF_SECTION_TABLE_ABSENT, PARTIAL_REASONS


def _corpus() -> tuple[Path, list[Path]]:
    """The corpus directory and its wheels, or a skip when there is nothing to scan.

    Called first in every test below rather than through a fixture, matching
    `test_binfmt_elf.py`'s own `_host_libcrypto` shape (without its CI-only require
    switch): skip when nothing is there to read, for the other marker that needs
    something on disk this repository does not ship.

    Wheels are found through `discover`, the same call `main`'s own scan takes --
    a corpus with wheels only in subdirectories is real (`discover` walks recursively),
    and a hand-rolled top-level-only glob here would both miss it and misreport the
    gate as unconfigured.
    """
    corpus_dir = os.environ.get("WCS_CORPUS_DIR")
    if not corpus_dir:
        pytest.skip("WCS_CORPUS_DIR is not set; this is an opt-in real-wheel gate")
    path = Path(corpus_dir)
    if not path.is_dir():
        pytest.skip(f"WCS_CORPUS_DIR={corpus_dir} is not a directory")
    wheels = discover([str(path)])
    if not wheels:
        pytest.skip(f"no .whl files found in WCS_CORPUS_DIR={corpus_dir}")
    return path, wheels


def _read_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.mark.real
def test_every_wheel_in_the_corpus_scans_without_raising(tmp_path: Path) -> None:
    corpus, wheels = _corpus()
    out = tmp_path / "out.jsonl"

    assert main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"]) == 0

    records = _read_records(out)
    assert len(records) == len(wheels)
    assert {record["wheel"]["filename"] for record in records} == {wheel.name for wheel in wheels}


@pytest.mark.real
def test_jobs_1_and_jobs_8_produce_byte_identical_output(tmp_path: Path) -> None:
    corpus, _wheels = _corpus()
    serial, parallel = tmp_path / "serial.jsonl", tmp_path / "parallel.jsonl"

    main(["scan", str(corpus), "-o", str(serial), "--jobs", "1", "--no-cache", "-q"])
    main(["scan", str(corpus), "-o", str(parallel), "--jobs", "8", "--no-cache", "-q"])

    assert serial.read_bytes() == parallel.read_bytes()


@pytest.mark.real
def test_a_warm_cache_run_matches_a_cold_one(tmp_path: Path) -> None:
    corpus, wheels = _corpus()
    cache = tmp_path / "cache"
    cold, warm = tmp_path / "cold.jsonl", tmp_path / "warm.jsonl"

    main(["scan", str(corpus), "-o", str(cold), "--cache-dir", str(cache), "-q"])
    # A cache that silently stopped writing (RecordCache.put swallows OSError) would
    # make the warm run cold too, and the byte-identical check below would still pass
    # for the wrong reason -- so first confirm the cold run actually populated it.
    cached = [entry for entry in cache.rglob("*") if entry.is_file()]
    assert len(cached) == len(wheels), "cold run did not populate the cache"

    main(["scan", str(corpus), "-o", str(warm), "--cache-dir", str(cache), "-q"])

    assert cold.read_bytes() == warm.read_bytes()


@pytest.mark.real
def test_no_wheel_is_opaque_only_because_symtab_was_read(tmp_path: Path) -> None:
    """Reading `.symtab`'s local definitions makes it load-bearing on the dynamically
    linked path too, beyond `stripped` and the count alone. That is a way to be marked
    partial that a read ignoring `.symtab` on this path would miss: an object whose
    `.symtab` or `.strtab` is over the byte budget, or whose rows name strings
    `.strtab` does not hold, says so. DESIGN.md claims that costs no real wheel its
    answer, measured over 18 wheels by hand, and this file exists to restate exactly
    that kind of claim as a re-runnable check.

    Corpus-independent, unlike the with-and-without comparison the measurement comes
    from: an object that is partial *only* for this reason, with every other cause
    absent, is the failure. An object partial for `elf_symtab_unread` alongside another
    cause is already partial regardless.
    """
    corpus, _wheels = _corpus()
    out = tmp_path / "out.jsonl"
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"])

    offenders = [
        (record["wheel"]["filename"], binary["path"])
        for record in _read_records(out)
        for binary in record["binaries"]
        if binary["partial_reasons"] == ["elf_symtab_unread"]
    ]
    assert offenders == [], f"objects partial only for reading .symtab: {offenders[:5]}"


@pytest.mark.real
def test_corpus_summary(tmp_path: Path) -> None:
    """Mostly prints: corpus contents vary. Prints counts a future issue can start from."""
    corpus, _wheels = _corpus()
    out = tmp_path / "summary.jsonl"
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"])
    records = _read_records(out)
    binaries = [binary for record in records for binary in record["binaries"]]

    # Corpus-independent: true of any corpus, not just this one.
    for binary in binaries:
        assert set(binary["partial_reasons"]) <= PARTIAL_REASONS

    counts = {
        "wheels scanned": len(records),
        "objects total": len(binaries),
        ".exe members": sum(1 for b in binaries if b["path"].endswith(".exe")),
        "ELF objects with no section header table (e_shoff == 0)": sum(
            1 for b in binaries if PARTIAL_ELF_SECTION_TABLE_ABSENT in b["partial_reasons"]
        ),
        "objects with partial_analysis": sum(1 for b in binaries if b["partial_analysis"]),
        "wheels with at least one scan error": sum(1 for record in records if record["errors"]),
    }
    width = max(len(label) for label in counts) + 2
    for label, count in counts.items():
        print(f"{label + ':':<{width}}{count}")
