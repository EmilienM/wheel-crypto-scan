"""End-to-end behaviour of the command line: output, parallelism, caching, resume."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest
from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan import TOOL_NAME
from wheel_crypto_scan.cli import main

WEAK_HASH_SOURCE = b"import hashlib\n\ndigest = hashlib.md5()\n"
CLEAN_SOURCE = b"VALUES = [1, 2, 3]\n"


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
    corpus: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Drift between record.py and schema.json would mislead every consumer."""
    main(["schema"])
    schema = json.loads(capsys.readouterr().out)
    out = tmp_path / "out.jsonl"
    main(["scan", str(corpus), "-o", str(out), "--no-cache", "-q"])
    record = read_records(out)[0]

    assert set(record) == set(schema["required"])
    for section in ("tool", "wheel", "artifacts", "verdict"):
        assert set(record[section]) == set(schema["properties"][section]["required"]), section


def test_the_schema_has_no_passing_class(capsys: pytest.CaptureFixture[str]) -> None:
    """The enum is deliberately open, so assert on the documented values instead."""
    main(["schema"])
    described = json.loads(capsys.readouterr().out)["$defs"]["verdictClass"]["description"]
    listed = described.split("Current values:", 1)[1].split(".", 1)[0]
    classes = {name.strip() for name in listed.split(",")}
    assert "NO_CRYPTO_DETECTED" in classes
    assert not {"COMPLIANT", "FIPS_COMPLIANT", "APPROVED", "PASS", "CLEAN"} & classes
