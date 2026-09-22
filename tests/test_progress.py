"""The progress display on stderr: plain lines for logs, a live block for terminals."""

from __future__ import annotations

import fcntl
import io
import json
import os
import re
import struct
import termios
import threading
from pathlib import Path

import pytest
from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan import progress as progress_module
from wheel_crypto_scan.cli import main
from wheel_crypto_scan.progress import Progress, wants_colour, wants_live
from wheel_crypto_scan.record import to_json_line
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.scan import ScanContext, scan_wheel
from wheel_crypto_scan.verdict import NO_CRYPTO_DETECTED

PRECEDENCE = ("WORST", "BAD", NO_CRYPTO_DETECTED)
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def _record(filename: str, verdict_class: str, **extra: object) -> str:
    record: dict[str, object] = {
        "wheel": {"filename": filename},
        "verdict": {
            "class": verdict_class,
            "needs_human_review": verdict_class != NO_CRYPTO_DETECTED,
        },
        "crypto": {"families": [], "libraries": []},
        "errors": [],
    }
    record.update(extra)
    return json.dumps(record) + "\n"


def _progress(
    stream: io.StringIO,
    clock: _Clock,
    *,
    total: int,
    live: bool,
    precedence: tuple[str, ...] = PRECEDENCE,
) -> Progress:
    return Progress(
        stream,
        total=total,
        jobs=4,
        precedence=precedence,
        live=live,
        colour=False,
        clock=clock,
    )


def _text(segments: list[tuple[str, str]]) -> str:
    return "".join(text for text, _ in segments)


# --- plain mode ------------------------------------------------------------------


def test_plain_mode_reports_every_hundred_wheels_with_rate_and_eta() -> None:
    stream, clock = io.StringIO(), _Clock()
    lines = [_record(f"w{i}.whl", NO_CRYPTO_DETECTED) for i in range(250)]
    passed = []
    with _progress(stream, clock, total=250, live=False) as progress:
        for line in progress.feed(lines):
            clock.now += 0.5
            passed.append(line)

    assert passed == lines
    out = stream.getvalue().splitlines()
    assert out[0].startswith("wheel-crypto-scan: 100/250 wheels (40%, 2.0/s, ETA 01:14)")
    assert out[1].startswith("wheel-crypto-scan: 200/250 wheels")
    assert out[2].startswith("wheel-crypto-scan: 250/250 wheels (100%")
    assert out[3] == (
        "wheel-crypto-scan: scanned 250 wheels in 02:05: WORST 0, BAD 0, "
        "NO_CRYPTO_DETECTED 250; crypto in 0, errors 0"
    )
    assert "\x1b" not in stream.getvalue()


def test_plain_mode_says_when_a_run_did_not_finish() -> None:
    stream = io.StringIO()
    with pytest.raises(KeyboardInterrupt):
        with _progress(stream, _Clock(), total=5, live=False) as progress:
            progress.update(_record("a.whl", "WORST"))
            raise KeyboardInterrupt
    assert (
        stream.getvalue()
        .splitlines()[-1]
        .startswith("wheel-crypto-scan: interrupted at 1/5 wheels in 00:00: WORST 1,")
    )


def test_nothing_to_scan_prints_nothing() -> None:
    stream = io.StringIO()
    with _progress(stream, _Clock(), total=0, live=True) as progress:
        assert not list(progress.feed([]))
    assert stream.getvalue() == ""


# --- tallies ---------------------------------------------------------------------


def test_live_block_tallies_the_evidence() -> None:
    stream, clock = io.StringIO(), _Clock()
    progress = _progress(stream, clock, total=10, live=True)
    progress.update(
        _record(
            "a.whl",
            "WORST",
            crypto={"families": ["hash"], "libraries": [{"name": "openssl", "linkage": "static"}]},
            errors=[{"kind": "x"}],
        )
    )
    progress.update(_record("b.whl", "BAD", crypto={"families": ["hash"], "libraries": []}))
    progress.update("not json\n")
    clock.now += 3.0

    head, activity, classes, evidence = (_text(line) for line in progress.lines(200))
    assert " 3/10 " in head
    assert "30.0%" in head
    assert "1.0 wheels/s" in head
    assert "elapsed 00:03" in head
    assert head.endswith("ETA 00:07")
    assert activity == "  4 workers  last emitted b.whl"
    # Precedence order, and a class that never fired still shows with a zero.
    assert classes.split() == ["WORST", "1", "BAD", "1", NO_CRYPTO_DETECTED, "0"]
    assert evidence.split() == [
        *("crypto", "in", "2", "wheels", "errors", "1", "openssl", "1"),
    ]


def test_tallies_read_a_real_record(tmp_path: Path) -> None:
    """Every other test here writes its own dict, so a renamed record field would
    leave the display showing zeros with the suite still green."""
    wheel = build_wheel(
        tmp_path / "weakhash-1.0-py3-none-any.whl",
        name="weakhash",
        version="1.0",
        files={"weakhash/__init__.py": b"import hashlib\n\ndigest = hashlib.md5()\n"},
    )
    ruleset = load_ruleset(None)
    record = scan_wheel(wheel, ScanContext.build(ruleset))
    assert record["verdict"]["class"] != NO_CRYPTO_DETECTED
    assert record["crypto"]["families"]

    progress = _progress(
        io.StringIO(), _Clock(), total=1, live=True, precedence=tuple(ruleset.precedence)
    )
    progress.update(to_json_line(record))
    _, activity, *rest = (_text(line) for line in progress.lines(500))
    classes, evidence = rest
    assert activity.endswith("last emitted weakhash-1.0-py3-none-any.whl")
    assert f"{record['verdict']['class']} 1" in classes
    assert "crypto in 1 wheels" in evidence


def test_a_class_outside_the_precedence_is_still_counted() -> None:
    progress = _progress(io.StringIO(), _Clock(), total=1, live=True)
    progress.update(_record("a.whl", "SOMETHING_ELSE"))
    assert _text(progress.lines(200)[2]).split()[-2:] == ["SOMETHING_ELSE", "1"]


def test_workers_count_down_as_the_queue_drains() -> None:
    progress = _progress(io.StringIO(), _Clock(), total=5, live=True)
    for name in ("a", "b", "c"):
        progress.update(_record(f"{name}.whl", NO_CRYPTO_DETECTED))
    assert _text(progress.lines(200)[1]).startswith("  2 workers")


def test_no_crypto_detected_is_never_drawn_in_colour() -> None:
    """It is what a wheel gets when nothing classified it. It must not look like a
    result, let alone a passing one, even where it is not last in the precedence."""
    progress = _progress(
        io.StringIO(), _Clock(), total=1, live=True, precedence=(NO_CRYPTO_DETECTED, "WORST")
    )
    progress.update(_record("a.whl", NO_CRYPTO_DETECTED))
    styles = dict(progress.lines(200)[2])
    assert styles[NO_CRYPTO_DETECTED] == progress_module._DIM


def test_a_control_character_in_a_filename_never_reaches_the_terminal() -> None:
    progress = _progress(io.StringIO(), _Clock(), total=1, live=True)
    progress.update(_record("evil\x1b[2J\x1b]0;pwned\x07\n-1.0-py3-none-any.whl", "WORST"))
    activity = _text(progress.lines(200)[1])
    assert activity.endswith("evil?[2J?]0;pwned??-1.0-py3-none-any.whl")


# --- layout ----------------------------------------------------------------------


def test_width_is_read_from_the_stream_drawn_on() -> None:
    """In the runs that draw a live view, stdout is a file or a pipe, so asking it
    for a width falls back to a guess."""
    parent, child = os.openpty()
    try:
        fcntl.ioctl(child, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 57, 0, 0))
        with open(child, "w", encoding="utf-8", closefd=False) as stream:
            assert progress_module._terminal_width(stream) == 57
    finally:
        os.close(parent)
        os.close(child)


def test_every_class_and_the_error_count_survive_a_narrow_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A row cut at the edge would hide OPAQUE and the errors first, which are the
    counts that say what could not be read. Rows wrap instead, and none of them wraps
    on the terminal: that would throw off the cursor-up count on the next frame."""
    monkeypatch.setattr(progress_module, "_terminal_width", lambda stream: 40)
    precedence = tuple(load_ruleset(None).precedence)
    stream = io.StringIO()
    progress = Progress(
        stream, total=9, jobs=1, precedence=precedence, live=True, colour=True, clock=_Clock()
    )
    progress.update(
        _record(
            "a-very-long-wheel-name-1.0-py3-none-any.whl",
            precedence[0],
            crypto={"families": [], "libraries": [{"name": "a-long-library", "linkage": "x"}]},
            errors=[{"kind": "x"}],
        )
    )
    progress._draw(progress.lines())
    visible = ANSI.sub("", stream.getvalue()).replace("\r", "")
    assert all(len(row) < 40 for row in visible.split("\n"))
    for name in precedence:
        assert name in visible
    assert "errors 1" in visible
    assert f"\x1b[1;31m{precedence[0]}" in stream.getvalue()


def test_a_shorter_frame_blanks_the_rows_the_taller_one_left() -> None:
    stream = io.StringIO()
    progress = _progress(stream, _Clock(), total=1, live=True)
    progress._draw([[("a", "")], [("b", "")], [("c", "")]])
    progress._draw([[("x", "")]])
    assert stream.getvalue().endswith("\x1b[2A\r\x1b[2Kx\n\x1b[2K\n\x1b[2K\x1b[2A")


# --- lifecycle -------------------------------------------------------------------


def test_close_replaces_the_block_with_a_summary() -> None:
    stream, clock = io.StringIO(), _Clock()
    with _progress(stream, clock, total=2, live=True) as progress:
        for line in progress.feed([_record("a.whl", "WORST"), _record("b.whl", "BAD")]):
            clock.now += 32.5
    out = ANSI.sub("", stream.getvalue())
    assert "Scanned 2 wheels in 01:05" in out
    assert "Interrupted" not in out
    assert out.endswith("\n")


def test_a_failing_consumer_stops_the_ticker_before_the_error_surfaces() -> None:
    """Closing from a generator's `finally` would wait for the generator to be
    collected, and the ticker would draw over the traceback until then."""
    stream = io.StringIO()
    with pytest.raises(BrokenPipeError):
        with _progress(stream, _Clock(), total=3, live=True) as progress:
            ticker = progress._ticker
            assert ticker is not None and ticker.is_alive()
            for _ in progress.feed([_record("a.whl", "WORST")]):
                raise BrokenPipeError
    assert not ticker.is_alive()
    out = ANSI.sub("", stream.getvalue())
    assert "Interrupted at 1/3" in out
    assert out.endswith("\n")
    written = stream.getvalue()
    progress.close()
    assert stream.getvalue() == written


def test_a_paused_terminal_never_blocks_a_record() -> None:
    """Ctrl-S blocks every write to the terminal. The redraw may wait on it; the
    records the scan hands over must not, or pausing the view pauses the scan."""
    entered, release = threading.Event(), threading.Event()

    class _Paused(io.StringIO):
        def write(self, text: str) -> int:
            entered.set()
            release.wait(5)
            return super().write(text)

    progress = _progress(_Paused(), _Clock(), total=3, live=True)
    with progress:
        assert entered.wait(2)
        updater = threading.Thread(target=progress.update, args=(_record("a.whl", "WORST"),))
        updater.start()
        updater.join(2)
        blocked = updater.is_alive()
        release.set()
    assert not blocked


def test_a_write_error_is_printed_after_the_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus = tmp_path / "wheels"
    corpus.mkdir()
    build_wheel(corpus / "plain-1.0-py3-none-any.whl", name="plain", version="1.0")
    blocker = tmp_path / "file"
    blocker.write_text("", encoding="utf-8")

    assert main(["scan", str(corpus), "-o", str(blocker / "out.jsonl"), "--no-cache"]) == 1
    err = capsys.readouterr().err.splitlines()
    assert err[-2].startswith("wheel-crypto-scan: interrupted at 0/1 wheels in ")
    assert err[-1].startswith("wheel-crypto-scan: cannot write output to ")


# --- mode selection --------------------------------------------------------------


def test_live_needs_stderr_on_a_terminal_it_does_not_share_with_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TERM", raising=False)
    assert wants_live(_Tty(), io.StringIO(), None)
    assert wants_live(_Tty(), _Tty(), Path("out.jsonl"))
    assert not wants_live(_Tty(), _Tty(), None)
    assert not wants_live(io.StringIO(), io.StringIO(), Path("out.jsonl"))
    monkeypatch.setenv("TERM", "dumb")
    assert not wants_live(_Tty(), io.StringIO(), Path("out.jsonl"))


def test_an_output_naming_the_terminal_shares_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """`-o /dev/stdout` with stdout on the terminal streams records onto the same
    device as the redraws, though no flag says stdout."""
    monkeypatch.delenv("TERM", raising=False)
    parent, child = os.openpty()
    try:
        with open(child, "w", encoding="utf-8", closefd=False) as stderr:
            assert not wants_live(stderr, io.StringIO(), Path(os.ttyname(child)))
            assert wants_live(stderr, io.StringIO(), Path(os.devnull))
    finally:
        os.close(parent)
        os.close(child)


def test_no_color_turns_colour_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert wants_colour(_Tty())
    assert not wants_colour(io.StringIO())
    monkeypatch.setenv("NO_COLOR", "1")
    assert not wants_colour(_Tty())
