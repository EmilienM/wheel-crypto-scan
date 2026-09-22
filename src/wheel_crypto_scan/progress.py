"""Scan progress on stderr: a live view on a terminal, plain lines everywhere else.

Everything here writes to stderr and nothing here reaches a record, so wall-clock time
is fine to use: the determinism promise covers the JSONL, not the progress display.

The live view is redrawn by a ticker thread rather than on each record. Records arrive
in submission order, so one slow wheel (torch, measured in gigabytes) holds every later
record back while the other workers keep going. Drawing only on arrival would freeze
the clock and make a busy run look hung. The counts are of records emitted, so the same
wheel stalls them too; it does not stall the scan.

`Progress` is a context manager, and the caller owns its lifetime rather than the
generator that feeds it. A generator abandoned mid-iteration by an exception closes only
when it is collected, which can be interpreter shutdown, and until then the ticker would
keep redrawing over the traceback that explains why.

Verdict classes are coloured by their position in the ruleset's precedence, never by
name, so the colours follow the precedence if it is reordered. `NO_CRYPTO_DETECTED` is
always dim: it is what a wheel gets when nothing classified it, and must not be drawn in
a colour that reads as a pass.

A redraw moves the cursor up by the number of rows it drew last time, so a line must
never wrap. Lines are cut to the width of the stream drawn on, counted in code points,
which assumes every character takes one column. The bar, spinner and marks are East
Asian ambiguous width and take two columns under a CJK locale's terminal settings; a
stream that is not UTF-8 gets ASCII instead. A terminal that reflows rows already drawn
when the window shrinks will still misplace the next frame; nothing short of a
full-screen interface avoids that.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any, TextIO

from . import TOOL_NAME
from .verdict import NO_CRYPTO_DETECTED

_PLAIN_EVERY = 100
_TICK_SECONDS = 0.1
_JOIN_SECONDS = 1.0
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_TOP_LIBRARIES = 4
_INDENT = "  "

_RESET = "\x1b[0m"
_BOLD = "1"
_DIM = "2"
_RED = "31"
_GREEN = "32"
_YELLOW = "33"
_MAGENTA = "35"
_CYAN = "36"
# By precedence position: the first class the ruleset lists gets the first colour.
_CLASS_COLOURS = (f"{_BOLD};{_RED}", _RED, _YELLOW, _CYAN, _MAGENTA)

Segment = tuple[str, str]  # (text, SGR code or "")


class Progress:
    """Tallies records as they come out of the scan and reports on them.

    `live` redraws a block in place and needs a terminal; otherwise one line is
    printed every `_PLAIN_EVERY` wheels, which is what a CI log wants. Use it as a
    context manager around everything that consumes `feed()`.
    """

    def __init__(
        self,
        stream: TextIO,
        *,
        total: int,
        jobs: int,
        precedence: Sequence[str],
        live: bool,
        colour: bool,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._stream = stream
        self._total = total
        self._jobs = max(1, jobs)
        self._precedence = tuple(precedence)
        self._live = live
        self._colour = colour
        self._clock = clock
        encoding = getattr(stream, "encoding", None) or ""
        self._unicode = encoding.lower().replace("-", "") == "utf8"
        self._start = clock()
        self._done = 0
        self._classes: Counter[str] = Counter()
        self._libraries: Counter[str] = Counter()
        self._with_crypto = 0
        self._errors = 0
        self._last = ""
        self._frame = 0
        self._drawn = 0
        self._closed = False
        # `_lock` guards the tallies, `_output` the stream. A terminal paused with
        # Ctrl-S blocks writes, and must stall the redraw, never `update()` and with
        # it the scan. Always taken in that order.
        self._lock = threading.Lock()
        self._output = threading.Lock()
        self._stop = threading.Event()
        self._ticker: threading.Thread | None = None

    # --- lifecycle ------------------------------------------------------------

    def __enter__(self) -> Progress:
        if self._live and self._total:
            self._ticker = threading.Thread(target=self._tick, daemon=True)
            self._ticker.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close(interrupted=exc_type is not None)

    def feed(self, lines: Iterable[str]) -> Iterator[str]:
        """Pass records through unchanged, tallying each one on the way."""
        for line in lines:
            self.update(line)
            yield line

    def update(self, line: str) -> None:
        record = _parse(line)
        with self._lock:
            self._done += 1
            self._tally(record)
            if not self._live and (self._done % _PLAIN_EVERY == 0 or self._done == self._total):
                self._stream.write(f"{TOOL_NAME}: {self._plain_status()}\n")
                self._stream.flush()

    def close(self, *, interrupted: bool = False) -> None:
        """Stop redrawing and print the summary. Safe to call more than once: the
        first call wins, so a caller about to print an error can close first and
        keep the ticker off its message."""
        self._stop.set()
        if self._ticker is not None:
            self._ticker.join(_JOIN_SECONDS)
        with self._lock:
            if self._closed or not self._total:
                self._closed = True
                return
            self._closed = True
            complete = not interrupted and self._done >= self._total
            if self._live:
                text = self._frame_text(self._summary_lines(complete)) + "\n"
            else:
                text = f"{TOOL_NAME}: {self._plain_summary(complete)}\n"
            with self._output:
                self._write(text)

    def _tick(self) -> None:
        while not self._stop.wait(_TICK_SECONDS):
            with self._lock:
                if self._closed:
                    return
                self._frame += 1
                text = self._frame_text(self.lines())
                # Taken before the state lock is let go, so frames reach the stream in
                # the order they were built even when a write blocks.
                self._output.acquire()
            try:
                self._write(text)
            finally:
                self._output.release()

    # --- state ----------------------------------------------------------------

    def _tally(self, record: dict[str, Any] | None) -> None:
        if record is None:
            return
        wheel = _mapping(record.get("wheel"))
        verdict = _mapping(record.get("verdict"))
        crypto = _mapping(record.get("crypto"))
        # A filename is attacker-controlled and json.loads turns an escaped control
        # character back into a raw one: never hand it to the terminal as is.
        self._last = "".join(
            char if char.isprintable() else "?" for char in str(wheel.get("filename", ""))
        )
        verdict_class = verdict.get("class")
        if isinstance(verdict_class, str):
            self._classes[verdict_class] += 1
        if record.get("errors"):
            self._errors += 1
        libraries = crypto.get("libraries") or []
        if crypto.get("families") or libraries:
            self._with_crypto += 1
        for library in libraries:
            if isinstance(library, dict) and isinstance(library.get("name"), str):
                self._libraries[library["name"]] += 1

    def _all_classes(self) -> list[str]:
        """The precedence, then any class a record carried that it leaves out, so the
        tallies always add up to the records counted."""
        extra = sorted(set(self._classes) - set(self._precedence))
        return [*self._precedence, *extra]

    def _elapsed(self) -> float:
        return max(0.0, self._clock() - self._start)

    def _rate(self) -> float:
        elapsed = self._elapsed()
        return self._done / elapsed if elapsed > 0 else 0.0

    def _eta(self) -> str:
        rate = self._rate()
        if not self._done or rate <= 0:
            return "--:--"
        return _duration((self._total - self._done) / rate)

    # --- rendering ------------------------------------------------------------

    def lines(self, width: int | None = None) -> list[list[Segment]]:
        """The live block, one list of segments per terminal row."""
        width = width or _terminal_width(self._stream)
        percent = 100 * self._done / self._total if self._total else 100.0
        spinner = _SPINNER if self._unicode else "-\\|/"
        head: list[Segment] = [
            (f"{spinner[self._frame % len(spinner)]} ", _CYAN),
            ("Scanning ", _BOLD),
            *self._bar(width),
            (f" {self._done}/{self._total}", _BOLD),
            (f"  {percent:5.1f}%", ""),
            (f"  {self._rate():.1f} wheels/s", _DIM),
            (f"  elapsed {_duration(self._elapsed())}", _DIM),
            ("  ETA ", ""),
            (self._eta(), _BOLD),
        ]
        # Capped by what is left, never measured: with records in submission order,
        # how many workers are idle behind a slow wheel is not visible from here.
        workers = min(self._jobs, max(0, self._total - self._done))
        activity: list[Segment] = [
            (_INDENT, ""),
            (f"{workers} {'worker' if workers == 1 else 'workers'}", _CYAN),
        ]
        if self._last:
            activity += [("  last emitted ", _DIM), (self._last, "")]
        return [head, activity, *self._class_lines(width), *self._evidence_lines(width)]

    def _summary_lines(self, complete: bool) -> list[list[Segment]]:
        width = _terminal_width(self._stream)
        noun = "wheel" if self._done == 1 else "wheels"
        if complete:
            mark = "✔" if self._unicode else "*"
            head: list[Segment] = [(f"{mark} ", _GREEN), (f"Scanned {self._done} {noun}", _BOLD)]
        else:
            mark = "✖" if self._unicode else "!"
            head = [(f"{mark} ", _RED), (f"Interrupted at {self._done}/{self._total}", _BOLD)]
        workers = "worker" if self._jobs == 1 else "workers"
        head += [
            (f" in {_duration(self._elapsed())}", ""),
            (f"  ({self._rate():.1f} wheels/s, {self._jobs} {workers})", _DIM),
        ]
        return [head, *self._class_lines(width), *self._evidence_lines(width)]

    def _bar(self, width: int) -> list[Segment]:
        size = max(10, min(40, width // 4))
        filled = size * self._done // self._total if self._total else size
        full, empty = ("━", "━") if self._unicode else ("#", "-")
        return [(full * filled, _GREEN), (empty * (size - filled), _DIM)]

    def _class_lines(self, width: int) -> list[list[Segment]]:
        chunks: list[list[Segment]] = []
        for index, name in enumerate(self._all_classes()):
            count = self._classes.get(name, 0)
            if name == NO_CRYPTO_DETECTED or not count or name not in self._precedence:
                style = _DIM
            else:
                style = _CLASS_COLOURS[min(index, len(_CLASS_COLOURS) - 1)]
            chunks.append([(name, style), (f" {count}", _BOLD if count else _DIM)])
        return _wrap(chunks, width)

    def _evidence_lines(self, width: int) -> list[list[Segment]]:
        # Errors before libraries: when the row is too narrow, the library names are
        # what should wrap, not the count of wheels that could not be read.
        chunks: list[list[Segment]] = [
            [("crypto in ", _DIM), (str(self._with_crypto), _BOLD), (" wheels", _DIM)],
            [("errors ", _DIM), (str(self._errors), _RED if self._errors else _DIM)],
        ]
        top = sorted(self._libraries.items(), key=lambda item: (-item[1], item[0]))
        for name, count in top[:_TOP_LIBRARIES]:
            chunks.append([(name, ""), (f" {count}", _BOLD)])
        return _wrap(chunks, width)

    def _draw(self, lines: list[list[Segment]]) -> None:
        with self._output:
            self._write(self._frame_text(lines))

    def _write(self, text: str) -> None:
        self._stream.write(text)
        self._stream.flush()

    def _frame_text(self, lines: list[list[Segment]]) -> str:
        """Everything that redraws `lines` over the last frame. Call under `_lock`:
        it records the height of the frame it builds."""
        width = _terminal_width(self._stream)
        out = []
        if self._drawn > 1:
            out.append(f"\x1b[{self._drawn - 1}A")
        out.append("\r")
        out.append("\n".join("\x1b[2K" + self._render(line, width) for line in lines))
        # Blank out whatever an earlier, taller frame left below this one.
        stale = self._drawn - len(lines)
        if stale > 0:
            out.append("".join("\n\x1b[2K" for _ in range(stale)))
            out.append(f"\x1b[{stale}A")
        self._drawn = len(lines)
        return "".join(out)

    def _render(self, segments: list[Segment], width: int) -> str:
        room = width - 1
        parts = []
        for text, style in segments:
            if room <= 0:
                break
            text = text[:room]
            room -= len(text)
            parts.append(f"\x1b[{style}m{text}{_RESET}" if self._colour and style else text)
        return "".join(parts)

    # --- plain mode -----------------------------------------------------------

    def _plain_status(self) -> str:
        percent = 100 * self._done // self._total if self._total else 100
        return (
            f"{self._done}/{self._total} wheels ({percent}%, {self._rate():.1f}/s, "
            f"ETA {self._eta()})"
        )

    def _plain_summary(self, complete: bool) -> str:
        classes = ", ".join(f"{name} {self._classes.get(name, 0)}" for name in self._all_classes())
        state = (
            f"scanned {self._done} wheels"
            if complete
            else f"interrupted at {self._done}/{self._total} wheels"
        )
        return (
            f"{state} in {_duration(self._elapsed())}: {classes}; "
            f"crypto in {self._with_crypto}, errors {self._errors}"
        )


def wants_live(stderr: TextIO, stdout: TextIO, output: Path | None) -> bool:
    """A redrawn block needs stderr to be a terminal, and must not share that terminal
    with records, which would interleave with the redraws. Records reach it through
    stdout, or through an `--output` naming the terminal device: `/dev/stdout`,
    `/dev/tty`, or the pty itself."""
    if os.environ.get("TERM") == "dumb" or not _isatty(stderr):
        return False
    if output is None:
        return not _isatty(stdout)
    return not _is_terminal_of(output, stderr)


def wants_colour(stderr: TextIO) -> bool:
    """Honours the NO_COLOR convention (https://no-color.org)."""
    return not os.environ.get("NO_COLOR") and _isatty(stderr)


def _parse(line: str) -> dict[str, Any] | None:
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    return record if isinstance(record, dict) else None


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _wrap(chunks: list[list[Segment]], width: int) -> list[list[Segment]]:
    """Lay chunks out on indented rows, starting a new row rather than cutting one."""
    rows: list[list[Segment]] = []
    row: list[Segment] = [(_INDENT, "")]
    used = len(_INDENT)
    for chunk in chunks:
        size = sum(len(text) for text, _ in chunk)
        if used > len(_INDENT) and used + 2 + size > width - 1:
            rows.append(row)
            row, used = [(_INDENT, "")], len(_INDENT)
        if used > len(_INDENT):
            row.append(("  ", ""))
            used += 2
        row += chunk
        used += size
    rows.append(row)
    return rows


def _is_terminal_of(path: Path, stream: TextIO) -> bool:
    """True when `path` is the character device behind `stream`, or `/dev/tty`,
    which is always the controlling terminal. Compared by device number, so nothing
    is opened: opening a device to ask it a question can have side effects."""
    try:
        target = os.stat(path)
        if not stat.S_ISCHR(target.st_mode):
            return False
        devices = {os.fstat(stream.fileno()).st_rdev}
    except (OSError, ValueError, AttributeError):
        return False
    try:
        devices.add(os.stat("/dev/tty").st_rdev)
    except OSError:
        pass
    return target.st_rdev in devices


def _isatty(stream: TextIO) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def _terminal_width(stream: TextIO) -> int:
    """The width of the stream drawn on. `shutil.get_terminal_size` asks stdout, which
    is a file or a pipe in exactly the runs that draw a live view on stderr."""
    try:
        return os.get_terminal_size(stream.fileno()).columns
    except (AttributeError, ValueError, OSError):
        return shutil.get_terminal_size(fallback=(100, 24)).columns


def _duration(seconds: float) -> str:
    whole = int(seconds)
    hours, rest = divmod(whole, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes:02d}:{secs:02d}"
