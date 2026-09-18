"""Command line entry point: argument parsing and run orchestration.

Two things here are less obvious than they look.

Results are emitted in input order even when scanning in parallel, because
`Executor.map` yields in submission order. Ordering the output by completion would make
the JSONL differ between runs of the same corpus, which would break the determinism
promise at the level people actually diff.

Workers never receive the ruleset over a pickle. Each process loads it once in its
initializer and keeps it in a module global, which avoids serialising compiled regexes
and read-only mappings thirty thousand times.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator, Sequence
from concurrent.futures import ProcessPoolExecutor
from importlib.resources import files
from pathlib import Path
from typing import Any, TextIO

from . import TOOL_NAME, __version__
from .cache import RecordCache, default_cache_root
from .discovery import discover
from .record import EVIDENCE_LEVELS, to_json_line
from .report import render_markdown
from .ruleset import Ruleset, load_ruleset
from .scan import ScanContext, scan_wheel
from .wheelfile import ArchiveLimits, hash_wheel

_PROGRESS_EVERY = 100

_CONTEXT: ScanContext | None = None
_CACHE: RecordCache | None = None


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules(args)
    if args.command == "schema":
        return _run_schema()
    parser.error(f"unknown command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Report crypto-relevant evidence found inside Python wheels. "
            "This tool gathers evidence; it does not decide FIPS compliance."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan wheels and emit one record each")
    scan.add_argument("inputs", nargs="*", help="wheel files or directories to search")
    scan.add_argument("-o", "--output", type=Path, help="write here instead of stdout")
    scan.add_argument("--format", choices=("jsonl", "md"), default="jsonl")
    scan.add_argument("--jobs", type=int, default=1, help="worker processes (default 1)")
    scan.add_argument("--ruleset", type=Path, help="use this ruleset instead of the shipped one")
    scan.add_argument("--evidence-level", choices=EVIDENCE_LEVELS, default="standard")
    scan.add_argument("--from-file", type=Path, help="read wheel paths from this file")
    scan.add_argument("--index-url", help="PEP 503 simple index page to download wheels from")
    scan.add_argument("--download-dir", type=Path, help="where --index-url downloads land")
    scan.add_argument("--cache-dir", type=Path, default=None)
    scan.add_argument("--no-cache", action="store_true")
    scan.add_argument(
        "--resume",
        action="store_true",
        help="keep records already in --output and scan only the rest, keyed on wheel filename",
    )
    scan.add_argument("--max-binary-bytes", type=int, default=ArchiveLimits().max_member_bytes)
    scan.add_argument(
        "--max-total-bytes", type=int, default=ArchiveLimits().max_total_uncompressed_bytes
    )
    scan.add_argument("-q", "--quiet", action="store_true", help="no progress on stderr")

    rules = sub.add_parser("rules", help="print the rule table for review")
    rules.add_argument("--format", choices=("md", "json"), default="md")
    rules.add_argument("--ruleset", type=Path)

    sub.add_parser("schema", help="print the JSON Schema for the output records")
    return parser


# --- scan -------------------------------------------------------------------


def _run_scan(args: argparse.Namespace) -> int:
    if not args.inputs and not args.from_file and not args.index_url:
        print(f"{TOOL_NAME}: nothing to scan", file=sys.stderr)
        return 2

    ruleset = load_ruleset(args.ruleset)
    wheels = discover(
        args.inputs,
        from_file=args.from_file,
        index_url=args.index_url,
        download_dir=args.download_dir,
    )

    existing: dict[str, str] = {}
    if args.resume and args.output is not None:
        existing = _existing_records(args.output)

    pending = [wheel for wheel in wheels if wheel.name not in existing]
    scanned = _scan_all(pending, args, ruleset)
    if not args.quiet:
        scanned = _with_progress(scanned, len(pending))

    # Reuse kept records in discovery order rather than prepending them. Resuming an
    # interrupted run has to produce the same bytes as scanning from scratch, for the
    # same reason parallelism does.
    return _write(_merge(wheels, existing, scanned), args)


def _merge(
    wheels: Sequence[Path], existing: dict[str, str], scanned: Iterator[str]
) -> Iterator[str]:
    for wheel in wheels:
        kept = existing.get(wheel.name)
        yield kept if kept is not None else next(scanned)


def _scan_all(wheels: Sequence[Path], args: argparse.Namespace, ruleset: Ruleset) -> Iterator[str]:
    settings = _worker_settings(args, ruleset)
    if args.jobs <= 1:
        _init_worker(settings)
        for wheel in wheels:
            yield _scan_path(str(wheel))
        return
    with ProcessPoolExecutor(
        max_workers=args.jobs, initializer=_init_worker, initargs=(settings,)
    ) as pool:
        # map yields in submission order, so parallelism never reorders the output.
        yield from pool.map(_scan_path, [str(wheel) for wheel in wheels])


def _worker_settings(args: argparse.Namespace, ruleset: Ruleset) -> dict[str, Any]:
    """Only picklable primitives cross the process boundary."""
    return {
        "ruleset_path": str(args.ruleset) if args.ruleset else None,
        "ruleset_version": ruleset.version,
        "evidence_level": args.evidence_level,
        "max_member_bytes": args.max_binary_bytes,
        "max_total_uncompressed_bytes": args.max_total_bytes,
        "cache_root": str(args.cache_dir) if args.cache_dir else str(default_cache_root()),
        "cache_enabled": not args.no_cache,
    }


def _init_worker(settings: dict[str, Any]) -> None:
    global _CONTEXT, _CACHE
    ruleset = load_ruleset(settings["ruleset_path"])
    _CONTEXT = ScanContext.build(
        ruleset,
        evidence_level=settings["evidence_level"],
        archive_limits=ArchiveLimits(
            max_member_bytes=settings["max_member_bytes"],
            max_total_uncompressed_bytes=settings["max_total_uncompressed_bytes"],
        ),
    )
    _CACHE = RecordCache(
        root=Path(settings["cache_root"]),
        ruleset_version=settings["ruleset_version"],
        evidence_level=settings["evidence_level"],
        enabled=settings["cache_enabled"],
    )


def _scan_path(path: str) -> str:
    assert _CONTEXT is not None and _CACHE is not None
    digest = hash_wheel(path)
    cached = _CACHE.get(digest)
    if cached is not None:
        return cached
    line = to_json_line(scan_wheel(path, _CONTEXT, sha256=digest))
    _CACHE.put(digest, line)
    return line


def _with_progress(lines: Iterable[str], total: int) -> Iterator[str]:
    for index, line in enumerate(lines, start=1):
        if index % _PROGRESS_EVERY == 0 or index == total:
            print(f"{TOOL_NAME}: {index}/{total} wheels", file=sys.stderr)
        yield line


def _existing_records(output: Path) -> dict[str, str]:
    """Complete records already in the output file, keyed by wheel filename.

    An interrupted run can leave a truncated final line, so anything that does not
    parse is dropped and rescanned rather than trusted.
    """
    records: dict[str, str] = {}
    try:
        text = output.read_text(encoding="utf-8")
    except OSError:
        return records
    for line in text.splitlines():
        try:
            filename = json.loads(line)["wheel"]["filename"]
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
        records[filename] = line + "\n"
    return records


def _write(lines: Iterable[str], args: argparse.Namespace) -> int:
    """Stream records out. Only the Markdown summary needs them all in memory at once."""

    def emit(stream: TextIO) -> None:
        if args.format == "md":
            stream.write(render_markdown([json.loads(line) for line in lines]))
        else:
            stream.writelines(lines)

    if args.output is None:
        emit(sys.stdout)
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".partial")
    with temporary.open("w", encoding="utf-8") as stream:
        emit(stream)
    temporary.replace(args.output)
    return 0


# --- rules and schema -------------------------------------------------------


def _run_rules(args: argparse.Namespace) -> int:
    ruleset = load_ruleset(args.ruleset)
    if args.format == "json":
        payload = {
            "ruleset_version": ruleset.version,
            "precedence": list(ruleset.precedence),
            "rules": [
                {
                    "id": rule.id,
                    "layer": rule.layer,
                    "category": rule.category,
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "verdict": rule.verdict,
                    "needs_human_review": rule.needs_human_review,
                    "title": rule.title,
                    "why": rule.why,
                }
                for rule in ruleset.rules
            ],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"# Ruleset {ruleset.version}\n")
    for rule in ruleset.rules:
        print(f"## {rule.id}\n")
        print(f"- **{rule.title}**")
        print(f"- layer: {rule.layer} | category: {rule.category} | severity: {rule.severity}")
        review = "yes" if rule.needs_human_review else "no"
        print(f"- verdict: {rule.verdict or '-'} | review: {review}")
        print(f"\n{rule.why}\n")
    return 0


def _run_schema() -> int:
    schema = files("wheel_crypto_scan").joinpath("data/schema.json").read_text(encoding="utf-8")
    sys.stdout.write(schema)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
