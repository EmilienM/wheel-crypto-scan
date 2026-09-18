# wheel-crypto-scan

Static analyser that reports crypto-relevant **evidence** inside Python wheels so consumers
of a package index can see per-wheel FIPS risk. It gathers evidence; it does not decide
compliance. Read `README.md` for what it detects and `SCHEMA.md` for the output contract.

## Invariants

These are design decisions, not accidents. Do not change one without saying so explicitly.

- **No passing verdict class.** The taxonomy has no "compliant" and must never acquire one.
  A human makes that call.
- **Deterministic output.** Same wheel in, byte-identical JSONL out, across `--jobs`, cache
  state, and interpreter version. Output is sorted, ASCII-only, float-free, and carries no
  host paths, timestamps or hostnames.
- **Unreadable means `OPAQUE`, never `NO_CRYPTO_DETECTED`.** Absence of evidence is not
  evidence of absence, and a test asserts every recordable failure maps to a rule.
- **One bad wheel never aborts a run.** Failures become error records. The broad
  `except Exception` handlers are deliberate; pylint is configured to allow them.
- **No network, no LLM, no dataflow analysis at runtime.** The only network access is an
  explicitly requested `--index-url` download.

## Where things live

| Path | Role |
|---|---|
| `data/ruleset.toml` | All policy: packages, symbols, strings, crates, libraries, verdicts |
| `engine.py`, `ruleset.py` | Rule dispatch and matchers |
| `layers/` | Evidence gathering: wheel metadata, Python AST, binaries, archive inventory |
| `binfmt/` | ELF, Mach-O, PE, Go, Rust and string readers |
| `wheelfile.py` | In-memory zip reading with the bounded decompression window |
| `record.py`, `verdict.py` | Output record shape and verdict assembly |

## Working rules

- **Policy goes in `ruleset.toml`, not Python.** Nothing in the scanner hardcodes a package
  name, symbol, library or verdict. Every entry carries a `why` in plain language; write one
  for anything you add.
- **Bump `ruleset_version` after editing the ruleset.** It is part of the cache key, so the
  bump is what re-evaluates already-scanned wheels.
- **Keep `record.py` and `data/schema.json` in step,** and update `SCHEMA.md` with them. A
  test fails on drift.
- **Dependencies are `pyelftools` and `packaging`.** Ask before adding a third.
- **Test fixtures are synthesised,** including the ELF objects (`tests/helpers/`). The suite
  needs no compiler, no network and no committed binaries. Keep it that way.
- Wheels are read from the zip in memory, never extracted to disk.

## Commands

```bash
uvx --with tox-uv tox              # py311-py314, ruff lint and format, pylint
uvx --with tox-uv tox -e lint      # ruff check --select=E,F,W, then ruff format --check
uvx --with tox-uv tox -e format    # apply formatting
uvx --with tox-uv tox -e real      # opt-in, needs real wheels in WCS_CORPUS_DIR
uv run wheel-crypto-scan scan /path/to/wheels -o index.jsonl --jobs 8
```

Tests marked `real` and `hostbin` are deselected by default: they need downloaded wheels or
host system libraries. Line length is 100.

## Releasing

A bare semver tag triggers publishing, and nothing else does. There is no version in the
repo to bump: `uv-dynamic-versioning` derives it from the tag.

```bash
git tag -a 0.1.0 -m "0.1.0" && git push origin 0.1.0
```
