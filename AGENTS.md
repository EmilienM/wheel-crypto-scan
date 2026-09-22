# wheel-crypto-scan

Static analyser that reports crypto-relevant **evidence** inside Python wheels so consumers
of a package index can see per-wheel FIPS risk. It gathers evidence; it does not decide FIPS
compatibility. Read `README.md` for what it detects, `SCHEMA.md` for the output contract, and
`DESIGN.md` for the design calls that cost something, including the holes left open on
purpose and the measurement behind each one.

## Invariants

These are design decisions, not accidents. Do not change one without saying so explicitly.

- **No passing verdict class.** The taxonomy has no passing class, no "compliant" and no
  "compatible", and must never acquire one. A human makes that call.
- **Deterministic output.** Same wheel in, byte-identical JSONL out, across `--jobs`, cache
  state, and interpreter version. Output is sorted, ASCII-only, float-free, and carries no
  host paths, timestamps or hostnames.
- **Unreadable means `OPAQUE`, never `NO_CRYPTO_DETECTED`.** Absence of evidence is not
  evidence of absence, and a test asserts every recordable failure maps to a rule. One
  carve-out, in `DESIGN.md`: a `partial_reasons` cause that is a linker convention
  rather than a failure is recorded without a verdict. Today that is one cause, an
  ordinal import, and only because the dependency name survives it -- when it is a name
  the ruleset knows, which `DESIGN.md` measures rather than assumes. An ordinal
  *export* is not on that list: it loses a definition, and a definition is how `static`
  is recognised, so the argument that admits the import does not apply to it. Adding
  to this list is changing this invariant, and the admission test is behavioural
  rather than editorial: go and find a crypto object that reads clean because the
  cause is on the list. If it exists the cause does not belong there, whatever the
  sentence says. That list is also the floor of the linkage exemptions below; the
  loader refuses a ruleset that drops an exemption without re-rating, and a test pins
  the other direction.
- **A structure that does not parse costs that structure, never the evidence already
  gathered.** A reader that cannot read its own header still returns the strings, cargo
  paths and Go markers it found, and still marks the object `partial_analysis`. The
  strings are often the only evidence there is: `cryptography` 42 and later compiles
  OpenSSL into the extension, with no library file and no dependency to name.
- **A name reported is a name read in full.** Never put bytes in `matched_symbols` that
  the object did not spell out: an index past the end of a string table, or into a run it
  never closes, is a name we could not resolve, not a short name. Recording what was
  reachable looks like the safe direction and is not -- it asserts a symbol that does not
  exist, in the field the whole tool turns on. Both binary readers resolve names this
  way, and a test holds each to it.
- **`partial_analysis` and `partial_reasons` never disagree.** The tuple is non-empty
  exactly when the boolean is true, asserted across every reader. Filter on the boolean;
  read the tuple to find out what to do about it.
- **One bad wheel never aborts a run.** Failures become error records. The broad
  `except Exception` handlers are deliberate; pylint is configured to allow them.
- **No network, no LLM, no dataflow analysis at runtime.** The only network access is an
  explicitly requested `--index-url` download.

## Where things live

| Path | Role |
|---|---|
| `data/ruleset.toml` | All policy: packages, symbols, strings, crates, libraries, verdicts, linkage |
| `engine.py`, `ruleset.py` | Rule dispatch and matchers |
| `ruleset_loader.py` | Parses and validates the TOML into the `Ruleset` object model `ruleset.py` defines |
| `conventions.py` | `Conventions`/`SonameInfo`, the structural facts about wheel layout, and their `[conventions]` parser |
| `layers/` | Evidence gathering: wheel metadata, Python AST, binaries, archive inventory |
| `binfmt/` | ELF, Mach-O, PE, Go and Rust readers, the `ar`-archive container reader, the shared strings pass, the shared symbol-table cross-check, the fallback |
| `caps.py` | The shared evidence-preserving cap: one representative per key before filling the rest. Top-level, not under `binfmt/`, because `record.py` caps `evidence.errors` with it too, and must not import the whole binary-reader stack to do it |
| `wheelfile.py` | In-memory zip reading with the bounded decompression window |
| `record.py`, `verdict.py` | Output record shape and verdict assembly |
| `evidence.py` | What extractors may say: the record dataclasses, and the `FORMAT_*`, `STAGE_*`, `BINDING_*` and `PARTIAL_REASONS` vocabularies |
| `errors.py` | The `ScanError` kinds, which the ruleset can match on |
| `report.py`, `data/report.html` | Human views of the records: the Markdown table and the self-contained HTML page |

## Working rules

- **Policy goes in `ruleset.toml`, not Python.** Nothing in the scanner hardcodes a package
  name, symbol, library or verdict. Every entry carries a `why` in plain language; write one
  for anything you add.
- **Bump `ruleset_version` after editing the ruleset.** It is part of the cache key, so the
  bump is what re-evaluates already-scanned wheels.
- **Bump `ANALYZER_VERSION` when an unchanged wheel would produce a different record.**
  Extraction, a new field, a changed verdict: all of it. The cache stores *serialised
  records*, so without the bump a stale entry is served and the change silently does not
  apply to anything already scanned. It is easy to forget because nothing fails without
  it. `schema_version` is different and rarer: adding an optional key or a new value does
  not bump it, removing or retyping a field does.
- **Vocabularies are facts, policy is what to do about them.** `FORMAT_*`, `PARTIAL_REASONS`
  and the error kinds live in Python because they describe what a reader did; which of
  them is worth a verdict lives in `ruleset.toml`, matched through `kind = "scan_error"`
  or `kind = "partial_binary"`. A token named by a rule is validated at load time, so a
  typo is a load error rather than a rule that silently matches nothing.
- **A prefilter lives beside the matcher it mirrors.** A reader that restates "could
  this match" in cheaper terms -- over raw bytes, before decoding -- puts the cheap
  version in `ruleset.py` next to the real one, with a test that fails when the real one
  grows an arm. A prefilter that quietly stops matching what the matcher matches loses
  evidence and fails nothing: `BinaryPatterns.symbol_locator` is the worked example.
- **One vocabulary can carry more than one split, and they must not be assumed equal.**
  `PARTIAL_REASONS` is read twice: a `partial_binary` rule with no verdict says which
  causes are not worth one, and `[linkage_policy] exclude_reasons` says which leave a
  linkage posture answerable. They differ, and the one containment between them is
  refused at load time rather than left to a test over the shipped ruleset. Reusing a
  list because it looks like the same question is how a field gets an answer nothing
  decided.
- **A shared check states what it assumes.** `binfmt.symtab` is only sound over a string
  table the caller read through, and moving it to a reader that does not guarantee that
  opens a hole. Moving a check to where two callers can use it moves its preconditions
  out of sight, so they go in its docstring.
- **A pass over a whole object belongs in C.** Every such pass runs once per slice of a
  universal binary, up to `_MAX_FAT_SLICES`, over regions the slices are free to share.
  A Python loop over a 2 MiB string table takes 19 seconds across one object; the same
  check as one compiled regex takes 1.2. `tests/test_hardening.py` is where that is held.
- **Keep `record.py` and `data/schema.json` in step,** and update `SCHEMA.md` with them. A
  test fails on drift, and so does `docs/output-schema.md`, the site's copy of its tables
  and prose.
- **Dependencies are `pyelftools` and `packaging`.** Ask before adding a third.
- **Imports go at the top of the file,** in `src/` and `tests/` alike: no import inside a
  function, a test or a branch. Pylint's `import-outside-toplevel` holds `src/` to it
  (`tox -e pylint`) and ruff's `PLC0415` holds `tests/` (`tox -e lint`).
- **Test fixtures are synthesised,** including the object files: `tests/helpers/binfmt/`
  writes ELF, Mach-O and PE byte for byte with `struct`. The suite needs no compiler, no
  network and no committed binaries. Keep it that way.
- **Break a guard to see whether it guards.** Much of this suite exists to hold an
  invariant rather than a behaviour, and such a test passes just as well when it asserts
  nothing. Deleting the line under test, or mutating it to the wrong answer, is the only
  way to tell. The obvious version of a guard often stays green with the line it guards
  deleted.
- **Write down the current design, not its history.** Comments, docstrings, test names,
  ruleset `why` text, `SCHEMA.md`, `DESIGN.md` and `docs/` say what the code does and
  why, as if it had always been this way. No issue or PR numbers, no "found by review",
  no "used to", "previously", "an earlier version", "before this fix", "revised",
  "corrected", "extended in". Keep the reasoning, the measurement and the rejected
  alternative, and describe a rejected approach as an alternative ("keying on the name
  alone reads X"), not as something the code once did. History belongs in the commit
  message and the PR. A test file is named for its topic, never for the review or fix
  that produced it. `tests/test_design_notes.py` catches citations, review framing, a
  quoted `DESIGN.md` heading that no longer exists, and a Markdown heading wrapped onto
  a second source line; the rest is on the writer.
- Wheels are read from the zip in memory, never extracted to disk.

## Commands

```bash
uvx --with tox-uv tox              # py311-py314, ruff lint and format, pylint
uvx --with tox-uv tox -e lint      # ruff check --select=E,F,W,PLC0415, then ruff format --check
uvx --with tox-uv tox -e format    # apply formatting
uvx --with tox-uv tox -e real      # opt-in, needs real wheels in WCS_CORPUS_DIR
uv run wheel-crypto-scan scan /path/to/wheels -o index.jsonl --jobs 8
```

Tests marked `real` are deselected by default: they need a corpus of real wheels
(`WCS_CORPUS_DIR`). Tests marked `hostbin` run by default and self-skip on a host without
the system library they check; CI sets `WCS_REQUIRE_HOSTBIN=1`, which turns that skip
into a failure. Line length is 100.

## Releasing

A bare semver tag triggers publishing, and nothing else does. There is no version in the
repo to bump: `uv-dynamic-versioning` derives it from the tag.

```bash
git tag -a 0.1.0 -m "0.1.0" && git push origin 0.1.0
```
