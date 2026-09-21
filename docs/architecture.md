# Architecture

The scanner reads a wheel from its zip in memory, gathers evidence in three layers, runs
the ruleset over that evidence, resolves a linkage posture per crypto library, and
assembles one JSON record. Nothing is extracted to disk and nothing leaves the process.

## Where things live

Everything below is under `src/wheel_crypto_scan/`.

| Path | Role |
|---|---|
| `data/ruleset.toml` | All policy: packages, symbols, strings, crates, libraries, verdicts, linkage |
| `engine.py`, `ruleset.py` | Rule dispatch and matchers |
| `ruleset_loader.py` | Parses and validates the TOML into the `Ruleset` object model `ruleset.py` defines |
| `layers/` | Evidence gathering: wheel metadata, Python AST, binaries, archive inventory |
| `binfmt/` | ELF, Mach-O, PE, Go and Rust readers, the `ar`-archive container reader, the shared strings pass, the shared symbol-table cross-check, the fallback |
| `caps.py` | The shared evidence-preserving cap: one representative per key before filling the rest. Top-level, not under `binfmt/`, because `record.py` caps `evidence.errors` with it too, and must not import the whole binary-reader stack to do it |
| `wheelfile.py` | In-memory zip reading with the bounded decompression window |
| `record.py`, `verdict.py` | Output record shape and verdict assembly |
| `evidence.py` | What extractors may say: the record dataclasses, and the `FORMAT_*`, `STAGE_*`, `BINDING_*` and `PARTIAL_REASONS` vocabularies |
| `errors.py` | The `ScanError` kinds, which the ruleset can match on |

Beside those: `cli.py` (argument parsing and run orchestration), `scan.py` (per-wheel
orchestration), `discovery.py` (turning inputs, a file list or an index URL into wheel
paths), `cache.py` (the record cache), `linkage.py` (posture resolution),
`findings.py` and `report.py`.

## The path a wheel takes

### 1. Reading the archive

`wheelfile.py` opens the zip and applies `ArchiveLimits`: a per-member uncompressed size,
a whole-wheel uncompressed total, and a compression ratio. Members under the in-memory
threshold become `io.BytesIO`; larger ones stream through a seekable zip member that
retains a bounded window of what it has already decompressed, so a multi-gigabyte
extension costs a bounded number of passes rather than a gigabyte of resident memory.
Symlinks are recorded and never followed. Members refused by a limit are recorded in
`artifacts.skipped`.

### 2. Gathering evidence

`layers/` holds four extractors, and they are pure data producers: they never reference
rules and never assign severity, verdict or meaning.

- **`layers/metadata.py`** — what the wheel says about itself. The `dist-info` directory,
  `METADATA`, `WHEEL`, `RECORD`, and any PEP 770 SBOM.
- **`layers/inventory.py`** — what the archive contains, independent of any rule: source
  and bytecode counts, native objects, vendored libraries, symlinks, skipped members.
- **`layers/python_ast.py`** — the Python layer, over `ast.parse`. Call sites, imports,
  attribute reads, `ctypes` loads, and the `usedforsecurity` flag's four states. Details
  are synthesised from the matched pattern, never from `ast.unparse`, whose output varies
  between interpreter versions and would break determinism.
- **`layers/binaries.py`** — decides which members are native objects and hands them to
  `binfmt/`.

Every sequence field the extractors fill in is a tuple already sorted by a stable key,
because the JSON record is emitted in that order and must be byte-identical across runs,
hosts and interpreter versions.

### 3. Reading native objects

`binfmt/` has one reader per format plus the pieces they share.

| Module | Role |
|---|---|
| `detect.py` | Which reader a member's magic bytes select |
| `elf.py` | ELF: sections by `sh_type`, `.dynamic`, `.dynsym`/`.dynstr`, `.symtab`, `.go.buildinfo` |
| `macho.py` | Mach-O, thin and universal: the load-command walk, `LC_SYMTAB`, the slice merge |
| `pe.py` | PE: the header chain, the import and export directories, forwarders |
| `strings.py` | The shared read-only-data strings pass and its byte budget |
| `symtab.py` | The shared symbol-table cross-check and the shared bounded name reader |
| `golang.py`, `rust.py` | Go build info and Rust crates inferred from embedded cargo paths |
| `fallback.py` | Formats with no structural reader: strings only, and say so |

Each reader produces a `BinaryEvidence`, including `partial_analysis` and the
`partial_reasons` tuple saying what it could not read. A structure that does not parse
costs that structure, never the evidence already gathered: a reader that cannot read its
own header still returns the strings, cargo paths and Go markers it found.

`binfmt.symtab`'s cross-check is worth calling out. A symbol table's declared count is not
the same thing as every symbol the object carries, so the count is checked against the
string table it points into: a crypto name in that table that no entry we read named is a
symbol the object carries and did not declare. The check is only sound over a string table
the caller read through, which its docstring states, because moving a check to where two
callers can use it moves its preconditions out of sight.

### 4. Matching and linkage

`engine.py` dispatches each `[rule.match]` to a matcher by `kind`. Every matcher takes the
same `(rule, match, ruleset, evidence, linkage, index)` signature so the engine can drive
them from one table; most ignore most of it. Matches become `Finding` objects, one per rule
and subject rather than per occurrence.

`linkage.py` resolves a posture per crypto library. `_binary_posture` reads one object's
own evidence — its `vendored_path`, each `needed` entry, the defined-versus-imported symbol
split, the version banners, the build strings that tell a compiled-in banner from a
header's, and the Rust crates that bind the library — and returns
`system`, `bundled`, `static`, `unknown` or `mixed`. `_aggregate` combines the objects'
answers into the wheel's. Two or more definite postures disagreeing, whether within one
object or across two, is `mixed`. The whole subsystem's reasoning is in
[OpenSSL linkage](decisions/linkage.md).

### 5. The record

`verdict.py` collects every class that fired and orders them by the ruleset's precedence.
`record.py` builds the JSON: canonical serialisation, sorted keys, ASCII only, no floats,
and the display caps applied **after** findings and the verdict are computed, so a cap can
bound the record without ever deciding what a rule got to see.

## Parallelism

`cli.py` runs `--jobs` worker processes. Two things there are less obvious than they look.

Results are emitted in input order even when scanning in parallel, because `Executor.map`
yields in submission order. Ordering the output by completion would make the JSONL differ
between runs of the same corpus, which would break the determinism promise at the level
people actually diff.

Workers never receive the ruleset over a pickle. Each process loads it once in its
initializer and keeps it in a module global, which avoids serialising compiled regexes and
read-only mappings thirty thousand times.

## Versions in a record

Four numbers travel with every record, and they mean different things.

- **`tool.version`** comes from the git tag at build time.
- **`tool.ruleset_version`** is a string in `ruleset.toml`, bumped on any policy edit. It
  is part of the cache key.
- **`tool.analyzer_version`** is `ANALYZER_VERSION` in `__init__.py`, bumped whenever an
  unchanged wheel would produce a different record. The cache stores *serialised records*,
  so without the bump a stale entry is served and the change silently does not apply to
  anything already scanned.
- **`schema_version`** is different and rarer: adding an optional key or a new value does
  not bump it; removing or retyping a field does.
