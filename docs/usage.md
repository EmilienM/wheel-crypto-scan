# Install and run

## Install

The project ships as an ordinary Python distribution with two runtime dependencies,
`pyelftools` and `packaging`. It needs Python 3.11 or newer.

```bash
uv tool install .          # installs the wheel-crypto-scan command
uv run wheel-crypto-scan   # or run it straight out of the source tree
```

The distribution carries `data/ruleset.toml` and `data/schema.json` inside it, and the
release workflow checks that both are present before publishing.

Versions come from the git tag through `uv-dynamic-versioning`, so the version in a record
is the version that produced it. An untagged build reports its commit, for example
`0.0.0.post14.dev0+1105fe9`, which makes it obvious when a record came from something
other than a release.

## Commands

There are three subcommands.

```bash
wheel-crypto-scan scan /path/to/wheels -o index.jsonl --jobs 8
wheel-crypto-scan rules                 # the rule table, for review
wheel-crypto-scan schema                # the JSON Schema for the output
```

`--version` prints the tool version and exits.

### `scan`

Reads wheels and emits one self-contained record per wheel, **in input order** even under
`--jobs`, because parallelism must never reorder the output.

```
wheel-crypto-scan scan [INPUTS...] [options]
```

`INPUTS` are wheel files or directories to search. A run needs at least one of `INPUTS`,
`--from-file` or `--index-url`, or it exits 2 with `nothing to scan`.

| Flag | Meaning |
|---|---|
| `-o`, `--output PATH` | Write here instead of stdout. A regular file is written to a `.partial` sibling and renamed into place, so an interrupted run never leaves a half-written record file. |
| `--format {jsonl,md,html}` | `jsonl` (default) streams one record per line; `md` renders a Markdown summary and needs every record in memory at once. `html` writes one self-contained page with no external assets, byte-stable for the same records and ruleset, and also holds every record in memory. |
| `--jobs N` | Worker processes, default 1. Each worker loads the ruleset once in its initializer rather than receiving it over a pickle. |
| `--ruleset PATH` | Use this ruleset instead of the shipped one. |
| `--evidence-level {minimal,standard}` | At `minimal`, `binaries[].matched_symbols`, `matched_strings` and `rust_crates` are **not recorded**, so an empty array there means "not recorded", not "none found". |
| `--from-file PATH` | Read wheel paths from this file. |
| `--index-url URL` | A PEP 503 simple index page to download wheels from. This is the only network access the tool ever makes. |
| `--download-dir PATH` | Where `--index-url` downloads land. |
| `--cache-dir PATH` | Where the record cache lives. Defaults to the per-user cache root. |
| `--no-cache` | Do not read or write the record cache. |
| `--resume` | Keep JSONL records already in `--output` and scan only the rest, keyed on wheel filename. Any other `--format` exits 2 before scanning anything. |
| `--max-binary-bytes N` | Archive limit on one member's uncompressed size. |
| `--max-total-bytes N` | Archive limit on the wheel's total uncompressed size. |
| `-q`, `--quiet` | No progress on stderr. On a terminal, progress is a live view: a bar with rate and ETA, the worker count, the last wheel emitted, and running tallies of verdict classes, errors and libraries. Elsewhere, or when records go to the same terminal (through stdout or an `--output` naming it), a line is printed every 100 wheels with rate and ETA, then a summary. A run that stops early says so instead of reporting success. `NO_COLOR` turns colour off. |

### `rules`

Prints the rule table for review. `--format md` (default) renders one section per rule with
its id, layer, category, severity, verdict, review flag and its `why` in plain language;
`--format json` prints the same data machine-readably, with the ruleset version and the
verdict precedence list. `--ruleset PATH` reads an alternative ruleset.

This is the command to hand a crypto engineer who wants to audit the policy without reading
any Python.

### `schema`

Prints `data/schema.json`, the machine-readable JSON Schema for the output records, on
stdout. See [Output schema](output-schema.md) for the prose contract.

## Caching and `--resume`

Records are cached by the wheel's content hash and filename together (two byte-identical
archives published under different names are two different records), keyed further by the
schema version, the analyzer version, the ruleset version, the evidence level, the tool
version and the archive limits. Bumping `ruleset_version` is what makes previously scanned
wheels get re-evaluated.

Not every record is cached. A record carrying a failure kind this scanner cannot yet prove
is deterministic for the wheel's own bytes is neither written to the cache nor treated as
already done by `--resume`, because such a record may reflect a condition (memory pressure,
a transient I/O error) that is already gone by the time anyone reads it back.
[A record produced without reading the wheel is never cached](design-summaries/tooling.md#a-record-produced-without-reading-the-wheel-is-never-cached)
has the reasoning and the measured cost.

`--resume` reads complete records back out of `--output`. Anything that does not parse, such
as a truncated final line from an interrupted run, is dropped and rescanned rather than
trusted. Reused records are emitted in discovery order rather than prepended, so resuming an
interrupted run produces the same bytes as scanning from scratch.

Only JSONL can be read back, so `--resume` with `--format md` or `html` exits 2 before
scanning anything rather than silently rescanning every wheel and overwriting the view. To
get a Markdown or HTML view of a resumed run, resume the JSONL, then render it in a separate
run with the cache warm.

## Triage recipes

```bash
# Wheels that ship or statically link their own OpenSSL (misses "mixed" -- a wheel that
# also links the system library from some object, or in one object alongside its own
# copy; add "mixed" to the set below to include those too)
jq -r 'select(.verdict.conditions.openssl_linkage | IN("bundled","static")) | .wheel.filename' index.jsonl

# Wheels that will raise under FIPS-enforcing mode, with the first reason
jq -r 'select(.verdict.class == "FIPS_BREAKING") | "\(.wheel.name)\t\(.verdict.reasons[0])"' index.jsonl

# Wheels we could not fully read -- treat as unknown, not clean
jq -r 'select(.verdict.class == "OPAQUE" or (.errors | length > 0)) | .wheel.filename' index.jsonl

# Everything still needing a human
jq -r 'select(.verdict.needs_human_review) | .wheel.filename' index.jsonl | wc -l

# Non-approved headline that may come from a wheel's own OpenSSL build rather than its own code
jq -r 'select(.verdict.class == "NON_APPROVED_CRYPTO" and (.verdict.conditions.openssl_linkage | IN("static","bundled","mixed"))) | .wheel.filename' index.jsonl

# Wheels whose findings are explained entirely by an algorithm implemented outside
# any FIPS-validated module -- no other relation contributed
jq -r 'select(.verdict.relations == ["outside_module"]) | .wheel.filename' index.jsonl
```

## Pinning the interpreter

`ast.parse` follows the grammar of the interpreter running it, so a wheel using syntax
newer than the scanner's interpreter will not parse. Pin the interpreter if you need
records comparable across hosts. The difference is never silently favourable: unparsed
files are counted in `artifacts.py_files_unparsed`, and a wheel whose every source file
failed reports `source_available: false` and comes out `OPAQUE`.
