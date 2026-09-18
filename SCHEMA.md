# Output schema

`wheel-crypto-scan scan` emits **JSONL**: one self-contained JSON object per wheel, in
input order. `wheel-crypto-scan schema` prints the machine-readable JSON Schema
(`src/wheel_crypto_scan/data/schema.json`).

**Nothing in this document asserts FIPS compatibility.** The verdict taxonomy has no passing
class and will not acquire one. The tool reports evidence; a human decides.

## Versioning contract

| Change | `schema_version` |
|---|---|
| A new optional key | unchanged |
| A new `rule_id`, `subject_kind`, verdict class, binary format, layer or error kind | unchanged |
| A key removed, renamed, or changed type | **bumped** |

Consumers **must ignore unknown keys** and **must not** treat the documented value lists as
closed. That is why the schema deliberately leaves the verdict class, binary format, layer
and stage fields as open strings: closing them would turn every intended addition into a
breaking change. Pin `tool.ruleset_version` if you need a fixed value set.

Canonical serialisation: keys sorted, ASCII only (`\uXXXX`-escaped), no floats anywhere, no
insignificant whitespace, exactly one trailing newline per record. No host paths,
timestamps, hostnames or user names appear in any field.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | int | Contract version. Currently `1`. |
| `tool` | object | What produced the record. |
| `wheel` | object | Identity of the wheel. |
| `artifacts` | object | What the archive contains. |
| `binaries` | array | Per-object native evidence. |
| `findings` | array | Rules that matched. |
| `verdict` | object | The classification. |
| `errors` | array | Non-fatal failures. **A non-empty array means part of the wheel was not examined.** |

## `tool`

| Field | Type | Meaning |
|---|---|---|
| `name` | string | `wheel-crypto-scan`. |
| `version` | string | Tool version. |
| `ruleset_version` | string | Policy version. Bumped on any ruleset edit; part of the scan cache key. |
| `analyzer_version` | int | Bumped when extraction changes for an unchanged wheel. |
| `evidence_level` | string | `standard` or `minimal`. At `minimal`, `binaries[].matched_symbols`, `matched_strings` and `rust_crates` are **not recorded**, so an empty array there means "not recorded", not "none found". |

## `wheel`

`filename`, `name`, `canonical_name` (PEP 503), `version`, `sha256`, `size_bytes`, `tags`,
`platform_tags`, `requires_python`, `requires_dist`, `root_is_purelib`.

`generator` is an object `{name, version, raw}`, or `null` when the wheel declared none.

Every field except `filename`, `sha256` and `size_bytes` is `null` or empty when the wheel's
metadata could not be read; the record keeps its full shape so consumers never guard for a
missing key.

## `artifacts`

`py_files`, `pyc_files`, `record_entries`, `total_uncompressed_bytes` (ints);
`extensions` (`{path, format}`), `bundled_libs` (paths under `*.libs/` or `.dylibs/`),
`sboms`, `symlinks` (`{path, target}`, recorded and never followed),
`skipped` (`{path, reason}` for members refused by a limit).

`py_files_unparsed` counts source files that would not parse. `binaries_truncated` is
true when the binary and extension lists were capped, so a wheel with thousands of
objects cannot produce an unbounded record.

`source_available` is `false` when the wheel ships no readable Python at all: bytecode
without source, or source that would not parse. **When it is false, the absence of Python
findings means nothing.** Because `ast.parse` follows the running interpreter's grammar,
pin the interpreter if you need records comparable across hosts.

## `binaries`

One entry per native object: `path`, `format`, `machine`, `bits`, `endian`, `elf_type`,
`soname`, `needed`, `rpath`, `runpath`, `rust_crates`, `go`.

For a universal Mach-O that is one entry for the member rather than one per
architecture, because the slices are merged. `matched_symbols` can therefore carry one
name as both `imported` and `defined`, which no single slice can be, when the
architectures disagree; `machine`, `bits` and `endian` describe the first slice alone.
`DECISIONS.md` records why they are merged anyway.

| Field | Meaning |
|---|---|
| `vendored_path` | The object lives in an auditwheel `*.libs/` or delocate `.dylibs/` directory, i.e. the wheel ships it. |
| `matched_symbols[].binding` | **`imported`** = the code lives elsewhere; **`defined`** = this object carries it. This is the distinction the whole tool turns on. |
| `matched_strings[]` | `{group, value}` from read-only data. Version banners land here. |
| `symbol_counts` | `{dynsym, symtab}`, and `symtab` means something different per format: `.symtab` entries in ELF, `LC_SYMTAB` entries in Mach-O, and in PE the things the object named — one per import thunk and one per export slot — because PE has no symbol table of its own to count. |
| `stripped` | No `.symtab`, or a Mach-O with no `LC_SYMTAB` entries. Never set for PE, whose own symbol table is debug information every linker drops, so there is no absence that could mean this; `symbol_counts.symtab == 0` is how a PE says it named nothing. Normal for release wheels; recorded, not a finding. |
| `truncated` | `{symbols, strings}` — evidence was capped. |
| `partial_analysis` | Part of the object was not read: a format with no structural reader (strings only); an object of any format whose header would not parse, which keeps the strings it had already found and is recorded as partial rather than empty; a PE whose section table was truncated, whose import directory was absent or could not be walked, that names an import or an export by ordinal alone, or that carries a delay-load import directory, which this reader does not parse; a Mach-O whose `LC_SYMTAB` could not be read in full; or a fat Mach-O with a slice that could not be read or that its header placed outside the object. A fat Mach-O whose every slice read cleanly is not partial: the slices are merged into one record, with `needed`, `rpath` and `matched_symbols` as sorted unions and `symtab_count` as a sum. |

A PE with genuinely no imports — a resource-only or satellite DLL — therefore always
reads as `partial_analysis: true`, because naming at least one dependency is part of
what clears the flag. That is the conservative direction, and a known source of false
positives rather than a surprise.

## `findings`

One entry per **rule and subject**, not per occurrence.

| Field | Meaning |
|---|---|
| `rule_id` | Stable id from the ruleset. New ids may appear without a version bump. |
| `subject` | The table entry that matched, or `null`. |
| `subject_kind` | What `subject` names: `distribution`, `library`, `crate`, `module`, `symbol_group`, `string_group`, `constant`, `attribute`, `component`, `generator`, `format`. `null` when there is no subject. |
| `severity` | `high` / `medium` / `low` / `info`. **Strength of the evidence, not a compatibility judgement.** |
| `category`, `layer`, `confidence` | Classification, source layer, and how sure we are the match means what we think. |
| `verdict` | The class this finding pushes the wheel into, or `null` for informational findings. |
| `occurrences` | Number of **distinct locations**. Two calls on one line count once. |
| `truncated` | The `locations` list was capped; `occurrences` still holds the full count. |
| `locations[]` | `{path, line, evidence}`. `line` is `null` for non-source findings. `evidence` is the literal matched text, printable ASCII, capped. |

## `verdict`

| Field | Meaning |
|---|---|
| `class` | The highest-precedence class that fired. Always equals `classes[0]`. |
| `classes` | **Every** class that fired, in precedence order. A wheel can be more than one thing. |
| `rule_ids`, `reasons` | Which rules produced the class, and a one-line reason each. |
| `conditions` | Resolved conditions, keyed `<library>_linkage`. |
| `needs_human_review` | `false` only when nothing was found and nothing failed. |

### `conditions.openssl_linkage`

The field most consumers filter on. Always present.

| Value | Meaning |
|---|---|
| `system` | Resolves `libcrypto`/`libssl` from the host, so it inherits the host's FIPS provider and crypto policy. **The condition under which a `CONDITIONAL` wheel is acceptable.** |
| `bundled` | Ships its own copy, in a vendor directory or via a hash-renamed dependency. Cannot see the system provider. |
| `static` | Compiled in, with no library file and no declared dependency. Same consequence as `bundled`, harder to spot. |
| `mixed` | Both postures across different objects in one wheel. |
| `none` | No OpenSSL evidence. |
| `unknown` | Evidence came only from an object we could not read. |

Other libraries appear as `<name>_linkage` when they have evidence.

### Verdict classes

| Class | Meaning |
|---|---|
| `NON_APPROVED_CRYPTO` | Implements or bundles a non-FIPS-approved primitive. |
| `FIPS_BREAKING` | Will raise at runtime under FIPS-enforcing mode. |
| `CONDITIONAL` | Approved only under a stated condition; read `conditions`. |
| `CONTEXT_DEPENDENT` | Non-approved primitive that may be a non-security use. |
| `OPAQUE` | Stripped, unreadable or source-free. Cannot determine. |
| `NO_CRYPTO_DETECTED` | Nothing found. **Absence of evidence, not evidence of absence.** |

Listed in precedence order, which lives in the ruleset's `[verdict] precedence` and can be
reordered there.

## `errors`

`{stage, kind, path, message}` where `stage` is `archive`, `metadata`, `binary` or `python`.
Messages are deterministic and contain no host paths.

A wheel that could not be read is `OPAQUE`, never `NO_CRYPTO_DETECTED`. Every error kind the
scanner can record has a rule that turns it into a finding, and a test enforces that.

## Triage recipes

```bash
# Wheels that ship or statically link their own OpenSSL
jq -r 'select(.verdict.conditions.openssl_linkage | IN("bundled","static")) | .wheel.filename' index.jsonl

# Wheels that will raise under FIPS-enforcing mode, with the first reason
jq -r 'select(.verdict.class == "FIPS_BREAKING") | "\(.wheel.name)\t\(.verdict.reasons[0])"' index.jsonl

# Wheels we could not fully read — treat as unknown, not clean
jq -r 'select(.verdict.class == "OPAQUE" or (.errors | length > 0)) | .wheel.filename' index.jsonl

# Everything still needing a human
jq -r 'select(.verdict.needs_human_review) | .wheel.filename' index.jsonl | wc -l
```
