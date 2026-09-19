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
| `errors` | array | Non-fatal failures. **A non-empty array means part of the wheel was not examined.** The converse does not hold: several causes record no error, such as a stripped Mach-O or a single import bound by ordinal, and they set `partial_analysis` and a `partial_reasons` token without recording one. Recording no error is not the same as carrying no verdict: only the latter is marked in the reason table below, and every other cause still makes the wheel `OPAQUE`. |

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
| `stripped` | No `.symtab`, or a Mach-O with no `LC_SYMTAB` entries. ELF reads the declared count; Mach-O reads what the table yielded, so a `nsyms` of zero over rows the object does carry is a table we could not use and sets `partial_analysis` instead of this. Never set for PE, whose own symbol table is debug information every linker drops, so there is no absence that could mean this; `symbol_counts.symtab == 0` is how a PE says it named nothing. Normal for release wheels; recorded, not a finding. |
| `truncated` | `{symbols, strings}` — more matches were found than the limits keep, so what is recorded is a sample of what was found rather than all of it. This is **not** the same as the byte budget running out, which is `partial_reasons: ["strings_bytes_unread"]`; an object can have either, both or neither. The sample is chosen to keep one match per string group, one per symbol group and binding, and every crate the ruleset names, so a cap bounds the record's size without silencing a kind of evidence. |
| `partial_analysis` | Part of the object was not read. **This is the field to filter on.** |
| `partial_reasons` | Sorted, deduplicated tokens saying *which* causes applied, empty exactly when `partial_analysis` is false. Six record no entry in `errors`; exactly one of those is also routine rather than a failure and carries no verdict, which is a different thing and is marked in the table below. New values may appear without a `schema_version` bump. |

A PE with genuinely no imports — a resource-only or satellite DLL — therefore always
reads as `partial_analysis: true`, because naming at least one dependency is part of
what clears the flag. That is the conservative direction, and a known source of false
positives rather than a surprise.


Each reason:

| Token | Cause |
|---|---|
| `no_structural_reader` | This tool has no reader for the format, so the object was scanned for strings alone; records no error, because not parsing a format nobody claimed to parse is not a failure. |
| `elf_header_unread` | The ELF header itself would not parse. |
| `elf_section_table_truncated` | The ELF header parsed but the section header table it points at does not fit the object. |
| `elf_sections_unread` | A section header could not be read. A section we cannot name is one we cannot use, so anything derived from the section list may be missing rather than absent: `needed`, `soname`, `rpath`, `runpath`, the symbol counts and the strings alike. |
| `elf_section_data_unread` | A section's bytes could not be read, so the strings pass ran over less than the object holds. |
| `elf_dynamic_unread` | `.dynamic` would not resolve, so `needed`, `soname`, `rpath` and `runpath` are empty because they could not be read, not because the object declares none. |
| `elf_dynsym_unread` | `.dynsym` would not read, named strings `.dynstr` does not hold, or declared fewer entries than `.dynstr` holds names for, so the imported-versus-defined split is missing or partial. |
| `elf_symtab_unread` | `.symtab` would not read, so `stripped` and `symbol_counts.symtab` describe a table we failed on rather than one the object does not have. Does not cost the linkage answer. The imported-versus-defined split comes from `.dynsym` alone. |
| `elf_go_buildinfo_unread` | `.go.buildinfo` would not read, so Go toolchain provenance is missing. Does not cost the linkage answer. |
| `macho_header_unread` | The Mach-O header, or a fat header, would not parse. |
| `macho_symtab_incomplete` | `LC_SYMTAB` was absent, declared no entries, or declared entries this reader could not take at their word: unreachable, naming strings it does not hold, holding nothing but debug records, or declaring fewer entries than the string table holds names for. It records an error unless the table left nothing unexplained -- an absent `LC_SYMTAB`, or one declaring no entries over a string table holding no name it failed to account for -- and that error says which way it fell short. `stripped` and `symbol_counts.symtab` then describe a table we could not use rather than one the object does not have. |
| `macho_fat_slice_unread` | A slice of a universal binary could not be read, or its header named one it did not describe. |
| `pe_header_unread` | The PE header chain would not parse. |
| `pe_section_table_truncated` | The section table was cut short, so an address may resolve to the wrong bytes. |
| `pe_no_import_directory` | No import directory, or one naming no DLL, so the object declared no dependency; records no error. Does not cost the linkage answer. It is an absence the reader observed rather than a read it fell short of: a walk that fell short carries `pe_import_incomplete` instead. |
| `pe_import_incomplete` | An import directory that was there and could not be walked in full. |
| `pe_export_incomplete` | An export directory that was there and could not be read in full. |
| `pe_ordinal_import` | An import named by ordinal alone, so its function has no name to match; routine on Windows, and records no error. Reported by `BIN_PARTIAL_ROUTINE` with no verdict, because the DLL it names survives in `needed`. Does not cost the linkage answer. |
| `pe_ordinal_export` | An export the name table never points at: a definition with no name; records no error. What is lost is a definition, and a definition is how a statically linked copy is recognised, so this is a failure to read rather than a convention: `BIN_PARTIAL_FORMAT` claims it and the wheel is `OPAQUE`. An understated `NumberOfNames` surfaces here, PE having no string table to check the count against. |
| `pe_delay_load` | A delay-load import directory, which this reader does not parse, so the libraries it names are undeclared dependencies; records no error. |
| `strings_bytes_unread` | The reader's byte budget ran out before the object did, so a region of it was never looked at and found nothing there for that reason; records no error. Emitted by every reader, each bounding what it pulls in: `binfmt.elf` bounds the concatenated read-only sections, the other three a prefix of the object. An extension whose only crypto evidence is an OpenSSL version banner past the budget reads exactly like one with no OpenSSL in it. |
| `symtab_understates_rows` | A symbol table declared fewer entries than the string table it points into holds names for, so symbols the object carries were never looked at. The object is not corrupt: every structural check passes and the count is simply not the truth. Emitted by the ELF and Mach-O readers alike, beside that format's own cause, because the lie and the check are the same in both. |

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
| `none` | No OpenSSL evidence, from objects read far enough to say so. |
| `unknown` | Evidence came only from an object we could not read, or some object in the wheel was not read in full and the cause could have hidden what this field is read off. `partial_reasons` names the cause; the ones that leave the answer intact are marked in the reason table above. |

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
