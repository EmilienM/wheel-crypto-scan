# Vocabularies

These are the fixed token sets the record uses, with one exception: `[[standard]].status`
never reaches a record -- it is parsed into the loaded `Ruleset` for the CLI and the HTML
report to read back on demand, not carried on the finding that cites the standard (see
"The ruleset cites a standard and the record carries only the pointer" in `DESIGN.md`).
The rest live in Python because they describe what a reader did; which of them is worth a
verdict lives in `ruleset.toml`. A token named by a rule is validated at load time, so a
typo is a load error rather than a rule that silently matches nothing.

They are part of the output contract. Adding a value is not a `schema_version` bump;
renaming or removing one is.

## `ScanError` kinds

`errors.py`. Every failure the scanner can survive has a stable `kind` string here. The
ruleset matches on these strings through `[rule.match] kind = "scan_error"`, and every kind
has a rule that turns it into a finding — a test enforces that, because a recordable failure
with no rule behind it is how a wheel reads clean for a reason nobody decided.

### Archive stage

| Kind | Meaning |
|---|---|
| `bad_zip` | Not a readable zip at all: `zipfile.BadZipFile`, `OSError` or `ValueError` while opening the archive, or the same trio plus `EOFError` while reading a member. A specific, checked claim about the archive's own bytes. |
| `duplicate_member` | A filename appears twice in the archive. |
| `size_limit_exceeded` | A member's declared uncompressed size is over the archive limit. |
| `compression_ratio_exceeded` | A member's compression ratio is over the archive limit. |
| `member_read_error` | A member could not be read. Recorded from a catch broad enough to admit a transient `MemoryError` or `OSError` alongside a genuinely corrupt member. |
| `unexpected_error` | An exception the collector did not specifically anticipate cut the read short before anything else ran. Distinct from `bad_zip`: this kind makes no claim about the wheel at all. |

### Metadata stage

| Kind | Meaning |
|---|---|
| `dist_info_missing` | No `.dist-info` directory. |
| `dist_info_ambiguous` | More than one `.dist-info` directory. |
| `metadata_missing` | No `METADATA`. |
| `metadata_decode_error` | `METADATA` would not decode or parse. |
| `wheel_missing` | No `WHEEL` file. |
| `wheel_filename_invalid` | The wheel's own filename does not parse as a wheel name. |
| `record_missing` | No `RECORD`. |
| `record_parse_error` | `RECORD` would not parse. |
| `sbom_parse_error` | A PEP 770 SBOM would not parse. |

### Binary stage

| Kind | Meaning |
|---|---|
| `elf_parse_error` | The ELF reader failed. |
| `macho_parse_error` | The Mach-O reader failed. |
| `pe_parse_error` | The PE reader failed. |
| `binary_truncated` | The object is shorter than its own headers claim. |
| `binary_too_large` | The object is over the per-member limit. |
| `binary_unknown_format` | The magic bytes match no reader. |
| `ar_parse_error` | An `ar`-format archive's (`.a`/`.lib`) member table could not be walked to completion. |

### Python stage

| Kind | Meaning |
|---|---|
| `python_syntax_error` | `ast.parse` raised a real `SyntaxError`, or the source carries a null byte. |
| `python_decode_error` | The source would not decode. |
| `python_too_large` | The source file is over the limit. |
| `python_recursion_limit_exceeded` | `ast.parse` or the tree walk recursed too deep -- depends on the interpreter's stack depth at scan time, not the source, unlike the other three. |

### `SCAN_ABORTED_KINDS`

A subset of the above: the archive-, member- and binary-stage kinds this scanner cannot yet
prove are deterministic for the wheel's own bytes. A record carrying one is not a final
answer for its wheel, so it is never cached and `--resume` never treats it as done.

```
bad_zip   unexpected_error   member_read_error
elf_parse_error   macho_parse_error   pe_parse_error
python_recursion_limit_exceeded
```

`duplicate_member`, `size_limit_exceeded`, `compression_ratio_exceeded` and
`binary_too_large` are deliberately **not** in the set: each is a comparison or a dict lookup
over zip metadata already fully in hand, with no I/O and no broad catch anywhere on the path
that records it, so the same wheel's bytes always produce the same one and caching it is
safe. See
[A record produced without reading the wheel is never cached](../design/tooling.md#a-record-produced-without-reading-the-wheel-is-never-cached).

## `PARTIAL_REASONS`

`evidence.py`. Why one object was not read in full. `partial_analysis` is a single boolean
with a score of causes behind it, and six of them record no `ScanError` at all, so a record
could read `partial_analysis: true, errors: []` with no way to tell which applied.

Each token names a **cause**, never the method used to cope with it: every object whose
header would not parse is also read for strings alone, so "strings only" would not tell
those records apart from the ones that have no reader at all.

The full per-token meanings are in the
[output schema reference](../output-schema.md#partial_reasons). The tokens themselves:

```
no_structural_reader

elf_header_unread              elf_section_table_truncated
elf_section_table_absent       elf_section_type_ambiguous
elf_sections_unread            elf_section_data_unread
elf_dynamic_unread             elf_dynsym_unread
elf_symtab_unread              elf_go_buildinfo_unread

macho_header_unread            macho_symtab_incomplete
macho_fat_slice_unread         macho_load_command_string_unread
macho_load_command_walk_truncated
macho_load_command_ambiguous

pe_header_unread               pe_section_table_truncated
pe_no_import_directory         pe_import_incomplete
pe_export_incomplete           pe_ordinal_import
pe_ordinal_export              pe_delay_load

symtab_understates_rows        strings_bytes_unread
```

Two are format-independent on purpose. `symtab_understates_rows` is emitted by the ELF and
Mach-O readers alike, because the lie and the check are the same in both, and which wheels in
an index understated their symbol table is a supply-chain question rather than a build quirk.
`strings_bytes_unread` is emitted by every reader, because every reader bounds what it pulls
into memory and each one can run short.

!!! note "A recording cap is not a partial read"

    `strings_truncated` and `symbols_truncated` are fields, not causes. The object *was*
    read; what was capped is what got written down. A cause means bytes nobody looked at.
    See [A recording cap is not a partial read](../design/limits.md#a-recording-cap-is-not-a-partial-read).

### The two splits over this vocabulary

`PARTIAL_REASONS` is read twice, and the two lists differ on purpose:

- A `partial_binary` rule with no verdict names the causes that are **not worth a verdict**.
  Today: `pe_ordinal_import`.
- `[linkage_policy] exclude_reasons` names the causes that **leave a linkage posture
  answerable**. Today: `pe_ordinal_import`, `elf_go_buildinfo_unread`,
  `pe_no_import_directory`. `elf_symtab_unread` is not on this list: `.symtab` drives
  the imported/defined split for an object with no `.dynsym`, and supplies local
  definitions when there is one.

The first must be a subset of the second, and the loader refuses a ruleset where it is not.
A test asserts the two are not equal, so if they ever coincide the mechanism is a rename and
should be one.

## `FORMAT_*`

`evidence.py`. What reader produced a `BinaryEvidence`: `elf`, `macho`, `pe`, `unknown`.
`binaries[].format` is an open string in the schema, so a new format is not a breaking
change.

## `STAGE_*`

`evidence.py`. Which part of the scan recorded an error: `archive`, `metadata`, `binary`,
`python`. This is `errors[].stage`.

## `BINDING_*`

`evidence.py`. The distinction the whole tool turns on, on `matched_symbols[].binding`:

- **`imported`** — the code lives elsewhere; the wheel calls into a library it does not ship.
- **`defined`** — this object carries that code itself.

## `RELATIONS`

`ruleset.py`. What a `relation` names: what would have to change for a finding to go
away, the question a consumer of the index actually asks. Carried on a rule and on an
entry in the four override-bearing tables, always beside a non-empty `basis` -- a
citation must never stand alone.
`ruleset_coherence.check_relation_matches_verdict` refuses, at load time, a `relation`
paired with a verdict class outside its row below.

| Value | Consistent verdict classes | Meaning |
|---|---|---|
| `not_specified` | `NON_APPROVED_CRYPTO` | No approved standard specifies an equivalent construction: only a protocol or algorithm change removes the finding, not a different module. |
| `restricted` | `NON_APPROVED_CRYPTO`, `CONTEXT_DEPENDENT` | The primitive is approved only under a stated restriction (SHA-1 for a non-signature, non-collision-resistant use, for instance). `NON_APPROVED_CRYPTO` when the wheel implements it itself, `CONTEXT_DEPENDENT` when it calls into the host module and only the restriction's applicability is in question. |
| `outside_module` | `NON_APPROVED_CRYPTO` | The algorithm is approved, but this copy of it -- a separate stack, or a definition compiled straight into the object -- is not a validated module reading the system's crypto policy. |
| `boundary_unresolved` | `CONDITIONAL` | Whether this reaches a validated module cannot be told from the wheel alone; `verdict.conditions` carries the linkage that decides it. |
| `runtime_refusal` | `FIPS_BREAKING` | Will raise at runtime under FIPS-enforcing mode. |
| `policy_bypass` | `CONDITIONAL` | Overrides or bypasses a system-level policy control -- a pinned TLS version, disabled certificate verification -- rather than implementing a primitive. |
| `use_unresolved` | `CONTEXT_DEPENDENT` | Whether this is a security use is not resolvable from the evidence alone: a non-cryptographic hash library, an alternative to `os.urandom`, a declared `usedforsecurity=False`, an ambiguous call. |

No relation names `OPAQUE`: unreadability has no standard to cite, so a verdict of
`OPAQUE` paired with any relation is refused the same way.

## `FAMILIES`

`ruleset.py`. The FIPS-agnostic vocabulary for what a piece of evidence *is*, as
opposed to what it means for FIPS compatibility: carried on a rule, on an entry in the
four override-bearing tables, and on every `[[symbol_group]]`/`[[string_group]]`, so a
wheel's crypto inventory can be read without going through the FIPS lens at all.
`category` stays the FIPS-lens vocabulary (`non-approved-impl`, `fips-breaking`,
`trust-policy` and the rest); `family` sits beside it rather than folding into it,
since widening `category`'s own values to also answer "what is this" would leave the
inventory unable to ask that question without reading the FIPS-lens answer too.

```
hash            checksum        block_cipher    stream_cipher
aead            mac             kdf             password_hash
signature       key_agreement   kem             drbg
entropy         tls             ssh             trust_store
library
```

`library` is a general-purpose stack -- OpenSSL, libsodium, pycryptodome -- whose own
primitives span several of the other families, rather than one itself.

## `[[standard]].status`

`standards.py`. The closed set of states a `[[standard]]` entry's `status` may hold.

| Value | Meaning |
|---|---|
| `current` | The standard to cite. A `basis` may name it. |
| `revision_planned` | Still the current text, on a published schedule to be replaced. A `basis` may still name it. |
| `draft` | Not yet in force. A `basis` may not name it. |
| `planned` | Documents what is coming before anything can cite it. A `basis` may not name it. |
| `withdrawn` | No longer in force. A `basis` may not name it; the entry is kept only as the context a `successor` link points back from. |
