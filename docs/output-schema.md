# Output schema

`wheel-crypto-scan scan` emits **JSONL**: one self-contained JSON object per wheel, in
input order. `wheel-crypto-scan schema` prints the machine-readable JSON Schema
(`src/wheel_crypto_scan/data/schema.json`).

!!! warning "Nothing on this page asserts FIPS compatibility"

    The verdict taxonomy has no passing class and will not acquire one. The tool reports
    evidence; a human decides.

## Versioning contract

| Change | `schema_version` |
|---|---|
| A new optional key | unchanged |
| A new key that is always present (`required` in the JSON Schema) | unchanged |
| A new `rule_id`, `subject_kind`, `relation`, `family`, verdict class, binary format, layer or error kind | unchanged |
| A key removed, renamed, or changed type | **bumped** |

Consumers **must ignore unknown keys** and **must not** treat the documented value lists as
closed. That is why the schema deliberately leaves the verdict class, `relation`, `family`,
binary format, layer and stage fields as open strings: closing them would turn every
intended addition into a breaking change. Pin `tool.ruleset_version` if you need a fixed
value set. A new key can be `required` in the schema without bumping this version: it is a
statement that the key is always present *from here on*, not a guarantee an old consumer
relied on and would break by its arrival — ignoring an unknown key already covers that
consumer.

Canonical serialisation: keys sorted, ASCII only (`\uXXXX`-escaped), no floats anywhere, no
insignificant whitespace, exactly one trailing newline per record. No host paths,
timestamps, hostnames or user names appear in any field.

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | int | Contract version. Currently `2`. |
| `tool` | object | What produced the record. |
| `wheel` | object | Identity of the wheel. |
| `artifacts` | object | What the archive contains. |
| `binaries` | array | Per-object native evidence. |
| `findings` | array | Rules that matched. |
| `verdict` | object | The classification. |
| `crypto` | object | The library/family inventory, derived from `findings` and `verdict.conditions`. |
| `errors` | array | Non-fatal failures. **A non-empty array means part of the wheel was not examined.** The converse does not hold: several causes record no error, such as a stripped Mach-O or a single import bound by ordinal, and they set `partial_analysis` and a `partial_reasons` token without recording one. Recording no error is not the same as carrying no verdict: only the latter is marked in the reason table below, and every other cause still makes the wheel `OPAQUE`. |
| `errors_truncated` | bool | True when the wheel produced more errors than fit in `errors`, so it is capped -- a wheel that hits the same recordable failure on thousands of members cannot produce an unbounded record. One representative error per `(stage, kind)` pair is kept before the rest, so a wheel drowning in one kind of failure cannot crowd a different, rarer one out. |

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

`bundled_libs_truncated` is true when the wheel vendors more native libraries than fit
in `bundled_libs`, so it is capped -- independently of `binaries_truncated` below,
since `bundled_libs` is a *subset* of the objects `binaries[]`/`extensions` list (only
the vendored ones) and can hit its own cap even when the full object list does not.
Capped the same finding-aware way `binaries[]` and `extensions` are.

`symlinks_truncated` and `skipped_truncated` are the same kind of flag for `symlinks`
and `skipped`, each capped independently of every other array above -- but through
`caps.cap`, not a plain prefix: `skipped`'s `reason` is `ScanError.kind` (two rules,
`BIN_TOO_LARGE` and `WHEEL_MEMBER_UNREADABLE`, do name `skipped` paths), and
`symlinks`' `target` is the field a consumer actually reads (a bundled library can be
reachable only through the one symlink naming it), so one representative per
`reason`/`target` survives a flood of another before the rest, the same starvation
`errors[]`'s own `cap_key` already guards against. `skipped` and `errors[]` are fed by
the same underlying archive errors for a member-refusal wheel, but capped separately
and can disagree on how many of those events they still list; `skipped_truncated` and
`errors_truncated` must both be read to know whether either is complete. See
[`skipped` and `symlinks` reuse `caps.cap`, not a plain prefix](design/limits.md#skipped-and-symlinks-reuse-capscap-not-a-plain-prefix).

`py_files_unparsed` counts source files that would not parse. `binaries_truncated` is
true when the wheel has more native objects than fit in the `extensions` list above
and the top-level `binaries[]` array, so a wheel with thousands of objects cannot
produce an unbounded record. **It means the listing is incomplete, never that the
evaluation was.** Every object that became part of this record's binary evidence is
fed to linkage and every rule regardless of this cap -- not that each one was read in
full (`partial_analysis` says that, per object) or that every archive member got this
far: one refused by a limit is in `skipped` above, one that failed to open or read is
an error instead. Only the arrays a consumer reads back out of the JSON are capped for
the objects that did become evidence, and `extensions` and `binaries[]` are always
capped to the same set of objects, so the two never disagree on which ones they list.
Neither is a plain path-sorted prefix: the objects any `findings[].locations[]` names are
kept first (one per distinct `(rule_id, subject)` a finding names, before any finding gets
a second object), and the remaining room is filled with the rest in path order. A
finding's `locations[].path` can still, rarely, name an object that is not present in
either array: only when findings alone name more distinct `(rule_id, subject)` groups than
the cap allows, in which case the groups that sort last by `(rule_id, subject)` lose out.
`findings[]` where `rule_id == "WHEEL_BINARIES_TRUNCATED"` names how many objects were
evaluated in total when this happens. See
[`binaries[]` keeps what a finding points at, before filling the rest](design/limits.md#binaries-keeps-what-a-finding-points-at-before-filling-the-rest).

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
[A universal binary is one record, and its slices are merged](design/macho.md#a-universal-binary-is-one-record-and-its-slices-are-merged)
records why they are merged anyway.

| Field | Meaning |
|---|---|
| `vendored_path` | The object lives in an auditwheel `*.libs/` or delocate `.dylibs/` directory, i.e. the wheel ships it. |
| `matched_symbols[].binding` | **`imported`** = the code lives elsewhere; **`defined`** = this object carries it. This is the distinction the whole tool turns on. `defined` covers both a name the object publishes and one it keeps to itself: an ELF object's local `.symtab` definitions are read too, which is how a statically linked copy whose symbols a version script kept out of `.dynsym` is recognised, so `defined` does not mean exported. |
| `matched_strings[]` | `{group, value}` from read-only data, or, for a group the ruleset marks `in_code`, from an ELF executable section too. Version banners land here. |
| `symbol_counts` | `{dynsym, symtab}`, and `symtab` means something different per format: `.symtab` entries in ELF, `LC_SYMTAB` entries in Mach-O, and in PE the things the object named — one per import thunk and one per export slot — because PE has no symbol table of its own to count. |
| `stripped` | No `.symtab`, or a Mach-O with no `LC_SYMTAB` entries. ELF reads the declared count; Mach-O reads what the table yielded, so a `nsyms` of zero over rows the object does carry is a table we could not use and sets `partial_analysis` instead of this. Never set for PE, whose own symbol table is debug information every linker drops, so there is no absence that could mean this; `symbol_counts.symtab == 0` is how a PE says it named nothing. Normal for release wheels; recorded, not a finding. |
| `truncated` | `{symbols, strings}` — more matches were found than the limits keep, so what is recorded is a sample of what was found rather than all of it. This is **not** the same as the byte budget running out, which is `partial_reasons: ["strings_bytes_unread"]`; an object can have either, both or neither. The sample is chosen to keep one match per string group, one per symbol group and binding, and every crate the ruleset names, so a cap bounds the record's size without silencing a kind of evidence. |
| `rust_crates[].version` | `null` when the cargo layout the object was built from names no version, which is `cargo vendor` without versioned directories or a cargo git dependency checkout. A crate name comes from a cargo registry, distro (`/usr/share/cargo/registry`), vendor or git dependency checkout source path; a root crate read from a git checkout carries its repository's name, not necessarily its own. A `vendor/` tree inside a registry crate's directory is read as part of that crate, not as a crate of its own. |
| `partial_analysis` | Part of the object was not read. **This is the field to filter on.** |
| `partial_reasons` | Sorted, deduplicated tokens saying *which* causes applied, empty exactly when `partial_analysis` is false. Six record no entry in `errors`; exactly one of those is also routine rather than a failure and carries no verdict, which is a different thing and is marked in the table below. New values may appear without a `schema_version` bump. |

A PE with genuinely no imports — a resource-only or satellite DLL — therefore always
reads as `partial_analysis: true`, because naming at least one dependency is part of
what clears the flag. That is the conservative direction, and a known source of false
positives rather than a surprise.

### `partial_reasons`

| Token | Cause |
|---|---|
| `no_structural_reader` | This tool has no reader for the format, so the object was scanned for strings alone; records no error, because not parsing a format nobody claimed to parse is not a failure. |
| `elf_header_unread` | The ELF header itself would not parse. |
| `elf_section_table_truncated` | The ELF header parsed but the section header table it points at does not fit the object. |
| `elf_section_table_absent` | The ELF header parsed and there is no section header table at all to read (`e_shoff == 0`), which a loadable object is entitled to since the dynamic linker never reads one. Not the same as `e_shnum == 0` on its own, which is the legal extended-numbering encoding and still has a table to read. `.dynamic`, `.dynsym` and `.symtab` cannot even be looked for, so `needed`, `soname`, `rpath`, `runpath`, the symbol split and `stripped` are all unavailable rather than empty; the whole file is scanned for strings the same way a header that would not parse is. |
| `elf_section_type_ambiguous` | More than one section shares the `sh_type` this reader looked for (`SHT_DYNAMIC`, `SHT_DYNSYM` or `SHT_SYMTAB`), so which one is real cannot be told from the type alone. None of the candidates is trusted; picking the first would let a decoy inserted ahead of the real section hide it. |
| `elf_sections_unread` | A section header could not be read. A section we cannot name is one we cannot use, so anything derived from the section list may be missing rather than absent: `needed`, `soname`, `rpath`, `runpath`, the symbol counts and the strings alike. |
| `elf_section_data_unread` | A section's bytes could not be read, so the strings pass ran over less than the object holds. An ordinary `.rodata`/`.comment` over this reader's own budget does not reach this cause: its in-budget prefix is kept and the object reads `strings_bytes_unread` instead, not this token — reserved for a section whose bytes really could not be produced at all. |
| `elf_dynamic_unread` | `.dynamic` would not resolve, or a section named `.dynamic` exists whose declared `sh_type` is not `SHT_DYNAMIC` and so cannot be trusted as one, so `needed`, `soname`, `rpath` and `runpath` are empty because they could not be read, not because the object declares none. |
| `elf_dynsym_unread` | `.dynsym` would not read, named strings `.dynstr` does not hold, declared fewer entries than `.dynstr` holds names for, a section named `.dynsym` exists whose declared `sh_type` is not `SHT_DYNSYM` and so cannot be trusted as one, or `.dynsym` or `.dynstr` declares more bytes than this reader's own budget is willing to read — the honest table may be entirely present in the object, and this cause does not mean it lied, only that the reader stopped short of it — so the imported-versus-defined split is missing or partial. |
| `elf_symtab_unread` | `.symtab` would not read, or a section named `.symtab` exists whose declared `sh_type` is not `SHT_SYMTAB` and so cannot be trusted as one, so `stripped` and `symbol_counts.symtab` describe a table we failed on rather than one the object does not have. Costs the imported-versus-defined split too, in two different degrees. For an object with no `.dynsym` at all, `.symtab` is the only symbol table and the whole split is unavailable; for an object that has one, `.dynsym` still answers imports and what is lost is the *local definitions* `.symtab` alone carries, which is how a statically linked copy with a version script is recognised. `.symtab` is matched for crypto symbols in both cases, and a budget refusal or a row naming a string `.strtab` does not hold folds into this kind in both. The cross-checks differ with the mode: with no `.dynsym`, `.symtab` is the object's only table and gets the full check `.dynsym` gets, so `.strtab` holding names for more entries than `.symtab` declares also lands here; with a `.dynsym` present, that check does not run, because it asks whether a *sole* table under-declared itself and a `.symtab` trimmed by a partial strip is ordinary rather than a lie. |
| `elf_go_buildinfo_unread` | `.go.buildinfo` would not read, so Go toolchain provenance is missing. Does not cost the linkage answer. |
| `macho_header_unread` | The Mach-O header, or a fat header, would not parse. |
| `macho_symtab_incomplete` | `LC_SYMTAB` was absent, declared no entries, or declared entries this reader could not take at their word: unreachable, naming strings it does not hold, holding nothing but debug records, declaring fewer entries than the string table holds names for, or declaring more symbol- or string-table bytes than this reader's own budget (`binfmt.strings.MAX_STRINGS_BYTES` by default) is willing to read — the honest table may be entirely present in the object, and this cause does not mean it lied, only that the reader stopped short of it. It records an error unless the table left nothing unexplained — an absent `LC_SYMTAB`, or one declaring no entries over a string table holding no name it failed to account for — and that error says which way it fell short. `stripped` and `symbol_counts.symtab` then describe a table we could not use rather than one the object does not have. |
| `macho_fat_slice_unread` | A slice of a universal binary could not be read, or its header named one it did not describe. |
| `macho_load_command_string_unread` | A dylib-loading command (`LC_LOAD_DYLIB` and its `LC_LOAD_WEAK_DYLIB`, `LC_LAZY_LOAD_DYLIB`, `LC_LOAD_UPWARD_DYLIB` and `LC_REEXPORT_DYLIB` siblings), `LC_ID_DYLIB` or `LC_RPATH` could not have its string read: the offset is outside the command's own body, below where a string could legitimately start, or the run it starts never closes. A dependency, the object's own install name, or an rpath entry was lost rather than absent. Records an error, the same way a PE import or export directory that could not be walked in full does. |
| `macho_load_command_walk_truncated` | A load command's own `cmd`/`cmdsize` header could not be trusted — too short to hold that 8-byte header, a `cmdsize` claiming to run past the end of the load commands, or a `cmdsize` that stays inside the load commands and is at least 8 but is not a multiple of the ABI's own alignment (8 bytes on a 64-bit object, 4 on a 32-bit one) — so the walk stopped there rather than guessing where the next command starts. Also covers a header whose own `ncmds` undercounts how many commands the object actually carries: the walk exhausts `ncmds` with real command bytes still unread, without any single command's header ever lying about itself. Distinct from `macho_load_command_string_unread`, which loses one command's name while the walk continues past it: here every command after the bad one is unaccounted for, not absent, which can be many commands' worth of dependencies rather than one. Records an error. |
| `macho_load_command_ambiguous` | More than one `LC_ID_DYLIB` or more than one `LC_SYMTAB` command in one object, so which candidate is real cannot be told from `cmd` alone — there is no name to disambiguate by, unlike a dylib-loading command's string. Neither candidate is trusted: `soname`, or the symbol table and the imported/defined split it drives, read as though nothing of that kind existed rather than as whichever command the walk reached last. One token covers both fields, the same way `elf_section_type_ambiguous` covers `SHT_DYNAMIC`, `SHT_DYNSYM` and `SHT_SYMTAB` alike, though the two causes get their own, distinct `errors[]` message when both fire on the same object. Records one or two errors. |
| `pe_header_unread` | The PE header chain would not parse. |
| `pe_section_table_truncated` | The section table was cut short, so an address may resolve to the wrong bytes. |
| `pe_no_import_directory` | No import directory, or one naming no DLL, so the object declared no dependency; records no error. Does not cost the linkage answer. It is an absence the reader observed rather than a read it fell short of: a walk that fell short carries `pe_import_incomplete` instead. |
| `pe_import_incomplete` | An import directory that was there and could not be walked in full. |
| `pe_export_incomplete` | An export directory that was there and could not be read in full. |
| `pe_ordinal_import` | An import named by ordinal alone, or a forwarder whose target is named by ordinal, so the function has no name to match; routine on Windows, and records no error. Reported by `BIN_PARTIAL_ROUTINE` with no verdict, because the DLL it names survives in `needed`. Does not cost the linkage answer. |
| `pe_ordinal_export` | An export the name table never points at: a definition with no name; records no error. What is lost is a definition, and a definition is how a statically linked copy is recognised, so this is a failure to read rather than a convention: `BIN_PARTIAL_FORMAT` claims it and the wheel is `OPAQUE`. An understated `NumberOfNames` surfaces here, PE having no string table to check the count against. |
| `pe_delay_load` | A delay-load import directory, which this reader does not parse, so the libraries it names are undeclared dependencies; records no error. |
| `strings_bytes_unread` | The reader's byte budget ran out before the object did, so a region of it was never looked at and found nothing there for that reason; records no error. Emitted by every reader, each bounding what it pulls in: `binfmt.elf` bounds the concatenated read-only sections, and a single eligible section too large for the budget on its own still contributes its own in-budget prefix rather than nothing; the other three readers bound a prefix of the object. An extension whose only crypto evidence is an OpenSSL version banner past the budget reads exactly like one with no OpenSSL in it. |
| `symtab_understates_rows` | A symbol table declared fewer entries than the string table it points into holds names for, so symbols the object carries were never looked at. The object is not corrupt: every structural check passes and the count is simply not the truth. Emitted by the ELF and Mach-O readers alike, beside that format's own cause, because the lie and the check are the same in both. |
| `ar_member_table_unread` | An `ar`-format archive (`.a`/`.lib`) whose member table could not be walked to completion before even one real object was found: a header running past the archive's own end, a non-numeric size field, or a member declaring more bytes than remain. Whatever real objects a partially-walked table did yield keep their own separate evidence under their own paths; this token marks the whole-archive fallback record built only when none were found at all. |

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
| `relation` | What would have to change for this finding to go away: `not_specified`, `restricted`, `outside_module`, `boundary_unresolved`, `runtime_refusal`, `policy_bypass`, `use_unresolved`, or `null` for a finding with no relation -- always paired with an empty `basis`. |
| `basis` | The standards that say so, as ids from the ruleset's `[[standard]]` table. Empty exactly when `relation` is `null`. |
| `family` | What kind of primitive this finding is evidence of, independent of the FIPS lens: `hash`, `checksum`, `block_cipher`, `stream_cipher`, `aead`, `mac`, `kdf`, `password_hash`, `signature`, `key_agreement`, `kem`, `drbg`, `entropy`, `tls`, `ssh`, `trust_store`, `library`, or `null` when not applicable. |
| `occurrences` | Number of **distinct locations**. Two calls on one line count once. |
| `truncated` | The `locations` list was capped; `occurrences` still holds the full count. |
| `locations[]` | `{path, line, evidence}`. `line` is `null` for non-source findings. `evidence` is the literal matched text, printable ASCII, capped. A `path` naming a native object is not *guaranteed* to appear in `binaries[]`, though `binaries[]` keeps every object a finding references before it keeps anything else: only when findings alone name more distinct `(rule_id, subject)` groups than `artifacts.binaries_truncated`'s cap allows can one be left out, while the object, and this finding, were still produced from reading it in full. See [`artifacts`](#artifacts) above. |

## `verdict`

| Field | Meaning |
|---|---|
| `class` | The highest-precedence class that fired. Always equals `classes[0]`. |
| `classes` | **Every** class that fired, in precedence order. A wheel can be more than one thing. |
| `relations` | Every `relation` a contributing finding cited, sorted -- no precedence order the way `classes` has one. |
| `rule_ids`, `reasons` | Which rules produced the class, and a one-line reason each. |
| `conditions` | Resolved conditions, keyed `<library>_linkage`. |
| `needs_human_review` | `false` only when nothing was found and nothing failed. |

### `conditions.openssl_linkage`

The field most consumers filter on. Always present.

| Value | Meaning |
|---|---|
| `system` | Resolves `libcrypto`/`libssl` from the host, so it inherits the host's FIPS provider and crypto policy. **The condition under which a `CONDITIONAL` wheel is acceptable.** An OpenSSL version banner in the same object does not change this when the object imports from the host library, was read in full, and carries no `openssl_build_info` string, because that banner is header text. The field can read `system` while some object in the wheel read `unknown` (an `unknown` never outvotes a definite posture). `DERIVED_SYSTEM_OPENSSL_ONLY` is then withheld, and `DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM` names that object and carries `OPAQUE`. The field can also read `system` while the wheel's own SBOM names OpenSSL or a crate that binds it, unless that same crate is also carried, in its own cargo paths, by an object whose own posture already reads `system` — an SBOM component restating what such an object already declared does not count as a second, unaccounted-for copy. When it does count, `DERIVED_SYSTEM_OPENSSL_ONLY` is withheld the same way, and `DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM` carries `OPAQUE` instead. |
| `bundled` | Ships its own copy: in a vendor directory, via a hash-renamed dependency, or via a dependency that names an unmangled but unrenamed file the wheel itself ships (delocate's convention). Cannot see the system provider. A version banner in the same object does not change it when the object imports from the bundled dependency, was read in full, and carries no `openssl_build_info` string: that banner is header text too, the same as beside a system dependency. |
| `static` | Compiled in, with no library file and no declared dependency: a definition, or a version banner beside the build strings (`openssl_build_info`) a compiled-in copy keeps beside it (or a banner alone on an object not read in full, where a partial read may have cut the build string) -- excluding a banner that is a listed fork's (AWS-LC's or BoringSSL's) own compatibility text, which does not corroborate a copy on its own. Same consequence as `bundled`, harder to spot. |
| `mixed` | Both postures found across different objects in one wheel (the cross-object case); or, for one object's own evidence: two or more of `system`, `bundled` and `static` all true for it at once (a `needed` match to the system library alongside a definition, or a banner that is not header text (see `system`); a `needed` entry that resolves inside the wheel alongside a *different* `needed` entry that resolves to the system library, or alongside a definition, or a banner that is not header text (see `bundled`)); or exactly one of `system`/`bundled` true alongside an unconfirmed, vendor-shaped-but-unconfirmed `needed` entry AND a definition/banner together (`uncertain` and `static` both true) — `uncertain` alone never triggers `mixed` on its own, only in combination with `static`. Includes the case a universal (fat) Mach-O object merges into one record when its slices disagree this way, which reads `mixed` rather than `bundled` or `system` outright. |
| `none` | No OpenSSL evidence in any binary object, and no shipped SBOM component naming the library or a crate that binds it, from objects read far enough to say so. |
| `unknown` | An object read far enough to say so uses OpenSSL without naming where it comes from (imported OpenSSL symbols and no dependency on the library, a Rust crate that binds it and nothing else, an OpenSSL-named definition alongside AWS-LC or BoringSSL, which define the same names, or AWS-LC's or BoringSSL's own compatibility banner, or a version banner with none of the build strings a compiled-in copy keeps beside it, on an object with no dependency on the library at all), or the wheel's own SBOM names the library or such a crate and no object answers; or evidence came only from an object we could not read, some object in the wheel was not read in full and the cause could have hidden what this field is read off, or the wheel itself was not read in full (a member skipped by an archive limit, or one that failed to open) and a dependency's path looks vendored (an `@loader_path`/`@rpath`-relative path, or a vendor-shaped `RPATH`/`RUNPATH`) without a shipped object confirming it — provided that same object carries no definition or banner of its own, and no *different* `needed` entry on it already resolves to `system` or `bundled`. When it carries a definition or banner, the object's own evidence is `mixed` instead. When a different `needed` entry on it already resolves to `system` or `bundled` — but the object carries no definition/banner, and does not also have a second, different `needed` entry resolving to the other of `system`/`bundled` — the object's own evidence is that one confirmed posture instead, unaffected by the unconfirmed entry; if it has both a confirmed `system` entry and a confirmed `bundled` entry, the object's own evidence is `mixed` instead, per the `mixed` row above, regardless of the unconfirmed one. A vendor-shaped path naming nothing, in a wheel read in full, is `system`: the complete member list not containing the answer is itself the answer. `partial_reasons` names the cause when it applies; the ones that leave the answer intact are marked in the reason table above. |

This field is read from the wheel's binary objects: a shipped copy of the library
itself, by file name; a `needed` entry naming the library; a symbol from its symbol
group; its version banner (and, for OpenSSL, the build strings that tell a compiled-in
banner from a header's); or a Rust crate the ruleset lists for it (in the shipped
ruleset, for OpenSSL: `openssl`, `openssl-sys`, `openssl-src`). A crate says the
object uses OpenSSL, not which copy, so it gives `unknown` on an object with nothing
else and never outvotes a definite posture.

There is one wheel-level input besides the objects: a PEP 770 SBOM component naming
the library, or a crate the ruleset lists for it, gives `unknown` the same way when no
object in the wheel answered definitely, and never outvotes a definite posture either.
A distribution name (`crypto_distribution`, e.g. `cryptography`) is a finding at most
and never moves this field, and neither does a soname in an SBOM component: this field
only compares an SBOM component's name against a library's own name and its `crates`,
the same names `SBOM_CRYPTO_COMPONENT` reports a finding for, compared
case-insensitively and, for a crate name, treating `-` and `_` as the same character
the way crates.io does. When a library's own
name is *also* a different `rust_crate` it does not itself list in `crates` -- in the
shipped ruleset, `argon2` and `blake2`, each both a C reference library and an
unrelated pure-Rust crate of the same name -- the component's `purl` breaks the tie:
only a `pkg:cargo/...` purl reads as the crate and leaves the C library's field
untouched, so a component named `argon2`/`blake2` with any other purl, or none,
moves it. `SBOM_CRYPTO_COMPONENT` reads that same purl to choose the crate's or the
library's entry for its own severity and verdict: a `pkg:cargo/...` purl is rated by
the `[[rust_crate]]` entry, any other purl or none by the `[[crypto_library]]` entry.

Other libraries appear as `<name>_linkage` when they have evidence.

### Verdict classes

| Class | Meaning |
|---|---|
| `NON_APPROVED_CRYPTO` | Implements or bundles cryptography that no validated module provides: a primitive no approved standard specifies, or an approved algorithm outside any validated module. |
| `FIPS_BREAKING` | Will raise at runtime under FIPS-enforcing mode. |
| `CONDITIONAL` | Approved only under a stated condition; read `conditions`. |
| `CONTEXT_DEPENDENT` | Non-approved primitive that may be a non-security use. |
| `OPAQUE` | Stripped, unreadable or source-free. Cannot determine. |
| `NO_CRYPTO_DETECTED` | Nothing found. **Absence of evidence, not evidence of absence.** |

Listed in precedence order, which lives in the ruleset's `[verdict] precedence` and can be
reordered there, except `NO_CRYPTO_DETECTED`, which the loader holds last.

## `crypto`

The library/family inventory: every primitive family a finding was evidence of, and every
library whose linkage resolved to something. Derived from `findings[].family` and
`verdict.conditions` rather than a separate pass, so it can never disagree with either -- a
library's posture is `none` exactly when it is left out of `libraries`, which is what gives a
`NO_CRYPTO_DETECTED` wheel a genuinely empty inventory.

| Field | Meaning |
|---|---|
| `families` | Every `findings[].family`, sorted, deduplicated, with `null` skipped. |
| `libraries[]` | `{name, linkage}` for every `<library>_linkage` key in `verdict.conditions` whose value is not `none`, sorted by `name`. `linkage` is `system`, `bundled`, `static`, `mixed` or `unknown` -- the same values `conditions.openssl_linkage` takes, minus `none`. |

## `errors`

`{stage, kind, path, message}` where `stage` is `archive`, `metadata`, `binary` or `python`.
Messages are deterministic and contain no host paths.

A wheel that could not be read is `OPAQUE`, never `NO_CRYPTO_DETECTED`. Every error kind the
scanner can record has a rule that turns it into a finding, and a test enforces that. The
full list of kinds is in [Vocabularies](reference/vocabularies.md).
