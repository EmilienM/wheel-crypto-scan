# The ruleset

All policy lives in one file,
[`src/wheel_crypto_scan/data/ruleset.toml`](https://github.com/EmilienM/wheel-crypto-scan/blob/main/src/wheel_crypto_scan/data/ruleset.toml).
Every package name, symbol, string, crate, library and verdict is data, each with a `why`
explaining in plain language what it is and why it is flagged. A crypto engineer can review
and edit it without reading any Python. `wheel-crypto-scan rules` renders it for review.

Nothing in the scanner hardcodes a package name, a symbol, a library or a verdict.

!!! note "Bump `ruleset_version` after editing"

    It is part of the scan cache key, so bumping it is what makes previously scanned
    wheels get re-evaluated. Nothing fails if you forget; you just silently get stale
    records back.

## How to read an entry

Every rule and every table entry carries the same vocabulary.

| Field | Meaning |
|---|---|
| `severity` | How strong the evidence is: `high` / `medium` / `low` / `info`. It is **not** a compatibility judgement. |
| `verdict` | Which class this evidence pushes the wheel into. The tool never emits a passing class, not "compliant" and not "compatible", and this field can never say so. |
| `confidence` | How sure we are the match means what we think it means. |
| `needs_human_review` | Set true whenever a crypto engineer must look at it. When in doubt, set it true. It is never wrong to ask for review. |
| `why` | Why this is flagged, in plain language. Every rule and every table entry has one. If you disagree with a `why`, change it: it is the part of the file that carries the reasoning. |

## The sections

### `[verdict]`

`precedence` is the ordered list of verdict classes. A wheel can produce evidence for
several classes at once; the record reports every class that fired in `verdict.classes`,
and the first one in this list as the single `verdict.class`. Reorder the list to change
which concern wins.

`NO_CRYPTO_DETECTED` must be the last entry. It is the class a wheel gets when no
finding assigns one, so it can never outrank a class that evidence did assign, and no
`[[rule]]` or table entry may name it as a `verdict`. The loader refuses a ruleset that
breaks either requirement, and one that names a class twice in `precedence`.

A static or bundled OpenSSL's own entry points for Blowfish, MD4/MD5/SHA-1/RIPEMD-160
and (a bundled copy only when it still carries a `.symtab`) the Curve25519 family are
compiled in by OpenSSL itself, so such a wheel's headline lands under
`NON_APPROVED_CRYPTO` rather than `CONDITIONAL`. `verdict.conditions.openssl_linkage`
is the field that may tell that case apart from a wheel whose own code defines a weak
primitive, though not when a wheel carries both.

### `[limits]`

Bounds on record size. They never change what is detected — only how much of what was
found gets written down. `max_locations_per_finding`, `max_symbols_per_binary`,
`max_strings_per_binary`, `max_rust_crates_per_binary`, `max_evidence_chars`,
`min_string_length`.

Lists are sorted before truncation, so truncation stays deterministic, and the sample is
chosen so that a cap bounds the record without silencing a kind of evidence. The loader
refuses limits too small to hold one of every key the ruleset itself declares. See
[Caps, budgets and record size](design/limits.md).

### `[conventions]`

How build tools lay wheels out, not policy: `vendor_dir_globs` (auditwheel's `*.libs`,
delocate's `.dylibs`), `mangled_soname_regex` (the content hash those tools append),
`library_suffixes` and the Windows-specific `windows_library_suffixes` /
`windows_version_suffix_regex` pair, `cargo_path_regex`, `cargo_vendor_path_regex` and
`cargo_git_path_regex` for the cargo source paths a Rust object embeds, `go_boring_group` /
`go_stock_group` naming the Go toolchain string groups, and `refused_hash_algorithms` /
`restricted_hash_algorithms`, the FIPS-refused and FIPS-restricted Python hash constructors.

The Windows entries matter more than they look. Windows puts a library's version, and often
its architecture, inside the file name where Unix puts it in a `.so.N` suffix:
`libcrypto-3-x64.dll`, `libgnutls-30.dll`. That is how the platform spells a name, not a
fact about any one library, so it is undone here rather than enumerated library by library.

### `[linkage_policy]`

Which `partial_reasons` causes leave a linkage posture answerable. `exclude_reasons` names
the causes that leave every field linkage reads — `needed`, `vendored_path`, the
imported-versus-defined split, `matched_strings` — intact. Everything else, named or added
later, makes the wheel's answer `unknown` rather than `none`.

It excludes rather than includes on purpose: a cause added later costs the answer until
someone decides otherwise, which is the safe direction. One coherence rule is enforced at
load time rather than left to prose: every cause a verdict-less rule claims must appear here
too. See [Linkage reads a second split over the same vocabulary](design/opacity.md#linkage-reads-a-second-split-over-the-same-vocabulary).

### The match tables

These are the things a rule can point at. Each is an array of tables.

| Table | What it holds |
|---|---|
| `[[crypto_distribution]]` | Distribution names, matched on the canonical PEP 503 name, so `PyNaCl`, `pynacl` and `py_nacl` are the same entry. |
| `[[crypto_library]]` | A native library: its `sonames`, and optionally the `symbol_group` and `string_group` that let the linkage resolver recognise it compiled straight into an extension, where there is no library file and no dependency to find. Optionally `copy_string_group`, strings only a compiled-in copy carries: on an object that imports the library from a dependency it resolved, whether system or bundled, a `string_group` match that matches nothing in `copy_string_group` is header text and does not count as a copy; on an object with no dependency on the library at all, that same absence makes the banner uncorroborated prose instead. Either way the gate stays shut on an object not read in full, because a partial read may have cut the copy string. Optionally `fork_symbol_groups`/`fork_string_groups`, symbol and string groups that identify a different library implementing this one's API under this one's names: a symbol group counts only when the match is DEFINED in the same object. On an object where one of them matched, this library's own `symbol_group` definitions say some implementation of the API was compiled in, not which one, so definitions alone (no banner) turn `static` into `unknown` rather than asserting the library by name. The loader refuses an unknown group name, the library's own `symbol_group`/`string_group`/`copy_string_group` named as one of its own forks, and a fork list on a library with no `symbol_group` to reclassify. Optionally `crates`, the `[[rust_crate]]` entries that bind it: a crate says an object uses the library, not which copy, so on an object with no other evidence it gives `unknown` rather than `none`. The library's own name or one of its `crates` named in a shipped SBOM gives `unknown` the same way when no object in the wheel answers, compared case-insensitively (SBOM names are folded through `ruleset.sbom_library_key`/`sbom_crate_key`, the same functions `SBOM_CRYPTO_COMPONENT` uses). When the library's own name is *also* a different `[[rust_crate]]` it does not itself list in `crates` -- as for `argon2` and `blake2`, each both a C reference library and an unrelated pure-Rust crate of the same name -- the SBOM component's `purl` decides instead: only a `pkg:cargo/...` purl reads as the crate rather than the library. `openssl` is the one reported unconditionally. Two `[[crypto_library]]` names that differ only in case are refused at load time, the same as for `[[rust_crate]]` below, since the SBOM fold above would otherwise make the lookup ambiguous. |
| `[[symbol_group]]` | Named groups of dynamic symbols, by `prefixes` and `exact` names. Imported means the wheel calls into a library it does not ship; defined means it carries that code itself. Every group must be read by a `dynamic_symbol` rule or by a `[[crypto_library]]`'s `symbol_group`, or carry `evidence_only = true` (with a `why` saying so, by convention); the loader refuses a group that is neither. |
| `[[string_group]]` | Named groups of read-only-data substrings. Version banners land here, and for a statically linked extension the banner is often the entire evidence. Substrings must be printable ASCII: an extracted run only ever holds printable ASCII, so anything else could never match, and the one non-printable character a rule author might reach for by mistake is the separator the matcher joins runs with internally. Optionally `in_code` (default `false`): also search ELF executable sections for this group's substrings, against their own read budget, independent of the read-only pass -- Mach-O, PE and the fallback reader already see the whole object regardless of this flag. A group should carry it only when missing it errs toward over-flagging -- the answer being wrong in the direction this tool already accepts -- which is a measured claim about where the substring actually lives, not a default worth reaching for. |
| `[[rust_crate]]` | Crates inferred from the embedded cargo source paths, each with its own `verdict` and `severity`. An entry can optionally carry its own `suppressed_by`, naming other `[[rust_crate]]` entries. Two entries whose names differ only in case or in `-`/`_` are refused at load time, since crates.io treats them as the same name. |
| `[[python_module]]` | Module names the AST layer watches for on import. |
| `[[ctypes_library]]` | Substrings that mean crypto is being reached at runtime by name, which no static dependency graph would show. |

### `[[rule]]`

A rule carries the vocabulary above plus an `id`, a `layer`, a `category`, a `title`, and
one or more `[rule.match]` tables. Several match tables are alternatives, ORed together:
one rule id, more than one way of reaching it.

`[rule.match]` has a `kind` that selects the matcher, and whatever that matcher needs —
most often `table`, naming one of the match tables above. The kinds in the shipped ruleset
are `dist_name`, `requires_dist`, `wheel_generator`, `record_mismatch`, `sbom_component`,
`dynamic_symbol`, `binary_string`, `dt_needed`, `bundled_library`, `rust_crate`,
`linkage`, `opaque_binary`, `partial_binary`, `binaries_truncated`, `no_source`,
`scan_error`, `py_import`, `py_call`, `py_attr`, `py_constant` and `py_ctypes_load`. Each
kind takes only the keys `ruleset.MATCH_KEYS` lists for it (which always includes `kind`
itself); any other key on that match table refuses the whole file at load time. The same
holds for `[[rule]]`, every entry table above, `[verdict]`, `[limits]`, `[conventions]`
and `[linkage_policy]`, and the top level of the file: a key none of these read is refused
rather than silently doing nothing. `sbom_component` takes the plural `tables`; the
singular `table` other kinds use to name a default's table is refused on this kind, since
`_match_sbom_component` never reads it either.

Three of those read the Python-side vocabularies rather than a table:

- `kind = "scan_error"` matches on the `ScanError` kinds.
- `kind = "partial_binary"` matches on `partial_reasons`, taking `reasons` and
  `exclude_reasons`, so the ruleset decides which causes are worth a verdict rather than
  the engine treating them alike.
- `kind = "linkage"` matches on the wheel's resolved posture for a library, taking
  `value`/`values`. It also takes the alternatives `object_values` (fire, once per
  object, when that object's own posture -- the same per-object answer the field was
  aggregated from -- is one of these) and `exclude_object_values` (fire only when no
  object's own posture is one of these). All four are validated against the closed set
  of linkage postures at load time, and `object_values`/`exclude_object_values` are
  refused empty. A `linkage` match also takes `sbom_declared` (a boolean, validated as
  one at load time), the wheel-level counterpart: `true` fires only when the wheel's
  own SBOM names the library or a crate that binds it, `false` only when it does not --
  except a crate name already carried, in its own cargo paths, by an object whose own
  posture is `system`, which does not count as declared: that object already answered
  `system` on its own evidence, and the SBOM restates it rather than naming a second,
  unaccounted-for copy. It combines with either object-value key rather than being an
  alternative to them.

Three more read Python source evidence, and each has a required field naming what it
matches on, refused if missing or empty: `kind = "py_call"` takes `targets` (dotted
callable names, `*.method` wildcards allowed), plus an optional `usedforsecurity`
(`"absent"`, `"true"`, `"false"` or `"unresolved"`, scalar or list), an optional
`algorithm` (any hash name a call might pass — never checked against a closed list, since
a rule naming a *strong* algorithm on purpose is a real shape), and an optional
`algorithm_list` (`"refused"`, `"restricted"` or `"weak"` -- the two `[conventions]`
hash lists, or their union). `kind = "py_attr"` takes `attributes`, plus an optional `values`
list. `kind = "py_constant"` takes `constants`. A `targets`/`attributes`/`constants`/
`values`/`usedforsecurity` of the wrong shape (not a string or list of strings, or an
empty list) is refused at load time rather than silently matching nothing or, for
`usedforsecurity` specifically, crashing the scan outright.

A token named by a rule is validated at load time, so a typo is a load error rather than a
rule that silently matches nothing. The vocabularies themselves are in
[Vocabularies](reference/vocabularies.md), and why they live in Python rather than here is
in [Invariants](invariants.md#working-rules).

`suppressed_by` drops a rule's finding on an object where one of the named rules also
fired there: it is per object, never per wheel, and non-cascading, so a suppressor that
is itself suppressed still suppresses. "Per object" means the same `Location.path`.
Which kind locates where is declared once, as `MATCHER_LOCATIONS` in `ruleset.py`: a
`linkage` match carrying `object_values` locates per object, one `Hit` per object whose
own posture matched, `scan_error` and `record_mismatch` locate wherever their error or
mismatch is and so accept a relation naming either one, and every other kind locates on
whatever class of path its own declaration says. The loader refuses a relation whose two
rules can never share a path, so an accepted ruleset is one where every `suppressed_by`
can fire. A `[[rust_crate]]` entry can carry the same field,
naming other `[[rust_crate]]` entries, for a relation between two crates that stay on
one rule rather than between two whole rules; entry-level `suppressed_by` is only
defined on `[[rust_crate]]`, and is refused on any other table. `kind = "sbom_component"`
honours it too, keyed on the SBOM document as the object: a crate component in one SBOM
carries the relations its crate has on a binary object, so an SBOM naming both a crate
and its suppressor in the same document reports only the suppressing one's finding. SBOM
and binary evidence never suppress each other, because they never share a path -- an SBOM
naming a crate beside a *binary* object carrying its suppressor still reports both (see
[Suppression is keyed on rule, subject and
object](design/policy.md#suppression-is-keyed-on-rule-subject-and-object) for why
that is accepted rather than fixed). A rule's own `tables` order is what decides which
entry rates a `sbom_component` match, except for a `pkg:cargo/...` purl: when the rule
lists `rust_crate`, that table is tried first for such a component, ahead of wherever
the rule places it, so for a cargo-sourced name, listing `crypto_library` first does
not make the C library's severity win. An unknown name, a name referring to itself, a
name no rule owns (or, for a `[[rust_crate]]` entry, a crate with no owner of its own
naming one), a `suppressed_by` cycle across rules and crates, a relation whose two rules
can never share a location path, and a crate `suppressed_by` that would leave a
library's linkage moved from an SBOM with no finding to explain it are all refused at
load time.

## Using a different ruleset

`--ruleset PATH` on `scan` and `rules` reads an alternative file. It goes through the same
loader and the same validation, including the coherence check between a verdict-less
`partial_binary` rule and `[linkage_policy] exclude_reasons`, the printable-ASCII check
on every `[[string_group]]` substring, an unknown key on any table, the shape checks
on `py_call`/`py_attr`/`py_constant`'s `targets`/`attributes`/`constants`/`values`/
`usedforsecurity` fields described above, and the coverage check on `[[symbol_group]]`
-- a group no `dynamic_symbol` rule or `[[crypto_library]]` reads, and no group marked
`evidence_only = true` that something does read -- all load errors rather than a test
precisely so that `--ruleset` users are inside the guard too. A `[rule.match]` missing
its kind's required field, or carrying one of the wrong shape, refuses the *whole* file
at load time rather than silently dropping just that one rule.
