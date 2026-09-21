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

### `[limits]`

Bounds on record size. They never change what is detected — only how much of what was
found gets written down. `max_locations_per_finding`, `max_symbols_per_binary`,
`max_strings_per_binary`, `max_rust_crates_per_binary`, `max_evidence_chars`,
`min_string_length`.

Lists are sorted before truncation, so truncation stays deterministic, and the sample is
chosen so that a cap bounds the record without silencing a kind of evidence. The loader
refuses limits too small to hold one of every key the ruleset itself declares. See
[Caps, budgets and record size](decisions/limits.md).

### `[conventions]`

How build tools lay wheels out, not policy: `vendor_dir_globs` (auditwheel's `*.libs`,
delocate's `.dylibs`), `mangled_soname_regex` (the content hash those tools append),
`library_suffixes` and the Windows-specific `windows_library_suffixes` /
`windows_version_suffix_regex` pair, `cargo_path_regex` for the source paths a Rust object
embeds, `go_boring_group` / `go_stock_group` naming the Go toolchain string groups, and
`weak_hash_algorithms`.

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
too. See [Linkage reads a second split over the same vocabulary](decisions/opacity.md#linkage-reads-a-second-split-over-the-same-vocabulary).

### The match tables

These are the things a rule can point at. Each is an array of tables.

| Table | What it holds |
|---|---|
| `[[crypto_distribution]]` | Distribution names, matched on the canonical PEP 503 name, so `PyNaCl`, `pynacl` and `py_nacl` are the same entry. |
| `[[crypto_library]]` | A native library: its `sonames`, and optionally the `symbol_group` and `string_group` that let the linkage resolver recognise it compiled straight into an extension, where there is no library file and no dependency to find. Optionally `crates`, the `[[rust_crate]]` entries that bind it: a crate says an object uses the library, not which copy, so on an object with no other evidence it gives `unknown` rather than `none`. `openssl` is the one reported unconditionally. |
| `[[symbol_group]]` | Named groups of dynamic symbols, by `prefixes` and `exact` names. Imported means the wheel calls into a library it does not ship; defined means it carries that code itself. |
| `[[string_group]]` | Named groups of read-only-data substrings. Version banners land here, and for a statically linked extension the banner is often the entire evidence. Substrings must be printable ASCII: an extracted run only ever holds printable ASCII, so anything else could never match, and the one non-printable character a rule author might reach for by mistake is the separator the matcher joins runs with internally. |
| `[[rust_crate]]` | Crates inferred from the embedded cargo registry paths, each with its own `verdict` and `severity`. |
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
`scan_error`, `py_import`, `py_call`, `py_attr`, `py_constant` and `py_ctypes_load`.

Two of those read the Python-side vocabularies rather than a table:

- `kind = "scan_error"` matches on the `ScanError` kinds.
- `kind = "partial_binary"` matches on `partial_reasons`, taking `reasons` and
  `exclude_reasons`, so the ruleset decides which causes are worth a verdict rather than
  the engine treating them alike.

Three more read Python source evidence, and each has a required field naming what it
matches on, refused if missing or empty: `kind = "py_call"` takes `targets` (dotted
callable names, `*.method` wildcards allowed), plus an optional `usedforsecurity`
(`"absent"`, `"true"`, `"false"` or `"unresolved"`, scalar or list), an optional
`algorithm` (any hash name a call might pass — never checked against a closed list, since
a rule naming a *strong* algorithm on purpose is a real shape), and an optional boolean
`weak_algorithms_only`. `kind = "py_attr"` takes `attributes`, plus an optional `values`
list. `kind = "py_constant"` takes `constants`. A `targets`/`attributes`/`constants`/
`values`/`usedforsecurity` of the wrong shape (not a string or list of strings, or an
empty list) is refused at load time rather than silently matching nothing or, for
`usedforsecurity` specifically, crashing the scan outright.

A token named by a rule is validated at load time, so a typo is a load error rather than a
rule that silently matches nothing. The vocabularies themselves are in
[Vocabularies](reference/vocabularies.md), and why they live in Python rather than here is
in [Invariants](invariants.md#working-rules).

## Using a different ruleset

`--ruleset PATH` on `scan` and `rules` reads an alternative file. It goes through the same
loader and the same validation, including the coherence check between a verdict-less
`partial_binary` rule and `[linkage_policy] exclude_reasons`, the printable-ASCII check
on every `[[string_group]]` substring, and the shape checks on `py_call`/`py_attr`/
`py_constant`'s `targets`/`attributes`/`constants`/`values`/`usedforsecurity` fields
described above -- all load errors rather than a test precisely so that `--ruleset`
users are inside the guard too. A `[rule.match]` missing its kind's required field, or
carrying one of the wrong shape, refuses the *whole* file at load time rather than
silently dropping just that one rule.
