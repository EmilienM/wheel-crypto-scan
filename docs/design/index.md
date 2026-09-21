# Design

Design calls that were deliberate, are not obvious from the code, and would otherwise be
re-litigated every time someone new reads it. [Invariants](../invariants.md) carries the
rules; this section carries the reasoning behind the ones that cost something, including the
holes left open on purpose and the measurement behind each one.

The canonical text is
[`DESIGN.md`](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md) in the
repository. What follows is the same set of entries, grouped by the subsystem they are
about, each summarising the call, what it cost, and what was rejected, with a link to the
full argument.

## How to read an entry

Every entry opens with a one-line status — **Accepted**, **Accepted, knowing what it
costs**, **Accepted, and it changes records** (or verdicts, or `openssl_linkage`),
**Accepted, and it changes no record**, or **Documented, not fixed** — and then answers
the same questions: what the call is, why, what it costs, what was rejected and why, and
what would make it worth revisiting.

Two habits in that file are worth knowing before you read it:

- **Claims are measured, not asserted.** Nearly every entry carries a reproduction, usually
  a pair contrasting one approach with another over a real or synthesised object.
- **What is left open is stated as plainly as what is closed.** An entry that ends with a
  residual has one because closing it needs a bigger change than this tool's scope covers
  today, and it says so.

---

## [Determinism and the Python layer](interpreter.md)

| Entry | Status |
|---|---|
| [The Python parser follows the interpreter running the scan](interpreter.md#the-python-parser-follows-the-interpreter-running-the-scan) | Accepted. Documented, not fixed |
| [An explicit `usedforsecurity=True`, and a non-constant flag, are not `NO_CRYPTO_DETECTED`](interpreter.md#an-explicit-usedforsecuritytrue-and-a-non-constant-flag-are-not-no_crypto_detected) | Accepted, and it changes verdicts |

## [Evidence, opacity and verdicts](opacity.md)

| Entry | Status |
|---|---|
| [A routine cause is recorded but does not make a wheel opaque](opacity.md#a-routine-cause-is-recorded-but-does-not-make-a-wheel-opaque) | Accepted, and it changes verdicts |
| [A symbol table is checked against the string table, not taken at its word](opacity.md#a-symbol-table-is-checked-against-the-string-table-not-taken-at-its-word) | Accepted, and it changes verdicts |
| [Linkage reads a second split over the same vocabulary](opacity.md#linkage-reads-a-second-split-over-the-same-vocabulary) | Accepted. It changes the field most consumers filter on |

## [OpenSSL linkage](linkage.md)

| Entry | Status |
|---|---|
| [A `needed` entry is bundled by what it resolves to, not by whether its name was renamed](linkage.md#a-needed-entry-is-bundled-by-what-it-resolves-to-not-by-whether-its-name-was-renamed) | Accepted, and it changes `openssl_linkage` and one finding |
| [A `needed` match and a definition inside one object are both true, so the object is `mixed`](linkage.md#a-needed-match-and-a-definition-inside-one-object-are-both-true-so-the-object-is-mixed) | Accepted, and it changes `openssl_linkage` |
| [An OpenSSL crate with no other evidence reads `unknown`, not `none`](linkage.md#an-openssl-crate-with-no-other-evidence-reads-unknown-not-none) | Accepted, and it changes `openssl_linkage` |
| [A version banner beside imports from the system library is header text, not a copy](linkage.md#a-version-banner-beside-imports-from-the-system-library-is-header-text-not-a-copy) | Accepted, and it changes `openssl_linkage` |
| [An object that read `unknown` withholds `DERIVED_SYSTEM_OPENSSL_ONLY`; the field stays `system`](linkage.md#an-object-that-read-unknown-withholds-derived_system_openssl_only-the-field-stays-system) | Accepted, and it changes verdicts |
| [An SBOM naming an OpenSSL crate reads `unknown`, not `none`](linkage.md#an-sbom-naming-an-openssl-crate-reads-unknown-not-none) | Accepted, and it changes `openssl_linkage` |

## [Policy data: what the ruleset enumerates](policy.md)

| Entry | Status |
|---|---|
| [`openssl_banner` names every major digit, not the majors that shipped](policy.md#openssl_banner-names-every-major-digit-not-the-majors-that-shipped) | Accepted |
| [Two kinds of list: a field's spellings and an entity list](policy.md#two-kinds-of-list-a-fields-spellings-and-an-entity-list) | Accepted |
| [Crates are read from every cargo source layout, and a vendored crate has no version](policy.md#crates-are-read-from-every-cargo-source-layout-and-a-vendored-crate-has-no-version) | Accepted, and it changes records |
| [A Go FIPS build is told from a stock one by its build settings](policy.md#a-go-fips-build-is-told-from-a-stock-one-by-its-build-settings) | Accepted |
| [A static OpenSSL's legacy primitives lead the headline](policy.md#a-static-openssls-legacy-primitives-lead-the-headline) | Accepted, knowing what it costs |
| [Suppression is keyed on rule, subject and object](policy.md#suppression-is-keyed-on-rule-subject-and-object) | Accepted |
| [An AWS-LC FIPS build is told from a stock one by its symbol prefix](policy.md#an-aws-lc-fips-build-is-told-from-a-stock-one-by-its-symbol-prefix) | Accepted |

## [Caps, budgets and record size](limits.md)

| Entry | Status |
|---|---|
| [A recording cap is not a partial read](limits.md#a-recording-cap-is-not-a-partial-read) | Accepted |
| [A cap bounds the record, it does not pick the evidence](limits.md#a-cap-bounds-the-record-it-does-not-pick-the-evidence) | Accepted, and it changes records |
| [A cap bounds the record, not the evaluation](limits.md#a-cap-bounds-the-record-not-the-evaluation) | Accepted, and it changes verdicts |
| [`binaries[]` keeps what a finding points at, before filling the rest](limits.md#binaries-keeps-what-a-finding-points-at-before-filling-the-rest) | Accepted, and it changes records |
| [A symbol name is capped the way PE's are](limits.md#a-symbol-name-is-capped-the-way-pes-are) | Accepted |
| [`caps.cap` scans `ordered` again instead of materialising `pinned`/`rest`/`leftovers`](limits.md#capscap-scans-ordered-again-instead-of-materialising-pinnedrestleftovers) | Accepted. Performance and memory, not correctness |
| [`bundled_libs` and `errors[]` get their own caps, not `binaries_truncated`'s](limits.md#bundled_libs-and-errors-get-their-own-caps-not-binaries_truncateds) | Accepted, and it changes records |
| [`skipped` and `symlinks` reuse `caps.cap`, not a plain prefix](limits.md#skipped-and-symlinks-reuse-capscap-not-a-plain-prefix) | Accepted, and it changes records |

## [ELF](elf.md)

| Entry | Status |
|---|---|
| [Sections are found by type, not by a name nobody checks](elf.md#sections-are-found-by-type-not-by-a-name-nobody-checks) | Accepted, and it changes verdicts |
| [A compressed section is checked before it is inflated](elf.md#a-compressed-section-is-checked-before-it-is-inflated) | Accepted, and it changes records |
| [`.symtab` is matched for crypto symbols when `.dynsym` is genuinely absent](elf.md#symtab-is-matched-for-crypto-symbols-when-dynsym-is-genuinely-absent) | Accepted, and it changes records |
| [`.symtab` local definitions are read when `.dynsym` is present](elf.md#symtab-local-definitions-are-read-when-dynsym-is-present) | Accepted, and it changes records |

## [Mach-O](macho.md)

| Entry | Status |
|---|---|
| [A universal binary is one record, and its slices are merged](macho.md#a-universal-binary-is-one-record-and-its-slices-are-merged) | Accepted, knowing what it costs |
| [Every dylib-loading command reaches `needed`, not just `LC_LOAD_DYLIB`](macho.md#every-dylib-loading-command-reaches-needed-not-just-lc_load_dylib) | Accepted |
| [An unparseable load-command header flags the walk, it does not end it in silence](macho.md#an-unparseable-load-command-header-flags-the-walk-it-does-not-end-it-in-silence) | Accepted, and it changes records |
| [`sizeofcmds` and the symbol table are capped, not just clamped to the member](macho.md#sizeofcmds-and-the-symbol-table-are-capped-not-just-clamped-to-the-member) | Accepted |
| [More than one `LC_ID_DYLIB` or `LC_SYMTAB` is ambiguous, not last-wins](macho.md#more-than-one-lc_id_dylib-or-lc_symtab-is-ambiguous-not-last-wins) | Accepted, and it changes records |

## [PE](pe.md)

| Entry | Status |
|---|---|
| [A forwarder resolves the dependency it forwards to, not just its own name](pe.md#a-forwarder-resolves-the-dependency-it-forwards-to-not-just-its-own-name) | Accepted, and it changes what a forwarding wrapper can hide |

## [Scanning, caching and layout](tooling.md)

| Entry | Status |
|---|---|
| [A record produced without reading the wheel is never cached](tooling.md#a-record-produced-without-reading-the-wheel-is-never-cached) | Accepted |
| [`.exe` is in `_BINARY_SUFFIX`, and `.com`, `.cpl` and `.sys` are not](tooling.md#exe-is-in-_binary_suffix-and-com-cpl-and-sys-are-not) | Accepted |
| [The loader lives in `ruleset_loader.py`, a sibling module, not a package](tooling.md#the-loader-lives-in-ruleset_loaderpy-a-sibling-module-not-a-package) | Accepted, and it changes no record |
| [`binfmt/elf.py` and `binfmt/macho.py` carry module-local line-count exemptions](tooling.md#binfmtelfpy-and-binfmtmachopy-carry-module-local-line-count-exemptions) | Accepted |
| [`binfmt.ar` reads `.a`/`.lib` static archives as a container, not a reader](tooling.md#binfmtar-reads-alib-static-archives-as-a-container-not-a-reader) | Accepted |
| [The HTML report embeds records and renders them in the browser](tooling.md#the-html-report-embeds-records-and-renders-them-in-the-browser) | Accepted |
