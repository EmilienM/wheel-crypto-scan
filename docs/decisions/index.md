# Design decisions

Design calls that were deliberate, are not obvious from the code, and would otherwise be
re-litigated every time someone new reads it. [Invariants](../invariants.md) carries the
rules; this section carries the reasoning behind the ones that cost something, including the
holes left open on purpose and the measurement behind each one.

The canonical text is
[`DECISIONS.md`](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md) in the
repository. What follows is the same set of entries, grouped by the subsystem they are
about, each summarising the call, what it cost, and what was rejected, with a link to the
full argument.

## How to read an entry

Every entry opens with a one-line disposition — **Accepted**, **Accepted, knowing what it
costs**, **Fixed**, **Reversed**, **Corrected** — and then answers the same questions:
what was wrong, what changed, what it costs, what was rejected and why, and what would make
it worth revisiting.

Three habits in that file are worth knowing before you read it:

- **Claims are measured, not asserted.** Nearly every entry carries a reproduction, usually
  a before/after pair from a real or synthesised object.
- **A claim that did not survive review is corrected in place**, under its own heading,
  rather than quietly dropped. Several entries have a subsection whose whole job is to say
  the paragraph above it was wrong. Those are usually the most useful part.
- **What is left open is stated as plainly as what is closed.** An entry that ends with a
  residual has one because closing it needs a bigger change than the issue asked for, and it
  says so.

---

## [Determinism and the Python layer](interpreter.md)

| Entry | Disposition |
|---|---|
| [The Python parser follows the interpreter running the scan](interpreter.md#the-python-parser-follows-the-interpreter-running-the-scan) | Accepted. Documented, not fixed |
| [An explicit `usedforsecurity=True`, and a non-constant flag, are not `NO_CRYPTO_DETECTED`](interpreter.md#an-explicit-usedforsecuritytrue-and-a-non-constant-flag-are-not-no_crypto_detected) | Fixed |

## [Evidence, opacity and verdicts](opacity.md)

| Entry | Disposition |
|---|---|
| [A routine cause is recorded but does not make a wheel opaque](opacity.md#a-routine-cause-is-recorded-but-does-not-make-a-wheel-opaque) | Accepted, and half of it was later reversed |
| [A symbol table is checked against the string table, not taken at its word](opacity.md#a-symbol-table-is-checked-against-the-string-table-not-taken-at-its-word) | Accepted. Reverses an earlier decision |
| [Linkage reads a second split over the same vocabulary](opacity.md#linkage-reads-a-second-split-over-the-same-vocabulary) | Accepted. It changes the field most consumers filter on |

## [OpenSSL linkage](linkage.md)

| Entry | Disposition |
|---|---|
| [A `needed` entry is bundled by what it resolves to, not by whether its name was renamed](linkage.md#a-needed-entry-is-bundled-by-what-it-resolves-to-not-by-whether-its-name-was-renamed) | Accepted, then corrected twice |
| [A `needed` match and a definition inside one object are both true, so the object is `mixed`](linkage.md#a-needed-match-and-a-definition-inside-one-object-are-both-true-so-the-object-is-mixed) | Fixed, and extended twice |

## [Policy data: what the ruleset enumerates](policy.md)

| Entry | Disposition |
|---|---|
| [`openssl_banner` names every major digit, not the majors that shipped](policy.md#openssl_banner-names-every-major-digit-not-the-majors-that-shipped) | Accepted |
| [The sweep that followed, and the two kinds of list it separated](policy.md#the-sweep-that-followed-and-the-two-kinds-of-list-it-separated) | Accepted |

## [Caps, budgets and record size](limits.md)

| Entry | Disposition |
|---|---|
| [A recording cap is not a partial read](limits.md#a-recording-cap-is-not-a-partial-read) | Accepted |
| [A cap bounds the record, it does not pick the evidence](limits.md#a-cap-bounds-the-record-it-does-not-pick-the-evidence) | Accepted, and it changes records |
| [A cap bounds the record, not the evaluation](limits.md#a-cap-bounds-the-record-not-the-evaluation) | Accepted, and it changes verdicts |
| [`binaries[]` keeps what a finding points at, before filling the rest](limits.md#binaries-keeps-what-a-finding-points-at-before-filling-the-rest) | Accepted, then revised after review |
| [A symbol name is capped like PE's already are](limits.md#a-symbol-name-is-capped-like-pes-already-are) | Accepted |

## [ELF](elf.md)

| Entry | Disposition |
|---|---|
| [Sections are found by type, not by a name nobody checks](elf.md#sections-are-found-by-type-not-by-a-name-nobody-checks) | Accepted, after five rounds of review |
| [A compressed section is checked before it is inflated](elf.md#a-compressed-section-is-checked-before-it-is-inflated) | Accepted, then widened |

## [Mach-O](macho.md)

| Entry | Disposition |
|---|---|
| [A universal binary is one record, and its slices are merged](macho.md#a-universal-binary-is-one-record-and-its-slices-are-merged) | Accepted, knowing what it costs |
| [Every dylib-loading command reaches `needed`, not just `LC_LOAD_DYLIB`](macho.md#every-dylib-loading-command-reaches-needed-not-just-lc_load_dylib) | Accepted |
| [An unparseable load-command header flags the walk, it does not end it in silence](macho.md#an-unparseable-load-command-header-flags-the-walk-it-does-not-end-it-in-silence) | Accepted, then extended |
| [`sizeofcmds` and the symbol table are capped, not just clamped to the member](macho.md#sizeofcmds-and-the-symbol-table-are-capped-not-just-clamped-to-the-member) | Accepted |
| [More than one `LC_ID_DYLIB` or `LC_SYMTAB` is ambiguous, not last-wins](macho.md#more-than-one-lc_id_dylib-or-lc_symtab-is-ambiguous-not-last-wins) | Accepted |

## [PE](pe.md)

| Entry | Disposition |
|---|---|
| [A forwarder resolves the dependency it forwards to, not just its own name](pe.md#a-forwarder-resolves-the-dependency-it-forwards-to-not-just-its-own-name) | Accepted |

## [Scanning, caching and layout](tooling.md)

| Entry | Disposition |
|---|---|
| [A record produced without reading the wheel is never cached](tooling.md#a-record-produced-without-reading-the-wheel-is-never-cached) | Accepted, then widened on a corrected audit |
| [`.exe` joins `_BINARY_SUFFIX`, and stops there](tooling.md#exe-joins-_binary_suffix-and-stops-there) | Accepted |
| [The loader moves to `ruleset_loader.py`, a sibling module, not a package](tooling.md#the-loader-moves-to-ruleset_loaderpy-a-sibling-module-not-a-package) | Accepted. Pure refactor |
