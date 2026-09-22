# Scanning, caching and layout

Entries that are not about one binary format: what the cache is allowed to remember,
which members count as native objects, where the ruleset loader lives, and how a
container of several objects fits a scanner built around reading one at a time.

## A record produced without reading the wheel is never cached

**Accepted.**

The outer `except Exception` — the one the "one bad wheel never aborts a run" invariant names
outright — catches everything the collector could raise. Recording that as `bad_zip`, "not a
readable zip at all", would be a claim more specific than the catch warrants: a `MemoryError`
under load, or any other unanticipated exception, says nothing about whether the archive
itself is readable.

Caching that record under the wheel's content hash unconditionally would make **one transient
failure permanently `OPAQUE`**: every later run, `--resume` included, would serve the same stale
record back and never read the wheel again, even though the condition that interrupted it is
long gone. Reproduced against an unconditional cache by making the collector raise `MemoryError`
on exactly its first call: the second call returns the first call's cached line, even though it
would have read the wheel correctly and found its real `hashlib.md5` call.

**How it is closed.** Two independent pieces. The outer catch records `unexpected_error`, and
`bad_zip` stays reserved for what it specifically means — a checked claim about the archive's
own bytes. A sibling rule claims `unexpected_error`: same `OPAQUE` verdict, same human review,
because absence of evidence is still not evidence of absence regardless of why the evidence is
absent, and with its own accurate `why` rather than `bad_zip`'s claim.

Second, the CLI does not cache a record carrying one of a small set of kinds, and `--resume`
drops one the same way rather than treating it as done.

**Narrow versus broad, and why the deciding axis is determinism, not completion or cost.**
Excluding four kinds on the grounds that they are recorded *alongside* a scan that
otherwise ran to completion, so skipping the cache throws away a real, expensive answer for no
benefit, is right for three of them and wrong for the fourth:
**"recorded alongside a completed scan" and "safe to cache" are not the same question.**

`duplicate_member`, `size_limit_exceeded` and `compression_ratio_exceeded` are computed purely
from zip metadata in hand — a filename seen twice, a size field compared to a limit — with no
I/O and no broad catch anywhere on the path, so the same wheel's bytes always produce the same
one. `member_read_error` *looks* like it belongs in that group because it is also
member-scoped, but every site that records it reaches it through a catch exactly as broad as
the outer one. **The axis that decides whether caching a kind is safe is determinism, not "does
the scan otherwise complete" or "is re-deriving it cheap"** — those point the same way for the
first three and not for this one.

### binfmt's own parse-error kinds are never cached either

The three binary readers each catch broadly around their own parsing and record their own
parse-error kind, one layer below where `member_read_error` is produced — the identical shape,
over a materially larger surface (many catch sites across three readers).

**An audit naming every recording site by hand, rather than assuming every site is, or falls
through to, a broad `except Exception` with no genuinely narrow catch among them.** The ELF
reader has nineteen sites, and thirteen of them are bare comparisons over data fully in hand —
not an `except` block at all. The Mach-O reader has no recording site lexically inside a
handler. And the PE reader's narrow exception class *is* a genuinely-narrow,
deterministic-only catch: it is raised at exactly seven points, every one a pure comparison,
and no exception is ever wrapped into it.

The count: the **majority** of what records these three kinds is deterministic.

None of that changes the conclusion, only its precision. Each reader also has at least one real
broad catch that can record the identical token for a transient reason, and the error kind is
the only granularity the vocabulary offers: **a kind reachable through a broad catch anywhere
belongs in the set entirely**, not just the specific call that happened to raise on a given run.
So all three are in it, deliberately accepting that the deterministic majority rides along
uncached too.

**Two real costs.** First, a permanently malformed object — the common case — is re-read in
full on every scan, forever. Measured on a real ~13 MiB object with two `SHT_DYNSYM` sections:
0.965 s to fail once, then 0.001 s on every later run if cached, **0.974 s on every later run
uncached**, roughly a thousand-fold cost for a wheel whose bytes can only ever produce the same
answer. This is the opposite of why `bad_zip` is in the set: that kind aborts before any real
read happens, so re-failing it is cheap, while these three are recorded *after* the strings
pass and the symbol walk ran. The trade is accepted anyway, on the principle the entries above
lead with — losing real evidence to a stale cache costs more than an expensive, correct
re-scan — but it is a real, ongoing cost, not a free lunch.

Second, this reasoning is **prospective only**. A cache entry written under a narrower set is
still served verbatim, because a cache hit returns before the check is ever consulted. Anyone
carrying such an entry stays stuck until they clear their cache by hand.

**`RecursionError` has its own kind, apart from `PYTHON_SYNTAX_ERROR`.** Sharing a kind with
a null byte or a real `SyntaxError`, both deterministic, would mean excluding it from caching
re-scans every ordinary, permanent syntax error on every run, for no benefit.
`errors.PYTHON_RECURSION_LIMIT_EXCEEDED` is a distinct kind, recorded only by the two
`except RecursionError:` sites in `layers/python_ast.py`, and it is in `SCAN_ABORTED_KINDS`
on its own; `python_syntax_error` keeps its two genuinely deterministic causes and stays out.

[Full entry](../DESIGN.md#a-record-produced-without-reading-the-wheel-is-never-cached)

---

## `.exe` is in `_BINARY_SUFFIX`, and `.com`, `.cpl` and `.sys` are not

**Accepted, the simpler of two ways to recognize `.exe`.**

A member is accepted as a native object by suffix, by vendor path, by living in a sniff
directory with no dot in its name, or by the executable bit with no dot in its name. Without
`exe` among the suffixes, a `.exe` member fails every route: the wrong suffix, and its own dot
disqualifies it from both "no dot" fallbacks. It is never even sniffed for magic bytes, so a
Windows executable shipped in a wheel is invisible while the identical bytes, shipped
suffix-less on the Linux build of the same tool, are read correctly.

```text
pkg-1.0.data/scripts/openssl       (win_amd64)  -> CONDITIONAL, openssl_linkage=static, extensions=1
pkg-1.0.data/scripts/openssl.exe   (win_amd64)  -> NO_CRYPTO_DETECTED, review=False, extensions=0
```

**How it is read.** `exe` is one alternative in the suffix pattern, and nothing else treats it
specially: the PE reader keys on the optional header's magic, not on any DLL-versus-EXE
distinction, so an `.exe` member is read by the exact same code path a `.pyd` is. This is
member classification, not a new reader.

**What was rejected.** Sniffing by magic for anything under a sniff directory regardless of
extension, which would also cover `.com`, `.cpl`, `.sys`-style oddities and a dotted,
suffix-less Mach-O tool name. That is a broader mechanism for a narrower concrete concern, a
`.exe` problem, not evidence of wheels shipping those others.

Extending the suffix pattern to those three as well is rejected for the same reason inverted:
adding a suffix to policy on the strength of "it would also be covered by the alternative"
rather than a measured, real case is exactly the kind of unmeasured addition the ruleset's own
`why` requirement exists to prevent, and there is no `why` here beyond "it exists as a Windows
extension". A member the scanner does not sniff stays invisible, which is no worse for being
left out.

[Full entry](../DESIGN.md#exe-is-in-_binary_suffix-and-com-cpl-and-sys-are-not)

---

## The loader lives in `ruleset_loader.py`, a sibling module, not a package

**Accepted, and it changes no record.** No rule, symbol, library or verdict depends on which module parses the
ruleset.

Held in one file, `ruleset.py` carries four responsibilities: the object model, the prefilter
that sits next to the matcher it mirrors, the compiled-pattern builder, and the TOML parser and
validator. Together they reach pylint's default module-line limit, and raising the limit papers
over four responsibilities sharing one file rather than reducing them.

**The split.** The parser and every validation helper live in `ruleset_loader.py`, a sibling
module. `ruleset.py` keeps the object model, the vocabulary constants — read by the loader's
checks and by the test suite, but describing the schema rather than how to walk it, so they stay
with the model they describe — and the prefilter beside the matcher it mirrors. Both files sit
well under the default limit.

**Sibling module, not a package.** Both are reasonable. `binfmt/` and `layers/` are
packages because each holds several *parallel* things — one reader per format, one extractor per
layer. This split is not parallel siblings; it is one concern divided by responsibility, the same
shape as `record.py`/`verdict.py` sitting as flat modules.

**Re-exporting from `ruleset.py` is rejected, measured.** The obvious way to keep every
`from .ruleset import load_ruleset` working is to import the loader's functions back into
`ruleset.py`, at the bottom of the file because the loader needs the object model above it to
exist. It parses, runs, and produces byte-identical output with a fully green test run — and
pylint correctly calls it what it is: a genuine cyclic import, on top of a
wrong-import-position and a useless-import-alias the self-alias idiom needs at every call site
to silence. Suppressing four stacked warnings to keep one import direction working is worse than
the thing it avoids, which is touching call sites. **The loader depending on the model it
validates against is the natural direction; asking the model to import back from its own
validator is what manufactures the cycle, not the split itself.**

**What it costs.** Every import of `load_ruleset`, `parse_ruleset` or `routine_reasons` comes
from `ruleset_loader`; everything that imports only object-model names imports them from
`ruleset`.

[Full entry](../DESIGN.md#the-loader-lives-in-ruleset_loaderpy-a-sibling-module-not-a-package)

## `Conventions`/`SonameInfo` and their `[conventions]` parser move to `conventions.py`

**Accepted, and it changes no record.** `ruleset_loader.py` reached pylint's default module-line
limit as SBOM name-folding and the cargo-purl reorder it backs joined a loader that already
carried the ruleset shape checks and every other parsing helper. `Conventions`/`SonameInfo` (the
object model) and `_parse_conventions` (the parser that builds one) move together into a new
sibling module, `conventions.py`, out of `ruleset.py` and `ruleset_loader.py` respectively, and
the parser drops its leading underscore to become the public `parse_conventions`:
`ruleset_loader.parse_ruleset` now calls it across the module boundary the underscore marks
private. `parse_conventions` builds nothing but a `Conventions`, so the model and the function
that builds it are one concern, not two files sharing a name by coincidence.

**Why the parser has to move too.** `ruleset_loader.py`, not `ruleset.py`, is the file that
reached the limit, and `_parse_conventions` is the piece of it large enough to matter. Moving
only the dataclasses would have fixed a limit nothing in `ruleset.py` had broken.

**What was rejected.** A module-local exemption for `ruleset_loader.py` to match
`binfmt/elf.py` and `binfmt/macho.py` below: those two earn theirs because about half of each is
docstring, and this module's growth is validation code, not documentation. A bigger
`max-module-lines`, for the same reason the entry below rejects one.

[Full entry](../DESIGN.md#conventionssonameinfo-and-their-conventions-parser-move-to-conventionspy)

## `binfmt/elf.py` and `binfmt/macho.py` carry module-local line-count exemptions

**Accepted.** Each of `binfmt/elf.py` and `binfmt/macho.py` carries its own module-local
`# pylint: disable=too-many-lines`, and the project-wide `max-module-lines` in `pyproject.toml`
stays at pylint's own default. `macho.py`'s docstring names every way `partial_analysis` can
survive; `elf.py` documents every way an attacker-controlled label can win a lookup and every
cross-check that closes one.

**Why not split.** Measured, about half of each module is docstring and comment — the code
alone is under 600 lines in each. The excess is the documentation this project's "every policy
entry carries a why" rule asks for, not unchecked growth, so splitting either module would move
prose between files rather than reduce what either one is responsible for. Contrast this with
the loader entry above, where four responsibilities shared one file and the split was right.

**Why not a global bump.** Raising the project-wide limit instead would silently give every
*other* module the same headroom, whether or not it has earned it. `binfmt/pe.py`, and every
other module, stays under the limit without a disable.

**What holds it.** `tests/test_design_notes.py` fails if a module carries the disable without
being listed, if a listed module drops the disable, if the doc's list and the test's set name
different modules in either direction, if `pyproject.toml` sets `max-module-lines` in any
`[tool.pylint.*]` table, or if `too-many-lines`/`C0302` is added to any table's `disable` list.

**Revisit if** a third module needs the exemption, at which point the trade a global bump makes
is worth re-measuring, or a listed module's code alone, excluding docstrings and comments, nears
the limit, at which point it is a split rather than an exemption.

[Full entry](../DESIGN.md#binfmtelfpy-and-binfmtmachopy-carry-module-local-line-count-exemptions)

## The cross-rule coherence checks live in `ruleset_coherence.py`

**Accepted, and it changes no record.** Held beside the shape checks, the unknown-key checks and
every other parsing helper, four checks bring `ruleset_loader.py` to pylint's default module-line
limit with no room for the next one. They live in a sibling module, `ruleset_coherence.py`,
public because `parse_ruleset` calls them across the module boundary: the two that refuse a
`suppressed_by` that can never fire or closes a cycle, and the two that refuse an SBOM relation
leaving a `<name>_linkage` moved with no finding to explain it.

**Why these four.** Each refuses a relation *between* rules that no single rule's parse can see,
reading rules the loader has already built, shape-checked and reference-resolved. None reads the
raw TOML or calls a loader helper, so the module imports only the object model; the loader
imports it and never the reverse. Every check that walks a raw table stays in the loader, with
the helpers that read it, and so does the check that bounds `[limits]` against the tables' sizes.

**What was rejected.** A module-local exemption for `ruleset_loader.py`, and a bigger
`max-module-lines`, for the reasons the two entries above give. Moving the raw-table checks as
well, which would mean restating the loader's small helpers a second time for lines the loader
does not need back.

[Full entry](../DESIGN.md#the-cross-rule-coherence-checks-live-in-ruleset_coherencepy)

## `binfmt.ar` reads `.a`/`.lib` static archives as a container, not a reader

**Accepted.**

A `.a`/`.lib` static archive — the `ar` container format bundling several `.o`/`.obj`
relocatable objects for downstream linking — matches no route into `is_binary_member`
other than its own suffix: not a vendor path, a sniff directory or an executable bit.
Without that suffix, a wheel vendoring a static crypto library is invisible to the scanner,
with nothing in the record to say so.

Every other reader answers to "one stream in, one `BinaryEvidence` out"; an archive holds
several separate, independently-linkable objects a consumer wants told apart, so
`binfmt.ar.read_ar_members` is not one more entry in the reader table. It is called
directly by `layers.binaries.scan_binaries`, once a `.a`/`.lib`-suffixed member's own
magic confirms it is really `ar`-format, and dispatches each real member it finds to
the same per-format readers everything else in the wheel goes through.

The container format itself — magic, 60-byte member headers, the GNU long-name table,
odd-size padding — is verified against real archives from this host's own `ar`, not only
the documented spec. A member table that cannot be walked to completion keeps whatever real
members were found; only when none were found at all does the whole archive fall back to one
strings-only record, the same shape a format with no registered reader gets. A member is never
dropped for having an unresolvable name — it is still read under a synthetic path, with its own
error naming why. Archive-derived evidence is marked `from_archive` and excluded from
`linkage.member_stem_counts`, so a bundled object's `SONAME` can never confirm a sibling
extension's `DT_NEEDED` entry as resolving inside the wheel.

**A relocatable `.o`'s `.symtab` needs nothing of `binfmt.ar`'s own.** A `.o` normally
carries `.symtab` and no `.dynsym`, and `binfmt.elf` matches `.symtab` whenever `.dynsym` is
genuinely absent (see the [ELF](elf.md) page); `binfmt.ar` calls `read_binary` per member, so
it gets that from `binfmt.elf` directly.

[Full entry](../DESIGN.md#binfmtar-reads-alib-static-archives-as-a-container-not-a-reader)

## The HTML report embeds records and renders them in the browser

**Accepted.**

`--format html` writes one self-contained page: no new dependency, and no external
asset — no CDN script, no stylesheet link, nothing the page loads over the network.
Python renders a static shell and embeds the records as one JSON block; the page's own
JavaScript builds the table and the drill-down views from that data at load time.

The embedded JSON is escaped so no wheel-controlled string — a filename, a matched
string, a piece of evidence — can close the `<script>` element it sits in, and the JS
that reads it back never uses `innerHTML`: every value reaches the DOM through
`textContent` or an element property, so nothing decoded from a wheel is ever parsed as
markup.

The page is byte-stable: a pure function of the records, the ruleset and the template,
with no timestamp, host path or hostname. Three `localStorage` keys hold view-time
preferences only — the theme, the onboarding dialog's checkbox (a missing key or `keep`
both show it with the checkbox checked; only `dismissed` suppresses it), and the wheel
table's resized column widths, each validated against the same ceiling a resize is
itself clamped to on the way in — each read and written through the same try/catch, so
unavailable or corrupt storage renders the same page with every preference at its
default.

The URL hash carries the open wheel (`wheel=<index>`), the top-level view (`view=rules`,
omitted for its default), the toolbar's filters (`class=`, `linkage=`, `review=`,
`q=`), and the Wheels table's own per-column filters (`f.<column>=`, one pair per active
column, written in column order), joined by `&` and written with `history.replaceState`
rather than `pushState` so filtering does not spam browser history. Reading is total:
applying a hash always sets every recognised field, from the hash or back to its default,
so a plain link never inherits a filter left active from whatever was open before.
Opening a wheel merges into the existing filter params instead of overwriting them, and a
link carrying any of these reproduces the same filtered view on load. The grammar's scope
is the Wheels view's own state; the Rules table sits outside that scope entirely, the same
way its sort already does, so neither its sort nor its own per-column filters are part of
the hash.

Both tables carry a per-column "contains" filter beside the sortable header, matching
case-insensitively against the text each cell already shows; the Wheels table's `reasons`
column matches the record's full reasons list rather than only the chips a cell displays,
so a reason hidden behind "+N more" still matches. An always-visible class legend beside
the toolbar lists every verdict class present in the current run with its own help text,
and the Wheels table carries an `openssl` column showing `conditions.openssl_linkage` for
the wheel as a whole, including `none` — evidence the Markdown table leaves out.

No verdict class gets a favourable colour. The two classes that mean "nothing was
decided" share one neutral token; every other class is a warning or a danger token, and
a wheel not flagged for review reads "not flagged", never a plain "no" or a checkmark.
The class and linkage help text shown in the page lives in `report.py` as plain
constants, next to a test that fails when a class in the ruleset's precedence has no
entry.

[Full entry](../DESIGN.md#the-html-report-embeds-records-and-renders-them-in-the-browser)
