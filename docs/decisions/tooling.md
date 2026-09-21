# Scanning, caching and layout

Entries that are not about one binary format: what the cache is allowed to remember,
which members count as native objects, where the ruleset loader lives, and how a
container of several objects fits a scanner built around reading one at a time.

## A record produced without reading the wheel is never cached

**Accepted.**

The outer `except Exception` — the one the "one bad wheel never aborts a run" invariant names
outright — caught everything the collector could raise and recorded it as `bad_zip`, "not a
readable zip at all". That claim is specific and was wrong: a `MemoryError` under load, or any
other unanticipated exception, says nothing about whether the archive itself is readable.

The CLI then cached that record under the wheel's content hash unconditionally, so **one
transient failure made a wheel permanently `OPAQUE`**: every later run, `--resume` included,
served the same stale record back and never read the wheel again, even though the condition
that interrupted it was long gone. Reproduced by making the collector raise `MemoryError` on
exactly its first call: the second call returns the first call's cached line, even though it
would have read the wheel correctly and found its real `hashlib.md5` call.

**What changed.** Two independent pieces. The outer catch now records `unexpected_error`, and
`bad_zip` stays reserved for what it already specifically means — a checked claim about the
archive's own bytes. A sibling rule claims the new kind: same `OPAQUE` verdict, same human
review, because absence of evidence is still not evidence of absence regardless of why the
evidence is absent, but with its own `why` rather than the false claim this fix removes.

Second, the CLI no longer caches a record carrying one of a small set of kinds, and `--resume`
drops one the same way rather than treating it as already done.

**Narrow versus broad, and why the first version of "broad" was still wrong.** This entry
originally excluded four kinds on the grounds that they are recorded *alongside* a scan that
otherwise ran to completion, so skipping the cache throws away a real, expensive answer for no
benefit. That reasoning is right for three of them and wrong for the fourth, and review caught
it: **"recorded alongside a completed scan" and "safe to cache" are not the same question.**

`duplicate_member`, `size_limit_exceeded` and `compression_ratio_exceeded` are computed purely
from zip metadata already in hand — a filename seen twice, a size field compared to a limit —
with no I/O and no broad catch anywhere on the path, so the same wheel's bytes always produce
the same one. `member_read_error` *looks* like it belongs in that group because it is also
member-scoped, but every site that records it reaches it through a catch exactly as broad as
the one this fix is about. **The axis that decides whether caching a kind is safe is
determinism, not "does the scan otherwise complete" or "is re-deriving it cheap"** — those
happened to point the same way for the first three and not for this one.

### Widened: binfmt's own parse-error kinds, on a corrected audit

The three binary readers each catch broadly around their own parsing and record their own
parse-error kind, one layer below where `member_read_error` is produced — the identical shape,
left out of the original fix because it is a materially larger surface.

**The audit was run twice, and the first pass was wrong on both halves.** It claimed every
recording site in all three readers was, or fell through to, a broad `except Exception`, and
that none of the three had a genuinely narrow catch. Review checked it against the code: the
ELF reader has nineteen sites, not ten, and thirteen of them are bare comparisons over data
already fully in hand — not an `except` block at all. The Mach-O reader has no recording site
lexically inside a handler. And the PE reader's narrow exception class *is* the
genuinely-narrow, deterministic-only catch the first pass said none of them had: it is raised
at exactly seven points, every one a pure comparison, and no exception is ever wrapped into it.

Corrected count: the **majority** of what records these three kinds is deterministic, not the
minority the first pass claimed.

None of that changes the conclusion, only its honesty. Each reader also has at least one real
broad catch that can record the identical token for a transient reason, and the error kind is
the only granularity the vocabulary offers: **a kind reachable through a broad catch anywhere
belongs in the set entirely**, not just the specific call that happened to raise on a given run.
So all three join it, deliberately accepting that the deterministic majority rides along
uncached too.

**Two real costs the first draft did not record.** First, a permanently malformed object — the
common case, per the corrected audit — is now re-read in full on every scan, forever. Measured
on a real ~13 MiB object with two `SHT_DYNSYM` sections: 0.965 s to fail once, then 0.001 s on
every later run before this fix, **0.974 s on every later run after it**, roughly a
thousand-fold cost for a wheel whose bytes can only ever produce the same answer. This is the
opposite of why `bad_zip` was accepted into the set: that kind aborts before any real read
happens, so re-failing it is cheap, while these three are recorded *after* the strings pass and
the symbol walk already ran. The trade is accepted anyway, on the principle the original entry
leads with — losing real evidence to a stale cache costs more than an expensive, correct
re-scan — but it is a real, ongoing cost, not a free lunch.

Second, the fix is **prospective only**. A cache entry already poisoned under pre-fix code is
still served verbatim, because a cache hit returns before the check is ever consulted. Anyone
who already hit this bug stays stuck until they clear their cache by hand.

**What was deferred, and closed in #109.** The Python layer used to turn a `RecursionError` into
the same syntax-error kind as a null byte or a real `SyntaxError`, both deterministic — sharing
one kind meant excluding it from caching would re-scan every ordinary, permanent syntax error on
every run, for no benefit. `errors.PYTHON_RECURSION_LIMIT_EXCEEDED` is now a distinct kind,
recorded only by the two `except RecursionError:` sites in `layers/python_ast.py`, and it joins
`SCAN_ABORTED_KINDS` on its own; `python_syntax_error` keeps its two genuinely deterministic
causes and stays out.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-record-produced-without-reading-the-wheel-is-never-cached) ·
[#64](https://github.com/EmilienM/wheel-crypto-scan/issues/64) ·
[#97](https://github.com/EmilienM/wheel-crypto-scan/issues/97) ·
[#109](https://github.com/EmilienM/wheel-crypto-scan/issues/109)

---

## `.exe` joins `_BINARY_SUFFIX`, and stops there

**Accepted, the simpler of the two options the issue itself named.**

A member was accepted as a native object by suffix, by vendor path, by living in a sniff
directory with no dot in its name, or by the executable bit with no dot in its name. `.exe`
failed every route: the wrong suffix, and its own dot disqualified it from both "no dot"
fallbacks. It was never even sniffed for magic bytes, so a Windows executable shipped in a
wheel was invisible while the identical bytes, shipped suffix-less on the Linux build of the
same tool, were read correctly.

```text
pkg-1.0.data/scripts/openssl       (win_amd64)  -> CONDITIONAL, openssl_linkage=static, extensions=1
pkg-1.0.data/scripts/openssl.exe   (win_amd64)  -> NO_CRYPTO_DETECTED, review=False, extensions=0
```

**What changed.** One alternative added to the suffix pattern. Nothing else moved: the PE reader
already keys on the optional header's magic, not on any DLL-versus-EXE distinction, so an `.exe`
member is read by the exact same code path a `.pyd` already was. This is a member-classification
fix, not a new reader.

**What was rejected.** The issue's second option — sniffing by magic for anything under a sniff
directory regardless of extension, which would also cover `.com`, `.cpl`, `.sys`-style oddities
and a dotted, suffix-less Mach-O tool name. The issue frames its two options as alternatives,
and its concrete concern is a `.exe` problem, not evidence of wheels shipping those.

Extending the suffix pattern to those three as well was considered and rejected for the same
reason inverted: adding a suffix to policy on the strength of "it would also be covered by the
alternative" rather than a measured, real case is exactly the kind of unmeasured addition the
ruleset's own `why` requirement exists to prevent, and there is no `why` here beyond "it exists
as a Windows extension". A member the scanner still does not sniff keeps its prior behaviour,
not a worse one.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#exe-joins-_binary_suffix-and-stops-there) ·
[#65](https://github.com/EmilienM/wheel-crypto-scan/issues/65)

---

## The loader moves to `ruleset_loader.py`, a sibling module, not a package

**Accepted. Pure refactor: no rule, symbol, library or verdict changed.**

`ruleset.py` had grown to four responsibilities in one file: the object model, the prefilter
that sits next to the matcher it mirrors, the compiled-pattern builder, and the TOML parser and
validator. The file had reached pylint's default module-line limit, and an unrelated fix had
raised that limit for a different module, which also gave this file slack it had not earned.
The point survives that: raising the limit again papers over four responsibilities sharing one
file, it does not reduce them.

**What changed.** The parser and every validation helper moved to a new sibling module.
`ruleset.py` keeps the object model, the vocabulary constants — read by the loader's checks and
by the test suite, but describing the schema rather than how to walk it, so they stayed with the
model they describe — and the prefilter beside the matcher it mirrors. Both files now sit well
under the old default, with headroom to spare.

**Sibling module, not a package.** The issue sanctioned both. `binfmt/` and `layers/` are
packages because each holds several *parallel* things — one reader per format, one extractor per
layer. This split is not parallel siblings; it is one concern divided by responsibility, the same
shape as `record.py`/`verdict.py` already sitting as flat modules.

**Re-exporting from `ruleset.py` was tried and rejected.** The obvious way to keep every existing
import working is to import the loader's functions back into `ruleset.py`. That was implemented
first, at the bottom of the file because the loader needs the object model above it to exist. It
parsed, ran, and produced byte-identical output with a fully green test run — and pylint
correctly called it what it is: a genuine cyclic import, on top of a wrong-import-position and a
useless-import-alias the self-alias idiom needs at every call site to silence. Suppressing four
stacked warnings to keep one import direction working is worse than the thing it avoids, which
is touching call sites. **The loader depending on the model it validates against is the natural
direction; asking the model to import back from its own validator is what manufactured the
cycle, not the split itself.**

**What it costs.** One import line in the CLI and one in each of 20 test files. No test's
assertions or fixtures changed. Everything that already imported only object-model names needed
no change at all.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#the-loader-moves-to-ruleset_loaderpy-a-sibling-module-not-a-package) ·
[#66](https://github.com/EmilienM/wheel-crypto-scan/issues/66)

## `binfmt.ar` reads `.a`/`.lib` static archives as a container, not a reader

**Accepted.**

A `.a`/`.lib` static archive — the `ar` container format bundling several `.o`/`.obj`
relocatable objects for downstream linking — matched no route into `is_binary_member`
at all: not suffix, vendor path, sniff directory or executable bit. A wheel vendoring a
static crypto library was invisible to the scanner, with nothing in the record to say
so.

Every existing reader answers to "one stream in, one `BinaryEvidence` out"; an archive
holds several separate, independently-linkable objects a consumer wants told apart, so
`binfmt.ar.read_ar_members` is not one more entry in the reader table. It is called
directly by `layers.binaries.scan_binaries`, once a `.a`/`.lib`-suffixed member's own
magic confirms it is really `ar`-format, and dispatches each real member it finds to
the same per-format readers everything else in the wheel goes through.

The container format itself — magic, 60-byte member headers, the GNU long-name table,
odd-size padding — was verified against real archives from this host's own `ar`, not
only the documented spec, before being written. A member table that cannot be walked
to completion keeps whatever real members were already found; only when none were
found at all does the whole archive fall back to one strings-only record, the same
shape a format with no registered reader already gets. A member is never dropped for
having an unresolvable name — it is still read under a synthetic path, with its own
error naming why. Archive-derived evidence is marked `from_archive` and excluded from
`linkage.member_stem_counts`, so a bundled object's `SONAME` can never confirm a
sibling extension's `DT_NEEDED` entry as system-resolved.

**What this did not close, at the time.** `binfmt.elf`'s symbol matching read `.dynsym`
only, never `.symtab` — the table a relocatable `.o` normally carries. Filed as
[#117](https://github.com/EmilienM/wheel-crypto-scan/issues/117), and closed since:
`binfmt.elf` now also matches `.symtab` whenever `.dynsym` is genuinely absent, and
`binfmt.ar` needed no change of its own to inherit it.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#binfmtar-reads-alib-static-archives-as-a-container-not-a-reader) ·
[#99](https://github.com/EmilienM/wheel-crypto-scan/issues/99)

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
with no timestamp, host path or hostname. The theme toggle reads and writes
`localStorage` at view time only, so it never touches the file's bytes.

No verdict class gets a favourable colour. The two classes that mean "nothing was
decided" share one neutral token; every other class is a warning or a danger token, and
a wheel not flagged for review reads "not flagged", never a plain "no" or a checkmark.
The class and linkage help text shown in the page lives in `report.py` as plain
constants, next to a test that fails when a class in the ruleset's precedence has no
entry.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#the-html-report-embeds-records-and-renders-them-in-the-browser)
