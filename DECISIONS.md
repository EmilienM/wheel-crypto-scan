# Decisions

Design calls that were deliberate, are not obvious from the code, and would otherwise be
re-litigated every time someone new reads it. `CLAUDE.md` carries the invariants; this
file carries the reasoning behind the ones that cost something.

## The Python parser follows the interpreter running the scan

**Accepted. Documented, not fixed.**

`ast.parse` follows the grammar of the interpreter running it, so a wheel using syntax
newer than the scanner's interpreter does not parse, and the same wheel can produce
different records on different Python versions. PEP 695 is the concrete case:
`type Digest = bytes` is a syntax error on 3.11 and valid from 3.12, so a wheel whose
only crypto evidence sits behind that syntax comes out `NO_CRYPTO_DETECTED` on 3.11 and
`FIPS_BREAKING` on 3.12 and later.

This is a real dent in the determinism the tool otherwise promises, and it is the one
place where "same wheel in, byte-identical JSONL out" is conditional on the host.

**Why it is tolerable.** The failure is never silently favourable. A file that does not
parse is counted in `artifacts.py_files_unparsed`; a wheel whose every source file failed
reports `source_available: false` and comes out `OPAQUE`. An older interpreter yields
*less* evidence, never a wheel that wrongly looks clean, which keeps the
"unreadable means `OPAQUE`, never `NO_CRYPTO_DETECTED`" invariant intact.

**Why the obvious fix does not work.** `ast.parse(..., feature_version=...)` gates only a
subset of the grammar and does not cover PEP 695. It was tried and removed: it cost
findings on newer interpreters without delivering the determinism it promised.

**What was rejected, and why.**

- *Vendor or depend on a version-independent parser.* It would close the gap properly,
  but the dependency list is two packages on purpose, and a third needs to buy more than
  this.
- *Record the parsing interpreter's version in the record.* Cheap, and it makes the
  difference visible rather than silent. Rejected because `tool` would then carry
  host-derived data, which the schema has avoided on purpose: a record that embeds the
  host it was produced on is no longer byte-comparable between producers, which trades a
  narrow non-determinism for a total one.

**How it is handled instead.** `README.md` and `SCHEMA.md` both say to pin the
interpreter when records must be comparable across hosts. CI runs 3.11 through 3.14, so
a divergence that grows beyond the Python layer shows up as a test failure.

Revisit if a version-independent parser lands in the standard library, or if a wheel in
the real corpus is found whose headline verdict flips on interpreter version alone.

Tracked in [#4](https://github.com/EmilienM/wheel-crypto-scan/issues/4).

## A universal binary is one record, and its slices are merged

**Accepted, knowing what it costs.**

A fat Mach-O is read slice by slice and reduced to a single `BinaryEvidence`. `needed`,
`rpath` and `matched_symbols` become sorted unions, `symtab_count` a sum, `stripped` true
only when every slice is. `machine`, `bits` and `endian` describe the first slice that
parsed, because they describe one architecture and cannot describe several.

**Why one record.** The thing being described is the member of the wheel. `path` is what
`conventions.own_base` and the vendored-path matching key on, so a record per slice would
carry the same `path` two or four times and every consumer counting binaries would
double-count. No field of the schema is per-architecture today, and adding a `slices`
array would be a schema change buying resolution nothing currently consumes.

**What it buys.** Before, only the first parseable slice was read, so every fat object
was `partial_analysis: true` for ever. Most macOS wheels are universal2, so a crypto-free
universal2 wheel came out `OPAQUE` rather than `NO_CRYPTO_DETECTED`, and the README's
`select(.verdict.class == "OPAQUE")` triage recipe listed all of them.

**What it costs.** A union hides an intra-object disagreement, but not the way this was
first written up, and not for every disagreement shape. A universal2 dylib whose x86_64
slice links the host OpenSSL and whose arm64 slice has it compiled in merges to
`needed: [libcrypto...]` plus both an `imported` and a `defined` `EVP_DigestInit_ex`.
**`linkage._binary_posture` tested `needed` first and returned as soon as it found a
system match, so the object resolved to `system` -- exactly what reading the slices
separately and letting `_aggregate` combine them would have called `mixed` instead. That
was the bug tracked in #60, now fixed for this shape: `_binary_posture` checks the
`needed` and defined/banner evidence together and returns `mixed` itself when both are
true.** The fix is narrower than "every disagreement reads the same merged or separate":
`_binary_posture` still returns `LINKAGE_BUNDLED` from inside the `needed` loop before the
new check runs, so a slice disagreement between `bundled` and `system`, or `bundled` and
`static`, still merges to `bundled` where reading the slices apart would give `mixed` --
verified directly, both on ELF-shaped mangled/absolute `needed` pairs and on the Mach-O
equivalent. The safe direction holds regardless (`bundled` is at least as conservative a
read as `mixed` for every rule that keys on it), so this is not a new hole, but it means
only the system-vs-static disagreement this issue asked about is actually fixed; which
architecture said which is gone either way, so a `mixed` record from a universal2 dylib
still cannot say "x86_64 links system, arm64 is static." Previously the record was
equally wrong about the posture but carried `partial_analysis: true`, which fired
`BIN_PARTIAL_FORMAT` and forced `needs_human_review`; #60 restores `needs_human_review`
for the system-vs-static shape by a different route -- `mixed` itself carries it, through
`BIN_OPENSSL_LINKAGE_UNKNOWN` -- so the net loss this paragraph originally described
turned out to be temporary for that one shape.

The trade of merging slices into one record at all is still right, independent of the
above: the losing case needs two independently built thin dylibs `lipo`-ed together,
which `delocate` does not produce, while the winning case (no fat-slice disagreement) is
most of the macOS wheels in the index. It is recorded here because nothing in the output
says a record was merged, so a reader of `matched_symbols` carrying one name as both
`imported` and `defined` should know why that is representable at all.

Revisit if a real wheel is found whose slices disagree between `bundled` and any other
posture -- `mixed` can represent that combination, the code just does not produce it from
inside the `needed` loop's early `bundled` return -- or whose architectures disagree in a
way `mixed` cannot represent at all, e.g. three or more slices that would benefit from
naming which architecture said what.

Tracked in [#10](https://github.com/EmilienM/wheel-crypto-scan/issues/10), the `mixed`
fix in [#60](https://github.com/EmilienM/wheel-crypto-scan/issues/60).

## A routine cause is recorded but does not make a wheel opaque

**Accepted, and it changes verdicts. Half of it was later taken back -- see "The export
half of this was wrong" below, which is the part to read first if you are deciding
whether a new cause belongs on this list.**

`partial_analysis` has a score of causes behind it, and `BIN_PARTIAL_FORMAT` used to fire
`OPAQUE` plus `needs_human_review` for every one of them equally. Two of them looked
like conventions a linker produces on purpose rather than anything that went wrong: an
import or an export bound by ordinal has no name to match.

`WS2_32` is normally bound by ordinal, so that is the ordinary shape of a Windows
extension that touches sockets. Measured on two wheels identical but for that:

```
all imports named   -> NO_CRYPTO_DETECTED
WS2_32 by ordinal   -> OPAQUE
```

One linker convention, and the wheel joined the README's `select(.verdict.class ==
"OPAQUE")` triage list. That is a real cost: the list is read by a human, and padding it
with wheels nobody needs to look at is how a triage list stops being read at all.

**What changed.** `[rule.match] kind = "partial_binary"` takes `reasons` and
`exclude_reasons`, so the ruleset decides which causes are worth a verdict rather than
the engine treating them alike. `BIN_PARTIAL_ROUTINE` claims the ordinal import with
no verdict and no human review; `BIN_PARTIAL_FORMAT` keeps `OPAQUE` for everything else. An object with both kinds of cause fires both rules, and each names only the causes
it speaks for, so the failure still wins.

**What it costs, and why `pe_delay_load` is not on the list.** A wheel whose only
incompleteness is an ordinal import now reads `NO_CRYPTO_DETECTED` where it read
`OPAQUE`. That is a real loss of conservatism: the function behind that ordinal genuinely
has no name, and if it were a crypto entry point we would not know.

What makes it tolerable is that the *dependency* name survives. An object importing
`libcrypto-3-x64.dll` by ordinal still carries that DLL in `needed`, so it still comes
out `CONDITIONAL` on the ordinary `needed` rule; what is lost is which function inside
it. A delay-load directory loses the dependency name itself, with nothing downstream to
recover it -- no string group matches a bare DLL name -- so a `.pyd` that delay-loads a
crypto DLL it does not ship would have read clean. It stays with the strict rule. The
two are not the same kind of gap, and only one of them has a backstop.
The record is unchanged either way -- `partial_analysis` is still true and
`partial_reasons` still names the cause -- so a consumer who disagrees can filter on the
record rather than the verdict.

**Why the strict rule excludes rather than includes.** A cause added later matches no
include list, so it would report nothing at all. Excluding means a new token is serious
until someone decides otherwise, which is the safe direction, and a test asserts every
token the strict rule excludes is claimed by name somewhere else.

Revisit if a crypto library is found being imported by ordinal in a real wheel.

Tracked in [#29](https://github.com/EmilienM/wheel-crypto-scan/issues/29).

### The export half of this was wrong

**Reversed. `pe_ordinal_export` is a failure to read, not a convention.**

The sentence above carries both causes at once -- "an import or an export bound by
ordinal has no name to match" -- and then justifies them with one argument: the
dependency name survives in `needed`, so a crypto dependency bound that way is still
caught. That argument is about imports. **An export names no dependency.** What an
ordinal export loses is a *definition*, and a definition is how a statically linked copy
is recognised, which is the posture this tool exists to catch and the one with no
`needed` entry behind it by definition. The export was on the list because it was
written into the same sentence, not because the sentence was ever true of it.

What that cost, measured on one `.pyd` exporting `PyInit__ext`, `EVP_DigestInit_ex` and
`SSL_new`, with no OpenSSL banner in it to fall back on:

```
honest                     -> static, BIN_STATIC_OPENSSL
NumberOfNames = 0          -> none,   BIN_PARTIAL_ROUTINE only, needs_human_review: false
NumberOfNames = 1 (of 3)   -> none,   BIN_PARTIAL_ROUTINE only, needs_human_review: false
```

One edited header field and a statically linked OpenSSL read clean. `NumberOfNames` is a
count the object keeps about itself and PE has no string table to check it against, the
way ELF and Mach-O now check theirs, so understating it is free. The name table simply
stops being walked, every address slot becomes one no name points at, and `unnamed`
fires -- so the cause *was* recorded. Only its classification made the record clean.

**What it costs to reverse, measured rather than assumed.** `unnamed` counts export
address slots the name table never points at, so an object exporting exactly what it
names has `unnamed == 0` and does not move. Two shapes do: a deliberate
`EXPORTS foo @1 NONAME`, and any name the reader could not resolve, which drops the slot
out of the named set. The population at risk is not only `.pyd` files -- every `.dll` a
wheel ships is read the same way, and ordinal-only exports are likelier in a
redistributable runtime than in an extension module.

Measured over 37 real `win_amd64` wheels from PyPI, 383 PE objects, chosen across
compiled extensions and the runtimes they vendor:

```
pe_ordinal_import       12
pe_export_incomplete     2
pe_ordinal_export        1
pe_import_incomplete     1
pe_no_import_directory   1

objects where pe_ordinal_export is the only cause:  0
net new OPAQUE wheels from this change:             0
```

The single object carrying it is `duckdb`'s `_duckdb.cp310-win_amd64.pyd`, and it is not
a NONAME export: export 724 of 3548 is a 1027-byte MSVC-mangled C++ name, three bytes
past the reader's own 1024-byte cap, so the name fails to resolve and the slot falls out
of the named set. That object already carried `pe_export_incomplete` and was already
`OPAQUE`, so it does not move either. The triage list does not grow by one wheel across
that corpus.

Revisit if a real Windows wheel is found whose only incompleteness is an ordinal export.

**Why the import stays.** Its argument survives its own scrutiny: `WS2_32` really is
bound by ordinal on every Windows extension that touches sockets, so the cost of
reversing it is every such wheel, and the DLL name really does survive in `needed`. The
residual there is narrower and is pinned by a test rather than assumed away: an ordinal
import from a DLL no soname matches loses the imported symbol that would have made the
object `unknown`.

Tracked in [#47](https://github.com/EmilienM/wheel-crypto-scan/issues/47), and it is
most of [#42](https://github.com/EmilienM/wheel-crypto-scan/issues/42). What is left
there is the shapes that leave nothing to notice: an export directory that zeroes
`NumberOfFunctions` as well, and one whose data directory entry is zeroed outright,
which this reader deliberately treats as a complete reading of an object that exports
nothing. Both still want the count check.

### A carve-out list is a claim, and claims get tested

**The general rule this produced, promoted out of the story that produced it.**

Two causes went onto a list that exempts them from a verdict because one sentence
covered both, and the sentence was true of one. Nothing failed; the list is policy and
policy has no wrong answers to fail against.

So the admission test for that list is behavioural, not editorial: **go and find a
crypto object that reads clean because the cause is on it.** If that object exists the
cause does not belong there, whatever the sentence says. For the ordinal export it took
one fixture and one edited header field. `AGENTS.md` carries this beside the invariant,
because the list is the invariant's only carve-out and the next candidate will arrive
with a sentence too.

## A symbol table is checked against the string table, not taken at its word

**Accepted. It reverses an earlier decision and it changes verdicts.**

`LC_SYMTAB` says where the symbol table is and how many entries it has, and `.dynsym`'s
`sh_size` says the same thing in ELF. Reading exactly that many is not the same as
reading every symbol the object carries, and the difference is a way to look clean:

```
honest: 2 crypto imports        -> OPAQUE
nsyms=0 over the same rows      -> NO_CRYPTO_DETECTED
nsyms=1 over 3, benign first    -> NO_CRYPTO_DETECTED
```

Both liars have `_EVP_DigestInit_ex` and `_SSL_new` physically present with a full string
table. Every structural check passed: the declared window was entirely there, no index
was unresolvable, and something in it resolved to a name.

**`nsyms == 0` was explicitly exempt,** on the reasoning that a table declaring nothing
has nothing to fail at. That was wrong in the same way counting a debug record was wrong:
it tells us exactly what an absent `LC_SYMTAB` tells us, and an absent one has always
been incomplete. The exemption is gone and a test that documented it now documents the
opposite.

**The count itself is cross-checked against the string table.** Nothing structural says
how many rows there really are -- what sits between the symbol table and the string table
is `LC_DYSYMTAB`'s business, and assuming they are adjacent is wrong for real LINKEDIT
layouts. But the string table is the one place every name must appear. A name in it that
matches a symbol group and that no entry we read named is a symbol the object carries and
did not declare.

**What it costs.** The string table is scanned by one regex in C, and only the runs it
lands in are decoded, so an honest table pays one pass and runs the rule matcher on
almost nothing. Splitting the table instead took peak memory from 1.0 MiB to 12.4 MiB on
a 1.6 MiB object, which this module is written around not doing; walking it run by run
in Python was worse on the axis that matters, putting a 2 MiB string table of two-byte
runs at 19 seconds across a universal binary's slices, and 31 seconds if the runs held
control bytes. Both are 1.2 seconds through the locator. Measured over the whole reader
on 497,040 honest symbols in a 26 MiB object: 2.7s to 3.1s, and peak RSS 12.4 MiB to
14.8 MiB, the extra being the crypto names read.

**Two limits, both deliberate.** The check asks whether a *crypto* name went unread, not
whether any name did, so padding and ordinary unreferenced strings do not make every
object partial.

And names are formed the way the table is laid out, from one NUL to the next. `n_strx`
may point at any byte, so a name that is the tail of a longer string is reachable and is
not formed here: `_not_EVP_DigestInit_ex` with a row pointing four bytes in resolves to
the real name and reads clean. Closing that means matching at every offset the locator
hits rather than at run starts, and the cost is not the scan, it is the false positives:
every Rust or C++ object with a crypto name mangled inside a symbol -- `_ZN..EVP_..E`,
or a SWIG `_wrap_EVP_DigestInit_ex` -- would read as an object hiding one, because the
mangled name the rows do declare is not itself claimed by any group. Left open
knowingly, and tracked in [#39](https://github.com/EmilienM/wheel-crypto-scan/issues/39).

Neither is the older blind spot: a crypto symbol whose name is not in the string table at
all, because it resolves through `LC_DYLD_EXPORTS_TRIE` or chained fixups, which this
reader does not parse and says so.

**Both readers make the check, from one place.** `.dynstr` is what `.dynsym` points into
for exactly the reason the string table is what `LC_SYMTAB` points into, and the same
object shape works on both: `sh_size` covering one entry of four hid two OpenSSL imports
and read `NO_CRYPTO_DETECTED`. `binfmt.symtab` holds the walk, because a security check
that exists twice is a security check that drifts. What the readers keep is what only
they know: Mach-O inverts Darwin's ABI underscore before matching and ELF must not, or an
honest `_EVP_DigestInit_ex` reads as a hidden `EVP_DigestInit_ex`. Cost on ELF matches
Mach-O: 497,040 dynamic symbols in a 29 MiB object go from 1.7s to 2.0s, memory
unchanged, and no object among 6,502 real ELF binaries on a Fedora host is flagged.

**The cross-check is only sound over a string table we read through,** which is the
sibling guard and was missing on the ELF side. Shrink `.dynstr` instead of `.dynsym` and
every row survives, every count survives, and the names simply stop being reachable: a
statically linked extension read `NO_CRYPTO_DETECTED` while carrying two OpenSSL
imports. Worse, the bytes left over were reported as symbols -- a `.dynstr` cut to 24
bytes put `EVP_DigestI` in `matched_symbols`, a name the object does not carry, in the
field the whole tool turns on. Both readers now treat an index past the end, or a run
the table never closes, as a name they could not resolve.

**Both name the cause the same way.** A count that understates its rows is the one
failure that is about neither format, so beside `elf_dynsym_unread` or
`macho_symtab_incomplete` it also emits `symtab_understates_rows`. Which wheels in an
index understated their symbol table is a supply-chain question rather than a build
quirk, and answering it should not mean substring-matching an error message that no
contract pins.

**Two tables are still believed.** ELF's `.symtab` drives `stripped` and
`symbol_counts.symtab` and nothing else -- the imported-versus-defined split comes from
`.dynsym` alone -- so a lie there costs a field that is recorded rather than a finding.
PE has no analogue to bring the check to: its imports have no declared count at all, and
its exports have one with no string table to check it against, because export names are
individually addressed rather than pooled. `NumberOfNames = 0` over a real name table is
nonetheless caught, but incidentally rather than by a check: understating the count
leaves every address slot with no name pointing at it, `unnamed` fires, and since
[#47](https://github.com/EmilienM/wheel-crypto-scan/issues/47) that cause carries
`OPAQUE`. Zero `NumberOfFunctions` as well and there is nothing left to notice, which is
what remains of [#42](https://github.com/EmilienM/wheel-crypto-scan/issues/42).

**Errors say which way it fell short.** A table that fell short records an error naming
the cause, instead of every case claiming the object "could not be read in full" when
every byte of it was read. Silence is reserved for a table that left nothing unexplained:
an absent `LC_SYMTAB`, or one declaring no entries over a string table holding no name it
failed to account for. Both are still incomplete, and neither is a clean bill.

`stripped` follows the same line, read off what the table yielded rather than off
`nsyms`. Exactly one of "fell short", "read in full" and "stripped" holds for any table,
which is why the three are derived in one place: a count of zero over rows holding crypto
names is a cause, and a cause must never be able to set a field documented as recorded
rather than a finding.

**What silence still costs, and it is not nothing.** `resolve_linkage` reads errors and
`is_opaque`, not `partial_analysis`, so a Mach-O that declares no entries comes out
`OPAQUE` with `openssl_linkage: none` -- one field saying we could not read it and
another saying there is no OpenSSL here. The verdict is right and the condition is not.
It is the same answer an absent `LC_SYMTAB` has always given, so this change neither
introduced it nor made it worse, and fixing it means teaching `linkage` which partial
causes cost it an answer, across all three readers rather than in this one. Tracked
in [#40](https://github.com/EmilienM/wheel-crypto-scan/issues/40).

Tracked in [#34](https://github.com/EmilienM/wheel-crypto-scan/issues/34).

## Linkage reads a second split over the same vocabulary

**Accepted. It changes the field most consumers filter on.**

`resolve_linkage` decided "we could not tell" from `is_opaque` and the binary-stage
errors, and never from `partial_analysis`. So an object a reader had explicitly marked
as not read in full, but that recorded no error, still contributed a definite posture.
The everyday case is a stripped macOS extension:

```
partial_reasons: ['macho_symtab_incomplete']
openssl_linkage: none
```

One field says the symbol table was not read; the next says there is no OpenSSL in the
object, which is a claim the first says we cannot make. `is_opaque` does not rescue it,
because `needed` is non-empty for every loadable dylib and every `.pyd`. The verdict was
already `OPAQUE` through `BIN_PARTIAL_FORMAT`, so what was wrong was the condition rather
than the headline -- and the condition is the field `verdict.conditions` exists to carry.

**Why it is not one boolean.** `partial_analysis` is true for linker conventions too.
Counting the tuple wholesale would turn every ordinal import into
`openssl_linkage: unknown`, which is exactly the noise [#29](https://github.com/EmilienM/wheel-crypto-scan/issues/29)
removed from the verdict, arriving again through a different field.

**So there are two lists over one vocabulary, and they differ on purpose.**
`[linkage_policy] exclude_reasons` in `ruleset.toml` names the causes that leave every
field linkage reads -- `needed`, `vendored_path`, the imported-versus-defined split,
`matched_strings` -- intact. A `partial_binary` rule with no verdict names the causes
not worth one. They are not the same question and their answers are not the same set:
`elf_go_buildinfo_unread` is worth a verdict and costs linkage nothing, because Go
toolchain provenance feeds no field `linkage` reads. A test asserts the two lists
differ, so if they ever coincide the mechanism is a rename and should be one.

It is named `linkage_policy` and not `linkage` because three things here are already
called linkage: the resolved posture per library, the matcher kind that reads those
postures, and this, which is about neither.

**One containment holds, and the loader refuses a ruleset that breaks it.** Every cause
a verdict-less rule claims must be exempt here too. A cause recorded without a verdict
has promised the wheel is not on its own worth a human's time; letting it cost the
linkage answer puts it straight back on the triage list through
`BIN_OPENSSL_LINKAGE_UNKNOWN`, which carries `OPAQUE`. Asserting that over the shipped
ruleset alone left every `--ruleset` user outside the guard, so it is a `RulesetError`
rather than a test.

**Absence of the table derives it, rather than emptying it.** An empty default is
conservative read on its own and self-contradicting read in composition: a custom
ruleset keeping `BIN_PARTIAL_ROUTINE` and omitting `[linkage_policy]` would report
`openssl_linkage: unknown` for an ordinary ordinal import, which is both the noise
removed when the split was drawn for verdicts and the contradiction the check above
refuses. Omitting the table now yields exactly the verdict-less causes; the explicit
table is the override that widens them.

**`pe_ordinal_export` was on this list and is not any more.** It was exempt because the
containment put it there: the ruleset recorded it without a verdict, so exempting it was
forced. That was the tail wagging the dog, and the fix was at the other end -- the cause
is a failure to read a definition, it now carries `OPAQUE`, and the exemption went with
it. "The export half of this was wrong", above, has the measurement.

**`elf_symtab_unread` was on this list too, and is not any more (#117).** Unlike
`pe_ordinal_export`, this one was never forced by the containment -- it was exempt on
its own claimed grounds, that `.symtab` drives only `stripped` and
`symbol_counts.symtab` while the imported-versus-defined split comes from `.dynsym`
alone. That stopped being true once `.symtab` became a relocatable object's *only*
symbol table for matching, when `.dynsym` is genuinely absent. The cause name cannot
say which of the two shapes -- an ordinary object where only `.symtab`'s count failed,
or a relocatable one where the split itself did -- produced it, so the same safe
default this vocabulary already takes for a cause it has never seen applies: it now
costs the linkage answer unconditionally, even for the ordinary case that was
genuinely safe before. `ruleset_version` moves for the same reason dropping any
exemption does.

The containment helped, in one direction only, and it is worth being exact about which.
The loader refuses `routine` that is not a subset of `exclude_reasons`, so dropping the
exemption forces the re-rating. It does not refuse the converse -- re-rating the verdict
while leaving the exemption in place loads clean, because a cause being worth a verdict
and costing linkage nothing is legitimate and is what `elf_go_buildinfo_unread` is. What
holds that side is the exact-set assertion in `tests/test_linkage.py`, which is a test
over the shipped ruleset and so does not reach a `--ruleset` user. That is the weaker
mechanism, and it is weaker on purpose: there is nothing here to enforce.

`pe_no_import_directory` is exempt on plainer grounds. It fires when the optional header
points at no import directory, or when the walk finished and named no DLL: both are an
absence the reader observed, not a read it fell short of. A walk that fell short carries
`pe_import_incomplete`, which is not exempt, and the two are separate non-`elif`
conditions so the exemption cannot swallow a failed read.

**Two fields used to be outside all of this,** and both still are: `strings_bytes_unread`
now carries the *reading gap* into `partial_reasons`, but `strings_truncated` and
`symbols_truncated` themselves stay fields, because a recording cap is not a partial
read. "A recording cap is not a partial read", below, says why, and says what the caps
cost instead.

**A partial read that names no cause costs the answer too.** `partial_analysis` true
with an empty `partial_reasons` is the shape `engine` singles out as the most serious
there is -- no reader produces it, so the evidence was built by hand. Reading the empty
tuple as "nothing excluded, so nothing was lost" made `linkage` the one consumer of that
field that quietly downgraded it.

**What it costs.** Every stripped macOS wheel moves from `openssl_linkage: none` to
`unknown` and picks up a `BIN_OPENSSL_LINKAGE_UNKNOWN` finding. That is a lot of wheels,
and the honest reading is that we never could answer for them. Their verdict class does
not move: `BIN_PARTIAL_FORMAT` already had them at `OPAQUE`. What moves is that
`select(.verdict.conditions.openssl_linkage == "none")` stops quietly including wheels
whose symbol tables nobody read -- a filter the README does not itself suggest today,
and a stronger `none` is what would make it worth suggesting.

**Only the libraries reported unconditionally are affected,** which is `openssl` alone
today. The signal reaches `_aggregate` already gated on `always_report`, so an object
that did not answer does not list every crypto library in the ruleset as `unknown`. A
false `none` does its damage in the field consumers filter on, and that field is the one
that is always present.

**Whose answer loses.** Only the wheel's. `_aggregate` consults this signal exclusively
when nothing in the wheel answered definitely, so one unreadable object still cannot
erase what the readable ones said.

Tracked in [#40](https://github.com/EmilienM/wheel-crypto-scan/issues/40).

### The `always_report` gate had a second, unguarded route around it

**Corrected. "Only the libraries reported unconditionally are affected" was true of the
`unanswered` path this entry describes, and false of a second path the code still had.**

`_binary_posture`'s own fallthrough, reached when nothing about an object said `system`,
`bundled`, `static` or `unknown`-via-imported-symbol, read:

```python
if binary.is_opaque:
    return LINKAGE_UNKNOWN
return LINKAGE_NONE
```

That `is_opaque` arm runs once per `(binary, library)` pair inside `resolve_linkage`'s
loop over every library in the ruleset, and it answers `LINKAGE_UNKNOWN` straight into
that one library's `postures` set -- not through `_aggregate`'s `unanswered` parameter,
which is where the `always_report` gate above actually lives. An opaque object therefore
made every one of the thirteen libraries in the shipped ruleset read `unknown`, not only
`openssl`:

```
pkg/_ext.so   stripped, no needed, no symbols, no strings -- is_opaque
-> before: 13 "*_linkage: unknown" keys, one per [[crypto_library]] entry
-> after:  1 "openssl_linkage: unknown" key (the only always_report = true library)
```

**Why this held for so long without a failing test.** `_left_unanswered` already checks
`binary.is_opaque` and returns `True` for exactly this object, which `resolve_linkage`
already passes into `_aggregate` as `unanswered and library.always_report` -- correctly
gated, library by library. The `is_opaque` arm inside `_binary_posture` was answering the
same question a second time, through a route that bypassed the gate entirely, and every
existing test asked only about `openssl`, the one library the two routes happen to agree
on. Mutation testing (deleting the arm) confirmed it: nothing in the suite moved.

**The fix.** Delete the arm. `unanswered` already carries the signal for `always_report`
libraries, which is the documented intent above; `_binary_posture` falls through to
`LINKAGE_NONE` for every other library, exactly as an object that answered nothing at all
should for a library nothing pointed at.
`test_an_opaque_binary_only_costs_the_libraries_always_reported` (`tests/test_linkage.py`)
pins the whole-ruleset shape this entry always meant, mirroring
`test_an_unanswered_object_costs_only_the_libraries_always_reported`'s existing coverage
of the *partial*-read case for the *opaque* one.

Tracked in [#68](https://github.com/EmilienM/wheel-crypto-scan/issues/68).

## A recording cap is not a partial read

**Accepted. One of the two halves of `truncated` became a cause; the other stayed a
field.**

`strings_truncated` was set by three different things at once, and `partial_analysis`
by none of them. So an object whose strings pass never reached the end of it still
contributed a definite posture, and the record said both at once:

```
strings_truncated: true
partial_analysis:  false   partial_reasons: []
openssl_linkage:   none    NO_CRYPTO_DETECTED   needs_human_review: false
```

Measured on one `.pyd` carrying an OpenSSL version banner in its last 26 bytes: scanned
whole it is `static` and `CONDITIONAL`; with the byte budget stopping short of the
banner, the same object is clean. The banner is not a nice-to-have. `cryptography` 42
and later compiles OpenSSL in, with no library file, no dependency and no exported
symbol, so the banner is the *entire* evidence, and `MAX_STRINGS_BYTES` is 64 MiB
against wheels that ship objects many times that.

**Only the reading gap got a token, and the reason is definitional rather than a
judgement about worth.** `partial_analysis` means part of the object was not read. A
*recording* cap -- more group matches than `max_strings_per_binary`, more crates than
`max_rust_crates_per_binary`, more symbols than `max_symbols_per_binary` -- is not that:
the object was read, and what was capped is what got written down. It is not a member of
the class `PARTIAL_REASONS` enumerates, so the vocabulary is not being asked to hold a
policy. `symbols_truncated` is a recording cap in that sense and gets the same answer.

The alternative was rejected on a harder ground than taste. Minting a cap token as a
fact and then exempting it in the ruleset needs a verdict-less `partial_binary` rule,
which the load-time floor then forces into `[linkage_policy] exclude_reasons` -- a
*second* carve-out on the "unreadable means `OPAQUE`" invariant, which `AGENTS.md` says
is a change to the invariant itself. One carve-out is what that document permits.

**What the caps do instead is worse, and it is not fixed here.** Writing this entry's
first draft claimed a recording cap "cannot produce a record that reads clean, because
it only fires once that many matches are in hand". That is false, and the counterexample
is four lines:

```
ring alone                 -> NON_APPROVED_CRYPTO  needs_human_review: true
ring + 130 earlier crates  -> NO_CRYPTO_DETECTED   needs_human_review: false
                              strings_truncated: true, partial_analysis: false
```

`find_rust_crates` sorts by `(name, version)` and cuts at 128, so a Rust wheel carrying
three hundred crates drops everything past the 128th name, and every crypto crate the
ruleset names -- `openssl`, `ring`, `rustls`, `sha1`, `sha2`, `pbkdf2` -- is in the o-to-s
range where `anyhow`-class names crowd it out. The string and symbol caps do the same one
step down: `StringMatch.sort_key` is `(group, value)` and `openssl_banner` is tenth of
thirteen group names, so seventy `mbedtls_` runs take the banner with them.

That is the same failure this entry is about, arriving through a cap rather than a
budget, and it did not want a `partial_reasons` token -- it wanted the caps to stop
dropping evidence a rule could match. Fixed in "A cap bounds the record, it does not
pick the evidence", below.

**What it costs, and the threshold is not the same in every format.** For Mach-O, PE and
the fallback the budget is measured against the object, so an object over 64 MiB is now
`OPAQUE`. For ELF it is measured against the concatenation of eligible read-only
sections, not the file, so a gigabyte `.so` that is mostly `.text` is untouched while a
smaller one carrying a large `.nv_fatbin` is not. That distinction matters here rather
than being a footnote: CUDA and PyTorch wheels, which is where the size is, ship
overwhelmingly as manylinux ELF.

Either way the honest statement is that these were never objects we had read. The
threshold is one constant and the verdict one line of `ruleset.toml`, so the lever is
short if the triage list becomes unreadable -- but the safe default for a new cause is
the strict rule, which is what the ruleset already says and what this takes.

Revisit if a real wheel is found on the triage list for this and nothing else.

**What it does not cover.** An object inside the budget whose evidence sits in a region
no reader hands to the strings pass at all -- `binfmt.elf` passes the read-only sections
rather than the file -- is a different question and not this one.

Tracked in [#48](https://github.com/EmilienM/wheel-crypto-scan/issues/48).

## A cap bounds the record, it does not pick the evidence

**Accepted, and it changes records.**

Three per-binary limits exist so one object cannot produce an unbounded JSON line:
`max_strings_per_binary`, `max_symbols_per_binary`, `max_rust_crates_per_binary`. None
of them exists to decide which evidence survives, and all three did, because each sorted
its matches and cut at the limit. The sort key has nothing to do with what a match is
worth, and the crypto names this ruleset claims sit in the middle of every one of those
orderings.

```
ring alone                 -> NON_APPROVED_CRYPTO  needs_human_review: true, findings: 1
ring + 130 earlier crates  -> NO_CRYPTO_DETECTED   needs_human_review: false, findings: 0

banner alone                 -> openssl_linkage: static
banner + 70 mbedtls_ runs    -> openssl_linkage: none

defined EVP_DigestInit_ex alone -> openssl_linkage: static
+ 70 defined crypto_box_*       -> openssl_linkage: none
```

The first is the one that matters: `partial_analysis` false, no findings, nothing in the
record saying anything was dropped except a `truncated.strings` flag whose meaning is
"we found more than we keep". A Rust wheel with three hundred crates is ordinary, and
every crypto crate named -- `openssl`, `ring`, `rustls`, `sha1`, `sha2`, `pbkdf2` -- is
in the o-to-s range where a hundred and twenty-eight `anyhow`-class names get in first.
The other two are the shape of a static mbedTLS beside a static OpenSSL, and of PyNaCl's
extension, which exports hundreds of `crypto_*` names.

**The fix is to notice how little the rules key on.** `binary_string` and `linkage` read
a string's `group`. `dynamic_symbol` and `linkage` read a symbol's `group` and its
`binding`. `rust_crate` reads a crate's `name`. So a cap that keeps one representative of
every key before filling the remainder answers every question the record is read for, and
costs at most one entry per key: thirteen strings, twenty symbols -- ten groups times
two bindings -- and one version of each named crate. `binfmt.caps` holds the walk and
each type says what makes it interchangeable through a `cap_key`, so the fact is stated
once beside the class it is a fact about rather than three times in three readers.

The crate list is the one that needs more than a key. A string or a symbol only reaches
a cap because a group matched it, so every entry is evidence; a crate list is also an
inventory, most of it named by nothing, so the helper takes a `pin` and an unclaimed
crate cannot take the room a claimed one needs. The first attempt gave crates their own
cap instead, and the second implementation had already drifted before review: it kept
every *version* of a claimed crate, so a hundred and thirty-three `openssl` versions
evicted `ring` -- the same bug one path down.

**The binding is part of the symbol key, not decoration.** Keying on the group alone
keeps whichever `EVP_*` sorts first, and if that one is imported then a defined one gets
dropped -- which is `unknown` where the object is `static`, a quieter version of the same
bug. A test pins it.

**What it does not promise.** A second banner from a group already represented still
goes, and so does a particular version of a crate already named. What cannot go is the
last evidence of a group nothing else speaks for. The caps stay, because bounding the
record is a real requirement and this does not weaken it: the limit is still the limit.

The guarantee has one condition, and it is now refused at load time rather than
documented: there has to be room for one of every key. `parse_ruleset` rejects a
`max_strings_per_binary` below the string group count, a `max_symbols_per_binary` below
twice the symbol group count, or a `max_rust_crates_per_binary` below the number of
crates named. Below any of those the choice among keys is the alphabet again, and
`SCHEMA.md` states the guarantee without conditions.

**What it costs.** Records change for any object that was over a limit, which is why
`ANALYZER_VERSION` moves. Nothing grows: the cap is honoured exactly, and `truncated`
still says a sample was taken.

**How it was found.** Not by a test. A sentence in the entry above asserted that a cap
"cannot produce a record that reads clean", and review went and built the object that
does. The admission test `AGENTS.md` names for the carve-out list works on a claim as
well as on a list.

Revisit if a ruleset ever wants limits below its own key counts, which the loader now
refuses: the question then is whether to drop the guarantee or raise the limit.

Tracked in [#51](https://github.com/EmilienM/wheel-crypto-scan/issues/51).

## A forwarder resolves the dependency it forwards to, not just its own name

**Accepted, and it changes what a forwarding wrapper can hide.**

`_read_exports` told a forwarder from a definition correctly -- its "address" lands
back inside the export directory, where it is a string rather than code -- but then
recorded only the export's *own* name as imported, and never read that string. A `.pyd`
exporting `my_digest_init` as a forwarder to `libcrypto-3-x64.EVP_DigestInit_ex` put
neither the DLL nor the real symbol anywhere in the record:

```
before  -> needed: [],  matched_symbols: [], NO_CRYPTO_DETECTED, needs_human_review: false
after   -> needed: ['libcrypto-3-x64.dll'], matched_symbols: [EVP_DigestInit_ex/imported],
           CONDITIONAL (openssl_linkage: system), needs_human_review: true
```

Only a wrapper whose *own* export name happened to match the ruleset was ever caught,
which is coincidence standing in for evidence -- the exact shape the "unreadable means
`OPAQUE`, never `NO_CRYPTO_DETECTED`" invariant exists to rule out, except here nothing
was even unreadable. The bytes were sitting in the object; this reader just never asked
for them.

**What changed.** The forwarder string itself, `OTHERDLL.Symbol` or `OTHERDLL.#Ordinal`,
is now read through the same `image.cstring` every other name in this file goes
through, split on its *first* dot -- the DLL half never carries the file extension, the
same convention `NTDLL.RtlAllocateHeap` uses, so `.dll` is appended to match what
`needed` already holds for every other dependency. The resolved DLL joins `needed`
beside `imports.dlls`; the resolved symbol, when the string names one rather than an
ordinal, joins `matched_symbols` as `imported` beside the wrapper's own name.

**First dot, not last, and this one was revised after the first pass shipped.** The
first pass split on the *last* dot on the theory that nothing in the format forbids a
dot in a DLL name. It missed a real shape: MSVC hot/cold splitting produces symbol
names like `EVP_DigestInit_ex.cold` or `Func.part.0`, so a forwarder to
`libcrypto-3-x64.EVP_DigestInit_ex.cold` last-dot-split into DLL =
`libcrypto-3-x64.EVP_DigestInit_ex` (garbage, matches nothing in the ruleset) and
symbol = `cold` (also matches nothing), which reads the wheel clean -- exactly the
failure this whole change exists to close. A literal dot in a DLL name is not something
the format forbids either, but it is not a shape a real Windows DLL name uses in
practice -- the `.dll` extension is implicit in the forwarder string, never spelled out
-- while a dot in the symbol half is a documented compiler behaviour. First-dot is the
bet that loses less evidence, not a reading the format makes certain: every forwarder
string this reader has had to resolve before now carried exactly one dot, so single-dot
fixtures read identically under either split and this only changes the multi-dot case.

**Why the DLL, not just the symbol.** The alternative on the table was to record only
the target symbol and leave `needed` alone, which is weaker on the field that matters
most: `linkage._binary_posture` reads `needed` first, and `BIN_NEEDED_SYSTEM_OPENSSL` /
`BIN_NEEDED_MANGLED_CRYPTO` key on it, not on `matched_symbols`. The Windows loader
resolves a forwarder exactly like an import at load time -- it opens the target DLL
before it can fail to find the symbol in it -- so the dependency is real in exactly the
sense `needed` already means, and recording only half of it would leave
`openssl_linkage` blind to a wheel that forwards its whole extension to system OpenSSL.

**An ordinal-named forwarder reuses `pe_ordinal_import`, not a new token.** A forwarder
to `SOMEDLL.#123` loses the function name the same way an ordinal-bound import does, for
the same reason: the loader opens the DLL regardless, so the dependency survives in
`needed` and only the symbol is unrecoverable. That is the exact shape
`BIN_PARTIAL_ROUTINE` already carves out with no verdict, so this reuses it rather than
adding a second cause with the same justification -- the "go and find a crypto object
that reads clean because the cause is on the list" test in `AGENTS.md` finds nothing
here that the existing entry did not already cover: the dependency name still survives.

**A forwarder string this reader cannot terminate is `pe_export_incomplete`, not a
silent gap.** Past `_MAX_NAME_BYTES` or the object's name budget, `cstring` returns
`None` the same as it does for any other name, and the object is marked incomplete
rather than reported as forwarding to nothing. One existing fixture,
`test_a_forwarder_at_the_export_directory_s_first_byte_is_still_a_forwarder`, places its
forwarder "address" at the export directory's own header bytes to test the boundary
classification in isolation; there is no real string there to resolve, so that object
now correctly picks up `pe_export_incomplete` too -- a fixture artifact surfacing the
same honesty the rest of this reader already has, not a new failure mode.

**What was rejected.** Recording only the target symbol and leaving `needed` untouched,
covered above. Inventing a new `partial_reasons` token for the ordinal-forwarder case,
which would have duplicated `pe_ordinal_import` for no reason the ruleset could tell
apart from the original. For the split direction itself: recording both candidate
splits -- union the symbol-group matches from both halves, union both candidate DLL
names into `needed` -- was on the table too, and was rejected as overkill for a case
that is, by the corpus this reader was measured against, vanishingly rare (a forwarder
string with more than one dot at all), against a real cost: doubling `needed` and
`matched_symbols` cardinality for every multi-dot forwarder, cutting against the same
record-size discipline `binfmt.caps` exists to hold. First-dot-as-primary is the
cheaper bet and, per the measurement above, the one less likely to be wrong.

**What it costs.** `ANALYZER_VERSION` moves, because a wheel already scanned under the
old reader can now produce a different record without changing on disk. Every wrapper
that forwards to a DLL or symbol the ruleset recognises moves off `NO_CRYPTO_DETECTED`.
That claim needs a correction from the first pass: nothing on `main`, before this whole
change, could "move the other way," because the forwarder string was never read at all
there -- there was no resolution to fail. This change is what introduces the
possibility of a forwarder failing to resolve (`pe_export_incomplete`) where it
previously read, silently and wrongly, as `NO_CRYPTO_DETECTED`. And the split-direction
choice itself has a real, if judged unlikely, failure mode: a forwarder string whose
DLL half genuinely embeds a literal dot now splits wrong, the same way the last-dot
choice split the `.cold` case wrong. `libcrypto.3.dll` as a DLL name is not actually an
example of this -- first-dot still yields `libcrypto`, `normalise_soname`'s suffix
stripping was never the thing at risk, and the object still resolves `system`. The real
shape is a dotted name whose first segment is not one the ruleset recognises on its
own, the way .NET's native shims are named: a forwarder to
`System.Security.Cryptography.Native.OpenSsl.CryptoNative_EvpDigestUpdate` first-dot
splits to DLL `System` and loses the rest, where last-dot would have recovered the
symbol. Nothing in the PE format rules either shape out, so this is a bet, not a
guarantee, and it is made in the direction the evidence above says loses less: MSVC
hot/cold splitting is default-on compiler behaviour for any MSVC-built wrapper, while a
CPython extension forwarding into a dotted native-shim family is a narrower shape.

Revisit if a real wheel forwards to a DLL name that legitimately carries a dot of its
own -- inside or outside the file extension -- which first-dot splitting would then
misread the way last-dot splitting misread `.cold`; or if `needed`'s forwarder-derived
entries need their own bound, since `exports.forwarded_dlls` is capped only by the
export directory's own `_MAX_EXPORT_NAMES`/`_MAX_NAME_TOTAL_BYTES` budget, not by
`_MAX_IMPORT_DESCRIPTORS` the way `imports.dlls` is -- large but not unbounded, and
a record-size question rather than a resource-exhaustion one, so left open rather than
given a cap purpose-built for this one source.

Tracked in [#54](https://github.com/EmilienM/wheel-crypto-scan/issues/54).

## A cap bounds the record, not the evaluation

**Accepted, and it changes verdicts.**

`max_binaries_per_record` exists for the same reason the three per-binary limits in "A
cap bounds the record, it does not pick the evidence" do: one wheel must not produce an
unbounded JSON line. It was applied in the one place that also decides what a rule can
see. `_collect` sliced the binaries list to the cap before building the `Evidence` that
`resolve_linkage`, `apply_rules` and `classify` all run over, so every object past the
256th was fully decompressed and read -- the cost was paid in full -- and then thrown
away before anything downstream ever looked at it.

```
256 filler .so + one static-OpenSSL .so, sorting 257th (last)  -> NO_CRYPTO_DETECTED
same wheel, crypto object moved to sort 256th (last kept)      -> CONDITIONAL, BIN_STATIC_OPENSSL
```

Same object, same wheel, different verdict, purely because of where its filename sorts
relative to a limit that exists to bound JSON size and was never meant to decide which
evidence a rule gets to see. `artifacts.binaries_truncated` was already set correctly
in this case; nothing in the ruleset or `engine._MATCHERS` read it, so it changed
nothing about the verdict. This is the same class of bug as the one `#51` fixed for
`max_strings_per_binary`, `max_symbols_per_binary` and `max_rust_crates_per_binary`,
one layer up: there the cap picked which *matches inside an object* a rule could see;
here it picked which *objects* existed at all as far as the rules were concerned.

**The fix.** `_collect` now hands `Evidence` the full, untruncated tuple of binaries
`scan_binaries` read. `resolve_linkage`, `apply_rules` and `classify` see all of it, so
the verdict no longer depends on sort order relative to a display limit. The cap moved
to the one place it always should have applied: `build_record`, which now takes
`max_binaries` and slices `evidence.binaries` there, after findings and the verdict are
already computed, so only the *serialised* `binaries[]` array is bounded. `build_inventory`
was untouched -- it was already being called with the full list and already computes
`binaries_truncated` correctly; only `Evidence` was getting the truncated view.

**What it costs.** A finding's `locations[].path` can now legitimately name an object
that is not present in the record's `binaries[]` array: the object was evaluated, a
rule matched something in it, and the cap left it out of the display list anyway.
`SCHEMA.md` says so under both `artifacts.binaries_truncated` and `findings[].locations[]`
rather than leaving it to be discovered. This was already possible in principle before
this fix wherever `binaries[]` disagreed with what `errors[]` or `artifacts.extensions`
named, so it is a wider instance of an existing shape, not a new one.

`ANALYZER_VERSION` moves: any already-scanned wheel with more than
`max_binaries_per_record` native objects can produce a different verdict now, and the
cache has no other way to know that.

**Whether `binaries_truncated` should also be a finding.** Fixing evaluation removes
the correctness bug -- a wheel is never again read clean because of where a filename
sorts -- but a human reading one JSON line still cannot tell "156 objects, all listed"
from "156 listed out of 400" without cross-referencing `artifacts.binaries_truncated`
against nothing else in the record. That gap is real, if smaller than the one this
entry mainly fixes, and it is what `WHEEL_BINARIES_TRUNCATED` closes: a
`kind = "binaries_truncated"` rule, informational (`severity = "info"`, no verdict,
`needs_human_review = false`), that fires whenever the flag is set and names how many
objects were actually evaluated. It follows the same shape as `WHEEL_RECORD_UNREADABLE`
and the rest of the informational `scan_error` rules: a fact that is not on its own a
reason to look, recorded so it is not only discoverable by a consumer who already knew
to look for `artifacts.binaries_truncated` specifically. It was implemented rather than
left as a follow-up because the marginal cost was one small matcher function and one
rule entry, once the evaluation-side fix already made `evidence.binaries` the correct,
full count to report at the point the rule runs.

**What was rejected.** Giving `WHEEL_BINARIES_TRUNCATED` a verdict, or
`needs_human_review = true`. Both were considered and dropped: once evaluation sees
everything, the verdict already reflects the whole wheel, and treating an ordinary
side effect of a display cap as something a human must act on would put every large
Rust or CUDA wheel back on a triage list for a reason that has nothing to do with
crypto. That mirrors why `BIN_PARTIAL_ROUTINE` carries no verdict for an ordinal
import: the evidence gap it names is real but does not, on its own, ask for a person.

Revisit if a consumer needs to reconstruct the *full* per-object list rather than just
knowing it is incomplete -- that is a different feature (streaming or paginating
`binaries[]`, or a `--max-binaries-per-record` raised at scan time) and not something
this fix or `WHEEL_BINARIES_TRUNCATED` attempts.

Tracked in [#55](https://github.com/EmilienM/wheel-crypto-scan/issues/55).

## `binaries[]` keeps what a finding points at, before filling the rest

**Accepted, and it changes records. Revised after adversarial review of the first
version of this fix found two things worth fixing in the fix itself -- see "What
adversarial review changed here" below, which is the part to read first if you are
deciding whether the fallback this entry describes still needs work.**

`#55`, directly above, made evaluation complete: every object in a wheel is read,
linked and matched against every rule regardless of `max_binaries_per_record`, so the
verdict no longer depends on where an object's filename happens to sort. What it left
alone was the *display* half -- `build_record`'s own `max_binaries` slice, which still
cut `evidence.binaries` (and, identically, `artifacts.extensions`) to a plain
path-sorted prefix. That is the same mistake `#51` ("A cap bounds the record, it does
not pick the evidence") fixed for the per-binary string, symbol and crate caps, one
layer up: a sort key with nothing to do with what a match is worth decided what
survived. There the unit was a match inside an object; here it is the object itself,
and crypto-relevant objects have no more reason to sort early than `ring` did among a
hundred `anyhow`-class crate names.

Adversarial review of `#55` built the shape directly: 300 filler `.so` objects plus
`pkg/zz1_broken.so` (a partial ELF carrying an OpenSSL banner) and
`pkg/zz2_opaque.so` (unparseable), both sorting after every filler.

```
verdict: CONDITIONAL, needs_human_review: true
rule_ids: [BIN_OPAQUE, BIN_PARTIAL_FORMAT, BIN_STATIC_OPENSSL, BIN_UNPARSEABLE]
binaries[]: the first 256 filler objects, neither zz1 nor zz2 present
```

Every finding correctly names one of the two objects that earned the verdict, and
neither object is anywhere in the array a human would read to corroborate it. The
verdict is right; nothing in the record backs it up. This is a completeness gap, not
the correctness gap `#55` closed -- the "unreadable means `OPAQUE`, never
`NO_CRYPTO_DETECTED`" invariant was never at risk here, since evaluation already saw
everything.

**The fix.** `record.py`'s `_cap_by_findings` fills `binaries[]` and
`artifacts.extensions` alike, both keyed by object path, in three passes, in the order
a reader would miss it most:

  1. One representative object per `(rule_id, subject)` a finding names, the groups
     themselves visited in a fixed, deterministic order.
  2. Every other object a finding references, in path order.
  3. Everything else, in path order -- the same rule the plain prefix already used
     for everything, when there was nothing to prefer.

`extensions` reuses the same function rather than a parallel copy of it, so the two
arrays keep agreeing on which objects survive the cap: they always agreed before this
fix, when both were the identical plain prefix, and there is no reason a reader should
have to learn that they can now disagree. `build_inventory` stopped capping
`extensions` itself for the same reason `#55` stopped truncating `Evidence.binaries`
before the rules ran: it does not have `findings` yet, and capping first is capping
blind.

`_cap_by_findings` is deliberately not a call into `binfmt.caps.cap()`, even though
pass 1 above is the same "give every group one slot before filling the rest" shape
that function already implements: `cap()`'s grouping is keyed on a `cap_key` that
comes from the *item* (a string's group, a symbol's group and binding, a crate's
name), and the group that matters here comes from the *finding*, not the object --
one object can be named by several different findings, so the natural key is not a
property `BinaryEvidence` or a bare `(path, format)` pair could sensibly expose
through a shared `Capped` protocol. The *pattern* is the same on purpose; the code is
not shared, for the same reason it was not shared before the grouping pass existed.

**What adversarial review changed here.** The version of this fix first proposed
skipped the grouping pass and went straight from "referenced objects, then the rest,
both in path order" to a flat truncation once the referenced set itself exceeded the
cap -- justified at the time by an unbounded worst case ("four hundred statically-linked
OpenSSL extensions, each individually named by `BIN_STATIC_OPENSSL`") that does not
actually happen: `BIN_STATIC_OPENSSL` is a `kind = "linkage"` rule, and
`engine._match_linkage`'s `Hit` always carries `evidence.filename` as its location,
never an individual object's path -- a wheel with any number of statically-linked
extensions contributes *zero* object paths to the referenced set through that rule,
verified directly against a one-object wheel. The real bound is `[limits]
max_locations_per_finding` (10) times the number of *object-naming* findings, which is
small and tractable, not unbounded -- the stated reason a smarter fallback was not
worth attempting turned out not to hold. With that correction, review also found the
flat fallback was severity-blind even within the tractable bound it actually has: a
wheel with 270 distinct crate-naming findings and a cap of 256 let ten low-severity
`getrandom` objects (subject sorts early, alphabetically) crowd the one `ring` object
(`NON_APPROVED_CRYPTO`, high severity, subject sorts late) out of `binaries[]`
entirely, because sorting the referenced set by path -- or, without the grouping pass,
by finding subject -- moves the same arbitrary-with-respect-to-severity ordering
problem rather than solving it. Grouping by `(rule_id, subject)` and reserving one
slot per group first is what closes that: it does not need to know what "high
severity" means, only that every *finding* gets a chance at a slot before any finding
gets a second one.

**What it still does not promise, and why this cap is not quite the string/symbol/crate
one even now.** `#51`'s caps validate at load time that `max_strings_per_binary`,
`max_symbols_per_binary` and `max_rust_crates_per_binary` are each large enough to
hold one of every group the *ruleset* declares -- a fixed, load-time-known vocabulary.
`max_binaries_per_record` still has no equivalent to refuse against: how many distinct
`(rule_id, subject)` groups a wheel's own findings produce is data the wheel supplies,
not policy the ruleset declares, and the corrected bound above (`10 x` the number of
object-naming findings) is real but wheel-dependent, not a ruleset-fixed count
`parse_ruleset` could check ahead of a scan. When the number of distinct groups itself
exceeds `max_binaries` -- plausible for a large Rust wheel naming many distinct
crates, each its own finding -- pass 1 cannot give every group its slot, and the
groups that lose are whichever sort last by `(rule_id, subject)`, a deterministic but
otherwise arbitrary tie-break, the same posture `binfmt.caps.cap()` documents for its
own analogous case ("the lowest-sorting keys win"). `binaries_truncated` and
`WHEEL_BINARIES_TRUNCATED` still fire whenever this happens, so it is never silent.

**`artifacts.binaries_truncated` and `WHEEL_BINARIES_TRUNCATED` keep their meaning.**
Both mean "the listing is a prefix of the full evaluated set," and neither ever meant
*which* prefix. `build_inventory`'s computation of the flag is untouched -- it compares
the full object count against the same `max_binaries` this fix also uses -- so a wheel
crosses the same threshold it always did, this fix or not, and a human reading the
flag learns the same fact either way: not every object made it into `binaries[]`, and
the count in `WHEEL_BINARIES_TRUNCATED`'s own evidence line is the true, full count.
The rule's own `why` text was updated alongside the fix -- it said "carries only a
prefix," which stopped being accurate the moment the prefix became finding-aware, and
that text is not only internal documentation: `wheel-crypto-scan rules` and `rules
--json` print it verbatim, so it is user-visible. `ruleset_version` moved because of
it, per `AGENTS.md`. What changed in the fields themselves is only that the flag no
longer needs to be cross-referenced to know whether a *specific* object a finding
names is missing -- it usually is not, now.

**Determinism.** `_cap_by_findings` sorts explicitly at every step -- the groups
(by key), each group's representative (`min` over its path set), the referenced fill
set, the general fill set, and the final `kept` list -- rather than trusting
`evidence.binaries`' own order or any intermediate `set`'s iteration order, the same
requirement `#51`'s `cap()` documents for its own `sort_key`. The `set`s involved
(`groups`' values, `referenced_paths`, `seen`) are read only for membership or via
`sorted`/`min`, never iterated for output order, so a hash-seed-dependent iteration
order has nowhere to leak into the result. Since `findings` themselves must already be
deterministic (`apply_rules` sorts by `(rule_id, subject)` and each finding's own
`locations` by `Location.sort_key`, both pre-existing requirements this fix does not
touch), and each wheel is scanned end to end inside one worker regardless of `--jobs`,
this selection is exercised by exactly the tests that were already pinning that: the
corpus-level `--jobs` comparisons in `test_cli.py`, plus one that shapes a wheel
specifically to hit the new code path.

**Cost.** `_cap_by_findings` only runs at all when `len(items) > max_binaries`, and
then does two linear passes over the input plus a handful of sorts bounded by the
number of distinct `(rule_id, subject)` groups, the referenced-path count and the
input size -- no worse, and no more than a constant factor worse, than the plain slice
it replaces. Building `groups` and `referenced_paths` is one pass over the
already-capped `findings[].locations[]`, which `#51`'s own
`max_locations_per_finding` keeps small regardless of wheel size, independent of how
many distinct findings a wheel produces. Nothing here is quadratic in the number of
binaries or findings.

**What was rejected.** Reusing `binfmt.caps.cap()` directly, covered above. Refusing,
at load or scan time, a `max_binaries_per_record` too small for a synthetic
worst-case wheel's referenced-group count: there is no ruleset-fixed worst case to
check against the way there is for the string/symbol/crate caps, so the check would
either be vacuous or wrong for some real wheel -- the corrected bound in this entry
makes the *typical* case tractable without making it a guarantee `parse_ruleset` could
enforce. Sorting groups by the rule's own `severity` instead of `(rule_id, subject)`
for pass 1: it would remove the one remaining arbitrary tie-break in the case groups
outnumber the cap, but `severity` is ruleset policy threaded through a `Rule`, not a
property of a `Finding` the record layer already holds without a lookup, and no real
wheel has been found yet where the deterministic-but-arbitrary key actually costs a
group its slot -- revisit if one is.

`ANALYZER_VERSION` moves: any already-cached wheel whose `binaries[]` or
`artifacts.extensions` was capped, and whose cut objects included one a finding
referenced or one a low-priority group's abundance had pushed out a scarcer group's
object, now serialises differently.

Revisit if a real wheel is found whose findings alone produce more distinct
`(rule_id, subject)` groups than `max_binaries_per_record` allows, and the lost
corroboration for the group that did not fit turns out to matter in practice -- that
would be the same question `#55`'s own entry left open for the fully-unbounded case:
reconstructing the full per-object list is a different feature (streaming or
paginating `binaries[]`) from what this fix or `WHEEL_BINARIES_TRUNCATED` attempts.

Tracked in [#75](https://github.com/EmilienM/wheel-crypto-scan/issues/75).

## Sections are found by type, not by a name nobody checks

**Accepted, and it changes records.**

`_find_section` compared `section.name` against `.dynamic`, `.dynsym` and `.symtab`, but
the ELF *loader* never reads section names or the section header table at all: it walks
`PT_DYNAMIC` and the tags it points at. A name-based lookup trusted a label nothing
downstream of the compiler checks.

```
honest: EVP_DigestInit_ex, SSL_new imported, libc.so.6 in DT_NEEDED
.dynsym renamed .dynsyx in .shstrtab, same bytes otherwise  -> NO_CRYPTO_DETECTED,
                                            needs_human_review: false, partial_analysis: false
```

Renaming `.dynamic` too empties `needed` as well, and the object still loads and runs
through `ctypes` exactly as before: nothing about what the loader does changed, only
what one label in `.shstrtab` said.

**The fix has two parts, because two different shapes produced the same silence.**

`.dynamic`, `.dynsym` and `.symtab` are now found by `sh_type` (`SHT_DYNAMIC`,
`SHT_DYNSYM`, `SHT_SYMTAB`) rather than by name. `pyelftools` already builds the right
wrapper class -- `DynamicSection`, `SymbolTableSection` -- from `sh_type` alone; the name
only ever became the object's `.name` attribute, which this reader was the only thing
reading. `.go.buildinfo`, `.note.go.buildid` and `.comment` stay name-based: they are
plain `SHT_PROGBITS`/`SHT_NOTE` sections with no type of their own, so a name is the
only signal there is, and the issue that reported this explicitly left them out of
scope.

The second shape is not a renamed label but no section header table at all:
`e_shoff == 0` is a loadable object's own right, since the dynamic linker never reads
one. That reads worse than a header that would not parse: `_unparsed` still scans the
whole file for strings when the ELF header itself is unreadable, but an empty section
list fed nothing to `_collect_string_bytes`, so a statically-linked `cryptography`
extension with no section headers lost even its OpenSSL version banner -- its only
evidence -- with no error and `partial_analysis: false`. `e_shnum == 0` (with
`e_shoff == 0`) is caught right after the section list is built, before
`.dynamic`/`.dynsym`/`.symtab` are even looked for, and falls back to the same
whole-file strings pass `_unparsed` uses, tagged with a new cause.

**`elf_section_table_absent` is a new token, not a reuse of `elf_sections_unread`.**
`elf_sections_unread` already means "a section header could not be read", a failure at
a section this reader tried and failed to look at; here there is no section list to try
at all, so `.dynamic`, `.dynsym` and `.symtab` are not merely unread but unavailable,
and `needed`, `soname`, `rpath`, `runpath`, the symbol split and `stripped` follow suit.
Reusing `elf_sections_unread` would have blurred a fact a consumer can currently rely
on: that cause fires only when the reader tried and failed at specific section indices.
This one always fires as a single, whole-object fact, closer in shape to
`elf_dynamic_unread` and `elf_dynsym_unread` combined than to a section-read failure,
and it records an error the same way those two do, rather than the way
`pe_no_import_directory` does: an object that carries structural information but chose
not to declare a table (as PE's absent import directory legitimately can) is a
different fact from an ELF `.so` shipping with no section headers at all, which every
real toolchain still emits for a dynamically-loaded library.

**Review found the first version of this fix still trusted two things it should not
have, both closed before merge.**

**First: "the first section of a matching type wins" let a decoy hide the real table,**
the exact failure this issue exists to close, one level down. Reproduced on a real,
loadable `/usr/lib64/libcrypto.so.3`: two 64-byte decoy section headers spliced in
*before* the real `.dynsym` and `.dynamic` (`sh_name = 0`, `sh_size = 0`, `sh_link`
pointing at `.shstrtab` rather than a real string table, every other `sh_link` and
`e_shstrndx` past the insertion point shifted by one to stay valid), `e_shnum` bumped.
The object still loads and runs. Before this second pass: `needed = ()`, `soname =
None`, 0 symbols, `partial_analysis: false`, 0 errors, where `main` correctly read
`needed = ('libc.so.6', 'libz.so.1')`, a soname, and 6043 dynsyms -- end to end through
`scan_wheel`, `main` read `CONDITIONAL` and this branch read `NO_CRYPTO_DETECTED`. The
existing symbol/string cross-check (`binfmt.symtab`, "A symbol table is checked
against the string table, not taken at its word") does not help here: it is sound only
over the string table the *chosen* section's `sh_link` actually names, and the decoy's
`sh_link` points at `.shstrtab` instead of `.dynstr`, which disarms it entirely rather
than tripping it. That disarm property is not incidental to this one fixture -- it is
its own attack surface, `sh_link` itself never being checked against anything, and
closing it is its own finding below rather than a footnote to this one.

`_find_section_by_type` no longer returns a single answer when more than one section
shares the type it is looking for; it reports the ambiguity, and the caller trusts
neither candidate. `needed`, `soname`, `rpath`, `runpath`, the symbol split and
`stripped` all read empty, the same shape as "nothing of that type exists" -- but
tagged `partial_analysis: true` with a new cause, `elf_section_type_ambiguous`, so an
object carrying two `SHT_DYNSYM` sections never reads as one carrying none. A test now
covers both orderings: `append_duplicate_dynsym_section` puts the decoy after the real
section (the shape the first version of this fix tested, which stayed safe only
because "first wins" happened to favour the real one), and
`insert_bogus_section_before` puts it ahead of the real one -- the shape that was
actually unguarded, and the one this measurement reproduced on a real object. Both now
read `elf_section_type_ambiguous`.

**Second: a forged `sh_type` on a legitimately-named section used to read as fully
absent, which is worse than `main`.** One four-byte edit -- `.dynsym`'s `sh_type`
changed from 11 (`SHT_DYNSYM`) to 1 (`SHT_PROGBITS`), the name `.dynsym` left
untouched -- and the object still loads. On `main`, the name-based lookup still finds
the section; `pyelftools` builds the wrong wrapper class for the forged type,
`num_symbols()` fails, and `main` correctly sets `partial_analysis: true` with
`elf_dynsym_unread` -- but `_symbol_bytes` reads the raw symbol bytes by `sh_offset`
and `sh_size` directly rather than through the wrapper, so `main` still recovered 2
symbols on a synthetic object and 64 on a real `libcrypto.so.3`, alongside the partial
flag. The first version of this fix's type-based lookup for `SHT_DYNSYM` found nothing
-- the forged section no longer matches -- and treated that the same as a genuinely
absent one: `partial_analysis: false`, 0 errors, 0 symbols. Strictly worse than `main`:
where `main` was conservative (partial, some evidence), this branch was confidently
wrong (clean, no evidence, no flag).

`_type_mismatch` closes it: a name-based lookup checks whether a section still called
`.dynamic`, `.dynsym` or `.symtab` exists whose declared `sh_type` does not match what
that name is supposed to mean. If it does, that is a section that exists and cannot be
trusted, not one that is absent, and it is folded into the same cause a read failure on
that section already carries -- `elf_dynamic_unread`, `elf_dynsym_unread` or
`elf_symtab_unread` -- rather than given a token of its own: the fact ("this section
could not be read") is the same fact a raw exception on it already names, whichever way
it fell short. This does not go as far as `main`'s raw-byte recovery; the requirement
is only that the shape can never read `partial_analysis: false` with zero evidence,
which folding it into the existing partial cause satisfies without a second reader for
the symbol table's raw bytes.

**Third, found in review of the second pass: the mismatch check ran only when the
type-based lookup found nothing, so one decoy of the target type disabled it
entirely -- the first bug's shape, through a third door.** `elif dynamic is None and
_type_mismatch(...)` reads as "check by name only once type-based lookup has drawn a
blank", but one harmless decoy `SHT_DYNSYM` section (the same construction as the first
finding's decoy, `sh_link` pointing at `.shstrtab`) is enough to make the type-based
lookup succeed *unambiguously* -- exactly one candidate of that type -- so `dynsym is
None` was `False` and `_type_mismatch` was never even called. Combine that decoy with
forging the real, correctly-named `.dynsym`'s own `sh_type` away, and the real section
is invisible from both directions at once: not found by type (its type no longer
matches), and not checked by name (the gate that would have caught it never ran because
something else satisfied the type-based lookup first).

```
honest:       partial=False needed=('libc.so.6',) syms=['EVP_DigestInit_ex','SSL_new']
              linkage={'openssl':'unknown'} verdict=OPAQUE      needs_human_review=True
decoy+forge:  partial=False needed=('libc.so.6',) syms=[]       errors=0
  (pre-fix)   linkage={'openssl':'none'}    verdict=NO_CRYPTO_DETECTED needs_human_review=False
```

The `#56` headline failure, verbatim, reached through the very check meant to close a
narrower version of it. `main` (name-based lookup, no decoy to satisfy) still catches
this exact byte pattern: `partial_analysis: true`, `['elf_dynsym_unread']`, 2 symbols
recovered by the raw-byte path -- so this was a regression against `main`, not merely a
gap this fix left open.

The fix drops the `X is None and` conjunct at all three call sites: the mismatch check
now runs unconditionally, every time, regardless of what the type-based lookup found
elsewhere. It costs nothing on an honest object -- `_type_mismatch` is `False` whenever
the name-based and type-based lookups agree, which is every fixture already in the
suite -- and it only starts firing for exactly the shape that was unguarded: a section
found by name whose type does not match, irrespective of whether some *other* section
happened to satisfy the type-based lookup in its place. Tests now cover a decoy plus a
forged real section for all three of `.dynamic`, `.dynsym` and `.symtab`.

**Fourth, found checking whether the third fix's own building block could be
defeated the same way: `_type_mismatch` found "the section named X" with
`_find_section`, which is "first match in section order wins" -- the identical
hazard `_find_section_by_type` was rebuilt to stop guessing about, just applied to
name instead of type.** A decoy that reuses the real section's own *name* --
`.dynsym`, say -- rather than its type, sorts first, is correctly typed (that is the
whole trick), and reports no mismatch, so a same-named real section sitting behind it
with its own forged `sh_type` went unseen from both directions again: not found by
type (wrong type) and not caught by the mismatch check (ambiguous by name rather than
by type, which nothing was checking). Reproduced and confirmed on the actual reader:

```
honest:            partial=False needed=('libc.so.6',) syms=['EVP_DigestInit_ex','SSL_new']
same-name decoy
  + real forged:    partial=False needed=('libc.so.6',) syms=[]           errors=0
```

The `#56` headline failure a fourth time, through the building block meant to close
the third occurrence of it. `_type_mismatch` now treats more than one section sharing
`name` the same way `_find_section_by_type` treats more than one sharing `sh_type`:
untrusted, folded into the same partial cause. `insert_bogus_section_before` grew a
`same_name` option to build this fixture (reusing the target's own `sh_name` offset
instead of the empty string), and `patch_section_header` grew an `occurrence` parameter
to reach the second, real section behind the decoy rather than the decoy itself. Tests
cover all three of `.dynamic`, `.dynsym` and `.symtab` for this shape too.

**It costs the linkage answer, on purpose.** `elf_section_table_absent` and
`elf_section_type_ambiguous` are not in `[linkage_policy] exclude_reasons`. The three
causes already excluded, at the time --
`elf_symtab_unread`, `elf_go_buildinfo_unread`, `pe_no_import_directory` -- each left
every field `linkage` reads intact: `.symtab` and `.go.buildinfo` fed nothing `linkage`
touched, and an absent PE import directory is a declaration the object really did
make. (`elf_symtab_unread` left this list later, #117, once `.symtab` started driving
the imported/defined split too for an object with no `.dynsym` -- see that entry.)
None of that held for either new cause. `needed`, the imported/defined split and
`matched_strings` are what `linkage` reads, and a sectionless or ambiguous object has
answered none of them -- `needed` is not "no dependencies", it is "we could not ask" or
"we cannot tell which answer is real". Excluding either would read `openssl_linkage:
none` off an object that told us nothing, the same failure `DECISIONS.md`'s "A symbol
table is checked against the string table, not taken at its word" entry already
measured for a lying `nsyms`. The reused tokens -- a forged `sh_type` folding into
`elf_dynamic_unread`, `elf_dynsym_unread` or `elf_symtab_unread` -- were already costing
the linkage answer (two of the three, at the time) or already excluded for an unrelated
reason (`elf_symtab_unread`, which had not yet fed `linkage` at all); reusing them
changed nothing about that table.

**What was rejected.** Reading `PT_DYNAMIC` and the program headers directly -- the
issue's option 3 -- as the primary or a fallback mechanism. It is the more complete fix,
the loader's own path, immune to a section header table that is present but lies in some
way types 1 and 2 do not cover. It is also materially more work, a second parser for
information this reader already gets from section headers in the common case, and the
issue that reported this said as much. Options 1 and 2, plus closing the two gaps
review found in them (ambiguous candidates, a forged `sh_type` on a still-named
section), close every shape that was actually measured without it, so it stayed out.

**What it costs.** Records change for a renamed section (now read), for a sectionless
object (now `partial_analysis: true` with the whole-file strings pass, where it used to
be a silent, complete-looking read), for an object with more than one section of a
type this reader looks for (now `partial_analysis: true` with
`elf_section_type_ambiguous` instead of whichever candidate sorted first), for a
section found by name whose `sh_type` was forged (now folded into the existing partial
cause for that section instead of reading as absent), for a decoy of the target type
sitting beside a real section forged away from that type (now caught by the same
mismatch check the second case introduced, since it is no longer gated on the
type-based lookup having found nothing), for a decoy sharing the real section's
*name* rather than its type (now caught the same way, since `_type_mismatch` no longer
trusts the first same-named section it finds either), and for a decoy string table
`.dynsym` or `.dynamic`'s `sh_link` names without corroborating `.dynamic`'s own
`DT_STRTAB` (now folded into `elf_dynsym_unread`/`elf_dynamic_unread` the same way,
and cascading to cost `.dynsym` too whenever `.dynamic` itself could not be read),
so `ANALYZER_VERSION` moves relative to `main`. This branch itself is unreleased, so
every extraction change accumulated across every round of this entry -- including
this one -- is covered by the single bump already made; there is no reason to bump it
again per round within one unmerged branch.

**Fifth, found in a further review pass: `sh_link` itself was never validated at
all, the same underlying pattern -- an attacker-controlled label winning a lookup so
the check meant to catch a mismatch never runs -- reached through a different field
than the previous four.** `_symbol_bytes` resolved `.dynsym`'s string table with
`elf.get_section(section["sh_link"])` and nothing else: no check that the resolved
section is even a string table, and no reconciliation against `.dynamic`'s own
`DT_STRTAB` tag, which `read_elf` already parses. `sh_link` is a section-header field
the loader never reads either -- `.dynamic` and `.dynsym` both resolve names through
`PT_DYNAMIC`'s `DT_STRTAB` tag, never through any section's `sh_link` -- so trusting
it outright is the identical hazard the previous four findings close for `.dynamic`,
`.dynsym` and `.symtab` themselves, one level further down, in the one place after
all of that where a section is still picked by a raw index with no check at all.

Reproduced directly against the actual reader, and independently on real, unmodified
loadable objects (`/usr/lib64/libcrypto.so.3`, a real CPython `_hashlib` extension):
append `N` NUL bytes plus a new `SHT_STRTAB` section header pointing at them, then
repoint `.dynsym`'s `sh_link` at that index. Every symbol name index resolves to `""`
against an all-NUL table -- `names.find(b"\x00", st_name)` finds a terminator at
`st_name` itself, so the empty slice is a name *resolved*, not one flagged unresolved
-- and `""` fails `patterns.symbol_groups_for` the same way any name nothing claims
does. `libcrypto.so.3`'s 64 crypto symbols, and a real `_hashlib` extension's 24,
both went to zero, `partial_analysis: false`, no error, both objects still loading
and running unmodified otherwise.

`.dynamic`'s own `sh_link` has the identical hole and is worse: it can *fabricate*
evidence, not just erase it. `.dynamic` resolves `DT_NEEDED`/`DT_SONAME` strings
through the same unchecked `sh_link`, so a decoy that happens to spell a real
dependency name at the byte offset a real `DT_NEEDED` tag points at reports a
dependency the object never declares -- an invented name, not a truncated one, which
is the fabrication direction of "A name reported is a name read in full" rather than
the truncation direction that invariant was written against.

The fix reconciles both against data this reader already has in hand. `.dynamic`'s
own `sh_link`, once `.dynamic` is read, is checked against its own `DT_STRTAB` tag;
`.dynsym`'s `sh_link` is checked against that same address, threaded through as
`dt_strtab_addr`. `DT_STRTAB`'s `d_ptr` needs no string resolution itself -- it is a
raw pointer value in the tag -- so it is available to check against even when the
string table it names cannot be trusted. A resolved section corroborates only when
its `sh_type` is `SHT_STRTAB` *and* its `sh_addr` matches `DT_STRTAB`'s `d_ptr`; either
mismatched, or no `DT_STRTAB` to compare against at all (`.dynamic` itself unreadable
or missing the tag), fails closed rather than trusting `sh_link` unwitnessed. On
failure the string table is treated as unresolved -- `_symbol_bytes` returns `b""` for
`.dynsym`'s names, which the *existing* `unresolved` counter already turns into
`elf_dynsym_unread`, and `.dynamic`'s own `needed`/`soname`/`rpath`/`runpath` are reset
to empty under `elf_dynamic_unread` the same way an exception on `.dynamic` already
does. No new `partial_reasons` token: both fold into causes that already mean "this
table's contents could not be trusted."

This cascades, correctly: an object whose `.dynamic` cannot be read or corroborated
has no `DT_STRTAB` to hand `.dynsym` either, so `.dynsym`'s string table is untrusted
too even when `.dynsym`'s own `sh_link` is perfectly honest. Several existing
fixtures that exercise a broken or ambiguous `.dynamic` now also carry
`elf_dynsym_unread` for exactly this reason, and their assertions were updated to
expect it -- a deliberate tightening, not a regression: the alternative is trusting a
symbol table's string resolution with no witness for it, which is the same "reads
clean because nothing checks" shape as the rest of this entry.

**What it costs.** No change to the honest path: `ElfBuilder`'s own fixtures, and
every real object this was tested against, have `.dynstr`'s `sh_addr` and
`DT_STRTAB`'s `d_ptr` agree (both are conventionally 0 in this suite's synthetic
objects, and correctly non-zero and matching on the two real ones this was verified
against), so `_validated_strtab` returns the same section `_symbol_bytes` always used.
The added cost is one more section-header fetch and a bounded scan of `.dynamic`'s own
tags for `DT_STRTAB` -- both O(1) against the object, not against symbol count -- so
the hot path this module is written around, hundreds of thousands of dynamic symbols
in one object, reads exactly as many bytes as before.

**What was rejected, again.** Full program-header-based virtual-address-to-file-offset
translation, to also catch a decoy that is correctly typed *and* correctly addressed
but whose `sh_offset` alone is forged to point at fabricated bytes at the same virtual
address. Closing that needs `PT_LOAD` segment parsing this issue's chain has
repeatedly and deliberately deferred as "option 3" -- see below, grouped with the
other shapes only program headers would close.

**Whether ambiguity detection can false-positive on a real wheel.** No real toolchain
this reader's own test corpus or review turned up emits two `SHT_DYNSYM` or
`SHT_DYNAMIC` sections in one object; the shape is adversarial or hand-crafted in every
example measured here, never something `gcc`, `rustc`, `go build` or `objcopy` produce
on their own. `elf_symtab_unread`-style tokens already accept the same tradeoff for a
single section that fails to read, so treating an ambiguous one the same way -- opaque
rather than guessed at -- is the conservative direction this file already takes
throughout, not a new risk class. Revisit if a real, non-adversarial wheel is found
carrying more than one section of the same type nonetheless: the fix would then need a
second signal beyond `sh_type` to break the tie (position, `sh_link` validity, `.dynamic`
tag content), which is a larger change than this token.

Revisit also if a real wheel is found carrying a section header table whose contents
lie in some way neither ambiguity detection nor the name/type mismatch check catches --
for example a forged `sh_type` that happens to collide with a *different* legitimate
section's type rather than a generic one like `SHT_PROGBITS` -- which is exactly the
class of gap option 3 would close structurally and this does not attempt to.

**Accepted residual, grouped with the two above: `sh_addr` matching while `sh_offset`
alone is forged.** A decoy resolved through `sh_link` that is correctly typed
`SHT_STRTAB` *and* whose `sh_addr` correctly matches `.dynamic`'s own `DT_STRTAB` --
but whose `sh_offset` (the file position, as opposed to the virtual address `sh_addr`
declares) alone points at fabricated bytes -- still reads clean. `sh_addr` and
`sh_offset` are two different claims a section makes about itself, and this reader
now checks one against `.dynamic`'s independent testimony (`DT_STRTAB`) without a way
to check the other: nothing outside `PT_LOAD` segment contents corroborates that a
given virtual address really lives at a given file offset. Closing it needs the same
program-header-based virtual-address-to-file-offset translation the other two
residuals need -- reading `PT_LOAD` segments to translate an address independently of
any section at all -- which is squarely "option 3", the scope this issue's chain has
repeatedly and deliberately deferred rather than one more targeted check like the
five closed above. Do not chase this by adding a sixth targeted field comparison; the
next real gap in this family is answered by option 3 as a whole, not by another
field.

Tracked in [#56](https://github.com/EmilienM/wheel-crypto-scan/issues/56).

## A `needed` entry is bundled by what it resolves to, not by whether its name was renamed

**Accepted, and it changes `openssl_linkage` and one finding. Two claims below did not
hold up under adversarial review -- see "Two claims here did not hold up" below, which
is the part to read first if you are deciding whether `member_stem_counts` or
`_looks_vendored` is safe to lean on as written.**

`_binary_posture` read `needed` first: a base name in a crypto library's `sonames` was
`bundled` only when the name itself carried a content hash (`libcrypto-3a1f2b4c.so.3`),
otherwise `system`. That is exactly what auditwheel and delvewheel produce, and it is
not what delocate produces. delocate, the macOS counterpart of auditwheel, copies a
dependency into `.dylibs/` and rewrites the load command to point there -- `@loader_path/
.dylibs/libcrypto.3.dylib`, or `@rpath/libcrypto.3.dylib` plus an `LC_RPATH` -- without
renaming the file. `normalise_soname` reduces either to the plain base `libcrypto`,
unmangled, so the extension read `system` while the vendored copy sitting right next to
it, under `.dylibs/`, independently read `bundled`: two postures for one OpenSSL,
`_aggregate` calling it `mixed`, plus `BIN_OPENSSL_LINKAGE_UNKNOWN` ("could not be
resolved") and `BIN_NEEDED_SYSTEM_OPENSSL` ("Links the system OpenSSL") both firing --
wrong on every count. The same shape reaches ELF too: nothing stops a build placing an
unmangled dependency beside the extension with `RUNPATH $ORIGIN`.

```
pkg/_ext.cpython-312-darwin.so   needed: @loader_path/.dylibs/libcrypto.3.dylib
pkg/.dylibs/libcrypto.3.dylib    vendored_path: true, defines EVP_DigestInit_ex, SSL_new
-> before: openssl_linkage: mixed, BIN_OPENSSL_LINKAGE_UNKNOWN, BIN_NEEDED_SYSTEM_OPENSSL
-> after:  openssl_linkage: bundled, BIN_BUNDLED_OPENSSL
```

**The fix has two parts, matched to the two ways a `needed` entry can prove it names a
file the wheel ships.** `Conventions.raw_stem` reduces a name the same way `own_base`
does -- strip path, version suffix, library extension -- but stops short of undoing a
content-hash rename, which is what keeps it from being the same question `own_base`
answers. `linkage.member_stems` collects every object's `raw_stem` across the wheel, and
a `needed` entry whose own `raw_stem` lands in that set is `bundled`, mangled or not:
this is what makes the delocate case, and the plain ELF-beside-the-extension case,
resolve without touching mangling at all. Second, `linkage._looks_vendored` reads the
`needed` string itself (`Conventions.is_vendor_path`, which already recognises `.dylibs`
and `*.libs` as path components regardless of what comes before them) and, for
`@rpath`-relative names, the object's own `LC_RPATH` list combined with it, or for a
bare ELF name, its `RPATH`/`RUNPATH`. This is a weaker signal used only as a backstop:
it never asserts `bundled` by itself.

**Why the path-convention half is capped at `unknown`, never `bundled`.** A `needed`
entry can look exactly like delocate's convention and still name nothing the wheel
actually ships -- a broken build, a load command nobody rewrote, a symlink `is_binary_
member` never followed into a record. Letting the shape alone promote to `bundled` would
manufacture the same overconfidence this issue closes, aimed the other way: a wheel that
plainly resolves to nothing being told with certainty that it carries its own copy. So a
`needed` entry that looks vendored but that `member_stems` cannot confirm reads
`unknown`, the same answer this tool already gives for "an object was read too little
to say", not `system` (which would be the old bug moved sideways) and not `bundled`
(which would be a new one).

**Why `member_stems` is enough on its own for both real reproductions.** `raw_stem`
only looks at the trailing file name, and a `needed` entry's own path prefix
(`@loader_path/`, `@rpath/`, `$ORIGIN/`) never survives into that trailing component,
so matching on it is already prefix-agnostic: `@rpath/libcrypto.3.dylib` and `pkg/
.dylibs/libcrypto.3.dylib` share the same `raw_stem` without any `@rpath`/`LC_RPATH`
resolution being consulted. `_looks_vendored`'s `@rpath` and `RPATH`/`RUNPATH` handling
earns its place on a narrower case: a member that is not independently a
`BinaryEvidence` at all (a symlink `layers.binaries` never follows into a record, or an
object dropped for a total read failure) has no `raw_stem` for `member_stems` to hold in
the first place, and the path shape is the only thing left to read off. It is measured
here rather than assumed: mutating each half out independently pins one test each
(`test_an_unmangled_elf_dependency_beside_the_extension_is_bundled` goes `system` without
the `member_stems` half; the three "naming nothing shipped" tests go `system` without
`_looks_vendored`), and no test in the added set needs both at once to pass.

**Kept out of scope, on purpose.** `_binary_posture`'s overall shape -- `needed` checked
before `defined`/`static`, one short-circuit per definite posture -- is unchanged; this
fix is one more way a `needed` entry can resolve to `bundled`, slotted into the existing
per-entry loop, not a restructuring. The precedence question between `needed` and
`defined` within one object is [#60](https://github.com/EmilienM/wheel-crypto-scan/issues/60)
(now fixed -- see "A `needed` match and a definition inside one object are both true"
below); the `is_opaque` arm's per-library fan-out is
[#68](https://github.com/EmilienM/wheel-crypto-scan/issues/68) (now fixed -- see "The
`always_report` gate had a second, unguarded route around it", above). Neither is
touched here.

**A real risk this does not fully close.** `member_stems` matches on file identity
alone, not on directory. Two different libraries that happen to share a basename in
different parts of the same wheel -- unusual, but not forbidden by any format here --
would let an unrelated `needed` entry read as `bundled` because *something* in the
wheel answers to that name, not because the referenced object actually does. Resolving
that precisely needs walking the actual search path (`@rpath` order, `RUNPATH` entries,
the standard library directories) to the specific candidate file, which is a
meaningfully bigger change than this issue's reproductions call for. Recorded here
rather than fixed, because the failure direction it can produce -- reading `system` as
`bundled` -- is the safe one for a FIPS-risk tool: it never manufactures the clean
answer, and the same false-`bundled` outcome only fires when the wheel already ships
*some* object under that literal name, which is itself circumstantial evidence worth a
human's attention.

Revisit if a real wheel is found where this collision actually happens, or if #60's
precedence work needs `member_stems` threaded further into `_binary_posture`.

Tracked in [#57](https://github.com/EmilienM/wheel-crypto-scan/issues/57).

### Two claims here did not hold up

**Corrected. "A real risk this does not fully close" understated the risk, and the
`_looks_vendored` backstop fired far more broadly than the "narrow case" claimed above.**

Adversarial review ran a 150-shape differential matrix against `main` and found both
wrong, with reproductions neither of the paragraphs above anticipated.

**Claim 1: "the same false-`bundled` outcome only fires when the wheel already ships
*some* object under that literal name, which is itself circumstantial evidence worth a
human's attention."** True of the *two-file* collision the paragraph had in mind, and
not the sharpest shape a `member_stems` lookup admits: a *single* object, no vendor
directory, no second file, whose own file name happens to reduce to the same stem as an
absolute, genuinely-system dependency it declares --

```
fakecrypto/libcrypto.so   soname: libcrypto.so
                          needed: /usr/lib64/libcrypto.so.3, libc.so.6
-> before: openssl_linkage: bundled, verdict.class: NO_CRYPTO_DETECTED,
           rule_ids: [], needs_human_review: false
```

`member_stems` included the querying object itself, so the object answered its own
question: `/usr/lib64/libcrypto.so.3` can never resolve to the object that names it,
under any real search order, whatever that object happens to be called. Worse than a
wrong posture, this one had no rule behind it at all -- there is a *third* route to
`openssl_linkage: bundled` besides the two the ruleset already accounts for
(`BIN_BUNDLED_OPENSSL` for a vendored member's own record, `BIN_NEEDED_MANGLED_CRYPTO`
for a literal hash rename), and nothing claimed it. `BIN_LINKED_CRYPTO_LIBRARY`'s own
`why` names exactly this failure mode for every other library and excludes openssl on
the assumption that openssl's own rules already cover it; they did not cover this one.

**The fix has two parts.** `member_stems` (a set) became `member_stem_counts` (a
`collections.Counter`), and `linkage._resolves_within_wheel(own_stem, needed_stem,
counts)` discounts an object's own contribution to its own answer: confirmation
requires a *second* contributor when the querying object's own stem is the one in
question, and any contributor at all otherwise -- so a genuinely different object that
happens to share the declaring object's stem still confirms it (the two-file case the
original paragraph had in mind stays possible, on purpose). Second, a new rule,
`BIN_NEEDED_VENDORED_CRYPTO` (`kind = "dt_needed"`, `table = "crypto_library"`,
`resolved = true`), fires whenever `needed_posture` reads `bundled` off this path and
the name was not literally mangled, so this third route to `bundled` is claimed the
same way the other two are, and the residual imprecision the two-file case still
allows (`test_the_documented_basename_collision_residual_still_carries_a_finding`,
`test_the_basename_collision_residual_is_never_silent`) is never silent about it:
`needs_human_review` is `true` even when the `bundled` classification itself is a false
positive from the coincidence.

**Claim 2: "`_looks_vendored`'s `@rpath` and `RPATH`/`RUNPATH` handling earns its place
on a narrower case."** The code did not match the claim: `_looks_vendored` fired
whenever the object had *any* vendor-shaped `RPATH`/`RUNPATH`/`LC_RPATH`, independent of
whether the specific `needed` entry in question could plausibly resolve under it. The
review's matrix found this misreading a genuine system dependency as `unknown` on 11 of
150 shapes, on both ELF and Mach-O: a FIPS-conscious build that runs auditwheel's
`--exclude libcrypto.so.3` (a real, intentional pattern) while vendoring an unrelated
library, say libjpeg, in the same wheel --

```
fakecrypto/_ext.so        needed: libcrypto.so.3, libc.so.6
                          runpath: $ORIGIN/../fakecrypto.libs
fakecrypto.libs/libjpeg.so.8   (unrelated to OpenSSL)
-> before: openssl_linkage: unknown, verdict.class: OPAQUE, BIN_OPENSSL_LINKAGE_UNKNOWN
```

The `RUNPATH` is vendor-shaped because the wheel vendors libjpeg, not because anything
there could be OpenSSL, and a wheel this tool can read in full is exactly the case where
it does not need to guess the way a real dynamic loader would: `member_stem_counts`
already speaks for everything the wheel ships.

**The fix.** `linkage.wheel_incompletely_read(evidence)` is `true` only when some member
never became a `BinaryEvidence` at all -- skipped by an archive-level limit
(`artifacts.skipped`) or a member that raised on open or failed its CRC (`errors` at
`STAGE_BINARY`). `needed_posture` now consults `_looks_vendored` -- and can therefore
read `unknown` -- only when that is `true`; when the wheel was read in full, a
vendor-shaped path naming nothing `member_stem_counts` confirms is genuine `system`,
because a complete member list that does not contain the answer is itself the answer.
`unknown` stays reachable for a wheel that genuinely was not read in full
(`test_a_vendor_shaped_path_is_unknown_when_a_member_could_not_be_read`,
`test_a_vendor_shaped_path_is_unknown_when_the_archive_skipped_a_member`), which is the
narrower case the original claim meant but the code had not yet been made to match.

**A smaller finding from the same review, folded into this fix:** mutation testing
showed the `@rpath/`-specific branch inside the old `_looks_vendored` was dead code --
deleting it failed nothing, because the generic fallthrough (joining the *whole* `needed`
string, `@rpath/` prefix included, to each `RPATH`/`RUNPATH`/`LC_RPATH` entry) already
finds a vendor-directory component anywhere in the combined path, prefix garbage or not.
The rewritten `_looks_vendored` has one combining branch instead of two.

### The `_looks_vendored` gate was still incomplete

**Corrected again. The fix above closed BLOCKING 2's over-firing but left the gate
itself unguarded on both the shape side and the completeness side.**

Two more findings from the same review thread, past the point above:

**The vendor-shape check itself had no test.** Mutating `_looks_vendored` to
unconditionally `return True` left the full suite green: the `incomplete` gate around
it was pinned in both directions, but nothing pinned the shape check *inside* the
gate. That mutant would have reintroduced BLOCKING 2's false-positive family for every
incompletely-read wheel carrying a plain, non-vendor-shaped dependency, just moved
behind "and the wheel happens to be incomplete for an unrelated reason" instead of
firing unconditionally. `test_a_plain_dependency_stays_system_even_in_an_incompletely_
read_wheel` builds a wheel that is incompletely read (a `STAGE_BINARY` error on an
unrelated member) with a needed entry that is plainly not vendor-shaped, and pins
`system`; it is the only test that mutation flips.

**`wheel_incompletely_read` did not check `artifacts.symlinks`, so the "narrower case"
sentence a few paragraphs up was still wrong when it was written.**
`layers.binaries.is_binary_member` returns `False` for every symlink, so a vendored
library shipped as one -- a real shape: a versioned `.so`/`.dylib` left as a symlink to
the real file is ordinary practice -- is never read as a binary at all. It records
neither a `skipped` entry nor a `STAGE_BINARY` error, only `artifacts.symlinks`, which
`wheel_incompletely_read` did not consult:

```
demo/_ext.abi3.so               needed: @loader_path/.dylibs/libcrypto.3.dylib
demo/.dylibs/libcrypto.3.dylib  -> a symlink, never read as a binary at all
-> before: openssl_linkage: system, BIN_NEEDED_SYSTEM_OPENSSL ("Links the system OpenSSL"),
           DERIVED_SYSTEM_OPENSSL_ONLY ("All OpenSSL use resolves to the system library")
```

Both finding descriptions are affirmatively wrong here: an `@loader_path`-anchored load
command is wheel-internal by construction and can never be the host's system OpenSSL.
`needs_human_review` was still `true`, so this was never silent, but it was confidently
wrong rather than honestly uncertain, which is the distinction this whole entry exists
to draw. `wheel_incompletely_read` now also checks `evidence.artifacts.symlinks`;
`test_a_symlinked_vendored_library_is_treated_as_incompletely_read` pins it.

Tracked in [#57](https://github.com/EmilienM/wheel-crypto-scan/issues/57).

**What is still true, and named honestly rather than assumed.** For every `bundled`
`_binary_posture` can produce, a rule now fires: the vendored-member path
(`BIN_BUNDLED_OPENSSL`), the literal-rename path (`BIN_NEEDED_MANGLED_CRYPTO`), and the
resolves-within-the-wheel path (`BIN_NEEDED_VENDORED_CRYPTO`), audited one branch at a
time against the three places `_binary_posture` returns `LINKAGE_BUNDLED`. But `system`
has an aggregate-level backstop no per-mechanism enumeration needs to keep in step --
`DERIVED_SYSTEM_OPENSSL_ONLY` fires off `linkage.get("openssl") == "system"` directly,
whatever mechanism produced it -- and `bundled` does not: nothing here would notice if a
fourth mechanism were added to `_binary_posture` without a fourth rule to match it. That
asymmetry is not new to this fix; `BIN_BUNDLED_OPENSSL` and `BIN_NEEDED_MANGLED_CRYPTO`
already worked this way.

**Two ways to close it, deferred rather than done here, both measured rather than
assumed.** An aggregate `openssl` "bundled" rule, mirroring `DERIVED_SYSTEM_OPENSSL_ONLY`,
breaks exactly one test -- an id-enumeration test, not a behavioural one -- and the
evidence-text objection above is weaker than it first reads: `DERIVED_SYSTEM_OPENSSL_ONLY`
already carries the identical limitation (it cannot name which object resolved system
either) and fires *alongside* the mechanism-specific rule rather than replacing it, so
the aggregate rule would cost nothing that `system` does not already cost. The cheaper
option is not a new rule at all but a behavioural invariant test -- the same species of
guard as the `partial_analysis`/`partial_reasons` agreement test and the test asserting
every recordable failure maps to a rule -- asserting that no definite `openssl_linkage`
value reaches the record without at least one contributing rule having fired for it.
That test changes no output and costs nothing to add; it was not written for this fix
only because doing so is itself the follow-up, not a step this fix needed to take to be
correct. A future change to `_binary_posture` that adds a fourth path to `bundled`
should read this paragraph before assuming the existing rules still enumerate every
case, and should prefer adding the invariant test over trusting enumeration again.

Revisit if a fourth mechanism is ever added to `_binary_posture`'s `bundled` branches,
or if the two-file basename collision is seen in a real wheel often enough that the
imprecision, rather than just the silence, needs closing. The invariant test above is
worth adding regardless, as a follow-up: it is free.

Tracked in [#57](https://github.com/EmilienM/wheel-crypto-scan/issues/57).

### An absolute `needed` entry closes part of the residual, rather than leaving it open

**Fixed. "A real risk this does not fully close" and the two-file basename collision
residual both assumed `member_stem_counts`/`_looks_vendored` were the only tools a
`needed` entry had to prove itself with, for every `needed` entry alike. They are not,
for one shape: an absolute path.**

`_resolves_within_wheel` matches purely on basename, with no regard for whether the
`needed` entry's own path shape could resolve inside the wheel under any real search
order at all. `$ORIGIN`/`@loader_path`/`@rpath`/RPATH/RUNPATH resolution never applies to
an absolute path -- a real dynamic loader uses it literally -- so an absolute entry that
happens to share a basename with some unrelated object elsewhere in the wheel read
`bundled` off that coincidence alone, and `_looks_vendored` had the mirror problem: it
joins the *whole* `needed` string to each `RPATH`/`RUNPATH` entry, so an absolute path
could produce a joined string containing a vendor-directory component purely by chance
(`$ORIGIN/pkg.libs` + `/usr/lib64/libcrypto.so.3`), promoting an unconfirmed absolute
path to `unknown` for a reason that has nothing to do with how it would actually resolve.

```
demo/libcrypto.so         needed: /usr/lib64/libcrypto.so.3
demo/plugins/libcrypto.so (unrelated, shares a basename by coincidence)
-> before: openssl_linkage: bundled, BIN_NEEDED_VENDORED_CRYPTO
-> after:  openssl_linkage: system,  BIN_NEEDED_SYSTEM_OPENSSL, DERIVED_SYSTEM_OPENSSL_ONLY
```

This is the same shape "Claim 1" above fixed for an object colliding with *itself*
(`_resolves_within_wheel`'s own-stem discount, #57's BLOCKING 1) -- the object count was
never the right test for an absolute path either way, self or genuinely different.

**The fix.** `needed_posture` now computes `absolute = info_original.startswith("/")` --
true for both an ELF `DT_NEEDED` and a Mach-O `LC_LOAD_DYLIB` absolute path; PE has no
such shape -- and skips `_resolves_within_wheel` and `_looks_vendored` for it, falling
through to `LINKAGE_SYSTEM` (the function's existing default) instead. `mangled` is
checked first and untouched by this: a hash-renamed basename is strong independent
evidence regardless of whether the path carrying it happens to be absolute, and mangled
detection has nothing to do with path shape.

**The skip covers both of `_looks_vendored`'s branches, not only the `RPATH`/`RUNPATH`
join the reproduction above shows.** `_looks_vendored` also matches `needed` on its own,
`conventions.is_vendor_path(needed)`, catching delocate's plain convention
(`@loader_path/.dylibs/...`) with no `RPATH` involved at all. That branch's evidence is
meaningful only because the vendor-directory component sits in a path that gets resolved
*relative to the loading object* -- which is precisely what never happens for an absolute
path. auditwheel and delocate both always rewrite a vendored dependency to a relative
form for exactly that portability reason, so neither ever emits an absolute reference for
a copy it ships; a vendor-glob-shaped component inside an absolute path is therefore
always a coincidence or a leftover build-time artifact, not a real vendoring signal,
whether it is read through the join or off the bare string.
`test_an_absolute_needed_entry_shaped_like_a_vendor_path_itself_stays_system_even_
incomplete` (`tests/test_linkage.py`) pins this branch on its own, with no `RPATH` in the
picture, so the two halves of the skip are each independently tested rather than only the
half the original reproduction happened to show.

**The own-stem discount (`_resolves_within_wheel`'s BLOCKING-1 fix, above) is still live
code, now reached only through a relative entry.** Every existing regression test for
that discount -- `test_a_needed_entry_matching_its_own_declaring_objects_name_is_not_
self_confirmed`, its `tests/test_engine.py` and `tests/test_acceptance.py` counterparts --
used an absolute `needed` string, which after this fix answers through the new
short-circuit before `_resolves_within_wheel` is ever called; their own assertions still
hold, just no longer through the route they were written to pin. Adversarial review of
this fix caught the gap by mutation (widening the discount left the whole suite green).
`test_a_relative_needed_entry_matching_its_own_declaring_objects_name_is_not_self_
confirmed` and its `tests/test_engine.py` sibling close it with a relative reproduction of
the same shape, which cannot take the new short-circuit.

**What this narrows, and what it does not.** The two-file basename collision residual
above stays open for a *relative* `needed` entry -- one that a real loader genuinely can
resolve via `$ORIGIN`/`@rpath`/RPATH/RUNPATH, which is the ordinary auditwheel/delocate
vendoring shape #57 was about -- and `test_a_relative_needed_entrys_basename_collision_
still_confirms_bundled` (`tests/test_linkage.py`) and
`test_the_documented_basename_collision_residual_still_carries_a_finding`
(`tests/test_engine.py`) pin that this fix left it alone. What closes is the absolute
case specifically: `test_an_absolute_needed_entrys_basename_collision_no_longer_confirms_
bundled` and `test_an_absolute_needed_entry_beside_a_vendor_shaped_runpath_stays_system_
even_incomplete` (`tests/test_linkage.py`), `test_an_absolute_basename_collision_no_
longer_reads_as_bundled` (`tests/test_engine.py`), and
`test_an_absolute_basename_collision_is_not_manufactured_bundled`
(`tests/test_acceptance.py`, real ELF bytes) pin it end to end.

**This can move more than the posture -- it can move the wheel's findings and
`verdict.classes`, corrected here after review measured the first draft's claim.** An
absolute entry that used to read `bundled` no longer disagrees with a second, genuinely
system `needed` entry on the same object: before, the two combined into `mixed`
(`_binary_posture`'s `sum((system, bundled, static)) > 1` check), which would have added
`BIN_OPENSSL_LINKAGE_UNKNOWN` to the findings and `OPAQUE` to `verdict.classes`; after,
both read `system`, so the object has one definite posture, not two, and the wheel reads
plain `system` with `DERIVED_SYSTEM_OPENSSL_ONLY` instead. The headline `verdict.class`
does **not** move for this specific reproduction -- it is `CONDITIONAL` both before and
after, because `BIN_NEEDED_VENDORED_CRYPTO` already forces `CONDITIONAL` pre-fix on its
own. What moves is the rule ids and the `classes` tuple, not the headline; an earlier
draft of this entry claimed the headline moved too, and adversarial review measured both
paths through `apply_rules` and `classify` to find that wrong before it shipped.
`test_an_absolute_basename_collision_beside_a_real_system_match_no_longer_self_
disagrees` (`tests/test_linkage.py`) pins the posture move at the `resolve_linkage`
level; `test_an_absolute_basename_collision_is_not_manufactured_bundled` and
`test_an_absolute_needed_entry_beside_an_unreadable_basename_collision_stays_system`
(`tests/test_acceptance.py`) carry the full-record assertions on findings and
`verdict.classes` the unit test does not itself make. The sharpest variant -- the object
colliding by
basename with the absolute entry is itself unreadable, not merely unrelated -- was
checked to confirm it stays safe: the `openssl` answer is unaffected (the absolute entry
answers on its own, unconditionally), and the unreadable member still gets its own
`OPAQUE`-headline finding rather than being folded into, or silencing, that answer; the
record never reads `NO_CRYPTO_DETECTED` and `needs_human_review` stays `true`.
`test_an_absolute_needed_entry_beside_an_unreadable_basename_collision_stays_system`
(`tests/test_acceptance.py`) pins that combination end to end.

**What "absolute" means here, and what it deliberately does not cover.** The fix tests
`info_original.startswith("/")` -- a genuinely absolute path. Adversarial review found
the argument above ("no loader resolves this against anything the wheel ships") applies
just as well to a shape the fix does not test for: a `needed` entry containing a slash
that is not `/`-prefixed and not `@`-prefixed either, such as `../../hostlib/
libcrypto.so.3` (glibc's loader skips every search-path list once `strchr(name, '/')` is
non-null, exactly as it does for a leading `/`), and a Mach-O `@executable_path/...`
entry, which resolves against the *interpreter binary*, never the wheel, and so is
exactly as meaningless for `_resolves_within_wheel`'s basename match as an absolute path
is -- yet still takes it, confirmed by reproduction. Both stay on the pre-#80 route,
unnarrowed, and can still read a spurious `bundled` or `unknown` from an unrelated
basename collision. This is not a regression -- neither shape was covered before #80
either -- but it means the residual "Claim 1" above documents is narrower now for a
literal absolute path specifically, not closed for every path a real loader would
never resolve inside the wheel. Left open rather than widened here, since widening the
predicate correctly needs to keep today's handling of `@rpath/`, `@loader_path/` and
`@executable_path/` (each already meaningful and already tested) from being caught by
the same net.

**Whether an absolute-path basename collision can ever be a genuine vendored copy,
rather than pure coincidence, is argued here from loader semantics, not measured
against a real corpus.** The argument: whatever a wheel ships under a matching
basename, an absolute `needed` entry's own dynamic loader resolves it literally, so
that entry will load whatever is actually installed at that path on the machine
running it -- never the wheel's own copy -- regardless of what the wheel happens to
ship alongside it. A wheel whose build recorded an absolute, machine-specific path in
`DT_NEEDED` for a library it also (separately) ships is a different problem from the
one this fix answers -- such a wheel will not load that dependency correctly on any
other machine either, absolute-path coincidence or not -- and is out of scope for the
FIPS-provenance question `linkage` exists to answer. No real corpus run backs this
argument the way #57's own 288-shape matrix backs its own claims, because none was
available when this fix was made. Revisit with a `WCS_CORPUS_DIR` count of absolute
`needed` entries whose `raw_stem` collides with a shipped object's stem if one becomes
available; if that count is ever non-zero for a wheel that was not built by
auditwheel/delvewheel/delocate, the honest answer for that specific intersection may be
`LINKAGE_UNKNOWN` rather than `LINKAGE_SYSTEM`, not the wholesale short-circuit this fix
takes.

Tracked in [#80](https://github.com/EmilienM/wheel-crypto-scan/issues/80).

## A `needed` match and a definition inside one object are both true, so the object is `mixed`

**Fixed. The precedence question #57 deliberately left open.**

`_binary_posture` read `needed` first and returned `LINKAGE_SYSTEM` as soon as one entry
resolved to the system library, before the defined-symbol and banner check a few lines
below it ever ran. An object that both declares `DT_NEEDED libssl.so.3` (or the Mach-O
equivalent) and defines `EVP_DigestInit_ex` -- or carries an OpenSSL version banner,
which a version script cannot hide -- read `system` regardless, and the record then
paired `DERIVED_SYSTEM_OPENSSL_ONLY` ("every piece of OpenSSL evidence points at the
system library and none at a bundled or static copy") with `BIN_OPENSSL_SYMBOLS_DEFINED`
("OpenSSL was compiled into it") in the same `rule_ids` list -- a contradiction in the
favourable direction, and the one shape this tool's invariants exist to rule out reads
clean instead of uncertain.

```
demo/_ext.so   needed: libc.so.6, libssl.so.3
               defines EVP_DigestInit_ex, rodata: "OpenSSL 3.0.14 4 Jun 2024"
-> before: openssl_linkage: system, verdict.rule_ids: [..., "DERIVED_SYSTEM_OPENSSL_ONLY",
           "BIN_OPENSSL_SYMBOLS_DEFINED", ...]
-> after:  openssl_linkage: mixed, verdict.rule_ids: [..., "BIN_OPENSSL_SYMBOLS_DEFINED",
           "BIN_OPENSSL_LINKAGE_UNKNOWN", ...] (no "DERIVED_SYSTEM_OPENSSL_ONLY");
           the needed-side evidence itself is in findings[] as "BIN_NEEDED_SYSTEM_OPENSSL",
           which carries no verdict of its own and so never appears in verdict.rule_ids
           either before or after
```

**The decision: `mixed`, not `static`-wins.** Two ways to resolve one object carrying
both signals were on the table. `static` wins outright, discarding the `needed` match's
own conclusion; or `mixed`, `_aggregate`'s existing answer for exactly this kind of
disagreement between two different objects, extended to mean "both postures found for
the evidence contributing to one object's own posture" as well as "two objects disagreed
about the same library." `mixed` was chosen: both facts are independently true and
independently reportable (a real `DT_NEEDED` entry names the system library, and a real
symbol or banner shows the object also carries its own copy), and `static`-wins would
suppress the `needed` evidence from `verdict.conditions.openssl_linkage` itself, not just
from the findings list -- the one field most consumers filter on would then say `static`
about an object that also, genuinely, links the system library. `mixed` costs no schema
change: the value already exists, `SCHEMA.md` already gives it a row, and it was already
reachable in principle (see the fat-merge entry above, corrected alongside this one) --
this fix is what makes `_binary_posture` produce it directly instead of only via
`_aggregate` combining two different objects.

**What changed.** `_binary_posture` now computes `defined`/banner evidence before
deciding what the `needed` loop found, and returns `LINKAGE_MIXED` when both `system` and
that evidence are true, ahead of the plain `system` and `static` returns; the ordinary
cases (`system` alone, `static` alone, neither) fall through to the same branches as
before, and the `uncertain` (vendor-shaped-but-unconfirmed) case is untouched by this
fix -- at the time, it still returned before the `static` check ever ran, so a `needed`
entry that only *might* resolve inside the wheel still won over a confirmed
`defined`/banner match the way a confirmed `system` match no longer did after this fix.
That was the same shape of gap #60 closes for `system`, left open for `uncertain` on
purpose: extending the same precedent there was not part of this fix, and was left for
its own follow-up rather than folded in here, since `uncertain` already means "the
record is not sure," where `system` meant "the record is sure, and wrong." (#87 closes
this follow-up; see below.) `_aggregate` needed a small change too: a per-binary posture
of `mixed` did not exist before this fix, only `_aggregate`'s own combination of two
*different* objects' definite postures, so `mixed` was not itself in `_DEFINITE` and a
set containing only `{"mixed"}` fell through to `openssl_linkage: none` -- the linkage
*value*, not the verdict *class*: `BIN_OPENSSL_SYMBOLS_DEFINED` still fired regardless, so
`verdict.class` never became `NO_CRYPTO_DETECTED` for this shape even before the
`_aggregate` fix, only the field consumers filter on went silently wrong. `_aggregate` now
returns `mixed` immediately whenever any object's own posture already is one, since the
vocabulary has no finer split than that to offer.

**What it costs.** `BIN_OPENSSL_LINKAGE_UNKNOWN` (`values = ["unknown", "mixed"]`,
`verdict = "OPAQUE"`) now also fires for this shape, because it already treated every
`mixed` as worth `OPAQUE` regardless of how the disagreement arose. Its own `why` --
"the wheel calls OpenSSL without declaring a dependency on it, or the only evidence came
from an object we could not read" -- describes the cross-object and uncertain shapes
`mixed`/`unknown` already covered, not this one: here the dependency *is* declared and
the object *was* read in full. `verdict.classes` still leads with `CONDITIONAL`
(`[verdict] precedence` ranks it ahead of `OPAQUE`), so `verdict.class` is unaffected,
but `classes` now lists `OPAQUE` too and `BIN_OPENSSL_LINKAGE_UNKNOWN` sits in `rule_ids`
next to a `why` that does not fit. Left as is rather than reworded here: rewording it
correctly means splitting what is now two different reasons `mixed` can fire, which is
exactly the kind of enumeration risk the #57 entry above warns against taking on lightly.

**What was rejected.** `static`-wins, covered above. A new rule id distinguishing
"mixed from one object's own contradiction" from "mixed from two objects disagreeing" --
rejected for the same reason `DERIVED_SYSTEM_OPENSSL_ONLY` does not distinguish which
object resolved `system`: the record's `openssl_linkage` field does not carry
per-object detail today, and a new rule id would answer a question `rule_ids` cannot
currently ask.

Revisit if `BIN_OPENSSL_LINKAGE_UNKNOWN`'s `why` text needs to name this case explicitly,
or if a real wheel's `mixed` verdict is confusing enough in practice that the two ways to
reach it need their own rule ids after all.

### Extended in #87: an `uncertain` needed match and a definition are mixed too

**Fixed. The follow-up the paragraph above named on purpose: "left open for `uncertain`
on purpose."**

The gap #60 left standing was structural, not an oversight: `_binary_posture` still
returned `LINKAGE_UNKNOWN` for the `uncertain` case -- a `needed` entry whose path or
`RPATH`/`RUNPATH` shape looks vendor-directed but that an incompletely-read wheel cannot
confirm either way (#57's `_looks_vendored`/`wheel_incompletely_read`) -- before the
defined/banner check a few lines below it ever ran. An object with both an unconfirmed
vendor-shaped `needed` entry and a confirmed static definition (or banner) read `unknown`
regardless, silently discarding the confirmed evidence in favour of the unconfirmed one --
the same shape of bug #60 fixed for `system`, this time for `uncertain`.

```
demo/_ext.so  needed: libcrypto.so.3, RUNPATH: $ORIGIN/../p.libs (names nothing shipped,
              wheel incompletely read), defines EVP_DigestInit_ex
-> before: openssl_linkage: unknown  (the confirmed static definition is discarded)
-> after:  openssl_linkage: mixed
same, with the OpenSSL banner instead of the symbol -> mixed
```

**The decision: `mixed`, extending the same reasoning, not a new rule.** Both facts are
independently true and independently reportable, exactly as above: a `needed` entry whose
shape cannot be ruled out either way, and a real symbol or banner the object genuinely
carries. `unknown`-wins would suppress the confirmed evidence from `verdict.conditions.
openssl_linkage` itself, the same objection that ruled out `static`-wins above. No ruleset
change needed: `BIN_OPENSSL_LINKAGE_UNKNOWN` already matches `values = ["unknown",
"mixed"]`. This widening of `mixed` is not free, though -- see "What it costs" below.

**Precedence, now that three signals can be in play on one object.** `_binary_posture`
gained one more branch: `if uncertain and static: return LINKAGE_MIXED`, placed after the
`system`-and-`static` check and the plain `system` return, ahead of the existing
`if uncertain: return LINKAGE_UNKNOWN`. This is *not* the same shape as the
`system`-and-`static` branch above -- `system` does not win outright over `static`; the
two combine into `mixed`, which is the entire point of #60, restated wrong once already in
an earlier draft of this very entry and corrected here. What the ordering of the new
branch actually encodes is different: `uncertain` is exactly `needed_posture`'s
`LINKAGE_UNKNOWN`, not one of the `_DEFINITE` postures (`system`, `bundled`, `static`; see
the comment above `_DEFINITE` in `linkage.py`), and `_aggregate` already treats a
non-definite posture as one that never outvotes a definite one already present when
combining different objects' answers (`len(definite) == 1: return definite[0]`, discarding
`LINKAGE_UNKNOWN` outright, whatever else is true). That same rule already held within one
object before this fix: once a `needed` entry confirms `system` for this object, an
unconfirmed `uncertain` entry elsewhere on the same object gets no vote, the same way a
non-definite posture gets none across objects in `_aggregate` -- delivered entirely by the
pre-existing, unconditional `if system: return LINKAGE_SYSTEM` two lines up, not by where
the new branch sits relative to it (moving the new branch above `if system and static:`
changes nothing the test suite can observe, confirmed by mutation). The new branch's
position only decides which of the two remaining facts, `uncertain` and `static`, it gets
to combine once `system` is already ruled out; it does not decide `system`'s own priority.
This says nothing about whether the *unconfirmed* entry itself is genuinely `system` or
genuinely `bundled` -- the object's posture does not track that, and
`DERIVED_SYSTEM_OPENSSL_ONLY`'s own `why` ("every piece of OpenSSL evidence points at the
system library and none at a bundled or static copy") is not strictly true when a
confirmed entry and a different, unconfirmed one coexist on the same object; that gap
predates this fix (it is visible in the plain `system`-alone case too, #87 changes nothing
about it) and is left as is here rather than folded in.

The three-way case (`system`, `uncertain` and `static` all true on one object, from two
different `needed` entries) collapses into the existing two-way `system`-and-`static`
`mixed` before `uncertain` is ever consulted. That collapse is provable rather than merely
observed: the two branches' conditions (`system and static`, `uncertain and static`) can
only be true together when `system` is also true, and both branches return the same value,
`mixed`, in that case -- so no test built from `resolve_linkage`'s output alone can tell
which of the two branches fired, or whether the new branch runs before or after the
`system` checks, for this specific shape; moving it above them, or deleting it outright,
still reads `mixed` here because the `system`-and-`static` branch from #60 already does.
`test_system_uncertain_and_static_together_still_read_mixed` is kept as a
characterization pin of that convergence, not as a guard for this ordering decision -- the
ordering itself is pinned by the two-signal reproduction tests instead
(`test_an_uncertain_needed_match_and_a_defined_symbol_together_are_mixed` and its banner
variant), where `system` is false and only the new branch can produce `mixed` at all;
reverting the fix turns both of those red. The ordinary cases are unchanged: `uncertain`
alone still reads `unknown`, `static` alone still reads `static`, and `system`-and-`static`
together still reads `mixed` exactly as #60 left it.

**What it costs.** `BIN_OPENSSL_LINKAGE_UNKNOWN` already fires for both `unknown` and
`mixed`, and its `why` text already undersells this shape the same way it undersells the
`system`-and-`static` one -- left as is for the same reason given above, so as not to split
one `why` into two without also giving the two shapes their own rule ids, which is its own
follow-up.

This also widens `mixed` one object beyond the one it fires on. `_aggregate` promotes any
wheel with an object whose own posture is `mixed` outright (`if LINKAGE_MIXED in postures:
return LINKAGE_MIXED`, checked before the `_DEFINITE` count) -- a rule #60 added and this
fix inherits rather than changes. A wheel with one object reading `bundled` (a
hash-renamed `needed` entry, say) and a second, incompletely-read object that now reads
`mixed` under this fix, used to aggregate to `bundled` at the wheel level: `unknown` was
never in `_DEFINITE`, so it never outvoted `bundled` there either. After this fix the
second object's own posture is `mixed` instead of `unknown`, and `mixed` anywhere in
`postures` short-circuits `_aggregate` immediately, so the whole wheel now reads `mixed`,
not `bundled`. That drops the wheel out of `SCHEMA.md`'s own `IN("bundled","static")`
triage recipe, whose comment already notes it misses `mixed` wheels -- this fix adds one
more way to land in that existing gap, not a new gap of its own, and the direction stays
conservative: the wheel gains `BIN_OPENSSL_LINKAGE_UNKNOWN`/`OPAQUE` rather than losing
anything silently. Worth naming plainly rather than leaving the earlier, incorrect
"costs nothing new" claim standing.

**What was rejected.** A three-way branch computing `system`, `uncertain` and `static`
together explicitly -- rejected because the existing two branches already produce the
right answer once ordered correctly (see "Precedence" above: the collapse is provable, not
assumed), and adding a third would duplicate logic the
`if system: return LINKAGE_SYSTEM` / `if system and static: return LINKAGE_MIXED` pair
already covers. `uncertain`-wins over a confirmed `static` -- rejected for the reason
#60 rejected `static`-wins over `system`: a confirmed fact must never be the one a
weaker, unconfirmed fact displaces.

Revisit if a real wheel is found where the three-way shape (`system` and `uncertain` from
two different `needed` entries, plus `static`) reads confusingly, if
`BIN_OPENSSL_LINKAGE_UNKNOWN`'s `why` text is reworded for the `system`-and-`static` case
above (the same rewording would need to cover this shape too), or if
`DERIVED_SYSTEM_OPENSSL_ONLY`'s `why` text needs correcting for the pre-existing gap named
above (a confirmed entry does not actually rule out a *different*, unconfirmed one on the
same object).

### Extended in #88: a bundled needed match and system/static are mixed too

**Fixed. The third extension of the same precedence work, this time for `bundled`.**

`_binary_posture`'s `needed` loop still returned `LINKAGE_BUNDLED` immediately, from
inside the loop, as soon as one entry resolved that way -- before a second, disagreeing
`needed` entry on the same object, or the defined/banner check below the loop, ever ran.
A universal (fat) Mach-O object merges its slices' `needed` tuples into one
(`binfmt.macho`; the merge itself is pinned by `test_load_dylibs_merge_across_slices` in
`test_binfmt_macho.py`), so an object whose slices disagreed about `bundled` versus
`system` or `static` read `bundled` outright, unlike the same evidence read as two
separate objects, which `_aggregate` already combines into `mixed`.

```
one object, needed=("libcrypto-3a1f2b4c.so.3", "/usr/lib64/libcrypto.so.3")
  -> before: openssl_linkage: bundled
  -> after:  openssl_linkage: mixed
same evidence in two separate objects -> mixed, unchanged by this fix

needed=("libcrypto-3a1f2b4c.3.dylib",), defines EVP_DigestInit_ex, one object
  -> before: openssl_linkage: bundled
  -> after:  openssl_linkage: mixed
```

`bundled` was never a safety regression on its own -- `BIN_NEEDED_MANGLED_CRYPTO`,
`BIN_NEEDED_VENDORED_CRYPTO` and `BIN_BUNDLED_OPENSSL` are findings read off each
`needed` entry directly (`engine._match_dt_needed`, `kind = "dt_needed"`/
`"bundled_library"`), not off the aggregated `openssl_linkage` value, so they already
fired regardless of whether the object's own posture read `bundled` or, after this fix,
`mixed`. This fix is about the merged object and the two-separate-objects equivalent
disagreeing with each other, not about a clean read.

**The fix.** The loop no longer returns from inside itself. It sets a third flag,
`bundled`, alongside the existing `system` and `uncertain`, and lets all three
per-`needed`-entry postures accumulate across the whole `needed` tuple before the
function branches on any of them -- the same restructuring #60 did for `system` against
the defined/banner check, extended to the third `_DEFINITE` posture. The check that read
`if system and static: return LINKAGE_MIXED` became a three-way count,
`if sum((system, bundled, static)) > 1: return LINKAGE_MIXED`, checked ahead of any of
the three being returned on its own.

**Precedence, now that four signals can be in play on one object.** Built out and
verified directly against the ladder in `linkage._binary_posture` and against the test
suite, not assumed from #60's or #87's own phrasing (both of those entries record an
adversarial review catching this same category of mistake once already):

| `system` | `bundled` | `static` | `uncertain` | Result | Why |
|---|---|---|---|---|---|
| 2+ of the three true | -- | -- | any | `mixed` | Two or more `_DEFINITE` postures disagree on one object, the same shape `_aggregate` already turns into `mixed` for two different objects. |
| T | F | F | any | `system` | Unchanged from #60/#87. |
| F | T | F | any | `bundled` | New in #88: symmetric to the row above, for the reason given below. |
| F | F | T | T | `mixed` | Unchanged from #87. |
| F | F | T | F | `static` | Unchanged. |
| F | F | F | T | `unknown` | Unchanged. |
| F | F | F | F | falls through to imported/opaque/none | Unchanged. |

`system`-alone-beats-`uncertain` and `bundled`-alone-beats-`uncertain` are the *same*
rule, not two rules that happen to agree: `system`, `bundled` and `uncertain` are all
read off the same `for needed in binary.needed` loop, over different entries, and what
actually makes a confirmed entry beat an unconfirmed one is that `if uncertain: return
LINKAGE_UNKNOWN` sits *below* both `if system:` and `if bundled:` in the ladder --
`_aggregate`'s "a non-definite posture never outvotes a definite one already present"
rule, applied within one object, exactly as #87 already established for `system`. This is
NOT about the `uncertain`-and-`static` branch's position relative to them: that branch
can be moved anywhere in the ladder -- above `if system:`, between it and `if bundled:`,
wherever -- without the test suite observing any difference, confirmed by mutation (the
same finding #87's own entry already records for the `system`-and-`static` check, and the
code comment above this paragraph in `linkage.py` already states correctly). What the
`uncertain`-and-`static` branch's position DOES decide is only which of the two remaining
facts it gets to combine, once `system` and `bundled` are both already ruled out.

`static` is not read off `binary.needed` at all (`matched_symbols`/`matched_strings`
instead), so it was never subject to the `if uncertain: return LINKAGE_UNKNOWN` rule the
other two `needed`-loop facts are -- which is why #87 made it combine with `uncertain`
into `mixed` rather than being outvoted by a later, unconfirmed `needed` entry. #88 gives
`bundled` the same treatment as `system` because `bundled`, like `system`, is a
`binary.needed` fact and `if uncertain:` sits below both.

**Does this reopen #87?** No, traced explicitly. #87's own branch
(`if uncertain and static: return LINKAGE_MIXED`) is unchanged and still runs, after the
new `if bundled: return LINKAGE_BUNDLED` branch. The three-way `_DEFINITE`-count check
above it now also fires when `bundled` and `static` are both true -- but it returns
`mixed`, the same value #87's own branch would return if it were reached for that case,
so nothing #87 pinned changes behaviour: every #87 test
(`test_an_uncertain_needed_match_and_a_defined_symbol_together_are_mixed`,
`test_system_uncertain_and_static_together_still_read_mixed`, and the rest) passes
unmodified, confirmed by running the full suite against this fix, not just the new tests.

**What it costs.** No ruleset change: `BIN_OPENSSL_LINKAGE_UNKNOWN` already matches
`values = ["unknown", "mixed"]` (added for #60/#87, re-checked here and still
sufficient). This does widen `mixed` the same way #87 already named for its own fix: an
object that used to read plain `bundled` (discarding a disagreeing `system` or `static`
signal on the same object) now reads `mixed`, and `_aggregate` promotes any wheel with a
`mixed` object outright, ahead of counting `_DEFINITE` postures -- so a wheel that used to
aggregate to `bundled` (one object now `mixed`, no other object contradicting it) now
aggregates to `mixed` instead, dropping out of `SCHEMA.md`'s `IN("bundled","static")`
triage recipe the same way #87's widening already does. The direction stays
conservative: `verdict.class` is unaffected (`BIN_NEEDED_MANGLED_CRYPTO`/
`BIN_BUNDLED_OPENSSL`/`BIN_NEEDED_VENDORED_CRYPTO` still fire on the `needed` entry
itself and still carry `CONDITIONAL`, which precedes `OPAQUE` in `[verdict] precedence`),
and `verdict.classes` only gains `OPAQUE` alongside it, never loses anything silently.

**What was rejected.** A fourth branch, `if bundled and uncertain: return LINKAGE_MIXED`,
mirroring the `uncertain`-and-`static` branch -- rejected because it would answer `mixed`
for a shape ("this confirmed `bundled` entry, plus a different, unconfirmed one") that
the same-loop precedent instead resolves to plain `bundled`, for the same reason #87
rejected `uncertain`-wins over `static`: the rule already established for `system` beside
`uncertain` should not read differently for `bundled` beside `uncertain` without a
positive reason, and none was found. Extending the disagreement check into the
top-of-function `vendored_path` early return (an object's own file identity matching the
library -- the vendored copy's own record, `BIN_BUNDLED_OPENSSL`'s evidence source) --
also rejected, out of scope: #88's reproductions and title are specifically about a
`needed` entry resolving `bundled`, and that early return is a different mechanism this
fix does not touch.

**Kept out of scope, on purpose -- and there is a real reproduction for it, found by
review.** Whether an object identified by its own `binary.vendored_path` (rather than by
a `needed` entry) can itself carry a disagreeing `system`/`static`/`uncertain` signal
that its own early return currently discards is a structurally similar question, and
adversarial review of this fix built a real one: a vendored `libssl` that itself links
the host `libcrypto` (the `auditwheel --exclude libcrypto.so.3` shape `DECISIONS.md`
already names elsewhere as real) --

```
demo/_ext.so                   needed: libc.so.6, libssl-abc123.so.3
demo.libs/libssl-abc123.so.3   needed: libc.so.6, libcrypto.so.3   defines SSL_new
-> openssl_linkage: bundled   (the system libcrypto dependency is discarded)
```

-- reads `bundled` where the same two `needed` entries on a non-vendored object would
read `mixed` under this fix. `BIN_NEEDED_SYSTEM_OPENSSL` still reaches `findings[]` and
`needs_human_review` is `true`, so it is milder than #60's original hole (nothing reads
clean), but it is the same family. This is left open anyway: #88's own reproductions and
title are specifically about a `needed` entry resolving `bundled`, `vendored_path`'s
early return is a genuinely different code path this fix does not touch, and folding it
in now would extend an already-large precedence change further than this issue asked
for. The honest reason is scope discipline, not the cost of computing the extra checks,
which is small (a handful of scans over evidence the record already carries).

Revisit if a real wheel is found matching the reproduction above, or if a fifth
`_DEFINITE`-shaped signal is ever added to `_binary_posture` and needs the same treatment
this one got.

Tracked in [#60](https://github.com/EmilienM/wheel-crypto-scan/issues/60),
[#87](https://github.com/EmilienM/wheel-crypto-scan/issues/87) and
[#88](https://github.com/EmilienM/wheel-crypto-scan/issues/88).

## An explicit usedforsecurity=True, and a non-constant flag, are not `NO_CRYPTO_DETECTED`

**Fixed. The AST extractor already recorded the right thing; the ruleset just never
asked for it.**

`_hashlib_usedforsecurity` in `layers/python_ast.py` has always yielded `"absent"`,
`"false"`, `"true"` or `"unresolved"` correctly. Nothing in `data/ruleset.toml` matched
`"true"` at all, so `hashlib.md5(data, usedforsecurity=True)` -- the code explicitly
declaring itself a security use -- produced zero findings and read as
`NO_CRYPTO_DETECTED`, the one outcome this tool's invariants exist to rule out for an
uncertain or unreadable case, and this case was neither: it was the single most certain
shape the extractor can produce. Likewise, `PY_WEAK_HASH_UNRESOLVED`'s own `why` claimed
to cover "usedforsecurity passed a non-constant," but no match table read that value; it
only matched a non-constant *algorithm name* on `hashlib.new`.

**The fix.** `PY_WEAK_HASH_CALL`'s match table now accepts `usedforsecurity = ["absent",
"true"]` instead of just `"absent"`; `_match_py_call` in `engine.py` normalises a scalar
string into a one-element tuple and checks membership, the same shape `_match_py_attr`
already uses for its `values` list. `PY_WEAK_HASH_UNRESOLVED` gained a second
`[[rule.match]]` table for `usedforsecurity = "unresolved"` with `weak_algorithms_only =
true`, ORed with its existing `algorithm = "unresolved"` table -- one rule id, two ways
of reaching it. This is the first rule in the shipped ruleset to use more than one
`[[rule.match]]` table; `Rule`'s docstring already defines several tables as alternatives
ORed together, and `tests/test_ruleset.py` already exercised the form synthetically, so
the mechanism was proven before this rule became its first real user.

**The judgment call: no new rule id for the `usedforsecurity=True` case.** An explicit
`True` is worth distinguishing from the bare no-keyword call in the evidence text, since
one is a default and the other is a declaration, but not in severity, confidence or
verdict class -- both are `FIPS_BREAKING`, both need human review. The distinction
already exists one layer down: `PySite.detail` carries `usedforsecurity=absent` or
`usedforsecurity=true` per occurrence, so a reader loses nothing by both landing under
`PY_WEAK_HASH_CALL`. A second rule id would duplicate the `why` for no material gain.

**The other judgment call: a non-constant usedforsecurity on a non-weak algorithm is not
this finding, at any verdict class.** `hashlib.new("sha256", usedforsecurity=flag)` does
not fire `PY_WEAK_HASH_UNRESOLVED` (or either of the other two): sha256 is FIPS-approved
regardless of what the flag turns out to be at runtime, so the uncertainty a human would
be asked to resolve does not exist. `weak_algorithms_only = true` on the new match table
does this for free, the same filter the two existing hash-call rules already rely on.

Revisit if a future weak-hash rule needs the True/absent split visible at the rule_id
level rather than in `detail`, or if `weak_algorithms_only`'s definition of "weak" ever
needs to move for reasons unrelated to `usedforsecurity`.

Tracked in [#58](https://github.com/EmilienM/wheel-crypto-scan/issues/58).

## Every dylib-loading command reaches `needed`, not just `LC_LOAD_DYLIB`

**Accepted, the direct Mach-O counterpart of #54's PE forwarder fix, and it changes
what a re-exporting shim can hide.**

`_read_thin` recognised exactly `LC_LOAD_DYLIB` and `LC_ID_DYLIB`. Four sibling
commands share the identical `dylib_command` layout -- cmd, cmdsize, then
name.offset, timestamp, current_version, compatibility_version -- and differ only in
what the dynamic linker does with the name: `LC_LOAD_WEAK_DYLIB` tolerates the library
being absent, `LC_LAZY_LOAD_DYLIB` and `LC_LOAD_UPWARD_DYLIB` are ordinary
dependencies with different load timing, and `LC_REEXPORT_DYLIB` folds the target's
exports into this object's own API surface. All four were silently skipped:

```
libcrypto.3.dylib via LC_LOAD_WEAK_DYLIB / LC_LAZY_LOAD_DYLIB / LC_LOAD_UPWARD_DYLIB
-> before: needed drops it entirely, partial_analysis: false, openssl_linkage: unknown
-> after:  needed carries it, openssl_linkage: system
```

The re-exporting shape is the sharper failure, and the one this entry tracks against
#54's precedent directly: a shim whose whole job is re-exporting libcrypto read
completely clean.

```
libshim.dylib   id: @rpath/libshim.dylib
                needed: /usr/lib/libSystem.B.dylib
                LC_REEXPORT_DYLIB -> /opt/homebrew/lib/libcrypto.3.dylib
-> before: needed: ['/usr/lib/libSystem.B.dylib'], class: NO_CRYPTO_DETECTED,
           openssl_linkage: none, needs_human_review: false
-> after:  needed carries the re-exported dylib too, openssl_linkage: system,
           class: CONDITIONAL, needs_human_review: true
```

**What changed.** `_LC_DYLIB_DEPENDENCIES`, a frozenset of the five command values
`LC_LOAD_DYLIB` shares its struct with, replaces the single-value check in `_read_thin`.
Every one of the five is read into `needed` the same way `LC_LOAD_DYLIB` always was;
`LC_ID_DYLIB` stays a separate arm because it names this object, not a dependency.

**No marker beyond `needed`, the same call #54 made.** The PE forwarder fix populated
`needed` and `matched_symbols` and let the existing rules do their job, rather than
inventing a "this dependency arrived via a forwarder" field. `linkage._binary_posture`
reads `needed` first regardless of which of the five commands put an entry there, so
that alone closes the shim case: `BIN_NEEDED_SYSTEM_OPENSSL` and
`DERIVED_SYSTEM_OPENSSL_ONLY` fire on the resolved posture, not on which load command
produced it. A `LC_REEXPORT_DYLIB` entry has less to distinguish it than a PE forwarder
did in the first place -- the load command names only the target dylib, never a target
symbol, so there is no per-symbol forwarding information to fold into
`matched_symbols` the way `exports.forwarded_targets` did for PE. Asymmetric handling
between the two formats would need a reason neither format's evidence gives one, and
there is a second reason beside the missing per-symbol data: no rule anywhere reads
"which load command produced this `needed` entry", so a distinguishing marker would
have no consumer to read it. Collapsing five commands into one field is also the
conservative direction for the one command that asserts slightly more than the object
guarantees -- `LC_LOAD_WEAK_DYLIB` tolerates the library being absent at load time, so
recording it exactly like an ordinary dependency can flag a wheel over a library that
may never actually load. That is a choice, not an oversight: `needs_human_review` is
what a false positive here costs, not a wrong verdict class, and the alternative --
a weak dependency excluded from `needed` -- reopens the silent-drop shape this whole
issue exists to close for a case a real object almost never exercises.

**Every one of the six commands sharing `dylib_command`'s or `rpath_command`'s layout
now has its string read the same way, through one function.** `_read_command_string`
takes the fixed header size for whichever struct it is (`dylib_command`'s 24 bytes or
`rpath_command`'s 12) and refuses two shapes an offset can take: below that header,
which points at one of the command's own integer fields rather than a string the
object spells out, and past the command's own body, which names nothing at all.
Trusting an in-header offset is a decoy risk `dylib_command` genuinely has --
`timestamp`, `current_version` and `compatibility_version` are three attacker-controlled
32-bit fields with no structural meaning to this reader, so an offset landing on them
can read whatever bytes are there as a name, and a crafted object can make that read
back as a plausible dependency string that the object never named. `rpath_command` has
no such room (`cmd` and `cmdsize` are the only fields ahead of the offset itself, and
both are structurally constrained), so the same floor there is a consistency measure
rather than a demonstrated risk; the test suite says so rather than claiming
otherwise.

**`macho_load_command_string_unread` is the one token for all of this, not a silent
drop.** `_read_cstring` returning `None` used to conflate two different things: an
offset the command's own bytes could not support, or (below) a non-ASCII byte that
made the whole name unrecoverable. No existing token covered a per-command name
failure -- the closest, `macho_symtab_incomplete`, is about `LC_SYMTAB` specifically --
so this is a new one, following the naming already used for the format's other partial
causes, and it covers `LC_RPATH` alongside the dylib-loading family and `LC_ID_DYLIB`:
`elf_dynamic_unread` is the precedent for one ELF token covering `needed`, `soname`,
`rpath` and `runpath` together, so one Mach-O token covering a dependency name, the
object's own name and an rpath entry is the same shape, not a new one. It records an
error, the way an unwalkable PE import or export directory does, and it is not on
`[linkage_policy] exclude_reasons`: a lost load-command string is a lost dependency or
a lost rpath entry, and #56's `elf_section_table_absent` is the precedent for costing
the linkage answer rather than assuming the loss is harmless. `linkage._looks_vendored`
reads `rpath` directly, so a lost rpath entry can misread a bundled library's posture
in either direction, the same stakes a lost dependency name already had.

**A non-ASCII byte in an install name, dependency name or rpath entry is sanitized,
not dropped.** `_read_cstring` decoded with plain `.decode("ascii")`, which raised on
any byte outside that range and was caught by returning `None` -- indistinguishable,
to the caller, from an offset that pointed nowhere. `binfmt.elf` and `binfmt.pe` both
decode permissively (`"utf-8", "replace"`) and then sanitize, so `_read_cstring` now
does the same: a `libcrypto\x80-3.dylib` reads as `libcrypto-3.dylib` rather than
vanishing along with whatever crypto evidence its dependency name carried.

**What it costs.** `ANALYZER_VERSION` moves: a wheel already scanned under the old
reader can produce a different record without changing on disk. A weak, lazy or
upward-loaded system OpenSSL now resolves rather than reading `unknown`; a
re-exporting shim moves off `NO_CRYPTO_DETECTED`; an object with an unreadable
dylib-loading, `LC_ID_DYLIB` or `LC_RPATH` string now reads `partial_analysis: true`
instead of silently losing that dependency, name or rpath entry.

**What was rejected.** A distinguishing marker for `LC_REEXPORT_DYLIB` beyond
`needed`, covered above. Reusing `macho_symtab_incomplete` for the unreadable-string
case, which would have named a `LC_SYMTAB`-specific cause for a failure that has
nothing to do with the symbol table. A second token to keep `LC_RPATH` separate from
the dylib-loading family, rejected on the `elf_dynamic_unread` precedent above.

**Found by adversarial review, before this shipped.** Three gaps in the first version
of this fix, none of them in the four sibling commands or the shim case above, which
were the reproductions this issue named:

- `_read_cstring`'s unterminated-run fallback (`end = len(body)` when no NUL was
  found) survived the first pass untouched, because the issue's own reproductions
  never removed a name's terminator. It is the identical failure `_iter_symbols`
  already guards against for the symbol string table, in the same file, and it means
  a name whose terminating NUL was clobbered read as a longer, wrong string with
  `partial_analysis: false` rather than as an unreadable one. Now `None`, joining
  `macho_load_command_string_unread` like every other unreadable case.
- Nothing stopped a name or path offset from pointing inside the command's own fixed
  header instead of past it. For `dylib_command`, `timestamp`, `current_version` and
  `compatibility_version` are three free 32-bit fields with no structural meaning to
  this reader, so a crafted offset could read a plausible-looking name out of them
  that the object never spelled out anywhere -- the same shape #56 closed for ELF's
  section tables. `_read_command_string`'s floor closes it here.
- `LC_RPATH` kept the exact silent-drop shape this issue closes for the dylib-loading
  family: an unreadable path offset lost the rpath entry with no error and no
  `partial_reasons` token. `linkage._looks_vendored` reads `rpath` directly, so this
  was not cosmetic.

Revisit if a real wheel is found using `LC_REEXPORT_DYLIB` to re-export a specific
symbol rather than a whole dylib -- nothing in this load command carries one, so this
would have to come from `LC_DYLD_EXPORTS_TRIE`, already named as a blind spot in
`binfmt.macho`'s module docstring. Also revisit `_read_thin`'s six-element positional
return if a further per-command cause is ever added to it: this change is what took it
from five elements to six, and a small dataclass would stop the signature growing by
one every time a new failure mode joins it.

Tracked in [#59](https://github.com/EmilienM/wheel-crypto-scan/issues/59).

## An unparseable load-command header flags the walk, it does not end it in silence

**Accepted, found while reviewing #59's fix to the same walk, and one level up from
what that fix closed.**

#59 made an individual command's *name* unreadable a partial reason
(`macho_load_command_string_unread`) while the walk kept going past it. `_read_thin`'s
loop has two earlier checks, over the command's own `cmd`/`cmdsize` header rather than
its name, that stayed silent:

```python
if pos + 8 > len(commands):
    break
cmd, cmdsize = struct.unpack_from(end + "II", commands, pos)
if cmdsize < 8 or pos + cmdsize > len(commands):
    break
```

Neither `break` recorded an error or a `partial_reasons` token. Every command after
the point either one fired -- an honest, later `LC_LOAD_DYLIB` naming the system
OpenSSL included -- was silently dropped, not merely one command's string:

```
poisoned cmdsize (0x10000, claims to run past the object)
-> before: needed drops the later LC_LOAD_DYLIB entirely, partial_analysis: false
-> after:  partial_analysis: true, macho_load_command_walk_truncated, error recorded
```

**Why a new token, not `macho_load_command_string_unread`.** The two claims are not
the same fact about the object. That token says one command's name could not be
trusted while the command itself -- its `cmd` and `cmdsize` -- could, so the walk kept
going and only that one command's string is missing. Here the command's own shape is
what lied, so nothing past it can be resynced on: not one name but every later
command, and everything it might have named, is unaccounted for. Forcing the existing
token onto this would understate it the same way reusing `macho_symtab_incomplete`
for an unreadable load-command string would have (#59's own rejected option). It
records an error and is not on `[linkage_policy] exclude_reasons`, the same reasoning
#59 gave for its own token, more so here: a lost command can be several dependencies,
not one.

**What was rejected: resyncing past the bad command.** Once `cmdsize` has lied once,
`pos + cmdsize` is a guess, not a fact -- there is no honest way to know where the
next command starts, so advancing past it risks reading a decoy command's body as if
it were real, the exact shape #56's floor checks exist to close elsewhere in this
reader. Stopping the walk where the previous fix already stopped it, but now with a
signal, is the safe direction and the one the invariant requires: evidence gathered
*before* the bad command is unaffected (a command read earlier in the same walk still
reaches `needed`), only what would have come after is lost, and it is lost as
`partial_analysis: true`, never as a silent `NO_CRYPTO_DETECTED`.

**What it costs.** `ANALYZER_VERSION` moves again: a wheel already scanned can produce
a different record without changing on disk. An object whose load-command header is
too short to hold `cmd`/`cmdsize` at all, or whose `cmdsize` is below that minimum or
claims to run past the end of the load commands, now reads `partial_analysis: true`
and `openssl_linkage: unknown` instead of quietly losing every command after it. This
covers those two specific header-shape failures, not every way a load command can
lie: an ABI-invalid `cmdsize` (not a multiple of 8 on a 64-bit object) and an `ncmds`
that understates the real command count both still read clean today, unclosed by this
fix.

Revisit `_read_thin`'s now seven-element positional return the same way #59's entry
already flagged at six: a small dataclass would stop the signature growing by one
every time a further per-command cause joins it, and this issue is the second time
that prediction came true. Also revisit `binfmt.macho.py`'s pylint `max-module-lines`
override (1100, in `pyproject.toml`) if the module keeps growing at this rate --
the docstring alone accounts for most of it.

### Extended in #90: a misaligned `cmdsize` and an understated `ncmds` close the two
named gaps

**Fixed. The follow-up the paragraph above named on purpose: "unclosed by this fix."**

Both shapes desync the same walk without tripping either of #84's two `break`s, because
both stay inside what those two checks look at. A `cmdsize` that is at least 8 and does
not run past the end of the load commands passes #84's check outright even when it is not
a multiple of the ABI's own alignment (8 bytes on a 64-bit object, 4 on a 32-bit one) --
the walk advances `pos` by the lied-about amount and reads every later command from the
wrong offset, silently, the same loss #84 closed for an overtly-lying `cmdsize`, just one
the header shape check alone cannot see. And `ncmds` itself is never checked against how
many bytes the walk actually consumed: a header that undercounts it makes the `for` loop
exhaust its iterations with real command bytes still sitting unread in `commands`, with no
single command's own header ever lying about itself for #84's checks to catch.

```
(i) cmdsize=12 on a 64-bit object (not a multiple of 8, but >= 8 and inside the commands)
    -> before: needed drops the later LC_LOAD_DYLIB naming libcrypto entirely,
               partial_analysis: false
    -> after:  partial_analysis: true, macho_load_command_walk_truncated, error recorded

(ii) ncmds says 3 (LC_ID_DYLIB, one LC_LOAD_DYLIB, LC_SYMTAB); the object carries a
     fourth, honest LC_LOAD_DYLIB naming libcrypto after a complete, already-read
     LC_SYMTAB
    -> before: needed drops the fourth command entirely, partial_analysis: false
    -> after:  partial_analysis: true, macho_load_command_walk_truncated, error recorded
```

**Same token, not two new ones.** Checked against AGENTS.md's "don't duplicate an
existing cause, but don't force a fit that overstates what happened" before reusing
`macho_load_command_walk_truncated` rather than minting
`macho_load_command_cmdsize_misaligned` and `macho_load_command_ncmds_understated`. The
token's own claim was never "a command's header failed one of two specific checks" --
it is "the walk did not honestly account for all its bytes, so everything after the
point of the lie is unaccounted for rather than absent," stated generically in the
docstring `partial_analysis` enumerates from and in the field comments on
`_ThinHeader`/`_SliceEvidence`, neither of which named #84's two checks as exhaustive.
Both new shapes are that same claim by a different route: a misaligned `cmdsize` means
the commands after it cannot be trusted, for the identical reason an overtly-overrunning
one cannot; an understated `ncmds` means the walk stopped short of what the object
really carries, for the identical reason a too-short `cmd`/`cmdsize` pair does. Applying
this issue's own admission test --
find a crypto object that reads clean because the cause is on a list that swallows it --
finds nothing: neither shape is a linker convention like the ordinal-import carve-out;
both are lies about the walk's own extent, and `macho_load_command_walk_truncated`'s
`[linkage_policy] exclude_reasons` absence (it already costs the linkage answer) is
therefore exactly the right posture for both, unchanged.

**Where the checks live.** Both are one line, at the point named in #90's own issue text.
The alignment check joins #84's existing header-shape check on the same `if`, ahead of
reading the command's body:
```python
if cmdsize < 8 or pos + cmdsize > len(commands) or cmdsize % cmdsize_alignment != 0:
    break
```
The post-loop check runs once, after the `for` loop, in the loop's own `else` clause --
which Python only runs when the loop finished its full range without a `break`, exactly
the "no command lied, but did the walk still cover the object" question this check asks:
```python
else:
    if pos != len(commands):
        load_command_walk_truncated = True
```
Despite the name this section opened with, this is not solely an `ncmds`-understated
check: it catches any shape where the loop finishes clean but `pos` and `len(commands)`
disagree, which also includes an aligned, individually-honest-looking `cmdsize` that
overstates its OWN command's real size and swallows a later command's bytes into its
own padding -- no single command's header fails a check, and `ncmds` may be entirely
correct, but the walk still stops short of the object's real extent. Confirmed directly:
patching an honest `cmdsize` of 40 up to 48 trips this check with the alignment check
disabled.

**Recovery, matching #84's own precedent rather than diverging from it.** #84 does not
resync past the point of the lie -- once one command's shape cannot be trusted, nothing
after it can be either, so the fix stops the walk and reports every later command as
unaccounted for, not attempted-and-failed. Both #90 shapes follow the same choice for the
same reason: a misaligned `cmdsize` means `pos + cmdsize` was never a trustworthy jump in
the first place, so guessing a corrected offset would be resyncing on a value that already
lied, the exact hazard #84's own entry rejected; an understated `ncmds` means the object
never admitted the trailing bytes exist, so reading them anyway would report evidence the
header itself disowns. Evidence read *before* either point survives untouched, the same
"costs that structure, never the evidence already gathered" invariant #84 holds.

**Interaction, checked rather than assumed.**
- *Misalignment and #85's ambiguity check, together.* A misaligned `cmdsize` cannot
  desync the walk into misreading later bytes as a decoy `LC_ID_DYLIB` or `LC_SYMTAB`
  and firing `macho_load_command_ambiguous` for the wrong reason, because the new check
  sits at the same point #84's does: the walk breaks the moment the lie is read, before
  any byte past it is ever interpreted as a command of its own. Pinned directly:
  `test_a_misaligned_cmdsize_desyncs_the_walk_rather_than_landing_clean` asserts
  `macho_load_command_ambiguous` is absent from the reproduction's `partial_reasons`.
- *The understated-`ncmds` check against #90's own companion misalignment check, on one
  object.* They cannot both fire from the same walk (one requires a `break`, the other
  requires the loop to finish without one), so the only way to see them together is two
  slices of one fat object, each tripping a different #90 cause.
  `test_misalignment_and_understated_ncmds_combine_without_contradiction` builds exactly
  that and confirms `macho_load_command_walk_truncated` appears once, not duplicated or
  contradicted, in the merged record -- the same de-duplication #85's own entry pins for
  ambiguity alongside #84's truncation.
- *#84's own two break conditions, as a regression guard.* Every existing #84 test
  passes unmodified against this fix; nothing about either new check changes what the
  two existing ones catch. One unrelated existing test, #63's
  `test_sizeofcmds_exactly_at_the_cap_is_read_while_one_byte_over_is_refused`, DID need
  a rewrite -- not because its own assertions changed, but because its fixture used dead
  zero padding the new checks correctly flag; it now uses a real, `ncmds`-accounted
  filler command instead, with every original assertion (including the untouched
  over-cap half) intact.

**A test-fixture gap this uncovered, fixed alongside it.** `MachOBuilder._dylib_command`
and `_rpath_command` padded every command's name to a 4-byte boundary regardless of
`is64`, which is honest for a 32-bit object but not for a 64-bit one -- the ABI's own
8-byte requirement this fix now checks. Most 64-bit fixtures in this file landed on a
`cmdsize` that was a multiple of 4 but not 8 purely by the length of the strings chosen
(confirmed by running the suite with the new check added and nothing else: 34 of 111
tests in `test_binfmt_macho.py` failed, 42 across the whole suite once the Mach-O
fixture consumers in `test_acceptance.py`, `test_hardening.py` and
`test_partial_reasons.py` are counted), so the helper itself was quietly building
objects #90's own check would
have flagged as malformed. Fixed at the source rather than by loosening the check:
`_cmd_alignment`/`_cmdsize_pad` now pad to 8 bytes on a 64-bit object, 4 on a 32-bit
one, and every "well-formed" fixture in this file is ABI-honest as a result, not just
the ones #90 added. Two fixtures needed their own fix beyond the shared helper:
`all_nonprintable_dylib_name` and `malformed_rpath_name_offset` pad with NUL bytes
after an already-closed string, which is safe; `unterminated_dylib_name` pads with
non-NUL filler instead, since a NUL pad would prematurely close the very run that
fixture exists to leave open.

**What it costs.** `ANALYZER_VERSION` moves again. An object whose `cmdsize` is
internally consistent by #84's own two checks but not aligned to the ABI's own boundary,
or whose header's `ncmds` undercounts the object's real command count, now reads
`partial_analysis: true` and `openssl_linkage: unknown` instead of quietly losing every
command the lie put out of reach. No `ruleset.toml` change: `BIN_PARTIAL_FORMAT` already
claims every cause not named in its own `exclude_reasons`, and this cause was already on
that claim before #90 widened what triggers it.

**What was rejected.** Two new tokens, covered above. Resyncing past either lie by
guessing a corrected `pos`, covered above under "Recovery." A separate check keyed to
`is64` alone without also comparing against #84's existing bounds check -- rejected
because the two questions ("is this cmdsize inside the object" and "is this cmdsize
aligned") are independent facts about the same field, and folding the alignment check into
a value clamp rather than a straight boolean would have to explain what an "aligned but
still out of bounds" `cmdsize` should read as, a question the existing `or` chain answers
for free.

Revisit if a real wheel is found where a `cmdsize` misaligned by exactly one word is a
known, benign quirk of some Mach-O producer rather than a sign of a genuinely malformed or
adversarial object -- no such producer is known today, and the ABI documentation this
check enforces states the alignment as a requirement, not a convention. Also revisit
`_read_thin`'s docstring/comment growth again the same way #84's and #85's own entries
already flag: three per-command causes on top of the original ambiguity split is close to
the point a positional accounting stops being legible in prose at all.

Tracked in [#84](https://github.com/EmilienM/wheel-crypto-scan/issues/84) and
[#90](https://github.com/EmilienM/wheel-crypto-scan/issues/90).

## A symbol name is capped like PE's already are

**Accepted. Ports #53's PE fix to ELF and Mach-O rather than inventing a second one.**

`binfmt.elf._iter_symbols` and `binfmt.macho._iter_symbols` found a name's terminator,
decoded the full slice and ran `sanitize` -- a per-character Python pass -- over it for
every row, with no per-name bound and no whole-table budget. `binfmt.pe` had exactly
this problem for PE's export and import tables and closed it in #53 with two bounds:
`_MAX_NAME_BYTES`, a per-name cap past which a name is unresolved rather than
truncated into the record, and `_MAX_NAME_TOTAL_BYTES`, a whole-object budget the cap
alone does not cover because nothing stops many rows pointing at one name, or many rows
pointing at many different long ones. Neither ELF nor Mach-O had either bound.

**Measured, reusing the issue's own numbers.** 2000 `.dynsym`/`LC_SYMTAB` rows all
pointing at one 2 MiB name cost 243.7s on `main`. Post-fix, the equivalent case --
built the same way, through `tests/test_hardening.py`'s full `scan_wheel` path, not a
microbenchmark of `_iter_symbols` alone -- runs in 0.02s for ELF and 0.11s for Mach-O.
The cost was never the row count; it was rows times the bytes each row's `sanitize`
call was asked to look at, and both bounds now hold that product down regardless of
how the rows are laid out.

**The two bounds, ported at PE's own values.** `_MAX_NAME_BYTES` (8 KiB) and
`_MAX_NAME_TOTAL_BYTES` (8 MiB) now live in `binfmt.symtab`, shared rather than
duplicated into both readers, sized off PE's own corpus measurement (#53: 30,835 real
export names, the longest an MSVC-mangled 1027-byte C++ name) for lack of an ELF or
Mach-O corpus of our own. Nothing here argues for a different number: an
Itanium-mangled C++ name or a legacy Rust symbol (a full module path plus a hash) grows
unbounded the same way MSVC's mangling does, so reusing PE's value is the same bet PE
made, not a smaller one. Revisit if a real ELF or Mach-O wheel is found on the triage
list with its only incompleteness a name past this cap, the same "and nothing else"
test the whole-table string budget's own entry above already asks.

A name of exactly `_MAX_NAME_BYTES` still resolves; one byte more does not. This
differs from PE's own `cstring`, which searches `[offset, offset + window)` for a
window equal to the cap and so silently stops resolving one byte short of it -- an
implementation detail of that reader, never written down as the bound's actual
meaning. `binfmt.symtab.BoundedNames` searches `[offset, offset + cap + 1)` instead, so
the cap means what its name says: the most a name may carry, not the most a name may
carry minus one. PE is not revisited here; its existing tests only pin behaviour past
its cap, never dead on it, so nothing there is disturbed by this reader defining the
edge differently.

**The same "+1" reasoning applies to the budget, and an early draft of `window` missed
it.** `window` was first `min(_MAX_NAME_BYTES + 1, available, self._budget)` -- the "+1"
covers the cap but not the budget it sits beside, so a name of exactly `self._budget`
content bytes has its terminator at `offset + self._budget`, one byte past a window
sized to `self._budget` itself. A table with `_MAX_NAME_BYTES` left in its budget could
resolve every name shorter than that but not one landing exactly on the amount
remaining -- fails safe (the row reads unresolved, `partial_analysis: true`, never a
name it did not carry), so this was not a correctness hole, but it silently spent a
name's budget one byte more conservatively than the number in `_MAX_NAME_TOTAL_BYTES`
says. `_resolve_uncached` now takes `min` of the cap and the budget *first*
(`max_len = min(_MAX_NAME_BYTES, self._budget)`) and only then turns that into a search
span (`window = min(max_len + 1, available)`), so the "+1" is applied once, to whichever
of the two is actually binding, not to the cap alone regardless of which one is.
`tests/test_binfmt_symtab.py::test_a_name_exactly_as_long_as_the_remaining_budget_still_resolves`
pins it by setting `_budget` directly rather than spending it down row by row, which
would need thousands of rows to reach a boundary this exact for no reason connected to
what the test checks.

**The second bound this issue asked for, that PE does not have: memoization by
string-table offset.** `BoundedNames` caches `(name, resolved)` by the raw offset a
row's `st_name`/`n_strx` names, so a repeated offset costs the decode once. This closes
a case the cap and the budget do not close between them: many rows honestly repeating
one *valid*, well-under-cap name would otherwise spend the whole-table budget once per
row, exhausting it partway through an object that carries exactly one real symbol and
turning it `partial_analysis: true` for no reason but that its own string table was
walked more than once. `tests/test_hardening.py`'s
`test_repeated_elf_dynsym_offsets_resolve_the_same_valid_name` and its Mach-O
counterpart pin this the same way the budget test pins the opposite failure: reverting
memoization (verified by hand, not committed) does not make either test slow -- 2000
rows through an 8 KiB-ish name is fast either way, since the cap alone already keeps
each row's search cheap -- it makes `partial_analysis` flip from `false` to `true`, a
correctness assertion rather than a stopwatch race. The bounded-time tests beside them
still assert a wall-clock ceiling, generously above the fixed cost, the same way #53's
own PE tests do; only the memoization guard specifically needed a non-timing signal to
fail reliably, since the cap alone already makes the over-cap case fast regardless of
whether repeats are memoized.

**The cache that makes memoization work has its own cap, found by asking what it costs
against a table shaped to dodge the byte budget rather than repeat an offset.** The
whole-table budget only shrinks for an offset that resolves to real bytes; an offset
past the table, into an unclosed run, or naming an empty string costs it nothing at
all, so a table of many rows -- one per row, each a distinct such offset -- would grow
`BoundedNames`'s cache by one entry per row with neither the per-name cap nor the byte
budget ever engaging to stop it. That is the exact cost `binfmt.elf` and `binfmt.macho`
already avoid elsewhere, by keeping only the crypto names actually read (`read_crypto:
set[str]`) rather than every name a table carries -- the comment beside it measures a
half-million-symbol table at 24 MiB remembered whole. `_MAX_CACHE_ENTRIES` (65536,
`binfmt.pe`'s `_MAX_THUNKS` scale) bounds the cache the same way: past it, `resolve`
still answers every row correctly, it simply stops remembering, which only gives up the
speedup for offsets beyond the cap, never an answer. `tests/test_binfmt_symtab.py`
pins this directly against `BoundedNames`, since exercising it through either reader
would need enough distinct offsets to make a full `scan_wheel` construction slow for
no reason connected to what the test checks.

**Correction: `binfmt.macho`'s `N_INDR` alias resolution was first left uncapped, on
two justifications that did not survive review, and is now covered by the same
mechanism.** The first pass at this fix read an alias's target straight out of
`strings` with no cap, no budget and no memoization -- the identical shape just closed
for `n_strx`, one call site over in the same `_iter_symbols` -- on the reasoning that an
`N_INDR` row is rarer by construction than an ordinary name, and that closing it would
change a function signature `_iter_symbols` already returns five values from.

Neither held. Every row in a reproduction is free to be `N_INDR`; frequency is not a
property a fixed-cost format has to have, and a table shaped to exploit this looks
exactly like the ordinary-name case, one field renamed. And the arity does not change:
`alias`'s *type* moves from `bytes | None` to `str | None` -- already-resolved,
ABI-stripped and sanitised, the way ordinary names already come back from `resolver` --
which is a one-line change at the single call site that used to `.decode()` it, not a
signature change at all. `resolver` was already in scope in `_iter_symbols` for
ordinary names; the alias branch simply was not calling it.

Measured the same way: 200 `N_INDR` rows aliasing one 2 MiB target cost 30.4s before
this correction (linear in rows, the same shape as the `n_strx` measurement above), and
2000 rows against a 4 MiB target run in well under a second after it.

The one asymmetry that is real, not a gap: an ordinary unresolved name always sets
`unresolved`, unconditionally, because the caller cannot tell in advance whether an
unreadable name would have been crypto-relevant. An alias whose target fails to
resolve sets nothing of its own -- the row's own name, from `n_strx`, is still fine,
and `alias` is simply `None`, the same value a row with no alias at all yields. This
is not a hole: the target string is still sitting in `strings` either way, and
`holds_a_name_not_read`'s independent scan already exists to find any crypto name
sitting there unaccounted for in `read_crypto`, regardless of *why* it went
unaccounted -- alias failure, an ordinary index past the string table, or a lying
`nsyms`, all read the same to that check. A non-crypto target that happens to be
over-cap costs nothing and is correctly not partial, the same way a huge non-crypto
ordinary name would not be; a crypto-matching one still is, via the existing
`macho_symtab_incomplete` / `symtab_understates_rows` pair, no new token needed.
`tests/test_hardening.py::test_a_mach_o_aiming_every_alias_at_one_over_cap_crypto_target_is_not_read_clean`
pins the case that matters; the sibling test beside it pins that a merely-long,
non-crypto target does not falsely turn the object partial.

**Where the two bounds are checked, and what they interact with.** Over the cap or over
budget, a row comes back `resolved=False`, the same signal an index past the string
table's end or into a run it never closes already produced -- `_iter_symbols`'s callers
in both readers already fold that into `unresolved` and, from there, into
`elf_dynsym_unread` or `macho_symtab_incomplete`, so no new `partial_reasons` token was
needed and none was added. ELF's index-0 short-circuit ("no name", unconditional by the
format's own definition) stays ahead of `BoundedNames` rather than folded into it: index
0 is "no name" regardless of what byte a decoy table puts there, which is a different
claim from "the table's own bytes say this name ends here," and collapsing the two
would let a forged byte at offset 0 answer a question the format does not leave open.
Mach-O's `n_strx == 0` case was never special-cased before this fix and is not special-
cased now -- it already fell out of the general path correctly, so changing that would
have been an unrelated behaviour change riding along with this one.

**What was rejected.** A per-format cap and budget, duplicated into `binfmt.elf` and
`binfmt.macho` the way the cross-check they already share (`holds_a_name_not_read`) was
not: `binfmt.symtab` already exists for exactly this, a check "the same in both readers"
that "drifts" if written twice, and the bounded-read logic is the same fact about a
string table the cross-check already is. A shared budget threaded across a fat Mach-O's
slices, rather than one `BoundedNames` per `_read_symbols` call: `AGENTS.md` already
treats a universal binary's slices as independent passes up to `_MAX_FAT_SLICES`, over
regions the slices are free to share, so a per-slice budget is the existing shape, not
a new one -- and a budget shared across slices would need threading extra state through
`_SymbolRead`'s return shape for a benefit no reproduction here shows: nothing in `#61`
or its own reproduction points at a fat binary as the multiplier.

**What it costs.** `ANALYZER_VERSION` moves: an ELF or Mach-O wheel whose symbol table
carries a name past the per-name cap, or whose table-wide budget the walk exhausts, now
reads `partial_analysis: true` where it previously read whatever the (slow, but
accurate) full decode produced -- most likely clean, since a name that long matching a
ruleset group by accident is not the shape any real wheel has shown, but no longer
taken on faith either way. This is a cost the same direction #48's string-budget entry
already accepted for the same reason: the honest answer for an object this expensive to
read in full is that it was never read, not a guess dressed as one. Nothing in
`ruleset.toml` changes: both partial-reasons tokens this reuses were already policy, so
`ruleset_version` does not move.

Tracked in [#61](https://github.com/EmilienM/wheel-crypto-scan/issues/61).

## A compressed section is checked before it is inflated

**Accepted. Option 1 of #62's three: refuse to inflate past what can be used.**

`Section.data()` decompresses a `SHF_COMPRESSED` section's `Chdr.ch_size` bytes before
`_collect_string_bytes` or `_symbol_bytes` ever get to apply their own budget. `ch_size`
is a 64-bit field the object declares about itself, the same shape `#61`'s per-name cap
and this file's own `#48` entry already closed for a name and a whole-table size --
except here the number buys an actual `zlib.decompressobj()` call rather than a Python
loop, so the cost is a memory spike, not CPU. The issue's own reproduction: a 255 KiB
ELF declaring a 256 MiB `.rodata`, `read_elf` peaking at 512 MiB in 0.82 s, recorded as
`partial=True reasons=('strings_bytes_unread',) errors=[]` -- the record was correct,
the cost was getting there. The wheel-level `ArchiveLimits.max_compression_ratio` guard
never sees this shape: the zlib stream sits inside the zip member, whose own compression
ratio looks ordinary either way.

**Checked with a call already made, not a new one.** `Section.__init__` reads `Chdr`
eagerly and cheaply -- `Elf64_Chdr` is `ch_type`, `ch_reserved`, `ch_size`,
`ch_addralign`, 24 bytes; `Elf32_Chdr` drops `ch_reserved`, 12 -- before `.data()` is
ever called, and exposes the result as `section.compressed` and `section.data_size`
(pyelftools, `elftools/elf/sections.py`; the struct layouts, elfclass-aware, are in
`elftools/elf/structs.py:_create_chdr`). `_bounded_section_data` (`binfmt/elf.py`) reads
those two properties and refuses -- `(b"", True)`, the same "unread" signal a
`.data()` call that raises already produced -- when `section.compressed and
section.data_size > max_bytes`, never calling `.data()` at all in that case. Both ELF
classes are covered by construction, through the one property read, not by hand-parsing
`Chdr` a second time or by a dedicated 32-bit test: `structs.Elf_Chdr` is already built
per-object from `elf.elfclass`.

**One helper, three call sites, the same shape at each.** `_collect_string_bytes`
checks against `remaining`, the budget actually left after earlier sections -- over
`remaining` is over `max_strings_bytes` outright whenever `remaining` is still the
whole budget, so nothing else needed comparing. `_symbol_bytes` reads `.dynsym`'s
entries and its string table through the same call `.rodata` is, so `max_strings_bytes`
-- already the caller's own ceiling on how much of this object it will inflate -- is
threaded through as `_symbol_bytes`'s bound too, rather than a second constant for a
question this file already answers once. Auditing every other `.data()` call in
`binfmt/elf.py` for the same exposure, per the issue's own reproduction only naming
`.rodata` and `.dynsym`/`.dynstr`, found one more: `.go.buildinfo`, read the identical
way with no size check of its own. It gets the same guard, against `max_strings_bytes`,
reusing `elf_go_buildinfo_unread`, no new token.

**`.go.buildinfo` carried a second, uncompressed exposure the same audit found, and
the first pass at this fix missed it.** `Section.data()` checks `SHT_NOBITS` before it
checks `compressed` at all, and for a `SHT_NOBITS` section returns `b"\0" *
self.data_size` with no file bytes read to justify the length -- `data_size` there is
just `sh_size` itself (`Section.__init__` sets `_decompressed_size = header['sh_size']`
whenever `compressed` is false), and `SHT_NOBITS` is defined to occupy no file space,
so nothing bounds it against the object's actual size. `_collect_string_bytes` was
never exposed to this: it already excludes `SHT_NOBITS` outright, for every section it
considers, before this fix existed. `.go.buildinfo` is found by `_find_section` on
name alone, with no `sh_type` check of any kind, so a section named `.go.buildinfo`
and flagged `SHT_NOBITS` reached `.data()` through this fix's first pass exactly the
way an honest one does -- `_bounded_section_data`'s original guard read `not
section.compressed` as "ordinary and file-backed," which is not what it means; it
means "not compressed," and `SHT_NOBITS` is the gap between those two readings.
Reproduced: a 298-byte object (no compression, no zlib) with `.go.buildinfo` marked
`SHT_NOBITS` and `sh_size` declaring 2048 MiB peaks at 2 GiB, `partial_analysis:
false`, no error -- three orders of magnitude cheaper to build than the compressed
reproduction above, and silent rather than merely expensive, since nothing about it
routes through the compression check at all. `.dynsym` and its string table are safe
from this by construction rather than by having been checked for it: both are reached
through `_find_section_by_type`/`_validated_strtab`, which match on `sh_type ==
"SHT_DYNSYM"`/`"SHT_STRTAB"` specifically, and a section cannot carry two `sh_type`
values at once, so the `SHT_NOBITS` branch those two call sites hand to
`_bounded_section_data` is reachable in the function but dead at both of them.
`_bounded_section_data` now refuses on `section.compressed or section["sh_type"] ==
"SHT_NOBITS"`, not on `compressed` alone, and its docstring no longer claims `sh_size`
bounds the uncompressed case -- it does not, `data_size` is the field that matters for
both shapes, and for `SHT_NOBITS` `data_size` is `sh_size` read with nothing checking
it. `tests/test_hardening.py::test_a_nobits_named_go_buildinfo_does_not_allocate` pins
this the same way the compressed cases above are pinned: a peak-bytes ceiling, reverted
by hand to confirm it fails red without the `SHT_NOBITS` arm.

**No new `partial_reasons` token at either site.** `.rodata`/`.comment`'s refusal folds
into `elf_section_data_unread`, the existing cause the `SHF_COMPRESSED`-over-garbage-bytes
case in `tests/test_partial_reasons.py` already produces from a `.data()` call that
raises -- refused before the call and raised inside it are the same fact for a consumer,
"this section was not read," so they share the token rather than needing a means-versus-
end distinction nothing downstream asks for. `.dynsym`/`.dynstr`'s refusal folds into
`elf_dynsym_unread` the same way, and for the case where only the string table is over
budget this mostly falls out of the existing cross-check for free: an empty `dynstr`
resolves nothing, `unresolved` climbs, and the existing `if unresolved: ...` branch
already adds the token. It is still named explicitly (`symtab_bytes_unread`, checked
before the resolve loop) because a `.dynsym` whose *own* bytes were refused iterates
zero rows -- `unresolved` stays zero, `holds_a_name_not_read` has nothing pointed away
from to notice either, and nothing else would say this object was not read at all.

**The boundary is "more than", not "at least".** A section declaring exactly `remaining`
(or exactly `max_strings_bytes`, for the symbol-table and `.go.buildinfo` call sites) is
refused nothing: `.data()` runs, produces exactly that many bytes, and nothing past this
point truncates it further, the same "cap means what its name says" reading `#61`'s own
entry above gives `_MAX_NAME_BYTES`.

**Measured, scaled down for the test suite.** The issue's own 256 MiB declared / 512 MiB
peak reproduces at 8 MiB declared against a 64 KiB budget: unfixed, `tracemalloc` shows
a ~16.9 MiB peak (the inflated buffer plus pyelftools' own read-back copy, the same
roughly-2x shape the issue's own 256 MiB/512 MiB numbers show); fixed, well under 2 MiB,
in well under a second either way since 8 MiB of zero bytes compresses and decompresses
fast regardless. `tests/test_hardening.py`'s two `..._does_not_allocate` tests assert a
peak-bytes ceiling rather than a timing race, the same technique `#61`'s own bounded-time
tests use for the same reason: reverting the guard (checked by hand, not committed) fails
both on the memory assertion, cleanly, not by chance timing. `tests/test_binfmt_elf.py`
carries the correctness side at unit scale -- refused-over-budget, honest-under-budget,
and exactly-at-the-boundary, for both `.rodata` and a corroborated decoy `.dynstr` -- and
pins the *token* difference a revert produces: unfixed, the over-budget `.rodata` case
above genuinely decompresses (it is an honest 8 KiB payload, not garbage) and reads as
`strings_bytes_unread` with no error, exactly the issue's own "the record was correct"
observation; fixed, it is `elf_section_data_unread` with one, and `strings_bytes_unread`
does *not* also fire -- see "`strings_truncated` can under-report a budget refusal"
below for why that is deliberate rather than a fact this fix dropped. The `.dynstr` case
has no truncate-and-continue at all today, so unfixed it is read in full at any size and
the symbol resolves -- there was no bound to test to begin with, only an unbounded read.

**`strings_truncated` can under-report a budget refusal, and this is left as-is rather
than papered over.** A section refused by `_collect_string_bytes`'s new pre-check sets
`unread`, not `truncated`: `truncated` is what a section read in full and then cut to
fit sets, and a refused section was never read at all, so nothing here actually knows
how many of its bytes -- if any -- would have been genuine strings versus more of
whatever made `ch_size` this large. The obvious fix, setting `truncated` too whenever
the refusal fires, does not hold up: `ch_size` alone cannot tell an honestly oversized
declaration apart from a malformed header that happens to decode to a huge number, and
`tests/test_partial_reasons.py`'s existing "elf section data unreadable" fixture is
exactly that shape -- `.rodata` filled with the OpenSSL banner text, `SHF_COMPRESSED`
set over bytes that were never really compressed at all, whose first 24 bytes decode as
a `Chdr` with `ch_size` around 3.76 * 10^18 purely by accident of what those ASCII
bytes happen to be. Setting `truncated` there is not a defensible claim -- there was
never a real 3.76-exabyte string payload to have dropped part of -- so the branch
cannot set it correctly for every case that reaches it, and the alternative of trying
to distinguish the two (checking `ch_type` before deciding) reintroduces exactly the
"is this header sane" question `_bounded_section_data` exists to avoid asking before
refusing. `strings_truncated: false` alongside `elf_section_data_unread` is therefore
the honest answer for this cause: `partial_analysis`/`partial_reasons` are what say the
object was not read in full, and `strings_truncated` narrows to the weaker, cap-specific
question of whether a definite number of budget bytes is known to have been dropped --
which, for a section refused before ever being read, is not a question this cause can
answer either way.

**What was rejected.** Option 2 (decompress with a caller-supplied `max_length`, keeping
whatever prefix fits, the same shape `_collect_string_bytes` already gives an honest
oversized *uncompressed* section) is bounded correctly: `zlib.decompressobj().
decompress(data, max_length=N)` allocates `N`, the defender's own chosen budget, not
anything the object declares -- verified directly, `max_length=4096` against a stream
that inflates to 256 MiB peaks at well under a megabyte, `max_length=64 MiB` peaks at
~128 MiB (the output buffer plus the same roughly-2x overhead this entry's own
measurements show elsewhere), regardless of what `ch_size` claims. That is not what ruled
it out. The issue's
own text notes it "needs the Chdr parse and a zlib call outside pyelftools" -- exactly
the second reader for one fact `#61`'s "what was rejected" paragraph above already
declined for `BoundedNames`. It would also split the two call
sites onto different rules for the identical shape of bug: a partial `.rodata` prefix
is enough evidence for `strings_bytes_unread`-style truncation, but a partial `.dynstr`
prefix is not obviously the same table `.dynsym`'s offsets were computed against, and
the issue's own text already answers this for the symbol tables ("(1) is the natural
rule"), so applying (2) to `.rodata` alone would have been two fixes for one bug rather
than one. Option 3 (treat any compressed eligible section as unread, regardless of size)
throws away an honest, small, well-under-budget compressed banner for no reason --
losing evidence `#48`'s entry above spent a whole entry establishing a budget precisely
to keep. Option 1 costs neither: an honest section under budget is untouched, and an
oversized one is refused before its size is spent on anything.

**What it costs.** `ANALYZER_VERSION` moves: an object whose eligible `.rodata`/
`.comment` declares a compressed size over the remaining strings budget now reads
`elf_section_data_unread` where it previously read `strings_bytes_unread` -- still
`partial_analysis: true` either way, but named, and with an error record, rather than
silently short. `strings_truncated` moves from `true` to `false` for this shape, which
is a real change and not just a rename: see "`strings_truncated` can under-report a
budget refusal" above for why the fix does not also set it. An object whose `.dynsym` or
its string table declares a compressed size over `max_strings_bytes` now reads
`elf_dynsym_unread` where it previously read whatever
a full, unbounded decompress produced -- most likely a correctly resolved symbol table,
since nothing in the issue's own "what I did not verify" section, nor anything checked
here, points at a real wheel shaped this way, but no longer taken on faith either way,
the same trade `#61`'s own entry above accepted for the per-name cap. `.go.buildinfo`
moves the same way, reusing its own existing token. Nothing in `ruleset.toml` changes:
every token this reuses was already policy, so `ruleset_version` does not move.

**What was not verified, same as the issue's own gap.** Whether any real wheel ships a
compressed *allocated* section at all -- `.debug_*` sections are the common carrier and
are not `SHF_ALLOC`, so `_collect_string_bytes` already skips them before `.data()` is
reached regardless of this fix; `.comment` is the one named unconditionally and is the
plausible carrier if any is. Revisit if a real wheel is found on the triage list for
this and nothing else.

**#95 closes the follow-up this entry's own scope left open: the same check, without
the `compressed or SHT_NOBITS` narrowing, for an ordinary section.** The fix above only
refused `_bounded_section_data`'s call to `.data()` when `section.compressed or
section["sh_type"] == "SHT_NOBITS"`, the two shapes this issue's own reproduction
measured -- an ordinary, uncompressed, file-backed section (or `.dynsym`/`.dynstr` from
a real symbol table, read through the identical call) fell through that `and` entirely
and reached `.data()` unconditionally, at whatever size `sh_size` names, with only the
*accumulated* buffer cut afterwards. `section.data_size` means the same thing here as
it does for the compressed and `SHT_NOBITS` cases above: `sh_size` itself, the field
pyelftools' `Section.__init__` sets `_decompressed_size` from whenever `compressed` is
false -- genuinely file-backed for an ordinary section, but that is exactly the
exposure: reading it costs whatever `sh_size` names before this reader's own budget
gets a say. The fix drops the `and` entirely: `if section.data_size > max_bytes: return
b"", True`, applied to every section regardless of shape.

**Reproduced at the issue's own scale, the same 8 MiB/64 KiB shape measured above for
the compressed case.** An honest, uncompressed 8 MiB `.rodata` against a 64 KiB budget:
unfixed, one `stream.read()` of 8388608 bytes, `tracemalloc` peaking at 8605805, and a
record that reads `strings_bytes_unread` -- correct, per the issue's own framing ("the
record is correct either way... this is cost, not evidence"), but only after the whole
section was read to get there. `.dynsym`/`.dynstr` from 200,000 real, distinct symbol
names (~4.8 MiB `.dynstr`, and a `.dynsym` of the identical size, 24 bytes per
`Elf64_Sym` entry) against the same 64 KiB budget: unfixed, `partial_analysis: false`
-- a fully clean, complete record, paid for at the size of the honest table rather than
the budget, with no way for a consumer to tell this table cost more than it should
have. Fixed, both `.dynsym` and `.dynstr` are checked independently against the same
budget (`_symbol_bytes` already threaded `max_table_bytes` through to both calls, as
its own docstring above already promised), either one over budget refuses the whole
table, and `elf_dynsym_unread` fires -- the honest symbol this fix's own test carries is
not silently dropped; the record has to say it was not read rather than stay clean.

**`.dynsym`'s own declared size was never checked before, independent of `.dynstr`'s.**
The issue names both explicitly ("a `.dynsym`/`.dynstr` from a real symbol table ...
falls through the `and` condition"), and closing the gap for `.dynstr` alone would have
left an honest `.dynsym` of any size read in full regardless of budget -- the shape
`#61`'s own per-name cap and this entry's own budget exist to bound. This has one
visible side effect on existing fixtures: a `.dynsym` with even a single real symbol is
two `Elf64_Sym` entries, not one -- index 0 is always the reserved null entry -- so 48
bytes (`Elf64_Sym`'s own 24, twice), not 24, is the floor a "declares exactly the
budget" boundary test now has to clear for `.dynsym` to be read at all alongside its
string table. `tests/test_binfmt_elf.py`'s existing `.dynstr`-only boundary tests were
sized against `.dynstr` alone and needed the same 48-byte floor to keep resolving
post-fix; not a behavioural regression, since the object under test is a two-entry
`.dynsym` either way, only a test fixture that had never had a reason to notice.

**An independent adversarial review of this fix found two further gaps before it was
accepted as final, both closed in the same pass.**

**The first was blocking: a refused `.dynsym` or `.dynstr` reached the existing
`unresolved`/`holds_a_name_not_read` cross-check with no guard against it, and could
fabricate `symtab_understates_rows` -- a specific, checkable claim ("every structural
check passes and the count is simply not the truth", per `SCHEMA.md`) -- against a
table that was never shown to lie, only left unread.** When `.dynsym` alone is refused
for budget, `table` is empty, so `_iter_symbols` yields no rows and `unresolved` stays
0; the `elif holds_a_name_not_read(dynstr, patterns, read_crypto):` branch then finds
whatever real crypto name sits in an honest, in-budget `.dynstr` unclaimed by any row
`read_crypto` never got the chance to populate, and reports it as an understated
symbol count. Reproduced directly: 101 `.dynsym` entries (100 short-named padding
rows plus one real `SSL_new`) against a 600-byte budget -- `.dynstr` (509 bytes) reads
fine, `.dynsym` (2448 bytes) is refused -- read as `('elf_dynsym_unread',
'symtab_understates_rows')` with the error `".dynsym declares fewer entries than
.dynstr holds names for"`, both false: the object's row count was correct throughout.
A companion, lower-severity shape reaches the sibling branch instead: `.dynstr` alone
refused (a real `.dynsym` entry, an oversized honest decoy `.dynstr`) means every row
resolves against an empty string table, so `unresolved > 0` fires
`".dynsym names strings .dynstr does not hold"` -- not exactly false (`.dynstr` really
does hold nothing, being empty) but redundant and misleading alongside the correct
budget error, and not the claim `unresolved` exists to make (the object lying about
`.dynstr`'s own contents). Fixed the same way `binfmt.macho`'s own `_SymbolRead`
already orders `truncated` ahead of its `unresolved`/understated pair: `read_elf` now
checks `symtab_bytes_unread` first and skips the entire per-symbol walk and both
follow-on branches when it is true, keeping only the `elf_dynsym_unread` error and
reason the refusal itself already sets -- there is nothing correct left for either
branch to add once a read was refused rather than completed. Skipping the walk also
means neither shape pays for iterating rows or resolving names that cannot answer
either question anyway, the same "cheapest question first, walk skipped for a table
already known to have fallen short" ordering `binfmt.macho`'s own comment gives it.
`tests/test_binfmt_elf.py::test_a_refused_dynsym_with_an_honest_dynstr_does_not_fabricate_understated_rows`
and `::test_a_refused_dynstr_with_an_honest_dynsym_does_not_fabricate_a_second_error`
pin both shapes, confirmed to fail -- the fabricated reason and the redundant message
both reappear, on the same assertions -- with the guard reverted by hand and restored
to pass again.

**The second, real-world reachable rather than synthetic: an ordinary section refused
for being over budget discarded its ENTIRE content, not just the excess, unlike every
other reader in this codebase and unlike this fix's own first version's intent.**
`binfmt/macho.py`, `binfmt/pe.py` and `binfmt/fallback.py` all read
`min(size, max_strings_bytes)` and keep the in-budget prefix; the first version of this
fix instead refused an over-budget ordinary section outright, `(b"", True)`, the same
shape a compressed section still must (an all-or-nothing `zlib` call with no cheap
partial-read) but for a plain file-backed section with no such constraint. Reproduced
against a real host library, `/usr/lib64/libLLVM.so.22.1` (68.3 MB of eligible sections
against the 64 MiB default budget): `main` reads it `strings_bytes_unread`, no errors;
the first version of this fix read it `elf_section_data_unread` plus a spurious
`elf_parse_error`, which fires `BIN_UNPARSEABLE` ("Truncated, corrupt or an
unrecognised format") over `BIN_STATIC_OPENSSL` -- a false-positive-shaped downgrade on
a perfectly ordinary, healthy object, at a size range ML/scientific wheels (`libxul`,
`libnode`, `pyarrow`'s `libarrow`) commonly reach. Fixed by giving
`_bounded_section_data` a `keep_prefix` parameter: an over-budget ordinary section
still refuses past the budget, but for `.rodata`/`.comment`/`.go.buildinfo` -- the
callers that pass `keep_prefix=True` -- it hands back `max_bytes` of its own real
content first, one plain `stream.seek`/`.read()` at the section's own offset, no
decompression and no second reader involved. `_collect_string_bytes` then treats a
non-empty recovered prefix as `truncated`, not `unread`: the object told the truth
about its bytes, this reader simply ran out of budget partway through them, which is
exactly what `strings_bytes_unread` (no error) already names for the pre-existing
"budget exhausted across several smaller sections" case -- restoring, at this call
site, the same record `main` already produced for an ordinary oversized section, now
at the cost of a single bounded read instead of a full one. `libLLVM.so.22.1` reads
`strings_bytes_unread`, no errors, one matched string, after the fix -- the same record
`main` gives it. `.go.buildinfo` keeps its existing `elf_go_buildinfo_unread` error
whenever refused, prefix or not (see "What was rejected" below for why), but the
recovered prefix is no longer discarded before reaching `build_go_info`: an honest Go
version sitting near the section's own 32-byte header, comfortably inside the budget,
still parses even though the section as a whole did not read in full.
`.dynsym`/`.dynstr` do not pass `keep_prefix` and keep refusing outright (see "What was
rejected" below).

**What was rejected, for the prefix-recovery half.** Applying `keep_prefix` to
`.dynsym`/`.dynstr` too: rejected, on the strength of the same guard fix above --
a byte-bounded prefix of a symbol table is not a set of complete rows, an entry near
the cut is as likely to point past a truncated string table as into it, and reading
one without a row-aware cap reopens a narrower version of the exact fabrication the
guard fix above exists to close (a partial table that iterates some real rows and some
garbage ones, with no way here to tell which is which). The honest way to bound a
symbol table without losing rows to that ambiguity already exists one layer over, in
`binfmt.macho`'s own per-slice `nsyms`/`strsize` cap (#63): porting that shape to ELF
is a real fix, but a different, larger one than this pass, and is left open rather than
half-built here. Compressed and `SHT_NOBITS` sections keep the original all-or-nothing
refusal regardless of `keep_prefix`: a compressed section has no cheap partial read
(#62's own "What was rejected" above already declines a second, `max_length`-bounded
decompression path for exactly this reason), and an `SHT_NOBITS` "prefix" is `b"\\0"`
bytes carrying no evidence either way, so there is nothing a keep-prefix path would
recover for either shape. Giving `.go.buildinfo`'s refusal the same "no error" treatment
`.rodata`/`.comment` now get: rejected, because `strings_bytes_unread` is specifically
the *strings pass* running short across the sections `_collect_string_bytes`
concatenates, and `.go.buildinfo` is parsed separately, outside that pass; reusing the
token for a question it was not built to answer is the same "one vocabulary, two
questions, do not assume they are equal" hazard `AGENTS.md` already names for
`PARTIAL_REASONS`, so `.go.buildinfo` keeps its own token and its own error whenever
the declared size is not honoured, prefix recovered or not -- a smaller, more
conservative change there than for the strings pass, and the one this pass makes.

**A second, quieter effect of the unconditional check itself, independent of the two
gaps above: `_collect_string_bytes`'s post-read truncation branch
(`if len(data) > remaining: buf.extend(data[:remaining]); truncated = True`) is now
unreachable.** `_bounded_section_data` already guarantees `len(data) <= max_bytes`
whenever it does not refuse -- for a compressed section (pyelftools raises
`ELFCompressionError` rather than return a mismatched length, caught one level up as
`unread`), for `SHT_NOBITS` (`data_size` bytes of zero, always), and now for an
ordinary one too (`stream.read(n)` never returns more than `n`). A section whose own
declared size is refused already `continue`s before reaching this check; one that is
not refused cannot produce more bytes than the budget it was measured against. This
was already true for the compressed and `SHT_NOBITS` cases; this fix makes it true for
the one case -- an ordinary section -- that could previously still reach it. Left in
place rather than deleted: it is confirmed dead by this fix's own logic, not by
omission, and removing it is a separate, purely-internal cleanup this fix did not need
to make to close #95.

**What was rejected, for the unconditional check itself.** Keeping the `and` and
adding a second, separate check for the ordinary case: rejected for the reason this
entry's own docstring already gives the compressed/`SHT_NOBITS` split -- `data_size`
means the same 64-bit self-declared size question regardless of shape, so a second
check would just be the same predicate typed twice, the identical objection `#61`'s
own "what was rejected" above raises against a second reader for one fact. Checking
`.dynstr` alone and leaving `.dynsym`'s own size unwidened: rejected above, for
reopening the exact door this fix exists to close on the symbol-table side.

**What it costs.** `ANALYZER_VERSION` moves. An object whose `.dynsym` or `.dynstr`
declares an uncompressed size over `max_strings_bytes` now reads `elf_dynsym_unread`
where it previously read whatever a full, unbounded read produced -- for `.dynsym`
specifically, this is a genuinely new check where none existed in any form before. An
object whose eligible `.rodata`/`.comment` declares an uncompressed size over the
remaining strings budget reads exactly as it did before this fix existed --
`strings_bytes_unread`, no error, whatever fits the budget kept -- now at the cost of
one bounded read instead of a full one; that record is unchanged by this fix, only how
cheaply it is reached. `.go.buildinfo` keeps its existing `elf_go_buildinfo_unread` and
error whenever refused, now with its own recovered prefix reaching `build_go_info`
rather than being discarded first. No `ruleset.toml` change: every token this reuses
was already policy.

**Same class of fix as #63's Mach-O counterpart, ported the other direction.** #63
closes `sizeofcmds` and the symbol/string-table size the same way -- a declared size
checked against a fixed budget before the read it would buy, not clamped to the member
afterwards -- and its own entry below notes explicitly that ELF's
`_bounded_section_data` had not yet closed this for the ordinary case, filing it as
this issue rather than folding it in. This fix is that filing closed. The
prefix-keeping half is also the same choice #63's own entry below draws for Mach-O's
symbol table -- "a capped read is a truncated read, not a refused one" -- applied here
to `.rodata`/`.comment`/`.go.buildinfo` rather than to a symbol table, which is exactly
the boundary "What was rejected" above draws for why `.dynsym`/`.dynstr` do not get the
same treatment yet.

Revisit if a real wheel is found on the triage list whose only incompleteness is an
ordinary section refused by this widened check -- the same admission test `AGENTS.md`
and this entry's own compressed-case revisit note above ask: an honest object this
generous a budget turns incomplete would be the sign the budget itself, not this check,
is too tight for real wheels. Also revisit if a real `.dynsym`/`.dynstr` is found on the
triage list large enough that refusing it outright, rather than capping it the way
`binfmt.macho` caps its own symbol table, costs real symbols a smaller, row-aware cap
would have kept -- the open door "What was rejected" above leaves for porting #63's own
shape to ELF's symbol table.

Tracked in [#62](https://github.com/EmilienM/wheel-crypto-scan/issues/62) and
[#95](https://github.com/EmilienM/wheel-crypto-scan/issues/95).

## sizeofcmds and the symbol table are capped, not just clamped to the member

**Accepted. The same class of fix as #61 and #62, ported to the two places in
`binfmt.macho` that were still measuring a declared 32-bit size against the member
rather than against a fixed budget.**

`_read_thin` read `commands = stream.read(sizeofcmds)` straight from the header's own
`sizeofcmds` field, with only a short-read check after the fact -- no cap before it. A
300 MiB member declaring `sizeofcmds = 0xFFFFFFFF` cost a 300 MiB single read for a
structure that is, honestly, low tens of KiB. `_read_symbols`'s `nsyms` and `strsize`
had the same shape one level down: `_available` -- "measured against the bytes that
exist," per `_Slice`'s own docstring -- clamps a declared table size to the *slice*,
which is exactly right for a slice smaller than any fixed budget and does nothing at
all for one larger. A streamed member well past `wheelfile.ArchiveLimits.
max_in_memory_bytes` is exactly that: `nsyms = 0x0FFFFFFF` over a 300 MiB member cost
24.5s and 664 MiB peak walking roughly twenty million 16-byte rows, each individually
classified as unresolved -- a wrong record (`partial_analysis: true`,
`macho_symtab_incomplete`, the same answer either way), paid for at full member cost.

**Measured, reusing the issue's own numbers plus this fix's own.** Scaled down for a
test suite that can afford to exercise the unfixed path directly: an object declaring
`sizeofcmds = 0xFFFFFFFF` over an honestly-small header, padded to 8 MiB, reads that
whole 8 MiB in one `stream.read()` call unfixed (measured with a `BytesIO` subclass
that records its largest single `read()`, the issue's own reproduction technique) and
`max_strings_bytes` (64 KiB in the test) fixed -- the `sizeofcmds` read is never
attempted at all once it is over cap. A lying `nsyms` over a 4 MiB pad peaks at 4.19
MiB unfixed and under 1 MiB fixed, in both cases well under the wall-clock ceiling
either way at this scale, which is why the memory ceiling is the assertion that
actually discriminates -- the same choice #61 and #62's own bounded-resource tests
make, for the same reason: 300 MiB's worth of wall-clock cost is real at the issue's
own scale but does not reproduce as a reliable *test* signal at a size small enough to
run in a suite, while the byte count read does not need to be flaky to prove the point.

**Two caps, at the two places the issue named.** `_MAX_SIZEOFCMDS` (1 MiB, `binfmt/
macho.py`) is checked in `_read_thin` before `stream.read(sizeofcmds)` runs at all --
real load commands are low tens of KiB even for the busiest fixture #59's or #84's own
tests build, a handful of dylib-loading commands at most, so a cap two orders of
magnitude above that is generous headroom, not a tight fit against anything a real
object does. Past it, `_read_thin` raises `_Unreadable` the same way a truncated
header or unparseable load commands already do, which `_read_slice_header` had one
exception clause rewriting into a generic "failed to parse mach-o load commands" --
now caught and re-raised first, the same special-casing `struct.error` already got,
so the record keeps this cause's own message rather than the catch-all one. No new
`partial_reasons` token: for a thin object this is the one slice that failed to
parse, so `read_macho` falls into the existing `headers` == [] path and reports
`macho_header_unread`, exactly the case that token already names ("the Mach-O header
... would not parse"); for one slice of a fat binary the object already treats any
per-slice `_Unreadable` as `macho_fat_slice_unread` for that slice while the others
still contribute, and this cause is not special enough to want different treatment
than a slice whose magic nobody recognises already gets.

The symbol-table half reuses `max_strings_bytes` itself rather than inventing a
second constant: already threaded into `read_macho` for the strings pass, it is
threaded two calls further down into `_read_slice_symbols` and `_read_symbols` and
taken as a second ceiling on what `nsyms * entry_size` and `strsize` may ask
`_available` for -- `sym_length = _available(sym_start, min(sym_wanted,
max_strings_bytes), end)`, and `strsize` the same way. `sym_wanted` and
`symtab.strsize` themselves stay uncapped in the `truncated` check below
(`len(table) != sym_wanted or len(strings) != symtab.strsize`), so reading less than
declared -- because the slice ran out or because the budget did -- both land exactly
where a genuinely short table already did, `macho_symtab_incomplete`, and the message
it carries ("mach-o symbol table is truncated") is honestly what happened either way.
No new token, no new message, and no new branch.

**This is stricter than `binfmt.elf._symbol_bytes`, not a port of it, and that
difference was found and corrected by review rather than assumed away.** An early
draft of this entry (and the code comment beside it) described the two as mirroring
one another, because `_symbol_bytes` takes the identical `max_table_bytes` parameter
for `.dynsym`/`.dynstr`. Threading the same parameter through is a real parallel;
enforcing it is not the same fact. `_symbol_bytes` reaches every declared table
through `_bounded_section_data`, whose refusal only fires when `section.compressed or
section["sh_type"] == "SHT_NOBITS"` -- #62's own scope, the shapes that reproduction
measured. An ordinary, uncompressed `.dynsym`/`.dynstr` skips that `and` entirely and
reaches `section.data()` unconditionally, so a large *honest* symbol table is read in
full regardless of `max_strings_bytes` today: reproduced directly against `main` at
200,000 real symbols (~4.8 MiB `.dynstr`), `max_strings_bytes=64 KiB`, reads in one
~4.8 MiB call and comes back `partial_analysis: false` -- a fully clean, complete
record, paid for at the size of the honest table rather than the budget. This
reader's cap has no such condition: it applies to `nsyms`/`strsize` unconditionally,
honest table or not, which is what closes it for Mach-O where ELF's own version does
not yet close it for ELF. Filed separately rather than folded in here, the same way
#93 was during #62's own review: #95.

**The walk is bounded per slice, not just the allocation per slice -- and that
qualifier is load-bearing, not decoration.** The issue is explicit that reading the
whole table and then deciding it is too much does not close the cost that mattered
most -- 24.5s of it was the row-by-row walk, not the read. Because the cap here is
applied to `wanted` *before* `_available` ever runs, `table` itself is never longer
than `min(sym_wanted, max_strings_bytes, available)`, so `_iter_symbols` -- the loop
that classified twenty million rows in the issue's own reproduction -- never sees more
than the budget's worth of them for *that slice* to begin with. There is no separate
"read it all, then stop walking partway" step to get wrong within one slice.

That bound does not extend to the object as a whole. `read_macho` calls
`_read_slice_symbols` once per slice, up to `_MAX_FAT_SLICES` (32), and nothing pools
a budget across them -- each slice independently gets up to `max_strings_bytes` worth
of symbol-table walk, so a crafted 32-slice universal binary, each slice lying about
`nsyms` the way the single-slice reproduction above does, still costs on the order of
`_MAX_FAT_SLICES * max_strings_bytes` of walking in total. An independent adversarial
review of this fix measured that shape directly: a crafted 32-slice object costs
roughly 49s post-fix against roughly 54s pre-fix -- the per-slice cap barely moves the
total, because `_MAX_FAT_SLICES` itself, not this cap, is what was already bounding
slice *count*, and slice count times a per-slice budget is still a real number. Memory
does not have the same gap: nothing keeps more than one slice's buffers alive at once,
so peak memory stays flat regardless of slice count, which is the half of "bounded,
not just allocated" that does hold end to end. Left open rather than folded into this
fix: pooling one `max_strings_bytes`-sized budget across every slice of one object,
rather than granting each slice its own, would close the CPU half too, but changes the
shape AGENTS.md already gives fat-binary slices ("independent passes ... over regions
the slices are free to share") and was out of scope for the two reads the issue named.

**A capped read is a truncated read, not a refused one, and that is a deliberate
difference from #62's own choice.** `_bounded_section_data` refuses an oversized ELF
section outright, `(b"", True)`, because `.data()` is an all-or-nothing zlib call with
no cheap way to keep a prefix. Mach-O's symbol and string tables are read through
plain byte-offset slicing, the same mechanism `_available`/`_region` already use for
"the slice ran out," so capping `wanted` to the budget costs nothing extra and keeps
whatever prefix the budget affords, real evidence rather than none: the honest symbol
this fix's own test builds sits at the start of the table, comfortably inside any
budget worth using, and stays in `matched_symbols` after the cap where a "refuse
outright" version of this fix would have thrown it away along with the twenty million
garbage rows. This is the same reading `AGENTS.md` already gives "a structure that
does not parse costs that structure, never the evidence already gathered," applied one
level down: a table that reads over budget costs its own tail, not its own head.

**Interaction checked, not assumed.** #59's dylib-loading-command tests and #84's
load-command-walk tests build a handful of commands each, nowhere near `_MAX_SIZEOFCMDS`;
none needed adjusting and the full suite (`uvx --with tox-uv tox`) stayed green
unmodified except for the new tests themselves. Three boundary pairs pin all three
caps at their own edge, `nsyms` and `strsize` each isolated from the other by keeping
the sibling field honest and small: `sizeofcmds` exactly at `_MAX_SIZEOFCMDS` reads
its commands in full (`needed` and `soname` both survive, no error), one byte over is
refused before the read is attempted; an honestly-declared symbol table whose byte
count lands exactly on the budget reads complete, one real entry more is
`macho_symtab_incomplete` even though every byte of it is genuinely present in the
object; a string table declared exactly at the budget, over an honest and otherwise
tiny symbol table, reads complete the same way, one byte more is
`macho_symtab_incomplete` too -- the same "more than, not at least" boundary #62's own
entry above drew for the identical shape of check, now drawn for all three.

**The `strsize` half of the cap shipped without a test of its own in the first version
of this fix, and an independent adversarial review caught it before this entry was
accepted as final.** Reverting only `str_length`'s `min(symtab.strsize,
max_strings_bytes)` back to plain `symtab.strsize`, leaving `sym_length`'s cap and the
`sizeofcmds` cap both untouched, left the entire suite green -- the `nsyms` boundary
test above only ever varied `nsyms`, so nothing exercised `strsize`'s own edge.
`test_strsize_exactly_at_the_budget_is_read_while_one_byte_over_is_incomplete`
(`tests/test_binfmt_macho.py`) and
`test_a_mach_o_string_table_declaring_more_than_the_budget_does_not_allocate`
(`tests/test_hardening.py`) close that: reproduced directly, `strsize` declaring 2 MiB
over a 64 KiB budget peaks at 4.19 MiB unfixed against under 1 MiB fixed, the same
shape and the same ceiling the `nsyms` hardening test above already uses, and both new
tests were confirmed to fail cleanly, on the same assertions, with the cap reverted by
hand and restored to pass again afterward.

**The `except _Unreadable: raise` routing clause was similarly untested on its own.**
Deleting it left the suite green too: `partial_reasons` and `error.kind` are unchanged
either way, because a generic `except Exception` still produces `macho_header_unread`
from the same `_unparsed` path. What the clause actually buys is the recorded error
*message* -- `"sizeofcmds is N bytes, over the M-byte cap on load commands"` instead of
the catch-all `"failed to parse mach-o load commands"` -- which nothing was asserting
on. `test_sizeofcmds_exactly_at_the_cap_is_read_while_one_byte_over_is_refused` now
pins the exact message text for the over-cap case, and was confirmed to fail with the
clause removed and pass with it restored.

**What was rejected.** A single shared constant for both caps: `sizeofcmds` and the
symbol/string tables are declared by different fields for different reasons, and
tying them to one number would make changing either bound to fit real load commands or
real symbol tables risk moving the other for no reason connected to it -- `_MAX_SIZEOFCMDS`
stays its own constant, sized off load commands; the symbol-table budget reuses
`max_strings_bytes`, the parameter this reader was already threading through for
exactly this kind of question, rather than adding a `_MAX_SYMTAB_BYTES` beside it that
could only ever drift from it. Refusing the whole symbol/string table outright once
`nsyms`/`strsize` is over budget, `_bounded_section_data`'s own shape: rejected above,
for losing evidence a bounded prefix read does not have to.

**What it costs.** `ANALYZER_VERSION` moves: a Mach-O object whose `sizeofcmds` or
whose symbol/string table declares more than these caps now reads incomplete at the
cap rather than after paying to read the whole declared size, which for a real,
honestly-small object changes nothing -- the caps sit two to three orders of magnitude
above what #59's and #84's own fixtures need. Nothing in `ruleset.toml` changes: both
tokens this reuses were already policy, so `ruleset_version` does not move.

**`macho_header_unread`'s wording needed nothing new; `macho_symtab_incomplete`'s
needed one clause, and an earlier version of this entry claimed neither did, on
reasoning that held for one token and not the other.** "Would not parse" already
covers a header refused for declaring more than this reader will read, the same
conclusion #62's own entry draws for "refused before" and "raised inside" being the
same fact for a consumer -- that part of the earlier claim was right. It does not
carry over to `macho_symtab_incomplete`: its existing wording ("declared entries this
reader could not take at their word: unreachable, naming strings it does not hold,
holding nothing but debug records, or declaring fewer entries than the string table
holds names for") is a closed list of ways the *object* fell short, and none of them
describe an honest, fully-present table the *reader* chose to stop reading at its own
budget. Read literally, the existing sentence would tell a consumer every occurrence
of this token means the object lied, which stops being true the moment a cap can fire
on an honest table. SCHEMA.md and `data/schema.json` (kept in step, per `AGENTS.md`)
both gained one added clause covering the budget case, naming it as a reader-side
stop rather than an object-side fault.

**`wheelfile.ArchiveLimits`'s docstring is corrected, not fully closed -- an earlier
draft of this entry, and of the docstring itself, overclaimed the second half and was
caught by an independent adversarial review before being accepted as written.** The
docstring's original claim was that streaming instead of holding a member whole is
what bounds memory past `max_in_memory_bytes` -- true of this module's own choice
between `io.BytesIO` and `SeekableZipMember`, and never what was broken. What was
broken is one level up: a reader built on top of a correctly-streamed member could
still pull most of it through the stream into its own retained `bytes`, which defeats
the point of streaming even though `WheelArchive` itself never lied. The docstring now
says so explicitly, and points at `binfmt.strings.MAX_STRINGS_BYTES` as the budget a
reader is expected to hold itself to on top of the streaming decision.

That is true of `binfmt.macho` as of this fix. It is **not** true of `binfmt.elf`
today: an early version of this entry claimed it was, on the strength of the issue's
own line that "the ELF strings pass is bounded by `max_strings_bytes`" -- true of the
*accumulated* buffer `_collect_string_bytes` builds across sections, and not the claim
that matters here, which is whether any *single* section's read is bounded before it
happens. It is not, for an ordinary uncompressed section: `_bounded_section_data`
(#62) only refuses before `.data()` runs when the section is `compressed` or
`SHT_NOBITS`, so a large honest `.rodata` or `.dynsym`/`.dynstr` still reads in full
first and only the running total gets cut afterward -- reproduced directly against
`main` post-#63 at an honest 8 MiB `.rodata` (`max_strings_bytes=64 KiB`): one 8 MiB
`read()`, 8.6 MiB peak, in a record `_collect_string_bytes` still reports as merely
`strings_bytes_unread`. The corrected docstring says this plainly rather than
asserting the gap closed, and points at #95, filed to track it rather than folded into
this fix -- the same "found a related gap, filed separately" shape #62's own review
gave #93. Closing #95 is not this fix's job: the two reads this issue named are
Mach-O's `sizeofcmds` and `nsyms`/`strsize`, and both are closed. Nothing about this
fix required falling back to the issue's own honest-ceiling formula, `jobs *
(max_member_bytes + max_strings_bytes)`, for Mach-O specifically; the docstring's
worst-case sentence is written in terms of the still-open ELF gap instead, which is
the more honest number until #95 lands.

Revisit if a real Mach-O object is found on the triage list whose only incompleteness is
one of these two caps -- the same admission test `AGENTS.md` asks of the carve-out list,
applied here to a cap rather than an exemption: an honest object this generous a cap
turns incomplete would be the sign `_MAX_SIZEOFCMDS` or the symbol-table budget is
tighter than real Mach-O objects, not just tighter than an attacker's.

Tracked in [#63](https://github.com/EmilienM/wheel-crypto-scan/issues/63).

## A record produced without reading the wheel is never cached

**Accepted.**

`scan_wheel`'s outer `except Exception` -- the one AGENTS.md's "one bad wheel never
aborts a run" names outright -- caught everything `_collect` could raise and recorded
it under `errors.BAD_ZIP`, "Not a readable zip at all." That claim is specific and was
wrong for this branch: a `MemoryError` under load, or any other exception `_collect`
did not specifically anticipate, says nothing about whether the archive itself is
readable. `cli._scan_path` then cached that record under the wheel's content hash
unconditionally, so one transient failure made a wheel permanently `OPAQUE`: every
later run, `--resume` included, served the same stale record back and never called
`_collect` again, even though the condition that interrupted it was long gone.
Reproduced directly: `_collect` monkeypatched to raise `MemoryError` on exactly its
first call, `cli._scan_path` invoked twice against the same wheel and a fresh
`RecordCache` -- on `main` before this fix, the second call returns the first call's
cached line and `_collect` is never called again, even though the second attempt would
have read the wheel correctly and found its real `hashlib.md5` call.

**What changed.** Two independent pieces, both small.

First, the outer `except Exception` now records `errors.UNEXPECTED_ERROR`
(`"unexpected_error"`) instead of `errors.BAD_ZIP`. `BAD_ZIP` stays reserved for what
it already specifically means: `WheelArchive.__init__` catching `zipfile.BadZipFile`,
`OSError` or `ValueError` while opening the archive, and `WheelArchive.read` catching
the same trio (plus `EOFError`) while reading a member -- both genuine, checked claims
about the archive's own bytes, and both already routed through `errors.WheelReadError`
rather than the broad catch. `WHEEL_SCAN_INTERRUPTED`, a sibling of `WHEEL_UNREADABLE`
in `data/ruleset.toml` rather than an extension of it, claims the new kind: same
`OPAQUE` verdict, same `needs_human_review`, because absence of evidence is still not
evidence of absence regardless of why the evidence is absent -- but its own `why`, not
`WHEEL_UNREADABLE`'s "not a readable zip at all," which would have been exactly the
false claim this fix removes.

Second, `cli._scan_path` no longer caches a record carrying one of a small set of
kinds, and `cli._existing_records` (what `--resume` reads back) drops one the same way
rather than treating it as already done. Both consult one fact,
`errors.SCAN_ABORTED_KINDS`, in the shape AGENTS.md already gives `FORMAT_*` and
`PARTIAL_REASONS`; which of them is safe to skip caching for lives in `cli.py`, where
the caching decision was already made.

**Narrow versus broad, and why broad -- and why the first version of "broad" was
still wrong.** The issue that reported this named two options: skip caching only for
the new kind, since that is the only one that is genuinely non-deterministic; or skip
it for both `BAD_ZIP` and `UNEXPECTED_ERROR`, since a genuinely malformed zip is cheap
to re-fail regardless -- nothing past `zipfile.ZipFile()` ever runs for either kind,
so there is no real scan to redo either way. This entry originally read "skip caching
any archive-stage error" as broader than either option and wrong, on the grounds that
`DUPLICATE_MEMBER`, `SIZE_LIMIT_EXCEEDED`, `COMPRESSION_RATIO_EXCEEDED` and
`MEMBER_READ_ERROR` are all recorded *alongside* a scan that otherwise ran to
completion, so skipping the cache for any of them throws away a real, expensive answer
for no benefit. That reasoning is right for the first three and wrong for the fourth,
and an independent adversarial review caught it before this entry was accepted as
final: "recorded alongside a completed scan" and "safe to cache" are not the same
question. `DUPLICATE_MEMBER`, `SIZE_LIMIT_EXCEEDED` and `COMPRESSION_RATIO_EXCEEDED`
(and `BINARY_TOO_LARGE`, which was never in this discussion because it never reaches
this vocabulary from a `MEMBER_READ_ERROR`-shaped path) are computed purely from zip
metadata already fully in hand -- a filename seen twice, a size field compared to a
limit -- with no I/O and no broad exception catch anywhere on the path that records
them, so the same wheel's bytes always produce the same one and caching is genuinely
safe. `MEMBER_READ_ERROR` looks like it belongs in that group because it is also
member-scoped rather than scan-aborting, but every site that records it
(`wheelfile.read`, `layers/binaries.py`'s two catches around `open_member` and
`read_binary`, `layers/metadata.py`'s three, `layers/python_ast.py`'s one) reaches it
through a catch exactly as broad as the one this whole fix is about -- `except
Exception`, or a name tuple wide enough to include `MemoryError` and `OSError`
alongside a genuinely corrupt member -- so it carries the identical risk `BAD_ZIP` and
`UNEXPECTED_ERROR` do: a transient failure permanently reads as a missing finding for
that one object, cached and served back forever. The axis that actually decides
whether caching a kind is safe is determinism, not "does the scan otherwise complete"
or "is re-deriving it cheap" -- those happened to point the same way for the first
three kinds and not for this one. `SCAN_ABORTED_KINDS` is `{BAD_ZIP, UNEXPECTED_ERROR,
MEMBER_READ_ERROR}`: every archive- and member-stage kind this fix could find that
cannot yet be proven deterministic, not every kind that aborts a scan or every kind
cheap to redo, and not a claim that nothing else in the tool shares this shape. It does
not reach `binfmt/`'s own `except Exception` catches (`binfmt/elf.py`, `macho.py`,
`pe.py` each have several, recording `elf_parse_error`/`macho_parse_error`/
`pe_parse_error` as `ScanError`s one layer below `MEMBER_READ_ERROR`), which have the
identical risk and are out of this fix's scope -- see "Revisit if" below.
`test_a_completed_scan_with_a_recorded_archive_error_is_still_cached` pins the three
kinds that do stay cached, with a wheel carrying a genuine `duplicate_member` error
and a real Python finding still found in the cache after the run that produced it;
`test_a_transient_member_read_failure_is_retried_not_cached` pins the corrected
kind, `read_binary` monkeypatched to raise `MemoryError` on exactly its first call
against a wheel linking `libsodium.so.23` -- the first attempt records
`member_read_error` with `binaries: []` and comes out `OPAQUE`, the second is not
served from a cache entry the first attempt would otherwise have written, and finds
the real linkage.

**What was rejected.** Letting a `MemoryError`-class failure propagate out of
`scan_wheel` instead of being caught at all, so the run stops rather than mislabels.
Rejected on the same grounds `scan_wheel`'s own docstring already gives: a scan of
tens of thousands of wheels that aborts on the first `MemoryError` loses every wheel
after it, which is a worse outcome than one wheel temporarily `OPAQUE`. The existing
`except Exception` stays; only what it records and whether that record is trusted as
final changed.

**What it costs.** `ANALYZER_VERSION` moves: a wheel that previously hit the broad
`except Exception` branch serialized `errors: [{"kind": "bad_zip", ...}]` with
`WHEEL_UNREADABLE` in `verdict.rule_ids`, and now serializes `unexpected_error` with
`WHEEL_SCAN_INTERRUPTED` instead -- an unchanged wheel hitting that exact path
produces a different record. That bump also has a useful side effect: it invalidates
every cache entry written under the old, mislabelled kind, so a wheel already stuck
`OPAQUE` from a past transient failure gets re-attempted by this fix too, not just
wheels that fail from here on. `ruleset_version` moves for `WHEEL_SCAN_INTERRUPTED`
itself. `schema_version` does not: `errors[].kind` is an open string with no
enumerated values in `data/schema.json`, the same "new value, no bump" shape
`SCHEMA.md` already documents for `partial_reasons`.

Adding `MEMBER_READ_ERROR` to `SCAN_ABORTED_KINDS` moved neither version by itself.
`ANALYZER_VERSION` governs whether an unchanged wheel produces a different *record*,
and this correction changes only whether a record already produced gets cached --
`scan_wheel`'s own output for a `MEMBER_READ_ERROR` wheel is exactly what it always
was. It piggybacks on the bump above for a different reason: this whole fix was still
an unreleased, unpushed commit when the correction landed, amended into it rather than
shipped separately, so there was no earlier released `ANALYZER_VERSION = 27` whose
cache entries needed invalidating -- nothing has run this code with `MEMBER_READ_ERROR`
excluded from the skip set outside this branch. Had the narrower version already
shipped, correcting it afterward would need the same bump the `bad_zip` ->
`unexpected_error` relabelling took above, for the same reason: forcing re-evaluation
of whatever the narrower version had already cached wrongly.

Revisit if a real corpus run turns up a wheel where `UNEXPECTED_ERROR` or
`MEMBER_READ_ERROR` fires repeatedly rather than transiently -- a deterministic bug
masquerading as a transient one would mean the cache is doing pointless work
re-attempting a wheel that will never read cleanly, which is the same admission test
AGENTS.md asks of the `partial_reasons` carve-out, applied here to a kind instead: go
and find a wheel this reads as "eventually fine" that never actually is. Also revisit
if `layers/binaries.py`, `layers/metadata.py` or `layers/python_ast.py` ever grows a
narrower catch that can tell a genuine content defect from a transient interruption
apart for `MEMBER_READ_ERROR` specifically, the way this fix gave `_collect`'s own
top-level catch `UNEXPECTED_ERROR` instead of leaving it inside `BAD_ZIP` -- at that
point the narrower kind, not `MEMBER_READ_ERROR` itself, is what belongs in this set.

`binfmt/elf.py`, `binfmt/macho.py` and `binfmt/pe.py` each catch broadly around their
own parsing and record `elf_parse_error`/`macho_parse_error`/`pe_parse_error`, one layer
below where `MEMBER_READ_ERROR` is produced -- the identical shape, not extended to here
because it is a materially larger surface (many catch sites across three readers) than
this fix's scope. Tracked separately in
[#97](https://github.com/EmilienM/wheel-crypto-scan/issues/97).

**#97's follow-up: binfmt's own parse-error kinds.** **Accepted, on a corrected audit.**
The audit that entry asked for was run twice: the first pass claimed every recording
site in all three readers was, or fell through to, a broad `except Exception`, and that
none of the three had a genuinely narrow catch. Adversarial review checked this against
the actual code and found both halves wrong. `elf.py` has nineteen sites that can record
`elf_parse_error`, not ten, and thirteen of them are bare `if`/`elif` comparisons over
data already fully in hand -- the same shape as #64's own excluded
`DUPLICATE_MEMBER`/`SIZE_LIMIT_EXCEEDED`, not an `except` block at all. One of them,
"more than one `SHT_DYNSYM` section, which is real cannot be told", is a purely
structural check with no exception anywhere near it. `macho.py` has no recording site
lexically inside a handler at all; every `macho_parse_error` is emitted from a flag or
reason string a broad catch set earlier, which is still eventually traceable to a broad
catch, but not the "narrows the message, still falls through" shape the first pass
described. `pe.py`'s `except _Malformed` is a real, narrow, deterministic-only catch:
`_Malformed` is raised at exactly seven points inside `_read_headers`, every one a pure
comparison over `raw`, and grepping the whole file confirms no exception is ever wrapped
into it -- a `MemoryError` or a flaky read cannot reach that branch. Corrected count: the
*majority* of what records these three kinds is deterministic, not the minority the
first pass claimed, and one of the three readers already has the "genuinely narrow,
exception-type-specific catch" the "Revisit if" clause below used to say would trigger a
revisit.

None of that changes the conclusion, only its honesty. Each reader also has at least one
real broad catch that can record the identical token for a transient reason
(`elf.py:592`/`:702`, `macho.py:454`/`:697`/`:752`, `pe.py:360`), and `ScanError.kind` is
the only granularity this vocabulary offers to tell a run's cause apart from another
run's (see "What NOT to do" in #97 itself): a kind reachable through a broad catch
*anywhere* belongs in `SCAN_ABORTED_KINDS` entirely, not the specific call that happened
to raise on a given run, so all three still join it -- deliberately accepting that the
deterministic majority rides along uncached too, which "What it costs" below now says
plainly instead of denying it has a majority to ride along.

**What changed.** `errors.SCAN_ABORTED_KINDS` gains `ELF_PARSE_ERROR`,
`MACHO_PARSE_ERROR` and `PE_PARSE_ERROR`. `cli.py` needed no change: `_scan_path` and
`_existing_records` already consult the set generically through `_scan_was_aborted`,
which is the whole reason this follow-up is three lines of vocabulary rather than a
second copy of the caching logic.

**Reproduction, adapted per format.** A single transient `MemoryError` inside
`elf.py`'s own `.dynamic` reading (patched onto `_validated_strtab`, which both the
`.dynamic` and `.dynsym` blocks call): the first attempt records `elf_parse_error`,
`needed: []` -- the `libsodium.so.23` dependency lost the same way DECISIONS.md's own
#64 entry describes -- and comes out `OPAQUE`; the second is not served from cache and
recovers `needed` and `libsodium_linkage: system`.
`test_a_transient_elf_parse_failure_is_retried_not_cached` pins it, plus
`test_resume_does_not_treat_an_aborted_elf_scan_as_already_done` for `--resume`. The
same shape holds for `macho.py` (`_read_thin` patched, an `LC_LOAD_DYLIB` dependency
lost then recovered: `test_a_transient_macho_parse_failure_is_retried_not_cached`) and
`pe.py` (`_read_imports` patched, an imported DLL lost then recovered:
`test_a_transient_pe_parse_failure_is_retried_not_cached`), all in `tests/test_cli.py`
beside the #64 tests they extend.

**What it costs.** No version bump, of either kind. `ANALYZER_VERSION` governs whether
an unchanged wheel produces a different *record*; this change touches nothing in
`scan_wheel`'s own output for a given attempt, only whether a record already produced
gets cached or read back by `--resume` -- the same reasoning #64 gave for adding
`MEMBER_READ_ERROR` to this set, and the same non-bump. `ruleset_version` does not move
either: `data/ruleset.toml` is unchanged, `BIN_UNPARSEABLE` already matched these three
kinds before this fix and still does.

Two real costs the first draft of this entry did not record. First: a permanently
malformed object -- the corrected audit above shows this is the common case, not the
rare one -- is now re-read in full on every scan, forever, rather than cached after the
first failure. Measured on a real ~13 MiB object with two `SHT_DYNSYM` sections (a
purely structural `elf.py` check, no exception involved): 0.965s to fail once, then
0.001s on every later run before this fix, 0.974s on every later run after it -- roughly
a thousand-fold cost, paid every time, for a wheel whose bytes can only ever produce the
same answer. This is the opposite of why `bad_zip` was accepted into this set: that
kind aborts `_collect` before any real read happens, so re-failing it is cheap; these
three are recorded *after* the strings pass (up to `MAX_STRINGS_BYTES`, 64 MiB per
object) and the symbol-table walk already ran, so re-failing them is the most expensive
thing this scanner does. It is also, for the `elf.py:657` "declares more bytes than the
budget allows" site specifically, the identical shape `SIZE_LIMIT_EXCEEDED` is excluded
from this set *for*, given the opposite treatment. The trade is accepted anyway, on the
same principle #64 leads with: losing real evidence to a stale cache costs more than an
expensive, correct re-scan, and there is no cheaper way to split a deterministic
occurrence of one of these kinds from a transient one without a narrower token than
`ScanError.kind` currently carries -- but it is a real, ongoing cost, not a free lunch.

Second: this fix is prospective only. A cache entry already poisoned by a transient
failure under pre-fix code is still served verbatim after this fix ships, because
`cli._scan_path` returns a cache hit before `_scan_was_aborted` is ever consulted, and
neither version bump above forces re-evaluation of it. Anyone who already hit this bug
stays stuck until they clear their cache by hand or until an unrelated version bump
forces re-evaluation for some other reason. Matches #64's own precedent for
`MEMBER_READ_ERROR`, which has the same property and was accepted the same way; stated
here rather than left implicit.

**What was deferred, and closed in #109 below.** `layers/python_ast.py` turns a `RecursionError` into
`PYTHON_SYNTAX_ERROR`, which shares the non-determinism risk -- the interpreter's stack
depth at scan time, not the wheel's bytes, decides whether it fires. It is a materially
different problem from the three kinds above, though: `PYTHON_SYNTAX_ERROR` is also
recorded for a null byte in the source and for a real `SyntaxError` from `ast.parse`,
both genuinely deterministic given the same bytes, so the kind is mixed rather than
uniformly one thing or the other the way `elf_parse_error` and its siblings turned out
to be. Excluding the whole kind from caching the way this fix excludes the three
`*_parse_error` kinds would mean re-scanning every source file with an ordinary,
permanent syntax error on every run, for no benefit; the token alone cannot tell
`RecursionError` apart from a real `SyntaxError` the way #97 itself says the token alone
cannot be split within a kind. Left out of this fix, which #97's own title and scope
name as the three `*_parse_error` kinds specifically. A correct fix needs either a
narrower token for the `RecursionError` branches or some other way to carry which cause
fired past the point `ScanError.kind` currently collapses it, which is a distinct,
narrower piece of work.

**Revisit if** `ScanError.kind` ever grows the ability to distinguish a deterministic
structural defect from a transient interruption within one of these three kinds --
`pe.py`'s narrow `except _Malformed` already proves a genuinely deterministic-only catch
can exist for one shape of `pe_parse_error`, but the *token* it records is the same one
a broad catch elsewhere in `pe.py` can also produce, and that collapse, not the absence
of a narrow catch, is what keeps the whole kind in this set. Splitting the token itself
-- a distinct kind for `_Malformed`'s deterministic shape, versus the broad-catch one --
would let the deterministic majority measured above be cached again without losing the
transient-safety this fix exists for; the same "revisit" clause above gives
`MEMBER_READ_ERROR`, applied here to three kinds instead of one. Also revisit
`PYTHON_SYNTAX_ERROR` once there is a way to
split its `RecursionError` occurrences from its deterministic ones; until then it stays
outside `SCAN_ABORTED_KINDS`, on the grounds that re-scanning a permanent syntax error
forever costs more than an occasional `RecursionError` staying cached.

### Closed in #109: a distinct kind splits `RecursionError` from `PYTHON_SYNTAX_ERROR`

**Accepted.** The narrower token this entry's own "what was deferred" paragraph named
as the missing piece: `errors.PYTHON_RECURSION_LIMIT_EXCEEDED`, recorded by
`layers/python_ast.py`'s two `except RecursionError:` sites (`ast.parse` and the
`_collect_sites` tree walk) instead of `PYTHON_SYNTAX_ERROR`. The two sites share the
new kind and the same message, since both are equally "not the wheel's bytes
deciding this" from a consumer's point of view. `PYTHON_SYNTAX_ERROR` keeps its two
remaining, genuinely deterministic occurrences -- the deliberate null-byte check and
a real `SyntaxError` from `ast.parse` -- and stays out of `SCAN_ABORTED_KINDS`,
exactly as this entry already argued it should for the reason it gives above. The new
kind joins `SCAN_ABORTED_KINDS` instead, on the identical reasoning #97 gives the
three `*_parse_error` kinds: every site that can record it is the same narrow catch,
not a mix of deterministic and transient causes the token cannot tell apart.

`ANALYZER_VERSION` moves: a wheel that previously hit the `RecursionError` path now
records a different `errors[].kind` for an unchanged input.
`data/ruleset.toml`'s `PY_UNREADABLE` rule (`error_kinds`) gained the new token
alongside the three it already claimed, so the finding, verdict and severity are
unchanged for this shape -- only the kind string and its caching behaviour move.
`ruleset_version` moves for the `error_kinds` edit.

Tests reproduce both sites via monkeypatching `ast.parse` and `_collect_sites`
directly, deliberately rather than via a deeply-nested source literal: which
construct actually exhausts the interpreter's C stack, as opposed to failing a
`SyntaxError` guard first (`"too many nested parentheses"` fires for 300-deep
parens/brackets on this interpreter, well before any `RecursionError` would), is
itself interpreter-version dependent, and this fix's whole point is to be pinned
regardless of that. A CLI-level test mirrors
`test_a_transient_elf_parse_failure_is_retried_not_cached`'s shape one layer up: a
first scan hits the monkeypatched `RecursionError`, and a second, unpatched attempt
is confirmed not to be served the first attempt's stale, evidence-free record.

Tracked in [#109](https://github.com/EmilienM/wheel-crypto-scan/issues/109).

Tracked in [#97](https://github.com/EmilienM/wheel-crypto-scan/issues/97), itself
tracked from [#64](https://github.com/EmilienM/wheel-crypto-scan/issues/64).

Tracked in [#64](https://github.com/EmilienM/wheel-crypto-scan/issues/64).

## `.exe` joins `_BINARY_SUFFIX`, and stops there

**Accepted, the simpler of the two options the issue itself named.**

`is_binary_member` accepted a member by suffix (`_BINARY_SUFFIX`), by vendor path, by
living in a sniff directory with no dot in its name, or by the executable bit with no
dot in its name. `.exe` failed every route: the wrong suffix, and its own dot
disqualified it from both "no dot" fallbacks. It was never even sniffed for magic
bytes, so a Windows executable shipped in a wheel was invisible to the scanner while
the identical bytes, shipped suffix-less on the Linux build of the same tool, were
read correctly.

```
pkg-1.0.data/scripts/openssl       (win_amd64)  -> class=CONDITIONAL  openssl_linkage=static  extensions=1
pkg-1.0.data/scripts/openssl.exe   (win_amd64)  -> class=NO_CRYPTO_DETECTED  review=False  extensions=0
```

**What changed.** `_BINARY_SUFFIX` gained one alternative: `exe`. Nothing else in
`layers/binaries.py` moved. `binfmt.pe` already keys a PE read on the optional
header's magic, not on any DLL-versus-EXE distinction, so an `.exe` member is read by
the exact same code path a `.pyd` or `.dll` already was; this is a member-
classification fix, not a new reader.
`tests/test_acceptance.py::test_the_exe_and_suffixless_forms_produce_the_same_record_but_for_the_path`
pins the issue's own reproduction pair directly: the same PE bytes at
`pkg-1.0.data/scripts/openssl` and `pkg-1.0.data/scripts/openssl.exe` now produce the
identical verdict, linkage and extension count, differing only in the path each was
shipped at.

**What was rejected.** The issue's second option: sniffing by magic for anything
under a sniff directory regardless of extension, which would also cover `.com`,
`.cpl`, `.sys`-style oddities and a dotted, suffix-less Mach-O tool name. The issue
frames its own two options as alternatives, not a pair to both take, and its concrete
concern -- `cmake.exe`, `node.exe`, the Windows build of a tool wheel reading
differently from its Linux build -- is a `.exe` problem, not evidence of wheels
shipping `.com`, `.cpl` or `.sys` members. Extending the suffix regex to those three as
well was considered and rejected too, for the same reason inverted: adding a suffix to
policy on the strength of "it would also be covered by the alternative" rather than a
measured, real case is exactly the kind of unmeasured addition `AGENTS.md` already
asks every ruleset entry to justify with a `why`, and there is no `why` here beyond
"it exists as a Windows extension." A member the scanner still does not sniff by
suffix keeps its prior behaviour (invisible to the scanner), not a worse one, so
nothing already working regresses by leaving them out; the full magic-sniff option
remains available if a real wheel ever needs it.

**What it costs.** `ANALYZER_VERSION` moves (27 -> 28): every wheel carrying a `.exe`
member now produces a different record than it did, as the issue's own text notes.
`ruleset_version` and `schema_version` do not move: no rule, symbol, library or
verdict changed, and the record shape is unchanged, only which members are read.

Revisit if a real `win_amd64` wheel is found shipping crypto-relevant evidence in a
`.com`, `.cpl` or `.sys` member, or in a dotted, suffix-less executable of another
format -- at that point the issue's second option, sniffing by magic under a
recognised directory regardless of extension, is the one to take, rather than growing
`_BINARY_SUFFIX` one exotic extension at a time.

Tracked in [#65](https://github.com/EmilienM/wheel-crypto-scan/issues/65).

## The loader moves to `ruleset_loader.py`, a sibling module, not a package

**Accepted. Pure refactor: no rule, symbol, library or verdict changed.**

`ruleset.py` had grown to four responsibilities in one file: the object model
(`Rule`, `Conventions`, `Ruleset` and the rest), the prefilter (`_symbol_locator`,
next to `SymbolGroup.matches` it mirrors, per `AGENTS.md`), the compiled-pattern
builder (`Ruleset.compile_patterns`, `BinaryPatterns`/`PythonPatterns`), and the TOML
parser and validator (`parse_ruleset`, `load_ruleset`, and everything only they call).
The file had reached 1000 lines against pylint's default `max-module-lines`, and a
later, unrelated fix (#84) raised the limit to 1100 to give `binfmt/macho.py` room --
which also gave this file slack it hadn't earned. The issue's own point survives that:
raising the limit again papers over four responsibilities sharing one file, it doesn't
reduce them.

**What changed.** The parser -- `_parse_conventions`, `_parse_linkage_policy`,
`_parse_rule`, `_parse_matches`, every `_validate_*` and `_entry_*` helper,
`_check_limits_leave_room_for_every_key`, `parse_ruleset`, `load_ruleset`, and the two
generic helpers only they used (`_require`, `_check`) -- moved to a new sibling module,
`ruleset_loader.py`. `ruleset.py` keeps the object model, the vocabulary constants
(`MATCHER_KINDS`, `SEVERITIES`, `ENTRY_TABLES`, `ROUTED_KINDS`, and the rest -- read
by the loader's `_check` calls and by the test suite that pins them, but describing the
schema rather than how to walk it, so they stayed with the model they describe), and
`_symbol_locator` beside
`SymbolGroup.matches`. `ruleset.py` is now 541 lines; `ruleset_loader.py` is 500.
Both sit well under the old 1000-line default, with headroom to spare before either
approaches it again.

**Sibling module, not a `ruleset/` package.** The issue sanctioned both. `binfmt/` and
`layers/` are packages in this codebase because each holds several *parallel* things --
one reader per binary format, one extractor per evidence layer. This split isn't
parallel siblings, it's one concern (the ruleset) divided by responsibility (model vs.
parser), the same shape as `record.py`/`verdict.py` already sitting as flat sibling
modules. A package would have meant an equivalent two-file split one directory deeper
for no structural gain, so the sibling module matched the existing convention better.

**Re-exporting from `ruleset.py` was tried and rejected.** The obvious way to keep
every `from .ruleset import load_ruleset` working unchanged is to import
`ruleset_loader`'s functions back into `ruleset.py`. That was implemented first: a
bottom-of-file `from .ruleset_loader import load_ruleset as load_ruleset` (the
self-alias PEP 484 uses for explicit re-exports), needed at the bottom rather than the
top because `ruleset_loader` needs the object model above it to exist first. It parsed,
ran, and produced byte-identical output -- `tox` was fully green under it -- but
`pylint` correctly called it what it is: `wheel_crypto_scan.ruleset` and
`wheel_crypto_scan.ruleset_loader` import each other, a genuine cycle
(`cyclic-import`), on top of a `wrong-import-position` and a `useless-import-alias` the
self-alias idiom needs at every call site to silence. Suppressing four separate,
stacked warnings to keep one import direction working is worse than the thing it
avoids: touching call sites. The loader depending on the model it validates against is
the natural direction; asking the model to import back from its own validator is what
manufactured the cycle, not the split itself.

**What it costs.** Every import of `load_ruleset`, `parse_ruleset` or
`routine_reasons` moved to `from .ruleset_loader import ...` (or
`wheel_crypto_scan.ruleset_loader` in tests): one line in `cli.py`, and one import
line each in 20 test files (a handful needed the import split across two lines because
they'd imported an object-model name and a loader name together, e.g.
`from wheel_crypto_scan.ruleset import PythonPatterns, load_ruleset`). No test's
assertions or fixtures changed, only their imports. Everything that already imported
only object-model names -- `Ruleset`, `Conventions`, `BinaryPatterns`, `StringGroup`,
`Limits`, the vocabulary constants -- needed no change at all, since none of that
moved.

**What was rejected.** Raising `max-module-lines` again, which is the option the issue
itself argues against: the file was fragile to the next three-line addition, not
short on numeric slack. The `ruleset/` package layout, for the reason above. Re-export
via the bottom-import/self-alias trick, for the cyclic-import reason above. Option 2
from the issue -- pulling `Conventions`/`SonameInfo` (~115 lines) into their own
`conventions.py` -- was also considered and left alone: option 1 alone leaves
`ruleset.py` under half the old limit, `linkage.py` and `engine.py` already import
`Conventions` by name, and a further split neither of them asked for would be moving
code to move it rather than fixing a real fragility.

**Revisit if** `ruleset.py` or `ruleset_loader.py` approaches 1000 lines again on its
own -- at that point option 2 (splitting `Conventions`/`SonameInfo` out) is the next
lever, not a bigger `max-module-lines`.

Tracked in [#66](https://github.com/EmilienM/wheel-crypto-scan/issues/66).

## More than one LC_ID_DYLIB or LC_SYMTAB is ambiguous, not last-wins

**Accepted. The Mach-O counterpart of #56's `elf_section_type_ambiguous`, and it
changes records.**

`_read_thin`'s load-command walk set `soname = name` on every `LC_ID_DYLIB` it
reached, and built a fresh `_Symtab` on every `LC_SYMTAB`, both unconditionally: a
second command of either kind silently overwrote the first, and the walk never
counted how many it had seen. `linkage._binary_posture` reads `soname` first, through
`conventions.own_base`, to decide whether the object itself *is* a named library --
the `vendored_path and own_base(...) in sonames` check that fires before `needed` is
even consulted -- so a decoy `LC_ID_DYLIB` is load-bearing for the verdict, not
cosmetic, and a decoy `LC_SYMTAB` is load-bearing for the imported/defined split the
whole tool turns on.

Reproduced on a wheel bundling `libcrypto` under a neutral member name, with the
install name as the only signal tying the object to that identity and a second, decoy
`LC_ID_DYLIB` appended:

```
honest LC_ID_DYLIB, single             -> openssl_linkage: bundled, needs_human_review: true
honest LC_ID_DYLIB + decoy appended    -> openssl_linkage: none,    needs_human_review: false
```

The decoy is not merely ignored -- `own_base` reads whichever name the walk reached
last, so the record actively misreports the object's own identity, and the wheel's
`openssl_linkage` was left with nothing to say the object had told us anything
questionable at all: `partial_analysis: false`, `errors: []`. Same shape as `main`
before #56, reached through `LC_ID_DYLIB` instead of a section header.

**The fix mirrors #56's treatment exactly: detect ambiguity, trust neither
candidate, cost the answer.** `_read_thin` now counts how many `LC_ID_DYLIB` and how
many `LC_SYMTAB` commands the walk actually reaches, regardless of whether each one's
own body could otherwise be read. More than one of either resets the corresponding
field to `None` after the walk finishes -- `soname`, or the `_Symtab` the walk had
been building -- rather than leaving whichever one was assigned last. `soname` and
the symbol table then read as though this slice itself never declared one: `own_base`
falls back to the member's file name the same way it always has for an object that
never declared `LC_ID_DYLIB` at all, and `_read_slice_symbols` takes an absent
`_Symtab` down the same path a genuinely stripped object already takes, `stripped`
included. That "read as absent, not as the decoy" rule is #56's own, applied here to
load commands instead of section headers. It is a per-slice fact, not necessarily the
record's final answer: `read_macho` still backfills `soname` from a later, unambiguous
fat-binary slice when one exists (see "A genuine residual" below), so a nulled `soname`
here can still surface a real name once the slices are merged.

**One token, not two.** `elf_section_type_ambiguous` already covers three ELF section
kinds (`SHT_DYNAMIC`, `SHT_DYNSYM`, `SHT_SYMTAB`) under one token, because the failure
is the same shape regardless of which kind of section it lands on: more than one
candidate of a kind the reader looks for, and no way to tell them apart from the kind
alone. `LC_ID_DYLIB` and `LC_SYMTAB` are the identical shape one level up -- load
commands instead of sections -- so `macho_load_command_ambiguous` covers both fields
rather than minting `macho_id_dylib_ambiguous` and `macho_symtab_ambiguous`
separately. Checked against #59's, #63's and #84's tokens first, per `AGENTS.md`'s
"don't duplicate an existing cause": none of them are this. `macho_symtab_incomplete`
comes closest, but its own entry ("A symbol table is checked against the string table,
not taken at its word") is about a table this reader reached and could not take at its
word for well-defined reasons -- unreachable, holding nothing but debug records,
understating its own rows. Ambiguity is a different fact: the table's own contents are
never even in question, because there is no way to tell which of two candidates is the
real table before either is read. Folding it into `macho_symtab_incomplete` would ask
one token to mean two different things a consumer might want to tell apart, the same
reasoning that kept `elf_section_type_ambiguous` off `elf_dynsym_unread`.

**Interaction, checked rather than assumed.** An ambiguous `LC_SYMTAB` still costs
`macho_symtab_incomplete` too, because the discarded table is handed to
`_read_slice_symbols` as `header.symtab is None`, the identical shape an absent
`LC_SYMTAB` already takes -- silently, no second error, since that token's own silent
case is exactly "nothing about this table was left unexplained beyond its absence."
The two tokens naming the same object is not a contradiction: `macho_load_command_ambiguous`
names *why* the table is gone, `macho_symtab_incomplete` names *what* is missing, the
same division `symtab_understates_rows` already draws beside a format-specific cause.
An ambiguous `LC_ID_DYLIB` costs nothing extra of the kind: `soname` has no sibling
token the way the symbol table does.

Checked against #84's walk-truncation shape directly: an ambiguous `LC_ID_DYLIB`
combined with a later `cmdsize` that truncates the walk records both
`macho_load_command_ambiguous` and `macho_load_command_walk_truncated` together,
neither one swallowing the other, and evidence read *before* the poison command --
including the first `LC_ID_DYLIB`, before ambiguity was even known -- survives exactly
the way #84 already guarantees.

**It costs the linkage answer, on purpose.** `macho_load_command_ambiguous` is not on
`[linkage_policy] exclude_reasons`, the same call #56 made for
`elf_section_type_ambiguous` and for the same reason: `soname` and the imported/defined
split are both fields `linkage` reads, and an ambiguous object has answered neither --
it is "we could not tell", not "there is nothing here." Excluding it would read
`openssl_linkage: none` off an object that told us nothing, the exact failure this
whole fix exists to close. The default `partial_binary` rule (`BIN_PARTIAL_FORMAT`)
claims it automatically, the same way it claims every cause not named in its own
`exclude_reasons = ["pe_ordinal_import"]`: no `ruleset.toml` change was needed for
either list.

**What was rejected.** A separate token per field (`macho_id_dylib_ambiguous` and
`macho_symtab_ambiguous`), covered above. Folding the `LC_SYMTAB` half into
`macho_symtab_incomplete`, covered above. Resyncing past a decoy by trusting
whichever `LC_ID_DYLIB` or `LC_SYMTAB` sorts *first* rather than last: that is still
picking one of two untrusted candidates, the identical hazard #56's first-pass fix
made for ELF sections before review found a decoy could sit ahead of the real one
too.

**What it costs.** `ANALYZER_VERSION` moves: an object carrying more than one
`LC_ID_DYLIB` or more than one `LC_SYMTAB` now reads `partial_analysis: true` with
`soname` and/or the symbol split unresolved, where it used to silently report
whichever candidate the walk reached last. `_read_thin`'s return type moved from a
bare positional tuple to a `_ThinHeader` dataclass, the refactor both #59's and #84's
own entries predicted the next per-command cause would force: seven positional
elements was the second time that prediction came true, and a third silent element
was the point past which naming each one stopped being optional.
`max-module-lines` for `binfmt/macho.py` moved from 1100 to 1200 for the same reason
#84 moved it from 1000 -- the docstring enumerating every `partial_analysis` cause
grew by one more paragraph, and pylint counts prose the same as code.

**Adversarial probes, beyond the reproduction above.** A third `LC_ID_DYLIB` is still
ambiguous -- the check counts occurrences rather than comparing exactly two values, so
it needs no third arm. Both orderings of a decoy `LC_SYMTAB` were built and checked:
after the real one, the shape that actually demonstrates the pre-fix bug (a last-wins
reader keeps the decoy's garbage offsets over the real table), and before it, the
shape a last-wins reader would have gotten right by accident and that a
first-wins-style fix would still get wrong -- both are refused identically, because
counting occurrences does not care which one the walk reached last.

**A genuine residual, found while probing the universal-binary merge and not closed
here.** This fix is about ambiguity *within* one thin header's own load-command walk.
It says nothing about two slices of a fat binary that each carry exactly one,
internally unambiguous `LC_ID_DYLIB`, but *disagree with each other*: `read_macho`
merges `soname` by "the first one any slice declared" (documented in this module's own
docstring and in "A universal binary is one record, and its slices are merged",
above), so a universal2 object whose x86_64 slice honestly declares `libcrypto.3.dylib`
and whose arm64 slice honestly declares something else still reads `soname:
"libcrypto.3.dylib"`, `partial_analysis: false`, with nothing in the record to say the
two slices disagreed. Reproduced directly: a two-slice fat object built exactly this
way returns `soname == "libcrypto.3.dylib"` and `partial_analysis is False` end to end
through `read_macho`. This is not the shape #85 was filed for -- neither slice's own
walk is ambiguous, so `macho_load_command_ambiguous` correctly does not fire for
either -- and it is not new: it is the same "first one any slice declared" rule the
universal-binary-merge entry above already documents and already accepted for
`soname`, one adversarial probe closer to a concrete counterexample than that entry
had before. Left open rather than folded into this fix, for the same reason that
entry gives for not tracking which architecture said what: closing it needs `soname`
to become a per-slice fact the merge can compare, which is a real, if smaller,
instance of the same three-or-more-architectures gap that entry already tracks under
#10.

Revisit if a real wheel is found whose fat slices honestly disagree about
`LC_ID_DYLIB` -- the probe above is synthetic, and #10's own entry records that no
disagreement of any kind has been found in a real universal2 wheel yet.

### A module-local line-count exemption instead of a third global bump

**Corrected after review.** This fix's own docstring/dataclass growth pushed
`binfmt/macho.py` over pylint's `max-module-lines`, and the first pass fixed it the way
#84 had: raising the project-wide limit again (1100 -> 1200). That is the third such
raise counting #84's own (1000 -> 1100), and each one silently gives every OTHER module
in the project the same extra headroom, whether or not it has earned it the way
`macho.py` has -- a documentation-heavy `partial_analysis` docstring that AGENTS.md's
"every policy entry carries a why" rule asks for, not unchecked growth. Replaced with a
module-local `# pylint: disable=too-many-lines` in `macho.py` itself, with the same
justification comment moved there, and `max-module-lines` reverted to pylint's own
default (1000) in `pyproject.toml`. `elf.py` (822 lines) and `pe.py` (812) were nowhere
close to either limit, so nothing else was depending on the raised ceiling; reverting it
costs nothing and stops the next module's growth from riding through unpoliced by
accident.

Revisit if a module OTHER than `binfmt/macho.py` needs the same exemption -- at that
point the pattern is common enough that a project-wide policy (or a documented list of
exempted modules) is worth the trade a global bump makes, rather than three modules
each carrying their own disable comment for the same underlying reason.

### #103: the error message names which command was ambiguous, the token still does not

**Fixed. Diagnostic text only -- does not reopen "one token, not two" above.**

"What was rejected" above covers merging `macho_id_dylib_ambiguous` and
`macho_symtab_ambiguous` into one `partial_reasons` token,
`PARTIAL_MACHO_LOAD_COMMAND_AMBIGUOUS`, and that call stands: `partial_analysis` and
the verdict are correct either way, and a second token would ask a consumer filtering
on `partial_reasons` to know Mach-O internals `elf_section_type_ambiguous`'s ELF
counterpart never asked of them. What #103 is about is one level down, in
`errors[].message`: `_read_thin` counted `id_dylib_seen` and `symtab_seen`
separately from the start (this entry's own "The fix mirrors #56's treatment exactly"
paragraph, above), but `_ThinHeader`/`_SliceHeader`/`_SliceEvidence` collapsed both
into one `load_command_ambiguous` boolean before `read_macho`'s error-emitting loop
ever saw them, so the merged message ("more than one LC_ID_DYLIB or LC_SYMTAB
command...") was a fact the reader already had and chose not to pass along --
`binfmt/elf.py`'s `elf_section_type_ambiguous` emits a distinct message per section
kind from the equivalent counts, and this fix brings Mach-O's diagnostic precision up
to that same level.

The two counts are now two booleans, `id_dylib_ambiguous` and `symtab_ambiguous`,
threaded through the same three dataclasses `load_command_ambiguous` was, and
`read_macho` emits up to two error records instead of one when both are true, each
naming its own command. `partial.add(evidence.PARTIAL_MACHO_LOAD_COMMAND_AMBIGUOUS)`
still fires from `id_dylib_ambiguous or symtab_ambiguous`, unchanged -- one token,
now backed by two possible error messages instead of one, the same relationship
`macho_load_command_ambiguous` and `macho_symtab_incomplete` already have to each
other, described above under "Interaction, checked rather than assumed."

`ANALYZER_VERSION` moves: an object with an ambiguous `LC_ID_DYLIB` or `LC_SYMTAB`
now records a different `errors[].message` for an unchanged input, even though
`partial_reasons`, `partial_analysis` and the verdict are all byte-identical to
before. Tests cover each command ambiguous alone (confirming the other command's
name never appears in its message) and both ambiguous on the same object at once
(confirming two distinct messages, not one, and that the `partial_reasons` token
still fires exactly once regardless).

Tracked in [#103](https://github.com/EmilienM/wheel-crypto-scan/issues/103).

Tracked in [#85](https://github.com/EmilienM/wheel-crypto-scan/issues/85), mirroring
[#56](https://github.com/EmilienM/wheel-crypto-scan/issues/56)'s ELF precedent, and
building on the same load-command walk [#59](https://github.com/EmilienM/wheel-crypto-scan/issues/59),
[#63](https://github.com/EmilienM/wheel-crypto-scan/issues/63) and
[#84](https://github.com/EmilienM/wheel-crypto-scan/issues/84) already touched.

## A `[[string_group]]` substring must be printable ASCII

**Accepted.**

Two performance fixes in `binfmt/strings.py`, both byte-identical by measurement, not
by argument. `sanitize` was a per-character generator; a compiled regex over the
complement of `PRINTABLE` (`_NON_PRINTABLE_RE`, quantified) is 13x faster on typical
symbol names and 28x on one long ASCII name, checked against the generator over 400
random cases spanning the full `str` code-point range including surrogates and the
astral plane. `match_string_groups` re-sliced a hit's whole enclosing run every time
its group matched inside it, which a crafted object could make quadratic: one
continuous run with "OpenSSL 3." repeated every 10 bytes measured 0.29s at 4 MiB,
scaling with the square of run length. Tracking the previously claimed run's end per
group and skipping a hit that falls inside it removes the re-slicing; both changes
needed no `ANALYZER_VERSION` bump.

**The skip introduced a real gap, found during adversarial review before it shipped.**
It assumes a `[[string_group]]` pattern can never match text spanning the `"\n"`
`extract_printable` joins runs with -- true because every shipped substring is
printable ASCII and `RUN_SEPARATOR` is not, but never enforced. A ruleset is
user-supplied (`--ruleset`), and a substring built to span that separator on purpose
(reachable only through an escaped literal containing a literal `"\n"`, since the
loader builds every pattern via `re.escape`) made the skip drop a real match: `text =
"Xb\nab\naY"` with substring `"b\na"` returns one hit instead of two, silently losing
the second run's evidence. Fuzzed at 20,000 trials with substrings allowed to contain
non-printable characters: 1,189 diverged from the pre-optimization behavior.

**What was rejected.** Making the skip unconditional on the match's own content
(`m.end() <= claimed_run_end`, dropping the `\n`-crossing assumption entirely) does not
work: once a match has spanned a separator, the claimed run is no longer newline-free,
so a later hit's boundaries would resolve against the wrong `"\n"`. The assumption has
to hold, not be routed around.

**How it is handled.** `ruleset_loader.py` refuses a `[[string_group]]` substring
containing any non-printable-ASCII character at load time, the same way it refuses an
empty substring list -- a substring that could only ever match by spanning the
separator, or that could never match extracted text at all, is an authoring mistake
either way, and nothing a rule author loses is expressive: extracted runs are
printable ASCII by construction. `tests/test_binfmt_strings.py` pins the property
itself against the shipped ruleset's compiled patterns, not just the substrings-are-
printable proxy for it, so a future group kind (a raw regex, a case-insensitive flag)
that kept the proxy green while letting a pattern cross the separator would still be
caught.

**Where the shared constant lives.** `PRINTABLE` moved from `binfmt/strings.py` to
`evidence.py`, beside `PARTIAL_REASONS` and the other extractor vocabularies. The
guard needs it in `ruleset_loader.py`, and importing it from `binfmt.strings` would
have made the loader execute `binfmt/__init__.py` -- every reader, `pyelftools`
included -- to reach one `range`. `evidence.py` is the leaf module every vocabulary
like this already lives in; `ruleset_loader.py` keeps importing only leaf modules, the
way it already does for `PARTIAL_REASONS`, and the loader-depends-on-binfmt edge this
would otherwise have opened stays closed, the same edge "The loader moves to
`ruleset_loader.py`, a sibling module, not a package" (above) already refused once
from the other direction.

Tracked in [#67](https://github.com/EmilienM/wheel-crypto-scan/issues/67) and
[#70](https://github.com/EmilienM/wheel-crypto-scan/issues/70).

## `py_call`/`py_attr`/`py_constant` match fields are validated, and their subject
fields made required

**Accepted. Closes a crash, not just a silent-match-nothing gap.**

`_validate_match_references` had arms for `dynamic_symbol`, `binary_string`,
`scan_error`, `partial_binary` and `linkage` but none for `py_call`, `py_attr` or
`py_constant` -- the three kinds that read Python-source evidence. Two failure modes
existed for all three, both unguarded: a typo'd or wrongly-shaped field loaded clean
and either matched nothing a rule author expected (the ordinary case every other kind
was already guarded against), or, for `py_call`'s `usedforsecurity` specifically,
crashed the scan outright. `_match_py_call` does `attrs.get("usedforsecurity") not in
want_used`; a bare TOML boolean (`usedforsecurity = true`) parses to a Python `bool`,
and `x not in True` raises `TypeError: argument of type 'bool' is not a container or
iterable` mid-scan, aborting the whole CLI run with no output file for what should
have been a rule that simply doesn't match. The identical shape crashes
`frozenset(match.get("targets", ()))` in the same function, and
`Ruleset.compile_patterns` reads `targets`/`attributes`/`constants` off *every* match
table regardless of kind, so the same crash was reachable through a stray key on an
unrelated rule, such as `targets = true` on a `dist_name` match.

**The fix, in `ruleset_loader.py`.** `usedforsecurity` (scalar or list) is checked
against the closed set `evidence.USED_FOR_SECURITY_VALUES` -- the only four values
`layers.python_ast._hashlib_usedforsecurity` can ever produce. `targets`, `attributes`,
`constants` and `values` are shape-checked (a list of strings, never a bool/dict/bare
string) wherever any match table carries one of them, via
`ruleset.GENERIC_MATCH_SEQUENCE_KEYS`, the same tuple `compile_patterns` iterates to
build `py_call_targets`/`py_attributes`/`py_constants` -- one definition read by both,
rather than the check silently drifting from what it protects if `compile_patterns`
ever grows a fourth generic key. `targets`, `attributes` and `constants` are each
required for their own kind (previously optional, defaulting to an empty tuple): a
`py_call` rule with no `targets` can never match anything, `_target_matches` has no
wildcard that reaches an empty set, so an omitted field was already a dead rule, never
a legitimate "match every call site" shape. Every shipped rule of these three kinds
already carries its subject field; the tightening changes nothing about the shipped
ruleset, only what a malformed custom one is allowed to load as.

**Why `algorithm` is checked for type only, never against a closed vocabulary.**
Unlike `usedforsecurity`, `algorithm` is open-ended: `_hashlib_algorithm` returns
whatever string literal a wheel's source passes to `hashlib.new(...)`, lowercased,
which could be any hash name that exists or will ever exist. Checking it against
`ruleset.conventions.weak_hash_algorithms` would refuse a rule intentionally naming a
*strong* algorithm -- a real, existing shape: the shipped `PY_WEAK_HASH_UNRESOLVED`
rule's own `algorithm = "unresolved"` match is not a member of that set either. Only
`isinstance(algorithm, str)` is checked.

**The `usedforsecurity` vocabulary's own drift risk, found and closed on review.** The
first pass introduced `USED_FOR_SECURITY_VALUES` in `evidence.py` with a comment
claiming `layers.python_ast` imports it "for extraction" -- untrue at the time: that
module still returned four bare string literals of its own, so the constant had one
consumer, not two, and a fifth value added to `_hashlib_usedforsecurity` without a
matching update to the frozenset would have made the loader wrongly refuse a rule that
should have matched. Closed by naming each of the four values individually in
`evidence.py` (`USED_FOR_SECURITY_ABSENT`/`_TRUE`/`_FALSE`/`_UNRESOLVED`, the same
shape `PARTIAL_REASONS` names each of its own members) and having
`_hashlib_usedforsecurity` return those constants instead of re-spelling the strings,
plus a test in `tests/test_python_ast.py` pinning that the four shapes it can produce
are exactly `USED_FOR_SECURITY_VALUES`, no more and no fewer -- mutation-confirmed to
fail when one return value is changed without updating the set.

**What was rejected.** A per-kind allowed-key set on `[rule.match]` tables -- refusing
any key a kind doesn't recognise, the way `_parse_linkage_policy` already refuses an
unknown key on `[linkage_policy]` -- would close the stray-key crash and a typo'd field
name in one mechanism, rather than the field-by-field shape checks this fix adds. Not
attempted here: it is a larger change to what every existing match table is allowed to
carry, worth its own issue rather than riding inside this one.

Tracked in [#82](https://github.com/EmilienM/wheel-crypto-scan/issues/82), alongside
[#77](https://github.com/EmilienM/wheel-crypto-scan/issues/77)'s `MATCHER_KINDS`-vs-
`engine._MATCHERS` drift test and its `WHEEL_BINARIES_TRUNCATED` wording correction
(also fixed in `SCHEMA.md` and `docs/output-schema.md`, which repeated the same
overstatement).

## `binfmt.ar` reads `.a`/`.lib` static archives as a container, not a reader

**Accepted. A new evidence source, not a new format for the record's `format` field.**

`.lib`/`.a` static archives -- the `ar` container format that bundles multiple `.o`/
`.obj` relocatable objects for downstream linking -- matched no route into
`layers.binaries.is_binary_member` at all, before or after #65: neither suffix, vendor
path, sniff directory nor executable bit. A wheel shipping a vendored `libcrypto.a` for
downstream linking, or a `.lib` import library, was invisible to the scanner on any
platform, with nothing in the record to say so -- not `OPAQUE`, not a missing-evidence
note, simply absent, because the member was never opened in the first place.

**Why this is not one more entry in `binfmt._READERS`.** Every existing reader answers
to `read_binary`'s contract: one stream in, one `BinaryEvidence` out. An archive holds
many separate, independently-linkable objects, and a consumer wants them told apart --
which member defines a crypto symbol matters as much as whether one does. Merging them
into one record would mean inventing an aggregation `read_binary` was never asked to
do, for a container that is not a "binary object" in the sense every other format
here is. `binfmt.ar.read_ar_members` is instead called directly by
`layers.binaries.scan_binaries`, in place of `read_binary`, once the member's own magic
(sniffed after opening, not trusted from the `.a`/`.lib` suffix alone) confirms it is
really `ar`-format -- an older MSVC `.lib` or a suffix collision falls through to the
same strings-only fallback any other unrecognised format already gets. `binfmt.ar` is
therefore a sibling module to `elf.py`/`macho.py`/`pe.py`, not a fourth entry in the
reader table, and imports `read_binary` from `binfmt/__init__.py` to dispatch each real
member to the same per-format readers everything else in the wheel goes through --
`layers.binaries` imports both directly rather than routing the container through
`binfmt/__init__.py`'s own dispatch. That split is a chosen direction, not a
structural necessity: nothing stops `binfmt/__init__.py` from importing `ar.py` and
re-exporting `read_ar_members` except that `ar.py` already imports `read_binary` from
`binfmt/__init__.py` at module load time, and importing back would make the cycle
real. `binfmt/__init__.py.__all__` says so at the point it omits `read_ar_members`,
so the omission reads as a decision rather than an oversight the next reader has to
rediscover.

**The container format itself, verified against real output before being written from
the documented spec.** An 8-byte magic, then 60-byte member headers (name, mtime, uid,
gid, mode, size, a 2-byte end marker) each followed by that many bytes of data, padded
to an even offset. Built real archives with this host's own GNU `ar` 2.46 (`gcc -c` two
trivial `.c` files, `ar rcs`, including a deliberately-long filename to force the GNU
long-name table and an odd-sized member to force the padding byte) and inspected the
bytes directly before writing `read_ar_members`, rather than trusting the documented
format alone -- the header layout, the end-of-header magic, the `//` long-name table's
`name/\n`-terminated entries and the odd-size padding byte all matched what the real
tool produced. BSD's `#1/<N>` extended-name convention is implemented from the
documented format only; no BSD `ar` was available to verify it against on this
development host. Every index/padding pseudo-member a real toolchain writes -- GNU's
own symbol index (name field exactly `/`), GNU's 64-bit index (`/SYM64/`), and BSD/
Apple `ar`'s ranlib index (`__.SYMDEF`, `__.SYMDEF SORTED` on newer toolchains,
`__.SYMDEF_64`) -- is skipped rather than dispatched as an object: its content is
`ar`'s own bookkeeping, not something `read_binary` has any use for. An earlier
version of this module only skipped the GNU index and read every BSD/Apple ranlib
member as an ordinary object; since it is neither ELF, Mach-O nor PE, that dispatch
always failed and cost the *whole archive* a spurious `partial_analysis`/
`BIN_PARTIAL_FORMAT` verdict hit -- every ordinary macOS static library or Windows
`/SYM64/`-indexed import archive would misreport as partially unreadable, not just a
crafted one. See #99's adversarial review.

**A structure that does not parse costs that structure, never the evidence already
gathered, applied one level higher than usual.** Every other reader's version of this
promise is about *one* object; an archive's version has to say what happens to the
objects a partially-walked member table already found before hitting a header that
overruns the archive, a non-numeric size field, or a member declaring more bytes than
remain. Answer: they keep their own evidence, each under its own path, independently of
whatever went wrong later in the table -- the failure is recorded once, against the
archive's own path, as `errors.AR_PARSE_ERROR`, and does not retract what earlier
members already yielded. Whenever the walk ends with zero real members -- whether
because a header overran the archive before any were found, or because the table
walked to completion and held nothing but index/padding pseudo-members -- the whole
archive falls back to one `read_strings_only` record over its raw bytes, marked
`evidence.PARTIAL_AR_MEMBER_TABLE_UNREAD`: the identical "no structure to split,
strings only" shape a format with no registered reader gets, not a new fallback
mechanism, tagged `evidence.FORMAT_AR` so the record still says this was a
recognised archive rather than an unknown format. Only a stream whose own magic
does not match `ar`'s at all -- unreachable through `layers.binaries`, which sniffs
that magic itself before ever calling in, but reachable by a test calling
`read_ar_members` directly -- takes the same fallback shape tagged `FORMAT_UNKNOWN`
instead.

**A member's name is never grounds to drop the member.** A `#1/<N>` field claiming
more bytes than the member holds, or a `/<offset>` pointing past the long-name
table's end or into an entry that never closes with `/\n`, leaves `_resolve_name`
unable to say what the member is called -- not whether it exists. An earlier version
of this module treated that as a reason to skip the member outright, which throws
away real, already-read evidence over nothing worse than its own label: "unreadable
means `OPAQUE`, never `NO_CRYPTO_DETECTED`" applies to a name exactly as much as to a
structure. The fix reads the member's bytes exactly as it would if the name had
resolved, under a synthetic `member@<offset>` path, with its own `AR_PARSE_ERROR`
naming why the real name could not be used. Two members that legitimately share one
resolved name -- ordinary in `ar`, since nothing stops two same-named `.o` files
vendored from different source directories -- are disambiguated with a `#2`, `#3`
suffix (`_dedupe`) for the same reason: `binaries[].path` was unique before this
module existed, and `record._cap_by_findings` keys a dict on it, so two members
silently sharing one path would let the second overwrite the first's evidence even
when the cap had room for both.

**Member bytes are windowed onto the original stream, never copied out first.** An
`ar` archive can legitimately be as large as any other member this tool streams, and
reading the whole thing into one buffer -- worse, slicing every member out of a
second full copy -- would spend exactly the memory `wheelfile.ArchiveLimits` streams
a large member specifically to avoid. `_Window(io.RawIOBase)`, wrapped in
`io.BufferedReader` for the same reason `wheelfile.open_member` wraps
`SeekableZipMember` (a bare `RawIOBase` only promises one underlying `read()` call
per request and can return short mid-stream), gives `read_binary` a seekable view of
`[member_start, member_start + size)` on the archive's own stream. No cap is applied
at the archive layer beyond `_MAX_MEMBERS`: truncating a member's bytes here would
risk misreading a section table that legitimately sits past an arbitrary cut as
corrupt, so each dispatched member applies its own `max_strings_bytes` budget the
same way it would outside an archive.

**An archive member's `SONAME` must not confirm a sibling's `needed` entry.**
`BinaryEvidence.from_archive` marks every record `read_ar_members` produces, and
`linkage.member_stem_counts` excludes them: a relocatable object bundled inside a
static archive was never a file a dynamic loader could resolve a `DT_NEEDED` entry
to, so a same-named `SONAME` on one -- bytes this module reads exactly as written,
not invented -- must not be able to make a genuinely system-linked sibling extension
read as bundled. Verified by mutation: removing the exclusion in
`member_stem_counts` turns a sibling's linkage classification from `system` to
`bundled` in `tests/test_linkage.py`'s
`test_an_archive_members_soname_never_confirms_a_siblings_needed_entry`.

**A cap on member count, independent of `max_binaries_per_record`.** That cap bounds
the record's *size*, applied once after every binary in the wheel (archive-contained or
not) has already been read; it says nothing about the *work* a crafted archive can
demand before ever reaching it. `_MAX_MEMBERS = 4096` bounds how many `read_binary`
dispatches one archive can force, reported the same way a truncation elsewhere in this
tool is: an `AR_PARSE_ERROR` naming the cap, not silence.

**What was rejected.** Reading `ar`'s own GNU symbol-index member (the `/`
pseudo-member's own name-to-offset table) to shortcut symbol matching, rather than
dispatching every real member through the ordinary per-format readers: rejected because
the index does not carry binding (imported vs. defined) or which crypto *group* a name
belongs to, both of which `read_binary`'s own matchers already compute correctly, and
because trusting an index a hostile archive controls without cross-checking it against
the object it claims to describe is the exact hazard `binfmt.symtab`'s cross-check
exists to close for `.dynsym`/`.symtab` themselves. Recursing into a member that is
itself `ar`-format (an archive inside an archive) was not attempted: `read_binary`'s
own dispatch does not special-case this, so such a member is read as `FORMAT_UNKNOWN`
strings-only rather than walked recursively -- static archives holding other static
archives are not a real toolchain output, and the existing fallback already keeps this
safe rather than silent.

**The scope this fix does not close.** `binfmt.elf`'s crypto symbol matching reads
`.dynsym` only, never `.symtab`. A relocatable `.o` -- every member of a real static
archive -- normally carries no `.dynsym` at all, so a genuine symbol *definition* with
no accompanying string banner is still invisible to symbol-based detection even though
this fix makes the archive and its members visible and read at all. Strings-based
detection (which reads every section regardless of symbol table) is unaffected, and is
demonstrated working in the same test that demonstrates the gap
(`test_a_symtab_only_definition_is_not_matched_the_documented_gap` and
`test_a_banner_string_in_a_relocatable_object_is_still_found`, `tests/test_binfmt_ar.py`).
Deliberately not attempted here, per the scoping decision made before implementation:
extending `.symtab` matching touches the reader used by every ELF object in the corpus,
not just archive members, and needs its own design pass on binding, on whether it
should apply only when `.dynsym` is absent or always, and on a real corpus check that
it does not change output for the ordinary case. Filed separately, found while scoping
this fix: [#117](https://github.com/EmilienM/wheel-crypto-scan/issues/117).

**Closed since**, by `binfmt.elf` matching `.symtab` whenever `.dynsym` is genuinely
absent -- see "`.symtab` is matched for crypto symbols when `.dynsym` is genuinely
absent" below. `binfmt.ar` needed no change of its own: it calls `read_binary` per
member regardless, so it inherited the fix the moment `binfmt.elf` had it. The two
tests this paragraph named were rewritten in place to pin the closed state instead of
the gap; see that entry for the design this fix's own scoping deferred.

`ANALYZER_VERSION` moves: a wheel shipping a `.a`/`.lib` now produces real evidence
where it previously produced none. `ruleset_version` moves: `ar_parse_error` joins
`BIN_UNPARSEABLE`'s `error_kinds`, the same rule `elf_parse_error`/`macho_parse_error`/
`pe_parse_error` already claim.

Tracked in [#99](https://github.com/EmilienM/wheel-crypto-scan/issues/99).

## `caps.cap` scans `ordered` again instead of materialising `pinned`/`rest`/`leftovers`

**Accepted. Performance and memory, not correctness.**

`cap`'s original three passes each built their own reference list on top of `ordered`:
`pinned` and `rest` (a stable partition of `ordered`, together the same length as it),
and `leftovers` (every item that lost its `cap_key` slot or arrived after the room was
gone). For the case this cap exists to bound -- an object with half a million matching
symbols -- that is up to three item-reference lists live at once on top of `ordered`
and `kept`. `pin` was also called twice per item: once building `pinned`, once
building `rest`.

**The fix keeps the same four-pass priority order** (one representative per `cap_key`
among the pinned items, then among the rest, then whatever pinned items are still
short of room, then whatever of the rest is) but scans `ordered` itself on every pass
instead of a materialised bucket. Two small aids replace the three item-reference
lists: `pinned_at`, `pin`'s answer for every index computed once up front (`pin` now
runs once per item, not twice), and `kept_at`, the set of indices already kept.
`kept_at` is bounded by `limit`, not by how many items came in -- it only grows when
an item is added to `kept`, which the cap itself already bounds. `pinned_at` is not:
it is one bool per input item, still smaller than an item reference but `O(n)`, not
`O(limit)`.

**Measured, not assumed, and the result corrects the first draft of this entry.** At
n=500,000, limit=512: the whole call's *peak* allocation is 47.86 MB, identical old and
new, for both `pin=None` and `pin` given -- `sorted(items, key=...)` materialising
`ordered` plus one key tuple per item sets the peak, before either version's own passes
run, and this fix does not touch that. What does shrink is the tail after the sort:
8.35 -> 0.06 MB unpinned, 8.20 -> 4.23 MB pinned. This is an auxiliary-allocation fix,
not a peak-memory one, and the earlier wording here claiming "roughly doubling the
memory the cap was meant to save" overstated it -- corrected once the diff had a
reviewer measure it rather than reason about it. `pin`'s call count is a real,
unconditional win: once per item instead of twice, for every input.

Verified equivalent to the original by two differentials: an exhaustive sweep (key
sequences, pin patterns, sort orders including a deliberately non-total `sort_key`, and
every `limit` in `0..n+1`, for `n <= 6`, 583,238 cases) and 20,000 randomised trials at
larger `n` -- zero divergences in either, across random item counts, key
cardinalities, pin predicates and limits -- alongside `tests/test_caps.py`'s existing
behavioural pins (representative per key, pins first, bounded, sorted,
order-independent) -- none needed to change, since
this is a rewrite of the same passes rather than a new selection rule. Not itself
re-measured against the 0.1.3 review's ~10% figure; the correctness of the cap was
never in question, only its footprint and its walk count.

**Correction, found by the same review that measured the peak above.** The first
version of this fix called a `want(index, wants_pinned)` closure from inside every
pass's inner loop, re-checking `pinned_at is None` on every call. Measured against the
`pin`-given post-sort tail specifically, that closure overhead cost more than the
three lists it removed saved: +8% for `pin=None`, +86% for `pin` given, in the tail
alone (the whole call, sort included, was a smaller +6%, since the sort dominates
there too). Fixed by inlining the check and hoisting the `pin is not None` test out of
the loop into one `passes` tuple computed once -- a change filed under "performance
and memory" regressing either was not an acceptable trade against three list
allocations, however large.

Neither `ANALYZER_VERSION` nor `ruleset_version` moves: the cap's output is identical
input for input, only how it gets there changed.

Tracked in [#71](https://github.com/EmilienM/wheel-crypto-scan/issues/71).

## `bundled_libs` and `errors[]` get their own caps, not `binaries_truncated`'s

**Accepted. A new pair of record fields, `bundled_libs_truncated` and
`errors_truncated`.**

`binaries_truncated` bounds `binaries[]` and `artifacts.extensions`, two arrays that
are always the same length (one entry per object read). `artifacts.bundled_libs` and
the top-level `errors[]` had no cap of their own at all: a wheel vendoring thousands of
small libraries under `*.libs/`/`.dylibs/`, or hitting the same recordable failure on
thousands of members, produced a correspondingly unbounded JSON line -- measured
during #55's adversarial review at 5000 vendored objects, a 274 KB line, reproducible
on `main` unrelated to that fix.

**Why not reuse `binaries_truncated` for `bundled_libs` too.** `bundled_libs` is a
*subset* of the objects `binaries[]`/`extensions` list -- only the vendored ones --
so its length can never exceed `binaries[]`'s, and a wheel with a huge object count
but a small vendored subset would report `binaries_truncated: true` while
`bundled_libs` itself was never actually cut. `bundled_libs_truncated` is computed
against `bundled_libs`'s own length, and the array itself is capped the same
finding-aware way `binaries[]` and `extensions` already are, through the same
`record._cap_by_findings`, keyed on the bare path string rather than a
`BinaryEvidence` or a `(path, format)` pair -- the same universe of paths, so a
finding naming a vendored library still wins it a slot ahead of an unclaimed one.

**Why `errors[]` needed a different cap, not a reuse of `_cap_by_findings`.**
`_cap_by_findings` picks winners by which object a *finding* references; an error is
not about an object a rule matched, and dropping one silently could itself hide the
reason a wheel reads `OPAQUE` -- a plain path-sorted prefix could crowd out a rare
`bad_zip` behind three thousand identical `binary_unknown_format` entries from a
flood of malformed members. `ScanError` gained a `cap_key`, `(stage, kind)`, making it
a `binfmt.caps.Capped` exactly like `SymbolMatch`/`StringMatch`/`RustCrate` already
are, and `build_record` caps `evidence.errors` through the very same `binfmt.caps.cap`
those three use -- one representative error per `(stage, kind)` pair survives before
the rest, so a wheel drowning in one kind of failure cannot crowd a different, rarer
one out. No new capping logic was written for this; reusing `cap` is what `caps.py`'s
own module docstring already promises for "a match list" in general, and a `ScanError`
qualifies exactly as well as the three it was written for.

Both `bundled_libs` and `errors[]` share `max_binaries_per_record`, the knob that
already bounds `binaries[]`/`extensions` -- no new context field or CLI flag, since
this is the same "keep one record bounded" concern at the same order of magnitude,
not a separate policy question.

**What was rejected.** A single, generic name-and-count field
(`something_truncated: {bundled_libs: bool, errors: bool}`) instead of two flat
top-level/nested booleans: rejected for staying consistent with `binaries_truncated`'s
own shape, one boolean per capped array, rather than inventing a second convention for
the same kind of fact.

**Neither flag gets a `binaries_truncated`-shaped rule.** `WHEEL_BINARIES_TRUNCATED`
exists because `binaries_truncated` being true changes what a reader can trust about
`findings[]` and `verdict`: an object past that cap was still evaluated, but a human
reading the record back cannot corroborate the verdict against every object that
earned it without also checking the flag, so the rule's own `why` argues explicitly
against leaving the boolean as the only trace. Neither new flag carries that
consequence -- `bundled_libs` and `errors[]` are inventory listings a rule never reads,
not evidence a finding or the verdict depends on -- so a human losing entries from
either learns less about the wheel's *inventory*, never less about why it was
classified the way it was. This is the same posture the per-object
`symbols_truncated`/`strings_truncated` flags already have: real signals with no rule
of their own, because what changes when they fire is what a record's arrays show, not
what a rule saw. Revisit if a future rule ever comes to depend on either array.

`ANALYZER_VERSION` moves: every record now carries `errors_truncated` and
`artifacts.bundled_libs_truncated`, so an unchanged wheel that never approaches either
cap still produces a record with two new keys. `schema_version` does not: `SCHEMA.md`'s
versioning table has its own row for exactly this, "a new key that is always present",
distinct from an optional one -- added alongside this fix, since the table did not yet
say what it meant for a *required* key to arrive rather than an optional one. No
existing consumer is broken by their arrival regardless, because the schema's own
description already asks every consumer to ignore unknown keys. `ruleset_version` does
not move: no rule, symbol, library or verdict changed.

**What this fix does not close.** `artifacts.skipped` and `artifacts.symlinks` are the
same shape -- plain inventory listings built without a cap -- and were not touched
here. Found while verifying this fix: 3000 members refused by
`ArchiveLimits.max_member_bytes` produces a correctly capped `errors: 256` sitting
next to an uncapped `artifacts.skipped: 3003`, a 220 KB record whose own
`errors_truncated` flag gives no hint that `skipped` is *also* incomplete -- `skipped`
and `errors[]` are fed by the same `archive.errors` for a member-refusal wheel, so the
two arrays now disagree about the same events. Deliberately not folded into this fix:
each needs its own cap decided (neither is finding-referenced, so `_cap_by_findings`
is unnecessary weight; a plain sorted-and-capped prefix, `bundled_libs`'s original
shape before this issue existed, is probably enough), and doing it well needs the same
scrutiny this entry's `pinned_at` and `schema_version` corrections show a first pass
tends to miss. Filed separately, found while verifying this fix:
[#119](https://github.com/EmilienM/wheel-crypto-scan/issues/119), closed by "A plain
cap for the two inventory listings no finding references" below.

Tracked in [#76](https://github.com/EmilienM/wheel-crypto-scan/issues/76).

## A plain cap for the two inventory listings no finding references

**Accepted. A new pair of record fields, `symlinks_truncated` and `skipped_truncated`.
`ANALYZER_VERSION` moves.**

`artifacts.skipped` (`{path, reason}`, for members refused by a limit) and
`artifacts.symlinks` (`{path, target}`) were the same unbounded shape the previous
entry fixed for `bundled_libs` and `errors[]`, and were found still uncapped while
verifying that fix: 3000 members refused by `ArchiveLimits.max_member_bytes` produced
a correctly capped `errors: 256` sitting next to an uncapped `artifacts.skipped: 3003`
-- a 220 KB record whose own `errors_truncated` gave no hint that `skipped` was also
incomplete, since the two arrays are fed by the same underlying `archive.errors` for a
member-refusal wheel but capped separately. `tests/test_hardening.py` reproduces both:
3000 refused `.so` members bound `skipped` to `max_binaries_per_record`, and 3000
symlinked members do the same for `symlinks`, each under a third of the pre-fix, 274 KB
measurement the previous entry took for `bundled_libs` at the same order of magnitude.

**Why a plain prefix, not `_cap_by_findings` or `binfmt.caps.cap`.** Both arrays are
plain inventory listings: no `Finding.locations[].path` ever names a skipped or
symlinked member (a rule matches evidence read *from* an object, and a refused or
symlinked member was never read as one), so there is no "which object does a finding
care about" question for a finding-aware cap to answer, unlike `bundled_libs` -- which
*is* a subset of `binaries[]`/`extensions`, objects findings do reference. And unlike
`errors[]`, dropping a `skipped` or `symlinks` entry costs a reader nothing about *why*
the wheel was classified the way it was: both are `layers.inventory.build_inventory`'s
own pre-sorted tuples, so `artifacts.skipped[:max_binaries]` and
`artifacts.symlinks[:max_binaries]` are the whole fix -- the same plain-prefix shape
`bundled_libs` itself had before the previous entry, before either array had a finding
to prefer. Both share `max_binaries_per_record`, the same knob every cap in this family
uses, for the same reason: this is the "keep one record bounded" concern, not a
separate policy question per array.

**Why not reuse `binaries_truncated` for either.** Same reasoning as `bundled_libs_truncated`:
`skipped` and `symlinks` can each be capped independently of the full object count
`binaries_truncated` bounds, and a wheel that never approaches either of *this* pair's
caps must not report truncation it never actually did.

**What was rejected.** Reusing `binfmt.caps.cap()` for either, the way `errors[]` does
through `ScanError.cap_key`: that machinery exists to keep one representative of each
kind before a flood of another crowds it out, which only matters when *what kind of
member this is* is itself worth preserving evidence of. Every `skipped` or `symlinks`
entry is already fully specific (one exact path and one exact reason or target), so
there is no group of interchangeable entries a plain prefix could crowd out unfairly --
unlike `errors[]`, where three thousand identical `binary_unknown_format` entries really
could crowd out one rare `bad_zip`. Reaching for the finding-aware or cap-key machinery
here anyway would be solving a starvation problem that does not exist for these two
arrays.

`ANALYZER_VERSION` moves: every record now carries `symlinks_truncated` and
`skipped_truncated`. `schema_version` does not, for the same reason the previous entry's
new keys did not move it: `SCHEMA.md`'s versioning table already covers "a new key that
is always present." `ruleset_version` does not move: no rule, symbol, library or
verdict changed.

Closes [#119](https://github.com/EmilienM/wheel-crypto-scan/issues/119).

## `.symtab` is matched for crypto symbols when `.dynsym` is genuinely absent

**Accepted. `ANALYZER_VERSION` moves.**

`binfmt.elf`'s crypto symbol matching read `.dynsym` only. Correct for a shared object
or executable, where `.dynsym` is what the dynamic linker actually uses -- but a
relocatable object (`ET_REL`, a `.o`/`.obj` before linking, the shape every member of
a `.a`/`.lib` static archive has, see #99) normally has no `.dynsym` at all, only
`.symtab`. Fed through the unmodified reader, such an object's `matched_symbols` came
back empty even when it genuinely defined a crypto symbol like `EVP_DigestInit_ex`,
with no accompanying string banner to fall back on -- invisible to the tool's primary
detection mechanism for "compiled straight into the extension, no library file, no
dependency", the shape `cryptography` 42+ relies on.

**Scoped to only when `.dynsym` is genuinely absent, not always alongside it.** Every
shared object and executable already carries a live `.dynsym` -- `strip` cannot remove
it without breaking dynamic linking -- so gating on absence means this reader's output
for the entire existing corpus of shared objects and executables is unaffected *by
construction*, not by a corpus check this repo has no wheel corpus to run locally.
Matching `.symtab` unconditionally was considered and rejected for exactly that reason:
it would touch every already-scanned ELF object with a live `.symtab`, most of which
also carry local, non-exported symbols a linker kept for debugging that `.dynsym` never
exposed, with no way to verify here that doing so does not introduce new matches or
duplicate findings on the ordinary case.

"Absent" means genuinely, cleanly absent, not merely `dynsym is None`: an ambiguous
`.dynsym` (more than one `SHT_DYNSYM` section) or one forged away from its own type
also makes the type-based lookup return `None`, but neither means the object has no
`.dynsym` -- both mean it has one this reader cannot trust which candidate is real, or
cannot trust the type of. Falling back to `.symtab` for either would read a crafted
object's debug table as though it were a relocatable object's own, and only, symbol
table, which it is not. `dynsym_absent` is computed explicitly as `dynsym is None and
not dynsym_ambiguous and not dynsym_type_mismatch`, and both edge cases have their own
test confirming `.symtab` is not consulted when they fire.

**Binding and the cross-check reuse `.dynsym`'s own machinery unchanged.**
`_iter_symbols` already operates on raw bytes against the shared `Elf32_Sym`/`Elf64_Sym`
layout, deriving imported/defined from `st_shndx == SHN_UNDEF` -- a fact the ELF spec
defines identically for both tables, so the function needed no change at all. The same
is true of the understated-rows and unresolved-name cross-checks: `holds_a_name_not_read`
already took the string bytes and the read-crypto set as plain arguments, with no
`.dynsym`-specific assumption baked in.

**The one piece that could not be reused as-is: `.symtab`'s string table has a
different trust model than `.dynsym`'s, and mixing them would have applied the wrong
one to one of the two callers.** `.dynsym`'s `sh_link` is not what the dynamic linker
trusts -- it uses `.dynamic`'s `DT_STRTAB` instead -- so `_validated_strtab` exists
specifically because a decoy `sh_link` could disagree with what the loader actually
resolves, and refuses to trust `sh_link` without cross-checking it against `DT_STRTAB`.
`.symtab` has no such hazard: nothing but a section-header-reading tool ever resolves a
`.symtab` name at all, the dynamic linker never touches it, and a relocatable object
normally carries no `.dynamic` section to cross-check against in the first place --
`sh_link` naming the associated string table *is* the ELF spec's own definition of what
`.symtab`'s string table is, not a hint a loader might disagree with. `_symtab_strtab`
is a new, separate function for this: it keeps the one check that generalises (`sh_link`
must resolve to a section really typed `SHT_STRTAB`) and drops the cross-check that does
not apply. `_symbol_bytes`, previously `.dynsym`-specific (`dt_strtab_addr` threaded
through from `.dynamic`), now takes an already-resolved `strtab: Section | None` from
either trust model instead, so the two callers' resolution logic never risks blending.

**What was rejected.** Reading `ar`'s own GNU symbol-index member to shortcut this
instead of matching through the archive member's own `.symtab`: already rejected for
#99 on the same grounds -- the index carries no binding and trusting it without
cross-checking against the object it claims to describe is the exact hazard
`binfmt.symtab`'s cross-check exists to close.

**What `binfmt.ar` needed to change: nothing, for an ELF member.** It calls
`read_binary` per member regardless of format, so the fix applies to every ELF
archive member automatically once `binfmt.elf` has it -- the same inheritance every
earlier `binfmt.elf` correction already gave `binfmt.ar` for free. Left open: a
Windows `.lib`'s `.obj` members are COFF, not ELF, and `binfmt.pe` deliberately does
not read the COFF symbol table at all (every modern linker strips it in favour of a
PDB); such a member stays `FORMAT_UNKNOWN`, strings-only, unaffected by this fix.

**Severe findings from two rounds of adversarial review plus a targeted verification
pass over the fixes themselves, all fixed before merge.**

- **A decoy `.strtab` defeated the new path entirely, and the object read clean, not
  `OPAQUE`.** `_symtab_strtab` has no independent authority to corroborate `sh_link`
  against -- that is the whole reason it does not attempt `_validated_strtab`'s
  address cross-check -- so a `.symtab` repointed at an appended, all-NUL `SHT_STRTAB`
  resolved every name to `""`: `st_name == 0` and an index into an all-NUL table both
  read as "no name, resolved successfully" rather than unresolved, so `symtab_unresolved`
  stayed `0`, the fabricated `.strtab` held no crypto name to flag, and the *real*
  `.strtab`, sitting untouched elsewhere in the section table, was never asked. Reproduced
  independently by both reviewers on an `ET_REL` object genuinely defining
  `EVP_DigestInit_ex`: `matched_symbols=() partial_analysis=False errors=[]`, exactly the
  "unreadable means `OPAQUE`, never `NO_CRYPTO_DETECTED`" failure this whole invariant
  exists to prevent, and exploitable on purpose by a crafted wheel wanting to hide a
  crypto symbol from this tool. Fixed by not trusting the one table `sh_link` names at
  all for this check: `_any_strtab_holds_a_name_not_read` asks every `SHT_STRTAB`
  section in the object, so the real `.strtab` still gets to contradict the decoy
  regardless of which one `.symtab` claims to point at.
- **That fix had its own gap, found dispatching a fork to verify it rather than
  trusting the fix on inspection.** The first version of `_any_strtab_holds_a_name_not_read`
  skipped a `SHT_STRTAB` section it could not fully read within the byte budget --
  reasonable-looking, since an unread section holds nothing this pass can confirm
  either way, but wrong: it reopened the identical decoy under a second construction.
  A *small* decoy `.symtab`'s `sh_link` is happy to point at (so the primary read
  stays clean and cheap), placed beside the genuine `.strtab` with its own declared
  `sh_size` inflated past the budget elsewhere in the section table -- the one section
  that could have contradicted the decoy was silently skipped rather than flagged as
  unchecked, and the object read clean again. Reproduced. Fixed by making an unread
  `SHT_STRTAB` section count as a hit, the same as finding an unclaimed name would:
  "unreadable means `OPAQUE`" applies to a string table this function could not fully
  examine exactly as it does to one that spelled a name out.
- **`dynsym_absent`'s three-way gate missed a fourth shape.** A `.dynsym` whose own
  section header fails to parse never reaches `sections` at all (`elf_sections_unread`),
  so `dynsym is None`, `dynsym_ambiguous` is `False`, and `dynsym_type_mismatch` is
  also `False` -- the mismatch check scans the same truncated `sections` list and
  misses it the identical way. Reproduced on an ordinary shared object with a corrupted
  `.dynsym` `sh_link`: `.symtab` matching fired and added evidence to an already-partial
  record. Bounded impact (evidence added, not lost, to a record already flagged
  partial), but the documented "unaffected by construction" claim was incomplete.
  Fixed: `dynsym_absent` now also requires `PARTIAL_ELF_SECTIONS_UNREAD not in reasons`.
- **`"unaffected by construction" was false for a statically linked executable.`** Only
  a *dynamically* linked shared object or executable is guaranteed a live `.dynsym`;
  a static `ET_EXEC` has none either, and reproducibly now gets `.symtab` matched --
  wheels shipping Go binaries are exactly this shape, which is why `binfmt.golang.py`
  exists at all. The behaviour is desirable, not a bug: a statically linked executable
  defining a crypto symbol should not stay invisible any more than a relocatable
  object should. What was wrong was the claim of *no* corpus impact; corrected in the
  module docstring and here to scope "unaffected by construction" to dynamically
  linked objects only, and name the static-executable case as the fix's intended
  further reach, not an oversight.
- **`.symtab` carries symbol types `.dynsym` never does.** `STT_FILE` (a source-file
  pseudo-symbol) and `STT_SECTION` entries are names too, and a file literally called
  `EVP_md5.c` or `blake3_dispatch.c` matched a group by nothing but coincidence of a
  filename with the code it happens to implement -- reproduced. `_iter_symbols` now
  yields each entry's `st_info`-derived type (`ELF32_ST_TYPE`, identical layout in
  both classes); the `.symtab` matching loop skips `STT_FILE`/`STT_SECTION`, and the
  `.dynsym` loop, which has never needed this since a dynamic symbol table does not
  normally carry either type, ignores the new field.

`ANALYZER_VERSION` moves: an unchanged `.o`/`.obj`-holding wheel, or a statically
linked executable, that previously read `matched_symbols: []` for lack of `.dynsym`
can now report real crypto symbol matches for the identical bytes. `ruleset_version`
also moves, for a related but distinct reason this fix surfaced: `elf_symtab_unread`
used to leave `[linkage_policy] exclude_reasons` unconditionally, on the premise that
`.symtab` only ever drove `stripped`/`symbol_counts.symtab` -- a premise this fix
breaks. See "Sections are found by type, not by a name nobody checks", the paragraph
beginning "`elf_symtab_unread` was on this list too, and is not any more (#117)".

Tracked in [#117](https://github.com/EmilienM/wheel-crypto-scan/issues/117).
