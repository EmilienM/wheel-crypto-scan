# Design

Design calls that were deliberate, are not obvious from the code, and would otherwise be
re-litigated every time someone new reads it. `AGENTS.md` carries the invariants; this
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
subset of the grammar and does not cover PEP 695. Measured, it costs findings on newer
interpreters without delivering the determinism it promises.

**What was rejected, and why.**

- *Vendor or depend on a version-independent parser.* It would close the gap properly,
  but the dependency list is two packages on purpose, and a third needs to buy more than
  this.
- *Record the parsing interpreter's version in the record.* Cheap, and it makes the
  difference visible rather than silent. Rejected because `tool` would then carry
  host-derived data, which the schema avoids on purpose: a record that embeds the host it
  was produced on is not byte-comparable between producers, which trades a narrow
  non-determinism for a total one.

**How it is handled instead.** `README.md` and `SCHEMA.md` both say to pin the
interpreter when records must be comparable across hosts. CI runs 3.12 and 3.14 on every
push, and the release workflow runs the suite on 3.11 through 3.14 before it publishes, so
a divergence that grows beyond the Python layer shows up as a test failure before it
ships.

Revisit if a version-independent parser lands in the standard library, or if a wheel in
the real corpus is found whose headline verdict flips on interpreter version alone.

## A universal binary is one record, and its slices are merged

**Accepted, knowing what it costs.**

A fat Mach-O is read slice by slice and reduced to a single `BinaryEvidence`. `needed`,
`rpath` and `matched_symbols` become sorted unions, `symtab_count` a sum, `stripped` true
only when every slice is. `machine`, `bits` and `endian` describe the first slice that
parsed, because they describe one architecture and cannot describe several.

**Why one record.** The thing being described is the member of the wheel. `path` is what
`conventions.own_base` and the vendored-path matching key on, so a record per slice would
carry the same `path` two or four times and every consumer counting binaries would
double-count. No field of the schema is per-architecture, and adding a `slices` array
would be a schema change buying resolution nothing consumes.

**What it buys.** Reading only the first parseable slice would leave every fat object
`partial_analysis: true` for ever. Most macOS wheels are universal2, so a crypto-free
universal2 wheel would come out `OPAQUE` rather than `NO_CRYPTO_DETECTED`, and the
README's `select(.verdict.class == "OPAQUE")` triage recipe would list all of them.

**What it costs.** A union hides which architecture said what. A universal2 dylib whose
x86_64 slice links the host OpenSSL and whose arm64 slice has it compiled in merges to
`needed: [libcrypto...]` plus both an `imported` and a `defined` `EVP_DigestInit_ex`.
`linkage._binary_posture` counts `system`, `bundled` and `static` on the one object and
returns `mixed` when two or more are true, so any disagreement between two definite
postures across slices -- system and static, bundled and system, bundled and static --
reads `mixed`, the same as reading the slices apart and letting `_aggregate` combine
them. What is gone either way is which architecture said which: a `mixed` record from a
universal2 dylib cannot say "x86_64 links system, arm64 is static." The `mixed` posture
itself carries `needs_human_review`, through `BIN_OPENSSL_LINKAGE_UNKNOWN`, so the shape
still reaches a human even though the per-architecture detail is lost.

The trade of merging slices into one record at all is right: the losing case needs two
independently built thin dylibs `lipo`-ed together, which `delocate` does not produce,
while the winning case (no fat-slice disagreement) is most of the macOS wheels in the
index. It is recorded here because nothing in the output says a record was merged, so a
reader of `matched_symbols` carrying one name as both `imported` and `defined` should
know why that is representable at all.

Revisit if a real wheel is found whose architectures disagree in a way `mixed` cannot
represent, e.g. three or more slices that would benefit from naming which architecture
said what.

## A routine cause is recorded but does not make a wheel opaque

**Accepted, and it changes verdicts. See "An ordinal export is a failure to read, not a
convention" below for the one cause this list does not hold.**

`partial_analysis` has a score of causes behind it. `BIN_PARTIAL_FORMAT` fires `OPAQUE`
plus `needs_human_review` for most of them; `BIN_PARTIAL_ROUTINE` claims the ones that
read as a linker convention rather than a failure. The one it claims is an import bound
by ordinal: a convention a linker produces on purpose rather than anything that went
wrong, with no function name to match.

`WS2_32` is normally bound by ordinal, so that is the ordinary shape of a Windows
extension that touches sockets. Measured on two wheels identical but for that, with the
ordinal import treated as a failure:

```
all imports named   -> NO_CRYPTO_DETECTED
WS2_32 by ordinal   -> OPAQUE
```

One linker convention, and the wheel joins the README's `select(.verdict.class ==
"OPAQUE")` triage list. That is a real cost: the list is read by a human, and padding it
with wheels nobody needs to look at is how a triage list stops being read at all.

**How it works.** `[rule.match] kind = "partial_binary"` takes `reasons` and
`exclude_reasons`, so the ruleset decides which causes are worth a verdict rather than
the engine treating them alike. `BIN_PARTIAL_ROUTINE` claims the ordinal import with no
verdict and no human review; `BIN_PARTIAL_FORMAT` keeps `OPAQUE` for everything else. An
object with both kinds of cause fires both rules, and each names only the causes it
speaks for, so the failure still wins.

**What it costs, and why `pe_delay_load` is not on the list.** A wheel whose only
incompleteness is an ordinal import reads `NO_CRYPTO_DETECTED` rather than `OPAQUE`.
That is a real loss of conservatism: the function behind that ordinal genuinely has no
name, and if it were a crypto entry point we would not know.

What makes it tolerable is that the *dependency* name survives. An object importing
`libcrypto-3-x64.dll` by ordinal still carries that DLL in `needed`, so it still comes
out `CONDITIONAL` on the ordinary `needed` rule; what is lost is which function inside
it. A delay-load directory loses the dependency name itself, with nothing downstream to
recover it -- no string group matches a bare DLL name -- so a `.pyd` that delay-loads a
crypto DLL it does not ship would read clean. It stays with the strict rule. The two are
not the same kind of gap, and only one of them has a backstop. The record is the same
either way -- `partial_analysis` is true and `partial_reasons` names the cause -- so a
consumer who disagrees can filter on the record rather than the verdict.

**Why the strict rule excludes rather than includes.** A cause added later matches no
include list, so it would report nothing at all. Excluding means a new token is serious
until someone decides otherwise, which is the safe direction, and a test asserts every
token the strict rule excludes is claimed by name somewhere else.

Revisit if a crypto library is found being imported by ordinal in a real wheel.

### An ordinal export is a failure to read, not a convention

**Accepted, and it changes verdicts. `pe_ordinal_export` is a failure to read, not a
convention.**

"An import or an export bound by ordinal has no name to match" reads as one argument,
and the reason it makes the import routine -- the dependency name survives in `needed`,
so a crypto dependency bound that way is still caught -- is about imports. **An export
names no dependency.** What an ordinal export loses is a *definition*, and a definition
is how a statically linked copy is recognised, which is the posture this tool exists to
catch and the one with no `needed` entry behind it by definition.

What treating it as routine costs, measured on one `.pyd` exporting `PyInit__ext`,
`EVP_DigestInit_ex` and `SSL_new`, with no OpenSSL banner in it to fall back on:

```
honest                     -> static, BIN_STATIC_OPENSSL
NumberOfNames = 0          -> none,   BIN_PARTIAL_ROUTINE only, needs_human_review: false
NumberOfNames = 1 (of 3)   -> none,   BIN_PARTIAL_ROUTINE only, needs_human_review: false
```

One edited header field and a statically linked OpenSSL reads clean. `NumberOfNames` is a
count the object keeps about itself and PE has no string table to check it against, the
way ELF and Mach-O check theirs, so understating it is free. The name table simply stops
being walked, every address slot becomes one no name points at, and `unnamed` fires --
so the cause *is* recorded. Only its classification decides whether the record reads
clean.

**What keeping it strict costs, measured rather than assumed.** `unnamed` counts export
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
net new OPAQUE wheels from keeping it strict:       0
```

The single object carrying it is `duckdb`'s `_duckdb.cp310-win_amd64.pyd`, and it is not
a NONAME export: export 724 of 3548 is a 1027-byte MSVC-mangled C++ name, three bytes
past the reader's own 1024-byte cap, so the name fails to resolve and the slot falls out
of the named set. That object also carries `pe_export_incomplete` and is `OPAQUE`
regardless, so it does not move either. The triage list does not grow by one wheel
across that corpus.

Revisit if a real Windows wheel is found whose only incompleteness is an ordinal export.

**Why the import stays.** Its argument survives its own scrutiny: `WS2_32` really is
bound by ordinal on every Windows extension that touches sockets, so the cost of making
it strict is every such wheel, and the DLL name really does survive in `needed`. The
residual there is narrower and is pinned by a test rather than assumed away: an ordinal
import from a DLL no soname matches loses the imported symbol that would have made the
object `unknown`.

**What is left open.** The shapes that leave nothing to notice at all: an export
directory that zeroes `NumberOfFunctions` as well, and one whose data directory entry is
zeroed outright, which this reader deliberately treats as a complete reading of an object
that exports nothing. Both still want the count check.

### A carve-out list is a claim, and claims get tested

**Accepted.**

A list that exempts causes from a verdict is policy, and policy has no wrong answers to
fail against. A cause admitted on the strength of a sentence that is true of its
neighbour, and not of itself, reads fine and fails nothing -- the ordinal export above is
exactly that shape.

So the admission test for that list is behavioural, not editorial: **go and find a
crypto object that reads clean because the cause is on it.** If that object exists the
cause does not belong there, whatever the sentence says. For the ordinal export it takes
one fixture and one edited header field. `AGENTS.md` carries this beside the invariant,
because the list is the invariant's only carve-out and the next candidate will arrive
with a sentence too.

## A symbol table is checked against the string table, not taken at its word

**Accepted, and it changes verdicts.**

`LC_SYMTAB` says where the symbol table is and how many entries it has, and `.dynsym`'s
`sh_size` says the same thing in ELF. Reading exactly that many is not the same as
reading every symbol the object carries, and the difference is a way to look clean.
Taken at its word:

```
honest: 2 crypto imports        -> OPAQUE
nsyms=0 over the same rows      -> NO_CRYPTO_DETECTED
nsyms=1 over 3, benign first    -> NO_CRYPTO_DETECTED
```

Both liars have `_EVP_DigestInit_ex` and `_SSL_new` physically present with a full string
table. Every structural check passes: the declared window is entirely there, no index is
unresolvable, and something in it resolves to a name.

**`nsyms == 0` is not exempt.** Exempting it rests on the reasoning that a table
declaring nothing has nothing to fail at. That reasoning fails the same way counting a
debug record as a symbol fails: a table declaring nothing tells us exactly what an
absent `LC_SYMTAB` tells us, and an absent one is incomplete. A test pins that a
zero-entry table is partial.

**The count itself is cross-checked against the string table.** Nothing structural says
how many rows there really are -- what sits between the symbol table and the string table
is `LC_DYSYMTAB`'s business, and assuming they are adjacent is wrong for real LINKEDIT
layouts. But the string table is the one place every name must appear. A name in it that
matches a symbol group and that no entry we read named is a symbol the object carries and
did not declare.

**What it costs.** The string table is scanned by one regex in C, and only the runs it
lands in are decoded, so an honest table pays one pass and runs the rule matcher on
almost nothing. Splitting the table instead takes peak memory from 1.0 MiB to 12.4 MiB on
a 1.6 MiB object, which this module is written around not doing; walking it run by run
in Python is worse on the axis that matters, putting a 2 MiB string table of two-byte
runs at 19 seconds across a universal binary's slices, and 31 seconds if the runs hold
control bytes. Both are 1.2 seconds through the locator. Measured over the whole reader
on 497,040 honest symbols in a 26 MiB object, against no cross-check at all: 2.7s to
3.1s, and peak RSS 12.4 MiB to 14.8 MiB, the extra being the crypto names read.

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
knowingly.

Neither is the separate blind spot: a crypto symbol whose name is not in the string
table at all, because it resolves through `LC_DYLD_EXPORTS_TRIE` or chained fixups,
which this reader does not parse and says so.

**Both readers make the check, from one place.** `.dynstr` is what `.dynsym` points into
for exactly the reason the string table is what `LC_SYMTAB` points into, and the same
object shape works on both: `sh_size` covering one entry of four hides two OpenSSL
imports and reads `NO_CRYPTO_DETECTED` without the check. `binfmt.symtab` holds the
walk, because a security check that exists twice is a security check that drifts. What
the readers keep is what only they know: Mach-O inverts Darwin's ABI underscore before
matching and ELF must not, or an honest `_EVP_DigestInit_ex` reads as a hidden
`EVP_DigestInit_ex`. Cost on ELF matches Mach-O: 497,040 dynamic symbols in a 29 MiB
object go from 1.7s to 2.0s, memory unchanged, and no object among 6,502 real ELF
binaries on a Fedora host is flagged.

**The cross-check is only sound over a string table we read through,** which is the
sibling guard. Shrink `.dynstr` instead of `.dynsym` and every row survives, every count
survives, and the names simply stop being reachable: without the guard, a statically
linked extension reads `NO_CRYPTO_DETECTED` while carrying two OpenSSL imports. Worse,
the bytes left over would be reported as symbols -- a `.dynstr` cut to 24 bytes puts
`EVP_DigestI` in `matched_symbols`, a name the object does not carry, in the field the
whole tool turns on. Both readers treat an index past the end, or a run the table never
closes, as a name they could not resolve.

**Both name the cause the same way.** A count that understates its rows is the one
failure that is about neither format, so beside `elf_dynsym_unread` or
`macho_symtab_incomplete` it also emits `symtab_understates_rows`. Which wheels in an
index understated their symbol table is a supply-chain question rather than a build
quirk, and answering it should not mean substring-matching an error message that no
contract pins.

**One table's size is still believed.** ELF's `.symtab` drives `stripped` and
`symbol_counts.symtab`, and a lie in its size costs a field that is recorded rather than
a finding; what `.symtab` contributes to matching is cross-checked the same way
`.dynsym`'s is (the two `.symtab` entries below). PE has no analogue to bring the check
to: its imports have no declared count at all, and its exports have one with no string
table to check it against, because export names are individually addressed rather than
pooled. `NumberOfNames = 0` over a real name table is nonetheless caught, but
incidentally rather than by a check: understating the count leaves every address slot
with no name pointing at it, `unnamed` fires, and that cause carries `OPAQUE` ("An
ordinal export is a failure to read, not a convention", above). Zero
`NumberOfFunctions` as well and there is nothing left to notice, which is the residual
that entry leaves open.

**Errors say which way it fell short.** A table that fell short records an error naming
the cause, rather than every case claiming the object "could not be read in full" when
every byte of it was read. Silence is reserved for a table that left nothing unexplained:
an absent `LC_SYMTAB`, or one declaring no entries over a string table holding no name it
failed to account for. Both are still incomplete, and neither is a clean bill.

`stripped` follows the same line, read off what the table yielded rather than off
`nsyms`. Exactly one of "fell short", "read in full" and "stripped" holds for any table,
which is why the three are derived in one place: a count of zero over rows holding crypto
names is a cause, and a cause must never be able to set a field documented as recorded
rather than a finding.

**Silence still costs the linkage answer.** A Mach-O that declares no entries records no
error, but its `partial_reasons` names `macho_symtab_incomplete`, and `resolve_linkage`
reads that cause as one that costs an answer. So the object comes out `OPAQUE` with
`openssl_linkage: unknown`, rather than one field saying we could not read it and another
saying there is no OpenSSL here ("Linkage reads a second split over the same
vocabulary", below).

## Linkage reads a second split over the same vocabulary

**Accepted. It changes the field most consumers filter on.**

Deciding "we could not tell" from `is_opaque` and the binary-stage errors alone, and never
from `partial_analysis`, lets an object a reader explicitly marked as not read in full,
but that recorded no error, contribute a definite posture. The everyday case is a
stripped macOS extension:

```
partial_reasons: ['macho_symtab_incomplete']
openssl_linkage: none
```

One field says the symbol table was not read; the next says there is no OpenSSL in the
object, which is a claim the first says we cannot make. `is_opaque` does not rescue it,
because `needed` is non-empty for every loadable dylib and every `.pyd`. The verdict is
`OPAQUE` through `BIN_PARTIAL_FORMAT` regardless, so what is at stake is the condition
rather than the headline -- and the condition is the field `verdict.conditions` exists to
carry.

**Why it is not one boolean.** `partial_analysis` is true for linker conventions too.
Counting the tuple wholesale would turn every ordinal import into
`openssl_linkage: unknown`, which is exactly the noise the routine-cause split ("A
routine cause is recorded but does not make a wheel opaque", above) keeps out of the
verdict, arriving again through a different field.

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
ruleset alone would leave every `--ruleset` user outside the guard, so it is a
`RulesetError` rather than a test.

**Absence of the table derives it, rather than emptying it.** An empty default is
conservative read on its own and self-contradicting read in composition: a custom
ruleset keeping `BIN_PARTIAL_ROUTINE` and omitting `[linkage_policy]` would report
`openssl_linkage: unknown` for an ordinary ordinal import, which is both the noise the
routine-cause split keeps out of verdicts and the contradiction the check above refuses.
Omitting the table yields exactly the verdict-less causes; the explicit table is the
override that widens them.

**`pe_ordinal_export` is not exempt.** An exemption for it would be forced by the
containment alone if the ruleset recorded it without a verdict. That is the tail wagging
the dog -- the cause is a failure to read a definition, it carries `OPAQUE`, and an
exemption does not hold up alongside that. "An ordinal export is a failure to read, not
a convention", above, has the measurement.

**`elf_symtab_unread` is not exempt either.** Unlike `pe_ordinal_export`, this one would
not be forced by the containment -- its case for exemption rests on its own claim, that
`.symtab` drives only `stripped` and `symbol_counts.symtab` while the
imported-versus-defined split comes from `.dynsym` alone. That claim does not hold:
`.symtab` is a relocatable object's *only* symbol table when `.dynsym` is genuinely
absent, and it supplies local definitions beside `.dynsym` when there is one. Either way
a failed `.symtab` read costs part of the split, so the cause costs the linkage answer
unconditionally.

The containment holds in one direction only, and it is worth being exact about which.
The loader refuses `routine` that is not a subset of `exclude_reasons`, so dropping an
exemption for a verdict-less cause forces the re-rating. It does not refuse the converse
-- re-rating the verdict while leaving the exemption in place loads clean, because a
cause being worth a verdict and costing linkage nothing is legitimate and is what
`elf_go_buildinfo_unread` is. What holds that side is the exact-set assertion in
`tests/test_linkage.py`, which is a test over the shipped ruleset and so does not reach
a `--ruleset` user. That is the weaker mechanism, and it is weaker on purpose: there is
nothing here to enforce.

`pe_no_import_directory` is exempt on plainer grounds. It fires when the optional header
points at no import directory, or when the walk finished and named no DLL: both are an
absence the reader observed, not a read it fell short of. A walk that fell short carries
`pe_import_incomplete`, which is not exempt, and the two are separate non-`elif`
conditions so the exemption cannot swallow a failed read.

**Two fields stay outside all of this:** `strings_bytes_unread` carries the *reading
gap* into `partial_reasons`, but `strings_truncated` and `symbols_truncated` themselves
stay fields, because a recording cap is not a partial read. "A recording cap is not a
partial read", below, says why, and says what the caps cost instead.

**A partial read that names no cause costs the answer too.** `partial_analysis` true
with an empty `partial_reasons` is the shape `engine` singles out as the most serious
there is -- no reader produces it, so the evidence was built by hand. Reading the empty
tuple as "nothing excluded, so nothing was lost" would make `linkage` the one consumer of
that field that quietly downgrades it.

**What it costs.** Every stripped macOS wheel reads `openssl_linkage: unknown` rather
than `none`, and carries a `BIN_OPENSSL_LINKAGE_UNKNOWN` finding. That is a lot of
wheels, and the honest reading is that we never could answer for them. Their verdict
class is unaffected: `BIN_PARTIAL_FORMAT` has them at `OPAQUE` regardless. What it buys
is that `select(.verdict.conditions.openssl_linkage == "none")` does not quietly include
wheels whose symbol tables nobody read -- a filter the README does not itself suggest,
and a stronger `none` is what would make it worth suggesting.

**Only the libraries reported unconditionally are affected,** which is `openssl` alone in
the shipped ruleset. The signal reaches `_aggregate` already gated on `always_report`, so
an object that did not answer does not list every crypto library in the ruleset as
`unknown`. A false `none` does its damage in the field consumers filter on, and that
field is the one that is always present.

**Whose answer loses.** Only the wheel's. `_aggregate` consults this signal exclusively
when nothing in the wheel answered definitely, so one unreadable object still cannot
erase what the readable ones said.

### The `always_report` gate also covers the opaque fallthrough

`_binary_posture`'s own fallthrough, reached when nothing about an object said `system`,
`bundled`, `static` or `unknown`-via-imported-symbol, returns `LINKAGE_NONE` and never
sets `LINKAGE_UNKNOWN` directly: an opaque object's `unknown` posture is set only through
`_aggregate`'s `unanswered` parameter, gated on `library.always_report`, the same gate
"Only the libraries reported unconditionally are affected" above describes. That keeps
an opaque object from costing every one of the thirteen libraries in the shipped ruleset
an `unknown` posture -- it costs only `openssl`, the one `always_report = true` library:

```
pkg/_ext.so   stripped, no needed, no symbols, no strings -- is_opaque
-> through the always_report gate:      1 "openssl_linkage: unknown" key
-> if the fallthrough answered directly: 13 "*_linkage: unknown" keys, one per
                                          [[crypto_library]] entry
```

The obvious version of `_binary_posture`'s fallthrough -- answering `LINKAGE_UNKNOWN`
directly for an opaque object, inside the loop over every library, bypassing
`_aggregate`'s gate -- stays green against a suite that asks only about `openssl`, the
one library the two routes happen to agree on.
`test_an_opaque_binary_only_costs_the_libraries_always_reported` (`tests/test_linkage.py`)
is what catches it: it pins the whole-ruleset shape, beside
`test_an_unanswered_object_costs_only_the_libraries_always_reported`'s coverage of the
*partial*-read case for the *opaque* one.

## A recording cap is not a partial read

**Accepted. One of the two halves of `truncated` is a cause; the other is a field.**

`strings_truncated` can be set by three different things at once: the byte budget
running out before the object does, and two recording caps. Left as a field alone, with
`partial_analysis` false, the budget half lets an object whose strings pass never reaches
the end of it contribute a definite posture, and the record says both at once:

```
strings_truncated: true
partial_analysis:  false   partial_reasons: []
openssl_linkage:   none    NO_CRYPTO_DETECTED   needs_human_review: false
```

Measured on one `.pyd` carrying an OpenSSL version banner in its last 26 bytes: scanned
whole it is `static` and `CONDITIONAL`; with the byte budget stopping short of the
banner and no cause recorded, the same object is clean. The banner is not a
nice-to-have. `cryptography` 42 and later compiles OpenSSL in, with no library file, no
dependency and no exported symbol, so the banner is the *entire* evidence, and
`MAX_STRINGS_BYTES` is 64 MiB against wheels that ship objects many times that.

**Only the reading gap has a token, and the reason is definitional rather than a
judgement about worth.** `partial_analysis` means part of the object was not read. A
*recording* cap -- more group matches than `max_strings_per_binary`, more crates than
`max_rust_crates_per_binary`, more symbols than `max_symbols_per_binary` -- is not that:
the object was read, and what was capped is what got written down. It is not a member of
the class `PARTIAL_REASONS` enumerates, so the vocabulary is not being asked to hold a
policy. `symbols_truncated` is a recording cap in that sense and gets the same answer.

The alternative is rejected on a harder ground than taste. Minting a cap token as a
fact and then exempting it in the ruleset needs a verdict-less `partial_binary` rule,
which the load-time floor then forces into `[linkage_policy] exclude_reasons` -- a
*second* carve-out on the "unreadable means `OPAQUE`" invariant, which `AGENTS.md` says
is a change to the invariant itself. One carve-out is what that document permits.

**A recording cap has its own way to read clean.** A recording cap looks safe on the
reasoning that it "cannot produce a record that reads clean, because it only fires once
that many matches are in hand". That is false of a plain sort-and-cut, and the
counterexample is four lines:

```
ring alone                 -> NON_APPROVED_CRYPTO  needs_human_review: true
ring + 130 earlier crates  -> NO_CRYPTO_DETECTED   needs_human_review: false
                              strings_truncated: true, partial_analysis: false
```

Sorting crates by `(name, version)` and cutting at 128 lets a Rust wheel carrying three
hundred crates drop everything past the 128th name, and every crypto crate the ruleset
names -- `openssl`, `ring`, `rustls`, `sha1`, `sha2`, `pbkdf2` -- is in the o-to-s range
where `anyhow`-class names crowd it out. The string and symbol caps do the same one step
down: `StringMatch.sort_key` is `(group, value)` and `openssl_banner` is tenth of
thirteen group names, so seventy `mbedtls_` runs take the banner with them.

That is the same failure this entry is about, arriving through a cap rather than a
budget, and the answer is not a `partial_reasons` token but caps that do not drop
evidence a rule could match: "A cap bounds the record, it does not pick the evidence",
below.

**What it costs, and the threshold is not the same in every format.** For Mach-O, PE and
the fallback the budget is measured against the object, so an object over 64 MiB is
`OPAQUE`. For ELF it is measured against the concatenation of eligible read-only
sections, not the file, so a gigabyte `.so` that is mostly `.text` is untouched while a
smaller one carrying a large `.nv_fatbin` is not. That distinction matters here rather
than being a footnote: CUDA and PyTorch wheels, which is where the size is, ship
overwhelmingly as manylinux ELF. Executable sections are read separately, for the
`[[string_group]]` entries flagged `in_code` (see "A version banner that lives in code
is read from executable sections, for the groups that say so"), against their own
budget of the same size -- a second read this same distinction applies to independently,
never sharing room with the read-only one above.

Either way the honest statement is that these were never objects we had read. The
threshold is one constant and the verdict one line of `ruleset.toml`, so the lever is
short if the triage list becomes unreadable -- but the safe default for a new cause is
the strict rule, which is what the ruleset says and what this takes.

Revisit if a real wheel is found on the triage list for this and nothing else.

**What it does not cover.** An object inside the budget whose evidence sits in a region
no reader hands to the strings pass at all -- `binfmt.elf` passes the read-only sections
rather than the file -- is a different question and not this one. Executable sections are
a stated exception: a group flagged `in_code` does reach `.text`, on its own separate
pass and its own budget, while every other group stays exactly where this entry leaves
it.

## A cap bounds the record, it does not pick the evidence

**Accepted, and it changes records.**

Three per-binary limits exist so one object cannot produce an unbounded JSON line:
`max_strings_per_binary`, `max_symbols_per_binary`, `max_rust_crates_per_binary`. None
of them exists to decide which evidence survives, and a limit that sorts its matches and
cuts decides it anyway. The sort key has nothing to do with what a match is worth, and
the crypto names this ruleset claims sit in the middle of every one of those orderings.
With a plain sort-and-cut:

```
ring alone                 -> NON_APPROVED_CRYPTO  needs_human_review: true, findings: 1
ring + 130 earlier crates  -> NO_CRYPTO_DETECTED   needs_human_review: false, findings: 0

banner and its build string alone -> openssl_linkage: static
banner + 70 mbedtls_ runs         -> openssl_linkage: none

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

**The cap works from how little the rules key on.** `binary_string` and `linkage` read a
string's `group`. `dynamic_symbol` and `linkage` read a symbol's `group` and its
`binding`. `rust_crate` reads a crate's `name`. So a cap that keeps one representative of
every key before filling the remainder answers every question the record is read for, and
costs at most one entry per key: thirteen strings, twenty symbols -- ten groups times
two bindings -- and one version of each named crate. `binfmt.caps` holds the walk and
each type says what makes it interchangeable through a `cap_key`, so the fact is stated
once beside the class it is a fact about rather than three times in three readers.

The crate list is the one that needs more than a key. A string or a symbol only reaches
a cap because a group matched it, so every entry is evidence; a crate list is also an
inventory, most of it named by nothing, so the helper takes a `pin` and an unclaimed
crate cannot take the room a claimed one needs. Giving crates their own cap that keeps
every *version* of a claimed crate is rejected: a hundred and thirty-three `openssl`
versions would evict `ring` -- the same failure one path down.

**The binding is part of the symbol key, not decoration.** Keying on the group alone
keeps whichever `EVP_*` sorts first, and if that one is imported then a defined one gets
dropped -- which is `unknown` where the object is `static`, a quieter version of the same
failure. A test pins it.

**What it does not promise.** A second banner from a group already represented still
goes, and so does a particular version of a crate already named. What cannot go is the
last evidence of a group nothing else speaks for. The caps stay, because bounding the
record is a real requirement and this does not weaken it: the limit is still the limit.

The guarantee has one condition, and a ruleset that breaks it is refused at load time
rather than documented: there has to be room for one of every key. `parse_ruleset`
rejects a `max_strings_per_binary` below the string group count, a
`max_symbols_per_binary` below twice the symbol group count, or a
`max_rust_crates_per_binary` below the number of crates named. Below any of those the
choice among keys is the alphabet again, and `SCHEMA.md` states the guarantee without
conditions.

**What it costs.** An object over a limit records a different sample than a sorted
prefix would. Nothing grows: the cap is honoured exactly, and `truncated` still says a
sample was taken.

**What holds it.** Not a test alone. The claim that a cap "cannot produce a record that
reads clean" is false of a plain sort-and-cut, and the Rust wheel above is the object
that disproves it. The admission test `AGENTS.md` names for the carve-out list works on
a claim as well as on a list.

Revisit if a ruleset ever wants limits below its own key counts, which the loader
refuses: the question then is whether to drop the guarantee or raise the limit.

## A forwarder resolves the dependency it forwards to, not just its own name

**Accepted, and it changes what a forwarding wrapper can hide.**

`_read_exports` tells a forwarder from a definition by where its "address" lands --
back inside the export directory, where it is a string rather than code. Recording only
the export's *own* name as imported, and never reading that string, leaves a `.pyd`
exporting `my_digest_init` as a forwarder to `libcrypto-3-x64.EVP_DigestInit_ex` with
neither the DLL nor the real symbol anywhere in the record:

```
own name only        -> needed: [],  matched_symbols: [], NO_CRYPTO_DETECTED,
                        needs_human_review: false
forwarder resolved   -> needed: ['libcrypto-3-x64.dll'], matched_symbols: [EVP_DigestInit_ex/imported],
                        CONDITIONAL (openssl_linkage: system), needs_human_review: true
```

Without resolution, only a wrapper whose *own* export name happens to match the ruleset
is caught, which is coincidence standing in for evidence -- the exact shape the
"unreadable means `OPAQUE`, never `NO_CRYPTO_DETECTED`" invariant exists to rule out,
except here nothing is even unreadable. The bytes sit in the object; a reader has only
to ask for them.

**How it is read.** The forwarder string itself, `OTHERDLL.Symbol` or
`OTHERDLL.#Ordinal`, is read through the same `image.cstring` every other name in this
file goes through, split on its *first* dot -- the DLL half never carries the file
extension, the same convention `NTDLL.RtlAllocateHeap` uses, so `.dll` is appended to
match what `needed` holds for every other dependency. The resolved DLL joins `needed`
beside `imports.dlls`; the resolved symbol, when the string names one rather than an
ordinal, joins `matched_symbols` as `imported` beside the wrapper's own name.

**First dot, not last: splitting on the last dot misses a real shape.** Splitting on
the *last* dot, on the theory that nothing in the format forbids a dot in a DLL name,
misses a real shape: MSVC hot/cold splitting produces symbol names like
`EVP_DigestInit_ex.cold` or `Func.part.0`, so a forwarder to
`libcrypto-3-x64.EVP_DigestInit_ex.cold` last-dot-splits into DLL =
`libcrypto-3-x64.EVP_DigestInit_ex` (garbage, matches nothing in the ruleset) and
symbol = `cold` (also matches nothing), which reads the wheel clean -- exactly the
failure resolving forwarders exists to prevent. A literal dot in a DLL name is not
something the format forbids either, but it is not a shape a real Windows DLL name uses
in practice -- the `.dll` extension is implicit in the forwarder string, never spelled
out -- while a dot in the symbol half is a documented compiler behaviour. First-dot is
the bet that loses less evidence, not a reading the format makes certain: every
forwarder string in the measured corpus carries exactly one dot, so single-dot strings
read identically under either split and the choice only matters for the multi-dot case.

**Why the DLL, not just the symbol.** Recording only the target symbol and leaving
`needed` alone is weaker on the field that matters most: `linkage._binary_posture` reads
`needed` first, and `BIN_NEEDED_SYSTEM_OPENSSL` / `BIN_NEEDED_MANGLED_CRYPTO` key on it,
not on `matched_symbols`. The Windows loader resolves a forwarder exactly like an import
at load time -- it opens the target DLL before it can fail to find the symbol in it --
so the dependency is real in exactly the sense `needed` means, and recording only half
of it would leave `openssl_linkage` blind to a wheel that forwards its whole extension
to system OpenSSL.

**An ordinal-named forwarder reuses `pe_ordinal_import`, not a new token.** A forwarder
to `SOMEDLL.#123` loses the function name the same way an ordinal-bound import does, for
the same reason: the loader opens the DLL regardless, so the dependency survives in
`needed` and only the symbol is unrecoverable. That is the exact shape
`BIN_PARTIAL_ROUTINE` carves out with no verdict, so this reuses it rather than adding a
second cause with the same justification -- the "go and find a crypto object that reads
clean because the cause is on the list" test in `AGENTS.md` finds nothing here that the
ordinal import does not already cover: the dependency name still survives.

**A forwarder string this reader cannot terminate is `pe_export_incomplete`, not a
silent gap.** Past `_MAX_NAME_BYTES` or the object's name budget, `cstring` returns
`None` the same as it does for any other name, and the object is marked incomplete
rather than reported as forwarding to nothing. One fixture,
`test_a_forwarder_at_the_export_directory_s_first_byte_is_still_a_forwarder`, places its
forwarder "address" at the export directory's own header bytes to test the boundary
classification in isolation; there is no real string there to resolve, so that object
carries `pe_export_incomplete` too -- the same honesty the rest of this reader has,
applied to a fixture.

**What was rejected.** Recording only the target symbol and leaving `needed` untouched,
covered above. Inventing a new `partial_reasons` token for the ordinal-forwarder case,
which would duplicate `pe_ordinal_import` for no reason the ruleset could tell apart.
For the split direction itself: recording both candidate splits -- union the
symbol-group matches from both halves, union both candidate DLL names into `needed` --
is rejected as overkill for a case that is, by the corpus this reader was measured
against, vanishingly rare (a forwarder string with more than one dot at all), against a
real cost: doubling `needed` and `matched_symbols` cardinality for every multi-dot
forwarder, cutting against the same record-size discipline `binfmt.caps` exists to
hold. First-dot-as-primary is the cheaper bet and, per the measurement above, the one
less likely to be wrong.

**What it costs.** Every wrapper that forwards to a DLL or symbol the ruleset recognises
reads off `NO_CRYPTO_DETECTED`. Resolving the string is also what introduces a forwarder
that fails to resolve (`pe_export_incomplete`), where reading nothing gives a silent,
wrong `NO_CRYPTO_DETECTED`. And the split-direction choice itself has a real, if judged
unlikely, failure mode: a forwarder string whose DLL half genuinely embeds a literal dot
splits wrong, the same way a last-dot split gets the `.cold` case wrong.
`libcrypto.3.dll` as a DLL name is not actually an example of this -- first-dot still
yields `libcrypto`, `normalise_soname`'s suffix stripping is not the thing at risk, and
the object still resolves `system`. The real shape is a dotted name whose first segment
is not one the ruleset recognises on its own, the way .NET's native shims are named: a
forwarder to `System.Security.Cryptography.Native.OpenSsl.CryptoNative_EvpDigestUpdate`
first-dot splits to DLL `System` and loses the rest, where last-dot would recover the
symbol. Nothing in the PE format rules either shape out, so this is a bet, not a
guarantee, and it is made in the direction the evidence above says loses less: MSVC
hot/cold splitting is default-on compiler behaviour for any MSVC-built wrapper, while a
CPython extension forwarding into a dotted native-shim family is a narrower shape.

Revisit if a real wheel forwards to a DLL name that legitimately carries a dot of its
own -- inside or outside the file extension -- which first-dot splitting would then
misread the way last-dot splitting misreads `.cold`; or if `needed`'s forwarder-derived
entries need their own bound, since `exports.forwarded_dlls` is capped only by the
export directory's own `_MAX_EXPORT_NAMES`/`_MAX_NAME_TOTAL_BYTES` budget, not by
`_MAX_IMPORT_DESCRIPTORS` the way `imports.dlls` is -- large but not unbounded, and a
record-size question rather than a resource-exhaustion one, so left open rather than
given a cap purpose-built for this one source.

## A cap bounds the record, not the evaluation

**Accepted, and it changes verdicts.**

`max_binaries_per_record` exists for the same reason the three per-binary limits in "A
cap bounds the record, it does not pick the evidence" do: one wheel must not produce an
unbounded JSON line. It applies in exactly one place, and that place is deliberate:
capping in `_collect`, before `Evidence` is built, would decide what a rule can see, not
just what a reader sees. With the cap applied to `Evidence`:

```
256 filler .so + one static-OpenSSL .so, sorting 257th (last)  -> NO_CRYPTO_DETECTED
same wheel, crypto object moved to sort 256th (last kept)      -> CONDITIONAL, BIN_STATIC_OPENSSL
```

A cap applied to `Evidence` slices the binaries list before `resolve_linkage`,
`apply_rules` and `classify` ever run over it, so every object past the 256th is still
fully decompressed and read -- the cost paid in full -- and then discarded before
anything downstream looks at it: same object, same wheel, a different verdict, purely
because of where its filename sorts relative to a limit that exists to bound JSON size
and has nothing to do with which evidence a rule sees. `artifacts.binaries_truncated`
does not save this: nothing in the ruleset or `engine._MATCHERS` reads it, so it cannot
correct a verdict computed over a truncated `Evidence`. This is the same class of
failure the per-binary evidence cap avoids for `max_strings_per_binary`,
`max_symbols_per_binary` and `max_rust_crates_per_binary`, one layer up: there the cap
picks which *matches inside an object* a rule can see; here it picks which *objects*
exist at all as far as the rules are concerned.

`_collect` hands `Evidence` the full, untruncated tuple of binaries `scan_binaries`
reads. `resolve_linkage`, `apply_rules` and `classify` see all of it, so the verdict
never depends on sort order relative to a display limit. The cap applies only in
`build_record`, which takes `max_binaries` and slices `evidence.binaries` there, after
findings and the verdict are computed, so only the *serialised* `binaries[]` array is
bounded. `build_inventory` is called with the full list and computes
`binaries_truncated` directly from it.

**What it costs.** A finding's `locations[].path` can legitimately name an object that
is not present in the record's `binaries[]` array: the object was evaluated, a rule
matched something in it, and the cap left it out of the display list anyway.
`SCHEMA.md` says so under both `artifacts.binaries_truncated` and `findings[].locations[]`
rather than leaving it to be discovered. The same shape exists wherever `binaries[]`
disagrees with what `errors[]` or `artifacts.extensions` names, so this is a wider
instance of an existing shape, not a new one.

**`binaries_truncated` is also a finding.** Evaluating every object means a wheel is
never read clean because of where a filename sorts -- but a human reading one JSON line
still cannot tell "156 objects, all listed" from "156 listed out of 400" without
cross-referencing `artifacts.binaries_truncated` against nothing else in the record.
That gap is real, if smaller, and it is what `WHEEL_BINARIES_TRUNCATED` closes: a
`kind = "binaries_truncated"` rule, informational (`severity = "info"`, no verdict,
`needs_human_review = false`), that fires whenever the flag is set and names how many
objects were actually evaluated. It follows the same shape as `WHEEL_RECORD_UNREADABLE`
and the rest of the informational `scan_error` rules: a fact that is not on its own a
reason to look, recorded so it is not only discoverable by a consumer who already knew
to look for `artifacts.binaries_truncated` specifically. It costs one small matcher
function and one rule entry, since `evidence.binaries` is the full count at the point
the rule runs.

**What was rejected.** Giving `WHEEL_BINARIES_TRUNCATED` a verdict, or
`needs_human_review = true`. Once evaluation sees everything, the verdict already
reflects the whole wheel, and treating an ordinary side effect of a display cap as
something a human must act on would put every large Rust or CUDA wheel on a triage list
for a reason that has nothing to do with crypto. That mirrors why `BIN_PARTIAL_ROUTINE`
carries no verdict for an ordinal import: the evidence gap it names is real but does
not, on its own, ask for a person.

Revisit if a consumer needs to reconstruct the *full* per-object list rather than just
knowing it is incomplete -- that is a different feature (streaming or paginating
`binaries[]`, or a `--max-binaries-per-record` raised at scan time) and not something
this entry or `WHEEL_BINARIES_TRUNCATED` attempts.

## `binaries[]` keeps what a finding points at, before filling the rest

**Accepted, and it changes records.**

Evaluating every object in a wheel ("A cap bounds the record, not the evaluation") reads,
links and matches every object against every rule regardless of `max_binaries_per_record`,
so the verdict never depends on where an object's filename happens to sort. The
*display* half is a separate concern: `build_record`'s own `max_binaries` slice cuts
`evidence.binaries` (and, identically, `artifacts.extensions`) to a set of objects, and a
plain path-sorted prefix would repeat the same mistake the per-binary evidence cap ("A
cap bounds the record, it does not pick the evidence") avoids for the per-binary string,
symbol and crate caps, one layer up: a sort key with nothing to do with what a match is
worth would decide what survives. There the unit is a match inside an object; here it is
the object itself, and crypto-relevant objects have no more reason to sort early than
`ring` does among a hundred `anyhow`-class crate names.

A test builds the shape directly: 300 filler `.so` objects plus `pkg/zz1_broken.so` (a
partial ELF carrying an OpenSSL banner) and `pkg/zz2_opaque.so` (unparseable), both
sorting after every filler. With a plain path-sorted prefix:

```
verdict: CONDITIONAL, needs_human_review: true
rule_ids: [BIN_OPAQUE, BIN_PARTIAL_FORMAT, BIN_STATIC_OPENSSL, BIN_UNPARSEABLE]
binaries[]: the first 256 filler objects, neither zz1 nor zz2 present
```

Every finding correctly names one of the two objects that earned the verdict, and
neither object is anywhere in the array a human would read to corroborate it. The
verdict is right; nothing in the record backs it up. This is a completeness gap, not the
correctness gap evaluating every object closes -- the "unreadable means `OPAQUE`, never
`NO_CRYPTO_DETECTED`" invariant is never at risk here, since evaluation sees everything.

**How `binaries[]` is filled.** `record.py`'s `_cap_by_findings` fills `binaries[]` and
`artifacts.extensions` alike, both keyed by object path, in three passes, in the order
a reader would miss it most:

  1. One representative object per `(rule_id, subject)` a finding names, the groups
     themselves visited in a fixed, deterministic order.
  2. Every other object a finding references, in path order.
  3. Everything else, in path order -- the same rule a plain prefix uses for
     everything, when there is nothing to prefer.

`extensions` reuses the same function rather than a parallel copy of it, so the two
arrays keep agreeing on which objects survive the cap: a plain path-sorted prefix would
let them agree by coincidence and disagree the moment one array's cap point fell inside
a finding-referenced run and the other's did not, and there is no reason a reader should
have to learn that they can disagree. `build_inventory` does not cap `extensions`
itself, for the same reason evaluation does not truncate `Evidence.binaries` before the
rules run: it does not have `findings` yet, and capping first is capping blind.

`_cap_by_findings` is deliberately not a call into `binfmt.caps.cap()`, even though
pass 1 above is the same "give every group one slot before filling the rest" shape
that function implements: `cap()`'s grouping is keyed on a `cap_key` that comes from
the *item* (a string's group, a symbol's group and binding, a crate's name), and the
group that matters here comes from the *finding*, not the object -- one object can be
named by several different findings, so the natural key is not a property
`BinaryEvidence` or a bare `(path, format)` pair could sensibly expose through a shared
`Capped` protocol. The *pattern* is the same on purpose; the code is not shared,
because there is no `cap_key` on the object itself for it to share.

**What a flat truncation of the referenced set would cost.** A fallback that skips the
grouping pass -- "referenced objects, then the rest, both in path order," truncating the
referenced set itself once it exceeds the cap -- looks safe against an unbounded worst
case: "four hundred statically-linked OpenSSL extensions, each individually named by
`BIN_STATIC_OPENSSL`." That worst case does not actually happen. `BIN_STATIC_OPENSSL`
is a `kind = "linkage"` rule, and `engine._match_linkage`'s `Hit` always carries
`evidence.filename` as its location, never an individual object's path -- a wheel with
any number of statically-linked extensions contributes *zero* object paths to the
referenced set through that rule, verified directly against a one-object wheel. The real
bound is `[limits] max_locations_per_finding` (10) times the number of *object-naming*
findings, which is small and tractable, not unbounded. Within that tractable bound, a
flat truncation is also severity-blind: a wheel with 270 distinct crate-naming findings
and a cap of 256 lets ten low-severity `getrandom` objects (subject sorts early,
alphabetically) crowd the one `ring` object (`NON_APPROVED_CRYPTO`, high severity,
subject sorts late) out of `binaries[]` entirely, because sorting the referenced set by
path -- or, without the grouping pass, by finding subject -- moves the same
arbitrary-with-respect-to-severity ordering problem rather than solving it. Grouping by
`(rule_id, subject)` and reserving one slot per group first is what closes that: it does
not need to know what "high severity" means, only that every *finding* gets a chance at
a slot before any finding gets a second one.

**What it does not promise, and why this cap is not quite the string/symbol/crate one.**
The per-binary caps are validated at load time: `max_strings_per_binary`,
`max_symbols_per_binary` and `max_rust_crates_per_binary` must each be large enough to
hold one of every group the *ruleset* declares -- a fixed, load-time-known vocabulary.
`max_binaries_per_record` has no equivalent to refuse against: how many distinct
`(rule_id, subject)` groups a wheel's own findings produce is data the wheel supplies,
not policy the ruleset declares, and the real bound above (`10 x` the number of
object-naming findings) is real but wheel-dependent, not a ruleset-fixed count
`parse_ruleset` could check ahead of a scan. When the number of distinct groups itself
exceeds `max_binaries` -- plausible for a large Rust wheel naming many distinct
crates, each its own finding -- pass 1 cannot give every group its slot, and the
groups that lose are whichever sort last by `(rule_id, subject)`, a deterministic but
otherwise arbitrary tie-break, the same posture `binfmt.caps.cap()` documents for its
own analogous case ("the lowest-sorting keys win"). `binaries_truncated` and
`WHEEL_BINARIES_TRUNCATED` still fire whenever this happens, so it is never silent.

**`artifacts.binaries_truncated` and `WHEEL_BINARIES_TRUNCATED` keep their meaning.**
Both mean "the listing is a prefix of the full evaluated set," and neither means *which*
prefix. `build_inventory` computes the flag by comparing the full object count against
`max_binaries`, so a human reading the flag learns the same fact regardless of which
prefix survived: not every object made it into `binaries[]`, and the count in
`WHEEL_BINARIES_TRUNCATED`'s own evidence line is the true, full count. The rule's own
`why` text describes the finding-aware prefix directly, rather than the plain "carries
only a prefix" that a path-sorted cap would justify -- that text is not only internal
documentation: `wheel-crypto-scan rules` and `rules --json` print it verbatim, so it is
user-visible. The flag does not need to be cross-referenced to know whether a
*specific* object a finding names is missing -- it usually is not.

**Determinism.** `_cap_by_findings` sorts explicitly at every step -- the groups
(by key), each group's representative (`min` over its path set), the referenced fill
set, the general fill set, and the final `kept` list -- rather than trusting
`evidence.binaries`' own order or any intermediate `set`'s iteration order, the same
requirement `caps.cap()` documents for its own `sort_key`. The `set`s involved
(`groups`' values, `referenced_paths`, `seen`) are read only for membership or via
`sorted`/`min`, never iterated for output order, so a hash-seed-dependent iteration
order has nowhere to leak into the result. `findings` themselves are deterministic
(`apply_rules` sorts by `(rule_id, subject)` and each finding's own `locations` by
`Location.sort_key`, requirements this selection relies on rather than duplicates), and
each wheel is scanned end to end inside one worker regardless of `--jobs`, so this
selection is exercised by the corpus-level `--jobs` comparisons in `test_cli.py`, plus
one test that shapes a wheel specifically to reach this selection path.

**Cost.** `_cap_by_findings` only runs at all when `len(items) > max_binaries`, and
then does two linear passes over the input plus a handful of sorts bounded by the
number of distinct `(rule_id, subject)` groups, the referenced-path count and the
input size -- no more than a constant factor worse than a plain slice. Building
`groups` and `referenced_paths` is one pass over the already-capped
`findings[].locations[]`, which `[limits] max_locations_per_finding` keeps small
regardless of wheel size, independent of how many distinct findings a wheel produces.
Nothing here is quadratic in the number of binaries or findings.

**What was rejected.** Reusing `binfmt.caps.cap()` directly, covered above. Refusing,
at load or scan time, a `max_binaries_per_record` too small for a synthetic
worst-case wheel's referenced-group count: there is no ruleset-fixed worst case to
check against the way there is for the string/symbol/crate caps, so the check would
either be vacuous or wrong for some real wheel -- the real bound in this entry makes
the *typical* case tractable without making it a guarantee `parse_ruleset` could
enforce. Sorting groups by the rule's own `severity` instead of `(rule_id, subject)`
for pass 1: it would remove the one remaining arbitrary tie-break in the case groups
outnumber the cap, but `severity` is ruleset policy threaded through a `Rule`, not a
property of a `Finding` the record layer holds without a lookup, and no real wheel has
been found where the deterministic-but-arbitrary key actually costs a group its slot --
revisit if one is.

Revisit if a real wheel is found whose findings alone produce more distinct
`(rule_id, subject)` groups than `max_binaries_per_record` allows, and the lost
corroboration for the group that did not fit turns out to matter in practice -- that
would be the same question "A cap bounds the record, not the evaluation", above, leaves
open for the fully-unbounded case: reconstructing the full per-object list is a
different feature (streaming or paginating `binaries[]`) from what this entry or
`WHEEL_BINARIES_TRUNCATED` attempts.

## Sections are found by type, not by a name nobody checks

**Accepted, and it changes records.**

Comparing `section.name` against `.dynamic`, `.dynsym` and `.symtab` trusts a label, but
the ELF *loader* never reads section names or the section header table at all: it walks
`PT_DYNAMIC` and the tags it points at. A name-based lookup trusts a label nothing
downstream of the compiler checks. Found by name:

```
honest: EVP_DigestInit_ex, SSL_new imported, libc.so.6 in DT_NEEDED
.dynsym renamed .dynsyx in .shstrtab, same bytes otherwise  -> NO_CRYPTO_DETECTED,
                                            needs_human_review: false, partial_analysis: false
```

Renaming `.dynamic` too empties `needed` as well, and the object still loads and runs
through `ctypes` regardless: the loader never reads section names, so only what one
label in `.shstrtab` says changes.

**Two parts, because two different shapes produce the same silence.**

`.dynamic`, `.dynsym` and `.symtab` are found by `sh_type` (`SHT_DYNAMIC`,
`SHT_DYNSYM`, `SHT_SYMTAB`) rather than by name. `pyelftools` builds the right wrapper
class -- `DynamicSection`, `SymbolTableSection` -- from `sh_type` alone; the name only
ever becomes the object's `.name` attribute, which this reader is the only thing
reading. `.go.buildinfo`, `.note.go.buildid` and `.comment` stay name-based: they are
plain `SHT_PROGBITS`/`SHT_NOTE` sections with no type of their own, so a name is the
only signal there is, and staying name-based for these three is a scope boundary, not
an oversight.

The second shape is not a renamed label but no section header table at all:
`e_shoff == 0` is a loadable object's own right, since the dynamic linker never reads
one. Unhandled, that reads worse than a header that would not parse: `_unparsed` scans
the whole file for strings when the ELF header itself is unreadable, but an empty
section list feeds nothing to `_collect_string_bytes`, so a statically-linked
`cryptography` extension with no section headers would lose even its OpenSSL version
banner -- its only evidence -- with no error and `partial_analysis: false`.
`e_shnum == 0` (with `e_shoff == 0`) is caught right after the section list is built,
before `.dynamic`/`.dynsym`/`.symtab` are even looked for, and falls back to the same
whole-file strings pass `_unparsed` uses, tagged with a cause of its own.

**`elf_section_table_absent` is its own token, not a reuse of `elf_sections_unread`.**
`elf_sections_unread` means "a section header could not be read", a failure at a
section this reader tried and failed to look at; here there is no section list to try
at all, so `.dynamic`, `.dynsym` and `.symtab` are not merely unread but unavailable,
and `needed`, `soname`, `rpath`, `runpath`, the symbol split and `stripped` follow suit.
Reusing `elf_sections_unread` would blur a fact a consumer can rely on: that cause fires
only when the reader tried and failed at specific section indices. This one always
fires as a single, whole-object fact, closer in shape to `elf_dynamic_unread` and
`elf_dynsym_unread` combined than to a section-read failure, and it records an error the
same way those two do, rather than the way `pe_no_import_directory` does: an object that
carries structural information but chose not to declare a table (as PE's absent import
directory legitimately can) is a different fact from an ELF `.so` shipping with no
section headers at all, which every real toolchain still emits for a dynamically-loaded
library.

**A name-based lookup and a naive type-based one both leave gaps a forged or
duplicated section can hide behind.** Four distinct forgery shapes need their own
defense, since each defeats a different assumption the lookup makes.

**A decoy of the target type, sitting ahead of the real one, must not win by sorting
first.** A "first section of a matching type wins" rule lets a decoy hide the real
table: two 64-byte decoy section headers spliced in *before* the real `.dynsym` and
`.dynamic` on a real, loadable `/usr/lib64/libcrypto.so.3` (`sh_name = 0`,
`sh_size = 0`, `sh_link` pointing at `.shstrtab` rather than a real string table, every
other `sh_link` and `e_shstrndx` past the insertion point shifted by one to stay valid,
`e_shnum` bumped) leaves the object loading and running exactly as before, while a
lookup that stops at the first match of the right type reads `needed = ()`, no soname,
0 symbols, `partial_analysis: false`, 0 errors, against the honest
`needed = ('libc.so.6', 'libz.so.1')`, a soname, and 6043 dynsyms the same object
actually carries. The symbol/string cross-check (`binfmt.symtab`, "A symbol table is
checked against the string table, not taken at its word") does not help here: it is
sound only over the string table the *chosen* section's `sh_link` actually names, and
the decoy's `sh_link` points at `.shstrtab` instead of `.dynstr`, which disarms it
entirely rather than tripping it -- `sh_link` itself needing its own check is a separate
defense, below.

`_find_section_by_type` reports ambiguity rather than returning a single answer when
more than one section shares the type it is looking for, and the caller trusts neither
candidate: `needed`, `soname`, `rpath`, `runpath`, the symbol split and `stripped` all
read empty, the same shape as "nothing of that type exists" -- but tagged
`partial_analysis: true` with its own cause, `elf_section_type_ambiguous`, so an object
carrying two `SHT_DYNSYM` sections never reads as one carrying none. Tests cover both
orderings, decoy after the real section (`append_duplicate_dynsym_section`) and decoy
ahead of it (`insert_bogus_section_before`, the shape measured above on a real object);
both read `elf_section_type_ambiguous`.

**A forged `sh_type` on a legitimately-named section must not read as fully absent,
which would be worse than trusting the name blindly.** One four-byte edit --
`.dynsym`'s `sh_type` changed from 11 (`SHT_DYNSYM`) to 1 (`SHT_PROGBITS`), the name
`.dynsym` left untouched -- and the object still loads. A name-based lookup still
finds the section and reads it partially: `pyelftools` builds the wrong wrapper class
for the forged type, `num_symbols()` fails, `partial_analysis: true` with
`elf_dynsym_unread`, but `_symbol_bytes` reads the raw symbol bytes by `sh_offset` and
`sh_size` directly rather than through the wrapper, recovering 2 symbols on a synthetic
object and 64 on a real `libcrypto.so.3` alongside the partial flag. A type-based
lookup alone finds nothing for the forged section -- it does not match `SHT_DYNSYM` --
and treating that the same as a genuinely absent section is strictly worse: no partial
flag, no error, no symbols, confidently wrong instead of conservatively partial.

`_type_mismatch` closes it: a name-based lookup checks whether a section still called
`.dynamic`, `.dynsym` or `.symtab` exists whose declared `sh_type` does not match what
that name is supposed to mean. If it does, that is a section that exists and cannot be
trusted, not one that is absent, and it is folded into the same cause a read failure on
that section carries -- `elf_dynamic_unread`, `elf_dynsym_unread` or
`elf_symtab_unread` -- rather than given a token of its own: the fact ("this section
could not be read") is the same fact a raw exception on it names, whichever way it fell
short. This does not go as far as raw-byte recovery from the forged section; the
requirement is only that the shape can never read `partial_analysis: false` with zero
evidence, which folding it into the existing partial cause satisfies without a second
reader for the symbol table's raw bytes.

**The mismatch check must run regardless of what the type-based lookup found
elsewhere, or one decoy of the target type disables it for the real section too.**
Gating `_type_mismatch` on `dynsym is None` -- "check by name only once the
type-based lookup has drawn a blank" -- leaves a gap: one harmless decoy `SHT_DYNSYM`
section (the same construction as above, `sh_link` pointing at `.shstrtab`) makes the
type-based lookup succeed *unambiguously*, exactly one candidate of that type, so the
gate never fires. Combine that decoy with forging the real, correctly-named `.dynsym`'s
own `sh_type` away, and the real section is invisible from both directions at once: not
found by type (its type does not match), and not checked by name (the gate that would
catch it never runs because something else satisfies the type-based lookup first).
With the gated check:

```
honest:       partial=False needed=('libc.so.6',) syms=['EVP_DigestInit_ex','SSL_new']
              linkage={'openssl':'unknown'} verdict=OPAQUE      needs_human_review=True
decoy+forge:  partial=False needed=('libc.so.6',) syms=[]       errors=0
              linkage={'openssl':'none'}    verdict=NO_CRYPTO_DETECTED needs_human_review=False
```

The mismatch check runs unconditionally at all three call sites, regardless of what
the type-based lookup found elsewhere. It costs nothing on an honest object --
`_type_mismatch` is `False` whenever the name-based and type-based lookups agree,
which is every fixture in the suite -- and it only fires for exactly the shape that is
otherwise unguarded: a section found by name whose type does not match, irrespective
of whether some *other* section satisfies the type-based lookup in its place. Tests
cover a decoy plus a forged real section for all three of `.dynamic`, `.dynsym` and
`.symtab`.

**The mismatch check's own name lookup needs the same ambiguity guard `_find_section_by_type`
gets, or a same-named decoy defeats it the identical way.** Finding "the section named
X" with `_find_section`, "first match in section order wins", is the same hazard
`_find_section_by_type` guards against, just applied to name instead of type. A decoy
that reuses the real section's own *name* -- `.dynsym`, say -- rather than its type,
sorts first, is correctly typed (that is the trick), and reports no mismatch, so a
same-named real section sitting behind it with its own forged `sh_type` is unseen from
both directions again: not found by type (wrong type), and not caught by the mismatch
check (ambiguous by name rather than by type). With a first-match name lookup:

```
honest:            partial=False needed=('libc.so.6',) syms=['EVP_DigestInit_ex','SSL_new']
same-name decoy
  + real forged:    partial=False needed=('libc.so.6',) syms=[]           errors=0
```

`_type_mismatch` treats more than one section sharing `name` the same way
`_find_section_by_type` treats more than one sharing `sh_type`: untrusted, folded into
the same partial cause. `insert_bogus_section_before` takes a `same_name` option to
build this fixture (reusing the target's own `sh_name` offset instead of the empty
string), and `patch_section_header` takes an `occurrence` parameter to reach the
second, real section behind the decoy rather than the decoy itself. Tests cover all
three of `.dynamic`, `.dynsym` and `.symtab` for this shape too.

**It costs the linkage answer, on purpose.** `elf_section_table_absent` and
`elf_section_type_ambiguous` are not in `[linkage_policy] exclude_reasons`.
`elf_go_buildinfo_unread` and `pe_no_import_directory` are excluded, and each leaves
every field `linkage` reads intact: `.go.buildinfo` feeds nothing `linkage` touches, and
an absent PE import directory is a declaration the object really makes.
(`elf_symtab_unread` is not excluded, because `.symtab` feeds the imported/defined
split -- see "Linkage reads a second split over the same vocabulary".) Neither
section-table cause fits the excluded pattern: `needed`, the imported/defined split and
`matched_strings` are what `linkage` reads, and a sectionless or ambiguous object has
answered none of them -- `needed` is not "no dependencies", it is "we could not ask" or
"we cannot tell which answer is real". Excluding either would read
`openssl_linkage: none` off an object that told us nothing, the same failure "A symbol
table is checked against the string table, not taken at its word" measures for a lying
`nsyms`.

**What was rejected.** Reading `PT_DYNAMIC` and the program headers directly, as the
primary or a fallback mechanism. It is the more complete answer, the loader's own
path, immune to a section header table that is present but lies in some way a
type-based or name-based check does not cover. It is also materially more work, a
second parser for information this reader gets from section headers in the common
case. The defenses above, closing both the ambiguous-candidate gap and the
forged-`sh_type`-on-a-still-named-section gap, close every shape actually measured
without it, so it stays out; see the residual sections below for what it would still be
needed for.

**What it costs.** Records differ from a name-based reader's for a renamed section
(read by type), for a sectionless object (`partial_analysis: true` with the whole-file
strings pass, where it would otherwise be a silent, complete-looking read), for an
object with more than one section of a type this reader looks for
(`partial_analysis: true` with `elf_section_type_ambiguous` instead of whichever
candidate sorts first), for a section found by name whose `sh_type` is forged (folded
into the existing partial cause for that section instead of reading as absent), for a
decoy of the target type sitting beside a real section forged away from that type
(caught by the unconditional mismatch check), for a decoy sharing the real section's
*name* rather than its type (caught the same way, since `_type_mismatch` does not trust
the first same-named section it finds either), and for a decoy string table `.dynsym` or
`.dynamic`'s `sh_link` names without corroborating `.dynamic`'s own `DT_STRTAB` (folded
into `elf_dynsym_unread`/`elf_dynamic_unread` the same way, and cascading to cost
`.dynsym` too whenever `.dynamic` itself cannot be read).

**`sh_link` itself needs its own validation, the same underlying pattern --
an attacker-controlled label winning a lookup so the check meant to catch a mismatch
never runs -- reached through a different field than the section lookups above.**
Resolving `.dynsym`'s string table with `elf.get_section(section["sh_link"])` and
nothing else -- no check that the resolved section is even a string table, and no
reconciliation against `.dynamic`'s own `DT_STRTAB` tag, which `read_elf` parses anyway
-- trusts a section-header field the loader never reads either: `.dynamic` and `.dynsym`
both resolve names through `PT_DYNAMIC`'s `DT_STRTAB` tag, never through any section's
`sh_link`. Trusting it outright is the identical hazard the defenses above close for
`.dynamic`, `.dynsym` and `.symtab` themselves, one level further down, in the one place
a section would otherwise be picked by a raw index with no check at all.

Reproduced against a reader that trusts `sh_link`, and independently on real, unmodified
loadable objects (`/usr/lib64/libcrypto.so.3`, a real CPython `_hashlib` extension):
append `N` NUL bytes plus a new `SHT_STRTAB` section header pointing at them, then
repoint `.dynsym`'s `sh_link` at that index. Every symbol name index resolves to `""`
against an all-NUL table -- `names.find(b"\x00", st_name)` finds a terminator at
`st_name` itself, so the empty slice is a name *resolved*, not one flagged unresolved
-- and `""` fails `patterns.symbol_groups_for` the same way any name nothing claims
does. `libcrypto.so.3`'s 64 crypto symbols, and a real `_hashlib` extension's 24, both
go to zero, `partial_analysis: false`, no error, both objects still loading and running
unmodified otherwise.

`.dynamic`'s own `sh_link` has the identical hole and is worse: it can *fabricate*
evidence, not just erase it. `.dynamic` resolves `DT_NEEDED`/`DT_SONAME` strings
through the same `sh_link`, so a decoy that happens to spell a real dependency name at
the byte offset a real `DT_NEEDED` tag points at reports a dependency the object never
declares -- an invented name, not a truncated one, which is the fabrication direction of
"A name reported is a name read in full" rather than the truncation direction.

Both are reconciled against data this reader has in hand. `.dynamic`'s own `sh_link`,
once `.dynamic` is read, is checked against its own `DT_STRTAB` tag; `.dynsym`'s
`sh_link` is checked against that same address, threaded through as `dt_strtab_addr`.
`DT_STRTAB`'s `d_ptr` needs no string resolution itself -- it is a raw pointer value in
the tag -- so it is available to check against even when the string table it names
cannot be trusted. A resolved section corroborates only when its `sh_type` is
`SHT_STRTAB` *and* its `sh_addr` matches `DT_STRTAB`'s `d_ptr`; either mismatched, or no
`DT_STRTAB` to compare against at all (`.dynamic` itself unreadable or missing the tag),
fails closed rather than trusting `sh_link` unwitnessed. On failure the string table is
treated as unresolved -- `_symbol_bytes` returns `b""` for `.dynsym`'s names, which the
`unresolved` counter turns into `elf_dynsym_unread`, and `.dynamic`'s own
`needed`/`soname`/`rpath`/`runpath` are reset to empty under `elf_dynamic_unread` the
same way an exception on `.dynamic` does. No new `partial_reasons` token: both fold into
causes that already mean "this table's contents could not be trusted."

This cascades, correctly: an object whose `.dynamic` cannot be read or corroborated
has no `DT_STRTAB` to hand `.dynsym` either, so `.dynsym`'s string table is untrusted
too even when `.dynsym`'s own `sh_link` is perfectly honest. Every fixture that
exercises a broken or ambiguous `.dynamic` also carries `elf_dynsym_unread` for exactly
this reason -- deliberately: the alternative is trusting a symbol table's string
resolution with no witness for it, which is the same "reads clean because nothing
checks" shape as the rest of this entry.

**What it costs.** Nothing on the honest path: `ElfBuilder`'s own fixtures, and every
real object this was tested against, have `.dynstr`'s `sh_addr` and `DT_STRTAB`'s
`d_ptr` agree (both are conventionally 0 in this suite's synthetic objects, and
correctly non-zero and matching on the two real ones this was verified against), so
`_validated_strtab` returns the same section `sh_link` names. The added cost is one more
section-header fetch and a bounded scan of `.dynamic`'s own tags for `DT_STRTAB` -- both
O(1) against the object, not against symbol count -- so the hot path this module is
written around, hundreds of thousands of dynamic symbols in one object, reads exactly
as many bytes as it would without the check.

**What was rejected, again.** Full program-header-based virtual-address-to-file-offset
translation, to also catch a decoy that is correctly typed *and* correctly addressed
but whose `sh_offset` alone is forged to point at fabricated bytes at the same virtual
address. Closing that needs `PT_LOAD` segment parsing, deliberately deferred as the
program-header approach -- see below, grouped with the other shapes only program
headers would close.

**Whether ambiguity detection can false-positive on a real wheel.** No real toolchain
in this reader's own test corpus emits two `SHT_DYNSYM` or
`SHT_DYNAMIC` sections in one object; the shape is adversarial or hand-crafted in every
example measured here, never something `gcc`, `rustc`, `go build` or `objcopy` produce
on their own. `elf_symtab_unread`-style tokens accept the same tradeoff for a single
section that fails to read, so treating an ambiguous one the same way -- opaque rather
than guessed at -- is the conservative direction this file takes throughout, not a new
risk class. Revisit if a real, non-adversarial wheel is found carrying more than one
section of the same type nonetheless: closing it would need a second signal beyond
`sh_type` to break the tie (position, `sh_link` validity, `.dynamic` tag content), a
larger mechanism than this one token.

Revisit also if a real wheel is found carrying a section header table whose contents
lie in some way neither ambiguity detection nor the name/type mismatch check catches --
for example a forged `sh_type` that happens to collide with a *different* legitimate
section's type rather than a generic one like `SHT_PROGBITS` -- which is exactly the
class of gap the program-header approach would close structurally and this does not
attempt to.

**Accepted residual, grouped with the two above: `sh_addr` matching while `sh_offset`
alone is forged.** A decoy resolved through `sh_link` that is correctly typed
`SHT_STRTAB` *and* whose `sh_addr` correctly matches `.dynamic`'s own `DT_STRTAB` --
but whose `sh_offset` (the file position, as opposed to the virtual address `sh_addr`
declares) alone points at fabricated bytes -- still reads clean. `sh_addr` and
`sh_offset` are two different claims a section makes about itself, and this reader
checks one against `.dynamic`'s independent testimony (`DT_STRTAB`) without a way to
check the other: nothing outside `PT_LOAD` segment contents corroborates that a given
virtual address really lives at a given file offset. Closing it needs the same
program-header-based virtual-address-to-file-offset translation the other two
residuals need -- reading `PT_LOAD` segments to translate an address independently of
any section at all -- which is deliberately deferred rather than one more targeted
check like the defenses above. Do not chase this by adding a sixth targeted field
comparison; the next real gap in this family is answered by the program-header
approach as a whole, not by another field.

## A `needed` entry is bundled by what it resolves to, not by whether its name was renamed

**Accepted, and it changes `openssl_linkage` and one finding.**

Keyed on the name alone, a base name in a crypto library's `sonames` is `bundled` only
when the name itself carries a content hash (`libcrypto-3a1f2b4c.so.3`), otherwise
`system`. That is exactly what auditwheel and delvewheel produce, and it is not what
delocate produces. delocate, the macOS counterpart of auditwheel, copies a dependency
into `.dylibs/` and rewrites the load command to point there -- `@loader_path/
.dylibs/libcrypto.3.dylib`, or `@rpath/libcrypto.3.dylib` plus an `LC_RPATH` -- without
renaming the file. `normalise_soname` reduces either to the plain base `libcrypto`,
unmangled, so by name alone the extension reads `system` while the vendored copy sitting
right next to it, under `.dylibs/`, independently reads `bundled`: two postures for one
OpenSSL, `_aggregate` calling it `mixed`, plus `BIN_OPENSSL_LINKAGE_UNKNOWN` ("could not
be resolved") and `BIN_NEEDED_SYSTEM_OPENSSL` ("Links the system OpenSSL") both firing
-- wrong on every count. The same shape reaches ELF too: nothing stops a build placing
an unmangled dependency beside the extension with `RUNPATH $ORIGIN`.

```
pkg/_ext.cpython-312-darwin.so   needed: @loader_path/.dylibs/libcrypto.3.dylib
pkg/.dylibs/libcrypto.3.dylib    vendored_path: true, defines EVP_DigestInit_ex, SSL_new
-> by name alone: openssl_linkage: mixed, BIN_OPENSSL_LINKAGE_UNKNOWN, BIN_NEEDED_SYSTEM_OPENSSL
-> by resolution: openssl_linkage: bundled, BIN_BUNDLED_OPENSSL
```

**Two parts, matched to the two ways a `needed` entry can prove it names a file the
wheel ships.** `Conventions.raw_stem` reduces a name the same way `own_base` does --
strip path, version suffix, library extension -- but stops short of undoing a
content-hash rename, which is what keeps it from being the same question `own_base`
answers. `linkage.member_stem_counts` counts every object's `raw_stem` across the wheel,
and a `needed` entry whose own `raw_stem` some other object answers to is `bundled`,
mangled or not: this is what makes the delocate case, and the plain
ELF-beside-the-extension case, resolve without touching mangling at all. Second,
`linkage._looks_vendored` reads the `needed` string itself (`Conventions.is_vendor_path`,
which recognises `.dylibs` and `*.libs` as path components regardless of what comes
before them) and, for `@rpath`-relative names, the object's own `LC_RPATH` list combined
with it, or for a bare ELF name, its `RPATH`/`RUNPATH`. This is a weaker signal used
only as a backstop: it never asserts `bundled` by itself.

**Why the path-convention half is capped at `unknown`, never `bundled`.** A `needed`
entry can look exactly like delocate's convention and still name nothing the wheel
actually ships -- a broken build, a load command nobody rewrote, a symlink `is_binary_
member` never follows into a record. Letting the shape alone promote to `bundled` would
manufacture the same overconfidence in the opposite direction: a wheel that plainly
resolves to nothing being told with certainty that it carries its own copy. So a
`needed` entry that looks vendored but that `member_stem_counts` cannot confirm reads
`unknown`, the same answer this tool gives for "an object was read too little to say",
not `system` (which repeats the unmangled-dependency gap in a new spot) and not
`bundled` (which would manufacture certainty this reader does not have).

**Why `member_stem_counts` is enough on its own for both real reproductions.**
`raw_stem` only looks at the trailing file name, and a `needed` entry's own path prefix
(`@loader_path/`, `@rpath/`, `$ORIGIN/`) never survives into that trailing component,
so matching on it is prefix-agnostic: `@rpath/libcrypto.3.dylib` and `pkg/
.dylibs/libcrypto.3.dylib` share the same `raw_stem` without any `@rpath`/`LC_RPATH`
resolution being consulted. `_looks_vendored`'s `@rpath` and `RPATH`/`RUNPATH` handling
earns its place on a narrower case: a member that is not independently a
`BinaryEvidence` at all (a symlink `layers.binaries` never follows into a record, or an
object dropped for a total read failure) has no `raw_stem` for `member_stem_counts` to
hold in the first place, and the path shape is the only thing left to read off. Each
half is pinned by its own tests, measured by mutation:
`test_an_unmangled_elf_dependency_beside_the_extension_is_bundled` goes `system` without
the `member_stem_counts` half, and the incompletely-read tests in `tests/test_linkage.py`
(a member that could not be read, a member the archive skipped, a symlinked vendored
library) go `system` without `_looks_vendored`. None of them needs both halves at once.

**Scope.** Resolution is one more way a `needed` entry can reach `bundled`, inside the
per-entry loop, not a restructuring of `_binary_posture`. The precedence question
between `needed` and `defined` within one object is answered separately (see "A
`needed` match and a definition inside one object are both true, so the object is
`mixed`", below); the `is_opaque` arm's per-library fan-out is answered separately too
(see "The `always_report` gate also covers the opaque fallthrough", above).

**A residual: basename, not directory.** `member_stem_counts` matches on file identity
alone, not on directory. Two different libraries that happen to share a basename in
different parts of the same wheel -- unusual, but not forbidden by any format here --
would let an unrelated `needed` entry read as `bundled` because *something* in the
wheel answers to that name, not because the referenced object actually does. Resolving
that precisely needs walking the actual search path (`@rpath` order, `RUNPATH` entries,
the standard library directories) to the specific candidate file, which is a
meaningfully bigger mechanism than the shapes measured here call for. Recorded rather
than closed, because the failure direction it can produce -- reading `system` as
`bundled` -- is the safe one for a FIPS-risk tool: it never manufactures the clean
answer, and the false-`bundled` outcome only fires when the wheel ships *some other*
object under that literal name, which is itself circumstantial evidence worth a human's
attention.

Revisit if a real wheel is found where this collision actually happens.

### What resolving by basename does not prove

**Accepted, and it changes `openssl_linkage`.**

Resolving a `needed` entry by basename alone proves less than it first appears to. A
150-shape differential matrix over real and synthetic wheels finds two claims weaker than
they read: that a false `bundled` needs a second object under the same name, and that
`_looks_vendored`'s path handling stays confined to the narrower case above.

**A false `bundled` from basename alone does not need a second file; a single object
can match itself.** A second object under the literal name is circumstantial evidence
worth a human's attention, and that is the *two-file* collision the residual above
describes. It is not the sharpest shape a stem lookup admits: a *single* object, no
vendor directory, no second file, whose own file name happens to reduce to the same stem
as an absolute, genuinely-system dependency it declares --

```
fakecrypto/libcrypto.so   soname: libcrypto.so
                          needed: /usr/lib64/libcrypto.so.3, libc.so.6
-> without an own-stem discount: openssl_linkage: bundled, verdict.class: NO_CRYPTO_DETECTED,
                                  rule_ids: [], needs_human_review: false
```

Counting the querying object itself lets the object answer its own question:
`/usr/lib64/libcrypto.so.3` can never resolve to the object that names it, under any
real search order, whatever that object happens to be called. Worse than a wrong
posture, that `bundled` has no rule behind it unless one claims it: resolution is a
*third* route to `openssl_linkage: bundled` besides the vendored member's own record
(`BIN_BUNDLED_OPENSSL`) and a literal hash rename (`BIN_NEEDED_MANGLED_CRYPTO`).
`BIN_LINKED_CRYPTO_LIBRARY`'s own `why` names exactly this failure mode for every other
library and excludes openssl on the understanding that openssl's own rules cover it, so
openssl's rules have to cover this route too.

**Two parts.** The stems are counted (`member_stem_counts`, a `collections.Counter`),
not collected into a set, and `linkage._resolves_within_wheel(own_stem, needed_stem,
counts)` discounts an object's own contribution to its own answer: confirmation
requires a *second* contributor when the querying object's own stem is the one in
question, and any contributor at all otherwise -- so a genuinely different object that
happens to share the declaring object's stem still confirms it (the two-file case stays
possible, on purpose). Second, a rule, `BIN_NEEDED_VENDORED_CRYPTO`
(`kind = "dt_needed"`, `table = "crypto_library"`, `resolved = true`), fires whenever
`needed_posture` reads `bundled` off this path and the name was not literally mangled,
so this third route to `bundled` is claimed the same way the other two are, and the
residual imprecision the two-file case allows
(`test_the_documented_basename_collision_residual_still_carries_a_finding`,
`test_the_basename_collision_residual_is_never_silent`) is never silent about it:
`needs_human_review` is `true` even when the `bundled` classification itself is a false
positive from the coincidence.

**`_looks_vendored` needs a gate; unguarded, it fires whenever the object has *any*
vendor-shaped `RPATH`/`RUNPATH`/`LC_RPATH`, independent of whether the specific
`needed` entry in question could plausibly resolve under it.** The matrix finds this
misreading a genuine system dependency as `unknown` on 11 of 150 shapes, on both ELF and
Mach-O: a FIPS-conscious build that runs auditwheel's `--exclude libcrypto.so.3` (a
real, intentional pattern) while vendoring an unrelated library, say libjpeg, in the
same wheel --

```
fakecrypto/_ext.so        needed: libcrypto.so.3, libc.so.6
                          runpath: $ORIGIN/../fakecrypto.libs
fakecrypto.libs/libjpeg.so.8   (unrelated to OpenSSL)
-> without the gate: openssl_linkage: unknown, verdict.class: OPAQUE, BIN_OPENSSL_LINKAGE_UNKNOWN
```

The `RUNPATH` is vendor-shaped because the wheel vendors libjpeg, not because anything
there could be OpenSSL, and a wheel this tool can read in full is exactly the case where
it does not need to guess the way a real dynamic loader would: `member_stem_counts`
speaks for everything the wheel ships.

**How the gate works.** `linkage.wheel_incompletely_read(evidence)` is `true` only when
some member never became a `BinaryEvidence` at all -- skipped by an archive-level limit
(`artifacts.skipped`), a member that raised on open or failed its CRC (`errors` at
`STAGE_BINARY`), or a symlink (`artifacts.symlinks`, below). `needed_posture` consults
`_looks_vendored` -- and can therefore read `unknown` -- only when that is `true`; when
the wheel was read in full, a vendor-shaped path naming nothing `member_stem_counts`
confirms is genuine `system`, because a complete member list that does not contain the
answer is itself the answer. `unknown` stays reachable for a wheel that genuinely was
not read in full (`test_a_vendor_shaped_path_is_unknown_when_a_member_could_not_be_read`,
`test_a_vendor_shaped_path_is_unknown_when_the_archive_skipped_a_member`), which is the
narrower case the path shape exists for.

**`_looks_vendored` has one combining branch, not an `@rpath/`-specific one.** A
separate `@rpath/` branch is redundant -- removing one fails nothing -- because the
generic join (the *whole* `needed` string, `@rpath/` prefix included, joined to each
`RPATH`/`RUNPATH`/`LC_RPATH` entry) finds a vendor-directory component anywhere in the
combined path, prefix garbage or not.

### How `_looks_vendored` is gated, and what pins it

**Accepted. The gate is pinned on both the shape side and the completeness side.**

Two more shapes the gate above must not miss:

**The vendor-shape check inside the gate is pinned by its own test.**
`test_a_plain_dependency_stays_system_even_in_an_incompletely_read_wheel` builds a wheel
that is incompletely read (a `STAGE_BINARY` error on an unrelated member) with a needed
entry that is plainly not vendor-shaped, and pins `system`. It fails if `_looks_vendored`
returns `True` unconditionally, and it is the only test that does: the tests around the
`incomplete` gate pin the gate in both directions, not the shape check inside it. That
mutant would reintroduce the over-firing false-positive family above for every
incompletely-read wheel carrying a plain, non-vendor-shaped dependency, just moved behind
"and the wheel happens to be incomplete for an unrelated reason" instead of firing
unconditionally.

**`wheel_incompletely_read` checks `artifacts.symlinks` too, or the gate is wrong for a
symlinked vendored library.** `layers.binaries.is_binary_member` returns `False` for
every symlink, so a vendored library shipped as one -- a real shape: a versioned
`.so`/`.dylib` left as a symlink to the real file is ordinary practice -- is never read
as a binary at all. It records neither a `skipped` entry nor a `STAGE_BINARY` error, only
`artifacts.symlinks`, so leaving that unconsulted reads:

```
demo/_ext.abi3.so               needed: @loader_path/.dylibs/libcrypto.3.dylib
demo/.dylibs/libcrypto.3.dylib  -> a symlink, never read as a binary at all
-> without checking artifacts.symlinks: openssl_linkage: system,
   BIN_NEEDED_SYSTEM_OPENSSL ("Links the system OpenSSL"),
   DERIVED_SYSTEM_OPENSSL_ONLY ("All OpenSSL use resolves to the system library")
```

Both finding descriptions are affirmatively wrong here: an `@loader_path`-anchored load
command is wheel-internal by construction and can never be the host's system OpenSSL.
`needs_human_review` is `true` either way, so this is never silent, but it would be
confidently wrong rather than honestly uncertain, which is the distinction this whole
entry exists to draw. `wheel_incompletely_read` checks `evidence.artifacts.symlinks`;
`test_a_symlinked_vendored_library_is_treated_as_incompletely_read` pins it.

**Every `bundled` has a rule, by enumeration.** For every `bundled` `_binary_posture`
can produce, a rule fires: the vendored-member path (`BIN_BUNDLED_OPENSSL`), the
literal-rename path (`BIN_NEEDED_MANGLED_CRYPTO`), and the resolves-within-the-wheel path
(`BIN_NEEDED_VENDORED_CRYPTO`), audited one branch at a time against the places
`_binary_posture` reaches `LINKAGE_BUNDLED`. But `system` has an aggregate-level
backstop no per-mechanism enumeration needs to keep in step -- `DERIVED_SYSTEM_OPENSSL_ONLY`
fires off `linkage.get("openssl") == "system"` directly, whatever mechanism produced it
-- and `bundled` does not: no aggregate rule stands behind it the way
`DERIVED_SYSTEM_OPENSSL_ONLY` stands behind `system`. That asymmetry holds for every
mechanism; `BIN_BUNDLED_OPENSSL` and `BIN_NEEDED_MANGLED_CRYPTO` work the same way.

**What holds the enumeration is a behavioural invariant, not the audit alone.** The
same species of guard as the `partial_analysis`/`partial_reasons` agreement test:
several tests in `tests/test_linkage.py` stand in for re-reading `_binary_posture` by
hand every time it changes. `test_every_definite_openssl_posture_has_a_finding_on_its_object`
asserts that every object whose own posture is `system`, `bundled`, `static` or `mixed`
carries a finding on that same object, in a rule category that fits the posture --
per object, not per wheel, because a wheel-level check ("some finding fired
somewhere") is satisfied vacuously: by the vendored member's own `BIN_BUNDLED_OPENSSL`
finding when the object actually reading `bundled` is a different one, or by
`BIN_OPENSSL_SYMBOLS_IMPORTED` on an object that only ever imports the library.
`test_every_definite_return_in_the_posture_functions_is_reached_by_a_fixture` traces
`_binary_posture` and `needed_posture` while their fixtures run and fails when either
function gains a definite `return` no fixture's evidence reaches, so a fourth
mechanism cannot silently join the three above without first earning a fixture and
then, if that fixture is unexplained, a rule. Two more tests hold the per-object check
itself to its subject and category conditions rather than trusting the map by
inspection: `test_dropping_both_system_rules_leaves_the_header_banner_object_unexplained`
drops both rules that can explain `system` from one fixture that also carries its own
`BIN_OPENSSL_BANNER` finding in the wrong category, and
`test_dropping_the_bundled_openssl_rule_leaves_only_a_libsodium_finding` drops
the rule that explains an object's `bundled` openssl posture while a same-object,
same-category finding for a *different* library survives it -- each proving that the
category and the subject filter, not just the object's location, are load-bearing.
A last test, `test_aggregate_never_returns_a_definite_posture_without_one`, closes
the wheel-level check's gap: it runs `_aggregate` directly over every subset
of the postures `_binary_posture`/`needed_posture` can produce, crossed with
`unanswered` and `declared`, and asserts that a result in `_DEFINITE_POSTURES` always
traces back to a definite posture already in the input -- so `unanswered`/`declared`
promoting a wheel straight to `bundled` with no object explaining it, which no fixture
above can exercise because none carries an SBOM or an unreadable member beside an
otherwise silent wheel, fails here instead of only being asserted.

**An aggregate `openssl` "bundled" rule, mirroring `DERIVED_SYSTEM_OPENSSL_ONLY`,
stays the unadopted alternative.** It breaks exactly one test -- an id-enumeration
test, not a behavioural one -- and the objection that it cannot name which object
resolved `bundled` is weaker than it first reads: `DERIVED_SYSTEM_OPENSSL_ONLY`
carries the identical limitation and fires *alongside* the mechanism-specific rule
rather than replacing it, so the aggregate rule would cost nothing that `system` does
not already cost. It is not needed now because the invariant test above closes the
same gap without adding a rule id or a line to any record.

**The category map the invariant test uses is its own, and coarse.** `system` accepts
either `system-crypto-link` rule that can explain it, `bundled` and `static` both
accept `bundled-crypto`, and `mixed` accepts either -- so an object that both imports
the library and carries a banner satisfies `system` through
`BIN_OPENSSL_SYMBOLS_IMPORTED` alone, without needing the `needed`-entry rule too, and
a bundled path reached only beside a system signal, so it is always `mixed`, is
explained by either category's rule on its own. Because the map is coarse, a fixture
carrying extra evidence would let an unrelated rule in the same category mask a
mechanism whose own rule was removed, so the fixtures each carry only the evidence
their own branch needs.

Revisit if a fourth mechanism is ever added to `_binary_posture`'s `bundled` branches,
if the two-file basename collision is seen in a real wheel often enough that the
imprecision, rather than just the silence, needs closing, or if a second library is
ever set `always_report`: the invariant test's fixtures and its
`test_openssl_is_the_only_library_always_reported` guard are both written for
`openssl` alone.

### An absolute `needed` entry is never resolved by basename

**Accepted, and it changes `openssl_linkage`.**

The basename residual above assumes `member_stem_counts` and `_looks_vendored` are the
only tools a `needed` entry has to prove itself with, for every `needed` entry alike.
They are not, for one shape: an absolute path.

`_resolves_within_wheel` matches purely on basename, with no regard for whether the
`needed` entry's own path shape could resolve inside the wheel under any real search
order at all. `$ORIGIN`/`@loader_path`/`@rpath`/RPATH/RUNPATH resolution never applies to
an absolute path -- a real dynamic loader uses it literally -- so an absolute entry that
happens to share a basename with some unrelated object elsewhere in the wheel would read
`bundled` off that coincidence alone, and `_looks_vendored` has the mirror problem: it
joins the *whole* `needed` string to each `RPATH`/`RUNPATH` entry, so an absolute path
can produce a joined string containing a vendor-directory component purely by chance
(`$ORIGIN/pkg.libs` + `/usr/lib64/libcrypto.so.3`), promoting an unconfirmed absolute
path to `unknown` for a reason that has nothing to do with how it would actually resolve.

```
demo/libcrypto.so         needed: /usr/lib64/libcrypto.so.3
demo/plugins/libcrypto.so (unrelated, shares a basename by coincidence)
-> by basename alone:  openssl_linkage: bundled, BIN_NEEDED_VENDORED_CRYPTO
-> by path shape too:  openssl_linkage: system,  BIN_NEEDED_SYSTEM_OPENSSL, DERIVED_SYSTEM_OPENSSL_ONLY
```

This is the same shape the own-stem discount above closes for an object colliding with
*itself* (`_resolves_within_wheel`'s own-stem discount, "What resolving by basename does
not prove") -- the object count is never the right test for an absolute path either way,
self or genuinely different.

**How the short-circuit works.** `needed_posture` tests `info_original.startswith("/")`
-- true for both an ELF `DT_NEEDED` and a Mach-O `LC_LOAD_DYLIB` absolute path; PE has
no such shape -- and returns `LINKAGE_SYSTEM`, the function's default, without consulting
`_resolves_within_wheel` or `_looks_vendored`. `mangled` is checked first, ahead of the
short-circuit: a hash-renamed basename is strong independent evidence regardless of
whether the path carrying it happens to be absolute, and mangled detection has nothing
to do with path shape.

**The short-circuit covers both of `_looks_vendored`'s branches, not only the
`RPATH`/`RUNPATH` join the reproduction above shows.** `_looks_vendored` also matches
`needed` on its own, `conventions.is_vendor_path(needed)`, catching delocate's plain
convention (`@loader_path/.dylibs/...`) with no `RPATH` involved at all. That branch's
evidence is meaningful only because the vendor-directory component sits in a path that
gets resolved *relative to the loading object* -- which is precisely what never happens
for an absolute path. auditwheel and delocate both always rewrite a vendored dependency
to a relative form for exactly that portability reason, so neither ever emits an
absolute reference for a copy it ships; a vendor-glob-shaped component inside an absolute
path is therefore always a coincidence or a leftover build-time artifact, not a real
vendoring signal, whether it is read through the join or off the bare string.
`test_an_absolute_needed_entry_shaped_like_a_vendor_path_itself_stays_system_even_
incomplete` (`tests/test_linkage.py`) pins this branch on its own, with no `RPATH` in the
picture, so the two halves are each independently tested rather than only the half the
reproduction above shows.

**The own-stem discount is live code, reached only through a relative entry.** The
absolute-path self-collision tests --
`test_a_needed_entry_matching_its_own_declaring_objects_name_is_not_self_confirmed`, its
`tests/test_engine.py` and `tests/test_acceptance.py` counterparts -- answer through the
short-circuit before `_resolves_within_wheel` is ever called, so they do not exercise the
discount: removing the discount leaves them green.
`test_a_relative_needed_entry_matching_its_own_declaring_objects_name_is_not_self_
confirmed` and its `tests/test_engine.py` sibling pin the discount with a relative
reproduction of the same shape, which cannot take the short-circuit.

**What this narrows, and what it does not.** The two-file basename collision residual
above stays open for a *relative* `needed` entry -- one that a real loader genuinely can
resolve via `$ORIGIN`/`@rpath`/RPATH/RUNPATH, which is the ordinary auditwheel/delocate
vendoring shape -- and `test_a_relative_needed_entrys_basename_collision_
still_confirms_bundled` (`tests/test_linkage.py`) and
`test_the_documented_basename_collision_residual_still_carries_a_finding`
(`tests/test_engine.py`) pin that the absolute-only short-circuit leaves it alone. What
is closed is the absolute case specifically:
`test_an_absolute_needed_entrys_basename_collision_reads_as_system` and
`test_an_absolute_needed_entry_beside_a_vendor_shaped_runpath_stays_system_
even_incomplete` (`tests/test_linkage.py`), `test_an_absolute_basename_collision_
reads_as_system` (`tests/test_engine.py`), and
`test_an_absolute_basename_collision_is_not_manufactured_bundled`
(`tests/test_acceptance.py`, real ELF bytes) pin it end to end.

**The path-shape check decides more than the posture -- it decides the wheel's findings
and `verdict.classes`, though not the headline class.** An absolute entry that resolves
`bundled` by basename alone would disagree with a second, genuinely system `needed`
entry on the same object: without the path-shape check, the two combine into `mixed`
(`_binary_posture`'s `sum((system, bundled, static)) > 1` check), adding
`BIN_OPENSSL_LINKAGE_UNKNOWN` to the findings and `OPAQUE` to `verdict.classes`; with it,
both read `system`, so the object has one definite posture, not two, and the wheel reads
plain `system` with `DERIVED_SYSTEM_OPENSSL_ONLY` instead. The headline `verdict.class`
does **not** differ for this specific reproduction -- it is `CONDITIONAL` either way,
because `BIN_NEEDED_VENDORED_CRYPTO` forces `CONDITIONAL` on its own. What differs is
the rule ids and the `classes` tuple, not the headline; measuring both paths through
`apply_rules` and `classify` is what pins that the headline does not move here.
`test_an_absolute_basename_collision_beside_a_real_system_match_does_not_self_disagree`
(`tests/test_linkage.py`) pins the posture at the `resolve_linkage` level;
`test_an_absolute_basename_collision_is_not_manufactured_bundled` and
`test_an_absolute_needed_entry_beside_an_unreadable_basename_collision_stays_system`
(`tests/test_acceptance.py`) carry the full-record assertions on findings and
`verdict.classes` the unit test does not itself make. The sharpest variant -- the object
colliding by basename with the absolute entry is itself unreadable, not merely
unrelated -- stays safe: the `openssl` answer is unaffected (the absolute entry answers
on its own, unconditionally), and the unreadable member still gets its own
`OPAQUE`-headline finding rather than being folded into, or silencing, that answer; the
record never reads `NO_CRYPTO_DETECTED` and `needs_human_review` stays `true`.
`test_an_absolute_needed_entry_beside_an_unreadable_basename_collision_stays_system`
(`tests/test_acceptance.py`) pins that combination end to end.

**What "absolute" means here, and what it deliberately does not cover.** The check tests
`info_original.startswith("/")` -- a genuinely absolute path. The argument above ("no
loader resolves this against anything the wheel ships") applies just as well to a shape
the check does not test for: a `needed` entry containing a slash that is not
`/`-prefixed and not `@`-prefixed either, such as `../../hostlib/
libcrypto.so.3` (glibc's loader skips every search-path list once `strchr(name, '/')` is
non-null, exactly as it does for a leading `/`), and a Mach-O `@executable_path/...`
entry, which resolves against the *interpreter binary*, never the wheel, and so is
exactly as meaningless for `_resolves_within_wheel`'s basename match as an absolute path
is -- yet still takes it, confirmed by reproduction. Both stay on the basename-only
route, unnarrowed, and can read a spurious `bundled` or `unknown` from an unrelated
basename collision. This is not a hole the absolute-path check opens -- nothing else
covers either shape -- but it means the residual "What resolving by basename does not
prove" documents is narrowed for a literal absolute path specifically, not closed for
every path a real loader would never resolve inside the wheel. Left open rather than
widened, since widening the predicate correctly needs to keep the handling of `@rpath/`,
`@loader_path/` and `@executable_path/` (each meaningful and tested) from being caught
by the same net.

**Whether an absolute-path basename collision can ever be a genuine vendored copy,
rather than pure coincidence, is argued here from loader semantics, not measured
against a real corpus.** The argument: whatever a wheel ships under a matching
basename, an absolute `needed` entry's own dynamic loader resolves it literally, so
that entry will load whatever is actually installed at that path on the machine
running it -- never the wheel's own copy -- regardless of what the wheel happens to
ship alongside it. A wheel whose build recorded an absolute, machine-specific path in
`DT_NEEDED` for a library it also (separately) ships is a different problem from the
one this check answers -- such a wheel will not load that dependency correctly on any
other machine either, absolute-path coincidence or not -- and is out of scope for the
FIPS-provenance question `linkage` exists to answer. No real corpus run backs this
argument the way the 288-shape matrix behind resolution by basename backs its claims;
none is available for this specific intersection. Revisit with a `WCS_CORPUS_DIR` count
of absolute `needed` entries whose `raw_stem` collides with a shipped object's stem if
one becomes available; if that count is ever non-zero for a wheel that was not built by
auditwheel/delvewheel/delocate, the honest answer for that specific intersection may be
`LINKAGE_UNKNOWN` rather than `LINKAGE_SYSTEM`, not the wholesale short-circuit this
check takes.

## A `needed` match and a definition inside one object are both true, so the object is `mixed`

**Accepted, and it changes `openssl_linkage`. The precedence question "A `needed` entry
is bundled by what it resolves to" deliberately leaves open.**

`_binary_posture` computes `defined`/banner evidence before deciding what the `needed`
loop found, and returns `LINKAGE_MIXED` when both `system` and that evidence are true,
ahead of the plain `system` and `static` returns. Deciding purely off `needed` -- return
`LINKAGE_SYSTEM` as soon as one entry resolves to the system library, before the
defined-symbol and banner check ever runs -- would read `system` for an object that both
declares `DT_NEEDED libssl.so.3` (or the Mach-O equivalent) and defines
`EVP_DigestInit_ex` -- or carries an OpenSSL version banner, which a version script
cannot hide -- and would pair `DERIVED_SYSTEM_OPENSSL_ONLY` ("every piece of OpenSSL
evidence points at the system library and none at a bundled or static copy") with
`BIN_OPENSSL_SYMBOLS_DEFINED` ("OpenSSL was compiled into it") in the same `rule_ids`
list -- a contradiction in the favourable direction, and the one shape this tool's
invariants exist to rule out reading clean instead of uncertain.

```
demo/_ext.so   needed: libc.so.6, libssl.so.3
               defines EVP_DigestInit_ex, rodata: "OpenSSL 3.0.14 4 Jun 2024"
-> needed decides alone:   openssl_linkage: system, verdict.rule_ids: [...,
           "DERIVED_SYSTEM_OPENSSL_ONLY", "BIN_OPENSSL_SYMBOLS_DEFINED", ...]
-> both signals weighed:   openssl_linkage: mixed, verdict.rule_ids: [...,
           "BIN_OPENSSL_SYMBOLS_DEFINED", "BIN_OPENSSL_LINKAGE_UNKNOWN", ...] (no
           "DERIVED_SYSTEM_OPENSSL_ONLY"); the needed-side evidence itself is in
           findings[] as "BIN_NEEDED_SYSTEM_OPENSSL", which carries no verdict of its
           own and so never appears in verdict.rule_ids either way
```

**The decision: `mixed`, not `static`-wins.** There are two ways to resolve one object
carrying both signals. `static` wins outright, discarding the `needed` match's own
conclusion; or `mixed`, `_aggregate`'s answer for exactly this kind of disagreement
between two different objects, read to mean "both postures found for the evidence
contributing to one object's own posture" as well as "two objects disagreed about the
same library." `mixed` is chosen: both facts are independently true and independently
reportable (a real `DT_NEEDED` entry names the system library, and a real symbol, or a
banner that is not header text, shows the object also carries its own copy: see "A
version banner beside imports from the system library is header text, not a copy",
below), and `static`-wins would suppress the `needed` evidence from `verdict.conditions.openssl_linkage` itself, not just from
the findings list -- the one field most consumers filter on would then say `static`
about an object that also, genuinely, links the system library. `mixed` costs no schema
change: the value exists, `SCHEMA.md` gives it a row, and it is reachable across objects
(and across a universal binary's slices, "A universal binary is one record, and its
slices are merged", above); `_binary_posture` produces it directly here as well as via
`_aggregate` combining two different objects.

**`_aggregate` has to take a per-object `mixed`.** `mixed` is not in `_DEFINITE`, and a
postures set containing only `{"mixed"}` would fall through to `openssl_linkage: none`
-- the linkage *value*, not the verdict *class*: `BIN_OPENSSL_SYMBOLS_DEFINED` fires
regardless, so `verdict.class` is not at risk of becoming `NO_CRYPTO_DETECTED` for this
shape, only the field consumers filter on would go silently wrong. `_aggregate` returns
`mixed` immediately whenever any object's own posture is one, since the vocabulary has
no finer split than that to offer.

**Why `uncertain` is a separate question.** `uncertain` means "the record is not sure,"
where a plain `needed`-decides `system` means "the record is sure, and wrong" -- a
different kind of gap, answered by its own rule in "An `uncertain` needed match beside a
definition is `mixed`", below.

**What it costs.** `BIN_OPENSSL_LINKAGE_UNKNOWN` (`values = ["unknown", "mixed"]`,
`verdict = "OPAQUE"`) also fires for this shape, because it treats every `mixed` as worth
`OPAQUE` regardless of how the disagreement arose. Its own `why` -- "the wheel calls
OpenSSL without declaring a dependency on it, or the only evidence came from an object we
could not read" -- describes the cross-object and uncertain shapes, not this one: here
the dependency *is* declared and the object *was* read in full. `verdict.classes` still
leads with `CONDITIONAL` (`[verdict] precedence` ranks it ahead of `OPAQUE`), so
`verdict.class` is unaffected, but `classes` lists `OPAQUE` too and
`BIN_OPENSSL_LINKAGE_UNKNOWN` sits in `rule_ids` next to a `why` that does not fit. Left
as is rather than reworded: rewording it correctly means splitting what are two
different reasons `mixed` can fire, which is exactly the kind of enumeration risk "Every
`bundled` has a rule, by enumeration", above, warns against taking on lightly.

**What was rejected.** `static`-wins, covered above. A new rule id distinguishing
"mixed from one object's own contradiction" from "mixed from two objects disagreeing" --
rejected for the same reason `DERIVED_SYSTEM_OPENSSL_ONLY` does not distinguish which
object resolved `system`: the record's `openssl_linkage` field does not carry
per-object detail, and a new rule id would answer a question `rule_ids` cannot ask.

Revisit if `BIN_OPENSSL_LINKAGE_UNKNOWN`'s `why` text needs to name this case explicitly,
or if a real wheel's `mixed` verdict is confusing enough in practice that the two ways to
reach it need their own rule ids after all.

### An `uncertain` needed match beside a definition is `mixed`

**Accepted, and it changes `openssl_linkage`.**

The `uncertain` case is a `needed` entry whose path or `RPATH`/`RUNPATH` shape looks
vendor-directed but that an incompletely-read wheel cannot confirm either way
(`_looks_vendored` behind `wheel_incompletely_read`, "What resolving by basename does not
prove", above). Returning `LINKAGE_UNKNOWN` for it before the defined/banner check a few
lines below ever runs would read an object with both an unconfirmed vendor-shaped
`needed` entry and a confirmed static definition (or banner) as `unknown` regardless,
silently discarding the confirmed evidence in favour of the unconfirmed one -- the same
shape as `system` beside a definition, this time for `uncertain`.

```
demo/_ext.so  needed: libcrypto.so.3, RUNPATH: $ORIGIN/../p.libs (names nothing shipped,
              wheel incompletely read), defines EVP_DigestInit_ex
-> uncertain returns first:     openssl_linkage: unknown  (the confirmed static definition is discarded)
-> uncertain combined with it:  openssl_linkage: mixed
same, with the OpenSSL banner instead of the symbol -> mixed
```

**The decision: `mixed`, by the same reasoning, not a new rule.** Both facts are
independently true and independently reportable, exactly as above: a `needed` entry whose
shape cannot be ruled out either way, and a real symbol or banner the object genuinely
carries. `unknown`-wins would suppress the confirmed evidence from `verdict.conditions.
openssl_linkage` itself, the same objection that rules out `static`-wins above. No
ruleset change is needed: `BIN_OPENSSL_LINKAGE_UNKNOWN` matches `values = ["unknown",
"mixed"]`. Widening `mixed` this way is not free, though -- see "What it costs" below.

**Precedence, with three signals in play on one object.** `_binary_posture` has the
branch `if uncertain and static: return LINKAGE_MIXED`, placed after the
`_DEFINITE`-count check and the plain `system` and `bundled` returns, ahead of
`if uncertain: return LINKAGE_UNKNOWN`. This is *not* the same shape as the
`_DEFINITE`-count branch -- `system` does not win outright over `static`; the two
combine into `mixed`, which is the entire point of the entry above, not what the
ordering of this branch encodes. What that ordering actually encodes is different:
`uncertain` is exactly `needed_posture`'s `LINKAGE_UNKNOWN`, not one of the `_DEFINITE`
postures (`system`, `bundled`, `static`; see the comment above `_DEFINITE` in
`linkage.py`), and `_aggregate` treats a non-definite posture as one that never outvotes
a definite one already present when combining different objects' answers
(`len(definite) == 1: return definite[0]`, discarding `LINKAGE_UNKNOWN` outright,
whatever else is true). That same rule holds within one object independent of where the
branch sits: once a `needed` entry confirms `system` for this object, an unconfirmed
`uncertain` entry elsewhere on the same object gets no vote, the same way a non-definite
posture gets none across objects in `_aggregate` -- delivered entirely by the
unconditional `if system: return LINKAGE_SYSTEM` above it, not by where the branch sits
relative to it (moving the branch above the `_DEFINITE`-count check changes nothing the
test suite can observe, confirmed by mutation). The branch's position only decides which
of the two remaining facts, `uncertain` and `static`, it gets to combine once `system`
is ruled out; it does not decide `system`'s own priority. This says nothing about
whether the *unconfirmed* entry itself is genuinely `system` or genuinely `bundled` --
the object's posture does not track that, and `DERIVED_SYSTEM_OPENSSL_ONLY`'s own `why`
("every piece of OpenSSL evidence points at the system library and none at a bundled or
static copy") is not strictly true when a confirmed entry and a different, unconfirmed
one coexist on the same object; that gap is visible in the plain `system`-alone case
too, this rule does not close it, and it is left as is rather than folded in.

The three-way case (`system`, `uncertain` and `static` all true on one object, from two
different `needed` entries) collapses into the two-way `system`-and-`static` `mixed`
before `uncertain` is ever consulted. That collapse is provable rather than merely
observed: the two branches' conditions (`system and static`, `uncertain and static`) can
only be true together when `system` is also true, and both branches return the same
value, `mixed`, in that case -- so no test built from `resolve_linkage`'s output alone
can tell which of the two branches fired, or whether the `uncertain` branch runs before
or after the `system` checks, for this specific shape; moving it above them, or deleting
it outright, still reads `mixed` here because the `_DEFINITE`-count branch does.
`test_system_uncertain_and_static_together_still_read_mixed` is kept as a
characterization pin of that convergence, not as a guard for this ordering decision --
the ordering itself is pinned by the two-signal tests instead
(`test_an_uncertain_needed_match_and_a_defined_symbol_together_are_mixed` and its banner
variant), where `system` is false and only the `uncertain` branch can produce `mixed` at
all; removing the branch turns both of those red. The ordinary cases stand as they are:
`uncertain` alone reads `unknown`, `static` alone reads `static`, and `system`-and-`static`
together reads `mixed`.

**What it costs.** `BIN_OPENSSL_LINKAGE_UNKNOWN` fires for both `unknown` and `mixed`,
and its `why` text undersells this shape the same way it undersells the
`system`-and-`static` one -- left as is for the same reason given above, so as not to
split one `why` into two without also giving the two shapes their own rule ids.

This also widens `mixed` one object beyond the one it fires on. `_aggregate` promotes any
wheel with an object whose own posture is `mixed` outright (`if LINKAGE_MIXED in postures:
return LINKAGE_MIXED`, checked before the `_DEFINITE` count). Consider a wheel with one
object reading `bundled` (a hash-renamed `needed` entry, say) and a second,
incompletely-read object whose own posture is `mixed` rather than `unknown`: since
`mixed` anywhere in `postures` short-circuits `_aggregate` immediately, the whole wheel
reads `mixed` at the wheel level, not `bundled` -- `unknown` is never in `_DEFINITE`, so
an `unknown` posture on that second object would never outvote `bundled` there either,
but `mixed` does, by the short-circuit rather than by outvoting anything. That drops the
wheel out of `SCHEMA.md`'s own `IN("bundled","static")` triage recipe, whose comment
notes it misses `mixed` wheels -- this is one more way to land in that gap, not a new gap
of its own, and the direction stays conservative: the wheel gains
`BIN_OPENSSL_LINKAGE_UNKNOWN`/`OPAQUE` rather than losing anything silently.

**What was rejected.** A three-way branch computing `system`, `uncertain` and `static`
together explicitly -- rejected because the two branches produce the right answer once
ordered correctly (see "Precedence" above: the collapse is provable, not assumed), and a
third would duplicate logic the `_DEFINITE`-count check and `if system: return
LINKAGE_SYSTEM` already cover. `uncertain`-wins over a confirmed `static` -- rejected
for the reason `static`-wins over `system` is rejected above: a confirmed fact must never
be the one a weaker, unconfirmed fact displaces.

Revisit if a real wheel is found where the three-way shape (`system` and `uncertain` from
two different `needed` entries, plus `static`) reads confusingly, if
`BIN_OPENSSL_LINKAGE_UNKNOWN`'s `why` text is reworded for the `system`-and-`static` case
above (the same rewording would need to cover this shape too), or if
`DERIVED_SYSTEM_OPENSSL_ONLY`'s `why` text needs correcting for the gap named above (a
confirmed entry does not actually rule out a *different*, unconfirmed one on the same
object).

### A bundled needed match beside `system` or `static` is `mixed`

**Accepted, and it changes `openssl_linkage`: the same precedence reasoning, applied
to `bundled`.**

`_binary_posture`'s `needed` loop sets a flag, `bundled`, alongside `system` and
`uncertain`, and lets all three per-`needed`-entry postures accumulate across the whole
`needed` tuple before the function branches on any of them -- the same approach the
entries above take for `system` against the defined/banner check, applied to the third
`_DEFINITE` posture. The disagreement check is a three-way count,
`if sum((system, bundled, static)) > 1: return LINKAGE_MIXED`, checked ahead of any of
the three being returned on its own. Returning `LINKAGE_BUNDLED` immediately from inside
the loop, on the first entry that resolves that way, would short-circuit ahead of a
second, disagreeing `needed` entry on the same object, or the defined/banner check below
the loop. A universal (fat) Mach-O object merges its slices' `needed` tuples into one
(`binfmt.macho`; the merge itself is pinned by `test_load_dylibs_merge_across_slices` in
`test_binfmt_macho.py`), so an object whose slices disagree about `bundled` versus
`system` or `static` would read `bundled` outright under that short-circuit, unlike the
same evidence read as two separate objects, which `_aggregate` combines into `mixed`.

```
one object, needed=("libcrypto-3a1f2b4c.so.3", "/usr/lib64/libcrypto.so.3")
  -> loop returns on first match:  openssl_linkage: bundled
  -> all needed entries weighed:   openssl_linkage: mixed
same evidence in two separate objects -> mixed either way

needed=("libcrypto-3a1f2b4c.3.dylib",), defines EVP_DigestInit_ex, one object
  -> loop returns on first match:  openssl_linkage: bundled
  -> all needed entries weighed:   openssl_linkage: mixed
```

`bundled` is never a safety regression on its own -- `BIN_NEEDED_MANGLED_CRYPTO`,
`BIN_NEEDED_VENDORED_CRYPTO` and `BIN_BUNDLED_OPENSSL` are findings read off each
`needed` entry directly (`engine._match_dt_needed`, `kind = "dt_needed"`/
`"bundled_library"`), not off the aggregated `openssl_linkage` value, so they fire
regardless of whether the object's own posture reads `bundled` or `mixed`. The
disagreement is between the merged object and its two-separate-objects equivalent, not
about a clean read.

**Precedence, with four signals in play on one object.** Built out and verified directly
against the ladder in `linkage._binary_posture` and against the test suite, not assumed
from the two entries above:

| `system` | `bundled` | `static` | `uncertain` | Result | Why |
|---|---|---|---|---|---|
| 2+ of the three true | -- | -- | any | `mixed` | Two or more `_DEFINITE` postures disagree on one object, the same shape `_aggregate` turns into `mixed` for two different objects. |
| T | F | F | any | `system` | A confirmed entry needs no vote from an unconfirmed one. |
| F | T | F | any | `bundled` | Symmetric to the row above, for the reason given below. |
| F | F | T | T | `mixed` | The `uncertain`-and-`static` branch. |
| F | F | T | F | `static` | The ordinary static case. |
| F | F | F | T | `unknown` | The ordinary `uncertain` case. |
| F | F | F | F | falls through to imported/opaque/none | No `needed` or static evidence. |

`system`-alone-beats-`uncertain` and `bundled`-alone-beats-`uncertain` are the *same*
rule, not two rules that happen to agree: `system`, `bundled` and `uncertain` are all
read off the same `for needed in binary.needed` loop, over different entries, and what
actually makes a confirmed entry beat an unconfirmed one is that `if uncertain: return
LINKAGE_UNKNOWN` sits *below* both `if system:` and `if bundled:` in the ladder --
`_aggregate`'s "a non-definite posture never outvotes a definite one already present"
rule, applied within one object, exactly as for `system` above. This is NOT about the
`uncertain`-and-`static` branch's position relative to them: that branch can be moved
anywhere in the ladder -- above `if system:`, between it and `if bundled:`, wherever --
without the test suite observing any difference, confirmed by mutation (the same finding
recorded above for the `_DEFINITE`-count check, and stated in the code comment in
`linkage.py`). What the `uncertain`-and-`static` branch's position DOES decide is only
which of the two remaining facts it gets to combine, once `system` and `bundled` are
both ruled out.

`static` is not read off `binary.needed` at all (`matched_symbols`/`matched_strings`
instead), so it is not subject to the `if uncertain: return LINKAGE_UNKNOWN` rule the
other two `needed`-loop facts are -- which is why it combines with `uncertain` into
`mixed` rather than letting it be outvoted by a different, unconfirmed `needed` entry.
`bundled` gets the same treatment as `system` because `bundled`, like `system`, is a
`binary.needed` fact and `if uncertain:` sits below both.

**It leaves the `uncertain`-and-`static` branch untouched,** traced explicitly. That
branch (`if uncertain and static: return LINKAGE_MIXED`) runs after the
`if bundled: return LINKAGE_BUNDLED` branch. The three-way `_DEFINITE`-count check above
it also fires when `bundled` and `static` are both true -- but it returns `mixed`, the
same value the `uncertain`-and-`static` branch would return if it were reached for that
case, so nothing that branch's tests pin changes behaviour: every one of them
(`test_an_uncertain_needed_match_and_a_defined_symbol_together_are_mixed`,
`test_system_uncertain_and_static_together_still_read_mixed`, and the rest) passes with
the three-way count in place, confirmed by running the full suite.

**What it costs.** No ruleset change: `BIN_OPENSSL_LINKAGE_UNKNOWN` matches
`values = ["unknown", "mixed"]`, which is sufficient here too. It does widen `mixed` the
same way the `uncertain` rule does: an object that would otherwise read plain `bundled`
(discarding a disagreeing `system` or `static` signal on the same object) reads `mixed`,
and `_aggregate` promotes any wheel with a `mixed` object outright, ahead of counting
`_DEFINITE` postures -- so a wheel that would otherwise aggregate to `bundled` (one
object `mixed`, no other object contradicting it) aggregates to `mixed` instead, dropping
out of `SCHEMA.md`'s `IN("bundled","static")` triage recipe the same way the `uncertain`
rule's widening does. The direction stays conservative: `verdict.class` is unaffected
(`BIN_NEEDED_MANGLED_CRYPTO`/`BIN_BUNDLED_OPENSSL`/`BIN_NEEDED_VENDORED_CRYPTO` fire on
the `needed` entry itself and carry `CONDITIONAL`, which precedes `OPAQUE` in
`[verdict] precedence`), and `verdict.classes` only gains `OPAQUE` alongside it, never
loses anything silently.

**What was rejected.** A fourth branch, `if bundled and uncertain: return LINKAGE_MIXED`,
mirroring the `uncertain`-and-`static` branch -- rejected because it would answer `mixed`
for a shape ("this confirmed `bundled` entry, plus a different, unconfirmed one") that
the same-loop precedent resolves to plain `bundled`, for the same reason
`uncertain`-wins over `static` is rejected: the rule for `system` beside `uncertain`
should not read differently for `bundled` beside `uncertain` without a positive reason,
and none was found. Extending the disagreement check into the top-of-function
`vendored_path` early return (an object's own file identity matching the library -- the
vendored copy's own record, `BIN_BUNDLED_OPENSSL`'s evidence source) -- also rejected,
out of scope: this rule is specifically about a `needed` entry resolving `bundled`, and
that early return is a different mechanism.

**Kept out of scope, on purpose -- and there is a real reproduction for it.** Whether an
object identified by its own `binary.vendored_path` (rather than by a `needed` entry)
can itself carry a disagreeing `system`/`static`/`uncertain` signal that its own early
return discards is a structurally similar question: a vendored `libssl` that itself
links the host `libcrypto` (the `auditwheel --exclude libcrypto.so.3` shape `DESIGN.md`
names elsewhere as real) --

```
demo/_ext.so                   needed: libc.so.6, libssl-abc123.so.3
demo.libs/libssl-abc123.so.3   needed: libc.so.6, libcrypto.so.3   defines SSL_new
-> openssl_linkage: bundled   (the system libcrypto dependency is discarded)
```

-- reads `bundled` where the same two `needed` entries on a non-vendored object would
read `mixed`. `BIN_NEEDED_SYSTEM_OPENSSL` still reaches `findings[]` and
`needs_human_review` is `true`, so it is milder than a `system` read beside a definition
(nothing reads clean), but it is the same family. This is left open anyway: this rule is
specifically about a `needed` entry resolving `bundled`, `vendored_path`'s early return
is a genuinely different code path, and folding it in would extend an already-large
precedence mechanism further than the reproductions above call for. The honest reason is
scope discipline, not the cost of computing the extra checks, which is small (a handful
of scans over evidence the record carries).

Revisit if a real wheel is found matching the reproduction above, or if a fifth
`_DEFINITE`-shaped signal is ever added to `_binary_posture` and needs the same treatment.

## An explicit usedforsecurity=True, and a non-constant flag, are not `NO_CRYPTO_DETECTED`

**Accepted, and it changes verdicts. The AST extractor records the right thing; the
ruleset has to ask for it.**

`_hashlib_usedforsecurity` in `layers/python_ast.py` yields `"absent"`, `"false"`,
`"true"` or `"unresolved"`. A ruleset that matches only `"absent"` leaves
`hashlib.md5(data, usedforsecurity=True)` -- the code explicitly declaring itself a
security use -- with zero findings, reading as `NO_CRYPTO_DETECTED`, the one outcome
this tool's invariants exist to rule out for an uncertain or unreadable case, and this
case is neither: it is the single most certain shape the extractor can produce. Likewise,
`PY_WEAK_HASH_UNRESOLVED`'s own `why` claims to cover "usedforsecurity passed a
non-constant," and a match table reading only a non-constant *algorithm name* on
`hashlib.new` would leave that claim matching nothing.

**How the rule matches it.** `PY_WEAK_HASH_CALL`'s match table accepts
`usedforsecurity = ["absent", "true"]` rather than just `"absent"`; `_match_py_call` in
`engine.py` normalises a scalar string into a one-element tuple and checks membership,
the same shape `_match_py_attr` uses for its `values` list. `PY_WEAK_HASH_UNRESOLVED`
has a second `[[rule.match]]` table for `usedforsecurity = "unresolved"` with
`algorithm_list = "weak"`, ORed with its `algorithm = "unresolved"` table -- one rule
id, two ways of reaching it. It is the one rule in the shipped ruleset with more than
one `[[rule.match]]` table; `Rule`'s docstring defines several tables as alternatives
ORed together, and `tests/test_ruleset.py` exercises the form synthetically, so the
mechanism has coverage independent of this one real user.

**The judgment call: no new rule id for the `usedforsecurity=True` case.** An explicit
`True` is worth distinguishing from the bare no-keyword call in the evidence text, since
one is a default and the other is a declaration, but not in severity, confidence or
verdict class -- both are `FIPS_BREAKING`, both need human review. The distinction
exists one layer down: `PySite.detail` carries `usedforsecurity=absent` or
`usedforsecurity=true` per occurrence, so a reader loses nothing by both landing under
`PY_WEAK_HASH_CALL`. A second rule id would duplicate the `why` for no material gain.

**The other judgment call: a non-constant usedforsecurity on a non-weak algorithm is not
this finding, at any verdict class.** `hashlib.new("sha256", usedforsecurity=flag)` does
not fire `PY_WEAK_HASH_UNRESOLVED` (or either of the other two): sha256 is FIPS-approved
regardless of what the flag turns out to be at runtime, so the uncertainty a human would
be asked to resolve does not exist. `algorithm_list = "weak"` on the second match
table does this for free, the same filter the two other hash-call rules rely on.

Revisit if a future weak-hash rule needs the True/absent split visible at the rule_id
level rather than in `detail`, or if `algorithm_list`'s definition of "weak" ever
needs to move for reasons unrelated to `usedforsecurity`.

## Every dylib-loading command reaches `needed`, not just `LC_LOAD_DYLIB`

**Accepted, the direct Mach-O counterpart of a PE forwarder ("A forwarder resolves the
dependency it forwards to, not just its own name", above), and it changes what a
re-exporting shim can hide.**

Four commands share `LC_LOAD_DYLIB`'s identical `dylib_command` layout -- cmd, cmdsize,
then name.offset, timestamp, current_version, compatibility_version -- and differ only in
what the dynamic linker does with the name: `LC_LOAD_WEAK_DYLIB` tolerates the library
being absent, `LC_LAZY_LOAD_DYLIB` and `LC_LOAD_UPWARD_DYLIB` are ordinary dependencies
with different load timing, and `LC_REEXPORT_DYLIB` folds the target's exports into this
object's own API surface. Recognising only `LC_LOAD_DYLIB` and `LC_ID_DYLIB` silently
skips all four:

```
libcrypto.3.dylib via LC_LOAD_WEAK_DYLIB / LC_LAZY_LOAD_DYLIB / LC_LOAD_UPWARD_DYLIB
-> if only LC_LOAD_DYLIB/LC_ID_DYLIB are read: needed drops it entirely,
   partial_analysis: false, openssl_linkage: unknown
-> reading all five commands:                 needed carries it, openssl_linkage: system
```

The re-exporting shape is the sharper failure, and the direct analogue of a PE
forwarder: a shim whose whole job is re-exporting libcrypto would read completely clean
if `LC_REEXPORT_DYLIB` were not read.

```
libshim.dylib   id: @rpath/libshim.dylib
                needed: /usr/lib/libSystem.B.dylib
                LC_REEXPORT_DYLIB -> /opt/homebrew/lib/libcrypto.3.dylib
-> if only LC_LOAD_DYLIB/LC_ID_DYLIB are read: needed: ['/usr/lib/libSystem.B.dylib'],
   class: NO_CRYPTO_DETECTED, openssl_linkage: none, needs_human_review: false
-> reading all five commands:                 needed carries the re-exported dylib too,
   openssl_linkage: system, class: CONDITIONAL, needs_human_review: true
```

**How all five are read.** `_LC_DYLIB_DEPENDENCIES`, a frozenset of the five command
values that share `LC_LOAD_DYLIB`'s struct, is what `_read_thin` checks. Every one of
the five is read into `needed` the same way `LC_LOAD_DYLIB` is; `LC_ID_DYLIB` stays a
separate arm because it names this object, not a dependency.

**No marker beyond `needed`, the same call as for a PE forwarder.** Forwarder
resolution populates `needed` and `matched_symbols` and lets the existing rules do their
job, rather than inventing a "this dependency arrived via a forwarder" field.
`linkage._binary_posture` reads `needed` first regardless of which of the five commands
put an entry there, so that alone covers the shim case: `BIN_NEEDED_SYSTEM_OPENSSL` and
`DERIVED_SYSTEM_OPENSSL_ONLY` fire on the resolved posture, not on which load command
produced it. A `LC_REEXPORT_DYLIB` entry has less to distinguish it than a PE forwarder
does in the first place -- the load command names only the target dylib, never a target
symbol, so there is no per-symbol forwarding information to fold into `matched_symbols`
the way `exports.forwarded_targets` does for PE. Asymmetric handling between the two
formats would need a reason neither format's evidence gives, and there is a second
reason beside the missing per-symbol data: no rule anywhere reads "which load command
produced this `needed` entry", so a distinguishing marker would have no consumer to read
it. Collapsing five commands into one field is also the conservative direction for the
one command that asserts slightly more than the object guarantees --
`LC_LOAD_WEAK_DYLIB` tolerates the library being absent at load time, so recording it
exactly like an ordinary dependency can flag a wheel over a library that may never
actually load. That is a choice, not an oversight: `needs_human_review` is what a false
positive here costs, not a wrong verdict class, and the alternative -- a weak dependency
excluded from `needed` -- reopens the silent-drop shape this entry exists to close for a
case a real object almost never exercises.

**Every one of the six commands sharing `dylib_command`'s or `rpath_command`'s layout
has its string read the same way, through one function.** `_read_command_string` takes
the fixed header size for whichever struct it is (`dylib_command`'s 24 bytes or
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
drop.** `_read_cstring` returning `None` conflates two different things unless it is
careful: an offset the command's own bytes could not support, or (below) a non-ASCII
byte that makes the whole name unrecoverable. No other token covers a per-command name
failure -- the closest, `macho_symtab_incomplete`, is about `LC_SYMTAB` specifically --
so this one follows the naming used for the format's other partial causes, and it
covers `LC_RPATH` alongside the dylib-loading family and `LC_ID_DYLIB`:
`elf_dynamic_unread` is the precedent for one ELF token covering `needed`, `soname`,
`rpath` and `runpath` together, so one Mach-O token covering a dependency name, the
object's own name and an rpath entry is the same shape, not a new one. It records an
error, the way an unwalkable PE import or export directory does, and it is not on
`[linkage_policy] exclude_reasons`: a lost load-command string is a lost dependency or
a lost rpath entry, and `elf_section_table_absent` is the precedent for costing the
linkage answer rather than assuming the loss is harmless. `linkage._looks_vendored`
reads `rpath` directly, so a lost rpath entry can misread a bundled library's posture
in either direction, the same stakes a lost dependency name has.

**A non-ASCII byte in an install name, dependency name or rpath entry is sanitized,
not dropped.** Decoding with plain `.decode("ascii")` raises on any byte outside that
range, and catching that by returning `None` is indistinguishable, to the caller, from
an offset that pointed nowhere. `binfmt.elf` and `binfmt.pe` both decode permissively
(`"utf-8", "replace"`) and then sanitize, and so does `_read_cstring`: a
`libcrypto\x80-3.dylib` reads as `libcrypto-3.dylib` rather than vanishing along with
whatever crypto evidence its dependency name carried.

**What it costs.** A weak, lazy or upward-loaded system OpenSSL resolves rather than
reading `unknown`; a re-exporting shim reads off `NO_CRYPTO_DETECTED`; an object with an
unreadable dylib-loading, `LC_ID_DYLIB` or `LC_RPATH` string reads `partial_analysis:
true` instead of silently losing that dependency, name or rpath entry.

**What was rejected.** A distinguishing marker for `LC_REEXPORT_DYLIB` beyond
`needed`, covered above. Reusing `macho_symtab_incomplete` for the unreadable-string
case, which would name a `LC_SYMTAB`-specific cause for a failure that has nothing to do
with the symbol table. A second token to keep `LC_RPATH` separate from the dylib-loading
family, rejected on the `elf_dynamic_unread` precedent above.

**Three shapes that reading the five dylib-loading commands alone would still miss,**
none of them in the four sibling commands or the shim case above:

- `_read_cstring`'s unterminated-run fallback (`end = len(body)` when no NUL was
  found). An implementation that only guards the reproductions above leaves it
  untouched, because none of those reproductions remove a name's terminator. It is the
  identical failure `_iter_symbols` guards against for the symbol string table, in the
  same file, and it means a name whose terminating NUL was clobbered reads as a longer,
  wrong string with `partial_analysis: false` rather than as an unreadable one.
  `_read_cstring` returns `None` for it, joining `macho_load_command_string_unread` like
  every other unreadable case.
- A name or path offset pointing inside the command's own fixed header instead of past
  it. For `dylib_command`, `timestamp`, `current_version` and `compatibility_version`
  are three free 32-bit fields with no structural meaning to this reader, so a crafted
  offset could read a plausible-looking name out of them that the object never spelled
  out anywhere -- the same decoy shape `binfmt.elf` refuses for its section tables.
  `_read_command_string`'s floor refuses it here.
- `LC_RPATH` would otherwise carry the exact silent-drop shape this entry closes for
  the dylib-loading family: an unreadable path offset loses the rpath entry with no
  error and no `partial_reasons` token. `linkage._looks_vendored` reads `rpath`
  directly, so this is not cosmetic.

**`_read_thin` returns a named record, not a positional tuple.** Every per-command cause
this reader names -- the unreadable string here, and the walk and ambiguity causes in
the entries below -- is one more field, and a positional return that grows by one
element per cause stops being the cheaper choice once there are three; `_ThinHeader`
carries them by name.

Revisit if a real wheel is found using `LC_REEXPORT_DYLIB` to re-export a specific
symbol rather than a whole dylib -- nothing in this load command carries one, so this
would have to come from `LC_DYLD_EXPORTS_TRIE`, named as a blind spot in `binfmt.macho`'s
module docstring.

## An unparseable load-command header flags the walk, it does not end it in silence

**Accepted, one level up from the load-command strings the entry above reads.**

An individual command's unreadable *name* is a partial reason
(`macho_load_command_string_unread`) while the walk keeps going past it. `_read_thin`'s
loop has two earlier checks, over the command's own `cmd`/`cmdsize` header rather than
its name:

```python
if pos + 8 > len(commands):
    break
cmd, cmdsize = struct.unpack_from(end + "II", commands, pos)
if cmdsize < 8 or pos + cmdsize > len(commands):
    break
```

A `break` that records neither an error nor a `partial_reasons` token drops every
command after the point it fires -- an honest, later `LC_LOAD_DYLIB` naming the system
OpenSSL included -- not merely one command's string:

```
poisoned cmdsize (0x10000, claims to run past the object)
-> silent break:   needed drops the later LC_LOAD_DYLIB entirely, partial_analysis: false
-> flagged break:  partial_analysis: true, macho_load_command_walk_truncated, error recorded
```

**Why its own token, not `macho_load_command_string_unread`.** The two claims are not
the same fact about the object. That token says one command's name could not be
trusted while the command itself -- its `cmd` and `cmdsize` -- could, so the walk kept
going and only that one command's string is missing. Here the command's own shape is
what lied, so nothing past it can be resynced on: not one name but every later
command, and everything it might have named, is unaccounted for. Forcing the string
token onto this would understate it the same way reusing `macho_symtab_incomplete` for
an unreadable load-command string would (the option the entry above rejects). It
records an error and is not on `[linkage_policy] exclude_reasons`, for the same reason
the string token is not, more so here: a lost command can be several dependencies, not
one.

**What was rejected: resyncing past the bad command.** Once `cmdsize` has lied once,
`pos + cmdsize` is a guess, not a fact -- there is no honest way to know where the
next command starts, so advancing past it risks reading a decoy command's body as if
it were real, the exact shape the command-string floor check refuses elsewhere in this
reader. Stopping the walk at the lie, with a signal, is the safe direction and the one
the invariant requires: evidence gathered *before* the bad command is unaffected (a
command read earlier in the same walk still reaches `needed`), only what would have come
after is lost, and it is lost as `partial_analysis: true`, never as a silent
`NO_CRYPTO_DETECTED`.

**What it costs.** An object whose load-command header is too short to hold
`cmd`/`cmdsize` at all, or whose `cmdsize` is below that minimum or claims to run past
the end of the load commands, reads `partial_analysis: true` and
`openssl_linkage: unknown` instead of quietly losing every command after it. These two
header-shape checks alone do not cover every way a load command can lie: an ABI-invalid
`cmdsize` (not a multiple of 8 on a 64-bit object) and an `ncmds` that understates the
real command count need checks of their own, below.

`binfmt/macho.py` grows with every cause its docstring enumerates; see "`binfmt/elf.py`
and `binfmt/macho.py` carry module-local line-count exemptions" for how the
module-length limit handles it.

### A misaligned `cmdsize` or an understated `ncmds` flags the walk too

**Accepted, and it changes records.**

Both shapes desync the same walk without tripping either of the two extent `break`s,
because both stay inside what those two checks look at. A `cmdsize` that is at least 8
and does not run past the end of the load commands passes the extent check outright even
when it is not a multiple of the ABI's own alignment (8 bytes on a 64-bit object, 4 on a
32-bit one) -- the walk advances `pos` by the lied-about amount and reads every later
command from the wrong offset, silently, the same loss as an overtly-lying `cmdsize`,
just one the header shape check alone cannot see. And `ncmds` itself says nothing about
how many bytes the walk actually consumed: a header that undercounts it makes the `for`
loop exhaust its iterations with real command bytes still sitting unread in `commands`,
with no single command's own header ever lying about itself for the extent checks to
catch.

```
(i) cmdsize=12 on a 64-bit object (not a multiple of 8, but >= 8 and inside the commands)
    -> without the alignment check: needed drops the later LC_LOAD_DYLIB naming
       libcrypto entirely, partial_analysis: false
    -> with it:                     partial_analysis: true,
       macho_load_command_walk_truncated, error recorded

(ii) ncmds says 3 (LC_ID_DYLIB, one LC_LOAD_DYLIB, LC_SYMTAB); the object carries a
     fourth, honest LC_LOAD_DYLIB naming libcrypto after a complete, already-read
     LC_SYMTAB
    -> without the post-loop check: needed drops the fourth command entirely,
       partial_analysis: false
    -> with it:                     partial_analysis: true,
       macho_load_command_walk_truncated, error recorded
```

**Same token, not two new ones.** Checked against AGENTS.md's "don't duplicate an
existing cause, but don't force a fit that overstates what happened" before reusing
`macho_load_command_walk_truncated` rather than minting
`macho_load_command_cmdsize_misaligned` and `macho_load_command_ncmds_understated`. The
token's claim is not "a command's header failed one of two specific checks" -- it is
"the walk did not honestly account for all its bytes, so everything after the point of
the lie is unaccounted for rather than absent," stated generically in the docstring
`partial_analysis` enumerates from and in the field comments on
`_ThinHeader`/`_SliceEvidence`, neither of which names the two extent checks as
exhaustive. Both shapes are that same claim by a different route: a misaligned
`cmdsize` means the commands after it cannot be trusted, for the identical reason an
overtly-overrunning one cannot; an understated `ncmds` means the walk stopped short of
what the object really carries, for the identical reason a too-short `cmd`/`cmdsize`
pair does. Applying AGENTS.md's admission test for a `partial_binary` list -- find a
crypto object that reads clean because the cause is on a list that swallows it -- finds
nothing: neither shape is a linker convention like the ordinal-import carve-out; both are
lies about the walk's own extent, and `macho_load_command_walk_truncated`'s absence from
`[linkage_policy] exclude_reasons` (it costs the linkage answer) is exactly the right
posture for both.

**Where the checks live.** Both are one line, at the point each check names above.
The alignment check joins the extent check on the same `if`, ahead of reading the
command's body:
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
Despite this section's title, that is not solely an `ncmds`-understated check: it
catches any shape where the loop finishes clean but `pos` and `len(commands)` disagree,
which also includes an aligned, individually-honest-looking `cmdsize` that overstates
its OWN command's real size and swallows a later command's bytes into its own padding --
no single command's header fails a check, and `ncmds` may be entirely correct, but the
walk still stops short of the object's real extent. Confirmed directly: patching an
honest `cmdsize` of 40 up to 48 trips this check with the alignment check disabled.

**Recovery, the same as for the extent checks.** The walk does not resync past the point
of the lie -- once one command's shape cannot be trusted, nothing after it can be
either, so the walk stops there and reports every later command as unaccounted for, not
attempted-and-failed. Both shapes follow the same choice for the same reason: a
misaligned `cmdsize` means `pos + cmdsize` was never a trustworthy jump in the first
place, so guessing a corrected offset would be resyncing on a value that already lied,
the exact hazard rejected above; an understated `ncmds` means the object never admitted
the trailing bytes exist, so reading them anyway would report evidence the header itself
disowns. Evidence read *before* either point survives untouched, the same "costs that
structure, never the evidence already gathered" invariant the extent checks hold.

**Interaction, checked rather than assumed.**
- *Misalignment and the duplicate-command ambiguity check, together.* A misaligned
  `cmdsize` cannot desync the walk into misreading later bytes as a decoy `LC_ID_DYLIB`
  or `LC_SYMTAB` and firing `macho_load_command_ambiguous` for the wrong reason, because
  the alignment check sits at the same point the extent check does: the walk breaks the
  moment the lie is read, before any byte past it is ever interpreted as a command of its
  own. Pinned directly: `test_a_misaligned_cmdsize_desyncs_the_walk_rather_than_landing_clean`
  asserts `macho_load_command_ambiguous` is absent from the reproduction's
  `partial_reasons`.
- *The understated-`ncmds` check and the alignment check, on one object.* They cannot
  both fire from the same walk (one requires a `break`, the other requires the loop to
  finish without one), so the only way to see them together is two slices of one fat
  object, each tripping a different cause.
  `test_misalignment_and_understated_ncmds_combine_without_contradiction` builds exactly
  that and confirms `macho_load_command_walk_truncated` appears once, not duplicated or
  contradicted, in the merged record -- the same de-duplication the duplicate-command
  entry pins for ambiguity alongside the extent check's truncation.
- *The two extent break conditions, as a guard.* Every extent-check test passes with
  the two checks here in place; nothing about either changes what the two extent checks
  catch. `test_sizeofcmds_exactly_at_the_cap_is_read_while_one_byte_over_is_refused`
  pads its at-cap object with a real, `ncmds`-accounted filler command rather than dead
  zero bytes, which the post-loop check correctly flags; every one of its assertions,
  including the over-cap half, holds.

**The fixtures are ABI-honest.** `MachOBuilder._dylib_command` and `_rpath_command` pad
every command to the ABI's own boundary through `_cmd_alignment`/`_cmdsize_pad`: 8 bytes
on a 64-bit object, 4 on a 32-bit one. A helper padding to 4 bytes regardless of `is64`
is honest for a 32-bit object but not for a 64-bit one, and builds objects the alignment
check flags as malformed purely by the length of the strings chosen -- measured with
4-byte padding: 34 of 111 tests in `test_binfmt_macho.py` fail, 42 across the whole suite
once the Mach-O fixture consumers in `test_acceptance.py`, `test_hardening.py` and
`test_partial_reasons.py` are counted. The padding is fixed at the source rather than by
loosening the check, so every "well-formed" fixture is ABI-honest. Two fixtures need
more than the shared helper: `all_nonprintable_dylib_name` and
`malformed_rpath_name_offset` pad with NUL bytes after an already-closed string, which is
safe; `unterminated_dylib_name` pads with non-NUL filler instead, since a NUL pad would
prematurely close the very run that fixture exists to leave open.

**What it costs.** An object whose `cmdsize` is internally consistent by the extent
checks but not aligned to the ABI's own boundary, or whose header's `ncmds` undercounts
the object's real command count, reads `partial_analysis: true` and
`openssl_linkage: unknown` instead of quietly losing every command the lie put out of
reach. No `ruleset.toml` change: `BIN_PARTIAL_FORMAT` claims every cause not named in its
own `exclude_reasons`, and this cause is on that claim whatever triggers it.

**What was rejected.** Two new tokens, covered above. Resyncing past either lie by
guessing a corrected `pos`, covered above under "Recovery." A separate check keyed to
`is64` alone without also comparing against the extent check's bounds -- rejected
because the two questions ("is this cmdsize inside the object" and "is this cmdsize
aligned") are independent facts about the same field, and folding the alignment check into
a value clamp rather than a straight boolean would have to explain what an "aligned but
still out of bounds" `cmdsize` should read as, a question the `or` chain answers for free.

Revisit if a real wheel is found where a `cmdsize` misaligned by exactly one word is a
known, benign quirk of some Mach-O producer rather than a sign of a genuinely malformed or
adversarial object -- no such producer is known, and the ABI documentation this check
enforces states the alignment as a requirement, not a convention. Also revisit
`binfmt.macho`'s docstring and comment growth: three per-command causes on top of the
ambiguity split is close to the point a positional accounting stops being legible in
prose at all.

## A symbol name is capped the way PE's are

**Accepted. PE's own name-cap mechanism, applied to ELF and Mach-O rather than a second
one invented.**

Finding a name's terminator, decoding the full slice and running `sanitize` -- a
per-character Python pass -- over it for every row, with no per-name bound and no
whole-table budget, costs rows times bytes. `binfmt.pe` bounds exactly this shape for
PE's export and import tables with two bounds: `_MAX_NAME_BYTES`, a per-name cap past
which a name is unresolved rather than truncated into the record, and
`_MAX_NAME_TOTAL_BYTES`, a whole-object budget the cap alone does not cover because
nothing stops many rows pointing at one name, or many rows pointing at many different
long ones. `binfmt.elf._iter_symbols` and `binfmt.macho._iter_symbols` need the same two.

**Measured directly.** 2000 `.dynsym`/`LC_SYMTAB` rows all pointing at one 2 MiB name
cost 243.7s without a per-name bound. With the bound, the equivalent case -- built the
same way, through `tests/test_hardening.py`'s full `scan_wheel` path, not a
microbenchmark of `_iter_symbols` alone -- runs in 0.02s for ELF and 0.11s for Mach-O.
The cost is not the row count; it is rows times the bytes each row's `sanitize` call is
asked to look at, and the two bounds hold that product down regardless of how the rows
are laid out.

**The two bounds, at PE's own values.** `_MAX_NAME_BYTES` (8 KiB) and
`_MAX_NAME_TOTAL_BYTES` (8 MiB) live in `binfmt.symtab`, shared rather than duplicated
into both readers, sized off PE's own corpus measurement (30,835 real export names, the
longest an MSVC-mangled 1027-byte C++ name) for lack of an ELF or Mach-O corpus of our
own. Nothing here argues for a different number: an Itanium-mangled C++ name or a legacy
Rust symbol (a full module path plus a hash) grows unbounded the same way MSVC's
mangling does, so reusing PE's value is the same bet PE makes, not a smaller one.
Revisit if a real ELF or Mach-O wheel is found on the triage list with its only
incompleteness a name past this cap, the same "and nothing else" test "A recording cap
is not a partial read", above, asks.

A name of exactly `_MAX_NAME_BYTES` still resolves; one byte more does not. This
differs from PE's own `cstring`, which searches `[offset, offset + window)` for a
window equal to the cap and so silently stops resolving one byte short of it -- an
implementation detail of that reader, never written down as the bound's actual
meaning. `binfmt.symtab.BoundedNames` searches `[offset, offset + cap + 1)` instead, so
the cap means what its name says: the most a name may carry, not the most a name may
carry minus one. PE is not revisited here; its tests only pin behaviour past its cap,
never dead on it, so nothing there is disturbed by this reader defining the edge
differently.

**The same "+1" reasoning applies to the budget, and a plainer `window` formula misses
it.** `window = min(_MAX_NAME_BYTES + 1, available, self._budget)` looks equivalent but
is not: the "+1" covers the cap but not the budget it sits beside, so a name of exactly
`self._budget` content bytes has its terminator at `offset + self._budget`, one byte
past a window sized to `self._budget` itself. A table with `_MAX_NAME_BYTES` left in
its budget could resolve every name shorter than that but not one landing exactly on
the amount remaining -- fails safe (the row reads unresolved, `partial_analysis: true`,
never a name it did not carry), so this is not a correctness hole, but it would
silently spend a name's budget one byte more conservatively than the number in
`_MAX_NAME_TOTAL_BYTES` says. `_resolve_uncached` takes `min` of the cap and the budget
*first* (`max_len = min(_MAX_NAME_BYTES, self._budget)`) and only then turns that into a
search span (`window = min(max_len + 1, available)`), so the "+1" is applied once, to
whichever of the two is actually binding, not to the cap alone regardless of which one is.
`tests/test_binfmt_symtab.py::test_a_name_exactly_as_long_as_the_remaining_budget_still_resolves`
pins it by setting `_budget` directly rather than spending it down row by row, which
would need thousands of rows to reach a boundary this exact for no reason connected to
what the test checks.

**The third bound, that PE does not have: memoization by string-table offset.**
`BoundedNames` caches `(name, resolved)` by the raw offset a row's `st_name`/`n_strx`
names, so a repeated offset costs the decode once. This covers a case the cap and the
budget do not cover between them: many rows honestly repeating one *valid*, well-under-cap
name would otherwise spend the whole-table budget once per row, exhausting it partway
through an object that carries exactly one real symbol and turning it
`partial_analysis: true` for no reason but that its own string table was walked more
than once. `tests/test_hardening.py`'s
`test_repeated_elf_dynsym_offsets_resolve_the_same_valid_name` and its Mach-O
counterpart pin this the same way the budget test pins the opposite failure: removing
memoization does not make either test slow -- 2000 rows through an 8 KiB-ish name is
fast either way, since the cap alone keeps each row's search cheap -- it makes
`partial_analysis` flip from `false` to `true`, a correctness assertion rather than a
stopwatch race. The bounded-time tests beside them assert a wall-clock ceiling,
generously above the bounded cost, the same way PE's own name-cap tests do; only the
memoization guard needs a non-timing signal to fail reliably, since the cap alone makes
the over-cap case fast regardless of whether repeats are memoized.

**The cache that makes memoization work has its own cap, sized against a table shaped to
dodge the byte budget rather than repeat an offset.** The whole-table budget only shrinks
for an offset that resolves to real bytes; an offset past the table, into an unclosed
run, or naming an empty string costs it nothing at all, so a table of many rows -- one
per row, each a distinct such offset -- would grow `BoundedNames`'s cache by one entry
per row with neither the per-name cap nor the byte budget ever engaging to stop it. That
is the exact cost `binfmt.elf` and `binfmt.macho` avoid elsewhere, by keeping only the
crypto names actually read (`read_crypto: set[str]`) rather than every name a table
carries -- the comment beside it measures a half-million-symbol table at 24 MiB
remembered whole. `_MAX_CACHE_ENTRIES` (65536, `binfmt.pe`'s `_MAX_THUNKS` scale) bounds
the cache the same way: past it, `resolve` still answers every row correctly, it simply
stops remembering, which only gives up the speedup for offsets beyond the cap, never an
answer. `tests/test_binfmt_symtab.py` pins this directly against `BoundedNames`, since
exercising it through either reader would need enough distinct offsets to make a full
`scan_wheel` construction slow for no reason connected to what the test checks.

**`binfmt.macho`'s `N_INDR` alias resolution needs the same cap as `n_strx`, at the
same call site.** An alias's target is read out of `strings` through `resolver`, the
same bounded, memoized path ordinary names use in `_iter_symbols` -- not read directly
with no cap, no budget and no memoization, which would reopen the identical shape the
bounds close for `n_strx`, one field over.

Leaving it uncapped is rejected on two counts. First, frequency: an `N_INDR` row is not
rarer by construction than an ordinary name -- every row in a reproduction is free to
be `N_INDR`, and a table shaped to exploit this looks exactly like the ordinary-name
case, one field renamed. Second, arity: routing the alias through `resolver` makes
`alias`'s *type* `str | None` rather than `bytes | None` -- resolved, ABI-stripped and
sanitised, the way ordinary names come back from `resolver` -- which is a one-line
difference at the single call site that would otherwise `.decode()` it, not a signature
change at all. `resolver` is in scope in `_iter_symbols` for ordinary names; the alias
branch uses it too.

Measured the same way: 200 `N_INDR` rows aliasing one 2 MiB target cost 30.4s without
this bound (linear in rows, the same shape as the `n_strx` measurement above), and 2000
rows against a 4 MiB target run in well under a second with it.

The one asymmetry that is real, not a gap: an ordinary unresolved name always sets
`unresolved`, unconditionally, because the caller cannot tell in advance whether an
unreadable name would have been crypto-relevant. An alias whose target fails to
resolve sets nothing of its own -- the row's own name, from `n_strx`, is still fine,
and `alias` is simply `None`, the same value a row with no alias at all yields. This
is not a hole: the target string is still sitting in `strings` either way, and
`holds_a_name_not_read`'s independent scan exists to find any crypto name sitting there
unaccounted for in `read_crypto`, regardless of *why* it went unaccounted -- alias
failure, an ordinary index past the string table, or a lying `nsyms`, all read the same
to that check. A non-crypto target that happens to be over-cap costs nothing and is
correctly not partial, the same way a huge non-crypto ordinary name would not be; a
crypto-matching one still is, via the `macho_symtab_incomplete` /
`symtab_understates_rows` pair, no new token needed.
`tests/test_hardening.py::test_a_mach_o_aiming_every_alias_at_one_over_cap_crypto_target_is_not_read_clean`
pins the case that matters; the sibling test beside it pins that a merely-long,
non-crypto target does not falsely turn the object partial.

**Where the bounds are checked, and what they interact with.** Over the cap or over
budget, a row comes back `resolved=False`, the same signal an index past the string
table's end or into a run it never closes produces -- `_iter_symbols`'s callers in both
readers fold that into `unresolved` and, from there, into `elf_dynsym_unread` or
`macho_symtab_incomplete`, so no new `partial_reasons` token is needed. ELF's index-0
short-circuit ("no name", unconditional by the format's own definition) stays ahead of
`BoundedNames` rather than folded into it: index 0 is "no name" regardless of what byte
a decoy table puts there, which is a different claim from "the table's own bytes say
this name ends here," and collapsing the two would let a forged byte at offset 0 answer
a question the format does not leave open. Mach-O's `n_strx == 0` case is not
special-cased -- it falls out of the general path correctly, so a special case would be
a behaviour change with nothing to justify it.

**What was rejected.** A per-format cap and budget, duplicated into `binfmt.elf` and
`binfmt.macho` the way the cross-check they share (`holds_a_name_not_read`) is not:
`binfmt.symtab` exists for exactly this, a check "the same in both readers" that
"drifts" if written twice, and the bounded-read logic is the same fact about a string
table the cross-check is. A shared budget threaded across a fat Mach-O's slices, rather
than one `BoundedNames` per `_read_symbols` call: `AGENTS.md` treats a universal
binary's slices as independent passes up to `_MAX_FAT_SLICES`, over regions the slices
are free to share, so a per-slice budget is the existing shape, not a new one -- and a
budget shared across slices would need threading extra state through `_SymbolRead`'s
return shape for a benefit no reproduction here shows: nothing in these measurements
points at a fat binary as the multiplier.

**What it costs.** An ELF or Mach-O wheel whose symbol table carries a name past the
per-name cap, or whose table-wide budget the walk exhausts, reads `partial_analysis:
true` instead of whatever the (slow, but accurate) full decode produces -- most likely
clean, since a name that long matching a ruleset group by accident is not the shape any
real wheel has shown, but not simply assumed either way. This is a cost in the same
direction "A recording cap is not a partial read", above, accepts for the string budget,
for the same reason: the honest answer for an object this expensive to read in full is
that it was never read, not a guess dressed as one. Nothing in `ruleset.toml` changes:
both partial-reasons tokens this reuses are policy already.

## A compressed section is checked before it is inflated

**Accepted: refuse to inflate past what can be used.**

`Section.data()` decompresses a `SHF_COMPRESSED` section's `Chdr.ch_size` bytes before
`_collect_string_bytes` or `_symbol_bytes` ever get to apply their own budget. `ch_size`
is a 64-bit field the object declares about itself, the same shape the per-name symbol
cap and the strings budget bound for a name and a whole-table size -- except here the
number buys an actual `zlib.decompressobj()` call rather than a Python loop, so the cost
is a memory spike, not CPU. Reproduced directly without a check: a 255 KiB ELF
declaring a 256 MiB `.rodata`, `read_elf` peaking at 512 MiB in 0.82 s, recorded as
`partial=True reasons=('strings_bytes_unread',) errors=[]` -- the record is correct,
the cost is getting there. The wheel-level `ArchiveLimits.max_compression_ratio` guard
never sees this shape: the zlib stream sits inside the zip member, whose own compression
ratio looks ordinary either way.

**Checked with a call pyelftools makes anyway, not a new one.** `Section.__init__` reads
`Chdr` eagerly and cheaply -- `Elf64_Chdr` is `ch_type`, `ch_reserved`, `ch_size`,
`ch_addralign`, 24 bytes; `Elf32_Chdr` drops `ch_reserved`, 12 -- before `.data()` is
ever called, and exposes the result as `section.compressed` and `section.data_size`
(pyelftools, `elftools/elf/sections.py`; the struct layouts, elfclass-aware, are in
`elftools/elf/structs.py:_create_chdr`). `_bounded_section_data` (`binfmt/elf.py`) reads
`section.data_size` and refuses -- `(b"", True)`, the same "unread" signal a `.data()`
call that raises produces -- when it is over `max_bytes`, never calling `.data()` at all
in that case. Both ELF classes are covered by construction, through the one property
read, not by hand-parsing `Chdr` a second time or by a dedicated 32-bit test:
`structs.Elf_Chdr` is built per-object from `elf.elfclass`.

**One helper, three call sites, the same shape at each.** `_collect_string_bytes`
checks against `remaining`, the budget left after earlier sections -- over `remaining`
is over `max_strings_bytes` outright whenever `remaining` is still the whole budget, so
nothing else needs comparing. `_symbol_bytes` reads `.dynsym`'s entries and its string
table through the same call `.rodata` is, so `max_strings_bytes` -- the caller's own
ceiling on how much of this object it will inflate -- is threaded through as
`_symbol_bytes`'s bound too, rather than a second constant for a question this file
answers once. Auditing every other `.data()` call in `binfmt/elf.py` for the same
exposure finds one more: `.go.buildinfo`, read the identical way. It gets the same
guard, against `max_strings_bytes`, reusing `elf_go_buildinfo_unread`, no new token.

**`.go.buildinfo` carries a second, uncompressed exposure, one a guard keyed only on
`compressed` misses.** `Section.data()` checks `SHT_NOBITS` before it checks
`compressed` at all, and for a `SHT_NOBITS` section returns `b"\0" * self.data_size`
with no file bytes read to justify the length -- `data_size` there is just `sh_size`
itself (`Section.__init__` sets `_decompressed_size = header['sh_size']` whenever
`compressed` is false), and `SHT_NOBITS` is defined to occupy no file space, so nothing
bounds it against the object's actual size. `_collect_string_bytes` is not exposed to
this: it excludes `SHT_NOBITS` outright, for every section it considers. `.go.buildinfo`
is found by `_find_section` on name alone, with no `sh_type` check of any kind, so a
section named `.go.buildinfo` and flagged `SHT_NOBITS` would reach `.data()` through a
guard keyed only on `compressed` exactly the way an honest one does: a guard reading
`not section.compressed` as "ordinary and file-backed" mistakes what that condition
means. It means "not compressed," and `SHT_NOBITS` is the gap between those two
readings. Reproduced: a 298-byte object (no compression, no zlib) with `.go.buildinfo`
marked `SHT_NOBITS` and `sh_size` declaring 2048 MiB peaks at 2 GiB, `partial_analysis:
false`, no error -- three orders of magnitude cheaper to build than the compressed
reproduction above, and silent rather than merely expensive, since nothing about it
routes through a compression check at all. `.dynsym` and its string table are safe from
this by construction rather than by a check: both are reached through
`_find_section_by_type`/`_validated_strtab`, which match on `sh_type == "SHT_DYNSYM"`/
`"SHT_STRTAB"` specifically, and a section cannot carry two `sh_type` values at once.
`tests/test_hardening.py::test_a_nobits_named_go_buildinfo_does_not_allocate` pins this
the same way the compressed cases are pinned: a peak-bytes ceiling, which fails without
the `SHT_NOBITS` arm.

**An ordinary section is checked too.** A guard that refuses only when `section.compressed
or section["sh_type"] == "SHT_NOBITS"` lets an ordinary, uncompressed, file-backed
section (or `.dynsym`/`.dynstr` from a real symbol table, read through the identical
call) reach `.data()` at whatever size `sh_size` names, with nothing left to cut it
back down afterwards: `_collect_string_bytes` has no post-read cut of its own, only
the per-section budget it passes into `_bounded_section_data` before each read.
`section.data_size` means the same thing here as for the
compressed and `SHT_NOBITS` cases: `sh_size` itself -- genuinely file-backed for an
ordinary section, but that is exactly the exposure: reading it costs whatever `sh_size`
names before this reader's own budget gets a say. So the check is unconditional:
`if section.data_size > max_bytes`, applied to every section regardless of shape.
Reproduced at the same 8 MiB/64 KiB scale as the compressed case, with the narrower
guard: an honest, uncompressed 8 MiB `.rodata` is read in one `stream.read()` of 8388608
bytes, `tracemalloc` peaking at 8605805, and the record reads `strings_bytes_unread` --
correct, but only after the whole section was read to get there. `.dynsym`/`.dynstr`
from 200,000 real, distinct symbol names (~4.8 MiB `.dynstr`, and a `.dynsym` of the
identical size, 24 bytes per `Elf64_Sym` entry) against the same 64 KiB budget read
whole and come back `partial_analysis: false` -- a fully clean, complete record, paid
for at the size of the honest table rather than the budget, with no way for a consumer
to tell this table cost more than it should have. With the unconditional check, both
`.dynsym` and `.dynstr` are checked independently against the same budget
(`_symbol_bytes` threads `max_table_bytes` through to both calls), either one over
budget refuses the whole table, and `elf_dynsym_unread` fires -- the honest symbol this
reproduction carries is not silently dropped; the record says it was not read rather
than staying clean.

**`.dynsym`'s own declared size is checked independently of `.dynstr`'s.** Checking
`.dynstr` alone leaves an honest `.dynsym` of any size read in full regardless of budget
-- the shape the per-name cap and this budget exist to bound. A `.dynsym` with even a
single real symbol is two `Elf64_Sym` entries, not one -- index 0 is always the reserved
null entry -- so 48 bytes (`Elf64_Sym`'s own 24, twice), not 24, is the floor a
"declares exactly the budget" boundary test has to clear for `.dynsym` to be read at all
alongside its string table; `tests/test_binfmt_elf.py`'s `.dynstr` boundary tests are
sized to that 48-byte floor.

**No new `partial_reasons` token at any site.** A compressed `.rodata`/`.comment`'s
refusal folds into `elf_section_data_unread`, the cause the
`SHF_COMPRESSED`-over-garbage-bytes case in `tests/test_partial_reasons.py` produces from
a `.data()` call that raises -- refused before the call and raised inside it are the same
fact for a consumer, "this section was not read," so they share the token rather than
needing a means-versus-end distinction nothing downstream asks for. `.dynsym`/`.dynstr`'s
refusal folds into `elf_dynsym_unread` the same way, and for the case where only the
string table is over budget this mostly falls out of the cross-check for free: an empty
`dynstr` resolves nothing, `unresolved` climbs, and the `if unresolved: ...` branch adds
the token. It is still named explicitly (`symtab_bytes_unread`, checked before the
resolve loop) because a `.dynsym` whose *own* bytes were refused iterates zero rows --
`unresolved` stays zero, `holds_a_name_not_read` has nothing pointed away from to notice
either, and nothing else would say this object was not read at all.

**The boundary is "more than", not "at least".** A section declaring exactly `remaining`
(or exactly `max_strings_bytes`, for the symbol-table and `.go.buildinfo` call sites) is
refused nothing: `.data()` runs, produces exactly that many bytes, and nothing past this
point truncates it further, the same "cap means what its name says" reading "A symbol
name is capped the way PE's are", above, gives `_MAX_NAME_BYTES`.

**Measured, scaled down for the test suite.** The 256 MiB declared / 512 MiB peak
reproduction above scales down to 8 MiB declared against a 64 KiB budget: without the
guard, `tracemalloc` shows a ~16.9 MiB peak (the inflated buffer plus pyelftools' own
read-back copy, the same roughly-2x shape the 256 MiB/512 MiB numbers show); with the
guard, well under 2 MiB, in well under a second either way since 8 MiB of zero bytes
compresses and decompresses fast regardless. `tests/test_hardening.py`'s
`..._does_not_allocate` tests assert a peak-bytes ceiling rather than a timing race, the
same technique the symbol-name bounded-time tests use for the same reason: removing the
guard fails them on the memory assertion, cleanly, not by chance timing.
`tests/test_binfmt_elf.py` carries the correctness side at unit scale --
refused-over-budget, honest-under-budget, and exactly-at-the-boundary, for both
`.rodata` and a corroborated decoy `.dynstr` -- and pins the *token* difference the
guard makes: without it, the over-budget compressed `.rodata` case genuinely
decompresses (it is an honest 8 KiB payload, not garbage) and reads as
`strings_bytes_unread` with no error -- the record is correct, the cost is getting
there; with the guard, it is `elf_section_data_unread` with one, and
`strings_bytes_unread` does *not* also fire -- see "`strings_truncated` can under-report
a budget refusal" below for why that is deliberate rather than a fact the guard drops.
The `.dynstr` case has no truncate-and-continue at all, so without a guard it is read in
full at any size and the symbol resolves -- there is no bound to test without one, only
an unbounded read.

**`strings_truncated` can under-report a budget refusal, and this is left as-is rather
than papered over.** A compressed section refused by `_collect_string_bytes`'s pre-check
sets `unread`, not `truncated`: `truncated` is what a section read in full and then cut
to fit sets, and a refused section was never read at all, so nothing here knows how many
of its bytes -- if any -- would have been genuine strings versus more of whatever made
`ch_size` this large. The obvious alternative, setting `truncated` too whenever the
refusal fires, does not hold up: `ch_size` alone cannot tell an honestly oversized
declaration apart from a malformed header that happens to decode to a huge number, and
`tests/test_partial_reasons.py`'s "elf section data unreadable" fixture is exactly that
shape -- `.rodata` filled with the OpenSSL banner text, `SHF_COMPRESSED` set over bytes
that were never really compressed at all, whose first 24 bytes decode as a `Chdr` with
`ch_size` around 3.76 * 10^18 purely by accident of what those ASCII bytes happen to be.
Setting `truncated` there is not a defensible claim -- there was never a real
3.76-exabyte string payload to have dropped part of -- so the branch cannot set it
correctly for every case that reaches it, and the alternative of trying to distinguish
the two (checking `ch_type` before deciding) reintroduces exactly the "is this header
sane" question `_bounded_section_data` exists to avoid asking before refusing.
`strings_truncated: false` alongside `elf_section_data_unread` is therefore the honest
answer for this cause: `partial_analysis`/`partial_reasons` are what say the object was
not read in full, and `strings_truncated` narrows to the weaker, cap-specific question of
whether a definite number of budget bytes is known to have been dropped -- which, for a
section refused before ever being read, is not a question this cause can answer either
way.

**A refused `.dynsym` or `.dynstr` must not reach the `unresolved`/
`holds_a_name_not_read` cross-check unguarded, or it fabricates
`symtab_understates_rows` -- a specific, checkable claim ("every structural check passes
and the count is simply not the truth", per `SCHEMA.md`) -- against a table that was
never shown to lie, only left unread.** When `.dynsym` alone is refused for budget,
`table` is empty, so `_iter_symbols` yields no rows and `unresolved` stays 0; the
`elif holds_a_name_not_read(dynstr, patterns, read_crypto):` branch would then find
whatever real crypto name sits in an honest, in-budget `.dynstr` unclaimed by any row
`read_crypto` never got the chance to populate, and report it as an understated symbol
count. Reproduced directly without the ordering: 101 `.dynsym` entries (100 short-named
padding rows plus one real `SSL_new`) against a 600-byte budget -- `.dynstr` (509 bytes)
reads fine, `.dynsym` (2448 bytes) is refused -- read as `('elf_dynsym_unread',
'symtab_understates_rows')` with the error `".dynsym declares fewer entries than
.dynstr holds names for"`, both false: the object's row count was correct throughout.
A companion, lower-severity shape reaches the sibling branch instead: `.dynstr` alone
refused (a real `.dynsym` entry, an oversized honest decoy `.dynstr`) means every row
resolves against an empty string table, so `unresolved > 0` fires
`".dynsym names strings .dynstr does not hold"` -- not exactly false (`.dynstr` really
does hold nothing, being empty) but redundant and misleading alongside the correct
budget error, and not the claim `unresolved` exists to make (the object lying about
`.dynstr`'s own contents). `binfmt.macho`'s `_SymbolRead` orders `truncated` ahead of
its `unresolved`/understated pair, and `read_elf` does the same: it checks
`symtab_bytes_unread` first and skips the entire per-symbol walk and both follow-on
branches when it is true, keeping only the `elf_dynsym_unread` error and reason the
refusal itself sets -- there is nothing correct left for either branch to add once a
read was refused rather than completed. Skipping the walk also means neither shape pays
for iterating rows or resolving names that cannot answer either question anyway, the
same "cheapest question first, walk skipped for a table already known to have fallen
short" ordering `binfmt.macho`'s own comment gives it.
`tests/test_binfmt_elf.py::test_a_refused_dynsym_with_an_honest_dynstr_does_not_fabricate_understated_rows`
and `::test_a_refused_dynstr_with_an_honest_dynsym_does_not_fabricate_a_second_error`
pin both shapes: with the ordering removed, the fabricated reason and the redundant
message both reappear, on the same assertions.

**An ordinary section refused for being over budget keeps its in-budget prefix, not its
entire content discarded, the same as every other reader in this codebase.**
`binfmt/macho.py`, `binfmt/pe.py` and `binfmt/fallback.py` all read
`min(size, max_strings_bytes)` and keep the in-budget prefix; refusing an over-budget
ordinary section outright, `(b"", True)`, is the shape a compressed section must take
(an all-or-nothing `zlib` call with no cheap partial-read) but is wrong for a plain
file-backed section with no such constraint. Reproduced against a real host library,
`/usr/lib64/libLLVM.so.22.1` (68.3 MB of eligible sections against the 64 MiB default
budget): keeping the in-budget prefix reads it `strings_bytes_unread`, no errors;
refusing it outright would read it `elf_section_data_unread` plus a spurious
`elf_parse_error`, which fires `BIN_UNPARSEABLE` ("Truncated, corrupt or an
unrecognised format") over `BIN_STATIC_OPENSSL` -- a false-positive-shaped downgrade on
a perfectly ordinary, healthy object, at a size range ML/scientific wheels (`libxul`,
`libnode`, `pyarrow`'s `libarrow`) commonly reach. `_bounded_section_data` takes a
`keep_prefix` parameter: an over-budget ordinary section still refuses past the budget,
but for `.rodata`/`.comment`/`.go.buildinfo` -- the callers that pass `keep_prefix=True`
-- it hands back `max_bytes` of its own real content first, one plain
`stream.seek`/`.read()` at the section's own offset, no decompression and no second
reader involved. `_collect_string_bytes` treats a non-empty recovered prefix as
`truncated`, not `unread`: the object told the truth about its bytes, this reader simply
ran out of budget partway through them, which is exactly what `strings_bytes_unread` (no
error) names for the "budget exhausted across several smaller sections" case --
producing, at this call site, the same record an unbounded read would produce for an
ordinary oversized section, at the cost of a single bounded read instead of a full one.
`libLLVM.so.22.1` reads `strings_bytes_unread`, no errors, one matched string, with
`keep_prefix` -- the same record an unbounded read gives it. `.go.buildinfo` keeps its
`elf_go_buildinfo_unread` error whenever refused, prefix or not (see "What was rejected"
below for why), but the recovered prefix reaches `build_go_info` rather than being
discarded: an honest Go version sitting near the section's own 32-byte header,
comfortably inside the budget, still parses even though the section as a whole did not
read in full. `.dynsym`/`.dynstr` do not pass `keep_prefix` and refuse outright (see
"What was rejected" below).

**The budget is decided before the read, once.** `_collect_string_bytes` has no
post-read cut: `_bounded_section_data` guarantees `len(data) <= max_bytes` whenever it
does not refuse -- for a compressed section (pyelftools raises `ELFCompressionError`
rather than return a mismatched length, caught one level up as `unread`), for
`SHT_NOBITS` (`data_size` bytes of zero, always, and skipped earlier anyway), and for an
ordinary one (`stream.read(n)` never returns more than `n`). A section whose own
declared size is refused `continue`s before `buf.extend(data)` is ever reached; one that
is not refused cannot produce more bytes than the budget it was measured against.

**What was rejected.** Decompressing with a caller-supplied `max_length`, keeping
whatever prefix fits, the same shape `_collect_string_bytes` gives an honest oversized
*uncompressed* section, is bounded correctly: `zlib.decompressobj().decompress(data,
max_length=N)` allocates `N`, the defender's own chosen budget, not anything the object
declares -- verified directly, `max_length=4096` against a stream that inflates to
256 MiB peaks at well under a megabyte, `max_length=64 MiB` peaks at ~128 MiB (the output
buffer plus the same roughly-2x overhead measured above), regardless of what `ch_size`
claims. That is not what rules it out: it needs the `Chdr` parse and a `zlib` call
outside `pyelftools` -- exactly the second reader for one fact "A symbol name is capped
the way PE's are" declines for `BoundedNames`. It would also split the call sites
onto different rules for the identical shape: a partial `.rodata` prefix is enough
evidence for `strings_bytes_unread`-style truncation, but a partial `.dynstr` prefix is
not obviously the same table `.dynsym`'s offsets were computed against, and treating an
unreadable symbol-table prefix as fully unread is the natural rule there, so applying it
to `.rodata` alone would answer one shape with two different mechanisms. Treating any
compressed eligible section as unread, regardless of size, throws away an honest, small,
well-under-budget compressed banner for no reason -- losing evidence "A recording cap is
not a partial read" establishes a budget precisely to keep. Refusing on the declared size
costs neither: an honest section under budget is untouched, and an oversized one is
refused before its size is spent on anything.

Applying `keep_prefix` to `.dynsym`/`.dynstr` too is rejected: a byte-bounded prefix of a
symbol table is not a set of complete rows, an entry near the cut is as likely to point
past a truncated string table as into it, and reading one without a row-aware cap
reopens a narrower version of the exact fabrication the ordering above exists to prevent
(a partial table that iterates some real rows and some garbage ones, with no way here to
tell which is which). The honest way to bound a symbol table without losing rows to that
ambiguity exists one layer over, in `binfmt.macho`'s per-slice `nsyms`/`strsize` cap
("sizeofcmds and the symbol table are capped, not just clamped to the member", below):
bringing that shape to ELF is a real change, but a different, larger one, and is left
open rather than half-built. Compressed and `SHT_NOBITS` sections keep the all-or-nothing
refusal regardless of `keep_prefix`: a compressed section has no cheap partial read (the
`max_length` path is declined above), and an `SHT_NOBITS` "prefix" is `b"\\0"` bytes
carrying no evidence either way, so there is nothing a keep-prefix path would recover
for either shape. Giving `.go.buildinfo`'s refusal the same "no error" treatment
`.rodata`/`.comment` get is rejected, because `strings_bytes_unread` is specifically the
*strings pass* running short across the sections `_collect_string_bytes` concatenates,
and `.go.buildinfo` is parsed separately, outside that pass; reusing the token for a
question it was not built to answer is the same "one vocabulary, two questions, do not
assume they are equal" hazard `AGENTS.md` names for `PARTIAL_REASONS`, so `.go.buildinfo`
keeps its own token and its own error whenever the declared size is not honoured, prefix
recovered or not.

A second, separate check for the ordinary case beside the compressed/`SHT_NOBITS` one is
rejected: `data_size` means the same 64-bit self-declared size question regardless of
shape, so a second check would just be the same predicate typed twice, the identical
objection raised against a second reader for one fact. Checking `.dynstr` alone and
leaving `.dynsym`'s own size unchecked is rejected above, for reopening the exact door
this entry exists to close on the symbol-table side.

**What it costs.** An object whose eligible `.rodata`/`.comment` declares a *compressed*
size over the remaining strings budget reads `elf_section_data_unread` rather than
`strings_bytes_unread` -- `partial_analysis: true` either way, but named, and with an
error record, rather than silently short -- and `strings_truncated` reads `false` for
this shape: see "`strings_truncated` can under-report a budget refusal" above for why.
An object whose `.dynsym` or its string table declares a size over `max_strings_bytes`,
compressed or not, reads `elf_dynsym_unread` instead of whatever a full, unbounded read
produces -- most likely a correctly resolved symbol table, since nothing checked here
points at a real wheel shaped this way, but not simply assumed either way, the same
trade the per-name cap accepts. An object whose eligible `.rodata`/`.comment` declares
an *uncompressed* size over the remaining budget reads the same record an unbounded read
gives -- `strings_bytes_unread`, no error, whatever fits the budget kept -- at the cost
of one bounded read instead of a full one. `.go.buildinfo` keeps its
`elf_go_buildinfo_unread` and error whenever refused, with its own recovered prefix
reaching `build_go_info`. Nothing in `ruleset.toml` changes: every token this reuses is
policy already.

**What is not verified.** Whether any real wheel ships a compressed *allocated* section
at all -- `.debug_*` sections are the common carrier and are not `SHF_ALLOC`, so
`_collect_string_bytes` skips them before `.data()` is reached regardless of this guard;
`.comment` is the one named unconditionally and is the plausible carrier if any is.

**The same class as Mach-O's caps.** "sizeofcmds and the symbol table are capped, not
just clamped to the member", below, bounds `sizeofcmds` and the symbol/string-table size
the same way -- a declared size checked against a fixed budget before the read it would
buy, not clamped to the member afterwards. The prefix-keeping half is the same choice
that entry draws for Mach-O's symbol table -- "a capped read is a truncated read, not a
refused one" -- applied here to `.rodata`/`.comment`/`.go.buildinfo` rather than to a
symbol table, which is exactly the boundary "What was rejected" above draws for why
`.dynsym`/`.dynstr` do not get the same treatment.

Revisit if a real wheel is found on the triage list for this and nothing else -- an
honest object this generous a budget turns incomplete would be the sign the budget
itself, not this check, is too tight for real wheels. Also revisit if a real
`.dynsym`/`.dynstr` is found on the triage list large enough that refusing it outright,
rather than capping it the way `binfmt.macho` caps its own symbol table, costs real
symbols a smaller, row-aware cap would have kept -- the open door "What was rejected"
above leaves for bringing Mach-O's shape to ELF's symbol table.

## sizeofcmds and the symbol table are capped, not just clamped to the member

**Accepted. The same kind of bound as the per-name symbol cap and the compressed-section
check, at the two places in `binfmt.macho` where a declared 32-bit size would otherwise
be measured only against the member rather than against a fixed budget.**

Reading `commands = stream.read(sizeofcmds)` straight from the header's own
`sizeofcmds` field, with only a short-read check after the fact, costs a 300 MiB member
declaring `sizeofcmds = 0xFFFFFFFF` a 300 MiB single read for a structure that is,
honestly, low tens of KiB. `_read_symbols`'s `nsyms` and `strsize` have the same shape
one level down: `_available` -- "measured against the bytes that exist," per `_Slice`'s
own docstring -- clamps a declared table size to the *slice*, which is exactly right for
a slice smaller than any fixed budget and does nothing at all for one larger. A streamed
member well past `wheelfile.ArchiveLimits.max_in_memory_bytes` is exactly that: with the
slice clamp alone, `nsyms = 0x0FFFFFFF` over a 300 MiB member costs 24.5s and 664 MiB
peak walking roughly twenty million 16-byte rows, each individually classified as
unresolved -- a wrong record (`partial_analysis: true`, `macho_symtab_incomplete`, the
same answer either way), paid for at full member cost.

**Measured, scaled down for a test suite that can afford to exercise the path without
the cap.** An object declaring `sizeofcmds = 0xFFFFFFFF` over an honestly-small header,
padded to 8 MiB, reads that whole 8 MiB in one `stream.read()` call without the cap
(measured with a `BytesIO` subclass that records its largest single `read()`) and never
at all with the cap and `max_strings_bytes` (64 KiB in the test) in place -- the
`sizeofcmds` read is never attempted once it is over cap. A lying `nsyms` over a 4 MiB
pad peaks at 4.19 MiB without the cap and under 1 MiB with it, in both cases well under
the wall-clock ceiling at this scale, which is why the memory ceiling is the assertion
that actually discriminates -- the same choice the other bounded-resource tests make,
for the same reason: 300 MiB's worth of wall-clock cost is real at the scale measured
above but does not reproduce as a reliable *test* signal at a size small enough to run
in a suite, while the byte count read does not need to be flaky to prove the point.

**Two caps, at the two places measured above.** `_MAX_SIZEOFCMDS` (1 MiB, `binfmt/
macho.py`) is checked in `_read_thin` before `stream.read(sizeofcmds)` runs at all --
real load commands are low tens of KiB even for the busiest fixture the dylib-loading
and load-command-walk tests build, a handful of dylib-loading commands at most, so a cap
two orders of magnitude above that is generous headroom, not a tight fit against anything
a real object does. Past it, `_read_thin` raises `_Unreadable` the same way a truncated
header or unparseable load commands do, and `_read_slice_header` catches and re-raises
it ahead of its generic "failed to parse mach-o load commands" clause, the same
special-casing `struct.error` gets, so the record keeps this cause's own message rather
than the catch-all one. No new `partial_reasons` token: for a thin object this is the
one slice that failed to parse, so `read_macho` falls into the `headers == []` path and
reports `macho_header_unread`, exactly the case that token names ("the Mach-O header ...
would not parse"); for one slice of a fat binary the object treats any per-slice
`_Unreadable` as `macho_fat_slice_unread` for that slice while the others still
contribute, and this cause is not special enough to want different treatment than a
slice whose magic nobody recognises gets.

The symbol-table half reuses `max_strings_bytes` itself rather than inventing a second
constant: threaded into `read_macho` for the strings pass, it is threaded two calls
further down into `_read_slice_symbols` and `_read_symbols` and taken as a second
ceiling on what `nsyms * entry_size` and `strsize` may ask `_available` for --
`sym_length = _available(sym_start, min(sym_wanted, max_strings_bytes), end)`, and
`strsize` the same way. `sym_wanted` and `symtab.strsize` themselves stay uncapped in
the `truncated` check below (`len(table) != sym_wanted or len(strings) !=
symtab.strsize`), so reading less than declared -- because the slice ran out or because
the budget did -- lands exactly where a genuinely short table does,
`macho_symtab_incomplete`, and the message it carries ("mach-o symbol table is
truncated") is honestly what happened either way. No new token, no new message, and no
new branch.

**ELF enforces the same parameter differently.** `binfmt.elf._symbol_bytes` threads the
identical `max_table_bytes` parameter for `.dynsym`/`.dynstr`, and an oversized table is
refused outright by `_bounded_section_data` ("A compressed section is checked before it
is inflated", above) rather than truncated byte-for-byte the way this reader's
`nsyms`/`strsize` cap is -- a different mechanism reaching the same guarantee: neither
format lets an unconditionally sized symbol table skip its budget.

**The walk is bounded per slice, not just the allocation per slice -- and that
qualifier is load-bearing, not decoration.** Reading the whole table and then deciding
it is too much would not bound the cost that matters most -- 24.5s of it is the
row-by-row walk, not the read. Because the cap is applied to `wanted` *before*
`_available` ever runs, `table` itself is never longer than `min(sym_wanted,
max_strings_bytes, available)`, so `_iter_symbols` -- the loop that classifies twenty
million rows in the reproduction above -- never sees more than the budget's worth of
them for *that slice* to begin with. There is no separate "read it all, then stop
walking partway" step to get wrong within one slice.

That bound does not extend to the object as a whole. `read_macho` calls
`_read_slice_symbols` once per slice, up to `_MAX_FAT_SLICES` (32), and nothing pools
a budget across them -- each slice independently gets up to `max_strings_bytes` worth
of symbol-table walk, so a crafted 32-slice universal binary, each slice lying about
`nsyms` the way the single-slice reproduction above does, still costs on the order of
`_MAX_FAT_SLICES * max_strings_bytes` of walking in total. Measured directly: a crafted
32-slice object costs roughly 49s with the per-slice cap in place against roughly 54s
without any cap at all -- the per-slice cap barely moves the total, because
`_MAX_FAT_SLICES` itself, not this cap, is what bounds slice *count*, and slice count
times a per-slice budget is still a real number. Memory does not have the same gap:
nothing keeps more than one slice's buffers alive at once, so peak memory stays flat
regardless of slice count, which is the half of "bounded, not just allocated" that does
hold end to end. Left open: pooling one `max_strings_bytes`-sized budget across every
slice of one object, rather than granting each slice its own, would close the CPU half
too, but changes the shape AGENTS.md gives fat-binary slices ("independent passes ...
over regions the slices are free to share") and is out of scope for the two reads
measured above.

**A capped read is a truncated read, not a refused one, and that is a deliberate
difference from the ELF compressed-section check.** `_bounded_section_data` refuses an
oversized compressed ELF section outright, `(b"", True)`, because `.data()` is an
all-or-nothing zlib call with no cheap way to keep a prefix. Mach-O's symbol and string
tables are read through plain byte-offset slicing, the same mechanism
`_available`/`_region` use for "the slice ran out," so capping `wanted` to the budget
costs nothing extra and keeps whatever prefix the budget affords, real evidence rather
than none: the honest symbol this entry's own test builds sits at the start of the
table, comfortably inside any budget worth using, and stays in `matched_symbols` after
the cap where a "refuse outright" approach would throw it away along with the twenty
million garbage rows. This is the same reading `AGENTS.md` gives "a structure that does
not parse costs that structure, never the evidence already gathered," applied one level
down: a table that reads over budget costs its own tail, not its own head.

**Interaction checked, not assumed.** The dylib-loading-command tests and the
load-command-walk tests build a handful of commands each, nowhere near
`_MAX_SIZEOFCMDS`, and read the same with the caps in place. Three boundary pairs pin all
three caps at their own edge, `nsyms` and `strsize` each isolated from the other by
keeping the sibling field honest and small: `sizeofcmds` exactly at `_MAX_SIZEOFCMDS`
reads its commands in full (`needed` and `soname` both survive, no error), one byte over
is refused before the read is attempted; an honestly-declared symbol table whose byte
count lands exactly on the budget reads complete, one real entry more is
`macho_symtab_incomplete` even though every byte of it is genuinely present in the
object; a string table declared exactly at the budget, over an honest and otherwise
tiny symbol table, reads complete the same way, one byte more is
`macho_symtab_incomplete` too -- the same "more than, not at least" boundary the ELF
check draws for the identical shape of check, drawn for all three.

**The `strsize` half of the cap has a test of its own, beside the `nsyms` boundary
test.** Changing only `str_length`'s `min(symtab.strsize, max_strings_bytes)` to plain
`symtab.strsize`, leaving `sym_length`'s cap and the `sizeofcmds` cap both untouched,
leaves a suite green whose `nsyms` boundary test only ever varies `nsyms`.
`test_strsize_exactly_at_the_budget_is_read_while_one_byte_over_is_incomplete`
(`tests/test_binfmt_macho.py`) and
`test_a_mach_o_string_table_declaring_more_than_the_budget_does_not_allocate`
(`tests/test_hardening.py`) pin that edge: reproduced directly, `strsize` declaring 2 MiB
over a 64 KiB budget peaks at 4.19 MiB without the cap against under 1 MiB with it, the
same shape and the same ceiling the `nsyms` hardening test uses, and both tests fail
cleanly, on the same assertions, with the cap removed.

**The `except _Unreadable: raise` routing clause is pinned by the message it keeps.**
Deleting it leaves `partial_reasons` and `error.kind` unchanged, because a generic
`except Exception` still produces `macho_header_unread` from the same `_unparsed` path.
What the clause actually buys is the recorded error *message* -- `"sizeofcmds is N bytes,
over the M-byte cap on load commands"` instead of the catch-all `"failed to parse mach-o
load commands"`. `test_sizeofcmds_exactly_at_the_cap_is_read_while_one_byte_over_is_refused`
pins the exact message text for the over-cap case, and fails with the clause removed.

**What was rejected.** A single shared constant for both caps: `sizeofcmds` and the
symbol/string tables are declared by different fields for different reasons, and
tying them to one number would make changing either bound to fit real load commands or
real symbol tables risk moving the other for no reason connected to it -- `_MAX_SIZEOFCMDS`
stays its own constant, sized off load commands; the symbol-table budget reuses
`max_strings_bytes`, the parameter this reader threads through for exactly this kind of
question, rather than adding a `_MAX_SYMTAB_BYTES` beside it that could only ever drift
from it. Refusing the whole symbol/string table outright once `nsyms`/`strsize` is over
budget, `_bounded_section_data`'s own shape: rejected above, for losing evidence a
bounded prefix read does not have to.

**What it costs.** A Mach-O object whose `sizeofcmds` or whose symbol/string table
declares more than these caps reads incomplete at the cap rather than after paying to
read the whole declared size, which for a real, honestly-small object changes nothing --
the caps sit two to three orders of magnitude above what the dylib-loading and
load-command-walk fixtures need. Nothing in `ruleset.toml` changes: both tokens this
reuses are policy already.

**`macho_header_unread`'s wording needs nothing new; `macho_symtab_incomplete`'s needs
one clause, and the reasoning for the two tokens does not carry over evenly.**
"Would not parse" covers a header refused for declaring more than this reader will read,
the same conclusion the ELF compressed-section entry draws for "refused before" and
"raised inside" being the same fact for a consumer. That reasoning does not carry over
to `macho_symtab_incomplete`: a wording listing only ways the *object* fell short
("declared entries this reader could not take at their word: unreachable, naming strings
it does not hold, holding nothing but debug records, or declaring fewer entries than the
string table holds names for") describes none of an honest, fully-present table the
*reader* chose to stop reading at its own budget. Read literally, such a sentence would
tell a consumer every occurrence of this token means the object lied, which is not true
once a cap can fire on an honest table. `SCHEMA.md` and `data/schema.json` (kept in step,
per `AGENTS.md`) both carry a clause covering the budget case, naming it as a
reader-side stop rather than an object-side fault.

**`wheelfile.ArchiveLimits`'s docstring names the whole bound, not just the streaming
half.** Streaming instead of holding a member whole is what bounds memory past
`max_in_memory_bytes` -- true of this module's own choice between `io.BytesIO` and
`SeekableZipMember`, but not the whole story: a reader built on top of a
correctly-streamed member can still pull most of it through the stream into its own
retained `bytes`, which defeats the point of streaming even though `WheelArchive`
itself never lies. The docstring says so explicitly, and points at
`binfmt.strings.MAX_STRINGS_BYTES` as the budget a reader is expected to hold itself to
on top of the streaming decision.

Both `binfmt.macho` and `binfmt.elf` hold to it. For `binfmt.elf`, the claim that
matters is not that "the ELF strings pass is bounded by `max_strings_bytes`" in
aggregate -- true of the *accumulated* buffer `_collect_string_bytes` builds across
sections only because `_bounded_section_data` bounds every section that feeds it --
but that any *single* section's read is bounded before it happens.
`_bounded_section_data` refuses before `.data()` runs for a `compressed` or
`SHT_NOBITS` section, and bounds a plain file-backed section too: an oversized `.rodata`
or `.comment` keeps its in-budget prefix (`strings_bytes_unread`, no error), while an
oversized `.dynsym`/`.dynstr` is refused outright (`elf_dynsym_unread`), because a
symbol table's count and a string table's contents cannot be trusted from a partial
read the way a strings-only section's prefix can. Nothing here needs the honest-ceiling
formula, `jobs * (max_member_bytes + max_strings_bytes)`, to fall back to a
whole-member worst case for either format: both bound the single-section read directly.

Revisit if a real Mach-O object is found on the triage list whose only incompleteness is
one of these two caps -- the same admission test `AGENTS.md` asks of the carve-out list,
applied here to a cap rather than an exemption: an honest object this generous a cap
turns incomplete would be the sign `_MAX_SIZEOFCMDS` or the symbol-table budget is
tighter than real Mach-O objects, not just tighter than an attacker's.

## A record produced without reading the wheel is never cached

**Accepted.**

`scan_wheel`'s outer `except Exception` -- the one AGENTS.md's "one bad wheel never
aborts a run" names outright -- catches everything `_collect` could raise. Recording it
under `errors.BAD_ZIP`, "Not a readable zip at all," would be a claim more specific than
the catch warrants: a `MemoryError` under load, or any other exception `_collect` does
not specifically anticipate, says nothing about whether the archive itself is readable.
Caching that record under the wheel's content hash unconditionally would make one
transient failure permanently `OPAQUE`: every later run, `--resume` included, would
serve the same stale record back and never call `_collect` again, even though the
condition that interrupted it is long gone. Reproduced directly against an unconditional
cache: `_collect` monkeypatched to raise `MemoryError` on exactly its first call,
`cli._scan_path` invoked twice against the same wheel and a fresh `RecordCache` -- the
second call returns the first call's cached line and `_collect` is never called again,
even though the second attempt would have read the wheel correctly and found its real
`hashlib.md5` call.

**How it is closed.** Two independent pieces, both small.

First, the outer `except Exception` records `errors.UNEXPECTED_ERROR`
(`"unexpected_error"`) rather than `errors.BAD_ZIP`. `BAD_ZIP` stays reserved for what
it specifically means: `WheelArchive.__init__` catching `zipfile.BadZipFile`, `OSError`
or `ValueError` while opening the archive, and `WheelArchive.read` catching the same trio
(plus `EOFError`) while reading a member -- both genuine, checked claims about the
archive's own bytes, and both routed through `errors.WheelReadError` rather than the
broad catch. `WHEEL_SCAN_INTERRUPTED`, a sibling of `WHEEL_UNREADABLE` in
`data/ruleset.toml` rather than an extension of it, claims `unexpected_error`: same
`OPAQUE` verdict, same `needs_human_review`, because absence of evidence is still not
evidence of absence regardless of why the evidence is absent -- but its own `why`, not
`WHEEL_UNREADABLE`'s "not a readable zip at all," which would be exactly the false claim
described above.

Second, `cli._scan_path` does not cache a record carrying one of a small set of kinds,
and `cli._existing_records` (what `--resume` reads back) drops one the same way rather
than treating it as done. Both consult one fact, `errors.SCAN_ABORTED_KINDS`, in the
shape AGENTS.md gives `FORMAT_*` and `PARTIAL_REASONS`; what to do about a kind in it
lives in `cli.py`, where the caching decision is made.

**Narrow versus broad, and why the deciding axis is determinism, not completion or
cost.** Two narrower options are on the table: skip caching only for
`UNEXPECTED_ERROR`, since that is the only kind that is plainly non-deterministic; or
skip it for both `BAD_ZIP` and `UNEXPECTED_ERROR`, since a genuinely malformed zip is
cheap to re-fail regardless -- nothing past `zipfile.ZipFile()` ever runs for either
kind, so there is no real scan to redo either way. Skipping the cache for every
archive-stage error would be broader than either and wrong for most of them:
`DUPLICATE_MEMBER`, `SIZE_LIMIT_EXCEEDED`, `COMPRESSION_RATIO_EXCEEDED` and
`MEMBER_READ_ERROR` are all recorded *alongside* a scan that otherwise ran to
completion, so skipping the cache for any of them throws away a real, expensive answer
-- but "recorded alongside a completed scan" and "safe to cache" are not the same
question. `DUPLICATE_MEMBER`, `SIZE_LIMIT_EXCEEDED` and `COMPRESSION_RATIO_EXCEEDED`
(and `BINARY_TOO_LARGE`, which never reaches this vocabulary from a
`MEMBER_READ_ERROR`-shaped path) are computed purely from zip metadata fully in hand --
a filename seen twice, a size field compared to a limit -- with no I/O and no broad
exception catch anywhere on the path that records them, so the same wheel's bytes
always produce the same one and caching is genuinely safe. `MEMBER_READ_ERROR` looks
like it belongs in that group because it is also member-scoped rather than
scan-aborting, but every site that records it (`wheelfile.read`, `layers/binaries.py`'s
two catches around `open_member` and `read_binary`, `layers/metadata.py`'s three,
`layers/python_ast.py`'s one) reaches it through a catch exactly as broad as the outer
one -- `except Exception`, or a name tuple wide enough to include `MemoryError` and
`OSError` alongside a genuinely corrupt member -- so it carries the identical risk
`BAD_ZIP` and `UNEXPECTED_ERROR` do: a transient failure permanently reads as a missing
finding for that one object, cached and served back forever. The axis that actually
decides whether caching a kind is safe is determinism, not "does the scan otherwise
complete" or "is re-deriving it cheap" -- those point the same way for the first three
kinds and not for this one. `SCAN_ABORTED_KINDS` holds `BAD_ZIP`, `UNEXPECTED_ERROR` and
`MEMBER_READ_ERROR` among the archive- and member-stage kinds: every one that cannot yet
be proven deterministic, not every kind that aborts a scan or every kind cheap to redo.
`test_a_completed_scan_with_a_recorded_archive_error_is_still_cached` pins the three
kinds that do stay cached, with a wheel carrying a genuine `duplicate_member` error
and a real Python finding still found in the cache after the run that produced it;
`test_a_transient_member_read_failure_is_retried_not_cached` pins
`MEMBER_READ_ERROR`'s transient case, `read_binary` monkeypatched to raise `MemoryError`
on exactly its first call against a wheel linking `libsodium.so.23` -- the first attempt
records `member_read_error` with `binaries: []` and comes out `OPAQUE`, the second is
not served from a cache entry the first attempt would otherwise have written, and finds
the real linkage.

**What was rejected.** Letting a `MemoryError`-class failure propagate out of
`scan_wheel` instead of being caught at all, so the run stops rather than mislabels.
Rejected on the grounds `scan_wheel`'s own docstring gives: a scan of tens of thousands
of wheels that aborts on the first `MemoryError` loses every wheel after it, which is a
worse outcome than one wheel temporarily `OPAQUE`. The `except Exception` stays; what
it records, and whether that record is trusted as final, is what this entry decides.

**Versions.** `errors[].kind` is an open string with no enumerated values in
`data/schema.json`, so `unexpected_error` needs no `schema_version` bump, the same
shape `SCHEMA.md` documents for `partial_reasons`. Membership of
`SCAN_ABORTED_KINDS` changes only whether a record already produced gets cached, not the
record `scan_wheel` produces, so it needs no `ANALYZER_VERSION` bump of its own -- unless
cache entries already exist under a narrower set, in which case widening the set needs a
bump to force re-evaluation of whatever the narrower set cached wrongly.

Revisit if a real corpus run turns up a wheel where `UNEXPECTED_ERROR` or
`MEMBER_READ_ERROR` fires repeatedly rather than transiently -- a deterministic bug
masquerading as a transient one would mean the cache is doing pointless work
re-attempting a wheel that will never read cleanly, which is the same admission test
AGENTS.md asks of the `partial_reasons` carve-out, applied here to a kind instead: go
and find a wheel this reads as "eventually fine" that never actually is. Also revisit
if `layers/binaries.py`, `layers/metadata.py` or `layers/python_ast.py` grows a
narrower catch that can tell a genuine content defect from a transient interruption
apart for `MEMBER_READ_ERROR` specifically, the way `_collect`'s own top-level catch
gives `UNEXPECTED_ERROR` rather than `BAD_ZIP` -- at that point the narrower kind, not
`MEMBER_READ_ERROR` itself, is what belongs in this set.

**binfmt's own parse-error kinds are never cached either.** **Accepted, on an audit of
every recording site in all three readers.** `binfmt/elf.py`, `binfmt/macho.py` and
`binfmt/pe.py` each catch broadly around their own parsing and record
`elf_parse_error`/`macho_parse_error`/`pe_parse_error`, one layer below where
`MEMBER_READ_ERROR` is produced -- the identical shape, over a materially larger surface
(many catch sites across three readers). An audit naming every site by hand, rather
than assuming every recording site is, or falls through to, a broad `except Exception`
with no genuinely narrow catch among them, finds a more mixed picture. `elf.py` has
nineteen sites that can record `elf_parse_error`, and thirteen of them are bare
`if`/`elif` comparisons over data fully in hand -- the same shape as the excluded
`DUPLICATE_MEMBER`/`SIZE_LIMIT_EXCEEDED`, not an `except` block at all. One of them,
"more than one `SHT_DYNSYM` section, which is real cannot be told", is a purely
structural check with no exception anywhere near it. `macho.py` has no recording site
lexically inside a handler at all; every `macho_parse_error` is emitted from a flag or
reason string a broad catch set earlier, which is still eventually traceable to a broad
catch, but not a narrowed, deterministic-only path. `pe.py`'s `except _Malformed` is a
real, narrow, deterministic-only catch: `_Malformed` is raised at exactly seven points
inside `_read_headers`, every one a pure comparison over `raw`, and grepping the whole
file confirms no exception is ever wrapped into it -- a `MemoryError` or a flaky read
cannot reach that branch. The *majority* of what records these three kinds is
deterministic, and one of the three readers has the "genuinely narrow,
exception-type-specific catch" the revisit clause above names.

None of that changes the conclusion, only its precision. Each reader also has at least
one real broad catch that can record the identical token for a transient reason
(`elf.py:592`/`:702`, `macho.py:454`/`:697`/`:752`, `pe.py:360`), and `ScanError.kind` is
the only granularity this vocabulary offers to tell a run's cause apart from another
run's: a kind reachable through a broad catch *anywhere* belongs in `SCAN_ABORTED_KINDS`
entirely, not the specific call that happened to raise on a given run, so all three are
in it -- deliberately accepting that the deterministic majority rides along uncached
too, which "What it costs" below says plainly.

**What this adds.** `errors.SCAN_ABORTED_KINDS` includes `ELF_PARSE_ERROR`,
`MACHO_PARSE_ERROR` and `PE_PARSE_ERROR`. `cli.py` needs nothing of its own for them:
`_scan_path` and `_existing_records` consult the set generically through
`_scan_was_aborted`, which is why three kinds cost three lines of vocabulary rather than
a second copy of the caching logic.

**Reproduction, adapted per format.** A single transient `MemoryError` inside
`elf.py`'s own `.dynamic` reading (patched onto `_validated_strtab`, which both the
`.dynamic` and `.dynsym` blocks call): the first attempt records `elf_parse_error`,
`needed: []` -- the `libsodium.so.23` dependency lost the same way the member-read case
above loses it -- and comes out `OPAQUE`; the second is not served from cache and
recovers `needed` and `libsodium_linkage: system`.
`test_a_transient_elf_parse_failure_is_retried_not_cached` pins it, plus
`test_resume_does_not_treat_an_aborted_elf_scan_as_already_done` for `--resume`. The
same shape holds for `macho.py` (`_read_thin` patched, an `LC_LOAD_DYLIB` dependency
lost then recovered: `test_a_transient_macho_parse_failure_is_retried_not_cached`) and
`pe.py` (`_read_imports` patched, an imported DLL lost then recovered:
`test_a_transient_pe_parse_failure_is_retried_not_cached`), all in `tests/test_cli.py`
beside the member-read and outer-catch tests.

**What it costs.** No version bump of either kind: this touches nothing in
`scan_wheel`'s own output for a given attempt, only whether a record already produced
gets cached or read back by `--resume`, and `BIN_UNPARSEABLE` matches these three kinds
in `data/ruleset.toml` as it is.

Two real costs are worth naming plainly. First: a permanently malformed object -- the
audit above shows this is the common case, not the rare one -- is re-read in full on
every scan, forever, rather than cached after the first failure. Measured on a real
~13 MiB object with two `SHT_DYNSYM` sections (a purely structural `elf.py` check, no
exception involved): 0.965s to fail once; a cached answer would cost 0.001s on every
later run, while re-reading it in full every time costs 0.974s -- roughly a thousand-fold
cost, paid every time, for a wheel whose bytes can only ever produce the same answer.
This is the opposite of why `bad_zip` is in this set: that kind aborts `_collect` before
any real read happens, so re-failing it is cheap; these three are recorded *after* the
strings pass (up to `MAX_STRINGS_BYTES`, 64 MiB per object) and the symbol-table walk
ran, so re-failing them is the most expensive thing this scanner does. It is also, for
the `elf.py:657` "declares more bytes than the budget allows" site specifically, the
identical shape `SIZE_LIMIT_EXCEEDED` is excluded from this set *for*, given the opposite
treatment. The trade is accepted anyway, on the principle this entry leads with: losing
real evidence to a stale cache costs more than an expensive, correct re-scan, and there
is no cheaper way to split a deterministic occurrence of one of these kinds from a
transient one without a narrower token than `ScanError.kind` carries -- but it is a
real, ongoing cost, not a free lunch.

Second, this is a prospective guarantee only. A cache entry already poisoned by a
transient failure is still served verbatim, because `cli._scan_path` returns a cache hit
before `_scan_was_aborted` is ever consulted, and membership of `SCAN_ABORTED_KINDS`
forces no re-evaluation of it. Anyone carrying such an entry stays stuck until they clear
their cache by hand or until an unrelated version bump forces re-evaluation for some
other reason. `MEMBER_READ_ERROR` has the same property and is accepted the same way;
stated here rather than left implicit.

**`PYTHON_SYNTAX_ERROR` is a different problem.** A `RecursionError` in
`layers/python_ast.py` shares the non-determinism risk -- the interpreter's stack depth
at scan time, not the wheel's bytes, decides whether it fires. But
`PYTHON_SYNTAX_ERROR` is also recorded for a null byte in the source and for a real
`SyntaxError` from `ast.parse`, both genuinely deterministic given the same bytes, so
that kind is mixed rather than uniformly one thing or the other the way
`elf_parse_error` and its siblings are. Excluding the whole kind from caching the way
the three `*_parse_error` kinds are excluded would mean re-scanning every source file
with an ordinary, permanent syntax error on every run, for no benefit; the token alone
cannot tell `RecursionError` apart from a real `SyntaxError`. A narrower token for the
`RecursionError` branches is what that needs, and is what "`RecursionError` has its own
kind, apart from `PYTHON_SYNTAX_ERROR`", below, gives it.

**Revisit if** `ScanError.kind` ever grows the ability to distinguish a deterministic
structural defect from a transient interruption within one of these three kinds --
`pe.py`'s narrow `except _Malformed` proves a genuinely deterministic-only catch can
exist for one shape of `pe_parse_error`, but the *token* it records is the same one a
broad catch elsewhere in `pe.py` can also produce, and that collapse, not the absence of
a narrow catch, is what keeps the whole kind in this set. Splitting the token itself --
a distinct kind for `_Malformed`'s deterministic shape, versus the broad-catch one --
would let the deterministic majority measured above be cached again without losing the
transient-safety this entry exists for; the same revisit clause above gives
`MEMBER_READ_ERROR`, applied here to three kinds instead of one.

### `RecursionError` has its own kind, apart from `PYTHON_SYNTAX_ERROR`

**Accepted.** `errors.PYTHON_RECURSION_LIMIT_EXCEEDED` is recorded by
`layers/python_ast.py`'s two `except RecursionError:` sites (`ast.parse` and the
`_collect_sites` tree walk) instead of `PYTHON_SYNTAX_ERROR`. The two sites share the
kind and the same message, since both are equally "not the wheel's bytes deciding this"
from a consumer's point of view. `PYTHON_SYNTAX_ERROR` keeps its two genuinely
deterministic occurrences -- the deliberate null-byte check and a real `SyntaxError`
from `ast.parse` -- and stays out of `SCAN_ABORTED_KINDS`, for the reason the entry
above gives. `PYTHON_RECURSION_LIMIT_EXCEEDED` is in `SCAN_ABORTED_KINDS`, on the
identical reasoning the entry above gives the three `*_parse_error` kinds: every site
that can record it is the same narrow catch, not a mix of deterministic and transient
causes the token cannot tell apart.

`data/ruleset.toml`'s `PY_UNREADABLE` rule (`error_kinds`) claims this kind alongside
the three others it claims, so the finding, verdict and severity are the same as for a
syntax error -- only the kind string and its caching behaviour differ.

Tests reproduce both sites via monkeypatching `ast.parse` and `_collect_sites`
directly, deliberately rather than via a deeply-nested source literal: which
construct actually exhausts the interpreter's C stack, as opposed to failing a
`SyntaxError` guard first (`"too many nested parentheses"` fires for 300-deep
parens/brackets on this interpreter, well before any `RecursionError` would), is
itself interpreter-version dependent, and the pin's whole point is to hold
regardless of that. A CLI-level test mirrors
`test_a_transient_elf_parse_failure_is_retried_not_cached`'s shape one layer up: a
first scan hits the monkeypatched `RecursionError`, and a second, unpatched attempt
is confirmed not to be served the first attempt's stale, evidence-free record.

## `.exe` is in `_BINARY_SUFFIX`, and `.com`, `.cpl` and `.sys` are not

**Accepted, the simpler of two ways to recognize `.exe`.**

`is_binary_member` accepts a member by suffix (`_BINARY_SUFFIX`), by vendor path, by
living in a sniff directory with no dot in its name, or by the executable bit with no
dot in its name. Without `exe` in `_BINARY_SUFFIX`, a `.exe` member fails every route:
the wrong suffix, and its own dot disqualifies it from both "no dot" fallbacks. It is
never even sniffed for magic bytes, so a Windows executable shipped in a wheel is
invisible to the scanner while the identical bytes, shipped suffix-less on the Linux
build of the same tool, are read correctly:

```
pkg-1.0.data/scripts/openssl       (win_amd64)  -> class=CONDITIONAL  openssl_linkage=static  extensions=1
pkg-1.0.data/scripts/openssl.exe   (win_amd64)  -> class=NO_CRYPTO_DETECTED  review=False  extensions=0
```

**How it is read.** `_BINARY_SUFFIX` includes `exe`, and nothing else in
`layers/binaries.py` treats it specially. `binfmt.pe` keys a PE read on the optional
header's magic, not on any DLL-versus-EXE distinction, so an `.exe` member is read by
the exact same code path a `.pyd` or `.dll` is; this is member classification, not a
reader of its own.
`tests/test_acceptance.py::test_the_exe_and_suffixless_forms_produce_the_same_record_but_for_the_path`
pins this directly: the same PE bytes at `pkg-1.0.data/scripts/openssl` and
`pkg-1.0.data/scripts/openssl.exe` produce the identical verdict, linkage and extension
count, differing only in the path each is shipped at.

**What was rejected.** Sniffing by magic for anything under a sniff directory
regardless of extension, which would also cover `.com`, `.cpl`, `.sys`-style oddities
and a dotted, suffix-less Mach-O tool name. That is a broader mechanism than the
concrete concern -- `cmake.exe`, `node.exe`, the Windows build of a tool wheel reading
differently from its Linux build -- which is a `.exe` problem, not evidence of wheels
shipping `.com`, `.cpl` or `.sys` members. Extending the suffix regex to those three as
well is rejected too, for the same reason inverted: adding a suffix to policy on the
strength of "it would also be covered by the alternative" rather than a measured, real
case is exactly the kind of unmeasured addition `AGENTS.md` asks every ruleset entry to
justify with a `why`, and there is no `why` here beyond "it exists as a Windows
extension." A member the scanner does not sniff by suffix stays invisible to the
scanner, which is no worse for being left out; the full magic-sniff option remains
available if a real wheel ever needs it.

**What it costs.** Every wheel carrying a `.exe` member produces a different record than
one read without it. The record shape is the same, only which members are read.

Revisit if a real `win_amd64` wheel is found shipping crypto-relevant evidence in a
`.com`, `.cpl` or `.sys` member, or in a dotted, suffix-less executable of another
format -- at that point sniffing by magic under a recognised directory regardless of
extension is the one to take, rather than growing `_BINARY_SUFFIX` one exotic extension
at a time.

## The loader lives in `ruleset_loader.py`, a sibling module, not a package

**Accepted, and it changes no record.** No rule, symbol, library or verdict depends on
which module parses the ruleset.

Held in one file, `ruleset.py` carries four responsibilities: the object model (`Rule`,
`Conventions`, `Ruleset` and the rest), the prefilter (`_symbol_locator`, next to
`SymbolGroup.matches` it mirrors, per `AGENTS.md`), the compiled-pattern builder
(`Ruleset.compile_patterns`, `BinaryPatterns`/`PythonPatterns`), and the TOML parser and
validator (`parse_ruleset`, `load_ruleset`, and everything only they call). Together
they reach pylint's default `max-module-lines` of 1000, and raising the limit papers
over four responsibilities sharing one file rather than reducing them.

**The split.** The parser -- `_parse_conventions`, `_parse_linkage_policy`,
`_parse_rule`, `_parse_matches`, every `_validate_*` and `_entry_*` helper,
`_check_limits_leave_room_for_every_key`, `parse_ruleset`, `load_ruleset`, and the two
generic helpers only they use (`_require`, `_check`) -- lives in `ruleset_loader.py`.
`ruleset.py` keeps the object model, the vocabulary constants (`MATCHER_KINDS`,
`SEVERITIES`, `ENTRY_TABLES`, `ROUTED_KINDS`, and the rest -- read by the loader's
`_check` calls and by the test suite that pins them, but describing the schema rather
than how to walk it, so they stay with the model they describe), and `_symbol_locator`
beside `SymbolGroup.matches`. Measured at the split, `ruleset.py` was 541 lines and
`ruleset_loader.py` 500, both well under the 1000-line default.

**Sibling module, not a `ruleset/` package.** Both are reasonable. `binfmt/` and
`layers/` are packages in this codebase because each holds several *parallel* things --
one reader per binary format, one extractor per evidence layer. This split isn't
parallel siblings, it's one concern (the ruleset) divided by responsibility (model vs.
parser), the same shape as `record.py`/`verdict.py` sitting as flat sibling modules. A
package would mean an equivalent two-file split one directory deeper for no structural
gain, so the sibling module matches the existing convention better.

**Re-exporting from `ruleset.py` is rejected, measured.** The obvious way to keep every
`from .ruleset import load_ruleset` working is to import `ruleset_loader`'s functions
back into `ruleset.py`: a bottom-of-file `from .ruleset_loader import load_ruleset as
load_ruleset` (the self-alias PEP 484 uses for explicit re-exports), needed at the
bottom rather than the top because `ruleset_loader` needs the object model above it to
exist first. It parses, runs, and produces byte-identical output -- `tox` is fully
green under it -- but `pylint` correctly calls it what it is:
`wheel_crypto_scan.ruleset` and `wheel_crypto_scan.ruleset_loader` import each other, a
genuine cycle (`cyclic-import`), on top of a `wrong-import-position` and a
`useless-import-alias` the self-alias idiom needs at every call site to silence.
Suppressing four separate, stacked warnings to keep one import direction working is
worse than the thing it avoids: touching call sites. The loader depending on the model
it validates against is the natural direction; asking the model to import back from its
own validator is what manufactures the cycle, not the split itself.

**What it costs.** Every import of `load_ruleset`, `parse_ruleset` or
`routine_reasons` is `from .ruleset_loader import ...` (or
`wheel_crypto_scan.ruleset_loader` in tests), including in modules that also import an
object-model name, which then need two import lines rather than one. Everything that
imports only object-model names -- `Ruleset`, `BinaryPatterns`, `StringGroup`,
`Limits`, the vocabulary constants -- imports them from `ruleset`. `Conventions` and
`SonameInfo` moved again, into their own module; see "`Conventions`/`SonameInfo` and
their `[conventions]` parser move to `conventions.py`" below for where and why.

**What was rejected.** Raising `max-module-lines`, the option this entry argues against:
the file would be fragile to the next three-line addition, not short on numeric slack.
The `ruleset/` package layout, for the reason above. Re-export via the
bottom-import/self-alias trick, for the cyclic-import reason above. Pulling
`Conventions`/`SonameInfo` (~115 lines) into their own `conventions.py` at the same
time: measured at this split, `ruleset.py` was already well under the limit on its
own, so a further split neither the model nor the loader asked for yet would have been
moving code to move it rather than fixing a real fragility.

**Revisit if** a third responsibility crowds either file for no structural reason of
its own -- the same shape `Conventions`/`SonameInfo` and their parser were in below,
once `ruleset_loader.py` reached the limit this split was measured against.

## `Conventions`/`SonameInfo` and their `[conventions]` parser move to `conventions.py`

**Accepted, and it changes no record.** No rule, symbol, library or verdict depends on
which module defines or parses `Conventions`.

`ruleset_loader.py` reached pylint's default `max-module-lines` (1000) as SBOM
name-folding and the cargo-purl reorder it backs were added to a loader that already
carried the ruleset shape checks, the linkage-policy coherence check and every other
`_parse_*`/`_validate_*` helper -- the trigger the entry above names for its own
"Revisit if". `Conventions` and `SonameInfo`, the object model, lived in `ruleset.py`;
`_parse_conventions` and the key set it checks against, the parser, lived in
`ruleset_loader.py`. Both move together into a new sibling module, `conventions.py`,
and the parser drops its leading underscore to become the public `parse_conventions`:
`ruleset_loader.parse_ruleset` now calls it across the module boundary the underscore
marks private, and `parse_conventions` builds nothing but a `Conventions`, and nothing
outside these two pieces reads the moved key set, so the model and the one function
that builds it are one self-contained concern, not two files sharing a name by
coincidence.

**Why the parser has to move too.** Moving only `Conventions`/`SonameInfo` out of
`ruleset.py` would shrink the file that was not the one over the limit.
`ruleset_loader.py` is the one that reached 1000, and `_parse_conventions` -- regex
compilation, the group checks, the Windows-suffix-subset check -- is the piece of it
large enough to matter; leaving the parser behind and moving only the dataclasses would
fix a limit nothing there had broken.

**`_require`/`_refuse_unknown_keys` are duplicated, not imported.** `conventions.py`
restates these two small checks rather than importing them from `ruleset_loader`,
because `ruleset_loader.parse_ruleset` needs `Conventions` and `parse_conventions` from
`conventions.py` to build a `Ruleset`. Importing the other way too would make the two
modules import each other, the same cyclic import the entry above already rejected
paying for once to keep `load_ruleset` re-exported from `ruleset.py`.

**What it costs.** Every import of `Conventions` or `SonameInfo` -- `ruleset.py`'s own
`Ruleset.conventions` field, `linkage.py`, `layers/binaries.py` -- comes from
`conventions`, not `ruleset`, so a module that also imports an object-model name needs
two import lines instead of one, the same cost the loader/model split above already
pays. `ruleset_loader.py` imports only `parse_conventions`, never `Conventions`
itself: it builds a `Ruleset` from what the parser returns and never names the class.

**What was rejected.** A module-local `too-many-lines` exemption for
`ruleset_loader.py`, matching `binfmt/elf.py` and `binfmt/macho.py` below: those two
carry the disable because about half of each is docstring, and splitting either would
move prose rather than reduce a responsibility. `ruleset_loader.py`'s growth here is
validation code, not documentation, so that reasoning does not carry over, and this
module already names the alternative to take instead of the exemption those two use. A
bigger `max-module-lines` for the same reason the entry below rejects one: it would
hand every other module the same headroom, earned or not.

**Revisit if** `ruleset.py` or `ruleset_loader.py` approaches the limit again on its
own -- at that point the next responsibility crowding either file for no structural
reason of its own is the next one to look for splitting out, not a bigger
`max-module-lines`.

## `binfmt/elf.py` and `binfmt/macho.py` carry module-local line-count exemptions

**Accepted.** Each of `binfmt/elf.py` and `binfmt/macho.py` carries its own
`# pylint: disable=too-many-lines`, with a justification comment beside it, and the
project-wide `max-module-lines` in `pyproject.toml` stays at pylint's own default
(1000).

**The list.**

- `binfmt/macho.py`: its docstring names every way `partial_analysis` can survive, and
  every load-command shape it flags adds a paragraph.
- `binfmt/elf.py`: it documents every way an attacker-controlled label can win a
  lookup, and every cross-check that closes one.

**Why not split.** Measured, about half of each module is docstring and comment; the
code alone is under 600 lines in each. The excess is the documentation AGENTS.md's
"every policy entry carries a why" rule asks for, not unchecked growth, and splitting
either module would move prose between files rather than reduce what either one is
responsible for. Contrast this with "The loader lives in `ruleset_loader.py`, a sibling
module, not a package", where four responsibilities shared one file and the split was
right.

**Why not a global bump.** Raising the project-wide limit instead would silently give
every OTHER module in the project the same extra headroom, whether or not it has earned
it. `binfmt/pe.py`, and every other module, stays under the limit without a disable.

**What holds it.** `tests/test_design_notes.py` fails if a module carries the disable
without being on this list, if a listed module drops the disable, if this entry's list
and `_LINE_LIMIT_EXEMPT` name different modules in either direction, if
`pyproject.toml` sets `max-module-lines` in any `[tool.pylint.*]` table, or if
`too-many-lines`/`C0302` is added to any table's `disable` list.

**Revisit if**:

- a third module needs the exemption, at which point the trade a global bump makes is
  worth re-measuring; or
- a listed module's code alone, excluding docstrings and comments, nears the limit, at
  which point it is a split rather than an exemption.

## The cross-rule coherence checks live in `ruleset_coherence.py`

**Accepted, and it changes no record.** No rule, symbol, library or verdict depends on
which module refuses an incoherent ruleset.

Held beside the shape checks, the unknown-key checks and every other
`_parse_*`/`_validate_*` helper, these four checks bring `ruleset_loader.py` to pylint's
default `max-module-lines` (1000) with no room for the next check -- the trigger
"`Conventions`/`SonameInfo` and their `[conventions]` parser move to `conventions.py`"
names for its own "Revisit if". They live in a sibling module, `ruleset_coherence.py`,
public for the same reason `parse_conventions` is, since `parse_ruleset` calls them
across the module boundary: `check_suppression_can_fire`, `check_suppression_acyclic`,
`validate_sbom_component_coverage` and
`validate_sbom_suppression_leaves_linkage_explained`.

**Why these four.** Each refuses a relation *between* rules that no single rule's parse
can see: a `suppressed_by` that can never fire or closes a cycle, or an SBOM relation
that would leave a `<name>_linkage` moved with no finding to explain it. Each reads
`Rule`/`Ruleset` objects the loader has already built, shape-checked and
reference-resolved, and relies on that last part: every `suppressed_by` and every crate
owner names a rule that exists, so a lookup that would otherwise raise `KeyError` never
does. None reads the raw TOML or calls a loader helper, so the module imports only the
object model and `RulesetError`. The loader imports it and never the reverse, the same
direction `conventions.py` keeps, so the two cannot import each other.

**What stays in the loader.** Every check that walks a raw table --
`_validate_match_references`, `_validate_conventions_references`, the unknown-key
checks, `_parse_linkage_policy`'s coherence check -- because each reads the TOML
mapping through the helpers that read it. `_check_limits_leave_room_for_every_key`
stays too, though it reads only built objects: it bounds `[limits]` against how many
groups and crates the tables hold, a relation between a table and its sizes rather than
between rules. Measured at the split, `ruleset_loader.py` was 856 lines and
`ruleset_coherence.py` 171.

**What was rejected.** A module-local `too-many-lines` exemption for
`ruleset_loader.py`, and a bigger `max-module-lines`, for the reasons the two entries
above give. Moving the raw-table checks as well: each would need the loader's helpers
restated or imported, and restating them is a cost `conventions.py` already pays once,
for `_require` and `_refuse_unknown_keys`, for lines the loader does not need back.

**Revisit if** `ruleset_loader.py` approaches the limit again: the per-table loops
inline in `parse_ruleset`, one per `[[crypto_library]]`, `[[rust_crate]]`,
`[[symbol_group]]` and the rest, are where most new checks land and the next concern
that could stand alone.

## More than one LC_ID_DYLIB or LC_SYMTAB is ambiguous, not last-wins

**Accepted. The Mach-O counterpart of ELF's `elf_section_type_ambiguous`, and it
changes records.**

Setting `soname = name` on every `LC_ID_DYLIB` the load-command walk reaches, and
building a fresh `_Symtab` on every `LC_SYMTAB`, both unconditionally, lets a second
command of either kind silently overwrite the first, with nothing counting how many were
seen. `linkage._binary_posture` reads `soname` first, through `conventions.own_base`, to
decide whether the object itself *is* a named library -- the `vendored_path and
own_base(...) in sonames` check that fires before `needed` is even consulted -- so a
decoy `LC_ID_DYLIB` is load-bearing for the verdict, not cosmetic, and a decoy
`LC_SYMTAB` is load-bearing for the imported/defined split the whole tool turns on.

Reproduced on a wheel bundling `libcrypto` under a neutral member name, with the
install name as the only signal tying the object to that identity and a second, decoy
`LC_ID_DYLIB` appended, read last-wins:

```
honest LC_ID_DYLIB, single             -> openssl_linkage: bundled, needs_human_review: true
honest LC_ID_DYLIB + decoy appended    -> openssl_linkage: none,    needs_human_review: false
```

The decoy is not merely ignored -- `own_base` reads whichever name the walk reached
last, so the record actively misreports the object's own identity, and the wheel's
`openssl_linkage` is left with nothing to say the object had told us anything
questionable at all: `partial_analysis: false`, `errors: []`. It is the same shape as a
section lookup that picks the first match, reached through `LC_ID_DYLIB` instead of a
section header.

**Detect ambiguity, trust neither candidate, cost the answer -- the same treatment ELF's
type-based section lookup gives two sections of one type.** `_read_thin` counts how many
`LC_ID_DYLIB` and how many `LC_SYMTAB` commands the walk actually reaches, regardless of
whether each one's own body could otherwise be read. More than one of either resets the
corresponding field to `None` after the walk finishes -- `soname`, or the `_Symtab` the
walk had been building -- rather than leaving whichever one was assigned last. `soname`
and the symbol table then read as though this slice itself never declared one:
`own_base` falls back to the member's file name the same way it does for an object that
never declared `LC_ID_DYLIB` at all, and `_read_slice_symbols` takes an absent `_Symtab`
down the same path a genuinely stripped object takes, `stripped` included. That "read as
absent, not as the decoy" rule is ELF's, applied here to load commands instead of section
headers. It is a per-slice fact, not necessarily the record's final answer: `read_macho`
backfills `soname` from a later, unambiguous fat-binary slice when one exists (see "A
genuine residual" below), so a nulled `soname` here can still surface a real name once
the slices are merged.

**One token, not two.** `elf_section_type_ambiguous` covers three ELF section kinds
(`SHT_DYNAMIC`, `SHT_DYNSYM`, `SHT_SYMTAB`) under one token, because the failure is the
same shape regardless of which kind of section it lands on: more than one candidate of a
kind the reader looks for, and no way to tell them apart from the kind alone.
`LC_ID_DYLIB` and `LC_SYMTAB` are the identical shape one level up -- load commands
instead of sections -- so `macho_load_command_ambiguous` covers both fields rather than
minting `macho_id_dylib_ambiguous` and `macho_symtab_ambiguous` separately. Checked
against the load-command string, walk and header-size tokens first, per `AGENTS.md`'s
"don't duplicate an existing cause": none of them is this. `macho_symtab_incomplete`
comes closest, but its own entry ("A symbol table is checked against the string table,
not taken at its word") is about a table this reader reached and could not take at its
word for well-defined reasons -- unreachable, holding nothing but debug records,
understating its own rows. Ambiguity is a different fact: the table's own contents are
never even in question, because there is no way to tell which of two candidates is the
real table before either is read. Folding it into `macho_symtab_incomplete` would ask
one token to mean two different things a consumer might want to tell apart, the same
reasoning that keeps `elf_section_type_ambiguous` off `elf_dynsym_unread`.

**Interaction, checked rather than assumed.** An ambiguous `LC_SYMTAB` also costs
`macho_symtab_incomplete`, because the discarded table is handed to
`_read_slice_symbols` as `header.symtab is None`, the identical shape an absent
`LC_SYMTAB` takes -- silently, no second error, since that token's own silent case is
exactly "nothing about this table was left unexplained beyond its absence." The two
tokens naming the same object is not a contradiction: `macho_load_command_ambiguous`
names *why* the table is gone, `macho_symtab_incomplete` names *what* is missing, the
same division `symtab_understates_rows` draws beside a format-specific cause. An
ambiguous `LC_ID_DYLIB` costs nothing extra of the kind: `soname` has no sibling token
the way the symbol table does.

Checked against the walk-truncation shape directly: an ambiguous `LC_ID_DYLIB` combined
with a later `cmdsize` that truncates the walk records both
`macho_load_command_ambiguous` and `macho_load_command_walk_truncated` together, neither
one swallowing the other, and evidence read *before* the poison command -- including the
first `LC_ID_DYLIB`, before ambiguity was even known -- survives exactly the way the walk
truncation guarantees.

**It costs the linkage answer, on purpose.** `macho_load_command_ambiguous` is not on
`[linkage_policy] exclude_reasons`, the same call as for `elf_section_type_ambiguous`
and for the same reason: `soname` and the imported/defined split are both fields
`linkage` reads, and an ambiguous object has answered neither -- it is "we could not
tell", not "there is nothing here." Excluding it would read `openssl_linkage: none` off
an object that told us nothing, the exact failure this entry exists to prevent. The
default `partial_binary` rule (`BIN_PARTIAL_FORMAT`) claims it automatically, the same
way it claims every cause not named in its own `exclude_reasons = ["pe_ordinal_import"]`:
neither list names it.

**What was rejected.** A separate token per field (`macho_id_dylib_ambiguous` and
`macho_symtab_ambiguous`), covered above. Folding the `LC_SYMTAB` half into
`macho_symtab_incomplete`, covered above. Resyncing past a decoy by trusting whichever
`LC_ID_DYLIB` or `LC_SYMTAB` sorts *first* rather than last: that is still picking one of
two untrusted candidates, the identical hazard ELF's ambiguity check refuses for a decoy
sitting ahead of the real section there too.

**What it costs.** An object carrying more than one `LC_ID_DYLIB` or more than one
`LC_SYMTAB` reads `partial_analysis: true` with `soname` and/or the symbol split
unresolved, rather than silently reporting whichever candidate the walk reached last.
The two ambiguity flags are named fields on `_ThinHeader` (see "Every dylib-loading
command reaches `needed`", above, on why that is a named record), and the cause is one
more paragraph in `binfmt/macho.py`'s docstring (see "`binfmt/elf.py` and
`binfmt/macho.py` carry module-local line-count exemptions", above).

**Two more shapes, beyond the reproduction above, the check must reject the same way.**
A third `LC_ID_DYLIB` is still ambiguous -- the check counts occurrences rather than
comparing exactly two values, so it needs no third arm. Both orderings of a decoy
`LC_SYMTAB` are checked: after the real one, the shape that actually demonstrates a
last-wins reader's failure (it keeps the decoy's garbage offsets over the real table),
and before it, the shape a last-wins reader would get right by accident and that a
first-wins-style check would still get wrong -- both are refused identically, because
counting occurrences does not care which one the walk reached last.

**A genuine residual, adjacent to this check and not closed here.** This check is about
ambiguity *within* one thin header's own load-command walk. It says nothing about two
slices of a fat binary that each carry exactly one, internally unambiguous
`LC_ID_DYLIB`, but *disagree with each other*: `read_macho` merges `soname` by "the first
one any slice declared" (documented in this module's own docstring and in "A universal
binary is one record, and its slices are merged", above), so a universal2 object whose
x86_64 slice honestly declares `libcrypto.3.dylib` and whose arm64 slice honestly
declares something else still reads `soname: "libcrypto.3.dylib"`,
`partial_analysis: false`, with nothing in the record to say the two slices disagreed.
Reproduced directly: a two-slice fat object built exactly this way returns
`soname == "libcrypto.3.dylib"` and `partial_analysis is False` end to end through
`read_macho`. This is not the shape this entry covers -- neither slice's own walk is
ambiguous, so `macho_load_command_ambiguous` correctly does not fire for either -- and it
is the same "first one any slice declared" rule the universal-binary entry documents and
accepts for `soname`, reached here by a concrete counterexample. Left open rather than
folded in, for the same reason that entry gives for not tracking which architecture said
what: closing it needs `soname` to become a per-slice fact the merge can compare, which
is a real, if smaller, instance of the same three-or-more-architectures gap that entry
tracks.

Revisit if a real wheel is found whose fat slices honestly disagree about
`LC_ID_DYLIB` -- the shape above is synthetic, and no disagreement of any kind has been
found in a real universal2 wheel.

### The error message names which command was ambiguous; the token does not

**Accepted. Diagnostic text only -- it does not reopen "one token, not two" above.**

"What was rejected" above covers merging `macho_id_dylib_ambiguous` and
`macho_symtab_ambiguous` into one `partial_reasons` token,
`PARTIAL_MACHO_LOAD_COMMAND_AMBIGUOUS`, and that call stands: `partial_analysis` and the
verdict are correct either way, and a second token would ask a consumer filtering on
`partial_reasons` to know Mach-O internals `elf_section_type_ambiguous`'s ELF counterpart
never asks of them. This is one level down, in `errors[].message`: `_read_thin` counts
`id_dylib_seen` and `symtab_seen` separately, and collapsing both into one boolean
before `read_macho`'s error-emitting loop sees them would make the merged message ("more
than one LC_ID_DYLIB or LC_SYMTAB command...") throw away a fact the reader has --
`binfmt/elf.py`'s `elf_section_type_ambiguous` emits a distinct message per section
kind from the equivalent counts, and Mach-O's diagnostic precision matches it.

The two counts are two booleans, `id_dylib_ambiguous` and `symtab_ambiguous`, threaded
through `_ThinHeader`/`_SliceHeader`/`_SliceEvidence`, and `read_macho` emits up to two
error records when both are true, each naming its own command.
`partial.add(evidence.PARTIAL_MACHO_LOAD_COMMAND_AMBIGUOUS)` fires from
`id_dylib_ambiguous or symtab_ambiguous` -- one token, backed by two possible error
messages, the same relationship `macho_load_command_ambiguous` and
`macho_symtab_incomplete` have to each other, described above under "Interaction,
checked rather than assumed."

The message text is part of the record, so it differs for an ambiguous object even
though `partial_reasons`, `partial_analysis` and the verdict do not. Tests cover each
command ambiguous alone (confirming the other command's name never appears in its
message) and both ambiguous on the same object at once (confirming two distinct
messages, not one, and that the `partial_reasons` token still fires exactly once
regardless).

## A `[[string_group]]` substring must be printable ASCII

**Accepted.**

Two performance properties of `binfmt/strings.py`, both byte-identical to the plain
implementation by measurement, not by argument. `sanitize` is a compiled regex over the
complement of `PRINTABLE` (`_NON_PRINTABLE_RE`, quantified), 13x faster than a
per-character generator on typical symbol names and 28x on one long ASCII name, checked
against the generator over 400 random cases spanning the full `str` code-point range
including surrogates and the astral plane. `match_string_groups` tracks the previously
claimed run's end per group and skips a hit that falls inside it, rather than re-slicing
a hit's whole enclosing run every time its group matches inside it -- which a crafted
object can make quadratic: one continuous run with "OpenSSL 3." repeated every 10 bytes
measures 0.29s at 4 MiB with re-slicing, scaling with the square of run length. Neither
changes a record.

**The skip must not assume a pattern can never match across a run boundary.**
Skipping a hit inside a previously claimed run assumes a `[[string_group]]` pattern can
never match text spanning the `"\n"` `extract_printable` joins runs with -- true because
every shipped substring is printable ASCII and `RUN_SEPARATOR` is not, but only if
enforced. A ruleset is user-supplied (`--ruleset`), and a substring built to span that
separator on purpose (reachable only through an escaped literal containing a literal
`"\n"`, since the loader builds every pattern via `re.escape`) makes the skip drop a
real match: `text = "Xb\nab\naY"` with substring `"b\na"` returns one hit instead of
two, silently losing the second run's evidence. Fuzzed at 20,000 trials with substrings
allowed to contain non-printable characters against a naive re-slicing reference
implementation: 1,189 diverged.

**What was rejected.** Making the skip unconditional on the match's own content
(`m.end() <= claimed_run_end`, dropping the `\n`-crossing assumption entirely) does not
work: once a match has spanned a separator, the claimed run is not newline-free, so a
later hit's boundaries would resolve against the wrong `"\n"`. The assumption has to
hold, not be routed around.

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

**Where the shared constant lives.** `PRINTABLE` lives in `evidence.py`, beside
`PARTIAL_REASONS` and the other extractor vocabularies, not in `binfmt/strings.py`. The
guard needs it in `ruleset_loader.py`, and importing it from `binfmt.strings` would make
the loader execute `binfmt/__init__.py` -- every reader, `pyelftools` included -- to
reach one `range`. `evidence.py` is the leaf module every vocabulary like this lives in;
`ruleset_loader.py` imports only leaf modules, the way it does for `PARTIAL_REASONS`,
and a loader-depends-on-binfmt edge stays closed, the same edge "The loader lives in
`ruleset_loader.py`, a sibling module, not a package" (above) refuses from the other
direction.

## `py_call`/`py_attr`/`py_constant` match fields are validated, and their subject fields made required

**Accepted. It prevents a crash, not just a silent-match-nothing gap.**

`_validate_match_references` checks match fields for every matcher kind, including the
three that read Python-source evidence: `py_call`, `py_attr` and `py_constant`. Without
those arms, two failure modes exist for all three: a typo'd or wrongly-shaped field
loads clean and either matches nothing a rule author expected (the ordinary case every
other kind is guarded against), or, for `py_call`'s `usedforsecurity` specifically,
crashes the scan outright. `_match_py_call` does `attrs.get("usedforsecurity") not in
want_used`; a bare TOML boolean (`usedforsecurity = true`) parses to a Python `bool`,
and `x not in True` raises `TypeError: argument of type 'bool' is not a container or
iterable` mid-scan, aborting the whole CLI run with no output file for what should
have been a rule that simply doesn't match. The identical shape crashes
`frozenset(match.get("targets", ()))` in the same function, and
`Ruleset.compile_patterns` reads `targets`/`attributes`/`constants` off *every* match
table regardless of kind, so the same crash is reachable through a stray key on an
unrelated rule, such as `targets = true` on a `dist_name` match.

**What `ruleset_loader.py` checks.** `usedforsecurity` (scalar or list) is checked
against the closed set `evidence.USED_FOR_SECURITY_VALUES` -- the only four values
`layers.python_ast._hashlib_usedforsecurity` can ever produce. `targets`, `attributes`,
`constants` and `values` are shape-checked (a list of strings, never a bool/dict/bare
string) wherever any match table carries one of them, via
`ruleset.GENERIC_MATCH_SEQUENCE_KEYS`, the same tuple `compile_patterns` iterates to
build `py_call_targets`/`py_attributes`/`py_constants` -- one definition read by both,
rather than the check silently drifting from what it protects if `compile_patterns`
ever grows a fourth generic key. `targets`, `attributes` and `constants` are each
required for their own kind rather than optional with an empty-tuple default: a
`py_call` rule with no `targets` can never match anything, `_target_matches` has no
wildcard that reaches an empty set, so an omitted field is a dead rule, never a
legitimate "match every call site" shape. Every shipped rule of these three kinds
carries its subject field; the requirement constrains only what a malformed custom
ruleset is allowed to load as.

**Why `algorithm` is checked for type only, never against a closed vocabulary.**
Unlike `usedforsecurity`, `algorithm` is open-ended: `_hashlib_algorithm` returns
whatever string literal a wheel's source passes to `hashlib.new(...)`, lowercased,
which could be any hash name that exists or will ever exist. Checking it against
`ruleset.conventions.weak_hash_algorithms` would refuse a rule intentionally naming a
*strong* algorithm -- a real, existing shape: the shipped `PY_WEAK_HASH_UNRESOLVED`
rule's own `algorithm = "unresolved"` match is not a member of that set either. Only
`isinstance(algorithm, str)` is checked.

**The `usedforsecurity` vocabulary guards its own drift risk.** `USED_FOR_SECURITY_VALUES`
in `evidence.py` names each of the four values individually
(`USED_FOR_SECURITY_ABSENT`/`_TRUE`/`_FALSE`/`_UNRESOLVED`, the same shape
`PARTIAL_REASONS` names each of its own members), and `_hashlib_usedforsecurity`
returns those constants instead of re-spelling the strings, so the constant has one
consumer and one source of truth: a fifth value added to `_hashlib_usedforsecurity`
without a matching addition to the frozenset would make the loader wrongly refuse a
rule that should match. A test in `tests/test_python_ast.py` pins that the four shapes
it can produce are exactly `USED_FOR_SECURITY_VALUES`, no more and no fewer --
mutation-confirmed to fail when one return value is changed without updating the set.

## Every table the loader reads is closed over its keys

**Accepted.** `ruleset.MATCH_KEYS` lists,
per matcher kind, the keys that kind's `[rule.match]` table may carry -- `kind` itself,
plus `table`/`default` where the loader and `Ruleset.default_rule_for_table` read them.
`ruleset_loader._refuse_unknown_keys` is the one mechanism, called against `MATCH_KEYS`
for a match table and against its own allowed-key constant for every other table this
file reads: `[[rule]]`, every entry table, `[verdict]`, `[limits]`, `[conventions]`,
`[linkage_policy]` and the top level. A typo'd or misplaced key -- `supressed_by` on a
rule, `verdit` on a library entry, `exclude_object_valu` on a `linkage` match -- loads
clean and does nothing without this; refusing it at load time is what keeps the ruleset
the ground truth for what a rule can express, rather than a superset of it a reader has
to notice went unread. Two calls follow from the field-by-field shape checks above
rather than from the key check itself: `default` is accepted wherever `table` is, so the
specific "never falls back" and "cannot be the default" messages `parse_ruleset` already
raises stay reachable, and `sbom_component` refuses the singular `table` rather than
honouring it, since `_match_sbom_component` only ever reads the plural `tables` --
letting the singular key through would give the coverage check two spellings of the same
requirement to union.

An AST test in `tests/test_ruleset.py` walks `engine.py`'s matcher functions and pins
`MATCH_KEYS` against what they actually read, both ways: a key a matcher reads that its
kind's entry does not list, and a key an entry lists that no matcher ever reads for that
kind (`table`/`default`, validated by the loader rather than the matcher itself, are the
exception). Adding a key one matcher reads without updating `MATCH_KEYS` fails the first
direction; allowing a key nothing reads fails the second -- a hole the key check exists
to close reopening itself through the one table meant to prevent it.

## `binfmt.ar` reads `.a`/`.lib` static archives as a container, not a reader

**Accepted. An evidence source of its own, not a new format for the record's `format`
field.**

`.lib`/`.a` static archives -- the `ar` container format that bundles multiple `.o`/
`.obj` relocatable objects for downstream linking -- match no route into
`layers.binaries.is_binary_member` on suffix alone other than their own: not a vendor
path, a sniff directory or an executable bit. Without `.a`/`.lib` among the suffixes, a
wheel shipping a vendored `libcrypto.a` for downstream linking, or a `.lib` import
library, is invisible to the scanner on any platform, with nothing in the record to say
so -- not `OPAQUE`, not a missing-evidence note, simply absent, because the member is
never opened in the first place.

**Why this is not one more entry in `binfmt._READERS`.** Every other reader answers
to `read_binary`'s contract: one stream in, one `BinaryEvidence` out. An archive holds
many separate, independently-linkable objects, and a consumer wants them told apart --
which member defines a crypto symbol matters as much as whether one does. Merging them
into one record would mean inventing an aggregation `read_binary` is not asked to do,
for a container that is not a "binary object" in the sense every other format here is.
`binfmt.ar.read_ar_members` is instead called directly by
`layers.binaries.scan_binaries`, in place of `read_binary`, once the member's own magic
(sniffed after opening, not trusted from the `.a`/`.lib` suffix alone) confirms it is
really `ar`-format -- an older MSVC `.lib` or a suffix collision falls through to the
same strings-only fallback any other unrecognised format gets. `binfmt.ar` is therefore
a sibling module to `elf.py`/`macho.py`/`pe.py`, not a fourth entry in the reader
table, and imports `read_binary` from `binfmt/__init__.py` to dispatch each real member
to the same per-format readers everything else in the wheel goes through --
`layers.binaries` imports both directly rather than routing the container through
`binfmt/__init__.py`'s own dispatch. That split is a chosen direction, not a structural
necessity: nothing stops `binfmt/__init__.py` from importing `ar.py` and re-exporting
`read_ar_members` except that `ar.py` imports `read_binary` from `binfmt/__init__.py` at
module load time, and importing back would make the cycle real.
`binfmt/__init__.py.__all__` says so at the point it omits `read_ar_members`, so the
omission reads as a decision rather than an oversight the next reader has to rediscover.

**The container format itself, verified against real output before being written from
the documented spec.** An 8-byte magic, then 60-byte member headers (name, mtime, uid,
gid, mode, size, a 2-byte end marker) each followed by that many bytes of data, padded
to an even offset. Real archives built with this host's own GNU `ar` 2.46 (`gcc -c` two
trivial `.c` files, `ar rcs`, including a deliberately-long filename to force the GNU
long-name table and an odd-sized member to force the padding byte) were inspected byte
for byte against the documented format -- the header layout, the end-of-header magic,
the `//` long-name table's `name/\n`-terminated entries and the odd-size padding byte
all match what the real tool produces. BSD's `#1/<N>` extended-name convention is
implemented from the documented format only; no BSD `ar` was available to verify it
against on this development host. Every index/padding pseudo-member a real toolchain
writes -- GNU's own symbol index (name field exactly `/`), GNU's 64-bit index
(`/SYM64/`), and BSD/Apple `ar`'s ranlib index (`__.SYMDEF`, `__.SYMDEF SORTED` on
newer toolchains, `__.SYMDEF_64`) -- is skipped rather than dispatched as an object:
its content is `ar`'s own bookkeeping, not something `read_binary` has any use for.
Skipping only the GNU index and reading every BSD/Apple ranlib member as an ordinary
object would not work: since it is neither ELF, Mach-O nor PE, that dispatch always fails
and costs the *whole archive* a spurious `partial_analysis`/`BIN_PARTIAL_FORMAT` verdict
hit -- every ordinary macOS static library or Windows `/SYM64/`-indexed import archive
would misreport as partially unreadable, not just a crafted one.

**A structure that does not parse costs that structure, never the evidence already
gathered, applied one level higher than usual.** Every other reader's version of this
promise is about *one* object; an archive's version has to say what happens to the
objects a partially-walked member table already found before hitting a header that
overruns the archive, a non-numeric size field, or a member declaring more bytes than
remain. Answer: they keep their own evidence, each under its own path, independently of
whatever went wrong later in the table -- the failure is recorded once, against the
archive's own path, as `errors.AR_PARSE_ERROR`, and does not retract what earlier
members yielded. Whenever the walk ends with zero real members -- whether because a
header overran the archive before any were found, or because the table walked to
completion and held nothing but index/padding pseudo-members -- the whole archive falls
back to one `read_strings_only` record over its raw bytes, marked
`evidence.PARTIAL_AR_MEMBER_TABLE_UNREAD`: the identical "no structure to split, strings
only" shape a format with no registered reader gets, not a new fallback mechanism,
tagged `evidence.FORMAT_AR` so the record still says this was a recognised archive
rather than an unknown format. Only a stream whose own magic does not match `ar`'s at
all -- unreachable through `layers.binaries`, which sniffs that magic itself before ever
calling in, but reachable by a test calling `read_ar_members` directly -- takes the same
fallback shape tagged `FORMAT_UNKNOWN` instead.

**A member's name is never grounds to drop the member.** A `#1/<N>` field claiming
more bytes than the member holds, or a `/<offset>` pointing past the long-name
table's end or into an entry that never closes with `/\n`, leaves `_resolve_name`
unable to say what the member is called -- not whether it exists. Skipping the member
outright over an unresolved name throws away real, already-read evidence over nothing
worse than its own label: "unreadable means `OPAQUE`, never `NO_CRYPTO_DETECTED`"
applies to a name exactly as much as to a structure. The reader reads the member's
bytes exactly as it would if the name had resolved, under a synthetic `member@<offset>`
path, with its own `AR_PARSE_ERROR` naming why the real name could not be used. Two
members that legitimately share one resolved name -- ordinary in `ar`, since nothing
stops two same-named `.o` files vendored from different source directories -- are
disambiguated with a `#2`, `#3` suffix (`_dedupe`) for the same reason:
`binaries[].path` is a unique key elsewhere in the scanner, and
`record._cap_by_findings` keys a dict on it, so two members silently sharing one path
would let the second overwrite the first's evidence even when the cap had room for both.

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
static archive is never a file a dynamic loader could resolve a `DT_NEEDED` entry
to, so a same-named `SONAME` on one -- bytes this module reads exactly as written,
not invented -- must not be able to make a genuinely system-linked sibling extension
read as bundled. Verified by mutation: removing the exclusion in
`member_stem_counts` turns a sibling's linkage classification from `system` to
`bundled` in `tests/test_linkage.py`'s
`test_an_archive_members_soname_never_confirms_a_siblings_needed_entry`.

**A cap on member count, independent of `max_binaries_per_record`.** That cap bounds
the record's *size*, applied once after every binary in the wheel (archive-contained or
not) has been read; it says nothing about the *work* a crafted archive can demand before
ever reaching it. `_MAX_MEMBERS = 4096` bounds how many `read_binary` dispatches one
archive can force, reported the same way a truncation elsewhere in this tool is: an
`AR_PARSE_ERROR` naming the cap, not silence.

**What was rejected.** Reading `ar`'s own GNU symbol-index member (the `/`
pseudo-member's own name-to-offset table) to shortcut symbol matching, rather than
dispatching every real member through the ordinary per-format readers: rejected because
the index does not carry binding (imported vs. defined) or which crypto *group* a name
belongs to, both of which `read_binary`'s own matchers compute correctly, and because
trusting an index a hostile archive controls without cross-checking it against the
object it claims to describe is the exact hazard `binfmt.symtab`'s cross-check exists to
close for `.dynsym`/`.symtab` themselves. Recursing into a member that is itself
`ar`-format (an archive inside an archive) is not attempted: `read_binary`'s own dispatch
does not special-case this, so such a member is read as `FORMAT_UNKNOWN` strings-only
rather than walked recursively -- static archives holding other static archives are not
a real toolchain output, and the fallback keeps this safe rather than silent.

**A relocatable `.o`'s `.symtab`-only definitions are matched too, with nothing of
`binfmt.ar`'s own.** `binfmt.elf` matches `.symtab` whenever `.dynsym` is genuinely
absent -- see "`.symtab` is matched for crypto symbols when `.dynsym` is genuinely
absent" below -- so a relocatable `.o`, every member of a real static archive, has its
symbol *definitions* visible to symbol-based detection even with no accompanying string
banner and no `.dynsym` of its own, which a real static-archive member normally lacks.
`binfmt.ar` calls `read_binary` per member regardless, so it gets that coverage from
`binfmt.elf` directly. Strings-based detection (which reads every section regardless of
symbol table) covers the same ground independently, demonstrated in
`test_a_banner_string_in_a_relocatable_object_is_still_found`,
`tests/test_binfmt_ar.py`. Matching `.symtab` touches the reader used by every ELF
object in the corpus, not just archive members, so its own design -- binding, whether it
applies only when `.dynsym` is absent or always, and a real corpus check that it does
not change output for the ordinary case -- is covered in its own entry, not here.

**What it costs.** A wheel shipping a `.a`/`.lib` produces real evidence instead of
none. `ar_parse_error` is among `BIN_UNPARSEABLE`'s `error_kinds`, the same rule
`elf_parse_error`/`macho_parse_error`/`pe_parse_error` are claimed by.

## `caps.cap` scans `ordered` again instead of materialising `pinned`/`rest`/`leftovers`

**Accepted. Performance and memory, not correctness.**

Building a reference list per pass on top of `ordered` -- `pinned` and `rest` (a stable
partition of `ordered`, together the same length as it), and `leftovers` (every item
that lost its `cap_key` slot or arrived after the room was gone) -- means that for the
case this cap exists to bound, an object with half a million matching symbols, up to
three item-reference lists are live at once on top of `ordered` and `kept`, and `pin` is
called twice per item: once building `pinned`, once building `rest`.

**Four passes over `ordered` itself, in the same priority order** (one representative
per `cap_key` among the pinned items, then among the rest, then whatever pinned items
are still short of room, then whatever of the rest is), with no materialised bucket. Two
small aids take the place of the three item-reference lists: `pinned_at`, `pin`'s answer
for every index computed once up front (`pin` runs once per item, not twice), and
`kept_at`, the set of indices already kept. `kept_at` is bounded by `limit`, not by how
many items came in -- it only grows when an item is added to `kept`, which the cap
itself bounds. `pinned_at` is not: it is one bool per input item, smaller than an item
reference but `O(n)`, not `O(limit)`.

**Measured, not assumed.** At n=500,000, limit=512: the whole call's *peak* allocation
is 47.86 MB, identical with and without the materialised lists, for both `pin=None` and
`pin` given -- `sorted(items, key=...)` materialising `ordered` plus one key tuple per
item sets the peak, before any pass runs, and the passes do not touch that. What does
shrink is the tail after the sort: 8.35 -> 0.06 MB unpinned, 8.20 -> 4.23 MB pinned.
This is an auxiliary-allocation saving, not a peak-memory one: "roughly doubling the
memory the cap was meant to save" overstates the list-building version, measured rather
than reasoned about. `pin`'s call count is a real, unconditional win: once per item
instead of twice, for every input.

Verified equivalent to the list-building passes by two differentials: an exhaustive
sweep (key sequences, pin patterns, sort orders including a deliberately non-total
`sort_key`, and every `limit` in `0..n+1`, for `n <= 6`, 583,238 cases) and 20,000
randomised trials at larger `n` -- zero divergences in either, across random item
counts, key cardinalities, pin predicates and limits -- alongside `tests/test_caps.py`'s
behavioural pins (representative per key, pins first, bounded, sorted,
order-independent), which hold for either implementation since the selection rule is
the same. The cap's overall overhead figure (roughly 10%) is not re-measured against
this; the correctness of the cap is not in question here, only its footprint and its
walk count.

**The per-pass check is inlined rather than called through a closure.** A
`want(index, wants_pinned)` closure from inside every pass's inner loop, re-checking
`pinned_at is None` on every call, costs more than the three lists it would remove
save: measured against the post-sort tail specifically, +8% for `pin=None`, +86% for
`pin` given, in the tail alone (the whole call, sort included, is a smaller +6%, since
the sort dominates there too). The check is inlined instead, with the `pin is not None`
test hoisted out of the loop into one `passes` tuple computed once -- slowing either
case down is not an acceptable trade against three list allocations, however large, for
a design whose whole point is performance and memory.

The cap's output is identical input for input either way; only how it gets there
differs.

## `bundled_libs` and `errors[]` get their own caps, not `binaries_truncated`'s

**Accepted, and it changes records: two record fields of their own,
`bundled_libs_truncated` and `errors_truncated`.**

`binaries_truncated` bounds `binaries[]` and `artifacts.extensions`, two arrays that
are always the same length (one entry per object read). `artifacts.bundled_libs` and
the top-level `errors[]` need caps of their own: without one, a wheel vendoring
thousands of small libraries under `*.libs/`/`.dylibs/`, or hitting the same recordable
failure on thousands of members, produces a correspondingly unbounded JSON line --
measured at 5000 vendored objects, a 274 KB line.

**Why not reuse `binaries_truncated` for `bundled_libs` too.** `bundled_libs` is a
*subset* of the objects `binaries[]`/`extensions` list -- only the vendored ones --
so its length can never exceed `binaries[]`'s, and a wheel with a huge object count
but a small vendored subset would report `binaries_truncated: true` while
`bundled_libs` itself was never actually cut. `bundled_libs_truncated` is computed
against `bundled_libs`'s own length, and the array itself is capped the same
finding-aware way `binaries[]` and `extensions` are, through the same
`record._cap_by_findings`, keyed on the bare path string rather than a
`BinaryEvidence` or a `(path, format)` pair -- the same universe of paths, so a
finding naming a vendored library still wins it a slot ahead of an unclaimed one.

**Why `errors[]` needs a different cap, not a reuse of `_cap_by_findings`.**
`_cap_by_findings` picks winners by which object a *finding* references; an error is
not about an object a rule matched, and dropping one silently could itself hide the
reason a wheel reads `OPAQUE` -- a plain path-sorted prefix could crowd out a rare
`bad_zip` behind three thousand identical `binary_unknown_format` entries from a
flood of malformed members. `ScanError` has a `cap_key`, `(stage, kind)`, making it
a `binfmt.caps.Capped` exactly like `SymbolMatch`/`StringMatch`/`RustCrate` are, and
`build_record` caps `evidence.errors` through the very same `binfmt.caps.cap` those
three use -- one representative error per `(stage, kind)` pair survives before the
rest, so a wheel drowning in one kind of failure cannot crowd a different, rarer one
out. No capping logic of its own: reusing `cap` is what `caps.py`'s own module docstring
promises for "a match list" in general, and a `ScanError` qualifies exactly as well as
the three it was written for.

Both `bundled_libs` and `errors[]` share `max_binaries_per_record`, the knob that
bounds `binaries[]`/`extensions` -- no context field or CLI flag of their own, since
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
against leaving the boolean as the only trace. Neither of these two flags carries that
consequence -- `bundled_libs` and `errors[]` are inventory listings a rule never reads,
not evidence a finding or the verdict depends on -- so a human losing entries from
either learns less about the wheel's *inventory*, never less about why it was
classified the way it was. This is the same posture the per-object
`symbols_truncated`/`strings_truncated` flags have: real signals with no rule of their
own, because what changes when they fire is what a record's arrays show, not what a
rule saw. Revisit if a future rule ever comes to depend on either array.

**Versions.** Both keys are present in every record, so they are a record change for
every wheel. `schema_version` does not move for them: `SCHEMA.md`'s versioning table has
its own row for "a key that is always present", distinct from an optional one, and no
consumer is broken by one arriving because the schema's own description asks every
consumer to ignore unknown keys.

**`skipped` and `symlinks` are the same shape, and are decided in their own entry.**
Plain inventory listings built without a cap: 3000 members refused by
`ArchiveLimits.max_member_bytes` would produce a correctly capped `errors: 256` sitting
next to an uncapped `artifacts.skipped: 3003`, a 220 KB record whose own
`errors_truncated` flag gives no hint that `skipped` is *also* incomplete -- `skipped`
and `errors[]` are fed by the same `archive.errors` for a member-refusal wheel, so the
two arrays would disagree about the same events. Each needs its own cap decided
(neither is finding-referenced in the same way, so `_cap_by_findings` is unnecessary
weight): see "`skipped` and `symlinks` reuse `caps.cap`, not a plain prefix" below.

## `skipped` and `symlinks` reuse `caps.cap`, not a plain prefix

**Accepted, and it changes records: two record fields of their own, `symlinks_truncated`
and `skipped_truncated`.**

`artifacts.skipped` (`{path, reason}`, for members refused by a limit) and
`artifacts.symlinks` (`{path, target}`) are the same unbounded shape as `bundled_libs`
and `errors[]`, and need their own caps: 3000 members refused by
`ArchiveLimits.max_member_bytes` would produce a correctly capped `errors: 256` sitting
next to an uncapped `artifacts.skipped: 3003` -- a 220 KB record whose own
`errors_truncated` gives no hint that `skipped` is also incomplete, since the two arrays
are fed by the same underlying `archive.errors` for a member-refusal wheel but capped
separately.

**A plain sorted-and-capped prefix is wrong for both arrays, on two premises worth
checking rather than assuming.**

For `skipped`: the premise "no `Finding.locations[].path` ever names a skipped member"
is false. `layers/inventory.py` builds `skipped` from `archive.errors`, and `scan.py`
folds those same errors into `evidence.errors`, which `engine.py`'s `_match_scan_error`
turns into `Location(path=error.path, ...)`. Two shipped rules match archive-stage
error kinds that carry a path -- `BIN_TOO_LARGE` (`error_kinds = ["binary_too_large"]`)
and `WHEEL_MEMBER_UNREADABLE` -- so a `skipped` entry can be exactly what a finding
names. Worse, the second premise ("every entry is already fully specific, so there is
no group a plain prefix could starve") mistakes *entry* uniqueness for *consumer-axis*
uniqueness: `skipped`'s `reason` **is** `ScanError.kind`, the exact axis
`ScanError.cap_key` exists to protect in `errors[]`. Reproduced with a plain prefix: 300
members refused by a compression-ratio limit plus 3 refused by a size limit, default
`max_binaries_per_record` -- the prefix drops `binary_too_large` from `skipped`
*entirely* while `errors[]`, capped through `caps.cap`, correctly keeps a
representative, and three `BIN_TOO_LARGE` finding locations name paths missing from
`skipped`. `SCHEMA.md` gives `errors[]`'s guarantee ("a wheel drowning in one kind of
failure cannot crowd a different, rarer one out"), and a `skipped` without it is exactly
the record self-contradiction the `errors[]` cap exists to prevent, one array over.

For `symlinks`: no rule reads a symlink path, so the first premise holds -- but the
second does not, because `target`, not the entry as a whole, is the axis a consumer
actually keys on. A vendored `libcrypto.dylib` reachable *only* through one symlink's
target, with no `skipped` entry and no binary error to fall back on, is this repo's own
worked example why ("How `_looks_vendored` is gated, and what pins it", above).
Reproduced with a plain prefix: 300 symlinks all targeting one boring library plus 1
targeting a bundled OpenSSL library, default cap -- the prefix keeps none of the
crypto-relevant target. This is `caps.py`'s own worked example (a Rust object's crates
sorted by name and cut at 128 drop `ring` behind an `anyhow`) reproduced one array over:
`caps.py` exists precisely because a plain prefix answers "how many entries survive,"
not "does the record still say what it needs to."

**Both go through `caps.cap`, keyed on the axis a consumer reads.** `skipped` gets
`cap_key() -> reason`, `symlinks` gets `cap_key() -> target` -- one representative of
each survives a flood of another before the rest, the same shape `ScanError.cap_key`
has for `errors[]`. Neither `(path, reason)` nor `(path, target)` implements
`caps.Capped` on its own (they are bare tuples in `ArtifactInventory`, used by
`layers/inventory.py` and every test as such), so `record.py` wraps each pair in a small
local `_SkippedEntry`/`_SymlinkEntry` frozen dataclass at cap time and unwraps the
result -- `ArtifactInventory.skipped`/`.symlinks` themselves stay plain tuples; nothing
outside serialisation needs the wrapper. This is *less* code than a plain-prefix
implementation: `cap()` returns the truncation flag directly, where a plain prefix
needs its own `X_truncated = max_binaries is not None and len(...) > max_binaries` line
per array (`bundled_libs_truncated` computes its own, since it goes through
`_cap_by_findings` instead). `tests/test_hardening.py`'s
`test_a_rare_skipped_reason_survives_a_flood_of_a_common_one` and
`test_a_rare_symlink_target_survives_a_flood_of_a_common_one` pin this: a plain-prefix
slice makes both fail.

**Why not `_cap_by_findings` instead**, given that `skipped` is finding-referenced:
`_cap_by_findings` picks winners by which *object* a finding references, keyed on path
-- the right shape for `bundled_libs`, which lists objects `binaries[]`/`extensions`
also list. `skipped` is not a list of objects a finding matched evidence *from*; it is a
list of refusals, and the thing worth preserving one of each of is the *reason*, not the
*path* a finding happens to name. `caps.cap`'s per-`cap_key` representative is the right
question for that; `_cap_by_findings`'s per-`(rule_id, subject)` representative is not.

**Why not reuse `binaries_truncated` for either.** Same reasoning as
`bundled_libs_truncated`: `skipped` and `symlinks` can each be capped independently of
the full object count `binaries_truncated` bounds, and a wheel that never approaches
either of *this* pair's caps must not report truncation it never actually did.

**Versions.** Both keys are present in every record; `schema_version` does not move,
for the same reason as `bundled_libs_truncated` and `errors_truncated` above. `skipped`
being finding-referenced decides how the *record* is capped, not what any rule matches.

## `.symtab` is matched for crypto symbols when `.dynsym` is genuinely absent

**Accepted, and it changes records.**

Crypto symbol matching over `.dynsym` alone is correct for a shared object or
executable, where `.dynsym` is what the dynamic linker actually uses -- but a
relocatable object (`ET_REL`, a `.o`/`.obj` before linking, the shape every member of a
`.a`/`.lib` static archive has, see "`binfmt.ar` reads `.a`/`.lib` static archives as a
container, not a reader") normally has no `.dynsym` at all, only `.symtab`. Read through
`.dynsym` alone, such an object's `matched_symbols` comes back empty even when it
genuinely defines a crypto symbol like `EVP_DigestInit_ex`, with no accompanying string
banner to fall back on -- invisible to the tool's primary detection mechanism for
"compiled straight into the extension, no library file, no dependency", the shape
`cryptography` 42+ relies on.

**Full matching applies only when `.dynsym` is genuinely absent.** When `.symtab` is the
object's only symbol table, it is read and matched the way `.dynsym` is: imports and
definitions, with its own cross-check. Every shared object and executable carries a live
`.dynsym` -- `strip` cannot remove it without breaking dynamic linking -- so this mode
leaves the reader's output for dynamically linked objects unaffected *by construction*.
Matching all of `.symtab` unconditionally, imports included, is rejected: it would touch
every ELF object with a live `.symtab`, most of which also carry local, non-exported
symbols a linker kept for debugging that `.dynsym` never exposed, and imports beside a
`.dynsym` would only restate what `.dynsym` must already declare. What is read beside a
live `.dynsym` is definitions only, with a corpus measurement behind it: "`.symtab`
local definitions are read when `.dynsym` is present, and only definitions", below.

"Absent" means genuinely, cleanly absent, not merely `dynsym is None`: an ambiguous
`.dynsym` (more than one `SHT_DYNSYM` section) or one forged away from its own type
also makes the type-based lookup return `None`, but neither means the object has no
`.dynsym` -- both mean it has one this reader cannot trust which candidate is real, or
cannot trust the type of. Falling back to `.symtab` for either would read a crafted
object's debug table as though it were a relocatable object's own, and only, symbol
table, which it is not. `dynsym_absent` is computed explicitly as `dynsym is None and
not dynsym_ambiguous and not dynsym_type_mismatch` (and a fourth condition, below), and
both edge cases have their own test confirming `.symtab` is not consulted when they fire.

**Binding and the cross-check reuse `.dynsym`'s own machinery.** `_iter_symbols`
operates on raw bytes against the shared `Elf32_Sym`/`Elf64_Sym` layout, deriving
imported/defined from `st_shndx == SHN_UNDEF` -- a fact the ELF spec defines
identically for both tables, so the one function serves both. The same is true of the
understated-rows and unresolved-name cross-checks: `holds_a_name_not_read` takes the
string bytes and the read-crypto set as plain arguments, with no `.dynsym`-specific
assumption baked in.

**The one piece that is not shared: `.symtab`'s string table has a different trust model
than `.dynsym`'s, and mixing them would apply the wrong one to one of the two callers.**
`.dynsym`'s `sh_link` is not what the dynamic linker trusts -- it uses `.dynamic`'s
`DT_STRTAB` instead -- so `_validated_strtab` exists specifically because a decoy
`sh_link` could disagree with what the loader actually resolves, and refuses to trust
`sh_link` without cross-checking it against `DT_STRTAB`. `.symtab` has no such hazard:
nothing but a section-header-reading tool ever resolves a `.symtab` name at all, the
dynamic linker never touches it, and a relocatable object normally carries no
`.dynamic` section to cross-check against in the first place -- `sh_link` naming the
associated string table *is* the ELF spec's own definition of what `.symtab`'s string
table is, not a hint a loader might disagree with. `_symtab_strtab` is a separate
function for this: it keeps the one check that generalises (`sh_link` must resolve to a
section really typed `SHT_STRTAB`) and drops the cross-check that does not apply.
`_symbol_bytes` is `.dynsym`-agnostic: it takes an already-resolved
`strtab: Section | None` from either trust model (`dt_strtab_addr`, threaded through
from `.dynamic`, for `.dynsym`; `_symtab_strtab`'s own check for `.symtab`) rather than
resolving `.dynsym`'s string table itself, so the two callers' resolution logic never
risks blending.

**What was rejected.** Reading `ar`'s own GNU symbol-index member to shortcut this
instead of matching through the archive member's own `.symtab`: rejected on the grounds
the archive entry gives -- the index carries no binding and trusting it without
cross-checking against the object it claims to describe is the exact hazard
`binfmt.symtab`'s cross-check exists to close.

**What `binfmt.ar` needs, for an ELF member: nothing.** It calls `read_binary` per
member regardless of format, so this applies to every ELF archive member through
`binfmt.elf` directly. Left open: a Windows `.lib`'s `.obj` members are COFF, not ELF,
and `binfmt.pe` deliberately does not read the COFF symbol table at all (every modern
linker strips it in favour of a PDB); such a member stays `FORMAT_UNKNOWN`,
strings-only, unaffected by this.

**Shapes this check must also reject, beyond a corroborated `sh_link`.**

- **A decoy `.strtab` must not defeat the check and read the object clean instead of
  `OPAQUE`.** `_symtab_strtab` has no independent authority to corroborate `sh_link`
  against -- that is the whole reason it does not attempt `_validated_strtab`'s
  address cross-check -- so trusting only the one table `sh_link` names, a `.symtab`
  repointed at an appended, all-NUL `SHT_STRTAB` resolves every name to `""`:
  `st_name == 0` and an index into an all-NUL table both read as "no name, resolved
  successfully" rather than unresolved, so `symtab_unresolved` stays `0`, the
  fabricated `.strtab` holds no crypto name to flag, and the *real* `.strtab`, sitting
  untouched elsewhere in the section table, is never asked. Reproduced on an `ET_REL`
  object genuinely defining `EVP_DigestInit_ex`, trusting `sh_link` alone:
  `matched_symbols=() partial_analysis=False errors=[]`, exactly the "unreadable means
  `OPAQUE`, never `NO_CRYPTO_DETECTED`" failure this whole invariant exists to prevent,
  and exploitable on purpose by a crafted wheel wanting to hide a crypto symbol from
  this tool. `_any_strtab_holds_a_name_not_read` closes it by not trusting the one table
  `sh_link` names at all for this check: it asks every `SHT_STRTAB` section in the
  object, so the real `.strtab` still gets to contradict the decoy regardless of which
  one `.symtab` claims to point at.
- **Skipping an unread `SHT_STRTAB` section reopens the identical decoy under a second
  construction.** Skipping a `SHT_STRTAB` section `_any_strtab_holds_a_name_not_read`
  could not fully read within the byte budget looks reasonable, since an unread section
  holds nothing this pass can confirm either way, but is wrong: a *small* decoy
  `.symtab`'s `sh_link` is happy to point at (so the primary read stays clean and
  cheap), placed beside the genuine `.strtab` with its own declared `sh_size` inflated
  past the budget elsewhere in the section table, means the one section that could
  contradict the decoy would be silently skipped rather than flagged as unchecked, and
  the object would read clean again. Reproduced. An unread `SHT_STRTAB` section counts
  as a hit, the same as finding an unclaimed name would: "unreadable means `OPAQUE`"
  applies to a string table this function could not fully examine exactly as it does to
  one that spelled a name out.
- **`dynsym_absent` needs a fourth condition.** A `.dynsym` whose own section header
  fails to parse never reaches `sections` at all (`elf_sections_unread`), so
  `dynsym is None`, `dynsym_ambiguous` is `False`, and `dynsym_type_mismatch` is also
  `False` -- the mismatch check scans the same truncated `sections` list and misses it
  the identical way, so `.symtab` matching would fire and add evidence to an
  already-partial record. Reproduced on an ordinary shared object with a corrupted
  `.dynsym` `sh_link`. Bounded impact either way (evidence added, not lost, to a record
  already flagged partial), but `dynsym_absent` also requires
  `PARTIAL_ELF_SECTIONS_UNREAD not in reasons`, so this shape does not fire matching at
  all.
- **The scope is dynamically linked objects specifically, not every object with no
  `.dynsym`.** Only a *dynamically* linked shared object or executable is guaranteed a
  live `.dynsym`; a static `ET_EXEC` has none either, and reproducibly gets `.symtab`
  matched too -- wheels shipping Go binaries are exactly this shape, which is why
  `binfmt.golang.py` exists at all. The behaviour is desirable, not a gap: a statically
  linked executable defining a crypto symbol should not stay invisible any more than a
  relocatable object should. The module docstring and this entry scope "unaffected by
  construction" to dynamically linked objects only, and name the static-executable case
  as this reader's intended reach, not an oversight.
- **`.symtab` carries symbol types `.dynsym` does not.** `STT_FILE` (a source-file
  pseudo-symbol) and `STT_SECTION` entries are names too, and a file literally called
  `EVP_md5.c` or `blake3_dispatch.c` would match a group by nothing but coincidence of a
  filename with the code it happens to implement -- reproduced. `_iter_symbols` yields
  each entry's `st_info`-derived type (`ELF32_ST_TYPE`, identical layout in both
  classes); the `.symtab` matching loop skips `STT_FILE`/`STT_SECTION`, and the
  `.dynsym` loop, which does not need this since a dynamic symbol table does not
  normally carry either type, ignores the field.

**What it costs.** A `.o`/`.obj`-holding wheel, or a statically linked executable, with
no `.dynsym` reports real crypto symbol matches instead of `matched_symbols: []`. And
`elf_symtab_unread` costs the linkage answer, since `.symtab` drives the imported/defined
split for an object with no `.dynsym`: see "Linkage reads a second split over the same
vocabulary", the paragraph beginning "`elf_symtab_unread` is not exempt either".

## `openssl_banner` names every major digit, not the majors that shipped

**Accepted.**

A `[[string_group]] openssl_banner` listing `OpenSSL 3.`, `OpenSSL 1.1.` and
`OpenSSL 1.0.` misses OpenSSL 4.0, and the current PyPI wheel of the package this tool
was written for compiles it in: `cryptography` 50.0.1 carries `OpenSSL 4.0.2 25 Aug
2026` in the read-only data of `cryptography/hazmat/bindings/_rust.abi3.so`, declares no
`DT_NEEDED` on libcrypto or libssl, exports no OpenSSL symbol from `.dynsym` (its 776
`EVP_*` definitions are local entries in `.symtab`), and names `openssl-sys 0.9.117` in
its cargo paths. Read through `.dynsym` and the banner alone, the banner is the entire
evidence, and with that major unlisted the wheel comes out `openssl_linkage: none`: a
wheel carrying its own OpenSSL reads exactly like a wheel with none in it. Nothing fails
while it does. The object parses, every structural check passes, and the record is
clean, which is what makes this worth writing down rather than quietly extending the
list.

**Why a digit is still required.** `OpenSSL ` on its own also matches prose. The same
`_rust.abi3.so` carries `OpenSSL 3's legacy provider failed to load`, and so does a
build that links the system library. Requiring a digit and a dot rules that undotted
string out. It does not rule out prose that names a *dotted* version -- `enable
OpenSSL 3.0 legacy provider` and `For OpenSSL 3.0.0 and newer` both still match -- and
a shape no `[[string_group]]` can close any tighter without also losing real banners
(see "A version banner with no dependency and no build strings reads `unknown`, not
`static`", below). What keeps that residual match from reading `static` outright is the
copy marker or the header-text gate, not the shape of the string. On an object with a
`needed` entry resolving the library and imports from it, the header-text gate closes:
the residual over-match is header text, and resolves to `system` or `bundled` like any
other header banner (see "A version banner beside imports from the system library is
header text, not a copy", below). On an object with a `needed` entry but no import from
the library, or with none at all, it is exactly the case the copy-marker gates cover --
`mixed`, through `_binary_posture`'s `sum(...) > 1` branch, when a `needed` entry is
present; `unknown` when there is none.

**Why all ten digits rather than the four that exist.** A major nobody has listed yet
is the failure above, waiting. Listing 0 through 9 costs one line, no code, and no
measurable time (the alternation is compiled once per process), and it cannot
over-match a version that does not exist. Measured over 18 native wheels off PyPI
(`cryptography`, `psycopg-binary`, `confluent-kafka`, `awscrt`, `grpcio`, `curl_cffi`,
`PyNaCl`, `argon2-cffi-bindings`, `pyzmq`, `hf-xet`, `lxml`, `scipy`, `aiohttp`,
`uvloop`, `zstandard`, `bcrypt`, `pycryptodome`, `requests`), against the three-major
list: exactly one record differs, `cryptography` from `none` to `static` with
`BIN_STATIC_OPENSSL` added, and the other seventeen are byte-identical. Three of them
carry banners (majors 3 and 4); none gains a match it does not have with the shorter
list. A separate run over 81 wheels finds the same: no verdict and no banner-match
differences beyond the intended one.

**What was rejected.** Letting a `[[string_group]]` carry a bounded pattern
(`OpenSSL \d+\.`) is the same answer with a code change behind it. `ruleset_loader.py`
refuses a non-printable substring precisely so `match_string_groups`' claimed-run
optimization can assume no pattern spans `RUN_SEPARATOR` (see "A `[[string_group]]`
substring must be printable ASCII"), and a pattern voids that assumption unless the
loader also refuses one that can match `"\n"`; `tests/test_binfmt_strings.py` derives
its separator-crossing inputs from `group.substrings`, which a pattern group would
leave with nothing to derive from. Ten literals buy the same decades and touch none of
it. Also rejected: a `why` telling whoever maintains the ruleset to add the next major
when it ships. This file refuses that remedy elsewhere ("A cause added later matches no
include list", and the enumeration risk in "Every `bundled` has a rule, by enumeration"):
a list that depends on somebody remembering is the failure, not the remedy.

**What it costs.** A banner for a major past 9. That is the same silent shape, and the
argument for accepting it is that OpenSSL took 23 years to reach 3.

This is a policy edit, not an extraction change, so it is carried by `ruleset_version`
alone: both versions salt the cache key, and `ANALYZER_VERSION` states in the record
that extraction changed, which it has not.

**Two kinds of enumeration exist in the ruleset, and must not be treated as one.**

*A field's spellings, enumerated.* These close mechanically, they are silent when
stale, and they are what this entry is about. `nss` (`NSS 3.`) names every digit.
`[conventions] windows_version_suffix_regex` matches the architecture decoration as a
token, not as `x64|x86|arm64|arm64ec`: four spellings of a field whose fifth (a vendor
writing `aarch64`) would leave `libcrypto-3-aarch64.dll` resolving to no library at all.
The group is called `decoration` rather than `arch` because that is what it matches.
`cargo_path_regex` accepts both path separators: cryptography 50.0.1's `win_amd64`
`.pyd` carries 153 `cargo\registry` paths and no `cargo/registry` path, so with one
separator every Rust wheel built on Windows reads as carrying no crates at all. That one
costs more evidence than the rest of these put together -- with both separators,
`hf-xet` has 74 crates on Windows rather than 0, including `rustls`, `aws-lc-rs` and
`blake3`, while all 18 Linux records are byte-identical either way.

*An entity list.* `[[rust_crate]]` names `openssl-src`, `boring`, `boring-sys`,
`sha-1`, `md5`, `sha1_smol` and `sha3` alongside the rest. These are different in kind:
no pattern closes the set of crates that exist in the world, so the list is incomplete
by construction rather than stale by neglect, and adding to it buys reach rather than
closing a hole. `openssl-src` is listed with that limit stated in its own `why`: its
Rust code runs in a build script and is not linked into the artifact, and neither
cryptography wheel measured carries the path, so it is reach nobody has observed rather
than the fallback for a stripped banner. A second limit is true of the whole table and
not just this row: a crate name never gives `openssl_linkage` a definite posture. An
object whose only OpenSSL evidence is a crate the `openssl` library lists reads
`unknown`, beside the crate's own `CONDITIONAL` finding ("An OpenSSL crate with no other
evidence reads `unknown`, not `none`", below).

One more is not an enumeration but a guarantee that has to be checked to hold.
`[conventions]` says naming the Go string groups in the ruleset means renaming a group
cannot silently flip a verdict-relevant field, and `binfmt.golang` reads
`go_boring_group` and `go_stock_group` for exactly that reason; a loader that does not
check them would load a name no group has and leave `GoBuildInfo.boring_crypto` false
for every Go binary in the run, while every other group reference in the file is refused
at load time. `_validate_conventions_references` checks them where those other
references are checked, and `Conventions` has no defaults for either field: a default
there would let a directly built `Conventions` point at groups that need not exist,
which is the same silent false wearing a dataclass default as a disguise.

**Two related causes are not enumerations, and have entries of their own.** A Go binary
built with `GOFIPS140` carries the stock package paths, which needs the build settings
read from `.go.buildinfo` ("A Go FIPS build is told from a stock one by its build
settings, not its package paths", below); and a static link that hides its symbols keeps
them in `.symtab` beside a `.dynsym` ("`.symtab` local definitions are read when
`.dynsym` is present, and only definitions", below). Still open: the `version` half of
`windows_version_suffix_regex` is an enumeration of two shapes, and Windows library
spellings are listed Unix-first (`libnss3`, not `nss3.dll`); both are unexercised by any
corpus measured rather than known good.

**Revisit if** a `[[string_group]]` needs a match ten literals cannot spell. Not on a
count of cases: the four enumerations above are not four of a kind, and only one of them
(`nss`) is a `[[string_group]]` a pattern capability would help.
`windows_version_suffix_regex` and `cargo_path_regex` are patterns, just ones that have
to be wide enough, and the crate names no pattern can close at all. A capability earns
itself when the enumeration cannot express the match, not when the list is long.

## A Go FIPS build is told from a stock one by its build settings, not its package paths

**Accepted.**

`go_stock_crypto` matches `crypto/sha256.`, `crypto/aes.`, `crypto/rsa.` and
`crypto/ecdsa.`, and `BIN_GO_STOCK_CRYPTO` turns that into `NON_APPROVED_CRYPTO`. Since
Go 1.24 the standard library implements those packages on top of
`crypto/internal/fips140`, so a binary built against the validated module carries every
one of those paths too, and with nothing to suppress it would read as non-approved. That
is a wrong verdict rather than a missing one, which is the worse direction: the wheel
that did the right thing is the one that gets flagged.

**Measured rather than reasoned, on go1.27.1**, building one program two ways:

| | stock | `GOFIPS140=v1.0.0` |
|---|---|---|
| `crypto/sha256.` occurrences | 9 | 9 |
| `crypto/aes.` occurrences | 6 | 6 |
| `crypto/internal/fips140` occurrences | 381 | 334 |
| `GOFIPS140=` in `.go.buildinfo` | absent | present |
| `fips140=on` in `.go.buildinfo` | absent | present |

The package paths cannot tell them apart, and the count going *down* in the FIPS build
rules out any threshold on them too. What separates the two is what `go version -m`
prints: `build GOFIPS140=v1.0.0-c2097c7c` and `build DefaultGODEBUG=fips140=on`, both of
which the toolchain writes into the `.go.buildinfo` section, which is `SHF_ALLOC` and so
reaches the strings pass.

**Why the verdict needs no reader change.** Parsing the modinfo blob into a
`GoBuildInfo` field looks like the obvious approach, and measuring first shows the
verdict does not need it. `.go.buildinfo` is `SHT_PROGBITS`, `SHF_ALLOC` and not
executable, which is exactly what `_collect_string_bytes` concatenates, so the settings
are printable strings the ELF reader already has, and a `[[string_group]]` plus a rule
reach them. That claim is ELF's; Mach-O and PE reach strings through a bounded prefix of
the object instead, and every measurement here is one program, go1.27.1, linux/amd64.
The module version is not lost by staying out of the reader either: the strings pass
records a hit's whole enclosing run, so the record carries
`{"group": "go_fips140", "value": "GOFIPS140=v1.0.0-c2097c7c"}` verbatim. What a typed
field would add is typing, not information.

**The record needs `[conventions]` to name every Go group.** A rule on a Go string group
the reader does not know about makes one record say two things: `binaries[].go.markers`
reading `["go_stock_crypto"]` on a build whose verdict is `BIN_GO_FIPS140`, from the
identical strings, because `markers` is built from the group names `[conventions]` lists.
That is the shape "`partial_analysis` and `partial_reasons` never disagree" exists to
refuse, one field over. `[conventions]` names every Go group rather than only the ones a
typed field is derived from, and a test holds the two lists equal.

**What the substrings are, and are not.** The two are matched independently on purpose: a
build can name a module version while a `//go:debug` directive turns enforcement off, and
a build can enforce the in-tree module without `GOFIPS140` naming a version. A test pins
each alone, because a fixture carrying both passes with either half deleted. `fips140=on`
is matched without its key because `DefaultGODEBUG` is a comma-joined list and `fips140`
need not be first; a fourth test case carries it between two other godebug defaults, so
tightening it to `DefaultGODEBUG=fips140=on` fails rather than silently stops matching.
The values `GOFIPS140` accepts are deliberately not enumerated: measured, `latest`
records `GOFIPS140=latest`, `inprocess` records `v1.26.0` and `certified` records
`v1.0.0-c2097c7c`, so a list of accepted values is a list that goes stale silently, which
is the `openssl_banner` lesson pointed the other way. `GOFIPS140=off` records no build
setting at all, so a build that opted out reads as the stock build it is.

**What it costs.** `CONDITIONAL`, never anything passing. The module being compiled in
does not mean it is in force: `GODEBUG=fips140` can be set back to off at run time, and
which validated version the toolchain carried is not something the wheel states.

The suppression is per object, the same as the BoringCrypto rule it sits beside (see
"Suppression is keyed on rule, subject and object", below): a wheel carrying one
FIPS-built and one stock Go binary reports both `CONDITIONAL` and `NON_APPROVED_CRYPTO`
in `classes`, and the stock finding's `locations` name only the stock object. A string
match is not proof a setting was recorded -- a binary that merely mentions `GOFIPS140=`
in help text matches too -- but per object that only suppresses that same binary's own
stock finding, never a real one on a binary beside it. That is accepted because the
alternative, a list of accepted values, goes stale in silence.

One property falls the safe way and is worth stating: `_collect_string_bytes` walks
sections in header order until the byte budget is spent, and `.go.buildinfo` sits after
`.rodata`. In an object large enough to exhaust the budget the condemning evidence is
read and the suppressing evidence is not, so such a build reads `NON_APPROVED_CRYPTO`
rather than `CONDITIONAL`. Over-flagging, which is the direction this tool errs in.

**Revisit if** a consumer needs the module version as a typed field rather than as a
recorded string, or when a third Go backend rule arrives: `suppressed_by` is an unordered
OR with no per-entry justification, and at two entries the rule's `why` carries two
different arguments (BoringCrypto *replaces* the stock implementations; the FIPS module
sits *underneath* them). At four the honest expression is specificity within the
`go-crypto` category, not a longer list.

## `.symtab` local definitions are read when `.dynsym` is present, and only definitions

**Accepted, and it changes records.**

Gating `.symtab` matching on `.dynsym` being genuinely absent ("`.symtab` is matched for
crypto symbols when `.dynsym` is genuinely absent", above) leaves every dynamically
linked object unaffected *by construction*, with no corpus check needed. That argument
is never that `.symtab` is untrustworthy; it is that the absence gate is scoped to zero
impact on dynamically linked objects. It is the right scope for relocatable objects, and
on its own it leaves the case this tool exists for unread.

`cryptography` 50.0.1's `cryptography/hazmat/bindings/_rust.abi3.so` carries **776 local
`EVP_*` definitions in `.symtab` and none in `.dynsym`**, whose only exports are the
module's own `PyInit` symbols. The OpenSSL it statically links is there, in a table this
reader parses for `stripped` and `symbol_counts.symtab` anyway, and an absence-gated
reader never looks. A definition nobody else can satisfy is what a static copy *is*.

**Only definitions are read beside a live `.dynsym`.** A dynamically linked object must
declare every import in `.dynsym` to link at all, so `.symtab` can say nothing new about
imports; taking them would record the same dependency twice under a second provenance,
and would let an undefined entry planted in a debug table read as a dependency the
object does not have. `STT_FILE` and `STT_SECTION` entries are skipped, as they are when
`.symtab` is the only table.

**One cross-check runs, and one does not, and they are not the same question.** The
understated-rows check asks whether a table under-declared itself, which is only a
question worth asking of the object's *sole* table; with `.dynsym` present and
cross-checked, a `.symtab` trimmed by a partial strip is ordinary rather than a lie, and
running it would mark a large share of honest release wheels `partial_analysis` for
carrying debug information in the state every linker leaves it in. The `unresolved`
count is a different question -- was a name this reader was *pointed at* readable -- and
an honest table never produces one, so it runs in both modes.

**A prefilter is measured and rejected for what it costs.** Walking every row of every
dynamically linked object's `.symtab` is work the absence gate avoids, and
`symbol_locator` -- the same compiled C-side scan `binfmt.symtab` mirrors
`symbol_groups_for` with -- could run over `.strtab` first and skip the walk when nothing
could match. Measured on a 26.7 MiB object with half a million symbols: 0.32s with the
prefilter against 0.55s without, and 0.50s against 0.43s on `cryptography` either way.
But shrinking `.strtab`'s `sh_size` so its rows point past it makes the prefilter read
the truncated table as holding nothing, skip the walk, and the object come out
`NO_CRYPTO_DETECTED` with `partial_analysis: false` -- the exact attack
`holds_a_name_not_read`'s own docstring names. A fifth of a second is not worth a silent
clean, so every row is visited and `tests/test_hardening.py` holds both halves: the
shrunken `.strtab` must read `OPAQUE`, and half a million rows must still walk in
reasonable time.

**Measured over 18 native wheels off PyPI, against the absence gate alone.** Five
verdict blocks differ; one headline class moves. `awscrt`, `curl_cffi` and `hf-xet` gain
local definitions from `.symtab` for the first time: the OpenSSL-named entry points each
one compiles in belong to the AWS-LC or BoringSSL fork each wheel actually ships, so
linkage reads them `unknown`, not `static` -- "OpenSSL-named definitions beside AWS-LC
or BoringSSL read `unknown`, not `static`" (above) is what tells a fork's own compiled-in
definitions apart from a real OpenSSL's. The whole purpose of reading local definitions
is `cryptography`'s own case, above: a real statically linked copy whose symbols a
version script hid from `.dynsym` entirely. `confluent-kafka` is the single class move,
`CONDITIONAL` to `NON_APPROVED_CRYPTO`. `cryptography`, `pycryptodome` and `PyNaCl` gain
symbols without changing class, and five wheels' `matched_symbols` report `truncated`.
That rate is a property of the population rather than of the reader: the gain lands only
on wheels that ship an **unstripped `.symtab`**, and over a corpus of fully stripped
manylinux wheels it would be zero.

Two claims here are worth separating. That no finding and no `(group, binding)` kind is
lost anywhere is not really a measurement: the local-definitions block only adds to a
set, and `SymbolMatch.cap_key()` is `(group, binding)`, so `caps.cap` keeps one of each
by construction. What genuinely needs measuring is whether reading `.symtab` marks an
object partial where nothing else would, and 18 wheels is thin evidence for it, so it is
also
`tests/test_real_corpus.py::test_no_wheel_is_opaque_only_because_symtab_was_read`, which
re-runs over whatever corpus a `WCS_CORPUS_DIR` holds rather than living in this
paragraph.

**What it costs.** Three things.

The hazard the absence gate avoids is open for definitions: a crafted object can plant
crypto names in a table trusted less than `.dynsym`, since `_symtab_strtab` has no
`DT_STRTAB`-equivalent authority to corroborate `sh_link`. The consequence is a false
*definition*, which reads as a static copy that is not there. That direction over-flags,
and this tool has no passing class to be tricked into, which is also why imports stay
out.

`.symtab` is read on every dynamically linked object, so a table or string table over
the byte budget records `elf_symtab_unread` where nothing else records anything, and
that cause is not in `[linkage_policy] exclude_reasons`, so it costs the linkage answer.
That is the honest reading: an object with no such record gives its answer without
looking at a table that could contradict it. No wheel in the corpus is partial for this
reason alone, which is what the real-corpus check above pins.

The third is a policy consequence this reader surfaces rather than creates. A statically
linked OpenSSL defines every legacy primitive OpenSSL ships, so `BF_*`, `MD4_*`, its
Curve25519 entry points and the rest match even where a version script hides them from
dynamic symbol resolution, and rules that carry `NON_APPROVED_CRYPTO` outrank
`BIN_STATIC_OPENSSL`'s `CONDITIONAL` in `[verdict] precedence`. `confluent-kafka` is one
instance and will not be the last: the headline class for static-OpenSSL wheels drifts
toward `NON_APPROVED_CRYPTO`, which is true but less actionable than "carries its own
OpenSSL". Nothing is lost from the record -- `verdict.classes` lists both -- and what to
do about it is a ruleset question rather than a reader one: see "A static OpenSSL's
legacy primitives lead the headline; the linkage condition says why", below.

**Revisit if** a consumer needs to tell a `.dynsym` export from a `.symtab` local
definition. Both record `binding: defined`, which is the honest answer to "does this
object carry it" and loses the distinction between a definition the object publishes and
one it keeps to itself. Adding a third binding value is not a `schema_version` bump, but
it is a contract decision nobody has asked for yet.

## An OpenSSL crate with no other evidence reads `unknown`, not `none`

**Accepted, and it changes `openssl_linkage`.**

Reading `openssl_linkage` off sonames, symbol groups and string groups alone leaves an
object read in full whose only OpenSSL evidence is a crate name -- `openssl-sys`,
`openssl`, `openssl-src` -- reading `none` beside a `CONDITIONAL` crate finding: "no
OpenSSL evidence" on a record carrying some, in the field most consumers filter on, and
in the direction `[linkage_policy]` exists to refuse.

**How `openssl_linkage` reads a crate.** `[[crypto_library]]` has `crates`, each
validated against `[[rust_crate]]` at load time, and `openssl` lists all three. An object
carrying a listed crate and nothing the checks above it read gives `unknown`. That is the
answer an object read far enough to say so gets for imported OpenSSL symbols with no
declared dependency, for the same reason: something uses OpenSSL, and the object does not
say which copy. The load-time check carries more than typo-catching: `find_rust_crates`
keeps every `[[rust_crate]]` name ahead of its cap, so a crate listed on the library
alone could be cut from an object with hundreds of crates and read `none` again.

**Never a definite posture.** The branch fires only on an object with no OpenSSL
`needed` entry, no OpenSSL symbol and no banner. A dynamically linked `openssl-sys`
leaves a `needed` entry and imports, so by elimination such an object is more likely a
static copy, but the elimination is only as good as the readers: a gap left open on
purpose, such as an ordinal import from a DLL the ruleset does not know, removes exactly
the evidence it rests on. Nor can the crate names settle it. `openssl-sys` links the
host's OpenSSL or vendors its own on a build feature, and `OPENSSL_NO_VENDOR` sends even
a `vendored` build back to the host's, so not even `openssl-src` in the build graph
means a vendored copy. One crate, built both ways:

```text
cryptography 50.0.1 off PyPI, cp311-abi3: manylinux_2_34_x86_64, macosx_11_0_arm64, win_amd64
  crates: openssl 0.10.81, openssl-sys 0.9.117     needed: nothing OpenSSL
  banner "OpenSSL 4.0.2 25 Aug 2026" on all three, defined symbols on ELF and Mach-O
  -> static
cryptography 50.0.0, Fedora 44 RPM, repackaged as a wheel
  needed: libcrypto.so.3, libssl.so.3              OpenSSL symbols: imported only
  crates: openssl 0.10.81, openssl-sys 0.9.117, from its distro cargo paths
  banner "OpenSSL 3.5.7 9 Jun 2026", which is header text
  -> system
```

Same crate, two postures. So the crate check sits below every other one, and
`_aggregate` treats its `unknown` like any other: it never outvotes a definite posture
elsewhere in the wheel. The Fedora row's crates come from the distro cargo-path layout
(see "Crates are read from every cargo source layout, and a vendored crate has no
version", below); its imports from the system library answer first, so it reads `system`
either way.

**Which records it decides.** None of the four records above: every object answers from
its own evidence, and the records are byte-identical with and without the crate check
apart from the `tool` block. What it decides is an object that answers with nothing
else. The win_amd64 `.pyd` is one banner away from being that object: it matches no
OpenSSL symbol and carries a `pe_ordinal_import` cause linkage ignores, so its banner is
the whole of its evidence. Scanned with `openssl_banner` restricted to `3.`, `1.1.` and
`1.0.`:

```text
without the crate check: openssl_linkage: none,    verdict.rule_ids: [..., "BIN_RUST_CRYPTO_CRATE", ...]
with it:                 openssl_linkage: unknown, verdict.rule_ids: [..., "BIN_OPENSSL_LINKAGE_UNKNOWN",
                         "BIN_RUST_CRYPTO_CRATE", ...]
```

**What was rejected, and why.**

- *A posture per crate: `static` for `openssl-src`, `unknown` for the rest.* `openssl-src`
  in the build graph does not mean a vendored copy, as above. Its Rust code also runs in
  a build script and leaves no path in the artifact (its `why` has the measurement), so
  a posture keyed on it would rarely have anything to fire on.
- *Leave `none` and document the coexistence.* `none` there says "no OpenSSL evidence"
  on a record carrying some, the direction `[linkage_policy]` exists to refuse, and
  `unknown` already has the meaning this case needs.
- *Widen what `unknown` means to "evidence whose posture is not decidable".* Not needed:
  the imported-symbol case already means that. `SCHEMA.md`'s `unknown` row says so for
  both causes.

**What it costs.**

- A wheel whose only OpenSSL evidence is a listed crate gains `BIN_OPENSSL_LINKAGE_UNKNOWN`
  and `OPAQUE` in `classes`. Its headline stays `CONDITIONAL`, which outranks `OPAQUE`,
  and the crate finding already asks for a human.
- A crate-only object beside a sibling that answers takes the sibling's posture,
  including `system`. The field is unaffected, but the rules do not read it alone:
  `DERIVED_SYSTEM_OPENSSL_ONLY` is withheld beside the crate-only object, and
  `DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM` names it instead (see "An object that read
  `unknown` withholds `DERIVED_SYSTEM_OPENSSL_ONLY`; the field stays `system`", below).
- An SBOM component naming `openssl-sys` moves the field the same way a crate does: see
  "An SBOM naming an OpenSSL crate reads `unknown`, not `none`", below.
- A build whose cargo paths use a layout the reader does not recognise, such as a git
  dependency checkout, carries no crate, so the crate check never fires on it.

## A version banner beside imports from the system library is header text, not a copy

**Accepted, and it changes `openssl_linkage`.**

`_binary_posture` does not count every `openssl_banner` match as `static`. A build
compiled against OpenSSL's own headers puts the banner in read-only data whether or not
the object links its own copy. Counted unconditionally, a `needed` entry resolving to the
system library and a banner in the same object are both true for every such build: the
record reads `mixed` and pairs `BIN_OPENSSL_LINKAGE_UNKNOWN` ("could not be resolved")
with evidence that, in fact, resolves cleanly to the host library.

```text
cryptography 50.0.0, Fedora 44 RPM, repackaged as a wheel
  needed: libcrypto.so.3, libssl.so.3              OpenSSL symbols: imported only
  banner "OpenSSL 3.5.7 9 Jun 2026", no OPENSSLDIR: string beside it
-> every banner a copy:       openssl_linkage: mixed,  verdict.rule_ids: [..., "BIN_OPENSSL_LINKAGE_UNKNOWN", ...]
-> header banner told apart:  openssl_linkage: system, verdict.rule_ids: [..., "DERIVED_SYSTEM_OPENSSL_ONLY", ...]
           (no "BIN_OPENSSL_LINKAGE_UNKNOWN"; "BIN_OPENSSL_BANNER" still fires -- the
           banner is still reported, just not read as a competing posture)
```

**How a header banner is told apart.** A `string_group` match does not count toward
`static` when all four hold on the one object it was found on:

- a `needed` entry resolved `system` or `bundled` in the loop -- a confirmed
  dependency, from the host or from a copy the wheel ships, not a guess;
- the object imports at least one symbol from the library's `symbol_group`, so it calls
  the resolved copy rather than only declaring a dependency on one;
- the object is not `partial_analysis`, for any cause -- deliberately its own, stricter
  split rather than a reuse of `[linkage_policy] exclude_reasons`, since a partial read
  can hide the very string the fourth gate looks for;
- the library names a `copy_string_group`, strings only a compiled-in copy carries, and
  the object matches none of them.

A defined symbol still makes `static` regardless of all four: `static = defined or
banner`, so a real definition never needs a fourth gate. A library naming no
`copy_string_group` has no way to tell a header banner from a copy, and counts every
banner match as a copy. On an object with no `needed` entry naming the library at all --
so the first gate above never opens -- the same four strings still decide whether a
banner is a copy, through a sibling condition: see "A version banner with no dependency
and no build strings reads `unknown`, not `static`", below.

**The auditwheel shape adds `bundled` to the first gate.** auditwheel rewrites an
extension's dependency to a hash-renamed copy it vendors into the wheel
(`libcrypto-3a1f2b4c.so.3`) and compiles the extension against OpenSSL's own headers,
so the extension carries `OPENSSL_VERSION_TEXT` whether or not anything in it calls
`OpenSSL_version()`. The vendored copy itself carries the real banner and its own
`OPENSSLDIR: ` string; the extension's copy of the banner is header text the same way a
system-linked object's is.

```text
cryptography 42.0.5-style auditwheel build
  extension NEEDs libcrypto-3a1f2b4c.so.3, imports OpenSSL symbols, no OPENSSLDIR: beside its banner
  vendored fakecrypto.libs/libcrypto-3a1f2b4c.so.3 carries the banner and OPENSSLDIR: beside it
-> every banner a copy:       openssl_linkage: mixed,   verdict.rule_ids: [..., "BIN_OPENSSL_LINKAGE_UNKNOWN", ...]
-> header banner told apart:  openssl_linkage: bundled, verdict.rule_ids: [..., "BIN_BUNDLED_OPENSSL", ...]
```

For OpenSSL, `copy_string_group` names the `openssl_build_info` string group, matching
`OPENSSLDIR: `. `OpenSSL_version()` returns the version banner and this string from the
same switch, so a compiled-in copy that keeps its banner keeps this string beside it,
and a header only ever supplies the banner macro. Measured on a Fedora 44 host:
`cryptography`'s own `.abi3.so`, built as a distro RPM, declares `NEEDED libssl.so.3` and
`libcrypto.so.3`, imports 331 OpenSSL-prefixed symbols and defines none, has no `.symtab`,
and carries the banner `OpenSSL 3.5.7 9 Jun 2026` with no `OPENSSLDIR: ` string anywhere
in it. A statically linked PyPI build of the same project carries no OpenSSL `NEEDED`
entry, no OpenSSL dynamic symbols, and both the banner and `OPENSSLDIR: "/outfiles/
openssl-3.5.8/openssl/ssl"` beside it. The real `/usr/lib64/libcrypto.so.3` on the same
host carries its own banner and `OPENSSLDIR: "/etc/pki/tls"`. Every ELF under `/usr/lib64`
and the Python site and `lib-dynload` directories declaring an OpenSSL `NEEDED` entry --
107 objects, 15 of them matching `openssl_banner` -- imports OpenSSL symbols, defines
none, and carries no `OPENSSLDIR: ` string. LibreSSL, BoringSSL and AWS-LC define an
`OPENSSLDIR: ` string in their own `OpenSSL_version()` too, from reading their source
rather than from this measurement.

**Why a marker and not the imports alone.** `needed` resolving `system`, imported
symbols, no defined symbol and a banner are not enough by themselves. Two genuinely mixed
shapes satisfy all four and still carry a real copy: a merged universal binary whose one
slice imports from the host library and whose other slice carries a hidden, stripped
static copy; and a static `libcrypto` linked beside a dynamic system `libssl`. That
copy's build strings ride beside its banner only when something in the object actually
calls `OpenSSL_version()` -- the one function, defined in `crypto/cversion.c`, that
returns both the banner and the `OPENSSLDIR: ` string. `cryptography` guarantees that
call by exposing `openssl_version_text`, which is why both shapes read `mixed` here. A
generic consumer that never calls `OpenSSL_version()` itself gives the linker no reason
to pull `cversion.o` out of a static `libcrypto.a`, so the copy carries neither string;
if that consumer's own header then supplies a banner, the marker has nothing to find and
the object reads `system`, not `mixed`. See "What it costs" below for that shape.

**What was rejected.**

- *The imports alone, with no marker.* Covered above: it moves the two genuinely mixed
  shapes into `system`, the direction this tool's invariants exist to refuse.
- *Comparing the banner's version against the host's.* The scan host is not the target
  the wheel will run on, and the tool makes no network call to look one up.
- *Dropping a banner outright whenever a system dependency is present, with no import or
  marker check.* Discards the banner as evidence even when it is the only sign of a
  genuine hidden copy; the four gates exist so the banner is dropped only when nothing
  else says it might be a copy.
- *Counting an unconfirmed, vendor-shaped `needed` entry (`uncertain`) as opening the
  first gate too.* `uncertain` is exactly the case nothing confirmed what the entry
  resolves to, so there is no confirmed copy for a header macro to belong to. Opening
  the gate there would let an unconfirmed guess demote a real, unexplained banner on an
  incompletely-read wheel; `uncertain` combines with `static` into `mixed` instead
  ("An `uncertain` needed match beside a definition is `mixed`", below), and a header
  banner does not change that.

**What it costs, and what is left unmeasured.**

- `BIN_OPENSSL_BANNER` still fires beside `DERIVED_SYSTEM_OPENSSL_ONLY` for this shape;
  its `why` says so.
- This moves the field in the favourable direction -- from `mixed`/`OPAQUE` to
  `system`/`CONDITIONAL` -- which is exactly why it takes four independent gates rather
  than one.
- The two mixed shapes under "Why a marker" are argued from the copy's measured
  strings, not measured as composites: no merged universal binary and no static
  `libcrypto` beside a dynamic system `libssl` has been built and scanned to confirm it
  reads `mixed` here. The argument rests on `OpenSSL_version()` being reachable, which
  holds for a real copy in general but is only guaranteed, not measured, for these two
  shapes specifically.
- A real copy whose banner survives a strip or a build without its `OPENSSLDIR: ` string
  reads `system`, and this is not only an unmeasured edge case: a stripped, hidden static
  `libcrypto` beside a dynamic system `libssl`, whose consumer never calls
  `OpenSSL_version()` and so never links in `crypto/cversion.c` -- the one object that
  carries both the banner and the OPENSSLDIR string -- keeps neither, and if the
  consumer's own header supplies a banner the object reads `system`. The marker does not
  create this residual: the same object with no header banner reads `system` whatever
  the banner rule does, since it carries no evidence of its copy at all. Every real copy
  measured kept both strings together, because `OpenSSL_version()` returns them from the
  same call -- but only when something calls it, which `cryptography` guarantees by
  exposing `openssl_version_text` and a generic consumer does not.
- Windows OpenSSL 3.5 builds that read their install directory from the registry rather
  than compiling it in, and LibreSSL, BoringSSL and AWS-LC generally, are not measured
  here; the `why` on the `openssl_build_info` string group says so and cites source
  rather than a host measurement for the latter three.
- An object that is `partial_analysis` for any cause keeps `mixed`, whatever the cause.
- A library other than OpenSSL names no `copy_string_group`, so every banner it finds
  counts as a copy.
- On the bundled side of the first gate, the misread direction if the four gates are
  wrong is `mixed` to `bundled`, not to `system`: a wheel wrongly read this way still
  carries its own copy and still cannot see the host provider, so the mistaken reading
  is still `CONDITIONAL` with `BIN_BUNDLED_OPENSSL`, not the clean-looking `system`
  outcome a mistake on the system side would produce.

Revisit if a real copy is found whose banner survives without its build strings, or if a
second library gains a `copy_string_group` and needs its own measurement the way OpenSSL's
does here.

## A version banner with no dependency and no build strings reads `unknown`, not `static`

**Accepted, and it changes `openssl_linkage`.**

`openssl_banner` matches any sentence naming a dotted OpenSSL version, not only OpenSSL's
own banner: `OpenSSL 3.` through `OpenSSL 9.` are substrings, so `enable OpenSSL 3.0
legacy provider` and `For OpenSSL 3.0.0 and newer it returns the state of the default
provider` both match, the same as `OpenSSL 3.0.14 4 Jun 2024` does. On a Fedora 44 host,
`libxmlsec1-openssl`, `libnode` and CPython's own `_hashlib` each carry a match of this
shape; each also `NEED`s `libcrypto.so.3`, so each is the system-linked case "A version
banner beside imports from the system library is header text, not a copy" (above)
already covers, not the no-dependency shape this entry is about. No library on this host
reproduces the no-dependency shape itself -- OpenSSL compiled straight into an extension
with no library file and no dependency at all -- without also carrying symbols or build
strings, so it is reproduced synthetically instead: a dlopen consumer or a literal string
that names a dotted OpenSSL version, with no `needed` entry, no OpenSSL symbol and no
build string beside it. An unguarded banner-only match of that shape reads
`openssl_linkage: static` and fires `BIN_STATIC_OPENSSL`, on an object with no `needed`
entry to weigh the banner against.

**The gate.** On an object where no `needed` entry resolved the library at all -- `system`,
`bundled` and `uncertain` are all false, so "A version banner beside imports from the
system library is header text, not a copy" (above) never applies, since its first gate
requires a confirmed dependency -- a banner counts as a copy only when the object also
carries the library's build strings (`copy_string_group`, `openssl_build_info` for
OpenSSL). Without them the banner is uncorroborated: real evidence that the library's API
is named in this object, but not evidence of a compiled-in copy. The gate stays shut on
an object not read in full, for the same reason the header-text gate does: a partial read
may have cut the very string that would prove a copy.

**Measured.** cryptography 42.0.5 and 50.0.1, on manylinux, macOS universal2 and Windows,
each carry `OPENSSLDIR: ` beside their banner; confluent-kafka's bundled `librdkafka`
does too. grpcio, awscrt and curl_cffi carry `OPENSSLDIR: n/a` and no `openssl_banner`
match at all. Every real static copy measured for this entry keeps its build string
beside its banner; every uncorroborated match measured is prose from a system-linked or
unrelated object.

**Why `unknown`, not `none`.** The object carries the library's own banner --
`BIN_OPENSSL_BANNER` still fires -- so `none` would say there is no OpenSSL evidence
beside a finding that says otherwise, the same reasoning "An OpenSSL crate with no other
evidence reads `unknown`, not `none`" (below) applies to a crate. `unknown` means "uses
the API, does not say which copy," which is what a dlopen consumer, a header-only build
or a sentence naming a version all are.

**What was rejected.**

- *Tightening the string shape instead.* A patch-level digit still matches `_hashlib`'s
  own prose ("For OpenSSL 3.0.0 and newer"); requiring a date drops a real banner from a
  build whose banner carries no date; and no shape at all can tell a header macro or a
  sentence from a real copy, which is the same argument "`openssl_banner` names every
  major digit, not the majors that shipped" (above) already makes for keeping the group a
  plain substring list.
- *Extending the same demotion to `bundled` and `uncertain`.* A `bundled` `needed` entry
  is already covered directly by the header-text gate's own bundled half (see "The
  auditwheel shape adds `bundled` to the first gate", above): the gate excludes the
  banner there too, once the object imports from the resolved copy. An `uncertain`
  entry combines with `static` into `mixed` instead ("An `uncertain` needed match beside
  a definition is `mixed`", below), unaffected by this entry either way, since nothing
  confirmed what it resolves to for a header macro to belong to.

**What it costs.**

- A real static copy whose consumer never calls `OpenSSL_version()`, whose symbols are
  all hidden, and whose own headers still supply a banner now reads `unknown` (OPAQUE,
  `BIN_OPENSSL_LINKAGE_UNKNOWN`) instead of `static`, on an object with no dependency to
  weigh the banner against. Local `.symtab` definitions still make it `static`
  regardless.
- An object that both imports the library with no confirmed dependency and carries an
  uncorroborated banner moves from `static` to `unknown`: imports with no confirmed
  provider already meant "uses, not which copy," and the banner without its build string
  adds no copy either.

A fork of OpenSSL's API carrying an `openssl_banner` match of its own is exactly the
shape "OpenSSL-named definitions beside AWS-LC or BoringSSL read `unknown`, not
`static`" (below) covers, when no `needed` entry resolves the library at all. With one,
the fork's own banner reads exactly as any other banner would: "A version banner beside
imports from the system library is header text, not a copy" (above) already decides it,
whether the resolved dependency is the system library or a bundled copy.

## OpenSSL-named definitions beside AWS-LC or BoringSSL read `unknown`, not `static`

**Accepted, and it changes `openssl_linkage`.**

AWS-LC and BoringSSL both implement OpenSSL's public API under OpenSSL's own names:
`EVP_*`, `BN_*`, `RSA_*`, `BIO_new` and the rest of the `openssl` `symbol_group` are
entry points either library defines too. `_binary_posture` reads a defined match from a
library's own `symbol_group` as that library, so an object built from either fork reads
`openssl_linkage: static` with no OpenSSL in it at all -- `defined` says an OpenSSL-API
symbol was compiled in, not which implementation supplied it.

Measured, scanning real PyPI wheels: `awscrt` 0.36.4's manylinux build (a C AWS-LC
build, unprefixed) defines 58 `AWSLC_*`-prefixed names and the OpenSSL-named
`BIO_new` alongside them, and carries no `openssl_banner` match. `curl_cffi` 0.16.3's
manylinux build (BoringSSL) defines 40 OpenSSL-named entry points and 16
`BORINGSSL_*`/`CRYPTO_BUFFER_*` names, also with no banner. The aws-lc-rs 1.18.1 FIPS
cdylib defines its `aws_lc_fips_*`-prefixed names alongside an unprefixed
`BN_from_montgomery_word`. None of the three carries an `openssl_banner` match, but a
consumer that does compile one in is not hypothetical: AWS-LC's and BoringSSL's own
public headers define `OPENSSL_VERSION_TEXT` as one string literal, `"OpenSSL 1.1.1
(compatible; AWS-LC <version>)"` or `"OpenSSL 1.1.1 (compatible; BoringSSL)"`, which
`openssl_banner` matches, and both forks' own `OpenSSL_version()` returns `"OPENSSLDIR:
n/a"`, which clears the copy-marker gate the same way a real copy's does -- so a fork's
own banner is not weaker evidence of a fork than a fork marker with no banner at all.

**The relation is ruleset data, not a Python special case.** `[[crypto_library]] openssl`
names `fork_symbol_groups`/`fork_string_groups`: symbol and string groups that identify
a different library implementing this one's API under this one's names, currently
`aws_lc`, `aws_lc_fips` and `boringssl`. On an object where one of them matched (a
symbol group only when the match is DEFINED in the same object, since an imported fork
symbol says the object calls a fork it does not compile in here, not that this object's
own `openssl`-named definitions belong to it), a banner whose text is entirely explained
by the fork groups' own patterns (`_banner_is_fork_text`) is that fork's own header
macro, not a real OpenSSL banner, so it cannot corroborate a copy either: `static`
here -- whether it holds because the `openssl` `symbol_group`'s own definitions are
present, because this banner is, or both -- reads `unknown` instead. This is tested
against the fork groups' own compiled patterns, not by requiring a same-object
`fork_string_groups` match to have survived `match_string_groups`' cap: a real AWS-LC or
BoringSSL object carries far more fork-group runs than the cap keeps (every
`OPENSSL_PUT_ERROR` expands `__FILE__` to one more `aws-lc/crypto/*.c` path), and a
comparison against whichever runs happened to survive would miss this exact shape
whenever the surviving runs are all paths rather than the banner's own. A banner on a
*different* printable run -- a real, dotted OpenSSL version with its own build string,
beside an unrelated fork marker elsewhere in the same object -- is not the fork's own
text and still corroborates a real copy, so `static` still stands in that shape,
whatever else the object also carries. This decision is made once, in `_binary_posture`'s
final `if static:` branch, after `system`, `bundled` and their disagreements with
`static` have already been resolved: a `needed` match to the system or a bundled
library, or a combination that already reads `mixed`, is unaffected either way.

**Why `unknown`, not `none`.** An object can carry a real OpenSSL and a fork marker at
once -- a Rust extension vendoring both `openssl-sys` and `rustls`/`aws-lc-rs`, say,
where the lowercase `aws-lc` string group also matches an `aws-lc-rs` cargo path -- so
`none` would be the false negative "absence of evidence is not evidence of absence"
rules out. `unknown` keeps the object on the triage list (`BIN_OPENSSL_LINKAGE_UNKNOWN`,
`OPAQUE`), consistent with the existing reading of imports with no declared provider or
a crate that binds the API and nothing else: "uses the API, does not say which copy."

**What was rejected.**

- *A Python special case naming AWS-LC and BoringSSL directly.* Nothing in the scanner
  hardcodes a library name; the relation belongs in `ruleset.toml` beside every other
  fact about `openssl`, matching how `crates` and `copy_string_group` already work.
- *Excluding AWS-LC's and BoringSSL's names from the `openssl` `symbol_group`.* That
  loses a real OpenSSL's own definitions when they happen to share an object with a
  fork, since the group would then no longer recognise them either. Reclassifying the
  *outcome* for this one library, rather than narrowing what counts as a match, keeps
  a real OpenSSL's own definitions visible to every rule that reads the group directly
  (`BIN_OPENSSL_SYMBOLS_DEFINED` still fires on a fork object; it matches names, not
  libraries).
- *Reading `none`.* Covered above.

**What it costs.** A real static OpenSSL whose only evidence is definitions, in an
object that also carries aws-lc-rs or BoringSSL, reads `unknown` (OPAQUE) rather than
`static`. `BIN_OPENSSL_SYMBOLS_DEFINED` still fires either way, since it matches names
directly rather than through linkage. The same reading applies when the only evidence is
a banner that is itself the fork's own header text, with no dependency to weigh it
against: an object carrying nothing but a fork's own compatibility banner and the
copy-marker string beside it reads `unknown`, not `static` -- the banner corroborates
only that some OpenSSL-API implementation was compiled in, not a distinct copy.

## An object that read `unknown` withholds `DERIVED_SYSTEM_OPENSSL_ONLY`; the field stays `system`

**Accepted, and it changes verdicts.**

`DERIVED_SYSTEM_OPENSSL_ONLY`'s `why` says every piece of OpenSSL evidence in the wheel
points at the system library, and `openssl_linkage` reading `system` is not enough to say
that. `_aggregate` never lets a per-object `unknown` outvote a definite posture, so a
wheel with one object reading `system` and another reading `unknown` -- positive,
library-specific evidence that OpenSSL is used, just not which copy -- resolves to
`system`. A rule keyed on the field alone fires there too. Reproduced on evidence built
by hand, in the three shapes an object can read `unknown` from: a listed Rust crate with
nothing else, imported OpenSSL symbols with no declared dependency, and a vendor-shaped
`needed` entry an incompletely read wheel could not confirm.

```text
keyed on openssl_linkage alone:
crate     + system sibling -> openssl_linkage: system, rule_ids include DERIVED_SYSTEM_OPENSSL_ONLY
import    + system sibling -> openssl_linkage: system, rule_ids include DERIVED_SYSTEM_OPENSSL_ONLY
uncertain + system sibling -> openssl_linkage: system, rule_ids include DERIVED_SYSTEM_OPENSSL_ONLY
```

In the import and uncertain shapes, `DERIVED_SYSTEM_OPENSSL_ONLY` is then the *only*
verdict-bearing finding on the wheel at all: `BIN_NEEDED_SYSTEM_OPENSSL` and
`BIN_OPENSSL_SYMBOLS_IMPORTED` carry none.

**How the rules read per-object postures.** `linkage.object_postures` exposes the
per-object tuple `_aggregate` reduces, shared with the engine so a rule and the field can
never disagree about what one object said. `engine._match_linkage` takes two alternative
match keys: `exclude_object_values` (skip the whole match when any object's own posture
is one of these) and `object_values` (fire once per object whose own posture is one of
these, located at that object rather than the wheel). `DERIVED_SYSTEM_OPENSSL_ONLY` takes
`exclude_object_values = ["unknown"]`, and `DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM`
takes `object_values = ["unknown"]` on the same `value = "system"` match and carries
`OPAQUE`. `DERIVED_SYSTEM_OPENSSL_ONLY` fires exactly when neither complement does. The
complementary rule is not optional -- withholding `DERIVED_SYSTEM_OPENSSL_ONLY` alone, on
the import and uncertain shapes above, would leave the wheel with no verdict-bearing
finding at all and a headline of `NO_CRYPTO_DETECTED`, which is exactly the "unreadable
or undeterminable must never read as nothing found" invariant in the wrong direction on a
wheel that plainly uses OpenSSL.

**What was rejected, and why.**

- *Move `openssl_linkage` itself to `unknown` beside a per-object `unknown`.* Moves the
  field most consumers filter on, needs a real-wheel measurement nobody has taken, and
  contradicts `_aggregate`'s documented rule that a non-definite posture never outvotes
  a definite one already present.
- *Let `DERIVED_SYSTEM_OPENSSL_ONLY` fire on the field alone.* Its own `why` becomes false
  on the record: not every piece of OpenSSL evidence points at the system library when
  another object says OpenSSL is used and does not say where from.
- *Cover only the crate shape.* The import shape declares no dependency either, and
  reading its `unknown` differently from the crate's would need a split the vocabulary
  does not carry and nothing else needs.

**What it costs.** A wheel whose only other OpenSSL evidence is `unknown` beside a system
sibling reads an `OPAQUE` headline rather than `CONDITIONAL` (the import and uncertain
shapes), or keeps its `CONDITIONAL` headline from `BIN_RUST_CRYPTO_CRATE` and gains
`OPAQUE` (the crate shape); `openssl_linkage` itself never moves. An unreadable (opaque)
sibling still leaves `DERIVED_SYSTEM_OPENSSL_ONLY` firing, by design: `object_postures`
never reports `unknown` for an object that could not be read at all, only for one that
was read and said so, the same way `_aggregate`'s own `unanswered` signal stays separate
from it.

**The wheel's own SBOM carries the same claim as a per-object `unknown` -- unless it is
naming the very object that already reads `system`.** `object_postures` reads only
per-object binary evidence, so a per-object `unknown` says nothing about an SBOM
component naming `openssl-sys` beside a system object, and neither does the reverse: a
system-linked object's own posture says nothing about a wheel-level SBOM component by
itself. `linkage.declared_by_sbom` reads the wheel-level SBOM signal directly (the same
`_declared_by_sbom` `resolve_linkage` folds into `_aggregate`), and a `linkage` match
takes it as `sbom_declared`: `DERIVED_SYSTEM_OPENSSL_ONLY` adds `sbom_declared = false`
to its match, and `DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM` takes `sbom_declared = true`
on the same `value = "system"` match and carries `OPAQUE`, naming the SBOM component
through `SBOM_CRYPTO_COMPONENT` rather than an object.

Before either rule reads it, `declared_by_sbom` drops one shape of component name from
consideration: one also carried, as its own crate, by an object whose own posture
already reads `system` (`linkage._sbom_names_confirmed_by_system_objects`, over the same
per-object cargo paths `BIN_RUST_CRYPTO_CRATE` reads). A single object
`demo/_rust.abi3.so`, `needed = (libc.so.6, libssl.so.3)`, `rust_crates =
(openssl-sys 0.9.117,)`, reads `system` on its own evidence alone; a wheel SBOM naming
that same `openssl-sys` component is the ordinary shape of that build declaring its own
dependency, not a second, unaccounted-for copy, so it does not cost
`DERIVED_SYSTEM_OPENSSL_ONLY`'s "every piece of evidence points at the system library"
claim, and the wheel keeps `DERIVED_SYSTEM_OPENSSL_ONLY` rather than gaining
`DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM`. A second, unrelated object in the same wheel
that answers `unknown` (or a component whose crate no `system`-posture object carries at
all) still moves it, because then the SBOM component is not restating what a
system-reading object already said. `openssl_linkage` itself never moves either way: an
`unaccounted` SBOM component beside a system object gains `OPAQUE` in `classes` and
loses `DERIVED_SYSTEM_OPENSSL_ONLY`'s "acceptable condition" statement, but keeps its
`CONDITIONAL` headline through `SBOM_CRYPTO_COMPONENT`, which every such component also
fires (`openssl`, `openssl-sys` and `openssl-src` are all `CONDITIONAL`). `openssl-src`
is never confirmed this way and so never gains the exemption: it is a build-script-only
dependency that never itself shows up in a compiled object's own cargo paths (its own
`why` in `ruleset.toml` says so), so a wheel whose SBOM names it beside a system object
always reads `DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM`, whatever else the wheel carries.

*Rejected: widen the exemption to any object whose cargo paths show the same crate,
whatever that object's own posture.* The exemption exists because the object already
answered `system` on its own evidence, not because it happens to share a crate name with
the SBOM component; extending it to an object reading `unknown`, `bundled`, `static` or
`mixed` would let a component escape `DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM` beside an
object whose own posture says nothing about which copy that component names, the exact
claim the finding exists to keep off the record.

## A static OpenSSL's legacy primitives lead the headline; the linkage condition says why

**Accepted, knowing what it costs.**

Reading `.symtab` local definitions beside a present `.dynsym` (above) surfaces a
static OpenSSL's own low-level API: `BF_*`, `MD4_*`, `SHA1_*` and `RIPEMD160_*` are
entry points OpenSSL defines itself, and so is its Curve25519 code. The `curve25519`
symbol group names every spelling OpenSSL itself uses for an X25519/Ed25519 entry
point: 1.1.1's `X25519`/`ED25519_*`, 3.x's `ossl_x25519`/`ossl_ed25519_*` provider
names, and the internal `x25519_fe51_*`/`x25519_fe64_*` field-arithmetic helpers both
versions define wherever the build includes the assembly path, in libcrypto's
`crypto/ec` code rather than in a provider. A static 1.1.1 build also defines
`X25519_public_from_private`, itself internal rather than public API; naming
OpenSSL's own spellings, not only the field helpers, is what keeps the finding the
same on every architecture rather than only where the assembly path exists. A
statically linked copy, even one a version script kept out of `.dynsym`, matches
`BIN_BCRYPT_BLOWFISH`, `BIN_OWN_WEAK_HASH_IMPL` and `BIN_CURVE25519` alongside
`BIN_STATIC_OPENSSL`, and a bundled `libcrypto` matches `BIN_BCRYPT_BLOWFISH` and
`BIN_OWN_WEAK_HASH_IMPL` the same way through its own `.dynsym` exports alongside
`BIN_BUNDLED_OPENSSL` -- that path needs no `.symtab` read at all. None of
`BIN_CURVE25519`'s OpenSSL names is part of libcrypto's public API and so is not
exported, so a bundled copy matches it too only if the bundle still carries its own
`.symtab`. Every one of those three carries `NON_APPROVED_CRYPTO`, which outranks
`BIN_STATIC_OPENSSL`'s and `BIN_BUNDLED_OPENSSL`'s `CONDITIONAL` in `[verdict]
precedence`, so such a wheel's headline is `NON_APPROVED_CRYPTO`.

**Why this is correct rather than a false positive.** The taxonomy's own definition of
`NON_APPROVED_CRYPTO` is cryptography that no validated module provides: a primitive no
approved standard specifies, or an approved algorithm outside any validated module. A
statically linked OpenSSL does bundle Blowfish, MD4 and the rest -- primitives no
approved standard specifies -- and because it is static the host FIPS provider has no
way to refuse them -- the exact argument `BIN_OWN_WEAK_HASH_IMPL`'s own `why` makes for
a private implementation. The record is telling the truth; the tool's accepted error
direction is over-flagging, and it has no passing class to be tricked into.

**Why an import of the same names gets a separate rule.** Calling `BF_encrypt` through
a library the wheel links neither implements nor bundles Blowfish, so
`NON_APPROVED_CRYPTO`'s own "implements or bundles" definition does not fit it, and
`BIN_BCRYPT_BLOWFISH` above matches only a definition. `NON_APPROVED_CRYPTO` on the
import was rejected for that reason. Leaving the import unmatched was rejected too: an
object that names `BF_encrypt` against a library other than OpenSSL (only `libc.so.6`
in `DT_NEEDED`, say) trips no OpenSSL linkage rule either, and a record with no finding
there would read `NO_CRYPTO_DETECTED`, which `BIN_LINKED_CRYPTO_LIBRARY`'s own `why`
calls the one thing a headline field must never do. `BIN_BCRYPT_BLOWFISH_IMPORTED`
keeps a class under the import instead, at `CONDITIONAL`: the library that answers the
call governs it, and `verdict.conditions.openssl_linkage` says whether that library is
the host's `libcrypto`. OpenSSL's low-level `BF_` functions sit outside its provider
mechanism, so a FIPS-enforcing host does not necessarily refuse a call resolved there
the way it refuses one made through EVP, which is why this goes to a human rather than
being read as acceptable. A bundled `libcrypto` that answers the call defines
`BF_encrypt` itself and carries `BIN_BCRYPT_BLOWFISH` on its own object, so nothing here
changes what a bundled or static copy reads.

**Why a narrower `binding` was rejected.** The finding is already `binding = "defined"`,
so nothing sharpens it there. The distinction that would help -- exported versus kept
local by a version script -- needs a third `SymbolMatch.binding` value the record
contract does not have, which the entry above leaves as a contract decision nobody has
asked for. It would also fail the tool's own admission test: a hidden-visibility C or
Rust extension that compiles its own `MD5_Init` or bcrypt has only a local definition,
and an exported-only binding would let exactly that object read clean. The names do not
separate the two either -- `BF_`, `MD4_`, `MD5_` and `RIPEMD160_` are OpenSSL's own
prefixes, not something written to look like OpenSSL.

**Why co-occurrence-aware precedence was deferred.** Making `verdict.class` depend on
which rules fired together needs a new match kind and changes what `verdict.class`
means for every wheel, not just this one. It is the more thorough answer, but it wants a
corpus wider than the 18 wheels measured for `.symtab` local definitions before anyone
changes precedence.

**Why dropping the field helpers was rejected.** The field helpers are not a separate
match: `x25519_fe51_*`/`x25519_fe64_*` reach `BIN_CURVE25519` through the same generic
`x25519_` prefix that also catches every other lowercase X25519 implementation,
OpenSSL's or not. The alternative actually weighed was dropping that reach, so every
static OpenSSL, with or without the assembly path, reads consistently silent about a
primitive it still bundles. That was rejected because there is no way to narrow the
match to only OpenSSL's own field helpers without narrowing the `x25519_` prefix
itself, which would also drop the group's hits on every other implementation's plain
`x25519_*` names, breaking the rule that absence of evidence is not evidence of
absence. Naming OpenSSL's other spellings (`X25519`/`ED25519_*`,
`ossl_x25519`/`ossl_ed25519_*`) alongside the generic prefix is what lets a static
build without the assembly path still be found, on any architecture; a bundled copy
still needs a kept `.symtab` to match any of them, field helpers included. A residual
worth recording: BoringSSL and an unprefixed C build of AWS-LC FIPS also export
`X25519` and `ED25519_sign`, so this widens nothing new for either -- a static
BoringSSL already reads `NON_APPROVED_CRYPTO` through `BIN_BORINGSSL`, and both read
`BIN_CURVE25519` through `X25519_public_from_private`/`X25519_keypair` under the
group's plain `X25519_` prefix on their own, independent of the OpenSSL-specific names
above.

**What it costs.** The headline for a static or bundled-OpenSSL wheel that carries any
of these three legacy groups drifts to `NON_APPROVED_CRYPTO`. `confluent-kafka` is the
measured static instance; the bundled path fires through ordinary `.dynsym` exports on
any auditwheel-vendored `libcrypto`, which is the more common manylinux shape, so the
affected population is wider than the static case alone -- this entry's corpus measured
only the static side. An index page that sorts on the headline alone will surface both
there rather than under `CONDITIONAL`. Nothing is lost from the record: `verdict.classes`
keeps `CONDITIONAL` alongside it, and `verdict.conditions.openssl_linkage` is the field
that answers the actionable question, "does this wheel carry its own OpenSSL" -- though
not, on its own, whether the headline came from that OpenSSL or from a weak primitive
the wheel's own code defines, when a wheel has both.

**Revisit if** a second, non-OpenSSL case turns up where a bundled library's own contents
dominate a wheel's headline the same way, or a consumer asks to tell an exported symbol
from a local definition -- either is the moment for a co-occurrence match kind or a
third binding value, measured over a wider corpus than this one.

## Suppression is keyed on rule, subject and object

**Accepted.**

`suppressed_by` keys on the hit, not the rule id: a hit is suppressed only where a
suppressing hit fired on the same `Location.path`. That gives a FIPS-built and a stock
Go binary in one wheel each their own finding, with the stock one's `locations` naming
only the stock object, and it gives two subjects of one rule a way to relate to each
other, through the entry-level field below. Keying wheel-wide, on the rule id alone,
would instead drop the suppressed rule's whole finding, not just the locations that
earned it, the moment the suppressor fired anywhere in the wheel. An object read out of
a static archive has its own path (`lib.a(member.o)`), so a suppressor in one archive
member never suppresses a finding in another; that over-flags, the direction this tool
is built to err in. Being keyed on the hit's path also means a suppressor whose hits are
located on a different kind of path never suppresses, because their hits never share a
path -- and what a rule's hits locate on follows its matcher kind, not its `layer`, and
not "wheel-scoped versus per-object" either. `MATCHER_LOCATIONS`, declared once beside
`MATCHER_KINDS` in `ruleset.py`, is the one place that says which class of
`Location.path` each matcher kind locates on; a test holds every declaration there to
what the engine actually locates on, so a relation the loader accepts is one that can
fire. A `linkage` match with `object_values` set is the one exception: it locates per
object instead, one `Hit` per object whose own posture matched, at that object's own
path -- `DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM` is the shipped example, so it *does*
share a path with a per-object binary rule on the same object. `scan_error` and
`record_mismatch` locate on whatever path the error or mismatch concerns, so a relation
naming either one is always accepted; every other pairing outside a kind's own declared
class is refused at load time.

A `[[rust_crate]]` entry can also carry its own `suppressed_by`, naming other
`[[rust_crate]]` entries, so two crates that stay on one rule can relate. The loader
resolves each name to the finding key it stands for -- `(owning rule id, crate name)`
-- through that crate's own routing or the table's default rule, and refuses a name
that is unknown, self-referential, owned by no single rule, or carried by a crate with
no single owner of its own. Scope stops at `[[rust_crate]]`: it is the only table this
has been measured for, and the loader refuses the field on any other table.

**No shipped entry carries one.** The shipped AWS-LC relation is rule-level:
`aws-lc-rs` is routed to its own rule, `BIN_AWS_LC_RS_CRATE`, `aws-lc-fips-sys` to its
own, `BIN_AWS_LC_FIPS`, and `BIN_AWS_LC_RS_CRATE` names `BIN_AWS_LC_FIPS` in its
rule-level `suppressed_by`. That way the FIPS build suppresses the aws-lc-rs finding on
the same object even when it is identified by the symbol prefix alone, with no
`aws-lc-fips-sys` cargo path anywhere in the object -- a measured FIPS build carries
none (see "An AWS-LC FIPS build is told from a stock one by its symbol prefix, not its
name" below). Routing, not an entry-level relation, does the suppressing here, because
the FIPS evidence that must do it is a whole rule's finding -- symbol prefix, cargo
path or version string -- not a crate subject; an entry-level key
`(owning rule, crate name)` could only name the `aws-lc-fips-sys` cargo-path subject,
and that subject is exactly the one absent on the measured build. `aws-lc-sys` stays on
the default crate rule and is not suppressed by `BIN_AWS_LC_FIPS`: it names the stock
build, so a wheel carrying both crates still reads `NON_APPROVED_CRYPTO`. Nor is
`rustls` related to anything: it says something its provider crate does not, that a TLS
stack ignores the system crypto policy, and whether it runs in FIPS mode is a runtime
configuration choice a provider-crate relation cannot answer. Entry-level
`suppressed_by` stays as a documented capability for two crates that stay on one rule
even with no shipped user: `--ruleset PATH` is a public entry point, and the mechanism
is fully guarded at load time, so keeping it costs nothing at scan time.

Suppression is non-cascading: what fired is read once, from every candidate finding,
before anything is dropped, so a suppressor that is itself suppressed still suppresses.
The per-object, per-subject key keeps that one-pass shape, which means a cycle (rule A
suppressed by rule B, B suppressed by A; the same shape between two crates; or a mix of
the two) would drop every member of it when all of them fire, losing evidence rather
than choosing the more specific finding. The loader refuses a `suppressed_by` cycle
across rules and crates at load time instead, including one closed by a crate that
carries the field itself with no owning rule of its own.

`sbom_component` honours the same relations, keyed on the SBOM document as the object.
A `[[rust_crate]]` component in one SBOM carries the relations its crate has on a
binary object: its own entry-level `suppressed_by`, and every crate whose owner is
named in this crate's owning rule's rule-level `suppressed_by`
(`Ruleset.crate_suppressors` in `ruleset.py`). An SBOM naming both `aws-lc-rs` and
`aws-lc-fips-sys` in one document reports only the FIPS build's `CONDITIONAL`, the
same way the pair reads on one binary object. A crate that `linkage._declared_by_sbom`
can count towards moving a library's `<name>_linkage` field cannot carry a suppressor of
its own: the loader refuses one, because a suppressed SBOM finding would leave that
field moved with nothing left in the record to say why -- the shipped ruleset's OpenSSL
crates carry no such relation, so they pass.

**Accepted over-flag: SBOM and binary evidence never suppress each other, because they
never share a `Location.path`.** An SBOM naming `aws-lc-rs` beside a FIPS *binary*
object, rather than beside `aws-lc-fips-sys` in the SBOM's own document, still reports
both findings, and so does a split across two separate SBOM documents. Both stay
over-flagged, the direction this tool is built to err in, rather than given a mechanism
that widens what the key means across sources of evidence nothing has measured a need
to relate.

**Revisit if** a table other than `[[rust_crate]]` needs a subject-level relation, a
real SBOM names `aws-lc-fips-sys` without `aws-lc-rs` compiling against it in the same
document, a real SBOM splits the aws-lc-rs/aws-lc-fips-sys pair across two documents and
the remaining over-flag is worth a cross-document key, or entry-level `suppressed_by`
still has no shipped or reported user when some other change next needs to touch it --
that is the moment to remove it rather than carry it.

## An AWS-LC FIPS build is told from a stock one by its symbol prefix, not its name

**Accepted.**

`aws_lc` matches `AWS-LC` and `aws-lc` in read-only data, and lowercase `aws-lc` also
matches any cargo source path containing it, including both `aws-lc-fips-sys` and
`aws-lc-rs`. `BIN_AWS_LC` has no way to tell the validated build from the stock one, so a
FIPS build reads `NON_APPROVED_CRYPTO` with nothing to suppress it, the same shape the Go
FIPS entry above describes for Go's own stock crypto rule.

**Measured rather than reasoned**, building one program two ways on linux/x86_64: a small
Rust program calling `digest::SHA256` through `aws-lc-rs` 1.18.1, once with
default-features off and feature `aws-lc-sys` (pulling `aws-lc-sys` 0.45.0), once with
feature `fips` (pulling `aws-lc-fips-sys` 0.14.2, AWS-LC FIPS 4.2.0). Each was scanned
stripped and unstripped, packaged as a manylinux wheel.

| | stock | FIPS |
|---|---|---|
| `AWS-LC FIPS 4.2.0` (version string) | absent | 1, in `.text` |
| `AWS-LC FIPS failure caused by:` | in the source of both builds | 1, in `.text` |
| `aws_lc_fips_0_14_2_*` names in `.symtab` | 0 | 2118 (local definitions) |
| `aws_lc_0_45_0_*` names in `.symtab` | 27 | 0 |
| `BORINGSSL_bcm_text_hash`, `BORINGSSL_integrity_test` | absent | present |
| cargo path `aws-lc-fips-sys` / `aws-lc-sys` | absent | absent |
| cargo path `aws-lc-rs-1.18.1` | present | present |
| `/aws-lc/crypto/*.c` paths in `.rodata` | present | present |

Four things follow from that table.

**ELF searches executable sections for this one group.** AWS-LC's FIPS build moves the
module's constants into its own `.text` so the integrity hash covers them, and every
`[[string_group]]` entry that flags `in_code` is searched for there too, alongside the
allocated, non-executable sections every group is searched in already. `aws_lc_fips` is
the one group that carries the flag: a stripped object loses the symbol prefix below,
and the version string in `.text` is what still identifies it. See "A version banner
that lives in code is read from executable sections, for the groups that say so",
further down, for the read itself, its budget and what it costs.

**What separates the builds when the version string is absent is the symbol prefix
`aws-lc-fips-sys` applies: `aws_lc_fips_<major>_<minor>_<patch>_`, where the stock
build uses `aws_lc_<major>_<minor>_<patch>_`.** These are local definitions in
`.symtab`, which the ELF reader reads when `.dynsym` is present. A stripped object
loses them, and then the version string in `.text` is what is left; an unstripped
object carries both, so the version string there is redundant evidence rather than
the only signal. Stripping
removes `.symtab` and `.strtab` outright, so there is no local name left to read; that
evidence is gone, not missing a reader.

**A bare `AWS-LC FIPS` substring would be wrong**, because `AWS-LC FIPS failure caused
by:` is compiled from both builds' source -- the measured stock build's linker drops the
failure message entirely, but a stock build that kept it would carry it outside `.text`,
where this group would still see it -- and a version digit with nothing else is
still too loose: it also matches prose such as `AWS-LC FIPS 140-3 validated` and
`AWS-LC FIPS 3's legacy provider failed to load`, neither of which names a build. The
group mirrors `openssl_banner` and requires a dot after the digit for the same reason.
No AWS-LC FIPS release has shipped a two-digit major: `gh api
repos/aws/aws-lc/git/matching-refs/tags/AWS-LC-FIPS` lists 1.x, 2.0.x and 3.0.0 through
3.3.0, and the measured build here is 4.2.0. The dot costs nothing today; if a
two-digit major ever ships, this group needs a further, undotted entry for it, listed in
"Revisit if" below.

**Suppressing `BIN_AWS_LC` alone does not move the headline**, because the `aws-lc-rs`
crate finding is always present too on a real build, owned by the default
`BIN_RUST_CRYPTO_CRATE` rule alongside every other crate suppression cannot reach. It
needs a rule of its own, `BIN_AWS_LC_RS_CRATE`, so `BIN_AWS_LC_FIPS` can suppress it:
measured on aws-lc-rs 1.18.1, a FIPS build carries the `aws-lc-rs` cargo path and no
`aws-lc-fips-sys` path, so without this a validated build reads as non-approved through
the crate alone. `aws-lc-sys` stays on the default rule and is not suppressed: it
names the stock build, so a wheel carrying both crates still reads `NON_APPROVED_CRYPTO`.

**BoringCrypto's names are not used by `aws_lc_fips`.** BoringCrypto's FIPS module and
AWS-LC's share `BORINGSSL_bcm_*` and `BORINGSSL_integrity_test`, so listing them in this
group would label a BoringSSL FIPS object as AWS-LC. A fork-neutral rule uses one of
them instead, below.

**What it costs.** `CONDITIONAL`, never a pass: the validated module is compiled in, but
it is a bundled static copy rather than the system provider, and which certificate
covers the compiled version is not something the wheel states. Suppression is per object
(above): a wheel shipping one FIPS object and one stock AWS-LC object keeps
`NON_APPROVED_CRYPTO` in `classes` for the stock object's own finding, with the
condition reported alongside it for the FIPS object rather than in place of it.

**An unstripped FIPS object keeps `NON_APPROVED_CRYPTO` in `classes` too, and not for an
unrelated reason: `curve25519_x25519` (`BIN_CURVE25519`) and `md5_final`
(`BIN_OWN_WEAK_HASH_IMPL`) are primitives the object defines, not evidence that happens
to sit near the FIPS module.** AWS-LC's FIPS module links as one monolithic `bcm` object,
so every algorithm it implements ships with it; the stock build's `gc-sections` drops
the ones nothing calls. Measured with `nm` on the same aws-lc-rs 1.18.1 build:
`curve25519_x25519` (s2n-bignum) and `md5_final` sit right next to
`aws_lc_fips_0_14_2_MD5_Final` in the unstripped FIPS object, and neither symbol appears
at all in the stock one. Neither is suppressed by `BIN_AWS_LC_FIPS`, and neither should
be: README defines `NON_APPROVED_CRYPTO` as implementing or bundling a non-approved
primitive, and these are exactly that. Suppressing them because a FIPS module is also
present in the object would decide the object is fine on balance, which is the
verdict-making call the taxonomy leaves to a human.

**A stripped FIPS object is where this asymmetry shows.** `curve25519_x25519` and
`md5_final` are local definitions in `.symtab`, the same table stripping removes
outright, so a stripped FIPS object never carries them: that evidence is gone on its
own, independent of anything read from `.text`. What the code read settles is whether
the object is *identified* as FIPS at all once those two are gone. Without a version
string in `.text`, a stripped FIPS object has nothing left to tell it apart from stock
and reads `NON_APPROVED_CRYPTO` through `BIN_AWS_LC` and `BIN_AWS_LC_RS_CRATE` alone --
correct in the sense that the taxonomy has no passing class to reach for, but not
because of any primitive the object is shown to define. With the version string read
from `.text`, the same stripped object reads `CONDITIONAL` alone: `BIN_AWS_LC_FIPS`
fires and suppresses both, and nothing else in the object defines a non-approved
primitive of its own. This is the real-world shape a release wheel ships in -- stripped,
with the version string as the only surviving evidence. `CONDITIONAL` is reached
whenever the FIPS build is identified -- by the symbol prefix, the cargo path, or the
version string, on every format the group is searched in -- and the object defines no
non-approved primitive of its own; `BIN_AWS_LC_FIPS` replaces `BIN_AWS_LC` and
`BIN_AWS_LC_RS_CRATE` among the findings behind `NON_APPROVED_CRYPTO` either way, naming
the FIPS condition alongside whatever primitives keep the class, rather than in place of
them. An SBOM naming both `aws-lc-rs` and `aws-lc-fips-sys` in the same document reads
the same way: the FIPS crate's `sbom_component` finding drops the `aws-lc-rs` one on the
strength of the same relation (see "Suppression is keyed on rule, subject and object"
above). A test pins the unstripped case directly:
`test_an_aws_lc_fips_modules_own_md5_and_x25519_keep_non_approved_leading` extends the
measured FIPS fixture with `md5_final` and `curve25519_x25519` as local `.symtab`
definitions, and the record it produces reads `NON_APPROVED_CRYPTO` with `CONDITIONAL`
in `classes` and `BIN_AWS_LC_FIPS`, `BIN_OWN_WEAK_HASH_IMPL` and `BIN_CURVE25519` all
present in `rule_ids`.

The distinction is ruleset data alone: two groups, one of them additionally read from
executable sections, and two rules, read by readers that treat AWS-LC no differently
from any other library.

**Revisit if** a C build of AWS-LC FIPS (unprefixed) shows up in a wheel, since
`BIN_AWS_LC` is not suppressed by the fork-neutral FIPS-module rule below and such an
object still reads `NON_APPROVED_CRYPTO` through `BIN_AWS_LC` rather than through the
FIPS condition alone; or AWS-LC FIPS ships a two-digit major, which this group's
dot-anchored digits do not cover.

## A version banner that lives in code is read from executable sections, for the groups that say so

**Accepted, and it changes verdicts.**

AWS-LC's FIPS build delocates the module's constants -- including its own version
banner -- into `.text`, so its integrity hash covers them. Measured on the FIPS build
above (aws-lc-rs 1.18.1 + `fips`, aws-lc-fips-sys 0.14.2, linux/x86_64): `AWS-LC FIPS
4.2.0` sits at file offset `0x8ae5c`, and `AWS-LC FIPS failure caused by:` at `0xd0888`,
both inside `.text` (`0x1000`-`0x2ed845`). `_collect_string_bytes` reads only allocated,
non-executable sections, on purpose (see "Sections are found by type, not by a name
nobody checks" and the compressed-section entry above): `.rodata`-like data, plus
`.comment`. Neither string sits there in this build.

**Only the groups that ask are searched for in code.** A `[[string_group]]` entry can
set `in_code = true`; today only `aws_lc_fips` does. Every other group's evidence model
stays read-only sections only. The ELF reader skips the code read outright, at zero
cost, when nothing is flagged --
`patterns.code_string_locator` is `None` for a ruleset that flags nothing, and
`_collect_code_regions` is never called.

**The search itself is one compiled byte regex, in C, the same shape
`BinaryPatterns.symbol_locator` already is.** `_code_string_locator` builds a trie over
every flagged group's substrings, exactly as `_symbol_locator` does over symbol names,
sharing the trie-building code between them (`_trie_locator`, parameterised by what can
separate one matched byte from the next: `_SANITIZED_AWAY` for a name padded with
control bytes in a string table, nothing at all for a substring read straight out of
code). A Python loop over a large `.text` is the cost `AGENTS.md` already measures at
nineteen seconds against 1.2 for the compiled-regex version, over a 2 MiB string table;
`.text` is routinely far larger than that in a CUDA or PyTorch wheel.

**A hit is turned into a window, not a full extraction of the section.** The locator
finds byte offsets worth decoding; `binfmt.strings.find_code_strings` extracts and
matches only a `max_evidence_chars`-wide window around each hit, not the whole section.
Overlapping windows are merged into one before extraction, so a `.text` full
of the same banner repeated -- the adversarial case, not a corner one, since a build
that emits the string at all often emits it from one code path called from several
places -- collapses to close to the region's own size rather than to one window per
hit: `tests/test_binfmt_strings.py` measures 10,000 repetitions joining to near the
region's own size, not the several million bytes one window per hit would cost.

**Code is read against its own budget, independent of the read-only pass's.**
`_collect_code_regions` spends `max_strings_bytes` again, but separately:
`_collect_string_bytes` already bounds `.rodata`-like evidence on its own, and a
`.text`-heavy object reading code must not leave it any less room, nor the reverse.
Sharing one budget between the two would let whichever section a reader happened to
visit first starve the other of room regardless of which one actually carried the
evidence a wheel was scanned for.

**An unread or truncated code region records no error and no partial reason,** unlike
every other truncation this reader names. The read-only strings pass's own overrun
names `strings_bytes_unread` because that pass is general evidence -- anything printable
in read-only data. The code read is not: it exists for one purpose, telling a validated
build apart from a stock one, and a group is only worth flagging `in_code` when missing
it errs toward over-flagging -- the direction this tool already accepts (see the
`in_code` entry in `data/ruleset.toml`'s own `why` for the group, and
`docs/ruleset.md`). Missing the banner leaves the object reading whatever its read-only
evidence already gives: usually the stock, over-flag reading, but `NO_CRYPTO_DETECTED`
for an object with no other AWS-LC evidence at all. Giving
that a `partial_reasons` token would need every large object with executable code and no
hit -- which is most of them, and includes every CUDA and PyTorch `.so` in the corpus --
to carry it, pushing them onto the triage list as `OPAQUE` for a read that was never
general evidence to begin with, and the "every recordable failure maps to a rule"
invariant would need a rule for a cause that is not a failure.

**What was rejected.** Reading `.text` into the general read-only strings pass, so every
group would be searched in code: the evidence model for every group but this one is
"read-only data", stated as an invariant of `_collect_string_bytes` itself, and widening
it for every group multiplies the cost measured above by however many groups the
ruleset carries, for groups with no measured reason to live in code at all.
BoringCrypto's own integrity-test names (`BORINGSSL_bcm_text_hash`,
`BORINGSSL_integrity_test`) were considered as a code-independent alternative and
rejected for the same reason the symbol group excludes them already: AWS-LC's FIPS
module shares them with BoringSSL's, so they would not separate the two.

**Revisit if** a second group needs the same treatment: `in_code` is already
general-purpose, a per-group ruleset flag rather than a name hardcoded into the reader,
so flagging one costs only the measurement that justifies it and a `why` saying missing
it errs toward over-flagging.

## A BoringSSL FIPS module is told from a stock build by its integrity test, not its strings

**Accepted.**

`boringssl` matches `BoringSSL` and `boringssl` in read-only data, and `BIN_BORINGSSL`
has no way to tell Google's separately validated BoringCrypto build from a stock
BoringSSL build, the same gap the AWS-LC entry above describes for its own fork.

**Measured rather than reasoned.** Three Go programs calling `crypto/sha256`, built
`GOEXPERIMENT=boringcrypto` (once unstripped, once `-ldflags='-s -w'`) and stock,
alongside a stripped stock BoringSSL object (`grpcio`'s `cygrpc` extension, which links
BoringSSL directly rather than through Go):

| | stock BoringSSL (`grpcio`, stripped) | BoringCrypto (Go, syso and built binary) |
|---|---|---|
| `BoringSSL` string outside `.text` | present | present, in `.rodata` |
| `BoringCrypto`, `BoringCrypto Key`, `FIPS self test` strings | present | present |
| `BORINGSSL_integrity_test` | absent | a local definition in `.symtab`, unstripped only |
| go_boring strings (`crypto/internal/boring`, `boringcrypto`) | absent | present |

**The strings do not separate the builds.** `BoringSSL`, `BoringCrypto` and `FIPS self
test` all appear in the stock `grpcio` object measured above, so a group built from any
of them reads a stock build as a FIPS one. The stock side of the `BORINGSSL_integrity_test`
row is source reading together with the AWS-LC stock measurement above, not a second
unstripped stock BoringSSL object: upstream defines the symbol only inside
`#if defined(BORINGSSL_FIPS)` and `#if !defined(OPENSSL_ASAN)`, and its header documents
it as existing only in a FIPS build without ASAN. AWS-LC shares the same module source,
and its own stock build, measured above, carries no such symbol either.

**What separates the builds is `BORINGSSL_integrity_test`, the module's own power-on
self-test entry point, and nothing else.** It is a local `.symtab` definition, read the
same way `aws_lc_fips`'s local definitions are read above, so a stripped static object
loses it and reads as stock BoringSSL -- the over-flag direction this tool errs in, and
the same shape the AWS-LC entry accepts for its own stripped case. A shared-library
build exports the symbol instead of keeping it local, so it survives in `.dynsym` after
stripping removes `.symtab` (source reading: `crypto.h` declares it `OPENSSL_EXPORT`; no
shared FIPS build was measured). The rule's `binding = "defined"` covers both shapes, a
local `.symtab` definition and an exported `.dynsym` definition, while an object that
only *imports* the symbol from elsewhere still fails to match: it contains no module.

**The rule is fork-neutral.** `BORINGSSL_integrity_test` is compiled from source AWS-LC's
FIPS module shares with BoringCrypto's, so a rule built on it names a FIPS build of the
BoringSSL-lineage module, not which fork produced it -- the fork itself is still named by
`BIN_BORINGSSL`'s or `BIN_AWS_LC`'s own strings, unaffected by this rule. It suppresses
only `BIN_BORINGSSL`: closing the equivalent C-built AWS-LC FIPS gap for `BIN_AWS_LC` is
left to the "Revisit if" above, since naming it here would explain a decision this entry
does not make.

**A Go BoringCrypto binary also suppresses `BIN_BORINGSSL` through its own marker.**
Every Go binary built with the BoringCrypto backend vendors BoringSSL's C source, so it
carries `BoringSSL` in `.rodata` regardless of whether the integrity-test symbol survives
stripping -- without this suppression, the stripped Go binary keeps `BIN_BORINGSSL` as
its only non-approved finding. `BIN_GO_BORING_CRYPTO`'s own strings
(`crypto/internal/boring`, `GOEXPERIMENT=boringcrypto`, a bare `boringcrypto`
substring) are absent from the stock `grpcio` object measured above, so this suppression
did not reach the stock build measured here; the bare substring carries no Go-binary
gate of its own, so it is not ruled out for every non-BoringCrypto build in general.

**What it costs.** `CONDITIONAL`, the same reasoning as the AWS-LC entry: the module
being compiled in is not the same as it being in force, and which certificate covers the
compiled version is not something the wheel states. A stripped static BoringSSL object
that carries neither the integrity-test symbol nor a Go marker still reads as stock
`NON_APPROVED_CRYPTO`, the accepted over-flag direction. An unstripped BoringCrypto
binary keeps `NON_APPROVED_CRYPTO` in `classes` too, and not for an unrelated reason:
its own primitives (`BIN_CURVE25519`, `BIN_OWN_WEAK_HASH_IMPL`) are left unsuppressed,
the same call the AWS-LC entry makes for its module's own primitives.

**Revisit if** a C-built BoringSSL FIPS module is measured carrying a string only its
FIPS build has, in `.text`, which is where its constants move on ELF the same way
AWS-LC's do: a group flagged `in_code` would read it there (see "A version banner that
lives in code is read from executable sections, for the groups that say so" above); or
an unstripped stock BoringSSL object is found carrying `BORINGSSL_integrity_test`, which
would mean the `#if defined(BORINGSSL_FIPS)` guard this rule relies on no longer holds.

## Every symbol group is read by a rule, or says it is evidence only

**Accepted, and it changes verdicts.**

A `[[symbol_group]]` the binary readers record but no rule reads is evidence gathered
and thrown away: a defined `argon2id_hash_raw`, alone in an object with no other
evidence, would read `NO_CRYPTO_DETECTED` with nothing but `WHEEL_GENERATOR` in the
record, because no rule looks at the `argon2` group `binfmt` populates. `blake`'s
*string*-group match alone has the same gap: a reference implementation compiled in
with no banner string carries nothing that arm matches.

**What closes the gap.** Argon2 gets its own rule, `BIN_ARGON2`: `NON_APPROVED_CRYPTO`,
`binding = "any"`. `blake` is read by `BIN_NON_CRYPTO_HASH` as a second `[[rule.match]]`
arm beside its existing `binary_string` one, keeping `CONTEXT_DEPENDENT`; the engine
folds a `binary_string` hit and a `dynamic_symbol` hit on the same group into one
finding, since a rule's hits key on `(rule id, subject)` and the group name is the
subject either way.

**Why `any` binding for Argon2 and blake.** Measured with `nm -D --defined-only` on
Fedora, OpenSSL 3.5.8:

| | exports an argon2*/blake2*/blake3 name |
|---|---|
| `/usr/lib64/libcrypto.so.3` | none |
| `/usr/lib64/libargon2.so.1` | `argon2_ctx`, `argon2d_hash_raw`, ... |
| `/usr/lib64/libb2.so.1` | `blake2b_init`, `blake2b_final`, `blake2bp_init`, ... |

OpenSSL's own Argon2 is reachable only through `EVP_KDF`, never through these entry
points, so an *imported* `argon2id_hash_raw` or `blake2b_init` can only mean a
dependency on libargon2 or libb2 (or an equivalent), never a call the host FIPS
provider could answer. No other rule in this class has that clean a split: `nm -D
--defined-only` on the same libcrypto shows 8 `BF_*` exports and both `MD5_*` and
`SHA1_*`, so an import of those names could be the host library instead of the wheel's
own copy, which is why `BIN_BCRYPT_BLOWFISH` and `BIN_OWN_WEAK_HASH_IMPL` do not share
Argon2 and blake's `any` reasoning.

**The loader check.** `parse_ruleset` refuses a ruleset where some `[[symbol_group]]` is
neither read nor marked as evidence. A group counts as read when some rule's
`dynamic_symbol` match names it, through `group` or `groups`, or when some
`[[crypto_library]]` names it as its own `symbol_group`; anything else must carry
`evidence_only = true` on the group, with its `why` saying so. The reverse is refused
too, so `evidence_only = true` cannot go stale on a group a rule is later given: marking
one that something already reads is a load error, not a leftover comment nobody revisits.
This is a load error rather than a test over the shipped ruleset, the same reasoning
`[[symbol_group]]`'s own name and reference checks already use, so a ruleset supplied
through `--ruleset` is inside the guard too.

**`boringssl` and `aws_lc` carry `evidence_only = true`.** `BIN_BORINGSSL` and
`BIN_AWS_LC` already read the same-named *string* groups, which the build writes into
read-only data, so no `dynamic_symbol` rule reads either symbol group. AWS-LC is a
BoringSSL fork and keeps BoringSSL-named symbols -- the `aws_lc_fips` group's own `why`
already notes its FIPS-only `BORINGSSL_*` names are shared with BoringSSL's FIPS module
-- so a rule over the `boringssl` symbol group would report BoringSSL on an AWS-LC
object. `[[crypto_library]] openssl` lists both in `fork_symbol_groups`, which does not
make either one read: a defined fork name only qualifies OpenSSL-named definitions
already on the same object, and alone it raises nothing, so the mark stays. Whether
either deserves a symbol-level rule of its own is left open, below.

**What it costs.** A BLAKE-only object reads `CONTEXT_DEPENDENT` instead of
`NO_CRYPTO_DETECTED`. `CONTEXT_DEPENDENT` outranks both `NO_CRYPTO_DETECTED` and
`OPAQUE` in `[verdict] precedence`, so it can move either headline: a partially read
object that also carries a BLAKE symbol headlines `CONTEXT_DEPENDENT` instead of
`OPAQUE`. An Argon2-only object moves further, to `NON_APPROVED_CRYPTO`, which outranks
`OPAQUE` too.

**Rejected: a `symbol_group` on `[[crypto_library]] argon2`.** It would move `argon2`
linkage and double-report through `BIN_LINKED_CRYPTO_LIBRARY` beside the dedicated
finding a compiled-in Argon2 implementation already gets from `BIN_ARGON2`, and nothing
here calls for a linkage field. **Rejected: a test over the shipped ruleset only.** It
would miss a ruleset supplied through `--ruleset`, the same gap the load-time check
above closes.

**Revisit if** a rule should read the `boringssl` or `aws_lc` symbol names directly,
rather than only through their string-group evidence.

## Crates are read from every cargo source layout, and a vendored crate has no version

**Accepted, and it changes records.**

Crates are read from four cargo source layouts: the crates.io registry layout `cargo
build` uses straight from a checkout, `cargo/registry/src/<index>/<name>-<version>/`;
distro packaging, where Fedora's RPM Rust macros lay a crate out at
`/usr/share/cargo/registry/<name>-<version>/` with no `src/<index>/` segment; `cargo
vendor`, what fromager configures for an offline build, which writes `vendor/<name>/...`
with no `cargo/registry` segment and, without `--versioned-dirs`, no version anywhere in
the path; and a git dependency checkout, `$CARGO_HOME/git/checkouts/<repo>-<16 hex
content hash>/<short rev>/...`, cargo's layout for a crate pinned by a git revision
rather than published to a registry.

**Measured on a Fedora 44 host.** A Fedora `python3-cryptography` build yields 14
crates, nine of them from `/usr/share/cargo/registry/`, including `openssl` and
`openssl-sys`; the other five are Rust std's own vendored dependencies, which every
Fedora-rustc-built object carries regardless. Read through the registry layout alone,
the same object yields none. A cdylib built exactly the way fromager configures cargo --
`cargo vendor vendor` without `--versioned-dirs`, then `[source.crates-io]
replace-with` pointing at it -- embeds paths like `vendor/base64/src/alphabet.rs`, with
no version.

**Measured for the git checkout layout, Fedora 44 host, cargo 1.98.1.** A cdylib built
with `base64 = { git = "https://github.com/marshallpierce/rust-base64" }` and `sha2 =
{ git = "https://github.com/RustCrypto/hashes" }` embeds paths like
`<CARGO_HOME>/git/checkouts/rust-base64-9af66aca7bf9fca2/5b98ee1/src/engine/mod.rs`;
`sha2`, a workspace member of the `hashes` repository, contributed no panic path in this
build. Two facts follow from the layout rather than from the wheel-build tooling. First,
the checkout directory is named after the repository, not the crate: `rust-base64`
holds crate `base64`, and for a workspace repository the crate that actually built lives
in a member directory below it (`hashes-<hash>/<rev>/sha2/src/...`, `rust-openssl-
<hash>/<rev>/openssl-sys/src/...`). Most crypto crates taken this way are workspace
members, so the member directory -- the one immediately holding `src/` -- is the name
read; a root crate with no member directory of its own (`ring`) is read under its
repository's name instead. Second, `CARGO_HOME` is arbitrary -- a custom directory in
this measurement, `/usr/local/cargo` in the Rust Docker images -- so the pattern anchors
on `git/checkouts/` with a boundary rather than on `cargo/git/checkouts/`; the
16-hex-digit content hash plus the short revision that follow are distinctive enough to
anchor on without the `cargo/` prefix.

**How the layouts are matched.** `cargo_path_regex` treats the `src/<index>/` segment as
optional, since distro packaging is the same cargo-registry layout minus that one
segment. The vendor and git-checkout layouts each have their own convention,
`cargo_vendor_path_regex` and `cargo_git_path_regex`, rather than an alternative branch
of the registry pattern: Python's `re` refuses two groups sharing a name in one
alternation, and each layout's rules differ enough to want its own pattern anyway. The
vendor and git-checkout patterns both require the path to reach a `.rs` file, because C
and Go projects vendor trees too -- `vendor/openssl/crypto/evp/evp_enc.c`,
`vendor/golang.org/x/crypto/...go`, and a `-sys` crate's own vendored C sources under its
git-checkout member directory -- and without that anchor a vendored or checked-out C
tree would read as a Rust crate. The crate name excludes `.`, which no crates.io name can
contain, so `vendor/gimli-0.32.3/` (`--versioned-dirs`, or how rustc vendors its own
dependencies) reads as `gimli` `0.32.3` rather than as a crate literally named
`gimli-0.32.3` with no version: a version always opens with digits then `.`, and once
`.` cannot appear in the name, the version's leading `-` is necessarily the last `-`
before the first `.`, so the split is unique whether the name group is lazy or greedy.
Every negated character class in both cargo patterns excludes `\n`, the run separator
`binfmt.strings.RUN_SEPARATOR` joins printable runs with, so a crate is always read from
one printable run and never spliced from two strings that never sat next to each other
in the object.

A `vendor/` tree inside a registry crate's own directory is that crate's own vendored
source, not a crate of its own: `.../bar-1.0.0/vendor/ring/src/x.rs` is read as `bar`
1.0.0, and the nested `vendor/ring/...` match is dropped rather than reported as a
second, unversioned crate. The registry crate's directory is taken to end at the first
`.rs` file on its path, not at the end of the printable run, because rustc packs
`&'static str` panic locations for unrelated crates back to back in read-only data: a
vendor match that starts in the directory components between a registry match and its
own `.rs` is nested and dropped; one that starts after it is a separate path and is
kept. Precedence runs one way only -- a registry match found inside an outer `vendor/`
directory is unaffected, which is the nesting gap this section already documents for
that layout.

**`RustCrate.version` is `str | None`.** A layout that names no version gets a `null` in
the record, never an invented one or an empty string standing in for it -- the same
choice `SbomComponent.version` makes. Widening a required field's type is a
`schema_version` bump under this repo's own versioning table, which is why
`schema_version` is 2; a consumer that calls `crate["version"].split(".")` without a
`None` check needs to know.

**Bounded, not backtracking.** A pattern that has to look ahead for a `.rs` file over an
unbounded run is quadratic on a long stretch of near-misses: an unbounded version of
`cargo_vendor_path_regex` takes about 1.6 seconds at 4,000 repetitions of `"vendor/a/"`
and roughly 40 seconds at 20,000. Every repetition in the shipped pattern is bounded
instead -- the crate name at 64 characters, crates.io's own limit; each path segment at
255; nesting at 16 levels -- and a 200,000-repetition input runs in well under a second.
The bounds alone are not enough against every near-miss shape: a name class that allows
`.` gives the name group and the version group's leading digits more ways to split the
same run of digits and dots, at 3.7 seconds per MiB against 0.4 for the shipped pattern.
Excluding `.`, which no crates.io crate name can contain, closes that off rather than
trading it for a lower size bound. `test_hardening.py` holds both shapes under a time
limit. `cargo_git_path_regex` is bounded the same way, and over 50,000 repetitions of a
repository/hash near-miss and 5,000 repetitions of a member-directory near-miss it runs
in well under a second either way, bounded or not: those two shapes never reach the
intermediate-directory repetition the `{0,16}?` bounds limit often enough to matter.
A run of literal `src/` segments does reach it, because `src/` is itself a candidate
for the pattern's required `src` anchor at every repetition: 50 repetitions of 40
`src/` segments followed by 200 bytes with no `.rs` in sight runs in a couple of
milliseconds bounded, and takes on the order of ten seconds with the `{0,16}?` bounds
on both sides of the anchor widened to an unbounded `*?`. `test_hardening.py` holds
all three shapes under a time limit; only the third pins the bounds themselves rather
than the shipped pattern's speed on a shape they turn out not to matter for.

An unbounded `cargo_path_regex` would have the same shape of problem in a different
place. An unbounded registry pattern whose name allows `.` and runs as an unbounded
greedy match, paired with an unbounded version tail, is quadratic on a long slash-free
segment of `a-1.1.1`-shaped near-misses: every `-` is a backtrack point, and an
unbounded tail re-scans the rest of the segment from each one, at 0.30 seconds at 20,000
characters and 1.24 at 40,000. Only all three together are quadratic: dropping any one
of the unbounded name, the unbounded tail, or the `.` in the name class keeps the shape
linear on its own. The shipped pattern takes the vendor pattern's shape instead -- name
without `.`, lazy, bounded at 64 characters; version tail bounded at 64; index segment
bounded at 255 (`NAME_MAX`) -- which a local check (54 real Rust objects over 200 KiB in
a uv cache, 870 crate reads, `cargo/registry` paths on both separators) found reads the
same (name, version) pairs an unbounded pattern would. With `.` allowed back in and the
same bounds otherwise applied, the cost is 0.10-0.15 seconds per MiB against 0.01-0.03
with `.` excluded, the same 5-10x the digit-and-dot shape above pays.

**What was rejected, and why.**

- *One pattern, one alternation.* Ruled out by Python `re`'s restriction on duplicate
  group names, not a judgement call.
- *Make the registry pattern's version group optional too, to save a second pattern.*
  The registry layout always carries a version; making it optional there would let a
  crate with a name that merely looks like `name-version` (there is no way to tell them
  apart without the version group doing the separating) silently swallow part of the
  name instead.
- *Refuse a `[conventions]` cargo pattern that can match `RUN_SEPARATOR`, at load time,
  instead of excluding it from the pattern.* Sound for a `[[string_group]]` substring,
  which is a literal, but a `[conventions]` entry is an arbitrary regex, and Python
  `re` has no public API to decide whether an arbitrary pattern can match a given
  character; `sre_parse` is private, and probing with sample strings is unsound. A
  load-time check that only looks complete breaks the rule that a guard must fail when
  the thing it guards is deleted. The precondition instead stays where `rust.py`
  already states it, held by a test over every shipped cargo pattern rather than by
  the loader.
- *Drop a match whose span crosses `RUN_SEPARATOR`, at scan time, instead of excluding
  the separator from the class.* `finditer` has already consumed a spliced match's
  span by the time such a filter would see it, so a legitimate match overlapping that
  span is lost with no signal -- a silent loss of evidence, the direction this tool
  never takes.
- *A structural check on the shipped pattern's repetition bounds, to catch a future
  unbounded edit without a hardening test.* The same private-API problem as the
  `RUN_SEPARATOR` check: nothing public in `re` says whether a compiled pattern's
  repetition is bounded. What it would hold differs by pattern. For the vendor
  pattern, `test_hardening.py`'s long-run-of-near-misses test already fails on an
  unbounded path-segment or nesting repetition alone, `.` excluded and the name and
  tail bounds untouched, so a structural check on those bounds would hold nothing
  that test does not; its digit-and-dot test guards the `.` exclusion separately,
  and neither pins the name or tail's `{0,63}` bound itself. For the registry
  pattern, the `{0,63}`/`{1,255}` bounds are a convention no test enforces, because
  excluding `.` already keeps an unbounded name and version tail linear on their
  own -- only all three together, an unbounded name, an unbounded version tail, and
  `.` allowed in the name class, turn it quadratic, and `test_hardening.py`'s
  linear-time test guards exactly that shape.
- *Refuse `vendor/` after any `name-version/` component, instead of anchoring on the
  registry match's own end.* This would misread fromager's own layout: `cargo vendor`
  writes `/work/cryptography-44.0.0/vendor/openssl-sys/src/lib.rs`, and
  `cryptography-44.0.0` is shaped exactly like a registry crate directory despite
  never being one. Telling the two apart would also need the lookbehind to be
  variable-length, which Python's `re` does not support.

**What it costs.** This reads the four layouts a wheel is actually built from and does
not close every gap. A crate that contributes no panic location or `assert!` message
anywhere in the object is invisible whichever layout built it: this is a path-based
signal, not a manifest. No fromager-built wheel has been measured, only cdylibs built
the way fromager configures cargo for the registry and vendor layouts, and by hand for
the git-checkout layout: a real fromager build goes through maturin or setuptools-rust
on top of that, either of which could relocate, strip or filter the embedded paths
before they reach the wheel. A crate name past 64 characters, or a version string whose
tail runs past 63 characters after `x.y.z`, does not read as a crate under any cargo
convention -- the same cost the vendor and git-checkout patterns' bounds accept, paid by
the registry pattern too. The vendor pattern's `.rs` anchor has no terminator and no
word boundary either, so a vendored C or Go tree misreads as a Rust crate in two cases:
a `.rst`/`.rsp` file (`vendor/openssl/doc/man7/ossl-guide.rst` reads as crate `openssl`),
and a `.rs` file elsewhere in the same printable run consuming a real vendor path ahead
of it (`vendor/openssl/crypto/rsa/x.c vendor/ring/src/a.rs` reads as `openssl` alone,
losing `ring`). Both are unlikely in real `rodata`, since a C `__FILE__` string is
NUL-terminated into its own run, but it is a trade-off, not a guarantee; the
git-checkout pattern shares the same no-terminator gap for the same reason. The vendor
pattern also always anchors on the first `vendor/` path component it finds: a build tree
that itself sits inside a directory named `vendor` collapses every crate under that
outer component into one crate named after it, with no version, and loses the real names
nested inside, claimed ones included.
`/work/vendor/mypkg/vendor/{ring,openssl-sys,sha1}/src/lib.rs` reads as one crate,
`mypkg`, dropping `ring`, `openssl-sys` and `sha1` entirely. Preferring the innermost
`vendor/` component would need the pattern to fail past a nested one rather than
consume through it, which it does not attempt. This is specific to the whole build
tree sitting under a directory literally named `vendor`. A `vendor/` match that follows
a registry match in the same printable run with no `.rs` between them, such as a
registry crate's own C source path packed against a later, unrelated vendor path with
nothing in between, reads as nested and is dropped even though it is not; this is
unlikely in practice, the same way the vendor pattern's own `.rs` misreads above are,
since a C `__FILE__` string is NUL-terminated into its own run.

A `vendor/` tree nested inside a git-checkout workspace member is not run through the
same nesting-gap precedence as the registry layout. `cargo_git_path_regex`'s own `name`
group is anchored immediately before `/src/`, so a path like
`.../member/vendor/ring/src/lib.rs` already reads `name` as `ring`, the same crate
`cargo_vendor_path_regex` reads from its own `vendor/` match on the same path -- the two
patterns agree without needing precedence between them, unlike a registry match, whose
pattern stops at the crate's own directory and never sees a `.rs` file past it. Extending
`_NESTED_GAP` to a git-checkout match would have to reconcile that its span already
ends at a `.rs` file rather than at a bare directory boundary, for no case measured here
where doing so changes which crate gets recorded; this is deliberately left undone
rather than added by analogy, and revisited if a build is found where the two patterns'
readings for the same git-checkout path disagree. A root crate read from a git checkout
carries its repository's name rather than its own whenever the two differ
(`rust-base64`, not `base64`), and a `[[rust_crate]]` entry does not claim a root crate
whose repository is named differently; a workspace member's directory name is
conventionally, but not necessarily, the crate it holds. The `member` group is optional
and tried first, and its own lazy intermediate-directory repetition can walk past an
early `src/` inside a root crate's own tree before reaching the one that actually holds
the matched file: a root crate (no workspace member of its own) with a nested
`src/.../src/` subtree is then read under the inner directory's name rather than the
repository's, losing the real crate -- `ring-<hash>/<rev>/src/aead/src/x.rs` reads as
crate `aead`, not `ring`. And because the group reads a repository name rather than a
crates.io one, it excludes `.` the same way the crates.io name class does even though a
repository name can contain it: a root crate checked out from a repository such as
`foo.rs` records no crate at all, while a workspace member of the same repository is
read normally. Both are unlikely in a crypto crate's own repository name or directory
layout.

Revisit if a fromager-built Rust wheel is measured and its vendor or git-checkout paths
do not match what the hand-built cdylibs above embed.

## An SBOM naming an OpenSSL crate reads `unknown`, not `none`

**Accepted, and it changes `openssl_linkage`.**

A wheel's own PEP 770 SBOM naming `openssl-sys` is the same claim the crate check reads
from cargo paths, and it gets the same answer: `unknown`. Without an SBOM signal in
`resolve_linkage`, the field ignores it:

```text
SBOM names openssl-sys 0.9.117
demo/_rust.abi3.so    needed: libc.so.6
-> without the SBOM signal: openssl_linkage: none,    verdict.rule_ids: [..., "SBOM_CRYPTO_COMPONENT", ...]
-> with it:                 openssl_linkage: unknown, verdict.rule_ids: [..., "SBOM_CRYPTO_COMPONENT",
                            "BIN_OPENSSL_LINKAGE_UNKNOWN", ...]
```

**How it is read.** `resolve_linkage` has a second wheel-level signal,
`_declared_by_sbom`, consulted alongside `_left_unanswered` and only where that one is:
after every object's own evidence has been checked and none of it was definite.
`_left_unanswered` is library-agnostic and gated on `always_report`, because it is a
fact about the wheel, not about any one library; `_declared_by_sbom` is about the
specific library being asked for, so it runs for every library with a
`[[crypto_library]]` entry, not only OpenSSL, the same way the crate branch in
`_binary_posture` is not gated either.

It matches an SBOM component whose name folds to `library.name`, or to one of
`library.crates` -- exactly the names `SBOM_CRYPTO_COMPONENT` also reports a finding
for through its `crypto_library` and `rust_crate` tables, folded through the same two
functions that finding's lookup uses: `ruleset.sbom_library_key` case-folds a
`[[crypto_library]]` name, and `ruleset.sbom_crate_key` case-folds a `[[rust_crate]]`
name and also treats `-` and `_` as the same character, the way crates.io does. The
finding's own subject keeps the SBOM's own spelling -- "a name reported is a name read
in full" -- so a component spelled `OpenSSL` still reports `SBOM_CRYPTO_COMPONENT`
with subject `OpenSSL`, not the folded key `openssl`. The field and that finding can
never disagree about the same string this way. The loader refuses a ruleset whose
`sbom_component` rules, taken together, do not report through both tables (a rule
missing one, or none at all), and refuses `suppressed_by` on a rule it relies on for
that coverage -- a suppressed finding would reopen the same hole a coverage gap does --
so this agreement cannot be broken by editing the ruleset alone. Coverage is checked
over the union of every such rule's `tables`, not rule by rule, so covering the two
tables through two separate rules is accepted the same as one rule doing both. A soname
is deliberately not compared: an SBOM component names a package, not a dependency
string, and this field's `needed`-side matching already owns that comparison. A
distribution name (`crypto_distribution`, e.g. `cryptography`) is also excluded: a
distribution wrapping a library is not the wheel carrying a copy of it, and
`SCHEMA.md` says a distribution name never moves this field.

Like a crate, an SBOM component says the wheel uses the library, not which copy: it
never gives a definite posture, only `unknown` in place of `none`, and it never
outvotes a `system`/`bundled`/`static` posture any object in the wheel gave.

**What was rejected.** Leaving `none` and documenting the coexistence, the same option
"An OpenSSL crate with no other evidence reads `unknown`, not `none`" rejects and for
the same reason: `none` says "no OpenSSL evidence" on a record that carries some, which
`[linkage_policy]` and "absence of evidence is not evidence of absence" both exist to
refuse, and `unknown` already has the meaning this case needs.

**What it costs.**

- A wheel whose only OpenSSL evidence is a shipped SBOM component gains
  `BIN_OPENSSL_LINKAGE_UNKNOWN` and `OPAQUE` in `classes`. Its headline stays
  `CONDITIONAL`, since `SBOM_CRYPTO_COMPONENT` fires and `[verdict] precedence` ranks
  `CONDITIONAL` ahead of `OPAQUE`.
- An SBOM naming any other listed library, `libsodium` for instance, also gives
  `<name>_linkage: unknown` where nothing else in the wheel answers for it.
- An SBOM that fails to parse (`SBOM_UNREADABLE`, `OPAQUE` on its own) does not move the
  field: `_declared_by_sbom` only ever sees components a reader actually extracted, so a
  wheel whose only OpenSSL evidence is an unparseable SBOM reads `none` beside `OPAQUE`.
- Name matching folds through `ruleset.sbom_library_key`/`sbom_crate_key`, like
  `SBOM_CRYPTO_COMPONENT`'s own: a `[[crypto_library]]` name folds by case only, since
  no registry treats a C library name's punctuation as insignificant and no shipped
  library name carries a `-` or `_`; a `[[rust_crate]]` name also folds `-` and `_`
  together, the way crates.io does. A component spelled `OpenSSL` or `openssl_sys` moves
  both the field and the finding, and the finding's own subject keeps the SBOM's own
  spelling. The loader refuses two `[[crypto_library]]` names, or two `[[rust_crate]]`
  names, that fold to the same key, so the fold can never make this lookup ambiguous.
  Only the component's own `name` is read this way: its `purl` decides which table
  rates a colliding name (below), never what the name itself is taken to be, and an
  RPM-derived spelling such as `openssl-libs` is not aliased to `openssl` -- that is a
  distribution-packaging convention, not a registry either `sbom_library_key` or
  `sbom_crate_key` folds for, and no shipped `[[crypto_library]]` or `[[rust_crate]]`
  entry lists it. A wheel whose only OpenSSL SBOM evidence is spelled `openssl-libs`
  moves neither the field nor `SBOM_CRYPTO_COMPONENT`, the same gap `partial_analysis`
  leaves open elsewhere: a hole recorded, not silently absorbed into the fold.
- `library.name` alone is not enough where the ruleset has both a `[[crypto_library]]`
  and an unrelated `[[rust_crate]]` of the same name: `argon2` and `blake2` are each
  both the C reference library (libargon2, libb2) and, separately, the pure-Rust
  RustCrypto crate of the same name, which does not bind the C library and is not
  listed in either library's `crates`. `openssl` collides the same way but is not a
  false positive, because the `openssl` crate really does bind libssl/libcrypto, and
  the ruleset's own `crates` list names it for exactly that reason. `_declared_by_sbom`
  resolves the `argon2`/`blake2` collision by the component's own `purl` rather than by
  name alone: only `pkg:cargo/...`, PEP 770's spelling for a crates.io crate, says the
  component is the pure-Rust crate, so only that purl skips the name match. A component
  named `argon2` with a non-cargo purl (`pkg:generic/...`, the shape a real libargon2
  SBOM entry would carry) or no purl at all moves the field, because it could name the
  C library. The collision test runs on the folded key (`sbom_library_key(library.name)`
  and `sbom_crate_key(library.name)`), so a case variant of the colliding name, `ARGON2`
  for instance, is still resolved as the same collision. Two simpler alternatives are
  rejected. Matching by name alone, whatever the purl, gives a false positive: a
  component naming the pure-Rust crate under `pkg:cargo/argon2@...` would move the C
  library's field when nothing about it says the C library is present. Skipping the
  name match on every colliding name, whatever the purl, gives the opposite failure: a
  component that really does declare libargon2 or libb2 under a non-cargo purl, or
  none, would move nothing, while `SBOM_CRYPTO_COMPONENT` fires on the same name -- the
  finding fires on the name whatever the purl, the purl only picks which table rates it
  -- leaving a finding that names the C library with no field reflecting it. Reading
  the purl trusts it at face value: an SBOM component that names the C library but is
  mislabelled with a `pkg:cargo/...` purl -- wrong or hostile metadata -- reads as the
  crate and moves nothing, the same class of trust every other field extracted from the
  SBOM places in it.
- `SBOM_CRYPTO_COMPONENT` reads the same purl for the same collision: a component whose
  purl says `pkg:cargo/...` is rated by its `[[rust_crate]]` entry, and any other purl,
  or none, by the `[[crypto_library]]` entry -- the crate's own severity and verdict, not
  the library's, whenever the two disagree. In the shipped ruleset only `openssl`
  differs this way (crate `medium`, library `high`); `argon2` and `blake2`'s crate and
  library entries already agree, so the choice is invisible for them. The preference
  only ever reorders a table the rule already lists (`engine._sbom_entry` never adds
  `rust_crate` to a rule that never named it), and falls back to the rule's own table
  order for a name the preferred table does not have an entry for.
- `ruleset_coherence.validate_sbom_component_coverage` refuses `suppressed_by` on a
  `sbom_component` rule it relies on for `crypto_library`/`rust_crate` coverage: a
  suppressed finding would leave the field moved with nothing in the record to explain
  it, the same hole a coverage gap opens.
- Beside a system-linked object, this same signal withholds `DERIVED_SYSTEM_OPENSSL_ONLY`
  through `sbom_declared` on its match (`linkage.declared_by_sbom`, the rule-facing view
  of `_declared_by_sbom`): see "An object that read `unknown` withholds
  `DERIVED_SYSTEM_OPENSSL_ONLY`; the field stays `system`" above.
- No real SBOM-only wheel has been measured; the shape above is synthesised.

## The HTML report embeds records and renders them in the browser

**Accepted.**

`--format html` writes one page: Python renders a static shell and embeds every scanned
record as one JSON block; the page's own JavaScript builds the table, the filters and
the drill-down views from that data at load time. The page's own JS is complete by
itself -- every filter, sort, drill-down and hash-routed link above works with no
network at all. Its external assets are DataTables 3.1.1's core script and its default
stylesheet from cdn.jsdelivr.net, each pinned to that exact version, verified with a
Subresource Integrity hash and fetched with `crossorigin="anonymous"` and
`referrerpolicy="no-referrer"`. The script is `defer`red so it never blocks the page's
own script from running first; the stylesheet is linked from the page's own script, so
it never blocks the first render (see "DataTables' default styling and chrome" below).
The scan and the render make no network access of their own; opening the page fetches
those two files, and the invariant that this tool makes no network access at runtime is
scoped to the scan and the render, not to a page a human later opens in a browser that
reaches the wider internet.

**The embedding is the security boundary.** Every filename, matched symbol, matched
string and piece of evidence a wheel carries is untrusted, and a wheel author controls
all of it. The JSON payload is escaped by replacing `<`, `>` and `&` with their JSON `\u`
escapes rather than HTML entities: `<script>` is an HTML "raw text" element, so its
content is scanned only for the literal bytes <code>&lt;/script</code>, never for character references,
and `.textContent` hands JavaScript back an HTML entity completely unchanged --
corrupting exactly the string it was meant to protect. A `\u` escape has no literal `<`
and round-trips through `JSON.parse` like any other escape in a JSON string. Verified
against a real browser, not only reasoned from the two specs. The JS that reads the
payload back never uses `innerHTML`: every value reaches the DOM through `textContent` or
an element property such as `.value`. DataTables is never handed record text either: no
`data-search`/`data-order` attribute carries one, and every search it runs is a function
closed over `DATA.records`, never a string built from a cell -- see "DataTables owns
sorting, searching and paging" below for what that closes off.

Two embedded records can share a filename -- a cpu and a cuda build of the same wheel
name, for instance -- so the drill-down is keyed on a record's position in the embedded,
sorted list, never on the filename: a filename-keyed lookup would let one record's row
silently open the other's evidence on a collision, with no way from the table to reach
the one that lost.

**DataTables owns sorting, searching and paging; the page owns the rules.** Once its
pinned script has loaded, DataTables runs the sort, the global search, the per-column
search and the paging on both the Wheels and the Rules table. It never runs its own
comparison or its own text match to do it: every one is the page's own `sortValue`/
`ruleSortValue`, `columnText`/`ruleColumnText`, `matchesQuery` and `matchesToolbar`,
handed to DataTables as `ext.order` functions and `search`/`search.fixed`/
`column().search()` functions, over the same rows `renderRow`/`renderRuleRow` already
built. A DataTables row index equals a record's position in `DATA.records` (a rule row's
position in the array `ruleRows()` returns, for the Rules table): rows are added once,
in that order, and never cleared or re-added, so the index one predicate reads back a
record by is the same index the other table-building path already uses. A page opened
with the script reachable and one opened without it therefore agree on which rows pass
the filters and in what order by design -- only by a bug -- and a `network`-marked test
drives both through the same script of clicks and keystrokes and diffs the two
transcripts. The hash grammar carries no sort, page or page length: none of the three is
part of it, whether the table is native or DataTables-enhanced. DataTables never writes a
cell: no `render`, `data`, `createdCell` or `title` option, no
`row().data()`/`cell().data()`/`invalidate()` call, an explicit `type` on every column,
and `searchable: false` on every column, which keeps its own per-cell search-text cache
-- the one place 3.1.1 decodes a `&` in cell text through a detached element's
`innerHTML` -- from ever running over a wheel-controlled string. Init replaces the
table's own `<colgroup>`; the page re-adopts whatever it leaves in place immediately
afterward, so the resize handles, `recomputeTableMinWidth` and Reset columns work against
it the same way they work against the native one.

**DataTables' default styling and chrome.** Enhanced, the tables look and behave like
DataTables' own default styling: the `display` class (stripe, hover, row borders, a tint
on the sorted column), the page-length menu and the search box above the table, the
"Showing 1 to 50 of 60 wheels" info line and the paging buttons below it, and
DataTables' own sort arrows in the header. Two concerns come with a third-party
stylesheet, and each has its own answer. *Render blocking:* a `<link>` the parser meets
in `<head>` holds the first render until the file arrives, so a CDN that hangs would
blank a page that needs nothing from it; the page's own script creates the link element
instead, which never blocks rendering. It also styles nothing before enhancement, since
every selector in it is scoped to `table.dataTable` or `div.dt-container`, which only
DataTables' own init creates, and a stylesheet that never arrives or fails its integrity
check leaves an enhanced table on the page's own CSS: plainer, still complete. *Theme:*
the stylesheet has no `prefers-color-scheme` rule; its dark palette hangs off a `dark`
class on `<html>`, so the theme toggle sets that class from the same answer the page's
own CSS reaches (the explicit choice, or under "system" the OS preference, followed live
through a `matchMedia` change listener). The link is inserted ahead of the page's own
`<style>`, so the page's rules win every specificity tie, and the handful of DataTables
custom properties that carry a colour of their own (input borders and background, the
header and row rules) are set on `.dt-container` from the page's tokens, since
DataTables sets its dark values under `:root.dark`, which a plain `:root` rule would not
outrank but an ancestor's own value always does through inheritance.

There is one search box on screen either way. Enhanced, the page's own `#search` moves
into DataTables' `topEnd` layout slot, wrapped in the `div.dt-search` markup DataTables'
built-in search draws, so it looks and sits like DataTables' box; it is the same element
with the same listener, so `matchesQuery`, its exact rule-id mode and the `q=` hash mean
the same thing online and offline. `#count` hides behind the info line, which says the
same. The header keeps the page's own sort button, "?" button and resize handle inside
DataTables' header layout; with `ordering.handler: false` DataTables binds nothing to
the header cell itself, so the page binds its sort to the button and to the order
indicator beside it, and draws the faint up/down pair on every sortable column from
DataTables' own arrow variables. The horizontal scroll moves inward to DataTables' own
table cell, so the controls above and below never scroll sideways with a wide table.
Column widths are set for what each column holds, measured from a real render: the
filename wide enough for a typical platform wheel name in two or three lines (breaking
at "-" and at the dots of its platform tag, never inside the version or the ".whl"
suffix), the class column for the widest badge, and each narrow column for its own
label, "?" button and sort arrows. Together they need about 1330px, so a 1366px-wide
window shows the whole table and a 1280px one scrolls it inside its own box.

**A tiebreak DataTables never computes.** `ext.order` hands DataTables one sort value
per row, the same `sortValue`/`ruleSortValue` result the native path compares, with no
tiebreak of its own: DataTables' own sort, like the native one, is stable, so a tie's
relative order falls out of `DATA.records`'/`ruleRows()`'s own array order rather than a
second comparison either path runs. That array order is a Python-side fact, not a JS
one: `DATA.records` is filename-ascending because `_html_sort_key` in report.py sorts it
that way before embedding, and `ruleRows()` reads rule ids id-ascending because
`_embed_json` writes the `rules` object with `sort_keys=True`, which a JSON object's own
key order (and so `Object.keys(DATA.rules)`) preserves for a string key -- an integer-like
key would enumerate first, in numeric order, ahead of every string key regardless of where
`sort_keys=True` put it, which never applies here since every rule id in `ruleset.toml` is
a name, never a bare number. Both match the tiebreak
`visibleRecords`'/`sortedRuleRows`' own native sort already computes explicitly
(filename, then rule id), so a tie lands the same place whichever path is showing it.
Folding the tiebreak into the value itself instead -- `[value, tiebreak]`, compared as
one string, to drop the dependency on that array order -- compares wrong on a descending
sort: `orderDescReverse: false` (needed so DataTables reverses a descending sort's
comparator rather than the whole sorted array, the same requirement the plain,
non-composite value already has) reverses a composite string's tiebreak right along with
its primary value, the two no longer being separate comparisons once joined.

**The cost, and the fallback.** Opening a report contacts cdn.jsdelivr.net, which
sees the client's IP address, the time of the request and its user agent; `no-referrer`
keeps the report's own address off that request, and the pin plus the integrity hash
mean the script that runs is exactly the one this project tested against, never
whatever jsdelivr serves next. A report served from behind a CSP has to allow that one
origin for `script-src`. Offline, blocked or served with a body that fails the
integrity check, the browser never executes the script at all -- `typeof window.DataTable`
stays `"undefined"` -- and the page falls back to the table it already rendered
natively, filter-row inputs and all; a later exception during either table's own setup
is caught the same way and that one table's native rendering restored. The test suite
that exercises the enhanced path is marked `network` and deselected by default, the same
way a `real`-marked test needs a wheel corpus few hosts carry; the tests that exercise
the fallback stub `window.DataTable` or block DNS resolution in Chrome
(`--host-resolver-rules=MAP * ~NOTFOUND`) and run unmarked, since neither needs a real
network to prove the fallback works.

**The `openssl` column and what a class means.** The Wheels table carries an `openssl`
column, after `libraries`, showing `conditions.openssl_linkage` -- the wheel's overall
OpenSSL posture, including `none` -- which the Markdown table leaves out. A class's
meaning is one hover away without opening the Help dialog: the toolbar's class chips
and the table's own class badges both carry its `CLASS_HELP` text as a tooltip, and the
Help dialog's Reference tab lists every class in full. A separate legend block between
the toolbar and the table would repeat the chips directly above it.

**Filtering.** The OpenSSL linkage toolbar filter is an exact-match dropdown over
`conditions.openssl_linkage`; its unfiltered option reads `all`, which keeps it from
reading like a linkage value the field could actually carry, or the ruleset's own
`binding = "any"` match spec. This matches the class filter's own reset button, which
reads `all` too. Both the Wheels and Rules tables also carry a per-column "contains" filter,
one `<input type="search">` per column, in a second header row below the column labels,
matching case-insensitively against the text each cell already shows -- `reasons` is the
one exception, matching the record's full `verdict.reasons` list rather than only the
three chips a cell displays, since matching only what is visible would let a reason
hidden behind "+N more" go unmatched. A `COLUMNS` entry that already has an exact
toolbar filter of its own -- `class` (the class-strip chips), `review` (the "needs
review only" checkbox) and `openssl` (this same linkage dropdown) -- carries
`filter: false` and gets no column filter: its cell in that second header row is left
empty rather than offering a second, looser filter over a field the toolbar already
covers exactly, so every field keeps exactly one hash parameter. A column filter
combines with every other active filter -- class, linkage, review-only, a Rules-tab rule
click -- the same way those already combine with each other, so a combination that
leaves zero rows is a reachable state, not a bug.

**Byte-stable, like the JSONL it views.** `render_html` is a pure function of the
records, the ruleset and the shipped template: no timestamp, host path, hostname or
random id. Three keys hold every view-time preference the page remembers, each read and
written through the same try/catch pattern since storage can be unavailable (private
browsing, disabled cookies, a `data:` origin): `wcs-theme` for the theme toggle,
`wcs-intro` for the onboarding dialog's checkbox, and `wcs-column-widths` for the wheel
table's resized column widths, a JSON object keyed by `COLUMNS`'s own column key. `wcs-intro`
holds one of three states, not two: a missing key (never decided) and the value `keep`
(explicitly chose to keep seeing it) both show the dialog on the next visit and default
its checkbox to checked; only `dismissed` (checked and closed) suppresses it, and only a
stored `keep` shows the checkbox unchecked on reopen -- collapsing "never decided" and
"keep" into one state would default a first-time visitor's checkbox to unchecked despite
the static markup's own `checked` attribute, defeating the dialog for anyone who never
notices and unticks a box they would reasonably assume already reflects the recommended
choice. A stored column width is applied only once validated -- a finite integer within
that column's own resize-handle minimum and the same fixed ceiling (`MAX_COLUMN_WIDTH`)
a drag or a Shift+Arrow resize is itself clamped to on the way in, so a value the UI
cannot even create in the first place cannot fail this read either -- so a stale or
hand-edited value is dropped rather than pinning a column narrower than its floor or wider
than sensible; malformed JSON is dropped the same way rather than thrown. None of the
three ever touches the file's bytes: unavailable or corrupt storage renders the same page
`render_html` would have produced with no storage at all, just with every preference at
its default. The template itself is pure ASCII, so `--format html` to a redirected
stdout does not crash on a non-UTF-8 locale the way a stray arrow glyph or em dash in the
JavaScript source would.

**The URL hash carries the open wheel, the top-level view, the toolbar's filters and the
Wheels table's own per-column filters.** `wheel=<index>` names the record open in the
detail panel; `view=rules` names the top-level view (omitted for its default, `wheels`);
`class=<comma list>`, `linkage=<value>`, `review=1` and `q=<text>` each name a toolbar
filter, present only when it differs from its default -- except `class`, which is present
and empty (`class=`) for the one reachable state whose value happens to be an empty
string, every class chip unticked, so that state round-trips instead of reading as "no
filter" and silently re-ticking every class on reload. `f.<column>=<text>` names one
Wheels table column filter, one pair per active `COLUMNS` key that carries no
`filter: false`, written in `COLUMNS` order so the hash is deterministic whatever order
the reader typed the filters in; an `f.` key naming a column that does not exist (a stale
link, a template that has since dropped the column) or that has `filter: false` (`class`,
`review`, `openssl` -- each already reachable through its own toolbar param above) is
dropped on read the same way a stale `class` token is. The grammar's scope is the Wheels
view's own state; the Rules table sits outside that scope entirely, the same way its sort
already does, so neither its sort nor its own per-column filters are part of the hash. A
`class` token not in the report's own `DATA.classes` (a stale link, a hand-edited value)
is dropped on read rather than kept as a filter nothing on screen explains. Multiple params
join with `&`, for example
`#class=NON_APPROVED_CRYPTO,FIPS_BREAKING&linkage=bundled&review=1&q=somefilename&f.families=hash`,
and a comma inside `class` stays literal rather than percent-encoded, so the hash reads the
same as it is written; a `.` inside an `f.<column>` key needs no encoding of its own, since
`encodeURIComponent` already leaves it untouched. The page writes the hash with
`history.replaceState`, never `pushState`:
a new history entry on every keystroke in the search box would make the back button
useless. Reading is total, not a merge: on boot, and again on `hashchange` (a shared or
bookmarked link, or a hand-edited address bar), every recognised field is set from whatever
the new hash carries or reset to its own default when the hash omits it, so applying a hash
produces the same `state` regardless of whatever filter was active before -- a plain
`#wheel=1` link a colleague sends clears a search or class filter already active in the tab
that follows it, rather than keeping it and writing it back into the URL on the next
interaction as though it had always belonged there. Opening a wheel merges `wheel=` into
whatever filter params are already in the hash rather than overwriting them, and closing
the detail panel strips only `wheel=`, leaving the filters in place. A hash-encoded param
present at load, of any kind, also keeps the onboarding dialog from auto-opening over a
link someone was sent on purpose.

**No verdict class gets a favourable colour.** The taxonomy has no passing class, and the
page must not invent one by way of colour: the two classes that mean "nothing was
decided" -- `NO_CRYPTO_DETECTED` and `OPAQUE` -- share one neutral CSS token, and every
other class is a warning or a danger token. A wheel not flagged for review reads "not
flagged", never a plain "no" or a checkmark. The class filter is seeded from the union of
the given ruleset's precedence and every class actually present in the records, not from
precedence alone: the loader requires `NO_CRYPTO_DETECTED` to close a ruleset's
`[verdict] precedence`, so a ruleset it loaded already names every class `classify()`
can emit, but `render_html` takes any `Ruleset`, including one built without the loader,
so the union keeps a record whose class that `Ruleset`'s own precedence leaves out
showing rather than hidden from a filter no control can reach.

The class and linkage help text shown in the page -- `CLASS_HELP` and `LINKAGE_HELP` in
`report.py` -- are plain constants rather than a ruleset addition, so no HTML-only text
can affect a verdict or need a `ruleset_version` bump. `CLASS_HELP` is verbatim from
SCHEMA.md's "Verdict classes" table, held to that by a test that parses the table
directly rather than only asserting the claim in prose. `LINKAGE_HELP` is a short form
of the `conditions.openssl_linkage` table instead, since several of its rows run to a
paragraph; a test holds it to the same set of values and requires each short form to
name the SBOM exactly when its row does, so a tooltip cannot send the reader to the
binaries for evidence that came from the wheel's SBOM.

**What was rejected, and why.**

- *A templating engine or a JS framework.* One HTML file with inline CSS and vanilla JS
  is the whole surface; a dependency buys nothing a `str.replace` on one sentinel token
  does not already do, and the sentinel avoids `str.format`'s clash with the page's own
  CSS braces.
- *HTML-entity escaping for the embedded JSON.* Survives `.textContent` as extra literal
  characters inside the string it is meant to protect, corrupting the data it carries.
  The `\u`-escape approach above has no literal `<` and avoids that.
- *Vendoring DataTables into the template.* Every report this tool renders would carry
  the library's ~120 KiB minified body inline, not the one `<script src>` tag a CDN
  reference costs regardless of how many reports get written; the project would carry
  third-party JS and its MIT licence notice as files of its own, the only vendored
  dependency it ships anywhere; and a version bump would mean re-generating and pasting
  in the whole minified blob rather than the two-line diff (the URL, the SRI hash) a
  pinned CDN reference already costs. `tests/helpers/binfmt/` synthesises every other
  test fixture this project ships rather than committing one; a minified library is not
  a fixture, but the same reasoning against a committed binary applies to it.
- *A static `<link>` for DataTables' stylesheet.* Blocks the first render until the file
  arrives, so a hung CDN would hold up a page that renders completely without it.
- *Only the layout rules DataTables' init needs, carried inline, with no stylesheet.*
  Keeps the table looking like the plain page rather than DataTables' default styling,
  and re-states by hand the stripes, hover, sort arrows and paging buttons the pinned
  stylesheet already draws.
- *`data-search`/`data-order` attributes holding record text.* `filterData` decodes a `&`
  in that text through a detached element's `innerHTML` -- an XSS path a wheel-controlled
  filename or matched string would reach directly. It would also mean a second copy of
  `columnText`/`sortValue`'s own logic stored as DOM text, one more place the two could
  drift apart.
- *DataTables' own string and "smart" search, and its built-in search box and column-search
  UI.* The built-in search splits words, ANDs them, strips diacritics and matches every
  column; none of that is `matchesQuery`'s exact-rule-id mode or its plain substring mode,
  so `#q=` would mean two different things online and offline. Its built-in search box
  runs that search, so the page's own `#search` takes its place in `layout` instead; its
  per-column UI would double up the filter-row inputs, so it is not placed at all.
- *Hiding the toolbar's search box and wiring a second one in DataTables' slot to it.* Two
  inputs to keep in step, on every keystroke and every hash change; moving the one input
  keeps a single element, a single listener and a single value.
- *Feeding DataTables only the rows that pass the toolbar filters.* `rows.add`/`rows.remove`
  on every filter change would break the row-index-equals-record-index mapping this design
  relies on, rebuild every row's DOM node, and force DataTables to recompute its own
  caches on every keystroke; a `search.fixed` predicate that runs over the full row set
  costs none of that.
- *Trimming the embedded record, or a size warning past some threshold.* Every field a
  consumer might need for a real investigation is already in the JSONL; leaving any of
  it out of the page would just send the reader back to the JSONL to finish the job the
  report exists to shortcut.

## The ruleset cites a standard and the record carries only the pointer

**Accepted, and it changes records.**

A finding's `basis` is a list of `[[standard]]` ids -- `FIPS-140-3`,
`SP-800-131A-r2` -- and nothing else. `title`, `edition`, `status`, `successor`,
`sunset` and `why` never reach a scan record: `standards.py` parses them once, into
the loaded `Ruleset`, and `wheel-crypto-scan rules --format json` and the HTML report
read them back out of that same `Ruleset` for display, on demand, rather than the scan
record duplicating them into every wheel that cites the standard. The Markdown report
prints a finding's raw `basis` ids and nothing more: it renders from records alone,
with no `Ruleset` in hand to resolve them against.

**Why the pointer, not the citation.** A scan record describes one wheel at one point
in time; a standard's edition and status describe the state of a NIST/FIPS
publication, which moves on its own schedule and has nothing to do with when any
particular wheel was scanned. Carrying `edition`/`status` on the finding would mean
either re-scanning every already-produced record when a standard's status changes --
SP 800-131A moving from `current` to `revision_planned`, say -- or letting two records
for the same wheel, scanned on either side of that change, disagree about a fact that
has nothing to do with the wheel. An id is stable in a way a status is not, so the
record holds only the part that is.

**Why a `withdrawn` standard fails the load, not just a lookup.** `basis` naming a
standard whose `status` is `draft`, `planned` or `withdrawn` is refused by
`ruleset_coherence.check_basis_targets_a_live_standard` at load time, before any wheel
is scanned. The alternative -- let the ruleset load and let the citation stand -- would
mean every finding citing that entry is quietly citing text that no longer governs
anything, or does not govern anything yet, with nothing in the record itself to say
so: the id looks exactly as authoritative as a live one. Refusing it at load time makes
updating a `[[standard]]`'s `status` (when a revision publishes, or a standard is
formally withdrawn) the trigger that forces every `basis` naming it to be re-pointed
at its `successor` before the ruleset can load again, rather than a fact that silently
goes stale in already-shipped rules.

**What was rejected.** Carrying `edition` and `status` on the finding alongside the
id, so a reader would not need the ruleset to interpret `basis`. Rejected because it
reintroduces exactly the staleness the pointer design avoids: a record embeds the
ruleset's state at scan time, and a consumer comparing two records scanned months
apart would see the same standard described two different ways for reasons that have
nothing to do with either wheel.

## `relation` and the verdict class are checked against each other at load time

**Accepted.**

`RELATION_CLASSES` in `ruleset.py` is a closed table: each of the seven `relation`
values names the verdict classes it is consistent with, and
`ruleset_coherence.check_relation_matches_verdict` refuses, at load time, any rule or
override-bearing entry whose `(verdict, relation)` pair is not one of those rows.
`restricted` is the one relation with two rows: `NON_APPROVED_CRYPTO` when the wheel
implements the primitive itself, `CONTEXT_DEPENDENT` when it defers to the host module
and only the use is in question -- `BIN_OWN_SHA1_IMPL` and `PY_RESTRICTED_HASH_CALL`
are the two, differing in exactly that way. No relation names `OPAQUE`, since
unreadability has no standard to cite, so a verdict of `OPAQUE` paired with any
relation is refused the same way.

**Why a load error, not a test over the shipped ruleset.** A `(verdict, relation)`
pair that disagrees with itself is a rule stating two facts about the same finding --
what would fix it, and how bad leaving it unfixed is -- that contradict each other:
`runtime_refusal` (raises at runtime) beside `CONDITIONAL` (approved under a stated
condition) would tell a consumer both that the wheel crashes under FIPS mode and that
it is fine if some condition holds. `tests/test_ruleset_data.py` already checks the
*shipped* ruleset's own choices are sound data, but a check that ran only there would
leave `--ruleset PATH` unguarded: nothing would stop a hand-edited or generated
alternative ruleset from loading with an internally contradictory rule, since the
inconsistency is a property of one rule's own two fields, checkable the moment the
rule is parsed, not something that needs the whole corpus of shipped rules to notice.
Refusing it in `ruleset_coherence.py` -- run against every `Ruleset` `load_ruleset`
builds, not only the one shipped in `data/ruleset.toml` -- means every consumer of
`--ruleset` gets the same guarantee the maintainers do.

**Entries with no owning rule.** A `crypto_distribution`/`crypto_library`/
`rust_crate`/`python_module` entry can state its own `verdict`/`relation`, fall back
to an owning rule's, or -- for `crypto_library` today, which no rule names as its
`bundled_library` default and none names by `rule =` -- have no owner to fall back to
at all. `check_relation_matches_verdict` still closes the pair for that shape: a
`relation` with no `verdict` anywhere to check it against is refused outright, since a
relation names what would fix a finding against some class, and one that can never be
checked against any class is not a citation of anything. A `verdict` with no
`relation` of its own is checked against every rule that could resolve as the entry's
owner at scan time -- `engine._match_bundled_library` lets any `bundled_library` rule
read an unowned entry -- rather than being skipped for lack of one fixed rule to ask.

**What was rejected.** Enforcing the pair only in `tests/test_ruleset_data.py`, over
the shipped ruleset's own data. Cheaper to write, and it is where the *totality*
requirement lives instead (every verdict-bearing rule and effective entry carries a
relation and basis, except a rule a table routes through -- `DIST_NON_APPROVED_CRYPTO`
sets `verdict` with no `relation` of its own, since its `crypto_distribution` entries
supply one each) -- but totality and compatibility are different questions, and
only the second is a property `--ruleset` needs enforced for every ruleset, not just
the one this repository ships.

## `family` is the FIPS-agnostic axis; `category` stays the FIPS one

**Accepted, and it changes records.**

`category` already existed on every rule -- `non-approved-impl`, `fips-breaking`,
`trust-policy`, `crypto-wrapper` and twenty more -- and reads as a FIPS-lens
classification of *why* a rule fires: which kind of FIPS concern it is. `family` is a
second, closed vocabulary (`FAMILIES` in `ruleset.py`): `hash`, `block_cipher`,
`signature`, `key_agreement`, `library` and the rest, describing what primitive a
finding is evidence of, with no FIPS content in it at all. It is carried on a rule, on
an entry in the four override-bearing tables, and on every
`[[symbol_group]]`/`[[string_group]]` -- the two tables that carry no `category` of
their own, since a symbol or string group is not itself a rule and states no verdict
-- so the crypto inventory `crypto.families` derives from can be built without
touching a FIPS class at all: a `NO_CRYPTO_DETECTED` wheel and an `OPAQUE` one both
have an empty `families` list for the same reason, not because either was asked a
FIPS question and answered no.

**Why `category` was not reused.** Widening `category`'s existing values to also
answer "what kind of primitive is this" was rejected: `category` names a rule's
*FIPS* story, and a rule that delegates rather than embodying one primitive itself --
`DIST_SYSTEM_CRYPTO_WRAPPER`'s `crypto-wrapper` category, for a distribution that
wraps a system crypto library without implementing anything -- carries no `family` at
all. There is no `hash`-shaped or `block_cipher`-shaped value in `category` to widen
toward, only a FIPS-lens classification that happens to correlate with a family for
most rules but is not the same question. Reading the inventory off `category` would
mean reading the FIPS lens to answer a question that has nothing to do with it, and
`crypto.families` would inherit `category`'s open-ended, per-rule-author vocabulary
rather than a small closed one a report's grouping can rely on.

**What it costs.** `category` and `family` are independent vocabularies that can drift
apart if either is filled in carelessly, and most rules leave `family` unset on the
rule itself: a finding's `family` comes from the matched `[[symbol_group]]`/
`[[string_group]]` or table entry as often as from the rule
(`engine._build_finding`'s `family=first.family or rule.family` reads the hit's own
family first), and the loader has no way to catch either one that reads wrong for
what a rule actually matches. `tests/test_ruleset_data.py` holds the shipped
ruleset's own choices to a manual review instead of a load-time rule.

## SHA-1 is restricted, not refused

**Accepted, and it changes verdicts.**

`[conventions]` splits Python's weak hash constructors into two lists rather than
one: `refused_hash_algorithms` (`md4`, `md5`, `md5-sha1`, `ripemd160`, `sm3`,
`whirlpool`) and `restricted_hash_algorithms` (`sha1` alone), with
`Conventions.weak_hash_algorithms` deriving their union for the one rule that still
wants "either list" -- `PY_WEAK_HASH_CALL_MARKED`, which reads `algorithm_list =
"weak"` because a caller who declared `usedforsecurity=False` gets the same degraded
severity whichever list their hash came from. A `py_call` match's own `algorithm_list`
takes `"refused"`, `"restricted"` or `"weak"`. `PY_WEAK_HASH_CALL` matches only the
refused list and reads `runtime_refusal`/`FIPS_BREAKING`: `hashlib.md5()` and the rest
raise on a FIPS-enforcing host unless the caller passes `usedforsecurity=False`.
`PY_RESTRICTED_HASH_CALL` matches `sha1` alone and reads `restricted`/
`CONTEXT_DEPENDENT` instead: it does not raise. The binary side carries the same
split -- `BIN_OWN_WEAK_HASH_IMPL` for a private implementation of the refused
algorithms and `BIN_OWN_SHA1_IMPL` for one of SHA-1 alone, both `NON_APPROVED_CRYPTO`,
`restricted`'s other row for a wheel that implements the primitive itself rather than
deferring to a host module.

**Why the split.** SHA-1 and the other five algorithms fail two different ways once
FIPS mode is enforcing. `providers/fips/fipsprov.c`'s `fips_digests[]` table -- the
OpenSSL FIPS provider's own list of what it will fetch -- registers `SHA1` with its
default, approved properties beside SHA-2/SHA-3, while MD4, MD5, the combined
MD5-SHA1 TLS digest, RIPEMD-160, SM3 and Whirlpool are absent from it entirely. A
provider fetch for an absent digest fails, which is what makes `hashlib.md5()` raise
under FIPS mode with no explicit `usedforsecurity=False`; a fetch for `SHA1` succeeds,
so `hashlib.sha1()` returns a working digest either way. One list reading "refused"
for all six would have `PY_RESTRICTED_HASH_CALL`'s own algorithm predicting a crash
that never happens on a real FIPS-enforcing host. SP 800-131A Rev. 2 Table 8 gives the
second half of why SHA-1 still gets its own class rather than folding into whichever
list means "fine": it sets SHA-1 acceptable only for a non-digital-signature use that
does not require collision resistance, disallowed for signature generation, with
retirement announced for the end of 2030 -- a restriction a static call site cannot
answer on its own, so `CONTEXT_DEPENDENT` sends it to a human rather than clearing it
or refusing it outright.

**The open residual.** The `fips_digests[]` registration is what the `why` text on
both rules cites, not a live measurement: `hashlib.sha1()`'s and `hashlib.md5()`'s
actual behaviour under FIPS enforcement is left unmeasured, read out of the provider's
own source rather than run and observed on a host with `fips=1` enforcing and
OpenSSL's FIPS provider active. This is a documented gap, not papered over by
inference: the source registration is the same claim a live measurement would
confirm, and closing the gap needs nothing more than such a host.
