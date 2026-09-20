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

**What it costs.** A union hides an intra-object disagreement. A universal2 dylib whose
x86_64 slice links the host OpenSSL and whose arm64 slice has it compiled in merges to
`needed: [libcrypto...]` plus both an `imported` and a `defined` `EVP_DigestInit_ex`.
`linkage._binary_posture` tests `needed` first, so the object resolves to `system`, where
reading the slices separately would give `system` and `static` and `_aggregate` would call
that `mixed`. Previously the record was equally wrong about the posture but carried
`partial_analysis: true`, which fired `BIN_PARTIAL_FORMAT` and forced
`needs_human_review`. That net is now gone for this case.

The trade is right because the losing case needs two independently built thin dylibs
`lipo`-ed together, which `delocate` does not produce, while the winning case is most of
the macOS wheels in the index. It is recorded here because nothing in the output says a
record was merged, so a reader of `matched_symbols` carrying one name as both `imported`
and `defined` should know why that is representable at all.

Revisit if a real wheel is found whose architectures disagree about linkage.

Tracked in [#10](https://github.com/EmilienM/wheel-crypto-scan/issues/10).

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
`elf_symtab_unread` is worth a verdict and costs linkage nothing, because `.symtab`
drives `stripped` and `symbol_counts.symtab` while the split comes from `.dynsym` alone.
A test asserts the two lists differ, so if they ever coincide the mechanism is a rename
and should be one.

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

The containment helped, in one direction only, and it is worth being exact about which.
The loader refuses `routine` that is not a subset of `exclude_reasons`, so dropping the
exemption forces the re-rating. It does not refuse the converse -- re-rating the verdict
while leaving the exemption in place loads clean, because a cause being worth a verdict
and costing linkage nothing is legitimate and is what `elf_symtab_unread` is. What holds
that side is the exact-set assertion in `tests/test_linkage.py`, which is a test over
the shipped ruleset and so does not reach a `--ruleset` user. That is the weaker
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
causes already excluded --
`elf_symtab_unread`, `elf_go_buildinfo_unread`, `pe_no_import_directory` -- each leave
every field `linkage` reads intact: `.symtab` and `.go.buildinfo` feed nothing `linkage`
touches, and an absent PE import directory is a declaration the object really did make.
None of that holds for either new cause. `needed`, the imported/defined split and
`matched_strings` are what `linkage` reads, and a sectionless or ambiguous object has
answered none of them -- `needed` is not "no dependencies", it is "we could not ask" or
"we cannot tell which answer is real". Excluding either would read `openssl_linkage:
none` off an object that told us nothing, the same failure `DECISIONS.md`'s "A symbol
table is checked against the string table, not taken at its word" entry already
measured for a lying `nsyms`. The reused tokens -- a forged `sh_type` folding into
`elf_dynamic_unread`, `elf_dynsym_unread` or `elf_symtab_unread` -- were already costing
the linkage answer (two of the three) or already excluded for an unrelated reason
(`elf_symtab_unread`, which never fed `linkage` in the first place); reusing them
changes nothing about that table.

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
`defined` within one object is [#60](https://github.com/EmilienM/wheel-crypto-scan/issues/60);
the `is_opaque` arm's per-library fan-out is [#68](https://github.com/EmilienM/wheel-crypto-scan/issues/68).
Neither is touched here.

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
