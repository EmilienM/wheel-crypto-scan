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
