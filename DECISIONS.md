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

**Accepted, and it changes verdicts.**

`partial_analysis` has twenty causes behind it, and `BIN_PARTIAL_FORMAT` used to fire
`OPAQUE` plus `needs_human_review` for every one of them equally. Two of them are
conventions a linker produces on purpose rather than anything that went wrong: an import
or an export bound by ordinal has no name to match.

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
the engine treating them alike. `BIN_PARTIAL_ROUTINE` claims the two ordinal causes with
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
individually addressed rather than pooled. `NumberOfNames = 0` over a real name table
therefore still reads clean, which is tracked in [#42](https://github.com/EmilienM/wheel-crypto-scan/issues/42).

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
