# Evidence, opacity and verdicts

Three entries about the line between "we read this and found nothing" and "we did not read
this". Getting that line wrong in the favourable direction is the failure mode the whole
tool exists to avoid, and all three of these were found by going and building the object
that crosses it.

## A routine cause is recorded but does not make a wheel opaque

**Accepted, and it changes verdicts. Half of it was later taken back — the export half,
below, is the part to read first if you are deciding whether a new cause belongs on this
list.**

`partial_analysis` has a score of causes behind it, and `BIN_PARTIAL_FORMAT` used to fire
`OPAQUE` plus `needs_human_review` for every one of them equally. Two looked like
conventions a linker produces on purpose rather than anything that went wrong: an import or
an export bound by ordinal has no name to match.

`WS2_32` is normally bound by ordinal, so that is the ordinary shape of a Windows extension
that touches sockets. Measured on two wheels identical but for that:

```text
all imports named   -> NO_CRYPTO_DETECTED
WS2_32 by ordinal   -> OPAQUE
```

One linker convention, and the wheel joined the `OPAQUE` triage list. That is a real cost:
the list is read by a human, and padding it with wheels nobody needs to look at is how a
triage list stops being read at all.

**What changed.** `[rule.match] kind = "partial_binary"` takes `reasons` and
`exclude_reasons`, so the ruleset decides which causes are worth a verdict rather than the
engine treating them alike. `BIN_PARTIAL_ROUTINE` claims the ordinal import with no verdict
and no human review; `BIN_PARTIAL_FORMAT` keeps `OPAQUE` for everything else. An object with
both kinds of cause fires both rules, so the failure still wins.

**What it costs, and why `pe_delay_load` is not on the list.** A wheel whose only
incompleteness is an ordinal import now reads `NO_CRYPTO_DETECTED` where it read `OPAQUE`.
That is a real loss of conservatism. What makes it tolerable is that the *dependency* name
survives: an object importing `libcrypto-3-x64.dll` by ordinal still carries that DLL in
`needed`, so it still comes out `CONDITIONAL` on the ordinary `needed` rule. A delay-load
directory loses the dependency name itself, with nothing downstream to recover it, so it
stays with the strict rule. The two are not the same kind of gap, and only one of them has a
backstop.

**Why the strict rule excludes rather than includes.** A cause added later matches no include
list, so it would report nothing at all. Excluding means a new token is serious until someone
decides otherwise, and a test asserts every token the strict rule excludes is claimed by name
somewhere else.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-routine-cause-is-recorded-but-does-not-make-a-wheel-opaque) ·
[#29](https://github.com/EmilienM/wheel-crypto-scan/issues/29)

### The export half of this was wrong

**Reversed. `pe_ordinal_export` is a failure to read, not a convention.**

The sentence above carries both causes at once — "an import or an export bound by ordinal has
no name to match" — and then justifies them with one argument: the dependency name survives in
`needed`. That argument is about imports. **An export names no dependency.** What an ordinal
export loses is a *definition*, and a definition is how a statically linked copy is
recognised, which is the posture this tool exists to catch and the one with no `needed` entry
behind it by definition. The export was on the list because it was written into the same
sentence, not because the sentence was ever true of it.

Measured on one `.pyd` exporting `PyInit__ext`, `EVP_DigestInit_ex` and `SSL_new`, with no
OpenSSL banner to fall back on:

```text
honest                     -> static, BIN_STATIC_OPENSSL
NumberOfNames = 0          -> none,   BIN_PARTIAL_ROUTINE only, needs_human_review: false
NumberOfNames = 1 (of 3)   -> none,   BIN_PARTIAL_ROUTINE only, needs_human_review: false
```

One edited header field and a statically linked OpenSSL read clean. `NumberOfNames` is a
count the object keeps about itself, and PE has no string table to check it against the way
ELF and Mach-O now check theirs, so understating it is free.

**What it costs to reverse, measured rather than assumed.** Over 37 real `win_amd64` wheels
from PyPI, 383 PE objects: `pe_ordinal_export` appeared once, on `duckdb`'s
`_duckdb.cp310-win_amd64.pyd`, and not as a `NONAME` export — export 724 of 3548 is a
1027-byte MSVC-mangled C++ name, three bytes past the reader's own 1024-byte cap. That object
already carried `pe_export_incomplete` and was already `OPAQUE`. Objects where
`pe_ordinal_export` is the only cause: **0**. Net new `OPAQUE` wheels: **0**.

**Why the import stays.** Its argument survives its own scrutiny: `WS2_32` really is bound by
ordinal on every Windows extension that touches sockets, so the cost of reversing it is every
such wheel, and the DLL name really does survive in `needed`. The residual there is narrower
and is pinned by a test rather than assumed away.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#the-export-half-of-this-was-wrong) ·
[#47](https://github.com/EmilienM/wheel-crypto-scan/issues/47)

### A carve-out list is a claim, and claims get tested

**The general rule this produced, promoted out of the story that produced it.**

Two causes went onto a list that exempts them from a verdict because one sentence covered
both, and the sentence was true of one. Nothing failed; the list is policy and policy has no
wrong answers to fail against.

!!! danger "The admission test"

    Go and find a crypto object that reads clean because the cause is on the list. If that
    object exists the cause does not belong there, whatever the sentence says.

For the ordinal export it took one fixture and one edited header field. This sits beside the
invariant in `AGENTS.md`, because the list is the invariant's only carve-out and the next
candidate will arrive with a sentence too.

---

## A symbol table is checked against the string table, not taken at its word

**Accepted. It reverses an earlier decision and it changes verdicts.**

`LC_SYMTAB` says where the symbol table is and how many entries it has, and `.dynsym`'s
`sh_size` says the same thing in ELF. Reading exactly that many is not the same as reading
every symbol the object carries, and the difference is a way to look clean:

```text
honest: 2 crypto imports        -> OPAQUE
nsyms=0 over the same rows      -> NO_CRYPTO_DETECTED
nsyms=1 over 3, benign first    -> NO_CRYPTO_DETECTED
```

Both liars have `_EVP_DigestInit_ex` and `_SSL_new` physically present with a full string
table. Every structural check passed.

`nsyms == 0` was explicitly exempt, on the reasoning that a table declaring nothing has
nothing to fail at. That was wrong the same way counting a debug record was wrong: it tells
us exactly what an absent `LC_SYMTAB` tells us, and an absent one has always been incomplete.

**The count is cross-checked against the string table.** Nothing structural says how many
rows there really are — what sits between the symbol table and the string table is
`LC_DYSYMTAB`'s business, and assuming they are adjacent is wrong for real LINKEDIT layouts.
But the string table is the one place every name must appear. A name in it that matches a
symbol group and that no entry we read named is a symbol the object carries and did not
declare.

**What it costs.** The string table is scanned by one regex in C, and only the runs it lands
in are decoded, so an honest table pays one pass. Splitting the table instead took peak
memory from 1.0 MiB to 12.4 MiB on a 1.6 MiB object; walking it run by run in Python put a
2 MiB string table of two-byte runs at 19 seconds across a universal binary's slices, and 31
seconds if the runs held control bytes. Both are 1.2 seconds through the locator. Over the
whole reader on 497,040 honest symbols in a 26 MiB object: 2.7s to 3.1s, peak RSS 12.4 MiB to
14.8 MiB.

**Two limits, both deliberate.** The check asks whether a *crypto* name went unread, not
whether any name did, so padding and ordinary unreferenced strings do not make every object
partial. And names are formed the way the table is laid out, from one NUL to the next, so a
name that is the tail of a longer string is reachable and is not formed here. Closing that
means matching at every offset the locator hits, and the cost is not the scan, it is the
false positives: every Rust or C++ object with a crypto name mangled inside a symbol would
read as an object hiding one. Left open knowingly
([#39](https://github.com/EmilienM/wheel-crypto-scan/issues/39)).

**Both readers make the check, from one place.** `binfmt.symtab` holds the walk, because a
security check that exists twice is a security check that drifts. What the readers keep is
what only they know: Mach-O inverts Darwin's ABI underscore before matching and ELF must not.
Cost on ELF matches Mach-O: 497,040 dynamic symbols in a 29 MiB object go from 1.7s to 2.0s,
memory unchanged, and no object among 6,502 real ELF binaries on a Fedora host is flagged.

**The cross-check is only sound over a string table we read through,** which is the sibling
guard and was missing on the ELF side. Shrink `.dynstr` instead of `.dynsym` and every row
survives, every count survives, and the names simply stop being reachable. Worse, the bytes
left over were reported as symbols — a `.dynstr` cut to 24 bytes put `EVP_DigestI` in
`matched_symbols`, a name the object does not carry, in the field the whole tool turns on.
Both readers now treat an index past the end, or a run the table never closes, as a name they
could not resolve.

**Two tables are still believed.** ELF's `.symtab` drives `stripped` and
`symbol_counts.symtab` and nothing else, so a lie there costs a recorded field rather than a
finding. PE has no analogue to bring the check to: its imports have no declared count at all,
and its exports have one with no string table to check it against.

**What silence still costs, and it is not nothing.** `resolve_linkage` reads errors and
`is_opaque`, not `partial_analysis`, so a Mach-O that declares no entries came out `OPAQUE`
with `openssl_linkage: none` — one field saying we could not read it and another saying there
is no OpenSSL here. That is the next entry.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-symbol-table-is-checked-against-the-string-table-not-taken-at-its-word) ·
[#34](https://github.com/EmilienM/wheel-crypto-scan/issues/34)

---

## Linkage reads a second split over the same vocabulary

**Accepted. It changes the field most consumers filter on.**

`resolve_linkage` decided "we could not tell" from `is_opaque` and the binary-stage errors,
and never from `partial_analysis`. So an object a reader had explicitly marked as not read in
full, but that recorded no error, still contributed a definite posture. The everyday case is
a stripped macOS extension:

```text
partial_reasons: ['macho_symtab_incomplete']
openssl_linkage: none
```

One field says the symbol table was not read; the next says there is no OpenSSL in the
object, which is a claim the first says we cannot make. `is_opaque` does not rescue it,
because `needed` is non-empty for every loadable dylib and every `.pyd`.

**Why it is not one boolean.** `partial_analysis` is true for linker conventions too.
Counting the tuple wholesale would turn every ordinal import into `openssl_linkage: unknown`,
which is exactly the noise the carve-out above removed from the verdict, arriving again
through a different field.

**So there are two lists over one vocabulary, and they differ on purpose.**
`[linkage_policy] exclude_reasons` names the causes that leave every field linkage reads —
`needed`, `vendored_path`, the imported-versus-defined split, `matched_strings` — intact. A
`partial_binary` rule with no verdict names the causes not worth one. They are not the same
question: `elf_symtab_unread` is worth a verdict and costs linkage nothing. A test asserts the
two lists differ, so if they ever coincide the mechanism is a rename and should be one.

**One containment holds, and the loader refuses a ruleset that breaks it.** Every cause a
verdict-less rule claims must be exempt here too. A cause recorded without a verdict has
promised the wheel is not on its own worth a human's time; letting it cost the linkage answer
puts it straight back on the triage list. Asserting that over the shipped ruleset alone left
every `--ruleset` user outside the guard, so it is a `RulesetError` rather than a test.

The containment holds in one direction only, and it is worth being exact about which. The
loader refuses a verdict-less cause that is not exempt, so dropping an exemption forces the
re-rating. It does not refuse the converse — re-rating the verdict while leaving the exemption
in place loads clean, because a cause being worth a verdict and costing linkage nothing is
legitimate and is what `elf_symtab_unread` is. What holds that side is an exact-set assertion
in the test suite, which does not reach a `--ruleset` user. That is the weaker mechanism, and
it is weaker on purpose: there is nothing here to enforce.

**Absence of the table derives it, rather than emptying it.** An empty default is
conservative read on its own and self-contradicting read in composition: a custom ruleset
keeping `BIN_PARTIAL_ROUTINE` and omitting `[linkage_policy]` would report `unknown` for an
ordinary ordinal import. Omitting the table now yields exactly the verdict-less causes; the
explicit table is the override that widens them.

**A partial read that names no cause costs the answer too.** `partial_analysis` true with an
empty `partial_reasons` is the shape the engine singles out as the most serious there is — no
reader produces it, so the evidence was built by hand. Reading the empty tuple as "nothing
excluded, so nothing was lost" made `linkage` the one consumer of that field that quietly
downgraded it.

**What it costs.** Every stripped macOS wheel moves from `openssl_linkage: none` to `unknown`
and picks up a `BIN_OPENSSL_LINKAGE_UNKNOWN` finding. That is a lot of wheels, and the honest
reading is that we never could answer for them. Their verdict class does not move; what moves
is that filtering on `openssl_linkage == "none"` stops quietly including wheels whose symbol
tables nobody read.

**Whose answer loses.** Only the wheel's. The aggregate consults this signal exclusively when
nothing in the wheel answered definitely, so one unreadable object still cannot erase what the
readable ones said.

### The `always_report` gate had a second, unguarded route around it

**Corrected.** `_binary_posture` (not `_left_unanswered`) separately returned `unknown` for
any opaque object, once per library in the ruleset's per-library loop -- bypassing the
`always_report` gate this whole entry describes and making all thirteen shipped libraries
report `unknown`, not only `openssl`, the one library with `always_report = true`. Deleted;
`_left_unanswered` already covered `is_opaque`, and now it is the only route a wheel-wide
non-answer can reach the record through.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#linkage-reads-a-second-split-over-the-same-vocabulary) ·
[#40](https://github.com/EmilienM/wheel-crypto-scan/issues/40), corrected in
[#68](https://github.com/EmilienM/wheel-crypto-scan/issues/68)
