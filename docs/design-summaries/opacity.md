# Evidence, opacity and verdicts

Three entries about the line between "we read this and found nothing" and "we did not read
this". Getting that line wrong in the favourable direction is the failure mode the whole
tool exists to avoid, and each of these is pinned by going and building the object that
crosses it.

## A routine cause is recorded but does not make a wheel opaque

**Accepted, and it changes verdicts. See "An ordinal export is a failure to read, not a
convention" below for the one cause this list does not hold.**

`partial_analysis` has a score of causes behind it. `BIN_PARTIAL_FORMAT` fires `OPAQUE`
plus `needs_human_review` for most of them; `BIN_PARTIAL_ROUTINE` claims the ones that
read as a linker convention rather than a failure. The one it claims is an import bound by
ordinal: a convention a linker produces on purpose rather than anything that went wrong,
with no function name to match.

`WS2_32` is normally bound by ordinal, so that is the ordinary shape of a Windows extension
that touches sockets. Measured on two wheels identical but for that, with the ordinal
import treated as a failure:

```text
all imports named   -> NO_CRYPTO_DETECTED
WS2_32 by ordinal   -> OPAQUE
```

One linker convention, and the wheel joins the `OPAQUE` triage list. That is a real cost:
the list is read by a human, and padding it with wheels nobody needs to look at is how a
triage list stops being read at all.

**How it works.** `[rule.match] kind = "partial_binary"` takes `reasons` and
`exclude_reasons`, so the ruleset decides which causes are worth a verdict rather than the
engine treating them alike. `BIN_PARTIAL_ROUTINE` claims the ordinal import with no verdict
and no human review; `BIN_PARTIAL_FORMAT` keeps `OPAQUE` for everything else. An object with
both kinds of cause fires both rules, so the failure still wins.

**What it costs, and why `pe_delay_load` is not on the list.** A wheel whose only
incompleteness is an ordinal import reads `NO_CRYPTO_DETECTED` rather than `OPAQUE`.
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

[Full entry](../DESIGN.md#a-routine-cause-is-recorded-but-does-not-make-a-wheel-opaque)

### An ordinal export is a failure to read, not a convention

**Accepted, and it changes verdicts. `pe_ordinal_export` is a failure to read, not a
convention.**

"An import or an export bound by ordinal has no name to match" reads as one argument, and
the reason it makes the import routine — the dependency name survives in `needed` — is
about imports. **An export names no dependency.** What an ordinal export loses is a
*definition*, and a definition is how a statically linked copy is recognised, which is the
posture this tool exists to catch and the one with no `needed` entry behind it by
definition.

What treating it as routine costs, measured on one `.pyd` exporting `PyInit__ext`,
`EVP_DigestInit_ex` and `SSL_new`, with no OpenSSL banner to fall back on:

```text
honest                     -> static, BIN_STATIC_OPENSSL
NumberOfNames = 0          -> none,   BIN_PARTIAL_ROUTINE only, needs_human_review: false
NumberOfNames = 1 (of 3)   -> none,   BIN_PARTIAL_ROUTINE only, needs_human_review: false
```

One edited header field and a statically linked OpenSSL reads clean. `NumberOfNames` is a
count the object keeps about itself, and PE has no string table to check it against the way
ELF and Mach-O check theirs, so understating it is free.

**What keeping it strict costs, measured rather than assumed.** Over 37 real `win_amd64` wheels
from PyPI, 383 PE objects: `pe_ordinal_export` appeared once, on `duckdb`'s
`_duckdb.cp310-win_amd64.pyd`, and not as a `NONAME` export — export 724 of 3548 is a
1027-byte MSVC-mangled C++ name, three bytes past the reader's own 1024-byte cap. That object
also carries `pe_export_incomplete` and is `OPAQUE` regardless. Objects where
`pe_ordinal_export` is the only cause: **0**. Net new `OPAQUE` wheels: **0**.

**Why the import stays.** Its argument survives its own scrutiny: `WS2_32` really is bound by
ordinal on every Windows extension that touches sockets, so the cost of making it strict is every
such wheel, and the DLL name really does survive in `needed`. The residual there is narrower
and is pinned by a test rather than assumed away.

[Full entry](../DESIGN.md#an-ordinal-export-is-a-failure-to-read-not-a-convention)

### A carve-out list is a claim, and claims get tested

**Accepted.**

A list that exempts causes from a verdict is policy, and policy has no wrong answers to fail
against. A cause admitted on the strength of a sentence that is true of its neighbour, and
not of itself, reads fine and fails nothing — the ordinal export above is exactly that
shape.

!!! danger "The admission test"

    Go and find a crypto object that reads clean because the cause is on the list. If that
    object exists the cause does not belong there, whatever the sentence says.

For the ordinal export it takes one fixture and one edited header field. This sits beside the
invariant in `AGENTS.md`, because the list is the invariant's only carve-out and the next
candidate will arrive with a sentence too.

---

## A symbol table is checked against the string table, not taken at its word

**Accepted, and it changes verdicts.**

`LC_SYMTAB` says where the symbol table is and how many entries it has, and `.dynsym`'s
`sh_size` says the same thing in ELF. Reading exactly that many is not the same as reading
every symbol the object carries, and the difference is a way to look clean. Taken at its
word:

```text
honest: 2 crypto imports        -> OPAQUE
nsyms=0 over the same rows      -> NO_CRYPTO_DETECTED
nsyms=1 over 3, benign first    -> NO_CRYPTO_DETECTED
```

Both liars have `_EVP_DigestInit_ex` and `_SSL_new` physically present with a full string
table. Every structural check passes.

`nsyms == 0` is not exempt. Exempting it rests on the reasoning that a table declaring
nothing has nothing to fail at, which fails the same way counting a debug record as a symbol
fails: a table declaring nothing tells us exactly what an absent `LC_SYMTAB` tells us, and an
absent one is incomplete.

**The count is cross-checked against the string table.** Nothing structural says how many
rows there really are — what sits between the symbol table and the string table is
`LC_DYSYMTAB`'s business, and assuming they are adjacent is wrong for real LINKEDIT layouts.
But the string table is the one place every name must appear. A name in it that matches a
symbol group and that no entry we read named is a symbol the object carries and did not
declare.

**What it costs.** The string table is scanned by one regex in C, and only the runs it lands
in are decoded, so an honest table pays one pass. Splitting the table instead takes peak
memory from 1.0 MiB to 12.4 MiB on a 1.6 MiB object; walking it run by run in Python puts a
2 MiB string table of two-byte runs at 19 seconds across a universal binary's slices, and 31
seconds if the runs hold control bytes. Both are 1.2 seconds through the locator. Over the
whole reader on 497,040 honest symbols in a 26 MiB object, against no cross-check: 2.7s to
3.1s, peak RSS 12.4 MiB to 14.8 MiB.

**Two limits, both deliberate.** The check asks whether a *crypto* name went unread, not
whether any name did, so padding and ordinary unreferenced strings do not make every object
partial. And names are formed the way the table is laid out, from one NUL to the next, so a
name that is the tail of a longer string is reachable and is not formed here. Closing that
means matching at every offset the locator hits, and the cost is not the scan, it is the
false positives: every Rust or C++ object with a crypto name mangled inside a symbol would
read as an object hiding one. Left open knowingly.

**Both readers make the check, from one place.** `binfmt.symtab` holds the walk, because a
security check that exists twice is a security check that drifts. What the readers keep is
what only they know: Mach-O inverts Darwin's ABI underscore before matching and ELF must not.
Cost on ELF matches Mach-O: 497,040 dynamic symbols in a 29 MiB object go from 1.7s to 2.0s,
memory unchanged, and no object among 6,502 real ELF binaries on a Fedora host is flagged.

**The cross-check is only sound over a string table we read through,** which is the sibling
guard. Shrink `.dynstr` instead of `.dynsym` and every row survives, every count survives, and
the names simply stop being reachable. Worse, the bytes left over would be reported as
symbols — a `.dynstr` cut to 24 bytes puts `EVP_DigestI` in `matched_symbols`, a name the
object does not carry, in the field the whole tool turns on. Both readers treat an index past
the end, or a run the table never closes, as a name they could not resolve.

**One table's size is still believed.** ELF's `.symtab` drives `stripped` and
`symbol_counts.symtab`, so a lie in its size costs a recorded field rather than a finding;
what `.symtab` contributes to matching is cross-checked the way `.dynsym`'s is. PE has no
analogue to bring the check to: its imports have no declared count at all, and its exports
have one with no string table to check it against.

**Silence still costs the linkage answer.** A Mach-O that declares no entries records no
error, but its `partial_reasons` names `macho_symtab_incomplete`, and `resolve_linkage` reads
that cause, so the object comes out `OPAQUE` with `openssl_linkage: unknown` rather than one
field saying we could not read it and another saying there is no OpenSSL here. That is the
next entry.

[Full entry](../DESIGN.md#a-symbol-table-is-checked-against-the-string-table-not-taken-at-its-word)

---

## Linkage reads a second split over the same vocabulary

**Accepted. It changes the field most consumers filter on.**

Deciding "we could not tell" from `is_opaque` and the binary-stage errors alone, and never
from `partial_analysis`, lets an object a reader explicitly marked as not read in full, but
that recorded no error, contribute a definite posture. The everyday case is a stripped macOS
extension:

```text
partial_reasons: ['macho_symtab_incomplete']
openssl_linkage: none
```

One field says the symbol table was not read; the next says there is no OpenSSL in the
object, which is a claim the first says we cannot make. `is_opaque` does not rescue it,
because `needed` is non-empty for every loadable dylib and every `.pyd`.

**Why it is not one boolean.** `partial_analysis` is true for linker conventions too.
Counting the tuple wholesale would turn every ordinal import into `openssl_linkage: unknown`,
which is exactly the noise the carve-out above keeps out of the verdict, arriving again
through a different field.

**So there are two lists over one vocabulary, and they differ on purpose.**
`[linkage_policy] exclude_reasons` names the causes that leave every field linkage reads —
`needed`, `vendored_path`, the imported-versus-defined split, `matched_strings` — intact. A
`partial_binary` rule with no verdict names the causes not worth one. They are not the same
question: `elf_go_buildinfo_unread` is worth a verdict and costs linkage nothing (Go toolchain
provenance feeds no field `linkage` reads). A test asserts the two lists differ, so if they
ever coincide the mechanism is a rename and should be one.

**One containment holds, and the loader refuses a ruleset that breaks it.** Every cause a
verdict-less rule claims must be exempt here too. A cause recorded without a verdict has
promised the wheel is not on its own worth a human's time; letting it cost the linkage answer
puts it straight back on the triage list. Asserting that over the shipped ruleset alone would
leave every `--ruleset` user outside the guard, so it is a `RulesetError` rather than a test.

The containment holds in one direction only, and it is worth being exact about which. The
loader refuses a verdict-less cause that is not exempt, so dropping an exemption forces the
re-rating. It does not refuse the converse — re-rating the verdict while leaving the exemption
in place loads clean, because a cause being worth a verdict and costing linkage nothing is
legitimate and is what `elf_go_buildinfo_unread` is. What holds that side is an exact-set
assertion in the test suite, which does not reach a `--ruleset` user. That is the weaker
mechanism, and it is weaker on purpose: there is nothing here to enforce.

**`elf_symtab_unread` is not on the exemption list.** Exempting it would rest on the claim
that `.symtab` drives only `stripped` and `symbol_counts.symtab`, never the
imported-versus-defined split — a claim that does not hold: `.symtab` is this reader's only
symbol table for a relocatable object with no `.dynsym`, and it supplies local definitions
beside `.dynsym` when there is one. Either way a failed `.symtab` read costs part of the
split, so the cause costs the linkage answer unconditionally.

**Absence of the table derives it, rather than emptying it.** An empty default is
conservative read on its own and self-contradicting read in composition: a custom ruleset
keeping `BIN_PARTIAL_ROUTINE` and omitting `[linkage_policy]` would report `unknown` for an
ordinary ordinal import. Omitting the table yields exactly the verdict-less causes; the
explicit table is the override that widens them.

**A partial read that names no cause costs the answer too.** `partial_analysis` true with an
empty `partial_reasons` is the shape the engine singles out as the most serious there is — no
reader produces it, so the evidence was built by hand. Reading the empty tuple as "nothing
excluded, so nothing was lost" would make `linkage` the one consumer of that field that
quietly downgrades it.

**What it costs.** Every stripped macOS wheel reads `openssl_linkage: unknown` rather than
`none`, and carries a `BIN_OPENSSL_LINKAGE_UNKNOWN` finding. That is a lot of wheels, and the
honest reading is that we never could answer for them. Their verdict class is unaffected;
what it buys is that filtering on `openssl_linkage == "none"` does not quietly include wheels
whose symbol tables nobody read.

**Whose answer loses.** Only the wheel's. The aggregate consults this signal exclusively when
nothing in the wheel answered definitely, so one unreadable object still cannot erase what the
readable ones said.

### The `always_report` gate also covers the opaque fallthrough

`_binary_posture`'s own fallthrough, reached when nothing about an object said `system`,
`bundled`, `static` or `unknown`-via-imported-symbol, returns `LINKAGE_NONE` and never
sets `LINKAGE_UNKNOWN` directly: an opaque object's `unknown` posture is set only through
`_left_unanswered`/`_aggregate`'s `always_report` gate, library by library, so an opaque
object costs only `openssl`, the one library with `always_report = true`, not all
thirteen shipped libraries.

[Full entry](../DESIGN.md#linkage-reads-a-second-split-over-the-same-vocabulary)
