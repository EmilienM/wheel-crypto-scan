# ELF

Three entries about `binfmt/elf.py`. The first covers the widest set of shapes — a
`.dynamic`/`.dynsym`/`.symtab` lookup has to reject each of them the same way — and the
pattern behind all of them is worth internalising before reading any: **an
attacker-controlled label winning a lookup, so the check meant to catch a mismatch never
runs.**

## Sections are found by type, not by a name nobody checks

**Accepted, and it changes records.**

Comparing `section.name` against `.dynamic`, `.dynsym` and `.symtab` trusts a label, but the
ELF *loader* never reads section names or the section header table at all: it walks
`PT_DYNAMIC` and the tags it points at. A name-based lookup trusts a label nothing downstream
of the compiler checks. Found by name:

```text
honest: EVP_DigestInit_ex, SSL_new imported, libc.so.6 in DT_NEEDED
.dynsym renamed .dynsyx in .shstrtab, same bytes otherwise  -> NO_CRYPTO_DETECTED,
                                    needs_human_review: false, partial_analysis: false
```

Renaming `.dynamic` too empties `needed` as well, and the object still loads and runs through
`ctypes` exactly as before: nothing about what the loader does differs, only what one label in
`.shstrtab` says.

**The check has two parts, because two shapes produce the same silence.** The three sections
are found by `sh_type`. `pyelftools` builds the right wrapper class from `sh_type` alone; the
name only ever becomes an attribute this reader is the only thing reading. `.go.buildinfo`,
`.note.go.buildid` and `.comment` stay name-based — they are plain `SHT_PROGBITS`/`SHT_NOTE`
sections with no type of their own, so a name is the only signal there is.

The second shape is not a renamed label but no section header table at all. `e_shoff == 0` is
a loadable object's own right, since the dynamic linker never reads one, and unhandled it reads
worse than a header that would not parse: the unparsed path scans the whole file for strings,
but an empty section list feeds nothing to the strings pass, so a statically-linked
`cryptography` extension with no section headers would lose even its OpenSSL version banner —
its only evidence — with no error and `partial_analysis: false`. It falls back to the same
whole-file strings pass, tagged `elf_section_table_absent`.

That token is its own rather than a reuse of `elf_sections_unread`, which means "a section
header could not be read" at a specific index. Here there is no section list to try at all, so
those sections are not merely unread but unavailable.

### What type-based section lookup has to reject

**A decoy of the matching type ahead of the real table must not hide it.** "The first
section of a matching type wins" would let a decoy hide the real table — the exact
failure this entry exists to prevent, one level down. Reproduced on a real, loadable
`/usr/lib64/libcrypto.so.3`: two 64-byte decoy section headers spliced in *before* the real
`.dynsym` and `.dynamic`, every dependent index shifted to stay valid. The object still loads
and runs; name-based lookup alone reads `needed = ('libc.so.6', 'libz.so.1')`, a soname and
6043 dynsyms, `CONDITIONAL` — "first match wins" over the decoyed section list would read
`needed = ()`, 0 symbols, `partial_analysis: false`, 0 errors, `NO_CRYPTO_DETECTED`.

The symbol/string cross-check ("A symbol table is checked against the string table, not
taken at its word") does not help here: it is sound only over the string table the
*chosen* section's `sh_link` names, and the decoy's `sh_link` points at `.shstrtab`, which
disarms it entirely rather than tripping it. That disarm property is its own attack
surface, closed separately below.

The lookup reports ambiguity instead of returning a single answer, and the caller trusts
neither candidate: everything derived reads empty, tagged `elf_section_type_ambiguous`, so an
object carrying two `SHT_DYNSYM` sections never reads as one carrying none. Tests cover both
orderings — the decoy after the real section (the shape a first-match-wins lookup would
get right by accident) and before it (the shape it would get wrong).

**A forged `sh_type` on a legitimately-named section must not read as fully absent,
which would be worse than trusting the name blindly.** One four-byte edit — `.dynsym`'s
`sh_type` changed from `SHT_DYNSYM` to `SHT_PROGBITS`, the name left untouched — and the
object still loads. Name-based lookup alone still finds it, the wrapper class is wrong
and the count fails, so it correctly sets `partial_analysis: true`; the raw symbol bytes
are read by offset and size directly regardless, so it still recovers 64 symbols on a
real `libcrypto.so.3`. Type-based lookup alone would find nothing and treat that as
genuinely absent: clean, no evidence, no flag — strictly worse than trusting the name.

`_type_mismatch` closes it: a name-based lookup checks whether a section still called one of
the three names exists whose declared `sh_type` does not match. If it does, that is a section
that exists and cannot be trusted, folded into the same cause a read failure carries.

**The mismatch check must not run only when the type-based lookup found nothing,** or
one decoy of the target type disables it entirely — the same hazard as above, through a
third door. One harmless decoy makes the type-based lookup succeed *unambiguously*, so a
gated mismatch check never runs; combine that with forging the real section's own
`sh_type` away and the real section is invisible from both directions at once.

```text
honest:       partial=False needed=('libc.so.6',) syms=['EVP_DigestInit_ex','SSL_new']
              linkage={'openssl':'unknown'} verdict=OPAQUE      needs_human_review=True
decoy+forge:  partial=False needed=('libc.so.6',) syms=[]       errors=0
  (gated)     linkage={'openssl':'none'}    verdict=NO_CRYPTO_DETECTED needs_human_review=False
```

The headline failure verbatim, reached through the very check meant to close a narrower
version of it, and worse than name-based lookup alone, which still catches this exact
byte pattern. The mismatch check runs unconditionally, every time, at no cost on an
honest object.

**`_type_mismatch`'s own building block must reject the same hazard, applied to name
instead of type.** Finding "the section named X" with a first-match-wins lookup is the
identical hazard above, applied to name instead of type. A decoy reusing the real
section's own *name*, correctly typed, sorts first and reports no mismatch, so a
same-named real section behind it with its own forged `sh_type` would go unseen from
both directions again — the headline failure again, through the building block meant to
close it. More than one section sharing a name is treated the same way as more than one
sharing a type.

**`sh_link` itself must be validated, not trusted at face value.** The string table is
resolved by raw index; trusting it with no check that the resolved section is even a
string table, and no reconciliation against `.dynamic`'s own `DT_STRTAB` tag (which the
reader parses anyway), leaves it open to the identical hazard above. `sh_link` is a
field the loader never reads either.

Reproduced against a reader that trusts `sh_link`, on real, unmodified loadable objects —
`/usr/lib64/libcrypto.so.3` and a real CPython `_hashlib` extension: append N NUL bytes plus a
new `SHT_STRTAB` header pointing at them, then repoint `.dynsym`'s `sh_link` at that index.
Every name index resolves to `""` against an all-NUL table, and `""` is a name *resolved*, not
one flagged unresolved. `libcrypto.so.3`'s 64 crypto symbols and `_hashlib`'s 24 both go to
zero, with `partial_analysis: false`, no error, and both objects still loading.

`.dynamic`'s own `sh_link` has the identical hole and is worse: it can **fabricate** evidence,
not just erase it. A decoy that happens to spell a real dependency name at the offset a real
`DT_NEEDED` tag points at reports a dependency the object never declares — the fabrication
direction of "a name reported is a name read in full", rather than the truncation direction.

Both are reconciled against data the reader has in hand: a resolved section corroborates only
when its `sh_type` is `SHT_STRTAB` **and** its `sh_addr` matches `DT_STRTAB`'s `d_ptr`. Either
mismatched, or no `DT_STRTAB` to compare against at all, fails closed. This cascades correctly:
an object whose `.dynamic` cannot be corroborated has no `DT_STRTAB` to hand `.dynsym` either,
so `.dynsym`'s string table is untrusted too even when its own `sh_link` is perfectly honest.

**What was rejected.** Reading `PT_LOAD` and the program headers directly — the loader's
own path, immune to a section header table that lies in ways these checks do not cover.
It is the more complete approach and materially more work, a second parser for
information this reader gets from section headers in the common case.

!!! note "Accepted residual"

    A decoy resolved through `sh_link` that is correctly typed **and** whose `sh_addr` matches,
    but whose `sh_offset` alone points at fabricated bytes, still reads clean. Nothing outside
    `PT_LOAD` segment contents corroborates that a given virtual address really lives at a
    given file offset. **Do not chase this by adding another targeted field comparison;** the
    next real gap in this family is answered by program-header-based translation as a whole,
    not by another field.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#sections-are-found-by-type-not-by-a-name-nobody-checks)

---

## A compressed section is checked before it is inflated

**Accepted. Refuse to inflate past what can be used.**

`Section.data()` decompresses a `SHF_COMPRESSED` section's declared `ch_size` bytes before the
reader's own budget ever applies. `ch_size` is a 64-bit field the object declares about itself,
except here the number buys an actual `zlib` call rather than a Python loop, so the cost is a
memory spike. The reproduction, without a check: a 255 KiB ELF declaring a 256 MiB `.rodata`,
peaking at **512 MiB** in 0.82 s. The archive-level compression-ratio guard never sees this
shape, because the zlib stream sits inside the zip member, whose own ratio looks ordinary.

**Checked with a call pyelftools makes anyway, not a new one.** `pyelftools` reads the
compression header eagerly and cheaply and exposes `section.compressed` and
`section.data_size`, so the guard reads a property and refuses without calling `.data()` at
all. Both ELF classes are covered by construction.

**`.go.buildinfo` carries a second, uncompressed exposure the same check must close.**
`Section.data()` checks `SHT_NOBITS` *before* it checks compression, and for such a section
returns that many zero bytes with no file bytes read to justify the length. `.go.buildinfo` is
found by name with no type check, so a section named `.go.buildinfo` and flagged `SHT_NOBITS`
would reach the call exactly the way an honest one does through a guard keyed only on
compression: a 298-byte object declaring 2048 MiB peaks at 2 GiB, `partial_analysis: false`,
no error — three orders of magnitude cheaper to build than the compressed reproduction, and
silent rather than merely expensive.

**The boundary is "more than", not "at least".** A section declaring exactly the remaining
budget is refused nothing.

**`strings_truncated` can under-report a budget refusal, and this is left as-is rather than
papered over.** A refused section was never read at all, so nothing knows how many of its bytes
would have been genuine strings. Setting the flag anyway does not hold up: a fixture has
`.rodata` filled with the OpenSSL banner text and `SHF_COMPRESSED` set over bytes that were
never compressed, whose first 24 bytes decode as a header with `ch_size` around 3.76×10^18
purely by accident of what those ASCII bytes are. There was never a real 3.76-exabyte payload
to have dropped part of.

**What was rejected.** Decompressing with a caller-supplied `max_length`, keeping whatever
prefix fits. It is bounded correctly — verified directly — and that is not what rules it out: it
needs a second zlib call outside `pyelftools`, a second reader for one fact, and it would split
two call sites onto different rules for the identical shape. And treating any compressed
eligible section as unread regardless of size, which throws away an honest, small,
well-under-budget banner for no reason.

### An ordinary section is bounded too

Checking the budget only when the section is compressed or `SHT_NOBITS` is not enough. An
ordinary, uncompressed, file-backed section falls through that `and` entirely and reaches
`.data()` unconditionally, at whatever size `sh_size` names, with only the *accumulated*
buffer cut afterwards. So the declared size is checked against the budget for every section
regardless of shape.

With the narrower guard: an honest 8 MiB `.rodata` against a 64 KiB budget is one
8388608-byte read. A `.dynsym`/`.dynstr` from 200,000 real symbol names against the same
budget reads `partial_analysis: false` — a fully clean, complete record, paid for at the size
of the honest table rather than the budget, with no way for a consumer to tell.

**Two more shapes this budget must also close.**

**A refused `.dynsym` or `.dynstr` must not reach the cross-check unguarded**, or it can
fabricate `symtab_understates_rows` — a specific, checkable claim ("every structural check
passes and the count is simply not the truth") — against a table that was never shown to lie,
only left unread. With `.dynsym` refused, no rows are yielded, so the sibling branch would find
a real crypto name in an honest `.dynstr` unclaimed by any row and report it as an understated
count. Reproduced without the ordering: 101 entries against a 600-byte budget read
`('elf_dynsym_unread', 'symtab_understates_rows')` with the error ".dynsym declares fewer
entries than .dynstr holds names for", both false. The refusal is checked first and the
whole per-symbol walk skipped.

**An over-budget ordinary section keeps its in-budget prefix, not discarding its entire
content**, the same as every other reader in the codebase. Reproduced against a real host
library, `/usr/lib64/libLLVM.so.22.1` (68.3 MB of eligible sections against the 64 MiB
default): keeping the in-budget prefix reads it `strings_bytes_unread`, no errors; refusing it
outright would read it `elf_section_data_unread` plus a spurious `elf_parse_error`, which fires
"truncated, corrupt or an unrecognised format" over `BIN_STATIC_OPENSSL` — a false-positive
downgrade on a perfectly ordinary, healthy object, at a size range that ML and scientific
wheels commonly reach. A `keep_prefix` flag hands back the section's own real first
`max_bytes` for `.rodata`/`.comment`/`.go.buildinfo`, one plain read, no decompression.

`.dynsym`/`.dynstr` keep the all-or-nothing refusal on purpose: **a byte-bounded prefix of a
symbol table is not a set of complete rows**, and an entry near the cut is as likely to point
past a truncated string table as into it. The honest way to bound a symbol table without losing
rows to that ambiguity exists in the Mach-O reader; bringing it here is a real change, and a
different, larger one.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-compressed-section-is-checked-before-it-is-inflated)

---

## `.symtab` is matched for crypto symbols when `.dynsym` is genuinely absent

**Accepted, and it changes records.**

Crypto symbol matching over `.dynsym` alone is correct for a dynamically linked object,
where `.dynsym` is what the dynamic linker actually uses, but a relocatable object
(`ET_REL`, a `.o`/`.obj` before linking, the shape every static archive member has) or
a statically linked executable normally has no `.dynsym` at all, only `.symtab`. A
genuine `EVP_DigestInit_ex` definition there, with no accompanying string banner, would be
invisible to the tool's primary detection mechanism.

Full matching — imports and definitions, `.symtab` as the object's only table — applies only
when `.dynsym` is genuinely absent: a *dynamically* linked shared object or executable always
carries a live `.dynsym` (`strip` cannot remove it without breaking dynamic linking), so this
mode leaves that part of the corpus unaffected by construction. A statically linked executable
is matched too, which is this reader's intended reach, not an incidental side effect.
"Genuinely absent" excludes an ambiguous or type-forged `.dynsym`, and a `.dynsym` whose own
section header failed to parse and so never reached the section list at all — all three make
the lookup return `None` without the object genuinely having none. Beside a live `.dynsym`,
`.symtab` supplies definitions only (the next entry).

**Shapes this check must also reject, beyond a corroborated `sh_link`.** A `.symtab`
repointed at a decoy, appended, all-NUL `SHT_STRTAB` resolves every name to `""` — not
unresolved, *resolved* — so a crafted object could hide a genuine crypto definition and
read completely clean, the identical decoy `_validated_strtab` exists to close for
`.dynsym`, reachable here because `.symtab` has no independent authority to
corroborate `sh_link` against. `_any_strtab_holds_a_name_not_read` closes it by not
trusting the one table `sh_link` names: the cross-check asks every `SHT_STRTAB`
section in the object, so the real `.strtab` still gets to contradict the decoy
regardless of which one `.symtab` claims. Skipping a `SHT_STRTAB` section it cannot
fully read within budget would reopen the identical decoy under a second
construction — a small decoy plus a genuine `.strtab` inflated past the budget
elsewhere. An unread `SHT_STRTAB` counts as a hit, not a skip. Separately, `.symtab`
carries `STT_FILE`/`STT_SECTION` pseudo-symbols `.dynsym` does not — a source file
named `EVP_md5.c` would match a group by filename coincidence alone; filtered by type,
while still counted as read for the understated-rows check, so filtering evidence does
not itself manufacture a false "the object understates its own rows" claim.

`binfmt.ar` needs nothing of its own for an ELF member: it calls `read_binary` per member
regardless of format, so this reads every ELF archive member through `binfmt.elf` directly. A
Windows `.lib`'s COFF members are untouched; `binfmt.pe` deliberately does not read the COFF
symbol table at all.

**It costs the linkage answer.** `elf_symtab_unread` is not exempt from costing the linkage
answer, since `.symtab` feeds the imported/defined split: see
[Linkage reads a second split over the same vocabulary](opacity.md#linkage-reads-a-second-split-over-the-same-vocabulary).

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#symtab-is-matched-for-crypto-symbols-when-dynsym-is-genuinely-absent)

## `.symtab` local definitions are read when `.dynsym` is present

**Accepted, and it changes records.**

Matching `.symtab` only when `.dynsym` is genuinely absent (the entry above) leaves every
dynamically linked object unaffected *by construction* — and on its own leaves the case this
tool exists for unread. `cryptography` 50.0.1 carries **776 local `EVP_*` definitions in
`.symtab` and none in `.dynsym`**, whose only exports are the module's own `PyInit` symbols.
The statically linked OpenSSL sits in a table the reader parses for `stripped` anyway, and an
absence-gated reader never looks.

Only definitions are read beside a live `.dynsym`: a dynamically linked object must declare
every import in `.dynsym` to link at all, so taking imports from a debug table would restate
them under a second provenance, or let a planted undefined entry read as a dependency the
object does not have. Of `.symtab`'s two cross-checks, the understated-rows one does not run in
that mode, because it exists to catch the object's *only* table understating itself, and a
partially stripped `.symtab` is ordinary rather than a lie. The `unresolved` count asks a
different question — was a name the reader was *pointed at* readable — and an honest table never
fails it, so it runs in both modes.

Measured over 18 native wheels against the absence gate alone: five verdict blocks differ and
one headline class moves; three wheels go `openssl_linkage: none` → `static` on the AWS-LC they
compile in, with no finding and no `(group, binding)` kind lost anywhere. Every row is walked,
on every such object. A `symbol_locator` prefilter over `.strtab` would avoid that, and is
rejected: it is worth 0.32s against 0.55s on a 26.7 MiB object with half a million symbols,
and a `.strtab` shrunk to hide a name is one the prefilter reads as holding nothing, so the walk
that would catch it never runs (`cryptography` 0.43s → 0.50s, `scipy` 8.37s → 8.40s).

The cross-check that compares `.symtab`'s rows against every `SHT_STRTAB` in the object runs
here too, because it is the only thing that sees a `sh_link` repointed at a decoy table of
NULs, where every row "resolves" to the empty name. It is fed the names both tables resolved,
so an imported name `.dynsym` accounted for does not read as one the object hid.

What it costs is stated in full in
[`DESIGN.md`](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md): a
crafted object can plant names in a table trusted less than `.dynsym`, and the
consequence is a false *definition*, which over-flags rather than under-flags.
