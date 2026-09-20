# ELF

Three entries about `binfmt/elf.py`. The first is the longest chain of review findings in the
project — five rounds, each one closing a hole and each one opening the next through a
different field — and the pattern behind all five is worth internalising before reading any
of them: **an attacker-controlled label winning a lookup, so the check meant to catch a
mismatch never runs.**

## Sections are found by type, not by a name nobody checks

**Accepted, and it changes records.**

`_find_section` compared `section.name` against `.dynamic`, `.dynsym` and `.symtab`, but the
ELF *loader* never reads section names or the section header table at all: it walks
`PT_DYNAMIC` and the tags it points at. A name-based lookup trusted a label nothing
downstream of the compiler checks.

```text
honest: EVP_DigestInit_ex, SSL_new imported, libc.so.6 in DT_NEEDED
.dynsym renamed .dynsyx in .shstrtab, same bytes otherwise  -> NO_CRYPTO_DETECTED,
                                    needs_human_review: false, partial_analysis: false
```

Renaming `.dynamic` too empties `needed` as well, and the object still loads and runs through
`ctypes` exactly as before: nothing about what the loader does changed, only what one label in
`.shstrtab` said.

**The fix has two parts, because two shapes produced the same silence.** The three sections are
now found by `sh_type`. `pyelftools` already builds the right wrapper class from `sh_type`
alone; the name only ever became an attribute this reader was the only thing reading.
`.go.buildinfo`, `.note.go.buildid` and `.comment` stay name-based — they are plain
`SHT_PROGBITS`/`SHT_NOTE` sections with no type of their own, so a name is the only signal
there is.

The second shape is not a renamed label but no section header table at all. `e_shoff == 0` is a
loadable object's own right, since the dynamic linker never reads one, and it read worse than a
header that would not parse: the unparsed path still scans the whole file for strings, but an
empty section list fed nothing to the strings pass, so a statically-linked `cryptography`
extension with no section headers lost even its OpenSSL version banner — its only evidence —
with no error and `partial_analysis: false`. It now falls back to the same whole-file strings
pass, tagged `elf_section_table_absent`.

That token is new rather than a reuse of `elf_sections_unread`, which already means "a section
header could not be read" at a specific index. Here there is no section list to try at all, so
those sections are not merely unread but unavailable.

### The five rounds of review

**First: "the first section of a matching type wins" let a decoy hide the real table** — the
exact failure this entry exists to close, one level down. Reproduced on a real, loadable
`/usr/lib64/libcrypto.so.3`: two 64-byte decoy section headers spliced in *before* the real
`.dynsym` and `.dynamic`, every dependent index shifted to stay valid. The object still loads.
`main` read `needed = ('libc.so.6', 'libz.so.1')`, a soname and 6043 dynsyms and came out
`CONDITIONAL`; the first version of this fix read `needed = ()`, 0 symbols,
`partial_analysis: false`, 0 errors, `NO_CRYPTO_DETECTED`.

The existing symbol/string cross-check does not help: it is sound only over the string table
the *chosen* section's `sh_link` names, and the decoy's `sh_link` points at `.shstrtab`, which
disarms it entirely rather than tripping it. That disarm property is its own attack surface,
and closing it is the fifth finding below.

The lookup now reports ambiguity instead of returning a single answer, and the caller trusts
neither candidate: everything derived reads empty, tagged `elf_section_type_ambiguous`, so an
object carrying two `SHT_DYNSYM` sections never reads as one carrying none. Tests cover both
orderings — the decoy after the real section (which stayed safe only because "first wins"
happened to favour the real one) and before it.

**Second: a forged `sh_type` on a legitimately-named section used to read as fully absent,
which is worse than `main`.** One four-byte edit — `.dynsym`'s `sh_type` changed from
`SHT_DYNSYM` to `SHT_PROGBITS`, the name left untouched — and the object still loads. On
`main`, the name-based lookup still found it, the wrapper class was wrong and the count failed,
so `main` correctly set `partial_analysis: true`; but the raw symbol bytes were read by offset
and size directly, so `main` still recovered 64 symbols on a real `libcrypto.so.3`. The
type-based lookup found nothing and treated that as genuinely absent: clean, no evidence, no
flag. Strictly worse than `main`.

`_type_mismatch` closes it: a name-based lookup checks whether a section still called one of
the three names exists whose declared `sh_type` does not match. If it does, that is a section
that exists and cannot be trusted, folded into the same cause a read failure already carries.

**Third: the mismatch check ran only when the type-based lookup found nothing**, so one decoy
of the target type disabled it entirely — the first bug's shape, through a third door. One
harmless decoy makes the type-based lookup succeed *unambiguously*, so the gate never ran;
combine that with forging the real section's own `sh_type` away and the real section is
invisible from both directions at once.

```text
honest:       partial=False needed=('libc.so.6',) syms=['EVP_DigestInit_ex','SSL_new']
              linkage={'openssl':'unknown'} verdict=OPAQUE      needs_human_review=True
decoy+forge:  partial=False needed=('libc.so.6',) syms=[]       errors=0
  (pre-fix)   linkage={'openssl':'none'}    verdict=NO_CRYPTO_DETECTED needs_human_review=False
```

The headline failure verbatim, reached through the very check meant to close a narrower version
of it — and a regression against `main`, which still caught this exact byte pattern. The fix
drops the gate: the mismatch check now runs unconditionally, every time. It costs nothing on an
honest object.

**Fourth: `_type_mismatch`'s own building block could be defeated the same way.** It found
"the section named X" with a first-match-wins lookup — the identical hazard, applied to name
instead of type. A decoy reusing the real section's own *name*, correctly typed, sorts first and
reports no mismatch, so a same-named real section behind it with its own forged `sh_type` went
unseen from both directions again. The headline failure a fourth time. More than one section
sharing a name is now treated the same way as more than one sharing a type.

**Fifth: `sh_link` itself was never validated at all.** The string table was resolved by raw
index with no check that the resolved section is even a string table, and no reconciliation
against `.dynamic`'s own `DT_STRTAB` tag, which the reader already parses. `sh_link` is a field
the loader never reads either.

Reproduced against real, unmodified loadable objects — `/usr/lib64/libcrypto.so.3` and a real
CPython `_hashlib` extension: append N NUL bytes plus a new `SHT_STRTAB` header pointing at
them, then repoint `.dynsym`'s `sh_link` at that index. Every name index resolves to `""`
against an all-NUL table, and `""` is a name *resolved*, not one flagged unresolved.
`libcrypto.so.3`'s 64 crypto symbols and `_hashlib`'s 24 both went to zero, with
`partial_analysis: false`, no error, and both objects still loading.

`.dynamic`'s own `sh_link` has the identical hole and is worse: it can **fabricate** evidence,
not just erase it. A decoy that happens to spell a real dependency name at the offset a real
`DT_NEEDED` tag points at reports a dependency the object never declares — the fabrication
direction of "a name reported is a name read in full", rather than the truncation direction
that invariant was written against.

Both are now reconciled against data the reader already has in hand: a resolved section
corroborates only when its `sh_type` is `SHT_STRTAB` **and** its `sh_addr` matches
`DT_STRTAB`'s `d_ptr`. Either mismatched, or no `DT_STRTAB` to compare against at all, fails
closed. This cascades correctly: an object whose `.dynamic` cannot be corroborated has no
`DT_STRTAB` to hand `.dynsym` either, so `.dynsym`'s string table is untrusted too even when
its own `sh_link` is perfectly honest.

**What was rejected, five times.** Reading `PT_LOAD` and the program headers directly — "option
3", the loader's own path, immune to a section header table that lies in ways these checks do
not cover. It is the more complete fix and materially more work, a second parser for
information this reader already gets from section headers in the common case.

!!! note "Accepted residual"

    A decoy resolved through `sh_link` that is correctly typed **and** whose `sh_addr` matches,
    but whose `sh_offset` alone points at fabricated bytes, still reads clean. Nothing outside
    `PT_LOAD` segment contents corroborates that a given virtual address really lives at a
    given file offset. **Do not chase this by adding a sixth targeted field comparison;** the
    next real gap in this family is answered by option 3 as a whole, not by another field.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#sections-are-found-by-type-not-by-a-name-nobody-checks) ·
[#56](https://github.com/EmilienM/wheel-crypto-scan/issues/56)

---

## A compressed section is checked before it is inflated

**Accepted. Refuse to inflate past what can be used.**

`Section.data()` decompresses a `SHF_COMPRESSED` section's declared `ch_size` bytes before the
reader's own budget ever applies. `ch_size` is a 64-bit field the object declares about itself,
except here the number buys an actual `zlib` call rather than a Python loop, so the cost is a
memory spike. The reproduction: a 255 KiB ELF declaring a 256 MiB `.rodata`, peaking at
**512 MiB** in 0.82 s. The archive-level compression-ratio guard never sees this shape, because
the zlib stream sits inside the zip member, whose own ratio looks ordinary.

**Checked with a call already made, not a new one.** `pyelftools` reads the compression header
eagerly and cheaply and exposes `section.compressed` and `section.data_size`, so the guard
reads two properties and refuses without calling `.data()` at all. Both ELF classes are
covered by construction.

**`.go.buildinfo` carried a second, uncompressed exposure the same audit found, and the first
pass at this fix missed it.** `Section.data()` checks `SHT_NOBITS` *before* it checks
compression, and for such a section returns that many zero bytes with no file bytes read to
justify the length. `.go.buildinfo` is found by name with no type check, so a section named
`.go.buildinfo` and flagged `SHT_NOBITS` reached the call exactly the way an honest one does:
a 298-byte object declaring 2048 MiB peaks at 2 GiB, `partial_analysis: false`, no error —
three orders of magnitude cheaper to build than the compressed reproduction, and silent rather
than merely expensive. The guard now refuses on `compressed or SHT_NOBITS`, not on
`compressed` alone.

**The boundary is "more than", not "at least".** A section declaring exactly the remaining
budget is refused nothing.

**`strings_truncated` can under-report a budget refusal, and this is left as-is rather than
papered over.** A refused section was never read at all, so nothing knows how many of its bytes
would have been genuine strings. Setting the flag anyway does not hold up: an existing fixture
has `.rodata` filled with the OpenSSL banner text and `SHF_COMPRESSED` set over bytes that were
never compressed, whose first 24 bytes decode as a header with `ch_size` around 3.76×10^18
purely by accident of what those ASCII bytes are. There was never a real 3.76-exabyte payload
to have dropped part of.

**What was rejected.** Decompressing with a caller-supplied `max_length`, keeping whatever
prefix fits. It is bounded correctly — verified directly — and that is not what ruled it out: it
needs a second zlib call outside `pyelftools`, a second reader for one fact, and it would split
two call sites onto different rules for the identical shape of bug. And treating any compressed
eligible section as unread regardless of size, which throws away an honest, small,
well-under-budget banner for no reason.

### Widened: an ordinary section is checked too

The fix above only refused when the section was compressed or `SHT_NOBITS`. An ordinary,
uncompressed, file-backed section fell through that `and` entirely and reached `.data()`
unconditionally, at whatever size `sh_size` names, with only the *accumulated* buffer cut
afterwards. The fix drops the `and`: the declared size is checked against the budget for every
section regardless of shape.

An honest 8 MiB `.rodata` against a 64 KiB budget: unfixed, one 8388608-byte read. A
`.dynsym`/`.dynstr` from 200,000 real symbol names against the same budget: unfixed,
`partial_analysis: false` — a fully clean, complete record, paid for at the size of the honest
table rather than the budget, with no way for a consumer to tell.

**Two further gaps, both found by an independent review of this widening.**

The first was blocking: a refused `.dynsym` or `.dynstr` reached the existing cross-check with
no guard, and could **fabricate `symtab_understates_rows`** — a specific, checkable claim
("every structural check passes and the count is simply not the truth") — against a table that
was never shown to lie, only left unread. With `.dynsym` refused, no rows are yielded, so the
sibling branch finds a real crypto name in an honest `.dynstr` unclaimed by any row and reports
it as an understated count. Reproduced: 101 entries against a 600-byte budget read
`('elf_dynsym_unread', 'symtab_understates_rows')` with the error ".dynsym declares fewer
entries than .dynstr holds names for", both false. The refusal is now checked first and the
whole per-symbol walk skipped.

The second, real-world reachable rather than synthetic: **an over-budget ordinary section
discarded its entire content, not just the excess**, unlike every other reader in the codebase.
Reproduced against a real host library, `/usr/lib64/libLLVM.so.22.1` (68.3 MB of eligible
sections against the 64 MiB default): `main` reads it `strings_bytes_unread`, no errors; the
first version read it `elf_section_data_unread` plus a spurious `elf_parse_error`, which fires
"truncated, corrupt or an unrecognised format" over `BIN_STATIC_OPENSSL` — a false-positive
downgrade on a perfectly ordinary, healthy object, at a size range that ML and scientific
wheels commonly reach. A `keep_prefix` flag now hands back the section's own real first
`max_bytes` for `.rodata`/`.comment`/`.go.buildinfo`, one plain read, no decompression.

`.dynsym`/`.dynstr` keep the all-or-nothing refusal on purpose: **a byte-bounded prefix of a
symbol table is not a set of complete rows**, and an entry near the cut is as likely to point
past a truncated string table as into it. The honest way to bound a symbol table without losing
rows to that ambiguity already exists in the Mach-O reader; porting it here is a real fix, and a
different, larger one.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-compressed-section-is-checked-before-it-is-inflated) ·
[#62](https://github.com/EmilienM/wheel-crypto-scan/issues/62) ·
[#95](https://github.com/EmilienM/wheel-crypto-scan/issues/95)

---

## `.symtab` is matched for crypto symbols when `.dynsym` is genuinely absent

**Accepted. `ANALYZER_VERSION` and `ruleset_version` both move.**

Crypto symbol matching read `.dynsym` only — correct for a dynamically linked object,
where `.dynsym` is what the dynamic linker actually uses, but a relocatable object
(`ET_REL`, a `.o`/`.obj` before linking, the shape every static archive member has) or
a statically linked executable normally has no `.dynsym` at all, only `.symtab`. A
genuine `EVP_DigestInit_ex` definition there, with no accompanying string banner, was
invisible to the tool's primary detection mechanism.

Scoped to only when `.dynsym` is genuinely absent, never alongside it: a *dynamically*
linked shared object or executable always carries a live `.dynsym` (`strip` cannot
remove it without breaking dynamic linking), so this reader's output for that part of
the corpus is unaffected by construction. A statically linked executable is not
unaffected — it gets matched too, which is the fix's intended reach, not an
incidental side effect. "Genuinely absent" excludes an ambiguous or type-forged
`.dynsym`, and a `.dynsym` whose own section header failed to parse and so never
reached the section list at all — all three make the lookup return `None` without the
object genuinely having none.

**Severe findings from two independent adversarial reviews plus a verification pass
over the fixes themselves, all fixed before merge.** A `.symtab` repointed at a decoy,
appended, all-NUL `SHT_STRTAB` resolved every name to `""` — not unresolved,
*resolved* — so a crafted object could hide a genuine crypto definition and read
completely clean, the identical decoy `_validated_strtab` exists to close for
`.dynsym`, reachable here because `.symtab` has no independent authority to
corroborate `sh_link` against. Closed by not trusting the one table `sh_link` names:
the cross-check now asks every `SHT_STRTAB` section in the object, so the real
`.strtab` still gets to contradict the decoy regardless of which one `.symtab`
claims. That fix had its own gap, found by dispatching a fork to verify it rather than
trusting it on inspection: it skipped a `SHT_STRTAB` section it could not fully read
within budget, which reopened the identical decoy under a second construction — a
small decoy plus a genuine `.strtab` inflated past the budget elsewhere. An unread
`SHT_STRTAB` now counts as a hit, not a skip. Separately, `.symtab` carries
`STT_FILE`/`STT_SECTION` pseudo-symbols `.dynsym` never does — a source file named
`EVP_md5.c` matched a group by filename coincidence alone; now filtered by type, while
still counted as read for the understated-rows check, so filtering evidence does not
itself manufacture a false "the object understates its own rows" claim.

`binfmt.ar` needed no change of its own for an ELF member: it calls `read_binary` per
member regardless of format, so the fix applies to every ELF archive member
automatically. A Windows `.lib`'s COFF members are untouched; `binfmt.pe` deliberately
does not read the COFF symbol table at all.

**A real, pre-existing bug this surfaced, unrelated to `.symtab` matching itself:**
`elf_symtab_unread` was wrongly exempt from costing the linkage answer. See "Sections
are found by type, not by a name nobody checks", the paragraph beginning
"`elf_symtab_unread` was on this list too, and is not any more".

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#symtab-is-matched-for-crypto-symbols-when-dynsym-is-genuinely-absent) ·
[#117](https://github.com/EmilienM/wheel-crypto-scan/issues/117)
