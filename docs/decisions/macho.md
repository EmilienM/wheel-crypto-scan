# Mach-O

Five entries about `binfmt/macho.py`, the largest reader in the tree. Four of them are about
the load-command walk, and they arrived in sequence: each fix named the next gap in its own
"what it costs" paragraph, and the next issue closed it.

## A universal binary is one record, and its slices are merged

**Accepted, knowing what it costs.**

A fat Mach-O is read slice by slice and reduced to a single `BinaryEvidence`. `needed`,
`rpath` and `matched_symbols` become sorted unions, the symbol count a sum, `stripped` true
only when every slice is. `machine`, `bits` and `endian` describe the first slice that parsed,
because they describe one architecture and cannot describe several.

**Why one record.** The thing being described is the member of the wheel. `path` is what the
vendored-path matching keys on, so a record per slice would carry the same `path` two or four
times and every consumer counting binaries would double-count. No field of the schema is
per-architecture today.

**What it buys.** Before, only the first parseable slice was read, so every fat object was
`partial_analysis: true` for ever. Most macOS wheels are universal2, so a crypto-free
universal2 wheel came out `OPAQUE` rather than `NO_CRYPTO_DETECTED`, and the `OPAQUE` triage
recipe listed all of them.

**What it costs.** A union hides an intra-object disagreement — but not the way this was first
written up, and not for every disagreement shape. A universal2 dylib whose x86_64 slice links
the host OpenSSL and whose arm64 slice has it compiled in merges to a `needed` entry plus both
an `imported` and a `defined` `EVP_DigestInit_ex`. The posture function tested `needed` first
and returned as soon as it found a system match, so the object resolved to `system` — exactly
what reading the slices separately would have called `mixed`. That is now fixed for this shape
(see [OpenSSL linkage](linkage.md)), but the fix is narrower than "every disagreement reads the
same merged or separate": a slice disagreement between `bundled` and `system` still merged to
`bundled` until a later change. Which architecture said which is gone either way, so a `mixed`
record from a universal2 dylib still cannot say "x86_64 links system, arm64 is static".

The trade of merging at all is still right, independent of that: the losing case needs two
independently built thin dylibs `lipo`-ed together, which `delocate` does not produce, while
the winning case is most of the macOS wheels in an index. It is recorded because nothing in the
output says a record was merged, so a reader of `matched_symbols` carrying one name as both
`imported` and `defined` should know why that is representable at all.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-universal-binary-is-one-record-and-its-slices-are-merged) ·
[#10](https://github.com/EmilienM/wheel-crypto-scan/issues/10)

---

## Every dylib-loading command reaches `needed`, not just `LC_LOAD_DYLIB`

**Accepted, the direct counterpart of the PE forwarder fix, and it changes what a
re-exporting shim can hide.**

The walk recognised exactly `LC_LOAD_DYLIB` and `LC_ID_DYLIB`. Four sibling commands share the
identical struct layout and differ only in what the dynamic linker does with the name:
`LC_LOAD_WEAK_DYLIB` tolerates the library being absent, `LC_LAZY_LOAD_DYLIB` and
`LC_LOAD_UPWARD_DYLIB` are ordinary dependencies with different load timing, and
`LC_REEXPORT_DYLIB` folds the target's exports into this object's own API surface. All four
were silently skipped.

The re-exporting shape is the sharper failure — a shim whose whole job is re-exporting
libcrypto read completely clean:

```text
libshim.dylib   id: @rpath/libshim.dylib
                needed: /usr/lib/libSystem.B.dylib
                LC_REEXPORT_DYLIB -> /opt/homebrew/lib/libcrypto.3.dylib
-> before: needed: ['/usr/lib/libSystem.B.dylib'], class: NO_CRYPTO_DETECTED,
           openssl_linkage: none, needs_human_review: false
-> after:  needed carries the re-exported dylib too, openssl_linkage: system,
           class: CONDITIONAL, needs_human_review: true
```

**No marker beyond `needed`.** No rule anywhere reads "which load command produced this
`needed` entry", so a distinguishing marker would have no consumer. Collapsing five commands
into one field is also the conservative direction for the one that asserts slightly more than
the object guarantees: a weak dependency can flag a wheel over a library that may never
actually load. That is a choice, not an oversight — a false positive here costs
`needs_human_review`, not a wrong verdict class, and the alternative reopens the silent-drop
shape this issue exists to close.

**Every command sharing a layout now has its string read through one function**, which refuses
two shapes an offset can take: below the command's own fixed header, and past the command's own
body. Trusting an in-header offset is a real decoy risk — the dylib struct has three
attacker-controlled 32-bit fields with no structural meaning to this reader, so an offset
landing on them can read whatever bytes are there as a plausible dependency string the object
never named.

**A non-ASCII byte is sanitized, not dropped.** The string reader decoded strictly and returned
`None` on any byte outside ASCII, indistinguishable from an offset that pointed nowhere. The
other two readers decode permissively and then sanitize, so this one now does too: a
`libcrypto\x80-3.dylib` reads as `libcrypto-3.dylib` rather than vanishing along with whatever
crypto evidence its name carried.

**Found by adversarial review, before this shipped.** Three gaps, none of them in the four
sibling commands the issue actually named: an unterminated-run fallback that read a name whose
terminating NUL was clobbered as a longer, wrong string with `partial_analysis: false`; the
in-header offset floor above; and `LC_RPATH` keeping the exact silent-drop shape this issue
closes for the dylib family, which is not cosmetic because `_looks_vendored` reads `rpath`
directly.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#every-dylib-loading-command-reaches-needed-not-just-lc_load_dylib) ·
[#59](https://github.com/EmilienM/wheel-crypto-scan/issues/59)

---

## An unparseable load-command header flags the walk, it does not end it in silence

**Accepted, found while reviewing the fix above, and one level up from what it closed.**

That fix made an individual command's *name* unreadable a partial reason while the walk kept
going. The loop has two earlier checks, over the command's own `cmd`/`cmdsize` header rather
than its name, that stayed silent:

```python
if pos + 8 > len(commands):
    break
cmd, cmdsize = struct.unpack_from(end + "II", commands, pos)
if cmdsize < 8 or pos + cmdsize > len(commands):
    break
```

Neither `break` recorded anything. Every command after the point either one fired — an honest,
later `LC_LOAD_DYLIB` naming the system OpenSSL included — was silently dropped, not merely one
command's string.

**Why a new token.** The existing one says one command's name could not be trusted while the
command itself could, so the walk kept going. Here the command's own shape is what lied, so
nothing past it can be resynced on: not one name but every later command, and everything it
might have named, is unaccounted for.

**What was rejected: resyncing past the bad command.** Once `cmdsize` has lied once,
`pos + cmdsize` is a guess, not a fact, so advancing past it risks reading a decoy command's
body as if it were real. Stopping where the previous fix already stopped, but now with a
signal, is what the invariant requires: evidence gathered *before* the bad command is
unaffected; only what would have come after is lost, and it is lost as `partial_analysis: true`.

### Extended: a misaligned cmdsize and an understated ncmds close the two named gaps

**Fixed. The follow-up the paragraph above named on purpose as "unclosed by this fix".**

Both shapes desync the same walk without tripping either check, because both stay inside what
those checks look at. A `cmdsize` that is at least 8 and does not run past the end passes
outright even when it is not a multiple of the ABI's own alignment — the walk advances by the
lied-about amount and reads every later command from the wrong offset. And `ncmds` is never
checked against how many bytes the walk actually consumed: a header that undercounts it makes
the loop exhaust its iterations with real command bytes still unread, without any single
command's header ever lying about itself.

```text
(i) cmdsize=12 on a 64-bit object (not a multiple of 8, but >= 8 and inside the commands)
    -> before: needed drops the later LC_LOAD_DYLIB naming libcrypto, partial_analysis: false
    -> after:  partial_analysis: true, macho_load_command_walk_truncated, error recorded

(ii) ncmds says 3; the object carries a fourth, honest LC_LOAD_DYLIB naming libcrypto
    -> before: needed drops the fourth command entirely, partial_analysis: false
    -> after:  partial_analysis: true, macho_load_command_walk_truncated, error recorded
```

**Same token, not two new ones.** The token's claim was never "a command's header failed one of
two specific checks" — it is "the walk did not honestly account for all its bytes". Both new
shapes are that same claim by a different route. Applying the admission test finds nothing:
neither is a linker convention, and both are lies about the walk's own extent.

The post-loop check lives in the `for` loop's own `else` clause, which Python only runs when the
loop finished without a `break` — exactly the "no command lied, but did the walk still cover the
object" question. Despite the name, it is not solely an `ncmds` check: it catches any shape
where the loop finishes clean but the position and the length disagree, including an aligned,
individually-honest `cmdsize` that overstates its own command's size and swallows a later one.

**A test-fixture gap this uncovered, fixed alongside it.** The Mach-O builder padded every
command's name to a 4-byte boundary regardless of bitness, which is honest for a 32-bit object
and not for a 64-bit one. Most 64-bit fixtures landed on a `cmdsize` that was a multiple of 4
but not 8 purely by the length of the strings chosen — 34 of 111 Mach-O tests, and 42 across the
whole suite, failed the moment the new check was added. Fixed at the source rather than by
loosening the check, so every "well-formed" fixture in the file is ABI-honest as a result, not
just the ones this issue added.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#an-unparseable-load-command-header-flags-the-walk-it-does-not-end-it-in-silence) ·
[#84](https://github.com/EmilienM/wheel-crypto-scan/issues/84) ·
[#90](https://github.com/EmilienM/wheel-crypto-scan/issues/90)

---

## sizeofcmds and the symbol table are capped, not just clamped to the member

**Accepted. The same class of fix as the two budget entries before it, ported to the two places
still measuring a declared 32-bit size against the member rather than against a fixed budget.**

The walk read its load commands straight from the header's own `sizeofcmds` field with only a
short-read check afterwards. A 300 MiB member declaring `sizeofcmds = 0xFFFFFFFF` cost a
300 MiB single read for a structure that is honestly low tens of KiB. The symbol table had the
same shape one level down: clamping a declared size to the *slice* is exactly right for a slice
smaller than any fixed budget and does nothing at all for one larger. `nsyms = 0x0FFFFFFF` over
a 300 MiB member cost **24.5 s and 664 MiB peak** walking roughly twenty million rows, each
individually classified as unresolved — for a record that was correct either way.

**Two caps.** A 1 MiB ceiling on load commands, checked before the read runs at all: real load
commands are low tens of KiB even for the busiest fixture in the suite, so two orders of
magnitude above that is generous headroom. The symbol-table half reuses the strings budget
already threaded through rather than inventing a second constant that could only ever drift
from it.

**This is stricter than the ELF reader, not a port of it**, and that difference was found by
review rather than assumed away. An early draft described the two as mirroring one another,
because the same parameter is threaded through both. Threading a parameter is a real parallel;
enforcing it is not the same fact — at the time, ELF's refusal only fired for compressed and
`SHT_NOBITS` sections, so a large *honest* symbol table was read in full regardless. That gap
was filed rather than folded in, and is the widening described on the [ELF](elf.md) page.

**The walk is bounded per slice, not just the allocation — and that qualifier is load-bearing.**
Because the cap is applied *before* the availability calculation, the table is never longer than
the budget, so the loop that classified twenty million rows never sees more than the budget's
worth of them for that slice. That bound does not extend to the object as a whole: nothing pools
a budget across slices, so a crafted 32-slice universal binary still costs on the order of
slices × budget. Review measured it directly — roughly 49 s post-fix against 54 s pre-fix,
because the slice count, not this cap, is what was bounding it. Memory does not have the same
gap: nothing keeps more than one slice's buffers alive at once.

**A capped read is a truncated read, not a refused one, and that is a deliberate difference.**
The ELF guard refuses an oversized section outright because inflating is all-or-nothing with no
cheap prefix. Mach-O's tables are read through plain byte-offset slicing, so capping costs
nothing extra and keeps whatever prefix the budget affords — the honest symbol in the test sits
at the start of the table and stays in `matched_symbols`, where a refuse-outright version would
have thrown it away along with the twenty million garbage rows. That is "a structure that does
not parse costs that structure, never the evidence already gathered", one level down: a table
that reads over budget costs its own tail, not its own head.

**Two things shipped untested in the first version, and review caught both.** The string-table
half of the cap had no test of its own — reverting it alone left the suite green, because the
boundary test only ever varied the symbol count. And the exception-routing clause that preserves
the specific error *message* was similarly untested: deleting it left the suite green too,
because the reason token and the error kind are unchanged either way, and nothing asserted on
the text.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#sizeofcmds-and-the-symbol-table-are-capped-not-just-clamped-to-the-member) ·
[#63](https://github.com/EmilienM/wheel-crypto-scan/issues/63)

---

## More than one LC_ID_DYLIB or LC_SYMTAB is ambiguous, not last-wins

**Accepted. The Mach-O counterpart of the ELF ambiguity token, and it changes records.**

The walk set `soname` on every `LC_ID_DYLIB` it reached and built a fresh symbol table on every
`LC_SYMTAB`, both unconditionally: a second command of either kind silently overwrote the
first, and the walk never counted how many it had seen. The posture function reads `soname`
first, to decide whether the object itself *is* a named library, so a decoy `LC_ID_DYLIB` is
load-bearing for the verdict, not cosmetic — and a decoy `LC_SYMTAB` is load-bearing for the
imported/defined split the whole tool turns on.

```text
honest LC_ID_DYLIB, single             -> openssl_linkage: bundled, needs_human_review: true
honest LC_ID_DYLIB + decoy appended    -> openssl_linkage: none,    needs_human_review: false
```

The decoy is not merely ignored: the record actively misreports the object's own identity, with
`partial_analysis: false` and no errors.

**The fix mirrors the ELF treatment exactly: detect ambiguity, trust neither candidate, cost the
answer.** More than one of either resets the corresponding field after the walk finishes, rather
than leaving whichever one was assigned last. `soname` and the symbol table then read as though
this slice never declared one. That "read as absent, not as the decoy" rule is the ELF entry's
own, applied to load commands instead of section headers.

**One token, not two**, for the same reason the ELF token covers three section kinds: the
failure is the same shape regardless of which field it lands on. Folding the symbol-table half
into the existing incompleteness token was rejected — that token is about a table this reader
reached and could not take at its word, whereas ambiguity means the table's contents are never
even in question, because there is no way to tell which of two candidates is real before either
is read.

**What was rejected.** Trusting whichever command sorts *first* rather than last: that is still
picking one of two untrusted candidates, the identical hazard the ELF fix's own first pass made
before review found a decoy could sit ahead of the real one.

**A genuine residual, found while probing the universal-binary merge.** This is about ambiguity
*within* one slice's walk. It says nothing about two slices that each carry exactly one,
internally unambiguous `LC_ID_DYLIB` but disagree with each other: the merge takes "the first
one any slice declared", so a universal2 object whose slices honestly declare different install
names reads the first with `partial_analysis: false` and nothing to say they disagreed.
Reproduced directly. Not new — it is the same merge rule the first entry on this page already
documents — but one adversarial probe closer to a concrete counterexample.

### A module-local line-count exemption instead of a third global bump

**Corrected after review.** This fix's own docstring growth pushed the module over pylint's
line limit, and the first pass fixed it the way an earlier one had: raising the project-wide
limit again. That would have been the third such raise, and each one silently gives every
*other* module the same extra headroom whether or not it has earned it the way this one has — a
documentation-heavy docstring that the "every policy entry carries a why" rule asks for, not
unchecked growth.

Replaced with a module-local disable in the file itself, with the justification comment moved
there, and the project-wide limit reverted to pylint's own default. The other two readers were
nowhere near either limit, so nothing was depending on the raised ceiling; reverting it costs
nothing and stops the next module's growth from riding through unpoliced by accident.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#more-than-one-lc_id_dylib-or-lc_symtab-is-ambiguous-not-last-wins) ·
[#85](https://github.com/EmilienM/wheel-crypto-scan/issues/85)
