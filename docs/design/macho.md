# Mach-O

Five entries about `binfmt/macho.py`, the largest reader in the tree. Four of them are about
the load-command walk, and each one covers a shape the one before it leaves open. One more
decision about this module — its module-local line-count exemption — is about tooling policy
rather than the reader, and lives under
[Scanning, caching and layout](tooling.md#binfmtelfpy-and-binfmtmachopy-carry-module-local-line-count-exemptions).

## A universal binary is one record, and its slices are merged

**Accepted, knowing what it costs.**

A fat Mach-O is read slice by slice and reduced to a single `BinaryEvidence`. `needed`,
`rpath` and `matched_symbols` become sorted unions, the symbol count a sum, `stripped` true
only when every slice is. `machine`, `bits` and `endian` describe the first slice that parsed,
because they describe one architecture and cannot describe several.

**Why one record.** The thing being described is the member of the wheel. `path` is what the
vendored-path matching keys on, so a record per slice would carry the same `path` two or four
times and every consumer counting binaries would double-count. No field of the schema is
per-architecture.

**What it buys.** Reading only the first parseable slice would leave every fat object
`partial_analysis: true` for ever. Most macOS wheels are universal2, so a crypto-free
universal2 wheel would come out `OPAQUE` rather than `NO_CRYPTO_DETECTED`, and the `OPAQUE`
triage recipe would list all of them.

**What it costs.** A union hides which architecture said what. A universal2 dylib whose x86_64
slice links the host OpenSSL and whose arm64 slice has it compiled in merges to a `needed`
entry plus both an `imported` and a `defined` `EVP_DigestInit_ex`. The posture function counts
`system`, `bundled` and `static` on the one object and returns `mixed` when two or more are
true (see [OpenSSL linkage](linkage.md)), so any disagreement between two definite postures
across slices reads `mixed`, the same as reading the slices apart. Which architecture said
which is gone either way, so a `mixed` record from a universal2 dylib cannot say "x86_64 links
system, arm64 is static".

The trade of merging at all is right: the losing case needs two independently built thin dylibs
`lipo`-ed together, which `delocate` does not produce, while the winning case is most of the
macOS wheels in an index. It is recorded because nothing in the output says a record was
merged, so a reader of `matched_symbols` carrying one name as both `imported` and `defined`
should know why that is representable at all.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-universal-binary-is-one-record-and-its-slices-are-merged)

---

## Every dylib-loading command reaches `needed`, not just `LC_LOAD_DYLIB`

**Accepted, the direct counterpart of a PE forwarder, and it changes what a re-exporting shim
can hide.**

Four commands share `LC_LOAD_DYLIB`'s struct layout and differ only in what the dynamic linker
does with the name: `LC_LOAD_WEAK_DYLIB` tolerates the library being absent,
`LC_LAZY_LOAD_DYLIB` and `LC_LOAD_UPWARD_DYLIB` are ordinary dependencies with different load
timing, and `LC_REEXPORT_DYLIB` folds the target's exports into this object's own API surface.
Reading only `LC_LOAD_DYLIB`/`LC_ID_DYLIB` would silently skip all four.

The re-exporting shape is the sharper failure — a shim whose whole job is re-exporting
libcrypto would read completely clean if only those two commands were read:

```text
libshim.dylib   id: @rpath/libshim.dylib
                needed: /usr/lib/libSystem.B.dylib
                LC_REEXPORT_DYLIB -> /opt/homebrew/lib/libcrypto.3.dylib
-> if only LC_LOAD_DYLIB/LC_ID_DYLIB are read: needed: ['/usr/lib/libSystem.B.dylib'],
           class: NO_CRYPTO_DETECTED, openssl_linkage: none, needs_human_review: false
-> reading all five commands: needed carries the re-exported dylib too,
           openssl_linkage: system, class: CONDITIONAL, needs_human_review: true
```

**No marker beyond `needed`.** No rule anywhere reads "which load command produced this
`needed` entry", so a distinguishing marker would have no consumer. Collapsing five commands
into one field is also the conservative direction for the one that asserts slightly more than
the object guarantees: a weak dependency can flag a wheel over a library that may never
actually load. That is a choice, not an oversight — a false positive here costs
`needs_human_review`, not a wrong verdict class, and the alternative reopens the silent-drop
shape this entry exists to close.

**Every command sharing a layout has its string read through one function**, which refuses two
shapes an offset can take: below the command's own fixed header, and past the command's own
body. Trusting an in-header offset is a real decoy risk — the dylib struct has three
attacker-controlled 32-bit fields with no structural meaning to this reader, so an offset
landing on them can read whatever bytes are there as a plausible dependency string the object
never named.

**A non-ASCII byte is sanitized, not dropped.** Decoding strictly and returning `None` on any
byte outside ASCII is indistinguishable from an offset that pointed nowhere. The other two
readers decode permissively and then sanitize, and so does this one: a `libcrypto\x80-3.dylib`
reads as `libcrypto-3.dylib` rather than vanishing along with whatever crypto evidence its name
carried.

**Three more shapes this reader must also close,** none of them in the four sibling commands
named above: an unterminated-run fallback that would read a name whose terminating NUL was
clobbered as a longer, wrong string with `partial_analysis: false`; the in-header offset floor
above; and `LC_RPATH` carrying the same silent-drop shape as the dylib family, which is not
cosmetic because `_looks_vendored` reads `rpath` directly.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#every-dylib-loading-command-reaches-needed-not-just-lc_load_dylib)

---

## An unparseable load-command header flags the walk, it does not end it in silence

**Accepted, one level up from the load-command strings the entry above reads.**

An individual command's unreadable *name* is a partial reason while the walk keeps going. The
loop has two earlier checks, over the command's own `cmd`/`cmdsize` header rather than its
name:

```python
if pos + 8 > len(commands):
    break
cmd, cmdsize = struct.unpack_from(end + "II", commands, pos)
if cmdsize < 8 or pos + cmdsize > len(commands):
    break
```

Neither `break` records anything on its own. Without a partial reason attached to them, every
command after the point either one fires — an honest, later `LC_LOAD_DYLIB` naming the system
OpenSSL included — would be silently dropped, not merely one command's string.

**Why a token of its own.** The string token says one command's name could not be trusted while
the command itself could, so the walk kept going. Here the command's own shape is what lied, so
nothing past it can be resynced on: not one name but every later command, and everything it
might have named, is unaccounted for.

**What was rejected: resyncing past the bad command.** Once `cmdsize` has lied once,
`pos + cmdsize` is a guess, not a fact, so advancing past it risks reading a decoy command's
body as if it were real. Stopping the walk at the lie, with a signal, is what the invariant
requires: evidence gathered *before* the bad command is unaffected; only what would have come
after is lost, and it is lost as `partial_analysis: true`.

### A misaligned `cmdsize` or an understated `ncmds` flags the walk too

Both shapes desync the same walk without tripping either check above, because both stay inside
what those checks look at. A `cmdsize` that is at least 8 and does not run past the end passes
outright even when it is not a multiple of the ABI's own alignment — the walk advances by the
lied-about amount and reads every later command from the wrong offset. And `ncmds` says nothing
about how many bytes the walk actually consumed: a header that undercounts it makes the loop
exhaust its iterations with real command bytes still unread, without any single command's
header ever lying about itself.

```text
(i) cmdsize=12 on a 64-bit object (not a multiple of 8, but >= 8 and inside the commands)
    -> without the alignment check: needed drops the later LC_LOAD_DYLIB naming
       libcrypto, partial_analysis: false
    -> with it: partial_analysis: true, macho_load_command_walk_truncated, error recorded

(ii) ncmds says 3; the object carries a fourth, honest LC_LOAD_DYLIB naming libcrypto
    -> without the post-loop check: needed drops the fourth command entirely,
       partial_analysis: false
    -> with it: partial_analysis: true, macho_load_command_walk_truncated, error recorded
```

**Same token, not two new ones.** The token's claim is not "a command's header failed one of
two specific checks" — it is "the walk did not honestly account for all its bytes". Both shapes
are that same claim by a different route. Applying the admission test finds nothing: neither is
a linker convention, and both are lies about the walk's own extent.

The post-loop check lives in the `for` loop's own `else` clause, which Python only runs when the
loop finished without a `break` — exactly the "no command lied, but did the walk still cover the
object" question. Despite the name, it is not solely an `ncmds` check: it catches any shape
where the loop finishes clean but the position and the length disagree, including an aligned,
individually-honest `cmdsize` that overstates its own command's size and swallows a later one.

**The fixtures are ABI-honest.** The Mach-O builder pads every command to the ABI's own
boundary: 8 bytes on a 64-bit object, 4 on a 32-bit one. A builder padding to 4 bytes
regardless of bitness is honest for a 32-bit object and not for a 64-bit one, and lands most
64-bit fixtures on a `cmdsize` that is a multiple of 4 but not 8 purely by the length of the
strings chosen — measured with 4-byte padding, 34 of 111 Mach-O tests, and 42 across the whole
suite, fail the alignment check. The padding is fixed at the source rather than by loosening the
check.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#an-unparseable-load-command-header-flags-the-walk-it-does-not-end-it-in-silence)

---

## sizeofcmds and the symbol table are capped, not just clamped to the member

**Accepted. The same kind of bound as the ELF compressed-section check and the per-name symbol
cap, at the two places a declared 32-bit size would otherwise be measured only against the
member rather than against a fixed budget.**

Reading load commands straight from the header's own `sizeofcmds` field with only a short-read
check afterwards costs a 300 MiB member declaring `sizeofcmds = 0xFFFFFFFF` a 300 MiB single
read for a structure that is honestly low tens of KiB. The symbol table has the same shape one
level down: clamping a declared size to the *slice* is exactly right for a slice smaller than
any fixed budget and does nothing at all for one larger. With the slice clamp alone,
`nsyms = 0x0FFFFFFF` over a 300 MiB member costs **24.5 s and 664 MiB peak** walking roughly
twenty million rows, each individually classified as unresolved — for a record that is correct
either way.

**Two caps.** A 1 MiB ceiling on load commands, checked before the read runs at all: real load
commands are low tens of KiB even for the busiest fixture in the suite, so two orders of
magnitude above that is generous headroom. The symbol-table half reuses the strings budget
threaded through the reader rather than inventing a second constant that could only ever drift
from it.

**ELF enforces the same parameter differently.** An oversized `.dynsym`/`.dynstr` is refused
outright by the ELF section check rather than truncated byte-for-byte the way this reader's cap
is (see the [ELF](elf.md) page) — a different mechanism reaching the same guarantee.

**The walk is bounded per slice, not just the allocation — and that qualifier is load-bearing.**
Because the cap is applied *before* the availability calculation, the table is never longer than
the budget, so the loop that classifies twenty million rows never sees more than the budget's
worth of them for that slice. That bound does not extend to the object as a whole: nothing pools
a budget across slices, so a crafted 32-slice universal binary still costs on the order of
slices × budget. Measured directly at roughly 49 s with the cap applied per slice against 54 s
without it, because the slice count, not this cap, is what bounds it. Memory does not have the
same gap: nothing keeps more than one slice's buffers alive at once.

**A capped read is a truncated read, not a refused one, and that is a deliberate difference.**
The ELF check refuses an oversized compressed section outright because inflating is
all-or-nothing with no cheap prefix. Mach-O's tables are read through plain byte-offset
slicing, so capping costs nothing extra and keeps whatever prefix the budget affords — the
honest symbol in the test sits at the start of the table and stays in `matched_symbols`, where
a refuse-outright version would throw it away along with the twenty million garbage rows. That
is "a structure that does not parse costs that structure, never the evidence already gathered",
one level down: a table that reads over budget costs its own tail, not its own head.

**Two things this cap needs a test of its own for.** The string-table half of the cap needs a
test that varies `strsize` independently: changing it alone leaves the suite green if the
boundary test only ever varies the symbol count. And the exception-routing clause that
preserves the specific error *message* needs its own test too: deleting it leaves the suite
green if nothing asserts on the text, since the reason token and the error kind are the same
either way.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#sizeofcmds-and-the-symbol-table-are-capped-not-just-clamped-to-the-member)

---

## More than one LC_ID_DYLIB or LC_SYMTAB is ambiguous, not last-wins

**Accepted. The Mach-O counterpart of the ELF ambiguity token, and it changes records.**

Setting `soname` on every `LC_ID_DYLIB` the walk reaches and building a fresh symbol table on
every `LC_SYMTAB`, both unconditionally, lets a second command of either kind silently overwrite
the first, with nothing counting how many were seen. The posture function reads `soname` first,
to decide whether the object itself *is* a named library, so a decoy `LC_ID_DYLIB` is
load-bearing for the verdict, not cosmetic — and a decoy `LC_SYMTAB` is load-bearing for the
imported/defined split the whole tool turns on. Read last-wins:

```text
honest LC_ID_DYLIB, single             -> openssl_linkage: bundled, needs_human_review: true
honest LC_ID_DYLIB + decoy appended    -> openssl_linkage: none,    needs_human_review: false
```

The decoy is not merely ignored: the record actively misreports the object's own identity, with
`partial_analysis: false` and no errors.

**The same treatment as ELF: detect ambiguity, trust neither candidate, cost the answer.** More
than one of either resets the corresponding field after the walk finishes, rather than leaving
whichever one was assigned last. `soname` and the symbol table then read as though this slice
never declared one. That "read as absent, not as the decoy" rule is ELF's, applied to load
commands instead of section headers.

**One token, not two**, for the same reason the ELF token covers three section kinds: the
failure is the same shape regardless of which field it lands on. Folding the symbol-table half
into the incompleteness token is rejected — that token is about a table this reader reached and
could not take at its word, whereas ambiguity means the table's contents are never even in
question, because there is no way to tell which of two candidates is real before either is read.

**What was rejected.** Trusting whichever command sorts *first* rather than last: that is still
picking one of two untrusted candidates, the identical hazard type-based section lookup rejects
for ELF's own section tables.

**A genuine residual, adjacent to this check.** This check is about ambiguity *within* one
slice's walk. It says nothing about two slices that each carry exactly one, internally
unambiguous `LC_ID_DYLIB` but disagree with each other: the merge takes "the first one any slice
declared", so a universal2 object whose slices honestly declare different install names reads the
first with `partial_analysis: false` and nothing to say they disagreed. Reproduced directly. It
is the same merge rule the first entry on this page documents, reached here by a concrete
counterexample.

### The error message names which command was ambiguous; the token does not

**Diagnostic text only — it does not reopen "One token, not two" above.** `errors[]`'s message
does not merge both possible causes into one sentence, matching ELF's per-kind messages for
`elf_section_type_ambiguous`. `_read_thin` counts each cause separately, and the two counts
survive through `_ThinHeader` as two flags rather than merging into one boolean before the
error-emitting loop reaches them. `read_macho` emits up to two distinct messages, and
`partial_reasons` adds `macho_load_command_ambiguous` exactly once, computed as the OR of both —
one token, backed by up to two messages, consistent with what "One token, not two" argues for.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#the-error-message-names-which-command-was-ambiguous-the-token-does-not)

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#more-than-one-lc_id_dylib-or-lc_symtab-is-ambiguous-not-last-wins)
