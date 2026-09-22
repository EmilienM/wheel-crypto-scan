# Caps, budgets and record size

A record has to be bounded: one wheel with thousands of objects must not produce an
unbounded JSON line. These entries are about that, and they share one theme — **a limit
that exists to bound output must not decide what the tool finds**, which it does if it is
applied in the place that also decides what a rule gets to see, or if the sort key it cuts on
has nothing to do with what a match is worth.

Each one is pinned by building the object that crosses the line, and two of them rest on
showing that a sentence claiming the shape could not happen is false.

## A recording cap is not a partial read

**Accepted. One of the two halves of `truncated` is a cause; the other is a field.**

`strings_truncated` can be set by three different things at once: the byte budget running
out before the object does, and two recording caps. Left as a field alone, with
`partial_analysis` false, the budget half lets an object whose strings pass never reaches the
end of it contribute a definite posture, and the record says both at once:

```text
strings_truncated: true
partial_analysis:  false   partial_reasons: []
openssl_linkage:   none    NO_CRYPTO_DETECTED   needs_human_review: false
```

Measured on one `.pyd` carrying an OpenSSL version banner in its last 26 bytes: scanned whole
it is `static` and `CONDITIONAL`; with the byte budget stopping short of the banner and no
cause recorded, the same object is clean. The banner is not a nice-to-have — `cryptography` 42
and later compiles OpenSSL in, with no library file, no dependency and no exported symbol, so
the banner is the *entire* evidence.

**Only the reading gap has a token, and the reason is definitional.** `partial_analysis` means
part of the object was not read. A *recording* cap — more group matches than the limit keeps —
is not that: the object was read, and what was capped is what got written down. It is not a
member of the class `PARTIAL_REASONS` enumerates, so the vocabulary is not being asked to hold
a policy.

The alternative is rejected on a harder ground than taste. Minting a cap token as a fact and
then exempting it in the ruleset needs a verdict-less `partial_binary` rule, which the
load-time floor then forces into `[linkage_policy] exclude_reasons` — **a second carve-out on
the "unreadable means `OPAQUE`" invariant**, which is a change to the invariant itself. One
carve-out is what that document permits.

**A recording cap has its own way to read clean.** A recording cap looks safe on the reasoning
that it "cannot produce a record that reads clean, because it only fires once that many matches
are in hand". That is false of a plain sort-and-cut, and the counterexample is four lines:

```text
ring alone                 -> NON_APPROVED_CRYPTO  needs_human_review: true
ring + 130 earlier crates  -> NO_CRYPTO_DETECTED   needs_human_review: false
                              strings_truncated: true, partial_analysis: false
```

That is the next entry.

**What it costs, and the threshold is not the same in every format.** For Mach-O, PE and the
fallback the budget is measured against the object, so an object over 64 MiB is `OPAQUE`.
For ELF it is measured against the concatenation of eligible read-only sections, so a gigabyte
`.so` that is mostly `.text` is untouched while a smaller one carrying a large `.nv_fatbin` is
not. That distinction matters rather than being a footnote: CUDA and PyTorch wheels, which is
where the size is, ship overwhelmingly as manylinux ELF. Executable sections are read
separately, against their own budget of the same size, only for the string groups the ruleset
flags `in_code` -- see [ELF](elf.md).

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-recording-cap-is-not-a-partial-read)

---

## A cap bounds the record, it does not pick the evidence

**Accepted, and it changes records.**

Three per-binary limits exist so one object cannot produce an unbounded JSON line. None of
them exists to decide which evidence survives, and a limit that sorts its matches and cuts
decides it anyway. The sort key has nothing to do with what a match is worth, and the crypto
names the ruleset claims sit in the middle of every one of those orderings. With a plain
sort-and-cut:

```text
ring alone                 -> NON_APPROVED_CRYPTO  needs_human_review: true, findings: 1
ring + 130 earlier crates  -> NO_CRYPTO_DETECTED   needs_human_review: false, findings: 0

banner alone                 -> openssl_linkage: static
banner + 70 mbedtls_ runs    -> openssl_linkage: none

defined EVP_DigestInit_ex alone -> openssl_linkage: static
+ 70 defined crypto_box_*       -> openssl_linkage: none
```

The first is the one that matters: `partial_analysis` false, no findings, nothing in the
record saying anything was dropped except a flag whose meaning is "we found more than we
keep". A Rust wheel with three hundred crates is ordinary, and every crypto crate named —
`openssl`, `ring`, `rustls`, `sha1`, `sha2`, `pbkdf2` — is in the o-to-s range where a hundred
and twenty-eight `anyhow`-class names get in first. The other two are the shape of a static
mbedTLS beside a static OpenSSL, and of PyNaCl's extension, which exports hundreds of
`crypto_*` names.

**The rules key on very little.** A string rule reads a string's `group`.
A symbol rule reads a symbol's `group` and its `binding`. A crate rule reads a crate's `name`.
So a cap that keeps one representative of every key before filling the remainder answers every
question the record is read for, and costs at most one entry per key. `binfmt.caps` holds the
walk and each type says what makes it interchangeable through a `cap_key`, so the fact is
stated once beside the class it is a fact about rather than three times in three readers.

The crate list needs more than a key. A string or a symbol only reaches a cap because a group
matched it, so every entry is evidence; a crate list is also an inventory, most of it named by
nothing, so the helper takes a `pin` and an unclaimed crate cannot take the room a claimed one
needs. Keeping every *version* of a claimed crate is a rejected alternative: a hundred and
thirty-three `openssl` versions would evict `ring` — the same failure one path down.

**The binding is part of the symbol key, not decoration.** Keying on the group alone keeps
whichever `EVP_*` sorts first, and if that one is imported then a defined one gets dropped —
which is `unknown` where the object is `static`, a quieter version of the same failure.

**What it does not promise.** A second banner from a group already represented still goes. What
cannot go is the last evidence of a group nothing else speaks for. The guarantee has one
condition, refused at load time rather than documented: there has to be room for one of every
key, so the loader rejects limits below the ruleset's own key counts.

**How it is pinned.** Not by a test alone. The admission test the invariants name for the
carve-out list — go and find a crypto object that reads clean because of it — works on a claim
as well as on a list, and this entry's own reproduction is that test applied to the previous
entry's claim.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-cap-bounds-the-record-it-does-not-pick-the-evidence)

---

## A cap bounds the record, not the evaluation

**Accepted, and it changes verdicts.**

`max_binaries_per_record` exists for the same reason the three per-binary limits do, and where
it applies decides what a rule can see. Slicing the binaries list to the cap before building the
`Evidence` that linkage, the rule engine and the classifier all run over means every object past
the 256th is fully decompressed and read — the cost paid in full — and then thrown away before
anything downstream ever looks at it:

```text
256 filler .so + one static-OpenSSL .so, sorting 257th (last)  -> NO_CRYPTO_DETECTED
same wheel, crypto object moved to sort 256th (last kept)      -> CONDITIONAL, BIN_STATIC_OPENSSL
```

Same object, same wheel, different verdict, purely because of where its filename sorts relative
to a limit that exists to bound JSON size. This is the same class of failure as the per-binary
evidence cap above, one layer up: there the cap picks which *matches inside an object* a rule
can see; here it picks which *objects* exist at all.

**Where it applies.** The collector hands `Evidence` the full, untruncated tuple. The cap
applies in one place: `build_record`, after findings and the verdict are computed, so only the
*serialised* array is bounded.

**What it costs.** A finding's `locations[].path` can legitimately name an object that is not
present in the record's `binaries[]`: the object was evaluated, a rule matched something in it,
and the cap left it out of the display list anyway. The schema says so rather than leaving it
to be discovered.

**The flag is also a finding.** Evaluating every object means a wheel is never read clean
because of where a filename sorts, but a human reading one JSON line still cannot tell "156
objects, all listed" from "156 listed out of 400". `WHEEL_BINARIES_TRUNCATED` closes that:
informational, no verdict, no human review, naming how many objects were actually evaluated.
Giving it a verdict is rejected — once evaluation sees everything, the verdict already reflects
the whole wheel, and treating an ordinary side effect of a display cap as something a human
must act on would put every large Rust or CUDA wheel on a triage list for a reason that has
nothing to do with crypto.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-cap-bounds-the-record-not-the-evaluation)

---

## `binaries[]` keeps what a finding points at, before filling the rest

**Accepted, and it changes records.**

Evaluation sees every object (the entry above). The *display* half is a separate concern: a
plain path-sorted prefix of `binaries[]` would repeat the same mistake, one layer up again. A
test builds the shape directly: 300 filler objects plus a partial ELF carrying an OpenSSL
banner and an unparseable object, both sorting after every filler. With a plain prefix:

```text
verdict: CONDITIONAL, needs_human_review: true
rule_ids: [BIN_OPAQUE, BIN_PARTIAL_FORMAT, BIN_STATIC_OPENSSL, BIN_UNPARSEABLE]
binaries[]: the first 256 filler objects, neither of the two present
```

Every finding correctly names one of the two objects that earned the verdict, and neither
object is anywhere in the array a human would read to corroborate it. The verdict is right;
nothing in the record backs it up. A completeness gap, not a correctness one.

**How it is filled.** `_cap_by_findings` fills `binaries[]` and `artifacts.extensions` alike,
in three passes, in the order a reader would miss it most:

1. One representative object per `(rule_id, subject)` a finding names, groups visited in a
   fixed deterministic order.
2. Every other object a finding references, in path order.
3. Everything else, in path order — the rule a plain prefix uses when there is nothing to
   prefer.

Both arrays use the same function rather than a parallel copy, so they keep agreeing on which
objects survive; there is no reason a reader should have to learn that they can disagree.

It deliberately does **not** call `binfmt.caps.cap()`, even though pass 1 is the same shape:
that function's grouping is keyed on a property of the *item*, and the group that matters here
comes from the *finding*, not the object — one object can be named by several findings, so the
natural key is not something a `BinaryEvidence` could sensibly expose.

**What a flat truncation of the referenced set would cost.** Skipping the grouping pass
entirely looks safe against an unbounded worst case that does not actually happen:
`BIN_STATIC_OPENSSL` is a linkage rule whose location is always the wheel filename, never
an object path, so a wheel with any number of statically-linked extensions contributes
*zero* object paths through it. The real bound is `max_locations_per_finding` times the
number of object-naming findings, which is small and tractable.

Within that tractable bound, a flat truncation is also severity-blind: a wheel with 270
distinct crate-naming findings would let ten low-severity `getrandom` objects, whose
subject sorts early, crowd the one `ring` object out of `binaries[]` entirely. Grouping
by `(rule_id, subject)` and reserving one slot per group first is what closes that. It
does not need to know what "high severity" means, only that **every finding gets a chance at a
slot before any finding gets a second one.**

**What it does not promise.** The per-binary caps validate at load time against a
ruleset-fixed vocabulary. This cap has no equivalent: how many distinct groups a wheel's
findings produce is data the wheel supplies, not policy the ruleset declares. When the group
count itself exceeds the cap, the groups that lose are whichever sort last — deterministic but
otherwise arbitrary. `binaries_truncated` and `WHEEL_BINARIES_TRUNCATED` still fire, so it is
never silent.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#binaries-keeps-what-a-finding-points-at-before-filling-the-rest)

---

## A symbol name is capped the way PE's are

**Accepted. PE's own bound, applied to ELF and Mach-O rather than a second one invented.**

Both `_iter_symbols` implementations find a name's terminator, decode the slice and run a
per-character Python sanitize pass over it for every row; with no per-name bound and no
whole-table budget, that costs rows times bytes. The PE reader bounds exactly this with two
bounds, and ELF and Mach-O use the same ones.

**Measured.** 2000 symbol rows all pointing at one 2 MiB name cost **243.7s** without the
bound. With it, the equivalent case runs in 0.02s for ELF and 0.11s for Mach-O. The cost is
not the row count; it is rows times the bytes each row's sanitize call is asked to look at.

**The two bounds, at PE's own values.** A per-name cap (8 KiB) past which a name is unresolved
rather than truncated into the record, and a whole-object budget (8 MiB) the cap alone does not
cover, because nothing stops many rows pointing at one name. Both live in `binfmt.symtab`,
shared rather than duplicated.

A name of exactly the cap still resolves; one byte more does not — **the cap means what its
name says**, the most a name may carry, not that minus one. The search window applies the
"+1" to whichever of the cap and the remaining budget is actually binding, not to the cap
alone: applying it to the cap alone fails safe but spends the budget one byte more
conservatively than the constant says.

**Memoization by string-table offset**, which PE does not have, covers a case neither bound
covers: many rows honestly repeating one *valid* name would otherwise spend the whole-table
budget once per row, turning an object carrying exactly one real symbol partial for no reason
but that its string table was walked more than once. The test that pins it is a correctness
assertion, not a stopwatch race — removing memoization does not make it slow, it makes
`partial_analysis` flip.

**The cache that makes memoization work has its own cap**, sized against a table shaped to
dodge the byte budget rather than repeat an offset: an offset past the table, into an unclosed
run, or naming an empty string costs the budget nothing, so one entry per row could accumulate
with neither bound engaging. Past 65536 entries `resolve` still answers every row correctly, it
simply stops remembering.

**Mach-O's `N_INDR` alias resolution calls the same resolver.** Leaving it uncapped, on the
reasoning that an alias row is rarer by construction or that capping it would change a
function signature, does not hold: every row in a reproduction is free to be `N_INDR`, and the
arity does not change at all; the alias branch calls the resolver in scope. 200 alias rows
against one 2 MiB target cost 30.4s without it.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-symbol-name-is-capped-the-way-pes-are)

---

## `caps.cap` scans `ordered` again instead of materialising `pinned`/`rest`/`leftovers`

**Accepted. Performance and memory, not correctness.**

Three passes each building their own reference list on top of `ordered` — `pinned` and
`rest` (together the same length as `ordered`), and `leftovers` (every item that lost
its `cap_key` slot or arrived after the room was gone) — would cost, for the case this
cap exists to bound (an object with half a million matching symbols), up to three
item-reference lists live at once on top of `ordered` and `kept`, and would call `pin`
twice per item.

`caps.cap` keeps the same four-pass priority order but scans `ordered` itself on every
pass, using `pin`'s answer for each index (`pinned_at`, computed once) and a set of
already-kept indices (`kept_at`) instead of the three item-reference lists.
`kept_at` is bounded by `limit`; `pinned_at`, one bool per item, is not — smaller than
a reference list but still `O(n)`. Measured, not assumed: at n=500,000 the whole
call's *peak* allocation is the same either way (the sort itself sets it); what
shrinks is the tail after the sort. Verified equivalent to the list-building passes by an
exhaustive sweep over small inputs (583,238 cases) and 20,000 randomised trials at
larger `n`, alongside `tests/test_caps.py`'s behavioural pins. The cap's output is the same
either way; only how it gets there differs.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#capscap-scans-ordered-again-instead-of-materialising-pinnedrestleftovers)

---

## `bundled_libs` and `errors[]` get their own caps, not `binaries_truncated`'s

**Accepted, and it changes records: two fields of their own, `bundled_libs_truncated` and
`errors_truncated`.**

`binaries_truncated` bounds `binaries[]` and `artifacts.extensions`, always the same
length. `artifacts.bundled_libs` and the top-level `errors[]` need caps of their own: without
one, a wheel vendoring thousands of small libraries, or hitting the same failure on thousands
of members, produces a correspondingly unbounded line — measured at 5000 vendored objects, a
274 KB line.

`bundled_libs` is a *subset* of `binaries[]`/`extensions`, so it needs its own
truncation flag rather than reusing `binaries_truncated`: a wheel with a huge object
count but a small vendored subset would otherwise report truncation that never
actually touched `bundled_libs`. It is capped the same finding-aware way
`binaries[]`/`extensions` are.

`errors[]` needs a different cap: dropping an error silently could hide the reason a
wheel reads `OPAQUE`, so a plain path-sorted prefix could crowd out a rare failure
behind a flood of one common kind. `ScanError` has a `cap_key`, `(stage, kind)`, making it a
`caps.Capped` exactly like `SymbolMatch`/`StringMatch`/`RustCrate`, and `build_record` caps
`evidence.errors` through that same `cap` — one representative error per `(stage, kind)`
survives before the rest. `caps.py` lives at the package's top level rather than under
`binfmt/` for this: `record.py` needs it too, and a module under `binfmt/` would make the
serialisation layer transitively import every structural reader, pyelftools included, just to
cap a list of errors.

Both share `max_binaries_per_record`, the same knob that bounds `binaries[]`/`extensions` — no
context field or CLI flag of their own.

**`skipped` and `symlinks` are the same shape** — without their own cap, a wheel with 3000
refused members produces a correctly capped `errors: 256` beside an uncapped
`artifacts.skipped: 3003`. They are decided in the next entry.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#bundled_libs-and-errors-get-their-own-caps-not-binaries_truncateds)

---

## `skipped` and `symlinks` reuse `caps.cap`, not a plain prefix

**Accepted, and it changes records: two fields of their own, `symlinks_truncated` and
`skipped_truncated`.**

`artifacts.skipped` and `artifacts.symlinks` are the same unbounded shape as
`bundled_libs`/`errors[]`. A plain sorted prefix is wrong for both, on two premises worth
checking rather than assuming: that neither is finding-referenced, and that every entry is
already fully specific. `skipped`'s `reason` **is** `ScanError.kind`, the exact axis
`errors[]`'s own `cap_key` protects, and two shipped rules (`BIN_TOO_LARGE`,
`WHEEL_MEMBER_UNREADABLE`) do name `skipped` paths — reproduced: a plain prefix drops an
entire reason class from `skipped` while `errors[]` correctly keeps a representative.
`symlinks`' `target`, not the entry as a whole, is the axis a consumer keys on (a bundled
library can be reachable only through its symlink's target) — reproduced: a plain prefix drops
the one crypto-relevant target behind a flood of boring ones, the same starvation `caps.py`'s
own `ring`-behind-`anyhow` crate example exists to prevent.

Both go through `caps.cap`, keyed on the axis that matters: `cap_key() -> reason` for
`skipped`, `cap_key() -> target` for `symlinks`. Neither bare tuple implements `caps.Capped`
on its own, so `record.py` wraps each pair in a small local frozen dataclass at cap time and
unwraps the result — `ArtifactInventory.skipped`/`.symlinks` themselves stay plain tuples
everywhere else.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#skipped-and-symlinks-reuse-capscap-not-a-plain-prefix)
