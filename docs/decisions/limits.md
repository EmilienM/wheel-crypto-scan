# Caps, budgets and record size

A record has to be bounded: one wheel with thousands of objects must not produce an
unbounded JSON line. Five entries about that, and they share one theme — **a limit that
exists to bound output kept deciding what the tool found**, because it was applied in the
place that also decides what a rule gets to see, and because the sort key it cut on had
nothing to do with what a match is worth.

Each one was found by building the object that crosses the line, and two of them were found
because a sentence in an earlier entry claimed it could not happen.

## A recording cap is not a partial read

**Accepted. One of the two halves of `truncated` became a cause; the other stayed a field.**

`strings_truncated` was set by three different things at once, and `partial_analysis` by none
of them. So an object whose strings pass never reached the end of it still contributed a
definite posture, and the record said both at once:

```text
strings_truncated: true
partial_analysis:  false   partial_reasons: []
openssl_linkage:   none    NO_CRYPTO_DETECTED   needs_human_review: false
```

Measured on one `.pyd` carrying an OpenSSL version banner in its last 26 bytes: scanned whole
it is `static` and `CONDITIONAL`; with the byte budget stopping short of the banner, the same
object is clean. The banner is not a nice-to-have — `cryptography` 42 and later compiles
OpenSSL in, with no library file, no dependency and no exported symbol, so the banner is the
*entire* evidence.

**Only the reading gap got a token, and the reason is definitional.** `partial_analysis` means
part of the object was not read. A *recording* cap — more group matches than the limit keeps —
is not that: the object was read, and what was capped is what got written down. It is not a
member of the class `PARTIAL_REASONS` enumerates, so the vocabulary is not being asked to hold
a policy.

The alternative was rejected on a harder ground than taste. Minting a cap token as a fact and
then exempting it in the ruleset needs a verdict-less `partial_binary` rule, which the
load-time floor then forces into `[linkage_policy] exclude_reasons` — **a second carve-out on
the "unreadable means `OPAQUE`" invariant**, which is a change to the invariant itself. One
carve-out is what that document permits.

**What the caps do instead is worse, and it was not fixed here.** This entry's first draft
claimed a recording cap "cannot produce a record that reads clean, because it only fires once
that many matches are in hand". That is false, and the counterexample is four lines:

```text
ring alone                 -> NON_APPROVED_CRYPTO  needs_human_review: true
ring + 130 earlier crates  -> NO_CRYPTO_DETECTED   needs_human_review: false
                              strings_truncated: true, partial_analysis: false
```

That is the next entry.

**What it costs, and the threshold is not the same in every format.** For Mach-O, PE and the
fallback the budget is measured against the object, so an object over 64 MiB is now `OPAQUE`.
For ELF it is measured against the concatenation of eligible read-only sections, so a gigabyte
`.so` that is mostly `.text` is untouched while a smaller one carrying a large `.nv_fatbin` is
not. That distinction matters rather than being a footnote: CUDA and PyTorch wheels, which is
where the size is, ship overwhelmingly as manylinux ELF.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-recording-cap-is-not-a-partial-read) ·
[#48](https://github.com/EmilienM/wheel-crypto-scan/issues/48)

---

## A cap bounds the record, it does not pick the evidence

**Accepted, and it changes records.**

Three per-binary limits exist so one object cannot produce an unbounded JSON line. None of
them exists to decide which evidence survives, and all three did, because each sorted its
matches and cut at the limit. The sort key has nothing to do with what a match is worth, and
the crypto names the ruleset claims sit in the middle of every one of those orderings.

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

**The fix is to notice how little the rules key on.** A string rule reads a string's `group`.
A symbol rule reads a symbol's `group` and its `binding`. A crate rule reads a crate's `name`.
So a cap that keeps one representative of every key before filling the remainder answers every
question the record is read for, and costs at most one entry per key. `binfmt.caps` holds the
walk and each type says what makes it interchangeable through a `cap_key`, so the fact is
stated once beside the class it is a fact about rather than three times in three readers.

The crate list needs more than a key. A string or a symbol only reaches a cap because a group
matched it, so every entry is evidence; a crate list is also an inventory, most of it named by
nothing, so the helper takes a `pin` and an unclaimed crate cannot take the room a claimed one
needs. The second implementation had already drifted before review: it kept every *version* of
a claimed crate, so a hundred and thirty-three `openssl` versions evicted `ring` — the same bug
one path down.

**The binding is part of the symbol key, not decoration.** Keying on the group alone keeps
whichever `EVP_*` sorts first, and if that one is imported then a defined one gets dropped —
which is `unknown` where the object is `static`, a quieter version of the same bug.

**What it does not promise.** A second banner from a group already represented still goes. What
cannot go is the last evidence of a group nothing else speaks for. The guarantee has one
condition, now refused at load time rather than documented: there has to be room for one of
every key, so the loader rejects limits below the ruleset's own key counts.

**How it was found.** Not by a test. A sentence in the entry above asserted that a cap "cannot
produce a record that reads clean", and review went and built the object that does. The
admission test the invariants name for the carve-out list works on a claim as well as on a
list.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-cap-bounds-the-record-it-does-not-pick-the-evidence) ·
[#51](https://github.com/EmilienM/wheel-crypto-scan/issues/51)

---

## A cap bounds the record, not the evaluation

**Accepted, and it changes verdicts.**

`max_binaries_per_record` exists for the same reason the three per-binary limits do, and it
was applied in the one place that also decides what a rule can see. The collector sliced the
binaries list to the cap before building the `Evidence` that linkage, the rule engine and the
classifier all run over, so every object past the 256th was fully decompressed and read — the
cost was paid in full — and then thrown away before anything downstream ever looked at it.

```text
256 filler .so + one static-OpenSSL .so, sorting 257th (last)  -> NO_CRYPTO_DETECTED
same wheel, crypto object moved to sort 256th (last kept)      -> CONDITIONAL, BIN_STATIC_OPENSSL
```

Same object, same wheel, different verdict, purely because of where its filename sorts relative
to a limit that exists to bound JSON size. This is the same class of bug as the entry above,
one layer up: there the cap picked which *matches inside an object* a rule could see; here it
picked which *objects* existed at all.

**The fix.** The collector hands `Evidence` the full, untruncated tuple. The cap moved to the
one place it always should have applied: `build_record`, after findings and the verdict are
already computed, so only the *serialised* array is bounded.

**What it costs.** A finding's `locations[].path` can now legitimately name an object that is
not present in the record's `binaries[]`: the object was evaluated, a rule matched something in
it, and the cap left it out of the display list anyway. The schema says so rather than leaving
it to be discovered.

**Whether the flag should also be a finding.** Fixing evaluation removes the correctness bug,
but a human reading one JSON line still cannot tell "156 objects, all listed" from "156 listed
out of 400". `WHEEL_BINARIES_TRUNCATED` closes that: informational, no verdict, no human
review, naming how many objects were actually evaluated. Giving it a verdict was considered and
dropped — once evaluation sees everything, the verdict already reflects the whole wheel, and
treating an ordinary side effect of a display cap as something a human must act on would put
every large Rust or CUDA wheel back on a triage list for a reason that has nothing to do with
crypto.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-cap-bounds-the-record-not-the-evaluation) ·
[#55](https://github.com/EmilienM/wheel-crypto-scan/issues/55)

---

## `binaries[]` keeps what a finding points at, before filling the rest

**Accepted, and it changes records. Revised after adversarial review found two things worth
fixing in the fix itself.**

The entry above made evaluation complete. What it left alone was the *display* half, which
still cut to a plain path-sorted prefix — the same mistake, one layer up again. Review built
the shape directly: 300 filler objects plus a partial ELF carrying an OpenSSL banner and an
unparseable object, both sorting after every filler.

```text
verdict: CONDITIONAL, needs_human_review: true
rule_ids: [BIN_OPAQUE, BIN_PARTIAL_FORMAT, BIN_STATIC_OPENSSL, BIN_UNPARSEABLE]
binaries[]: the first 256 filler objects, neither of the two present
```

Every finding correctly names one of the two objects that earned the verdict, and neither
object is anywhere in the array a human would read to corroborate it. The verdict is right;
nothing in the record backs it up. A completeness gap, not a correctness one.

**The fix.** `_cap_by_findings` fills `binaries[]` and `artifacts.extensions` alike, in three
passes, in the order a reader would miss it most:

1. One representative object per `(rule_id, subject)` a finding names, groups visited in a
   fixed deterministic order.
2. Every other object a finding references, in path order.
3. Everything else, in path order — the rule the plain prefix already used when there was
   nothing to prefer.

Both arrays reuse the same function rather than a parallel copy, so they keep agreeing on which
objects survive; there is no reason a reader should have to learn that they can now disagree.

It deliberately does **not** call `binfmt.caps.cap()`, even though pass 1 is the same shape:
that function's grouping is keyed on a property of the *item*, and the group that matters here
comes from the *finding*, not the object — one object can be named by several findings, so the
natural key is not something a `BinaryEvidence` could sensibly expose.

**What adversarial review changed here.** The first version skipped the grouping pass entirely,
justified by an unbounded worst case that does not actually happen: `BIN_STATIC_OPENSSL` is a
linkage rule whose location is always the wheel filename, never an object path, so a wheel with
any number of statically-linked extensions contributes *zero* object paths through it. The real
bound is `max_locations_per_finding` times the number of object-naming findings, which is small
and tractable — so the stated reason a smarter fallback was not worth attempting turned out not
to hold.

With that corrected, review found the flat fallback was also severity-blind within the bound it
really has: a wheel with 270 distinct crate-naming findings let ten low-severity `getrandom`
objects, whose subject sorts early, crowd the one `ring` object out of `binaries[]` entirely.
Grouping by `(rule_id, subject)` and reserving one slot per group first is what closes that. It
does not need to know what "high severity" means, only that **every finding gets a chance at a
slot before any finding gets a second one.**

**What it still does not promise.** The per-binary caps validate at load time against a
ruleset-fixed vocabulary. This cap has no equivalent: how many distinct groups a wheel's
findings produce is data the wheel supplies, not policy the ruleset declares. When the group
count itself exceeds the cap, the groups that lose are whichever sort last — deterministic but
otherwise arbitrary. `binaries_truncated` and `WHEEL_BINARIES_TRUNCATED` still fire, so it is
never silent.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#binaries-keeps-what-a-finding-points-at-before-filling-the-rest) ·
[#75](https://github.com/EmilienM/wheel-crypto-scan/issues/75)

---

## A symbol name is capped like PE's already are

**Accepted. Ports the PE fix to ELF and Mach-O rather than inventing a second one.**

Both `_iter_symbols` implementations found a name's terminator, decoded the full slice and ran
a per-character Python sanitize pass over it for every row, with no per-name bound and no
whole-table budget. The PE reader had closed exactly this with two bounds and neither ELF nor
Mach-O had either.

**Measured.** 2000 symbol rows all pointing at one 2 MiB name cost **243.7s**. Post-fix, the
equivalent case runs in 0.02s for ELF and 0.11s for Mach-O. The cost was never the row count;
it was rows times the bytes each row's sanitize call was asked to look at.

**The two bounds, ported at PE's own values.** A per-name cap (8 KiB) past which a name is
unresolved rather than truncated into the record, and a whole-object budget (8 MiB) the cap
alone does not cover, because nothing stops many rows pointing at one name. Both now live in
`binfmt.symtab`, shared rather than duplicated.

A name of exactly the cap still resolves; one byte more does not — **the cap means what its
name says**, the most a name may carry, not that minus one. An early draft of the search window
applied the "+1" to the cap alone rather than to whichever of the cap and the remaining budget
was actually binding, which failed safe but spent the budget one byte more conservatively than
the constant said.

**Memoization by string-table offset**, which PE does not have, closes a case neither bound
closes: many rows honestly repeating one *valid* name would otherwise spend the whole-table
budget once per row, turning an object carrying exactly one real symbol partial for no reason
but that its string table was walked more than once. The test that pins it is a correctness
assertion, not a stopwatch race — reverting memoization does not make it slow, it makes
`partial_analysis` flip.

**The cache that makes memoization work has its own cap**, found by asking what it costs
against a table shaped to dodge the byte budget rather than repeat an offset: an offset past
the table, into an unclosed run, or naming an empty string costs the budget nothing, so one
entry per row could accumulate with neither bound engaging. Past 65536 entries `resolve` still
answers every row correctly, it simply stops remembering.

**Correction: Mach-O's `N_INDR` alias resolution was first left uncapped**, on two
justifications that did not survive review — that an alias row is rarer by construction, and
that closing it would change a function signature. Neither held. Every row in a reproduction is
free to be `N_INDR`, and the arity does not change at all; the alias branch simply was not
calling the resolver that was already in scope. 200 alias rows against one 2 MiB target cost
30.4s before the correction.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-symbol-name-is-capped-like-pes-already-are) ·
[#61](https://github.com/EmilienM/wheel-crypto-scan/issues/61)
