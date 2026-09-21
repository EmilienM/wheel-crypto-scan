# PE

One entry about `binfmt/pe.py` here. Two more PE decisions live elsewhere because they are
about the invariant rather than the reader: the ordinal import and export carve-out is under
[Evidence, opacity and verdicts](opacity.md#a-routine-cause-is-recorded-but-does-not-make-a-wheel-opaque),
and `.exe` among the recognised suffixes is under
[Scanning, caching and layout](tooling.md#exe-is-in-_binary_suffix-and-com-cpl-and-sys-are-not).

## A forwarder resolves the dependency it forwards to, not just its own name

**Accepted, and it changes what a forwarding wrapper can hide.**

The export reader tells a forwarder from a definition by where its "address" lands — back
inside the export directory, where it is a string rather than code. Recording only the
export's *own* name as imported, and never reading that string, leaves a `.pyd` exporting
`my_digest_init` as a forwarder to `libcrypto-3-x64.EVP_DigestInit_ex` with neither the DLL
nor the real symbol anywhere in the record:

```text
own name only       -> needed: [],  matched_symbols: [], NO_CRYPTO_DETECTED, needs_human_review: false
forwarder resolved  -> needed: ['libcrypto-3-x64.dll'], matched_symbols: [EVP_DigestInit_ex/imported],
                       CONDITIONAL (openssl_linkage: system), needs_human_review: true
```

Without resolution, only a wrapper whose *own* export name happens to match the ruleset is
caught, which is coincidence standing in for evidence — the exact shape the "unreadable means
`OPAQUE`" invariant exists to rule out, except here nothing is even unreadable. The bytes sit
in the object; a reader has only to ask for them.

**How it is read.** The forwarder string itself, `OTHERDLL.Symbol` or `OTHERDLL.#Ordinal`, is
read through the same bounded string reader every other name in the file goes through, and
split on its *first* dot. The DLL half never carries the file extension — the same convention
`NTDLL.RtlAllocateHeap` uses — so `.dll` is appended to match what `needed` holds for every
other dependency. The resolved DLL joins `needed`; the resolved symbol, when the string names
one rather than an ordinal, joins `matched_symbols` as `imported`.

**First dot, not last: splitting on the last dot misses a real shape.** Splitting
on the *last* dot, on the theory that nothing in the format forbids a dot in a DLL name,
misses a real shape: MSVC hot/cold splitting produces symbol names like
`EVP_DigestInit_ex.cold`, so a forwarder to `libcrypto-3-x64.EVP_DigestInit_ex.cold`
last-dot-splits into a DLL name that matches nothing and a symbol `cold` that also matches
nothing — reading the wheel clean, exactly the failure resolving forwarders exists to prevent.

A literal dot in a DLL name is not forbidden either, but it is not a shape a real Windows DLL
name uses in practice, while a dot in the symbol half is documented compiler behaviour.
First-dot is the bet that loses less evidence, not a reading the format makes certain.

**Why the DLL, not just the symbol.** Recording only the target symbol and leaving `needed`
alone is weaker on the field that matters most: the posture function reads `needed` first,
and the two dependency rules key on it, not on `matched_symbols`. The Windows loader resolves
a forwarder exactly like an import at load time — it opens the target DLL before it can fail
to find the symbol in it — so the dependency is real in exactly the sense `needed` means.

**An ordinal-named forwarder reuses the ordinal-import token, not a new one.** A forwarder to
`SOMEDLL.#123` loses the function name the same way an ordinal-bound import does, for the same
reason: the loader opens the DLL regardless, so the dependency survives in `needed` and only
the symbol is unrecoverable. The admission test finds nothing here that the ordinal-import
carve-out does not already cover.

**A forwarder string this reader cannot terminate is `pe_export_incomplete`, not a silent gap.**
Past the name cap or the object's name budget, the string reader returns nothing the same as for
any other name, and the object is marked incomplete rather than reported as forwarding to
nothing.

**What was rejected.** Recording only the target symbol. Inventing a new token for the
ordinal-forwarder case, which would duplicate the ordinal-import token for no reason the
ruleset could tell apart. And recording *both* candidate splits — unioning the matches from both
halves and both candidate DLL names into `needed` — rejected as overkill for a case that is, by
the corpus this reader was measured against, vanishingly rare, against a real cost: doubling
`needed` and `matched_symbols` cardinality for every multi-dot forwarder, cutting against the
same record-size discipline the cap module exists to hold.

**What it costs.** Resolving the string is what introduces a forwarder that fails to resolve
(`pe_export_incomplete`), where reading nothing gives a silent, wrong `NO_CRYPTO_DETECTED`.

And the split direction has a real, if judged unlikely, failure mode: a forwarder whose DLL half
genuinely embeds a literal dot splits wrong, the way a last-dot split gets the `.cold` case wrong.
The shape is a dotted name whose first segment is not one the ruleset recognises on its own, the
way .NET's native shims are named — a forwarder to
`System.Security.Cryptography.Native.OpenSsl.CryptoNative_EvpDigestUpdate` first-dot splits to
`System` and loses the rest, where last-dot would recover the symbol. Nothing in the PE
format rules either shape out, so this is a bet made in the direction the evidence says loses
less: MSVC hot/cold splitting is default-on compiler behaviour for any MSVC-built wrapper, while
a CPython extension forwarding into a dotted native-shim family is a narrower shape.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-forwarder-resolves-the-dependency-it-forwards-to-not-just-its-own-name)
