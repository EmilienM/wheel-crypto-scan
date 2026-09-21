# OpenSSL linkage

`linkage.py` answers the question the tool exists for: does this wheel use the system
OpenSSL, or does it carry its own? The first two entries below are about
`_binary_posture`, the function that reads one object's own evidence, and both were
corrected more than once, each time by an object the prose had not anticipated. The third
is about the weakest evidence it reads: a Rust crate name, which can say `unknown` and
nothing more. The fourth is back on `_binary_posture`, about a banner it once counted as
a copy even when the object's headers, not a linked copy, put the banner there.

## A `needed` entry is bundled by what it resolves to, not by whether its name was renamed

**Accepted, and it changes `openssl_linkage` and one finding. Two claims did not hold up
under review — see below, which is the part to read first if you are deciding whether
`member_stem_counts` or `_looks_vendored` is safe to lean on as written.**

`_binary_posture` read `needed` first: a base name in a crypto library's `sonames` was
`bundled` only when the name itself carried a content hash (`libcrypto-3a1f2b4c.so.3`),
otherwise `system`. That is exactly what auditwheel and delvewheel produce, and it is not
what delocate produces. delocate copies a dependency into `.dylibs/` and rewrites the load
command to point there — `@loader_path/.dylibs/libcrypto.3.dylib` — **without renaming the
file**.

```text
pkg/_ext.cpython-312-darwin.so   needed: @loader_path/.dylibs/libcrypto.3.dylib
pkg/.dylibs/libcrypto.3.dylib    vendored_path: true, defines EVP_DigestInit_ex, SSL_new
-> before: openssl_linkage: mixed, BIN_OPENSSL_LINKAGE_UNKNOWN, BIN_NEEDED_SYSTEM_OPENSSL
-> after:  openssl_linkage: bundled, BIN_BUNDLED_OPENSSL
```

Two postures for one OpenSSL, with "could not be resolved" and "links the system OpenSSL"
both firing — wrong on every count. The same shape reaches ELF too: nothing stops a build
placing an unmangled dependency beside the extension with `RUNPATH $ORIGIN`.

**The fix has two parts, matched to the two ways a `needed` entry can prove it names a file
the wheel ships.** `Conventions.raw_stem` reduces a name the way `own_base` does but stops
short of undoing a content-hash rename; `linkage.member_stems` collects every object's
`raw_stem` across the wheel, and a `needed` entry whose own `raw_stem` lands in that set is
`bundled`, mangled or not. Second, `_looks_vendored` reads the `needed` string itself and,
for `@rpath`-relative names, the object's own `LC_RPATH` list — a weaker signal used only as
a backstop that never asserts `bundled` by itself.

**Why the path-convention half is capped at `unknown`, never `bundled`.** A `needed` entry
can look exactly like delocate's convention and still name nothing the wheel actually ships.
Letting the shape alone promote to `bundled` would manufacture the same overconfidence this
issue closes, aimed the other way.

**A real risk this does not fully close.** `member_stems` matches on file identity alone, not
on directory, so two different libraries sharing a basename in one wheel would let an
unrelated `needed` entry read as `bundled`. Resolving that precisely needs walking the actual
search path, a meaningfully bigger change. Recorded rather than fixed, because the failure
direction — reading `system` as `bundled` — is the safe one for a FIPS-risk tool.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-needed-entry-is-bundled-by-what-it-resolves-to-not-by-whether-its-name-was-renamed) ·
[#57](https://github.com/EmilienM/wheel-crypto-scan/issues/57)

### Two claims here did not hold up

**Corrected. The "real risk" paragraph above understated the risk, and the `_looks_vendored`
backstop fired far more broadly than the "narrow case" it claimed.**

Adversarial review ran a 150-shape differential matrix and found both wrong.

**Claim 1** was that a false `bundled` only fires when the wheel already ships *some* object
under that literal name, "which is itself circumstantial evidence worth a human's attention."
True of the two-file collision the paragraph had in mind, and not the sharpest shape the
lookup admits — a *single* object, no vendor directory, no second file, whose own file name
reduces to the same stem as an absolute, genuinely-system dependency it declares:

```text
fakecrypto/libcrypto.so   soname: libcrypto.so
                          needed: /usr/lib64/libcrypto.so.3, libc.so.6
-> before: openssl_linkage: bundled, verdict.class: NO_CRYPTO_DETECTED,
           rule_ids: [], needs_human_review: false
```

`member_stems` included the querying object itself, so the object answered its own question.
Worse than a wrong posture, this one had **no rule behind it at all**: a third route to
`bundled` existed that nothing claimed.

Fixed in two parts. `member_stems` became `member_stem_counts`, a `Counter`, and
`_resolves_within_wheel` discounts an object's own contribution to its own answer.
And a new rule, `BIN_NEEDED_VENDORED_CRYPTO`, claims this third route the same way the other
two are claimed, so the residual imprecision the two-file case still allows is never silent:
`needs_human_review` is true even when the `bundled` classification is a false positive from
the coincidence.

**Claim 2** was that `_looks_vendored`'s `@rpath` and `RPATH`/`RUNPATH` handling "earns its
place on a narrower case". The code did not match the claim: it fired whenever the object had
*any* vendor-shaped search path, independent of whether the specific `needed` entry could
plausibly resolve under it. The matrix found this misreading a genuine system dependency as
`unknown` on 11 of 150 shapes — a FIPS-conscious build running auditwheel's
`--exclude libcrypto.so.3` while vendoring an unrelated library, say libjpeg, in the same
wheel.

Fixed with `wheel_incompletely_read(evidence)`, true only when some member never became a
`BinaryEvidence` at all. `_looks_vendored` is consulted only when that holds; when the wheel
was read in full, a vendor-shaped path naming nothing is genuine `system`, because **a
complete member list that does not contain the answer is itself the answer.**

### The `_looks_vendored` gate was still incomplete

**Corrected again.** Two more findings past that point.

**The vendor-shape check itself had no test.** Mutating `_looks_vendored` to unconditionally
`return True` left the full suite green: the gate around it was pinned in both directions, but
nothing pinned the shape check *inside* the gate.

**`wheel_incompletely_read` did not check `artifacts.symlinks`.** A vendored library shipped
as a symlink — ordinary practice for a versioned `.so`/`.dylib` — is never read as a binary at
all, and records neither a skipped entry nor an error:

```text
demo/_ext.abi3.so               needed: @loader_path/.dylibs/libcrypto.3.dylib
demo/.dylibs/libcrypto.3.dylib  -> a symlink, never read as a binary at all
-> before: openssl_linkage: system, BIN_NEEDED_SYSTEM_OPENSSL, DERIVED_SYSTEM_OPENSSL_ONLY
```

Both finding descriptions are affirmatively wrong here: an `@loader_path`-anchored load
command is wheel-internal by construction and can never be the host's system OpenSSL.
`needs_human_review` was still true, so this was never silent, but it was confidently wrong
rather than honestly uncertain, which is the distinction this whole entry exists to draw.

**What is still true, named honestly rather than assumed.** Every `bundled` posture
`_binary_posture` can produce now has a rule behind it, audited one branch at a time. But
`system` has an aggregate-level backstop that no per-mechanism enumeration needs to keep in
step, and `bundled` does not: nothing would notice if a fourth mechanism were added without a
fourth rule. The cheap close is a behavioural invariant test asserting that no definite
`openssl_linkage` value reaches the record without a contributing rule having fired. It costs
nothing and is worth adding regardless.

### An absolute `needed` entry closes part of "a real risk this does not fully close"

**Fixed, for one shape.** The "real risk" paragraph above accepted that a basename collision
between two unrelated objects could manufacture a false `bundled`. That is no longer true when
the colliding `needed` entry is an absolute path (`/usr/lib64/libcrypto.so.3`): no real dynamic
loader resolves an absolute path against anything the wheel ships, so `needed_posture` now
answers `system` for it outright, before consulting the basename match or the vendor-shape
check at all. The residual stays open for a *relative* entry that a loader genuinely could
resolve via `$ORIGIN`/`@rpath`/`RPATH`/`RUNPATH` — the ordinary vendoring shape this whole
entry is about — and, narrower still, for a relative-but-non-wheel-resolvable shape like
`../../hostlib/libcrypto.so.3` or a Mach-O `@executable_path/...` entry, neither of which this
fix covers even though the same argument applies to them.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#an-absolute-needed-entry-closes-part-of-the-residual-rather-than-leaving-it-open) ·
[#80](https://github.com/EmilienM/wheel-crypto-scan/issues/80)

---

## A `needed` match and a definition inside one object are both true, so the object is `mixed`

**Fixed. The precedence question the entry above deliberately left open.**

`_binary_posture` read `needed` first and returned `system` as soon as one entry resolved to
the system library, before the defined-symbol and banner check below it ever ran. An object
that both declares `DT_NEEDED libssl.so.3` and defines `EVP_DigestInit_ex` — or carries an
OpenSSL version banner, which a version script cannot hide — read `system` regardless, and
the record then paired "every piece of OpenSSL evidence points at the system library" with
"OpenSSL was compiled into it" in the same `rule_ids` list. A contradiction in the favourable
direction.

```text
demo/_ext.so   needed: libc.so.6, libssl.so.3
               defines EVP_DigestInit_ex, rodata: "OpenSSL 3.0.14 4 Jun 2024"
-> before: openssl_linkage: system, with DERIVED_SYSTEM_OPENSSL_ONLY
-> after:  openssl_linkage: mixed, with BIN_OPENSSL_LINKAGE_UNKNOWN and no
           DERIVED_SYSTEM_OPENSSL_ONLY
```

**The decision: `mixed`, not `static`-wins.** Both facts are independently true and
independently reportable — a real `DT_NEEDED` entry names the system library, and a real
symbol, or a banner that is not header text (see
[the entry on header banners](#a-version-banner-beside-imports-from-the-system-library-is-header-text-not-a-copy)),
shows the object also carries its own copy. `static`-wins would suppress the
`needed` evidence from the field most consumers filter on, which would then say `static`
about an object that also, genuinely, links the system library. `mixed` costs no schema
change: the value already existed for the cross-object case.

**What it costs.** `BIN_OPENSSL_LINKAGE_UNKNOWN` now also fires for this shape, and its own
`why` — "the wheel calls OpenSSL without declaring a dependency on it, or the only evidence
came from an object we could not read" — describes neither: here the dependency *is* declared
and the object *was* read in full. Left as is rather than reworded, because rewording it
correctly means splitting what is now two different reasons `mixed` can fire.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-needed-match-and-a-definition-inside-one-object-are-both-true-so-the-object-is-mixed) ·
[#60](https://github.com/EmilienM/wheel-crypto-scan/issues/60)

### Extended: an uncertain needed match and a definition are mixed too

**Fixed.** The gap above was structural, not an oversight: `_binary_posture` still returned
`unknown` for the `uncertain` case — a `needed` entry whose shape looks vendor-directed but
that an incompletely-read wheel cannot confirm — before the defined/banner check ran. An
object with both an unconfirmed vendor-shaped entry and a confirmed static definition read
`unknown` regardless, silently discarding the confirmed evidence in favour of the unconfirmed
one.

```text
demo/_ext.so  needed: libcrypto.so.3, RUNPATH: $ORIGIN/../p.libs (names nothing shipped,
              wheel incompletely read), defines EVP_DigestInit_ex
-> before: openssl_linkage: unknown   -> after: mixed
```

**Precedence, stated correctly at the third attempt.** What makes a confirmed entry beat an
unconfirmed one is not where the new branch sits: it is that `if uncertain: return unknown`
sits *below* `if system:` in the ladder, applying within one object the same rule the
aggregate already applies across objects — a non-definite posture never outvotes a definite
one already present. Moving the new branch changes nothing the test suite can observe,
confirmed by mutation. This exact category of mistake had already been made once in this same
precedence work, which is why the entry now says it twice.

The three-way case collapses into the existing two-way branch before `uncertain` is ever
consulted, and that collapse is provable rather than merely observed: the two conditions can
only be true together when `system` is also true, and both branches return the same value.

**What it costs**, named plainly rather than leaving an earlier "costs nothing new" claim
standing: this widens `mixed` one object beyond the one it fires on. A wheel with one object
reading `bundled` and a second that now reads `mixed` used to aggregate to `bundled`; it now
aggregates to `mixed`, dropping out of the `IN("bundled","static")` triage recipe. The
direction stays conservative — the wheel gains `OPAQUE` rather than losing anything silently.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#extended-in-87-an-uncertain-needed-match-and-a-definition-are-mixed-too) ·
[#87](https://github.com/EmilienM/wheel-crypto-scan/issues/87)

### Extended again: a bundled needed match and system/static are mixed too

**Fixed. The third extension of the same precedence work.**

The `needed` loop still returned `bundled` immediately, from inside the loop, before a second
disagreeing entry or the defined/banner check ever ran. A universal Mach-O merges its slices'
`needed` tuples into one, so an object whose slices disagreed about `bundled` versus `system`
read `bundled` outright, unlike the same evidence read as two separate objects.

```text
one object, needed=("libcrypto-3a1f2b4c.so.3", "/usr/lib64/libcrypto.so.3")
  -> before: bundled   -> after: mixed
same evidence in two separate objects -> mixed, unchanged
```

**The fix.** The loop no longer returns from inside itself. It accumulates `system`,
`bundled` and `uncertain` across the whole `needed` tuple before branching, and the
two-way check becomes a three-way count: `sum((system, bundled, static)) > 1` is `mixed`.

| `system` | `bundled` | `static` | `uncertain` | Result |
|---|---|---|---|---|
| 2+ of the three true | — | — | any | `mixed` |
| T | F | F | any | `system` |
| F | T | F | any | `bundled` |
| F | F | T | T | `mixed` |
| F | F | T | F | `static` |
| F | F | F | T | `unknown` |
| F | F | F | F | falls through |

`bundled` gets the same treatment as `system` beside `uncertain` because both are read off the
same `needed` loop and `if uncertain:` sits below both. `static` is not read off `needed` at
all, which is why it combines with `uncertain` into `mixed` rather than being outvoted.

**Kept out of scope, and there is a real reproduction for it.** An object identified by its
own `vendored_path` rather than by a `needed` entry can still carry a disagreeing signal that
its early return discards — a vendored `libssl` that itself links the host `libcrypto`, which
is the real `auditwheel --exclude libcrypto.so.3` shape:

```text
demo/_ext.so                   needed: libc.so.6, libssl-abc123.so.3
demo.libs/libssl-abc123.so.3   needed: libc.so.6, libcrypto.so.3   defines SSL_new
-> openssl_linkage: bundled   (the system libcrypto dependency is discarded)
```

Milder than the original hole — nothing reads clean, and `needs_human_review` is true — but
the same family. Left open on scope discipline, not on cost: the extra checks are cheap, the
early return is a genuinely different code path, and folding it in would extend an
already-large precedence change further than the issue asked for.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#extended-in-88-a-bundled-needed-match-and-systemstatic-are-mixed-too) ·
[#88](https://github.com/EmilienM/wheel-crypto-scan/issues/88)

---

## An OpenSSL crate with no other evidence reads `unknown`, not `none`

**Fixed.**

An object read in full whose only OpenSSL evidence was a crate name (`openssl-sys`,
`openssl`, `openssl-src`) read `openssl_linkage: none` beside a `CONDITIONAL` crate
finding: "no OpenSSL evidence" on a record carrying some.

**The fix.** `[[crypto_library]]` gains `crates`, validated against `[[rust_crate]]` at
load time. An object carrying a listed crate and nothing else `_binary_posture` reads gives
`unknown`, the answer imported OpenSSL symbols with no declared dependency already get, for
the same reason: something uses OpenSSL, and the object does not say which copy.

**Never a definite posture.** The branch fires only on an object with no OpenSSL
`needed` entry, symbol or banner, which is more likely a static copy, but only as far as
the readers left nothing open. And the crate cannot settle it: `OPENSSL_NO_VENDOR` sends
even a `vendored` `openssl-sys` build back to the host's OpenSSL. One crate, built both
ways:

```text
cryptography 50.0.1 off PyPI (manylinux, macOS, Windows)
  crates: openssl, openssl-sys   banner "OpenSSL 4.0.2 25 Aug 2026"          -> static
cryptography 50.0.0, Fedora 44 RPM, repackaged as a wheel
  needed: libcrypto.so.3, libssl.so.3   SBOM names openssl-sys             -> system
```

Same crate, two postures, so the crate check sits below every other one and its `unknown`
never outvotes a definite posture elsewhere in the wheel. None of the four records moved.
The Windows `.pyd` shows what does: its banner is its only OpenSSL evidence, and with
`openssl_banner` restricted to `3.`, `1.1.` and `1.0.`, it reads `none` before and
`unknown` after. The Fedora row's missing crate is its own gap, tracked in
[#137](https://github.com/EmilienM/wheel-crypto-scan/issues/137).

**What was rejected.** A posture per crate, `static` for `openssl-src`: that crate in
the build graph does not mean a vendored copy, and it leaves no path in the artifact to
fire on. Leaving `none` and documenting it: "no OpenSSL evidence" on a record carrying
some, when `unknown` already means what this case needs.

**What it costs.**

- The headline stays `CONDITIONAL`; `OPAQUE` and `BIN_OPENSSL_LINKAGE_UNKNOWN` join it.
- A crate-only object beside a system-linked sibling still lets the wheel read `system`,
  but the rules no longer read that alone: `DERIVED_SYSTEM_OPENSSL_ONLY` is withheld
  beside it, and a complementary rule names the object instead (see "An object that read
  `unknown` withholds `DERIVED_SYSTEM_OPENSSL_ONLY`" below).
- An SBOM component naming `openssl-sys` does not move the field. The one wheel-level
  signal linkage has is library-agnostic on purpose, and no SBOM-only wheel has been
  measured. It matters most where [#137](https://github.com/EmilienM/wheel-crypto-scan/issues/137) bites.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#an-openssl-crate-with-no-other-evidence-reads-unknown-not-none) ·
[#128](https://github.com/EmilienM/wheel-crypto-scan/issues/128)

---

## A version banner beside imports from the system library is header text, not a copy

**Fixed.**

A banner counted as `static` unconditionally, so an object whose `needed` entries
resolved OpenSSL from the host, and that imports from it, still read `mixed` if its
headers alone put the version banner in read-only data — which they do for any consumer
that includes OpenSSL's headers, whether or not it links its own copy.

```text
cryptography 50.0.0, Fedora 44 RPM, repackaged as a wheel
  needed: libcrypto.so.3, libssl.so.3, OpenSSL symbols imported, header banner, no
  OPENSSLDIR: string beside it
-> before: openssl_linkage: mixed, with BIN_OPENSSL_LINKAGE_UNKNOWN
-> after:  openssl_linkage: system, with DERIVED_SYSTEM_OPENSSL_ONLY
```

**The fix.** A banner stops counting toward `static` only when all four hold on the one
object: a `needed` entry resolved the library from the host; the object imports a symbol
from it; the object was read in full; and the library names a `copy_string_group` —
strings only a real compiled-in copy carries — that the object matches none of. For
OpenSSL, that group is `OPENSSLDIR: `, which `OpenSSL_version()` returns from the same
call as the banner, so a compiled-in copy keeps both together and a header never supplies
the second string. A defined symbol is unaffected and still makes `static` on its own.

**Why a marker and not the imports alone.** The banner-plus-imports shape alone is not
enough: a merged universal binary whose other slice carries a hidden static copy, and a
static `libcrypto` linked beside a dynamic system `libssl`, both satisfy it while
genuinely carrying a copy. Both keep the copy's build strings beside its banner only when
something in the object actually calls `OpenSSL_version()` -- the one function that
returns both. `cryptography` guarantees that call; a generic consumer does not, and can
link a static `libcrypto` whose `cversion.o` is never pulled in, carrying neither string.

**What it costs.** This moves the field in the favourable direction, which is why it
needed four independent gates rather than one. A copy whose `OpenSSL_version()` is never
called -- so its banner survives without its build strings -- reads `system`: a stripped,
hidden static `libcrypto` beside a dynamic system `libssl`, with the consumer's own
header supplying the banner, is the residual case, and it read `system` on `main` too
whenever no header banner happened to be present. A library naming no marker keeps every
banner it finds counting as a copy, unchanged. An object that is not read in full, for
any cause, keeps `mixed`.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#a-version-banner-beside-imports-from-the-system-library-is-header-text-not-a-copy)

---

## An object that read `unknown` withholds `DERIVED_SYSTEM_OPENSSL_ONLY`; the field stays `system`

**Fixed.**

`DERIVED_SYSTEM_OPENSSL_ONLY` fired whenever `openssl_linkage` resolved to `system`, but
its `why` claims every piece of OpenSSL evidence in the wheel points there -- false when
a sibling object reads `unknown` (a listed crate with nothing else, imported symbols with
no declared dependency, or an unconfirmed vendor-shaped `needed` entry), since
`_aggregate` never lets that `unknown` outvote the definite posture. In the import and
uncertain shapes, the derived rule was the *only* verdict-bearing finding on the wheel,
so withholding it alone would read `NO_CRYPTO_DETECTED` on a wheel that plainly uses
OpenSSL.

**The fix.** `linkage.object_postures` exposes the per-object tuple `_aggregate` reduces,
shared with the engine. `DERIVED_SYSTEM_OPENSSL_ONLY` takes `exclude_object_values =
["unknown"]`; a complementary rule, `DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM`, takes
`object_values = ["unknown"]` on the same match and carries `OPAQUE`, naming the object.
The two are complementary by construction: exactly one fires whenever `openssl_linkage`
is `system`. `openssl_linkage` itself never moves, and an unreadable (opaque) sibling
still leaves `DERIVED_SYSTEM_OPENSSL_ONLY` firing: `object_postures` never reports
`unknown` for an object that was not read at all.

**What it costs.** The import-only and uncertain shapes beside a system sibling move
headline `CONDITIONAL` to `OPAQUE`. The crate shape keeps its `CONDITIONAL` headline and
gains `OPAQUE`. A known residual: an SBOM component naming a crypto crate does not make
an object's own posture read `unknown`, so it changes neither rule's firing.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#an-object-that-read-unknown-withholds-derived_system_openssl_only-the-field-stays-system)
