# OpenSSL linkage

`linkage.py` answers the question the tool exists for: does this wheel use the system
OpenSSL, or does it carry its own? The first two entries below are about
`_binary_posture`, the function that reads one object's own evidence, and both cover
several object shapes the plain rule does not resolve on its own. The third is about the
weakest evidence it reads: a Rust crate name, which can say `unknown` and nothing more.
The fourth is back on `_binary_posture`: a version banner the object's headers put there
is not a copy. The fifth is about the rule that says an object's evidence all points at
the system library, and what it needs to know about the wheel's other objects to say so.
The last is about the same weak claim as the third, made a second way: the wheel's own
SBOM naming the library or such a crate.

## A `needed` entry is bundled by what it resolves to, not by whether its name was renamed

**Accepted, and it changes `openssl_linkage` and one finding.**

Keyed on the name alone, a base name in a crypto library's `sonames` is `bundled` only
when the name itself carries a content hash (`libcrypto-3a1f2b4c.so.3`), otherwise
`system`. That is exactly what auditwheel and delvewheel produce, and it is not what
delocate produces. delocate copies a dependency into `.dylibs/` and rewrites the load
command to point there — `@loader_path/.dylibs/libcrypto.3.dylib` — **without renaming the
file**.

```text
pkg/_ext.cpython-312-darwin.so   needed: @loader_path/.dylibs/libcrypto.3.dylib
pkg/.dylibs/libcrypto.3.dylib    vendored_path: true, defines EVP_DigestInit_ex, SSL_new
-> by name alone: openssl_linkage: mixed, BIN_OPENSSL_LINKAGE_UNKNOWN, BIN_NEEDED_SYSTEM_OPENSSL
-> by resolution: openssl_linkage: bundled, BIN_BUNDLED_OPENSSL
```

By name alone that is two postures for one OpenSSL, with "could not be resolved" and
"links the system OpenSSL" both firing — wrong on every count. The same shape reaches ELF
too: nothing stops a build placing an unmangled dependency beside the extension with
`RUNPATH $ORIGIN`.

**Two parts, matched to the two ways a `needed` entry can prove it names a file
the wheel ships.** `Conventions.raw_stem` reduces a name the way `own_base` does but stops
short of undoing a content-hash rename; `linkage.member_stem_counts` counts every object's
`raw_stem` across the wheel, and a `needed` entry whose own `raw_stem` some other object
answers to is `bundled`, mangled or not. Second, `_looks_vendored` reads the `needed`
string itself and, for `@rpath`-relative names, the object's own `LC_RPATH` list — a weaker
signal used only as a backstop that never asserts `bundled` by itself.

**Why the path-convention half is capped at `unknown`, never `bundled`.** A `needed` entry
can look exactly like delocate's convention and still name nothing the wheel actually ships.
Letting the shape alone promote to `bundled` would manufacture the same overconfidence,
aimed the other way.

**A residual: basename, not directory.** `member_stem_counts` matches on file identity
alone, not on directory, so two different libraries sharing a basename in one wheel would
let an unrelated `needed` entry read as `bundled`. Resolving that precisely needs walking
the actual search path, a meaningfully bigger mechanism. Recorded rather than closed,
because the failure direction — reading `system` as `bundled` — is the safe one for a
FIPS-risk tool.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-needed-entry-is-bundled-by-what-it-resolves-to-not-by-whether-its-name-was-renamed)

### What resolving by basename does not prove

**Accepted, and it changes `openssl_linkage`.** Resolving a `needed` entry by basename
alone proves less than it first appears to. A 150-shape differential matrix over real and
synthetic wheels finds two claims weaker than they read: that a false `bundled` needs a
second object under the same name, and that `_looks_vendored`'s path handling stays
confined to a narrower case.

**A false `bundled` from basename alone does not need a second file; a single object can
match itself** — no vendor directory, no second file, whose own file name reduces to the
same stem as an absolute, genuinely-system dependency it declares:

```text
fakecrypto/libcrypto.so   soname: libcrypto.so
                          needed: /usr/lib64/libcrypto.so.3, libc.so.6
-> without an own-stem discount: openssl_linkage: bundled, verdict.class: NO_CRYPTO_DETECTED,
                                  rule_ids: [], needs_human_review: false
```

Counting the querying object itself lets the object answer its own question. Worse than a
wrong posture, that `bundled` has **no rule behind it** unless one claims it: resolution is
a third route to `bundled`, beside a vendored member's own record and a literal hash rename.

Two parts. The stems are counted (`member_stem_counts`, a `Counter`), and
`_resolves_within_wheel` discounts an object's own contribution to its own answer. And a
rule, `BIN_NEEDED_VENDORED_CRYPTO`, claims this third route the same way the other two are
claimed, so the residual imprecision the two-file case allows is never silent:
`needs_human_review` is true even when the `bundled` classification is a false positive from
the coincidence.

**`_looks_vendored` needs a gate.** Unguarded, it fires whenever the object has *any*
vendor-shaped search path, independent of whether the specific `needed` entry could
plausibly resolve under it. The matrix finds this misreading a genuine system dependency as
`unknown` on 11 of 150 shapes — a FIPS-conscious build running auditwheel's
`--exclude libcrypto.so.3` while vendoring an unrelated library, say libjpeg, in the same
wheel.

`wheel_incompletely_read(evidence)` is the gate: true only when some member never became a
`BinaryEvidence` at all. `_looks_vendored` is consulted only when that holds; when the wheel
was read in full, a vendor-shaped path naming nothing is genuine `system`, because **a
complete member list that does not contain the answer is itself the answer.**

### How `_looks_vendored` is gated, and what pins it

Two more shapes the gate above must not miss:

**The vendor-shape check inside the gate is pinned by its own test.** With the gate pinned
in both directions, mutating `_looks_vendored` to unconditionally `return True` would still
leave a suite green that pins only the gate; the test that fails is
`test_a_plain_dependency_stays_system_even_in_an_incompletely_read_wheel`, which pins the
shape check *inside* the gate.

**`wheel_incompletely_read` checks `artifacts.symlinks` too.** A vendored library shipped as
a symlink — ordinary practice for a versioned `.so`/`.dylib` — is never read as a binary at
all, and records neither a skipped entry nor an error:

```text
demo/_ext.abi3.so               needed: @loader_path/.dylibs/libcrypto.3.dylib
demo/.dylibs/libcrypto.3.dylib  -> a symlink, never read as a binary at all
-> without checking artifacts.symlinks: openssl_linkage: system, BIN_NEEDED_SYSTEM_OPENSSL, DERIVED_SYSTEM_OPENSSL_ONLY
```

Both finding descriptions would be affirmatively wrong here: an `@loader_path`-anchored load
command is wheel-internal by construction and can never be the host's system OpenSSL.
`needs_human_review` is true either way, so this is never silent, but it would be
confidently wrong rather than honestly uncertain, which is the distinction this whole entry
exists to draw.

**Every `bundled` has a rule, by enumeration.** Every `bundled` posture `_binary_posture`
can produce has a rule behind it, audited one branch at a time. But `system` has an
aggregate-level backstop that no per-mechanism enumeration needs to keep in step, and
`bundled` does not: nothing would notice if a fourth mechanism were added without a fourth
rule. The cheap close is a behavioural invariant test asserting that no definite
`openssl_linkage` value reaches the record without a contributing rule having fired. It costs
nothing and is worth adding regardless.

### An absolute `needed` entry is never resolved by basename

**Accepted, and it changes `openssl_linkage`, for one shape.** The basename residual above
accepts that a collision between two unrelated objects could manufacture a false
`bundled`. That is not so when the colliding `needed` entry is an absolute path
(`/usr/lib64/libcrypto.so.3`): no real dynamic loader resolves an absolute path against
anything the wheel ships, so `needed_posture` answers `system` for it outright, before
consulting the basename match or the vendor-shape check at all. The residual stays open for
a *relative* entry that a loader genuinely could resolve via `$ORIGIN`/`@rpath`/`RPATH`/
`RUNPATH` — the ordinary vendoring shape this whole entry is about — and, narrower still,
for a relative-but-non-wheel-resolvable shape like `../../hostlib/libcrypto.so.3` or a
Mach-O `@executable_path/...` entry, neither of which this check covers even though the same
argument applies to them.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#an-absolute-needed-entry-is-never-resolved-by-basename)

---

## A `needed` match and a definition inside one object are both true, so the object is `mixed`

**Accepted, and it changes `openssl_linkage`. The precedence question the entry above
deliberately leaves open.**

Returning `system` as soon as one `needed` entry resolves to the system library, before the
defined-symbol and banner check runs, would read `system` for an object that both declares
`DT_NEEDED libssl.so.3` and defines `EVP_DigestInit_ex` — or carries an OpenSSL version
banner, which a version script cannot hide — and the record would pair "every piece of
OpenSSL evidence points at the system library" with "OpenSSL was compiled into it" in the
same `rule_ids` list. A contradiction in the favourable direction.

```text
demo/_ext.so   needed: libc.so.6, libssl.so.3
               defines EVP_DigestInit_ex, rodata: "OpenSSL 3.0.14 4 Jun 2024"
-> needed checked first, alone: openssl_linkage: system, with DERIVED_SYSTEM_OPENSSL_ONLY
-> needed and defined/banner together: openssl_linkage: mixed, with
   BIN_OPENSSL_LINKAGE_UNKNOWN and no DERIVED_SYSTEM_OPENSSL_ONLY
```

**The decision: `mixed`, not `static`-wins.** Both facts are independently true and
independently reportable — a real `DT_NEEDED` entry names the system library, and a real
symbol, or a banner that is not header text (see
[the entry on header banners](#a-version-banner-beside-imports-from-the-system-library-is-header-text-not-a-copy)),
shows the object also carries its own copy. `static`-wins would suppress the `needed`
evidence from the field most consumers filter on, which would then say `static`
about an object that also, genuinely, links the system library. `mixed` costs no schema
change: the value exists for the cross-object case.

**What it costs.** `BIN_OPENSSL_LINKAGE_UNKNOWN` also fires for this shape, and its own
`why` — "the wheel calls OpenSSL without declaring a dependency on it, or the only evidence
came from an object we could not read" — describes neither: here the dependency *is* declared
and the object *was* read in full. Left as is rather than reworded, because rewording it
correctly means splitting what are two different reasons `mixed` can fire.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-needed-match-and-a-definition-inside-one-object-are-both-true-so-the-object-is-mixed)

### An `uncertain` needed match beside a definition is `mixed`

`_binary_posture` must not return `unknown` for the `uncertain` case — a `needed` entry
whose shape looks vendor-directed but that an incompletely-read wheel cannot confirm —
before the defined/banner check runs. An object with both an unconfirmed vendor-shaped
entry and a confirmed static definition would otherwise read `unknown`, silently
discarding the confirmed evidence in favour of the unconfirmed one.

```text
demo/_ext.so  needed: libcrypto.so.3, RUNPATH: $ORIGIN/../p.libs (names nothing shipped,
              wheel incompletely read), defines EVP_DigestInit_ex
-> uncertain checked alone: openssl_linkage: unknown
-> uncertain and definite together: openssl_linkage: mixed
```

**Precedence.** What makes a confirmed entry beat an unconfirmed one is not where the
branch sits in isolation: it is that `if uncertain: return unknown` sits *below*
`if system:` in the ladder, applying within one object the same rule the aggregate applies
across objects — a non-definite posture never outvotes a definite one already present.
Moving the branch changes nothing the test suite can observe, confirmed by mutation.

The three-way case collapses into the two-way branch before `uncertain` is ever consulted,
and that collapse is provable rather than merely observed: the two conditions can only be
true together when `system` is also true, and both branches return the same value.

**What it costs.** This widens `mixed` one object beyond the one it fires on. A wheel
with one object reading `bundled` and a second reading `mixed` aggregates to `mixed`
rather than `bundled`, dropping out of the `IN("bundled","static")` triage recipe. The
direction stays conservative — the wheel gains `OPAQUE` rather than losing anything silently.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#an-uncertain-needed-match-beside-a-definition-is-mixed)

### A bundled needed match beside `system` or `static` is `mixed`

The `needed` loop must not return `bundled` immediately, from inside the loop, before a
second disagreeing entry or the defined/banner check runs. A universal Mach-O merges its
slices' `needed` tuples into one, so an object whose slices disagree about `bundled`
versus `system` would read `bundled` outright, unlike the same evidence read as two
separate objects.

```text
one object, needed=("libcrypto-3a1f2b4c.so.3", "/usr/lib64/libcrypto.so.3")
  -> bundled checked alone: bundled   -> both checked together: mixed
same evidence in two separate objects -> mixed, either way
```

**How the loop works.** It does not return from inside itself. It accumulates `system`,
`bundled` and `uncertain` across the whole `needed` tuple before branching, and the
disagreement check is a three-way count: `sum((system, bundled, static)) > 1` is `mixed`.

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

Milder than a `system` read beside a definition — nothing reads clean, and
`needs_human_review` is true — but the same family. Left open on scope discipline, not on
cost: the extra checks are cheap, the early return is a genuinely different code path, and
folding it in would extend an already-large precedence mechanism further than this entry's
own reproductions ask for.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-bundled-needed-match-beside-system-or-static-is-mixed)

---

## An OpenSSL crate with no other evidence reads `unknown`, not `none`

**Accepted, and it changes `openssl_linkage`.**

An object read in full whose only OpenSSL evidence is a crate name (`openssl-sys`,
`openssl`, `openssl-src`) would otherwise read `openssl_linkage: none` beside a
`CONDITIONAL` crate finding: "no OpenSSL evidence" on a record carrying some.

**How it reads a crate.** `[[crypto_library]]` has `crates`, validated against
`[[rust_crate]]` at load time. An object carrying a listed crate and nothing else
`_binary_posture` reads gives `unknown`, the answer imported OpenSSL symbols with no declared
dependency get, for the same reason: something uses OpenSSL, and the object does not say
which copy.

**Never a definite posture.** The branch fires only on an object with no OpenSSL
`needed` entry, symbol or banner, which is more likely a static copy, but only as far as
the readers left nothing open. And the crate cannot settle it: `OPENSSL_NO_VENDOR` sends
even a `vendored` `openssl-sys` build back to the host's OpenSSL. One crate, built both
ways:

```text
cryptography 50.0.1 off PyPI (manylinux, macOS, Windows)
  crates: openssl, openssl-sys   banner "OpenSSL 4.0.2 25 Aug 2026"          -> static
cryptography 50.0.0, Fedora 44 RPM, repackaged as a wheel
  needed: libcrypto.so.3, libssl.so.3   crates: openssl, openssl-sys       -> system
```

Same crate, two postures, so the crate check sits below every other one and its `unknown`
never outvotes a definite posture elsewhere in the wheel. None of the four records depend on
it. The Windows `.pyd` shows what does: its banner is its only OpenSSL evidence, and with
`openssl_banner` restricted to `3.`, `1.1.` and `1.0.`, it would read `none` without the
crate check; with it, `unknown`. The Fedora row's crates come from the distro
cargo-path layout, and its imports from the system library answer first.

**What was rejected.** A posture per crate, `static` for `openssl-src`: that crate in
the build graph does not mean a vendored copy, and it leaves no path in the artifact to
fire on. Leaving `none` and documenting it: "no OpenSSL evidence" on a record carrying
some, when `unknown` already means what this case needs.

**What it costs.**

- The headline stays `CONDITIONAL`; `OPAQUE` and `BIN_OPENSSL_LINKAGE_UNKNOWN` join it.
- A crate-only object beside a system-linked sibling still lets the wheel read `system`,
  but the rules do not read that alone: `DERIVED_SYSTEM_OPENSSL_ONLY` is withheld beside
  it, and a complementary rule names the object instead (see "An object that read
  `unknown` withholds `DERIVED_SYSTEM_OPENSSL_ONLY`" below).
- An SBOM component naming `openssl-sys` moves the field the same way a crate does: see
  the last entry on this page.
- A build whose cargo paths use a layout the reader does not recognise, such as a git
  dependency checkout, carries no crate, so the crate check never fires on it.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#an-openssl-crate-with-no-other-evidence-reads-unknown-not-none)

---

## A version banner beside imports from the system library is header text, not a copy

**Accepted, and it changes `openssl_linkage`.**

Any consumer that includes OpenSSL's headers puts the version banner in read-only data,
whether or not it links its own copy. Counted as `static` unconditionally, that banner
makes an object whose `needed` entries resolve OpenSSL from the host, and that imports
from it, read `mixed`.

```text
cryptography 50.0.0, Fedora 44 RPM, repackaged as a wheel
  needed: libcrypto.so.3, libssl.so.3, OpenSSL symbols imported, header banner, no
  OPENSSLDIR: string beside it
-> every banner a copy:      openssl_linkage: mixed, with BIN_OPENSSL_LINKAGE_UNKNOWN
-> header banner told apart: openssl_linkage: system, with DERIVED_SYSTEM_OPENSSL_ONLY
```

**How a header banner is told apart.** A banner does not count toward `static` when all
four hold on the one object: a `needed` entry resolved the library from the host; the
object imports a symbol from it; the object was read in full; and the library names a
`copy_string_group` — strings only a real compiled-in copy carries — that the object
matches none of. For OpenSSL, that group is `OPENSSLDIR: `, which `OpenSSL_version()`
returns from the same call as the banner, so a compiled-in copy keeps both together and a
header never supplies the second string. A defined symbol is unaffected and still makes
`static` on its own.

**Why a marker and not the imports alone.** The banner-plus-imports shape alone is not
enough: a merged universal binary whose other slice carries a hidden static copy, and a
static `libcrypto` linked beside a dynamic system `libssl`, both satisfy it while
genuinely carrying a copy. Both keep the copy's build strings beside its banner only when
something in the object actually calls `OpenSSL_version()` -- the one function that
returns both. `cryptography` guarantees that call; a generic consumer does not, and can
link a static `libcrypto` whose `cversion.o` is never pulled in, carrying neither string.

**What it costs.** This moves the field in the favourable direction, which is why it
takes four independent gates rather than one. A copy whose `OpenSSL_version()` is never
called -- so its banner survives without its build strings -- reads `system`: a stripped,
hidden static `libcrypto` beside a dynamic system `libssl`, with the consumer's own
header supplying the banner, is the residual case, and the same object with no header
banner reads `system` whatever the banner rule does. A library naming no marker counts
every banner it finds as a copy. An object that is not read in full, for any cause,
keeps `mixed`.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-version-banner-beside-imports-from-the-system-library-is-header-text-not-a-copy)

---

## An object that read `unknown` withholds `DERIVED_SYSTEM_OPENSSL_ONLY`; the field stays `system`

**Accepted, and it changes verdicts.**

`DERIVED_SYSTEM_OPENSSL_ONLY`'s `why` claims every piece of OpenSSL evidence in the wheel
points at the system library -- false when a sibling object reads `unknown` (a listed
crate with nothing else, imported symbols with no declared dependency, or an unconfirmed
vendor-shaped `needed` entry), even though `_aggregate` never lets that `unknown` outvote
the definite posture and the field reads `system`. In the import and uncertain shapes,
the derived rule would be the *only* verdict-bearing finding on the wheel, so withholding
it alone would read `NO_CRYPTO_DETECTED` on a wheel that plainly uses OpenSSL.

**How the rules read per-object postures.** `linkage.object_postures` exposes the
per-object tuple `_aggregate` reduces, shared with the engine.
`DERIVED_SYSTEM_OPENSSL_ONLY` takes `exclude_object_values = ["unknown"]`; a
complementary rule, `DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM`, takes `object_values =
["unknown"]` on the same match and carries `OPAQUE`, naming the object. The two are
complementary by construction: exactly one fires whenever `openssl_linkage` is `system`.
`openssl_linkage` itself never moves, and an unreadable (opaque) sibling still leaves
`DERIVED_SYSTEM_OPENSSL_ONLY` firing: `object_postures` never reports `unknown` for an
object that was not read at all.

**What it costs.** The import-only and uncertain shapes beside a system sibling read an
`OPAQUE` headline rather than `CONDITIONAL`. The crate shape keeps its `CONDITIONAL`
headline and gains `OPAQUE`. A known residual: an SBOM component naming a crypto crate
does not make an object's own posture read `unknown`, so it changes neither rule's
firing.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#an-object-that-read-unknown-withholds-derived_system_openssl_only-the-field-stays-system)

---

## An SBOM naming an OpenSSL crate reads `unknown`, not `none`

**Accepted, and it changes `openssl_linkage`.**

A wheel's own PEP 770 SBOM naming `openssl-sys` is the same claim the crate check reads
from cargo paths, and it gets the same answer: `unknown` in place of `none`.

`resolve_linkage` has a second wheel-level signal, `_declared_by_sbom`, consulted only
where `_left_unanswered` is: after every object's own evidence has been checked and none
of it was definite. Unlike `_left_unanswered`, it is not gated on `always_report`,
because it is about the specific library named, not about the wheel as a whole. It
matches an SBOM component whose name equals a library's own name or one of its `crates`
— the same names `SBOM_CRYPTO_COMPONENT` reports a finding for — and, like a crate, never
gives a definite posture, only `unknown` in place of `none`. Where the library's own name
also names an unrelated `[[rust_crate]]` the library does not list in `crates`
(`argon2`, `blake2`), the component's own `purl` decides instead of the name alone: only
a `pkg:cargo/...` purl reads as the crate and leaves the C library's field untouched; any
other purl, or none, moves it.

**What was rejected.** Two simpler alternatives. Matching by name alone, whatever the
purl, gives a false positive: a component naming the pure-Rust crate under
`pkg:cargo/argon2@...` would move the C library's field when nothing says the C library
is present. Skipping the name arm on every colliding name, whatever the purl, gives the
opposite failure: a component that really does name the C library under a non-cargo
purl, or none, would leave `SBOM_CRYPTO_COMPONENT` firing with no field beside it.

The loader refuses a ruleset whose `sbom_component` rules do not, between them, report
through both the `crypto_library` and `rust_crate` tables this signal reads names from,
and refuses `suppressed_by` on a rule relied on for that coverage, so neither a coverage
gap nor a suppressed finding can silently break the agreement between the field and the
finding.

**What it costs.** A known residual, the same one the withholding entry above carries:
`DERIVED_SYSTEM_OPENSSL_ONLY`'s `exclude_object_values` reads the per-object tuple
`object_postures` exposes, and this signal is wheel-level, so an SBOM naming an OpenSSL
crate beside a system-linked object fires `DERIVED_SYSTEM_OPENSSL_ONLY` outright rather
than the complementary, `OPAQUE`-carrying rule.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#an-sbom-naming-an-openssl-crate-reads-unknown-not-none)
