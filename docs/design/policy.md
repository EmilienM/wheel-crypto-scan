# Policy data: what the ruleset enumerates

Entries about the shape of the data in `data/ruleset.toml` rather than about any one
reader: which lists close mechanically, which never close, and what happens when one
stops matching the world without anything failing.

## `openssl_banner` names every major digit, not the majors that shipped

**Accepted.**

A group listing `OpenSSL 3.`, `OpenSSL 1.1.` and `OpenSSL 1.0.` misses OpenSSL 4.0, and
the current PyPI wheel of the package this tool was written for compiles it in:
`cryptography` 50.0.1 carries `OpenSSL 4.0.2 25 Aug 2026` in read-only data, declares no
`DT_NEEDED` on libcrypto, and exports no OpenSSL symbol. Read through `.dynsym` and the
banner alone, the banner is the entire evidence, and with that major unlisted the wheel
comes out `openssl_linkage: none` — a wheel carrying its own OpenSSL reading exactly like
a wheel with none in it. Nothing fails while it does: the object parses, every structural
check passes, the record is clean.

**Why a digit is still required.** `OpenSSL ` alone also matches prose. That same object
carries `OpenSSL 3's legacy provider failed to load`, and so does a build that links the
system library, while a banner is one of the two things that make an object read
`static`.

**What all ten digits cost, and what they buy.** Listing 0 through 9 is one line and no
code. Measured over 18 native wheels off PyPI against the three-major list, exactly one
record differs — `cryptography` from `none` to `static` — and the other seventeen are
byte-identical.

**What was rejected.** A bounded pattern capability for `[[string_group]]`, which is the
same answer with a code change behind it: the loader refuses non-printable substrings
precisely so the strings matcher can assume no pattern spans its run separator, and a
raw pattern voids that assumption. Also rejected: a note telling the next maintainer to
add the following major when it ships — a list that depends on somebody remembering is
the failure, not the remedy.

## Two kinds of list: a field's spellings and an entity list

The ruleset's lists fall into two kinds that read alike but answer different questions.

**A field's spellings, enumerated.** These close mechanically and are silent when stale.
`nss` (`NSS 3.`) names every digit. The Windows version suffix matches the architecture
decoration as a token, not as `x64|x86|arm64|arm64ec`: four spellings of a field whose
fifth — a vendor writing `aarch64` — would leave `libcrypto-3-aarch64.dll` resolving to
no library at all. `cargo_path_regex` accepts both path separators: cryptography's
`win_amd64` `.pyd` carries 153 `cargo\registry` paths and no `cargo/registry` path, so with
one separator every Rust wheel built on Windows reads as carrying no crates at all. That
one costs more evidence than the rest together — with both separators `hf-xet` has 74
crates on Windows rather than 0, including `rustls` and `aws-lc-rs`, while all 18 Linux
records are identical either way.

**An entity list.** The crate table names `openssl-src`, `boring`, `boring-sys`, `sha-1`,
`md5`, `sha1_smol` and `sha3` alongside the rest. No pattern closes the set of crates that
exist in the world, so this list is incomplete by construction rather than stale by
neglect, and adding to it buys reach rather than closing a hole. `openssl-src` carries its
own limit in its `why`: its code runs in a build script and is not linked into the
artifact, so nobody has observed the path in a shipped wheel, and on an object with no
other OpenSSL evidence it gives `openssl_linkage: unknown`, never `static`.

**A guarantee that has to be checked to hold.** `[conventions]` says naming the Go string
groups in the ruleset means renaming a group cannot silently flip a verdict-relevant
field. The loader checks those names where it checks every other group reference: a
loader that did not would load a name no group has and leave `GoBuildInfo.boring_crypto`
false for every Go binary in the run.

**Revisit if** a `[[string_group]]` needs a match ten literals cannot spell — not on a
count of cases. A capability earns itself when the enumeration cannot express the match,
not when the list is long.

## Crates are read from every cargo source layout, and a vendored crate has no version

**Accepted, and it changes records.**

Crates are read from three cargo source layouts: the crates.io registry layout `cargo
build` uses straight from a checkout, `cargo/registry/src/<index>/<name>-<version>/`;
distro packaging, where Fedora's RPM Rust macros lay a crate out at
`/usr/share/cargo/registry/<name>-<version>/` with no `src/<index>/` segment; and
`cargo vendor` — what fromager configures for an offline build — which writes
`vendor/<name>/...` with no `cargo/registry` segment and, without `--versioned-dirs`, no
version anywhere in the path. Measured on a Fedora `python3-cryptography` build: the
object yields 14 crates, including `openssl` and `openssl-sys`.

`cargo_path_regex` treats the `src/<index>/` segment as optional, which covers the distro
layout. The vendor layout has its own convention, `cargo_vendor_path_regex`, rather than
a branch of the same pattern — Python's `re` refuses two groups sharing a name in one
alternation — and it must contain `.rs` past the crate directory (no terminator
required, since a Rust panic location is not NUL-terminated), which keeps a vendored C
or Go tree from being misread as a Rust crate in the common case, without a
word-boundary guarantee. Every repetition in both patterns is bounded (crate name at 64
characters, crates.io's own limit; path segments at 255; nesting at 16 levels for the
vendor pattern): an unbounded version of the vendor pattern measures about 40 seconds at
20,000 repetitions of a near-miss input, against well under a second bounded, and the
registry pattern is bounded the same way for the same reason. Both patterns' name
classes also exclude `.`, which no crates.io crate name can contain: that is what makes
`vendor/gimli-0.32.3/` split uniquely into name `gimli` and version `0.32.3` rather than
one long name, regardless of whether the name group is lazy or greedy, and it is why the
registry pattern reads a numeric semver prerelease like `foo-1.0.0-1.2.3` as name `foo`
rather than name `foo-1.0.0`. Allowing `.` lets the name group and the version group's
leading digits split a run of digits and dots several ways, which costs 3.7 seconds per
MiB against 0.4 without it for the vendor pattern, and 0.10-0.15 against 0.01-0.03 for
the registry pattern. Every negated character class in both patterns also excludes `\n`,
the run separator printable runs are joined with, so a match can never bridge two
strings that never sat next to each other in the object.

A `vendor/` tree inside a registry crate's own directory —
`.../bar-1.0.0/vendor/ring/src/x.rs` — is that crate's own vendored source, not a
crate of its own: it reads as `bar` 1.0.0, and the nested `ring` match is dropped. The
registry crate's directory is taken to end at its first `.rs` file rather than the end
of the printable run, since rustc packs panic locations for unrelated crates back to
back in read-only data; a `vendor/` match after that point is a separate path and is
kept. Precedence runs one way — a registry match nested inside an outer `vendor/`
directory is unaffected.

`RustCrate.version` is `str | None`: a layout that names no version records `null`,
never an invented one. That makes `rust_crates[].version` nullable in the record, which
is why `schema_version` is 2.

**What it costs.** A build whose cargo paths use none of the three layouts, such as a
git dependency checkout, carries no crate. A crate that contributes no panic location or
`assert!` message anywhere in the object is invisible whichever layout built it. No
fromager-built wheel has been measured, only a cdylib built the way fromager configures
cargo. The vendor pattern always anchors on the first `vendor/` path component: a build
tree that itself sits inside a directory named `vendor` collapses every crate nested
inside it into one crate named after that outer component, losing the real, possibly
claimed, names underneath.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#crates-are-read-from-every-cargo-source-layout-and-a-vendored-crate-has-no-version)

## A Go FIPS build is told from a stock one by its build settings

**Accepted.**

Since Go 1.24 the standard library implements its crypto on top of
`crypto/internal/fips140`, so a binary built against the validated module carries the
stock package paths exactly as a stock build does, and with nothing to suppress it would
read as `NON_APPROVED_CRYPTO`. Built one program two ways on go1.27.1: `crypto/sha256.`
appears 9 times in both, `crypto/aes.` 6 times in both, and `crypto/internal/fips140` more
often in the *stock* binary (381) than in the FIPS one (334). What separates them is
`GOFIPS140=` and `fips140=on`, which the toolchain writes into `.go.buildinfo` — an
allocated section the strings pass reads, so the verdict needs no reader change.

The verdict is `CONDITIONAL`: the module being compiled in does not mean it is in force,
since `GODEBUG=fips140` can be turned back off at run time.

The record needs `[conventions]` to name every Go group. `binaries[].go.markers` is built
from the Go group names `[conventions]` lists, so a rule on a group missing from that list
would make one record say two things — `markers: ["go_stock_crypto"]` beside a verdict of
`BIN_GO_FIPS140`, from the same strings. A test holds the two lists equal.

Full argument, with the measurements and what is deliberately left open:
[`DESIGN.md`](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md).

## A static OpenSSL's legacy primitives lead the headline

**Accepted, knowing what it costs.**

Reading `.symtab` local definitions beside a present `.dynsym` surfaces a statically
linked OpenSSL's own low-level API — `BF_*`, `MD4_*`, `SHA1_*`, `RIPEMD160_*`, and a
static OpenSSL 3's `x25519_fe51_*`/`x25519_fe64_*` field-arithmetic helpers, internal
`crypto/ec` code rather than provider entry points (those are `ossl_x25519`,
`ossl_ed25519_sign` and so on, which the group does not match; nor does 1.1.1's own
`ED25519_sign`, capitalised differently from the group's `Ed25519_` prefix) — so such a
wheel also matches `BIN_BCRYPT_BLOWFISH`, `BIN_OWN_WEAK_HASH_IMPL` and `BIN_CURVE25519`
alongside `BIN_STATIC_OPENSSL`. A bundled `libcrypto` matches `BIN_BCRYPT_BLOWFISH` and
`BIN_OWN_WEAK_HASH_IMPL` the same way, through its own `.dynsym` exports alongside
`BIN_BUNDLED_OPENSSL`, with no `.symtab` read involved; `BIN_CURVE25519`'s field helpers
are not part of libcrypto's public API, so a bundled copy matches it only if the bundle
still carries a `.symtab`. Either way `NON_APPROVED_CRYPTO` outranks the `CONDITIONAL` of
`BIN_STATIC_OPENSSL` or `BIN_BUNDLED_OPENSSL`. The taxonomy calls this correctly: a
static or bundled OpenSSL bundles those primitives and the host FIPS provider cannot
refuse them.

**What was rejected.** A narrower `binding` on the three rules, because the record has
no way to tell an exported symbol from one a version script kept local, and the names
that would need separating are OpenSSL's own. Co-occurrence-aware precedence, because it
changes what `verdict.class` means for every wheel and wants a wider corpus than the one
measured for `.symtab` local definitions.

**What it costs.** The headline for a static or bundled-OpenSSL wheel carrying any of
the three legacy groups drifts to `NON_APPROVED_CRYPTO`. `confluent-kafka` is the
measured static instance; a bundled `libcrypto` is the more common PyPI shape and hits
the same drift through ordinary `.dynsym` exports. `verdict.classes` still carries
`CONDITIONAL`, and `verdict.conditions.openssl_linkage` answers whether the wheel
carries its own OpenSSL at all -- though not, on its own, which case produced the
headline when a wheel carries both; the object's own `matched_symbols` is what tells
them apart.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-static-openssls-legacy-primitives-lead-the-headline-the-linkage-condition-says-why)

## Suppression is keyed on rule, subject and object

**Accepted.**

`suppressed_by` keys on the object a hit fired on, not the whole wheel: a suppressor on
one binary never drops a finding on a different one. Because of that, a suppressor whose
hits are located on a different kind of path than the rule it names never suppresses it,
since their hits never share a path; what a rule locates on follows its matcher kind, not
its `layer` -- most binary-layer `linkage` rules locate on the wheel path, not on the
binary they describe, so a same-layer relation naming one of them against a per-object
binary rule is just as dead as a cross-layer one. A `linkage` match with `object_values`
set is the exception: it locates per object instead, so a relation naming that rule
against a per-object binary rule on the same object does suppress. The loader accepts
either shape without complaint, so check what each side locates on rather than which
layer or matcher kind alone promises.

A `[[rust_crate]]` entry can also carry its own `suppressed_by`, naming another crate
entry, so two subjects of the same rule -- `aws-lc-rs` and its FIPS build
`aws-lc-fips-sys` -- can relate the way two whole rules can; no other table reads
entry-level `suppressed_by`, and the loader refuses it there. Only the `rust_crate`
matcher honours it, though: `sbom_component` takes a component's verdict from the same
`[[rust_crate]]` entry but not its `suppressed_by`, so an SBOM naming both aws-lc-rs and
aws-lc-fips-sys still reports both, an accepted over-flag. Suppression is
non-cascading, and the loader refuses a `suppressed_by` cycle across rules and crates,
including one closed by an ownerless crate, rather than silently dropping every member
of one.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#suppression-is-keyed-on-rule-subject-and-object),
including why `aws-lc-sys` and `rustls` get no such relation, and why the SBOM gap is left
as an accepted over-flag.

## An AWS-LC FIPS build is told from a stock one by its symbol prefix

**Accepted.**

`aws_lc` matches `AWS-LC` and `aws-lc` in read-only data, and lowercase `aws-lc` also
matches the cargo path of either AWS-LC crate, so `BIN_AWS_LC` alone cannot tell the
validated build from the stock one. Built one program two ways on linux/x86_64 with
`aws-lc-rs` 1.18.1: the FIPS build (`aws-lc-fips-sys` 0.14.2) carries 2118 local
`aws_lc_fips_0_14_2_*` names in `.symtab` and the stock build (`aws-lc-sys` 0.45.0)
carries none. The version string is not the answer on ELF: AWS-LC's FIPS build moves its
constants into `.text` so its integrity hash covers them, and the strings pass reads only
non-executable sections, so `AWS-LC FIPS 4.2.0` sits somewhere this tool never reads on
this format. A stripped object loses the symbol prefix too and reads as stock AWS-LC,
which is the over-flag direction this tool errs in.

The verdict is `CONDITIONAL`, the same reasoning as the Go entry above: the module being
compiled in is not the same as it being in force, and which certificate covers the
compiled version is not something the wheel states.

`aws-lc-rs`'s own crate finding needs a rule of its own to be suppressible: on the
default crate rule, alongside every crate suppression cannot reach, a FIPS build's
`aws-lc-rs` cargo path (present on every measured build, FIPS or stock) keeps
`NON_APPROVED_CRYPTO` in the record even once the FIPS condition is identified.
`aws-lc-sys` stays on the default rule, since it names the stock build specifically.

`CONDITIONAL` is reached whenever the FIPS build is identified and the object defines no
non-approved primitive of its own; the cargo path being the object's sole evidence is one
way to reach it, not the only one. No real build measured here does, though: a stripped
object loses the symbol prefix, so `BIN_AWS_LC_FIPS` never fires and `BIN_AWS_LC` names it
as stock, and an unstripped one fires `BIN_AWS_LC_FIPS` correctly but still reads
`NON_APPROVED_CRYPTO`, because `curve25519_x25519` and `md5_final` are the FIPS module's
own primitive implementations, which is exactly what that class is defined to catch,
condition or not.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#an-aws-lc-fips-build-is-told-from-a-stock-one-by-its-symbol-prefix-not-its-name)
