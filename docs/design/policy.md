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
system library. Requiring a digit and a dot rules that undotted string out, but not a
sentence naming a *dotted* version — "enable OpenSSL 3.0 legacy provider" still matches.
What keeps that from reading `static` is the copy marker, not the shape of the string:
see [the entry on an uncorroborated banner](linkage.md#a-version-banner-with-no-dependency-and-no-build-strings-reads-unknown-not-static).

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

Crates are read from four cargo source layouts: the crates.io registry layout `cargo
build` uses straight from a checkout, `cargo/registry/src/<index>/<name>-<version>/`;
distro packaging, where Fedora's RPM Rust macros lay a crate out at
`/usr/share/cargo/registry/<name>-<version>/` with no `src/<index>/` segment; `cargo
vendor` — what fromager configures for an offline build — which writes
`vendor/<name>/...` with no `cargo/registry` segment and, without `--versioned-dirs`, no
version anywhere in the path; and a git dependency checkout,
`$CARGO_HOME/git/checkouts/<repo>-<16 hex hash>/<short rev>/...`, cargo's layout for a
crate pinned by a git revision. Measured on a Fedora `python3-cryptography` build: the
object yields 14 crates, including `openssl` and `openssl-sys`. Measured for the git
layout (cargo 1.98.1): a cdylib built from git dependencies on `rust-base64` and
`hashes` (the `sha2` crate's repository) embeds paths like
`.../git/checkouts/rust-base64-9af66aca7bf9fca2/5b98ee1/src/engine/mod.rs`; `CARGO_HOME`
is arbitrary (a custom directory here, `/usr/local/cargo` in the Rust Docker images), so
the pattern anchors on `git/checkouts/`, not `cargo/git/checkouts/`.

`cargo_path_regex` treats the `src/<index>/` segment as optional, which covers the distro
layout. The vendor and git-checkout layouts each have their own convention,
`cargo_vendor_path_regex` and `cargo_git_path_regex`, rather than a branch of the
registry pattern — Python's `re` refuses two groups sharing a name in one alternation —
and both must contain `.rs` past the crate directory (no terminator required, since a
Rust panic location is not NUL-terminated), which keeps a vendored or checked-out C or
Go tree from being misread as a Rust crate in the common case, without a word-boundary
guarantee. Every repetition in both is bounded (crate name at 64 characters, path
segments at 255, nesting at 16 levels): an unbounded version of the vendor pattern
measures about 40 seconds at 20,000 repetitions of a near-miss input, against well
under a second bounded. A repository/hash near-miss and a member-directory near-miss
stay under a second for the git-checkout pattern either way, bounded or not, at
comparable sizes; a run of literal `src/` segments ahead of a non-matching tail does
reach the bound that matters, since `src/` is itself a candidate for the pattern's
required anchor at every repetition — bounded, that shape runs in milliseconds;
unbounded, it takes on the order of ten seconds at 50 repetitions of 40 `src/`
segments. The vendor pattern's name class also excludes `.`, which
no crates.io crate name can contain: that is what makes `vendor/gimli-0.32.3/` split
uniquely into name `gimli` and version `0.32.3` rather than one long name, regardless of
whether the name group is lazy or greedy. Allowing `.` lets the name group and the
version group's leading digits split a run of digits and dots several ways, which costs
3.7 seconds per MiB against 0.4 without it. A git checkout names no version at all — a
revision, not a version — so `cargo_git_path_regex`'s `version` group is declared but can
never participate, the same way it is for a crate named literally without one. The
checkout directory is named after the repository, not any one crate inside it: a
workspace member's own directory, immediately above its `src/`, is read as the crate
name (`rust-openssl` holds `openssl-sys`); a root crate with no member directory of its
own (`ring`) is read under its repository's name instead.

A `vendor/` tree inside a registry crate's own directory —
`.../bar-1.0.0/vendor/ring/src/x.rs` — is that crate's own vendored source, not a
crate of its own: it reads as `bar` 1.0.0, and the nested `ring` match is dropped. The
registry crate's directory is taken to end at its first `.rs` file rather than the end
of the printable run, since rustc packs panic locations for unrelated crates back to
back in read-only data; a `vendor/` match after that point is a separate path and is
kept. Precedence runs one way — a registry match nested inside an outer `vendor/`
directory is unaffected. A `vendor/` tree inside a git-checkout workspace member is not
given the same precedence: `cargo_git_path_regex`'s own `name` group already reads the
directory immediately above `src/`, so it agrees with `cargo_vendor_path_regex` on the
same crate without needing one pattern to defer to the other.

`RustCrate.version` is `str | None`: a layout that names no version records `null`,
never an invented one. That makes `rust_crates[].version` nullable in the record, which
is why `schema_version` is 2.

**What it costs.** A crate that contributes no panic location or `assert!` message
anywhere in the object is invisible whichever layout built it. No fromager-built wheel
has been measured, only cdylibs built the way fromager configures cargo for the
registry and vendor layouts, and by hand for the git-checkout layout. A root crate read
from a git checkout carries its repository's name rather than its own whenever the two
differ (`rust-base64`, not `base64`), and a workspace member's directory name is
conventionally, but not necessarily, the crate it holds. The vendor pattern always
anchors on the first `vendor/` path component: a build tree that itself sits inside a
directory named `vendor` collapses every crate nested inside it into one crate named
after that outer component, losing the real, possibly
claimed, names underneath. A `vendor/` tree inside a git-checkout workspace member is
unaffected, since `cargo_vendor_path_regex` matches on its own `vendor/` component
regardless of what layout surrounds it.

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
linked OpenSSL's own low-level API — `BF_*`, `MD4_*`, `SHA1_*`, `RIPEMD160_*`, and its
Curve25519 entry points: 1.1.1's `X25519`/`ED25519_*`, 3.x's
`ossl_x25519`/`ossl_ed25519_*` provider names, and both versions' internal `crypto/ec`
`x25519_fe51_*`/`x25519_fe64_*` field-arithmetic helpers (present only where the build
includes the assembly path, not provider entry points) — so such a wheel also matches
`BIN_BCRYPT_BLOWFISH`, `BIN_OWN_WEAK_HASH_IMPL` and `BIN_CURVE25519` alongside
`BIN_STATIC_OPENSSL`. A bundled `libcrypto` matches `BIN_BCRYPT_BLOWFISH` and
`BIN_OWN_WEAK_HASH_IMPL` the same way, through its own `.dynsym` exports alongside
`BIN_BUNDLED_OPENSSL`, with no `.symtab` read involved; none of `BIN_CURVE25519`'s
OpenSSL names is part of libcrypto's public API, so a bundled copy matches it only if
the bundle still carries a `.symtab`. Either way `NON_APPROVED_CRYPTO` outranks the
`CONDITIONAL` of `BIN_STATIC_OPENSSL` or
`BIN_BUNDLED_OPENSSL`. The taxonomy calls this correctly: a static or bundled OpenSSL
bundles those primitives and the host FIPS provider cannot refuse them.

An import of these same names -- `BF_encrypt` called through a linked library rather
than defined by the wheel -- neither implements nor bundles Blowfish, so it does not
match `BIN_BCRYPT_BLOWFISH` and does not read `NON_APPROVED_CRYPTO`. It still carries a
class, through `BIN_BCRYPT_BLOWFISH_IMPORTED` at `CONDITIONAL`, so a Blowfish import
against a library other than OpenSSL never reads `NO_CRYPTO_DETECTED`. OpenSSL's
low-level `BF_` API bypasses its provider mechanism, which is why the import goes to a
human rather than being called acceptable.

**What was rejected.** A narrower `binding` on the three rules, because the record has
no way to tell an exported symbol from one a version script kept local, and the names
that would need separating are OpenSSL's own. Co-occurrence-aware precedence, because it
changes what `verdict.class` means for every wheel and wants a wider corpus than the one
measured for `.symtab` local definitions. Dropping the field helpers' reach, because
they match through the same generic `x25519_` prefix as every other lowercase
Curve25519 implementation, so narrowing that prefix to exclude OpenSSL's own would
also drop the group's hits on those other implementations, leaving every static
OpenSSL, with or without the assembly path, consistently silent about a primitive it
still bundles.

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
one binary never drops a finding on a different one. What a rule locates on follows its
matcher kind, not its `layer`, so a same-layer relation between two kinds that never
share a path is refused at load time exactly like a cross-layer one -- a `linkage` match
with `object_values` set is the one exception, since it locates per object rather than by
its kind alone. `MATCHER_LOCATIONS` in `ruleset.py` is the one declaration of which class
of path each matcher kind locates on, and the loader refuses any relation between two
rules that can never share one.

A `[[rust_crate]]` entry can also carry its own `suppressed_by`, naming another crate
entry, so two crates that stay on one rule can relate; no other table reads entry-level
`suppressed_by`, and the loader refuses it there. No shipped entry carries one: the
AWS-LC relation is rule-level instead, `aws-lc-rs` and `aws-lc-fips-sys` each routed to
a rule of their own, and the former naming the latter in its rule-level `suppressed_by`.
`sbom_component` honours both the entry- and rule-level relations too, keyed on the SBOM
document as the object, so an SBOM naming both crates in one document reports only
the FIPS build's finding. SBOM and binary evidence never suppress each other, because
they never share a path, which is the accepted over-flag that remains: an SBOM naming
`aws-lc-rs` beside a FIPS binary object still reports both. Suppression is
non-cascading, and the loader refuses a `suppressed_by` cycle across rules and crates,
including one closed by an ownerless crate, rather than silently dropping every member
of one.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#suppression-is-keyed-on-rule-subject-and-object),
including why `aws-lc-sys` and `rustls` are not suppressed, and why the cross-source
over-flag is accepted.

## An AWS-LC FIPS build is told from a stock one by its symbol prefix

**Accepted.**

`aws_lc` matches `AWS-LC` and `aws-lc` in read-only data, and lowercase `aws-lc` also
matches the cargo path of either AWS-LC crate, so `BIN_AWS_LC` alone cannot tell the
validated build from the stock one. Built one program two ways on linux/x86_64 with
`aws-lc-rs` 1.18.1: the FIPS build (`aws-lc-fips-sys` 0.14.2) carries 2118 local
`aws_lc_fips_0_14_2_*` names in `.symtab` and the stock build (`aws-lc-sys` 0.45.0)
carries none. AWS-LC's FIPS build moves its constants, including the version string,
into `.text` so its integrity hash covers them: `AWS-LC FIPS 4.2.0` sits at file offset
`0x8ae5c`. ELF searches executable sections for the one string group that asks to be
found there, so a stripped object -- the shape a release wheel usually ships as, and the
one that loses the symbol prefix above -- is still identified by the version string
alone; every other string group stays read-only-data-only.

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
way to reach it, not the only one, and an SBOM naming both `aws-lc-rs` and
`aws-lc-fips-sys` in the same document reads the same way. A stripped object reaches it in
full: `.symtab` is gone either way, so `curve25519_x25519` and `md5_final` -- the FIPS
module's own primitive implementations, defined only there -- were never reachable on a
stripped object to begin with, and the version string in `.text` is what identifies the
build once the symbol prefix is gone with it. An unstripped one still fires
`BIN_AWS_LC_FIPS` but keeps `NON_APPROVED_CRYPTO`, because those two symbols are exactly
what that class is defined to catch, condition or not.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#an-aws-lc-fips-build-is-told-from-a-stock-one-by-its-symbol-prefix-not-its-name)

## A BoringSSL FIPS module is told from a stock build by its integrity test

**Accepted.**

`boringssl` matches `BoringSSL` in read-only data, but a stripped stock BoringSSL object
(measured on `grpcio`'s `cygrpc` extension) carries that string, `BoringCrypto` and
`FIPS self test` too, so none of them tell a validated BoringCrypto build apart.
`BORINGSSL_integrity_test`, the FIPS module's power-on self-test entry point, does:
upstream compiles it only into a FIPS build without ASAN, and it is a local `.symtab`
definition, read the same way as the AWS-LC symbol prefix above.

The rule is fork-neutral: AWS-LC's FIPS module shares the same source and the same
symbol, so the rule names a FIPS build of the BoringSSL-lineage module rather than which
fork compiled it, and suppresses only `BIN_BORINGSSL`. Every Go binary built with the
BoringCrypto backend also suppresses `BIN_BORINGSSL`, since it vendors BoringSSL's own
strings regardless of whether the integrity-test symbol survives stripping.

The verdict is `CONDITIONAL`, the same reasoning as the AWS-LC entry above. A stripped
static object that carries neither marker still reads as stock `NON_APPROVED_CRYPTO`,
and an unstripped BoringCrypto binary keeps `NON_APPROVED_CRYPTO` in `classes` through
its own primitives, unsuppressed for the same reason AWS-LC's are.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#a-boringssl-fips-module-is-told-from-a-stock-build-by-its-integrity-test-not-its-strings)

## Every symbol group is read by a rule, or says it is evidence only

**Accepted, and it changes verdicts.**

A `[[symbol_group]]` the binary readers populate but no rule reads is evidence gathered
and thrown away: a defined `argon2id_hash_raw`, alone in an object with no other
evidence, would read `NO_CRYPTO_DETECTED`, because no rule looks at the `argon2` group.
`blake`'s string-group match alone has the same gap: a reference implementation with no
banner string carries nothing that arm matches.

Argon2 gets its own rule, `BIN_ARGON2`, `NON_APPROVED_CRYPTO` on either binding: OpenSSL
exports no `argon2*`/`blake2*`/`blake3*` name (measured with `nm -D --defined-only` on
Fedora, its own Argon2 reaches only through `EVP_KDF`), so an *imported* name from
either group can only be a dependency on a library like libargon2, never a call the
host FIPS provider could answer. `blake` is read by `BIN_NON_CRYPTO_HASH` as a second
match arm beside its existing string-group one, keeping `CONTEXT_DEPENDENT`; a hit from
either arm on the same group folds into one finding.

The loader refuses a ruleset where some `[[symbol_group]]` is neither read by a
`dynamic_symbol` rule or a `[[crypto_library]]`'s `symbol_group`, nor marked
`evidence_only = true` on the group itself -- and refuses the opposite too, a group
marked `evidence_only` that something does read. `boringssl` and `aws_lc` take the
`evidence_only` mark: `BIN_BORINGSSL` and `BIN_AWS_LC` already read the same-named
string groups instead, and AWS-LC keeps BoringSSL-named symbols, so a rule over the
`boringssl` symbol group would report BoringSSL on an AWS-LC object.

**What it costs.** A BLAKE-only object reads `CONTEXT_DEPENDENT` instead of
`NO_CRYPTO_DETECTED`, which outranks both that and `OPAQUE` in `[verdict] precedence`,
so a partially read object carrying a BLAKE symbol headlines `CONTEXT_DEPENDENT`
instead of `OPAQUE`. An Argon2-only object moves further, to `NON_APPROVED_CRYPTO`.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DESIGN.md#every-symbol-group-is-read-by-a-rule-or-says-it-is-evidence-only),
including the measurement behind the `any` binding and why a `[[crypto_library]]`
`symbol_group` on `argon2` was rejected.
