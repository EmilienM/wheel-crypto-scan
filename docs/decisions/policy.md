# Policy data: what the ruleset enumerates

Entries about the shape of the data in `data/ruleset.toml` rather than about any one
reader: which lists close mechanically, which never close, and what happens when one
stops matching the world without anything failing.

## `openssl_banner` names every major digit, not the majors that shipped

**Accepted.**

The group listed `OpenSSL 3.`, `OpenSSL 1.1.` and `OpenSSL 1.0.` OpenSSL 4.0 shipped, and
the current PyPI wheel of the package this tool was written for compiles it in:
`cryptography` 50.0.1 carries `OpenSSL 4.0.2 25 Aug 2026` in read-only data, declares no
`DT_NEEDED` on libcrypto, and exports no OpenSSL symbol. The banner was the entire
evidence, the banner was not listed, and the wheel came out `openssl_linkage: none` — a
wheel carrying its own OpenSSL reading exactly like a wheel with none in it. Nothing
failed while it did: the object parsed, every structural check passed, the record was
clean.

**Why a digit is still required.** `OpenSSL ` alone also matches prose. That same object
carries `OpenSSL 3's legacy provider failed to load`, and so does a build that links the
system library, while a banner is one of the two things that make an object read
`static`.

**What it cost to fix, and what it buys.** Listing 0 through 9 is one line and no code.
Measured over 18 native wheels off PyPI, exactly one record changes — `cryptography`
from `none` to `static` — and the other seventeen are byte-identical.

**What was rejected.** A bounded pattern capability for `[[string_group]]`, which is the
same answer with a code change behind it: the loader refuses non-printable substrings
precisely so the strings matcher can assume no pattern spans its run separator, and a
raw pattern voids that assumption. Also rejected: a note telling the next maintainer to
add the following major when it ships, a remedy this file has refused before.

## The sweep that followed, and the two kinds of list it separated

Reviewing that fix turned up more lists of the same shape, and sorted them into two
kinds that had been treated as one.

**A field's spellings, enumerated.** These close mechanically and are silent when stale.
`nss` (`NSS 3.`) now names every digit. The Windows version suffix spelled the
architecture as `x64|x86|arm64|arm64ec`, four spellings of a field whose fifth — a vendor
writing `aarch64` — left `libcrypto-3-aarch64.dll` resolving to no library at all.
`cargo_path_regex` spelled one path separator: cryptography's `win_amd64` `.pyd` carries
153 `cargo\registry` paths and no `cargo/registry` path, so every Rust wheel built on
Windows read as carrying no crates at all. That last one cost more evidence than the rest
of the sweep together — with both separators `hf-xet` goes from 0 crates to 74 on
Windows, including `rustls` and `aws-lc-rs`, while all 18 Linux records stay identical.

**An entity list.** The crate table gained `openssl-src`, `boring`, `boring-sys`,
`sha-1`, `md5`, `sha1_smol` and `sha3`. No pattern closes the set of crates that exist in
the world, so this list is incomplete by construction rather than stale by neglect, and
adding to it buys reach rather than closing a hole. `openssl-src` carries its own limit
in its `why`: its code runs in a build script and is not linked into the artifact, so
nobody has observed the path in a shipped wheel, and on an object with no other OpenSSL
evidence it gives `openssl_linkage: unknown`, never `static`.

**A guarantee that was not there.** `[conventions]` says naming the Go string groups in
the ruleset means renaming a group cannot silently flip a verdict-relevant field. The
loader never checked: a name no group had loaded clean and left `GoBuildInfo.boring_crypto`
false for every Go binary in the run, while every other group reference in the file was
refused at load time.

**Revisit if** a `[[string_group]]` needs a match ten literals cannot spell — not on a
count of cases. A capability earns itself when the enumeration cannot express the match,
not when the list is long.

## A Go FIPS build is told from a stock one by its build settings

**Accepted.**

Since Go 1.24 the standard library implements its crypto on top of
`crypto/internal/fips140`, so a binary built against the validated module carries the
stock package paths exactly as a stock build does and read as `NON_APPROVED_CRYPTO` with
nothing to suppress it. Built one program two ways on go1.27.1: `crypto/sha256.` appears
9 times in both, `crypto/aes.` 6 times in both, and `crypto/internal/fips140` more often
in the *stock* binary (381) than in the FIPS one (334). What separates them is
`GOFIPS140=` and `fips140=on`, which the toolchain writes into `.go.buildinfo` — an
allocated section the strings pass already reads, so this needed no reader change and no
`ANALYZER_VERSION` bump.

The verdict is `CONDITIONAL`: the module being compiled in does not mean it is in force,
since `GODEBUG=fips140` can be turned back off at run time.

The record needed a change even though the verdict did not. `binaries[].go.markers` is
built from the Go group names `[conventions]` lists, so a rule on a group missing from
that list made one record say two things — `markers: ["go_stock_crypto"]` beside a
verdict of `BIN_GO_FIPS140`, from the same strings. `[conventions]` now names every Go
group, and `ANALYZER_VERSION` moves with it.

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

Full argument, with the measurements and what the sweep deliberately left open:
[`DECISIONS.md`](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md).

## A static OpenSSL's legacy primitives lead the headline

**Accepted, knowing what it costs.**

Reading `.symtab` local definitions beside a present `.dynsym` surfaced a statically
linked OpenSSL's own low-level API — `BF_*`, `MD4_*`, `SHA1_*`, `RIPEMD160_*`, and a
static OpenSSL 3's `x25519_fe51_*`/`x25519_fe64_*` field-arithmetic helpers, internal
`crypto/ec` code rather than provider entry points (those are `ossl_x25519`,
`ossl_ed25519_sign` and so on, which the group does not match; nor does 1.1.1's own
`ED25519_sign`, capitalised differently from the group's `Ed25519_` prefix) — so such a
wheel now also matches `BIN_BCRYPT_BLOWFISH`, `BIN_OWN_WEAK_HASH_IMPL` and
`BIN_CURVE25519` alongside `BIN_STATIC_OPENSSL`. A bundled `libcrypto` matches
`BIN_BCRYPT_BLOWFISH` and `BIN_OWN_WEAK_HASH_IMPL` the same way, through its own
`.dynsym` exports alongside `BIN_BUNDLED_OPENSSL`, unrelated to `.symtab` reading;
`BIN_CURVE25519`'s field helpers are not part of libcrypto's public API, so a bundled
copy matches it only if the bundle still carries a `.symtab`.
Either way `NON_APPROVED_CRYPTO` outranks the `CONDITIONAL` of `BIN_STATIC_OPENSSL` or
`BIN_BUNDLED_OPENSSL`. The taxonomy calls this correctly: a static or bundled OpenSSL
bundles those primitives and the host FIPS provider cannot refuse them.

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

Full argument: [`DECISIONS.md`](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md).


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
A `[[rust_crate]]` entry can also carry its own
`suppressed_by`, naming another crate entry, so two subjects of the same rule --
`aws-lc-rs` and its FIPS build `aws-lc-fips-sys` -- can relate the way two whole rules
already can; no other table reads entry-level `suppressed_by`, and the loader refuses it
there. Only the `rust_crate` matcher honours it, though: `sbom_component` takes a
component's verdict from the same `[[rust_crate]]` entry but not its `suppressed_by`, so
an SBOM naming both aws-lc-rs and aws-lc-fips-sys still reports both, an accepted
over-flag. Suppression stays non-cascading, and the loader refuses a `suppressed_by`
cycle across rules and crates, including one closed by an ownerless crate, rather than
silently dropping every member of one.

Full argument, including why `aws-lc-sys` and `rustls` get no such relation, and why the
SBOM gap is left as an accepted over-flag rather than fixed:
[`DECISIONS.md`](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md).
