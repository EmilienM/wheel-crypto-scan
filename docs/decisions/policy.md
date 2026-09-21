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
nobody has observed the path in a shipped wheel, and a crate name cannot move
`openssl_linkage` in any case.

**A guarantee that was not there.** `[conventions]` says naming the Go string groups in
the ruleset means renaming a group cannot silently flip a verdict-relevant field. The
loader never checked: a name no group had loaded clean and left `GoBuildInfo.boring_crypto`
false for every Go binary in the run, while every other group reference in the file was
refused at load time.

**Revisit if** a `[[string_group]]` needs a match ten literals cannot spell — not on a
count of cases. A capability earns itself when the enumeration cannot express the match,
not when the list is long.

Full argument, with the measurements and what the sweep deliberately left open:
[`DECISIONS.md`](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md).
