# Determinism and the Python layer

Two entries about the Python source layer: the one place where "same wheel in,
byte-identical JSONL out" is conditional on the host, and a rule that was reading the right
evidence but never asking for it.

## The Python parser follows the interpreter running the scan

**Accepted. Documented, not fixed.**

`ast.parse` follows the grammar of the interpreter running it, so a wheel using syntax newer
than the scanner's interpreter does not parse, and the same wheel can produce different
records on different Python versions. PEP 695 is the concrete case: `type Digest = bytes` is
a syntax error on 3.11 and valid from 3.12, so a wheel whose only crypto evidence sits behind
that syntax comes out `NO_CRYPTO_DETECTED` on 3.11 and `FIPS_BREAKING` on 3.12 and later.

**Why it is tolerable.** The failure is never silently favourable. A file that does not parse
is counted in `artifacts.py_files_unparsed`; a wheel whose every source file failed reports
`source_available: false` and comes out `OPAQUE`. An older interpreter yields *less*
evidence, never a wheel that wrongly looks clean, which keeps the "unreadable means
`OPAQUE`" invariant intact.

**Why the obvious fix does not work.** `ast.parse(..., feature_version=...)` gates only a
subset of the grammar and does not cover PEP 695. It was tried and removed: it cost findings
on newer interpreters without delivering the determinism it promised.

**What was rejected.** Vendoring or depending on a version-independent parser — it would
close the gap properly, but the dependency list is two packages on purpose and a third needs
to buy more than this. And recording the parsing interpreter's version in the record: cheap,
and it makes the difference visible rather than silent, but `tool` would then carry
host-derived data, which trades a narrow non-determinism for a total one — a record that
embeds the host it was produced on is no longer byte-comparable between producers.

**How it is handled instead.** The documentation says to pin the interpreter when records
must be comparable across hosts. CI runs 3.11 through 3.14, so a divergence that grows beyond
the Python layer shows up as a test failure.

**Revisit** if a version-independent parser lands in the standard library, or if a wheel in
the real corpus is found whose headline verdict flips on interpreter version alone.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#the-python-parser-follows-the-interpreter-running-the-scan) ·
[#4](https://github.com/EmilienM/wheel-crypto-scan/issues/4)

## An explicit usedforsecurity=True, and a non-constant flag, are not `NO_CRYPTO_DETECTED`

**Fixed. The AST extractor already recorded the right thing; the ruleset just never asked
for it.**

`_hashlib_usedforsecurity` has always yielded `"absent"`, `"false"`, `"true"` or
`"unresolved"` correctly. Nothing in `ruleset.toml` matched `"true"` at all, so
`hashlib.md5(data, usedforsecurity=True)` — the code explicitly declaring itself a security
use — produced zero findings and read as `NO_CRYPTO_DETECTED`, the one outcome this tool's
invariants exist to rule out for an uncertain case. This case was neither uncertain nor
unreadable: it was the single most certain shape the extractor can produce.

Likewise `PY_WEAK_HASH_UNRESOLVED`'s own `why` claimed to cover "usedforsecurity passed a
non-constant", but no match table read that value; it only matched a non-constant *algorithm
name* on `hashlib.new`.

**What changed.** `PY_WEAK_HASH_CALL`'s match table now accepts
`usedforsecurity = ["absent", "true"]`. `PY_WEAK_HASH_UNRESOLVED` gained a second
`[[rule.match]]` table for `usedforsecurity = "unresolved"` with
`weak_algorithms_only = true`, ORed with its existing table — one rule id, two ways of
reaching it. This is the first rule in the shipped ruleset to use more than one match table,
though the mechanism was already defined and already exercised synthetically.

**The judgment call: no new rule id for the explicit-`True` case.** An explicit `True` is
worth distinguishing from the bare no-keyword call in the evidence text, since one is a
default and the other is a declaration, but not in severity, confidence or verdict class:
both are `FIPS_BREAKING` and both need human review. The distinction already exists one layer
down, in `PySite.detail`.

**The other judgment call: a non-constant flag on a non-weak algorithm is not this finding,
at any class.** `hashlib.new("sha256", usedforsecurity=flag)` fires nothing: sha256 is
FIPS-approved regardless of what the flag turns out to be at runtime, so the uncertainty a
human would be asked to resolve does not exist.

[Full entry](https://github.com/EmilienM/wheel-crypto-scan/blob/main/DECISIONS.md#an-explicit-usedforsecuritytrue-and-a-non-constant-flag-are-not-no_crypto_detected) ·
[#58](https://github.com/EmilienM/wheel-crypto-scan/issues/58)
