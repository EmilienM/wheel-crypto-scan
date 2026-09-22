# Determinism and the Python layer

Two entries about the Python source layer: the one place where "same wheel in,
byte-identical JSONL out" is conditional on the host, and a rule that has to ask for
evidence the extractor already records.

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
subset of the grammar and does not cover PEP 695. Measured, it costs findings on newer
interpreters without delivering the determinism it promises.

**What was rejected.** Vendoring or depending on a version-independent parser — it would
close the gap properly, but the dependency list is two packages on purpose and a third needs
to buy more than this. And recording the parsing interpreter's version in the record: cheap,
and it makes the difference visible rather than silent, but `tool` would then carry
host-derived data, which trades a narrow non-determinism for a total one — a record that
embeds the host it was produced on is not byte-comparable between producers.

**How it is handled instead.** The documentation says to pin the interpreter when records
must be comparable across hosts. CI runs 3.12 and 3.14 on every push, and the release workflow
runs the suite on 3.11 through 3.14 before it publishes, so a divergence that grows beyond the
Python layer shows up as a test failure before it ships.

**Revisit** if a version-independent parser lands in the standard library, or if a wheel in
the real corpus is found whose headline verdict flips on interpreter version alone.

[Full entry](../DESIGN.md#the-python-parser-follows-the-interpreter-running-the-scan)

## An explicit usedforsecurity=True, and a non-constant flag, are not `NO_CRYPTO_DETECTED`

**Accepted, and it changes verdicts. The AST extractor records the right thing; the
ruleset is what has to ask for it.**

`_hashlib_usedforsecurity` yields `"absent"`, `"false"`, `"true"` or `"unresolved"`, so
an explicit `usedforsecurity=True` is exactly as available to the ruleset as every other
value. `PY_WEAK_HASH_CALL`'s match table accepts
`usedforsecurity = ["absent", "true"]`, so `hashlib.md5(data, usedforsecurity=True)` —
the code explicitly declaring itself a security use — is at least as confident as the
bare no-keyword call, not less: both are `FIPS_BREAKING`, and treating the explicit
declaration as if it were `NO_CRYPTO_DETECTED` would rule out the one outcome this
tool's invariants exist to catch for the single most certain shape the extractor can
produce.

`PY_WEAK_HASH_UNRESOLVED` has a second `[[rule.match]]` table for `usedforsecurity =
"unresolved"` with `algorithm_list = "weak"`, ORed with its `algorithm =
"unresolved"` table — one rule id, two ways of reaching it, since a non-constant flag on
a weak algorithm is context-dependent whichever way `usedforsecurity` was passed. It is
the one rule in the shipped ruleset with more than one match table; the mechanism is
defined for every rule and exercised synthetically too.

**The judgment call: no new rule id for the explicit-`True` case.** An explicit `True` is
worth distinguishing from the bare no-keyword call in the evidence text, since one is a
default and the other is a declaration, but not in severity, confidence or verdict class:
both are `FIPS_BREAKING` and both need human review. The distinction lives one layer
down, in `PySite.detail`.

**The other judgment call: a non-constant flag on a non-weak algorithm is not this finding,
at any class.** `hashlib.new("sha256", usedforsecurity=flag)` fires nothing: sha256 is
FIPS-approved regardless of what the flag turns out to be at runtime, so the uncertainty a
human would be asked to resolve does not exist.

[Full entry](../DESIGN.md#an-explicit-usedforsecuritytrue-and-a-non-constant-flag-are-not-no_crypto_detected)
