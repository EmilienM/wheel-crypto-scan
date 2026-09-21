# wheel-crypto-scan

Reports crypto-relevant **evidence** found inside Python wheels, so the teams consuming a
package index can see per-wheel FIPS risk before they ship it.

It gathers evidence. It does not decide FIPS compatibility.

## The question it exists for

**Does this wheel use the system OpenSSL, or does it carry its own?** A wheel that resolves
`libcrypto.so.3` from the host inherits the host's FIPS provider and crypto policy. A wheel
that ships or statically links its own copy does not, and no amount of host configuration
changes that.

There are three ways a wheel can carry its own OpenSSL, and all three are caught:

| Evidence | `openssl_linkage` |
|---|---|
| Plain `DT_NEEDED libcrypto.so.3`, OpenSSL symbols imported, and nothing in the wheel resolves it | `system` |
| A library under `*.libs/` or `.dylibs/`, a dependency on a hash-renamed `libcrypto-3a1f2b4c.so.3`, or an unrenamed dependency (delocate's convention) that still names a file the wheel itself ships | `bundled` |
| No dependency and no vendor directory, but OpenSSL symbols defined or its version banner in read-only data | `static` |

A version banner beside a system dependency is header text rather than a copy when the
object imports its OpenSSL from that dependency, was read in full, and carries none of
the build strings (`OPENSSLDIR:`) a compiled-in OpenSSL keeps beside its banner.

The third case is the one that matters most and the one a vendor-directory check alone
misses. Run against three real builds of `cryptography`:

```text
Fedora RPM build      DT_NEEDED libcrypto.so.3, libssl.so.3    64 imported, header banner   -> system
PyPI 42.0.5           empty cryptography.libs/, no DT_NEEDED,  0 symbols exported           -> static
PyPI 3.4.8            no DT_NEEDED, no vendor directory,       0 symbols exported           -> static
```

For PyPI 42.0.5 the *only* evidence is the `OpenSSL 3.2.1` banner in `.rodata`: the vendor
directory is empty, nothing is declared, and the symbols are hidden by a version script.

## What it explicitly does not do

- **It never says a wheel passes.** The taxonomy has no passing class, not "FIPS compliant"
  and not "FIPS compatible", and cannot acquire one. A human makes that call.
- **No LLM at runtime.** Pure static analysis. The JSON is what gets fed to a model later,
  as a separate step.
- **No dataflow or reachability analysis.** It records the call site; it does not try to
  prove the call runs.
- **No container images, no RPMs, no sdists.** Wheels only.
- **No network**, except an explicitly requested `--index-url` download of the wheels.

## Quick start

```bash
uv tool install .                       # or: uv run wheel-crypto-scan
wheel-crypto-scan scan /path/to/wheels -o index.jsonl --jobs 8
wheel-crypto-scan scan one.whl --format md
wheel-crypto-scan scan /path/to/wheels --format html -o report.html
wheel-crypto-scan rules                 # the rule table, for review
wheel-crypto-scan schema                # the JSON Schema for the output
```

Triage the output with `jq`:

```bash
jq -r 'select(.verdict.conditions.openssl_linkage == "bundled") | .wheel.filename' index.jsonl
jq -r 'select(.verdict.class == "FIPS_BREAKING") | "\(.wheel.name) \(.verdict.reasons[0])"' index.jsonl
jq -r 'select(.verdict.class == "OPAQUE") | .wheel.filename' index.jsonl   # could not be read
```

[Install and run](usage.md) has every flag; [Output schema](output-schema.md) documents
every field of the record.

## The verdict classes

JSONL, one record per wheel.

| Verdict class | Meaning |
|---|---|
| `NON_APPROVED_CRYPTO` | Implements or bundles a non-FIPS-approved primitive |
| `CONDITIONAL` | Approved only under a stated condition; `verdict.conditions` says which holds |
| `FIPS_BREAKING` | Will raise at runtime under FIPS-enforcing mode |
| `CONTEXT_DEPENDENT` | Non-approved primitive that may be a non-security use |
| `NO_CRYPTO_DETECTED` | Nothing found. Absence of evidence, not evidence of absence |
| `OPAQUE` | Stripped, unreadable or source-free. Cannot determine |

A wheel that could not be read is `OPAQUE`, never `NO_CRYPTO_DETECTED`. That distinction is
enforced by a test asserting every recordable failure has a rule.

One carve-out: an import bound by ordinal has no function name to match, which is how
Windows normally binds `WS2_32`. That is recorded in `partial_reasons` but does not make
the wheel `OPAQUE`, because the DLL it names survives in `needed` and is matched there.
An *export* bound by ordinal is not the same trade and is not carved out: it loses a
definition, which is how a statically linked copy is recognised, and it names no
dependency to fall back on. [Evidence, opacity and verdicts](design/opacity.md) says
what both cost.

## Determinism

Same wheel in, byte-identical JSONL out. Verified on a 100-wheel corpus to be identical
across repeat runs, `--jobs 1` vs `--jobs 8`, cold vs warm cache, and Python 3.11, 3.12,
3.13 and 3.14. Output is sorted, ASCII-only, float-free, and contains no host paths,
timestamps or hostnames.

One caveat worth knowing: `ast.parse` follows the grammar of the interpreter running it,
so a wheel using syntax newer than the scanner's interpreter will not parse. **Pin the
interpreter** if you need output comparable across hosts. That difference is never
silently favourable: unparsed files are counted in `artifacts.py_files_unparsed`, and a
wheel whose every source file failed reports `source_available: false` and comes out
`OPAQUE`, not clean. [Determinism and the Python layer](design/interpreter.md) records
why this is documented rather than fixed.

## Performance

Measured on 100 synthetic wheels averaging 3.3 MiB uncompressed, on 16 cores:

| Mode | wheels/s | per wheel |
|---|---|---|
| `--jobs 1`, cold | 3.1 | 320 ms |
| `--jobs 4`, cold | 11.8 | 85 ms |
| `--jobs 8`, cold | 20.4 | 49 ms |
| `--jobs 8`, warm cache | 674 | 1.5 ms |

Wheels are read from the zip in memory and never extracted to disk. Members above the
in-memory threshold stream through a seekable zip reader that retains a bounded window of
what it has already decompressed, so a multi-gigabyte extension costs a bounded number of
passes rather than a gigabyte of resident memory. Reading the real 5.5 MiB
`libcrypto.so.3` through that path takes 0.19 s with one decompression; without the
window it took 17 s and 3,161.

## Licence

Apache 2.0. See [LICENSE](https://github.com/EmilienM/wheel-crypto-scan/blob/main/LICENSE).
