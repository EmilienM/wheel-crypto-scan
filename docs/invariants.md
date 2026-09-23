# Invariants

These are design decisions, not accidents. **Do not change one without saying so
explicitly.** They live in
[`AGENTS.md`](https://github.com/EmilienM/wheel-crypto-scan/blob/main/AGENTS.md) in the
repository, which is what a contributor or an agent working in the tree reads first.

---

## No passing verdict class

The taxonomy has no passing class, no "compliant" and no "compatible", and must never
acquire one. A human makes that call.

## Deterministic output

Same wheel in, byte-identical JSONL out, across `--jobs`, cache state, and interpreter
version. Output is sorted, ASCII-only, float-free, and carries no host paths, timestamps or
hostnames.

## Unreadable means `OPAQUE`, never `NO_CRYPTO_DETECTED`

Absence of evidence is not evidence of absence, and a test asserts every recordable failure
maps to a rule.

One carve-out: a `partial_reasons` cause that is a linker convention rather than a failure
is recorded without a verdict. Today that is one cause, an ordinal import, and only because
the dependency name survives it — when it is a name the ruleset knows, which
[the design notes](design-summaries/opacity.md#a-routine-cause-is-recorded-but-does-not-make-a-wheel-opaque)
measure rather than assume.

An ordinal *export* is not on that list: it loses a definition, and a definition is how
`static` is recognised, so the argument that admits the import does not apply to it.

!!! danger "The admission test is behavioural, not editorial"

    Adding to this list is changing this invariant. Go and find a crypto object that reads
    clean because the cause is on the list. If it exists the cause does not belong there,
    whatever the sentence says.

That list is also the floor of the `[linkage_policy]` exemptions; the loader refuses a
ruleset that drops an exemption without re-rating, and a test pins the other direction.

## A structure that does not parse costs that structure, never the evidence already gathered

A reader that cannot read its own header still returns the strings, cargo paths and Go
markers it found, and still marks the object `partial_analysis`. The strings are often the
only evidence there is: `cryptography` 42 and later compiles OpenSSL into the extension,
with no library file and no dependency to name.

## A name reported is a name read in full

Never put bytes in `matched_symbols` that the object did not spell out: an index past the
end of a string table, or into a run it never closes, is a name we could not resolve, not a
short name.

Recording what was reachable looks like the safe direction and is not — it asserts a symbol
that does not exist, in the field the whole tool turns on. Both binary readers resolve names
this way, and a test holds each to it.

## `partial_analysis` and `partial_reasons` never disagree

The tuple is non-empty exactly when the boolean is true, asserted across every reader.
Filter on the boolean; read the tuple to find out what to do about it.

## One bad wheel never aborts a run

Failures become error records. The broad `except Exception` handlers are deliberate; pylint
is configured to allow them.

## No network, no LLM, no dataflow analysis at runtime

Scoped to the scan and the render: the only network access either makes is an
explicitly requested `--index-url` download. Opening the HTML report is not the scan or
the render: it fetches DataTables' pinned, integrity-checked script and stylesheet from
a CDN, and falls back to a native table when the script cannot be reached or verified.

---

## Working rules

Not invariants, but the conventions that keep the invariants true.

### Policy goes in `ruleset.toml`, not Python

Nothing in the scanner hardcodes a package name, symbol, library or verdict. Every entry
carries a `why` in plain language; write one for anything you add.

### Bump `ruleset_version` after editing the ruleset

It is part of the cache key, so the bump is what re-evaluates already-scanned wheels.

### Bump `ANALYZER_VERSION` when an unchanged wheel would produce a different record

Extraction, a new field, a changed verdict: all of it. The cache stores *serialised
records*, so without the bump a stale entry is served and the change silently does not apply
to anything already scanned. It is easy to forget because nothing fails without it.

`schema_version` is different and rarer: adding an optional key or a new value does not bump
it, removing or retyping a field does.

### Vocabularies are facts, policy is what to do about them

`FORMAT_*`, `PARTIAL_REASONS` and the error kinds live in Python because they describe what
a reader did; which of them is worth a verdict lives in `ruleset.toml`, matched through
`kind = "scan_error"` or `kind = "partial_binary"`. A token named by a rule is validated at
load time, so a typo is a load error rather than a rule that silently matches nothing.

### A prefilter lives beside the matcher it mirrors

A reader that restates "could this match" in cheaper terms — over raw bytes, before
decoding — puts the cheap version in `ruleset.py` next to the real one, with a test that
fails when the real one grows an arm. A prefilter that quietly stops matching what the
matcher matches loses evidence and fails nothing: `BinaryPatterns.symbol_locator` is the
worked example.

### One vocabulary can carry more than one split, and they must not be assumed equal

`PARTIAL_REASONS` is read twice: a `partial_binary` rule with no verdict says which causes
are not worth one, and `[linkage_policy] exclude_reasons` says which leave a linkage posture
answerable. They differ, and the one containment between them is refused at load time rather
than left to a test over the shipped ruleset. Reusing a list because it looks like the same
question is how a field gets an answer nothing decided.

### A shared check states what it assumes

`binfmt.symtab` is only sound over a string table the caller read through, and moving it to
a reader that does not guarantee that opens a hole. Moving a check to where two callers can
use it moves its preconditions out of sight, so they go in its docstring.

### A pass over a whole object belongs in C

Every such pass runs once per slice of a universal binary, up to `_MAX_FAT_SLICES`, over
regions the slices are free to share. A Python loop over a 2 MiB string table takes 19
seconds across one object; the same check as one compiled regex takes 1.2.
`tests/test_hardening.py` is where that is held.

### Keep `record.py` and `data/schema.json` in step

And update the schema documentation with them. A test fails on drift.

### Dependencies are `pyelftools` and `packaging`

Ask before adding a third.

### Test fixtures are synthesised

Including the object files: `tests/helpers/binfmt/` writes ELF, Mach-O and PE byte for byte
with `struct`. The suite needs no compiler, no network and no committed binaries. Keep it
that way.

### Break a guard to see whether it guards

Much of this suite exists to hold an invariant rather than a behaviour, and such a test
passes just as well when it asserts nothing. Deleting the line under test, or mutating it to
the wrong answer, is the only way to tell. The obvious version of a guard often stays green
with the line it guards deleted.

### Write down the current design, not its history

Comments, docstrings, test names, ruleset `why` text, `SCHEMA.md`, `DESIGN.md` and `docs/`
say what the code does and why, as if it had always been this way. No issue or PR numbers,
no "found by review", no "used to", "previously", "an earlier version", "before this fix",
"revised", "corrected", "extended in". Keep the reasoning, the measurement and the rejected
alternative, and describe a rejected approach as an alternative ("keying on the name alone
reads X"), not as something the code once did. History belongs in the commit message and
the PR. A test file is named for its topic, never for the review or fix that produced it.
`tests/test_design_notes.py` catches citations, review framing and a quoted `DESIGN.md`
heading that no longer exists; the rest is on the writer.

Wheels are read from the zip in memory, never extracted to disk.
