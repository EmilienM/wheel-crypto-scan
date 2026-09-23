# Contributing

Read [Invariants](invariants.md) first. Most of what would otherwise be a surprising review
comment is written down there.

## Commands

```bash
uvx --with tox-uv tox              # py311-py314, ruff lint and format, pylint, docs build
uvx --with tox-uv tox -e lint      # ruff check --select=E,F,W,PLC0415, then ruff format --check
uvx --with tox-uv tox -e format    # apply formatting
uvx --with tox-uv tox -e pylint    # pylint the package
uvx --with tox-uv tox -e real      # opt-in, needs real wheels in WCS_CORPUS_DIR
uvx --with tox-uv tox -e network   # opt-in, needs a live network connection
uvx --with tox-uv tox -e docs      # build this site into site/
uv run wheel-crypto-scan scan /path/to/wheels -o index.jsonl --jobs 8
```

Line length is 100.

## Tests

Tests marked `real` are deselected by default: they need downloaded wheels, given through
`WCS_CORPUS_DIR`. Tests marked `network` are deselected by default too: they check the
HTML report's own DataTables enhancement against the real, pinned script and stylesheet
from cdn.jsdelivr.net, given a live connection -- `tox -e network` runs them, skipping
without one unless `WCS_REQUIRE_NETWORK` is set to any non-empty value, as CI does, which
turns that skip into a failure. Tests marked `hostbin` run by default: they look for
`libcrypto.so.3` in the usual Fedora and Debian/Ubuntu library directories and skip
without it, unless `WCS_REQUIRE_HOSTBIN` is set to any non-empty value, as CI does.
`tox -e real` runs both `real` and `hostbin`.

**Test fixtures are synthesised, including the object files.** `tests/helpers/binfmt/`
writes ELF, Mach-O and PE byte for byte with `struct`. The suite needs no compiler, no
network and no committed binaries, and runs byte-identically anywhere. Keep it that way.

**Break a guard to see whether it guards.** Much of this suite exists to hold an invariant
rather than a behaviour, and such a test passes just as well when it asserts nothing.
Deleting the line under test, or mutating it to the wrong answer, is the only way to tell.
The obvious version of a guard often stays green with the line it guards deleted.

## Adding policy

Policy goes in `data/ruleset.toml`, not Python. Every entry carries a `why` in plain
language; write one for anything you add. See [The ruleset](ruleset.md).

Then bump `ruleset_version`. It is part of the cache key, so the bump is what re-evaluates
already-scanned wheels.

## Changing extraction

Bump `ANALYZER_VERSION` in `__init__.py` whenever an unchanged wheel would produce a
different record. The cache stores serialised records, so without the bump a stale entry is
served and your change silently does not apply to anything already scanned. Nothing fails if
you forget.

Keep `record.py` and `data/schema.json` in step, and update `SCHEMA.md` with them. A test
fails on drift. `docs/output-schema.md` is the site's copy of `SCHEMA.md`: edit `SCHEMA.md`
first, then copy the changed table rows and prose over (` -- ` or an em dash, either reads
the same; cross-references as links). Tests compare every table row and every non-table
paragraph between the two.

## Writing it down

A design call that cost something goes in `DESIGN.md`: what the code does, what it costs,
what was rejected and why, what was measured rather than assumed, what is left open, and
what would make it worth revisiting. This site renders those entries under
[Design](design-summaries/index.md).

The house style there is worth matching. Claims are measured, not asserted, and an entry
says what it leaves open as plainly as what it closes.

Comments, docstrings, test names and `why` text describe the current design, not its
history: no issue or PR numbers, no "used to" or "before this fix". See AGENTS.md's
"Write down the current design, not its history." `tests/test_design_notes.py` checks the
mechanical part of that, and that every `DESIGN.md` heading something quotes still exists.

## Dependencies

Runtime dependencies are `pyelftools` and `packaging`. **Ask before adding a third.**

Development and documentation tooling is not covered by that rule and does not belong in
`[project] dependencies`. It is declared per environment in `tox.ini`, the way `ruff`,
`pylint`, `pytest` and `mkdocs-material` already are.

## Documentation

The site is MkDocs Material. `mkdocs.yml` sits at the repository root and the pages are
under `docs/`.

```bash
uvx --with tox-uv tox -e docs                          # build, --strict
uvx --with mkdocs-material mkdocs serve                # live preview on :8000
```

The build runs with `--strict`, so a broken internal link fails it. A push to `main`
publishes the result to GitHub Pages through `.github/workflows/docs.yml`.

## Releasing

A bare semver tag triggers publishing, and nothing else does. There is no version in the
repo to bump: `uv-dynamic-versioning` derives it from the tag.

```bash
git tag -a 0.1.0 -m "0.1.0" && git push origin 0.1.0
```

No `v` prefix. The workflow re-runs the full matrix, builds, checks that the ruleset and
schema are actually inside the distribution, and uploads through PyPI Trusted Publishing, so
there is no token to store.

An untagged build reports its commit, for example `0.0.0.post14.dev0+1105fe9`, which makes
it obvious when a record came from something other than a release.
