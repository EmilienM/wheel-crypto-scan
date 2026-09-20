# Contributing

Read [Invariants](invariants.md) first. Most of what would otherwise be a surprising review
comment is written down there.

## Commands

```bash
uvx --with tox-uv tox              # py311-py314, ruff lint and format, pylint
uvx --with tox-uv tox -e lint      # ruff check --select=E,F,W, then ruff format --check
uvx --with tox-uv tox -e format    # apply formatting
uvx --with tox-uv tox -e pylint    # pylint the package
uvx --with tox-uv tox -e real      # opt-in, needs real wheels in WCS_CORPUS_DIR
uvx --with tox-uv tox -e docs      # build this site into site/
uv run wheel-crypto-scan scan /path/to/wheels -o index.jsonl --jobs 8
```

Line length is 100.

## Tests

Tests marked `real` and `hostbin` are deselected by default: they need downloaded wheels or
host system libraries. `tox -e real` runs both, with `WCS_CORPUS_DIR` pointing at a
directory of real wheels.

**Test fixtures are synthesised, including the object files.** `tests/helpers/binfmt/`
writes ELF, Mach-O and PE byte for byte with `struct`. The suite needs no compiler, no
network and no committed binaries, and runs byte-identically anywhere. Keep it that way.

**Break a guard to see whether it guards.** Much of this suite exists to hold an invariant
rather than a behaviour, and such a test passes just as well when it asserts nothing.
Deleting the line under test, or mutating it to the wrong answer, is the only way to tell.
Several guards in the tree were added after a review showed the obvious version of them
stayed green.

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
fails on drift.

## Writing it down

A design call that cost something goes in `DECISIONS.md`: what was decided, what it costs,
what was rejected and why, what was measured rather than assumed, and what would make it
worth revisiting. This site renders those entries under
[Design decisions](decisions/index.md).

The house style there is worth matching. Claims are measured, not asserted; a claim that did
not survive review is corrected in place rather than quietly dropped; and an entry says what
it leaves open as plainly as what it closes.

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
