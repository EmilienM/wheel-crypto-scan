"""Deterministic FIPS-risk evidence inspector for Python wheels.

The tool gathers crypto-relevant evidence statically and never decides FIPS compatibility.
See SCHEMA.md for the output contract and data/ruleset.toml for the rules.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _installed_version

TOOL_NAME = "wheel-crypto-scan"

try:
    # Derived from the git tag at build time, so the version in a record is the
    # version that produced it and there is no number to remember to bump.
    __version__ = _installed_version(TOOL_NAME)
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"

# Breaking changes to the output contract only. Adding optional keys or new rule ids
# does not bump this; removing or retyping a field does. See SCHEMA.md.
SCHEMA_VERSION = 1

# Bumped whenever extraction behaviour changes such that an unchanged wheel would
# produce a different record. Part of the cache key, so a reader fix can never serve
# a stale cached record.
ANALYZER_VERSION = 28

__all__ = ["ANALYZER_VERSION", "SCHEMA_VERSION", "TOOL_NAME", "__version__"]
