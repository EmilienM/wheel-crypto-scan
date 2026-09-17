"""Deterministic FIPS-risk evidence inspector for Python wheels.

The tool gathers crypto-relevant evidence statically and never decides compliance.
See SCHEMA.md for the output contract and data/ruleset.toml for the rules.
"""

TOOL_NAME = "wheel-crypto-scan"

__version__ = "0.1.0"

# Breaking changes to the output contract only. Adding optional keys or new rule ids
# does not bump this; removing or retyping a field does. See SCHEMA.md.
SCHEMA_VERSION = 1

# Bumped whenever extraction behaviour changes such that an unchanged wheel would
# produce a different record. Part of the cache key, so a reader fix can never serve
# a stale cached record.
ANALYZER_VERSION = 1

__all__ = ["ANALYZER_VERSION", "SCHEMA_VERSION", "TOOL_NAME", "__version__"]
