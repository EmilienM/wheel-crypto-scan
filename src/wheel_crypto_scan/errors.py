"""The vocabulary of non-fatal scan failures.

Every failure the scanner can survive has a stable `kind` string here. The ruleset
matches on these strings in `[rule.match] kind = "scan_error"`, so adding a kind to the
scanner means adding it here first, and a kind named by the ruleset that does not exist
here is a load-time error.

Kinds are part of the output contract. Rename one only with a schema version bump.
"""

from __future__ import annotations

# Archive level.
BAD_ZIP = "bad_zip"
DUPLICATE_MEMBER = "duplicate_member"
SIZE_LIMIT_EXCEEDED = "size_limit_exceeded"
COMPRESSION_RATIO_EXCEEDED = "compression_ratio_exceeded"
MEMBER_READ_ERROR = "member_read_error"

# Distribution metadata.
DIST_INFO_MISSING = "dist_info_missing"
DIST_INFO_AMBIGUOUS = "dist_info_ambiguous"
METADATA_MISSING = "metadata_missing"
METADATA_DECODE_ERROR = "metadata_decode_error"
WHEEL_MISSING = "wheel_missing"
WHEEL_FILENAME_INVALID = "wheel_filename_invalid"
RECORD_MISSING = "record_missing"
RECORD_PARSE_ERROR = "record_parse_error"
SBOM_PARSE_ERROR = "sbom_parse_error"

# Native binaries.
ELF_PARSE_ERROR = "elf_parse_error"
MACHO_PARSE_ERROR = "macho_parse_error"
BINARY_TRUNCATED = "binary_truncated"
BINARY_TOO_LARGE = "binary_too_large"
BINARY_UNKNOWN_FORMAT = "binary_unknown_format"

# Python source.
PYTHON_SYNTAX_ERROR = "python_syntax_error"
PYTHON_DECODE_ERROR = "python_decode_error"
PYTHON_TOO_LARGE = "python_too_large"

ERROR_KINDS: frozenset[str] = frozenset(
    {
        BAD_ZIP,
        DUPLICATE_MEMBER,
        SIZE_LIMIT_EXCEEDED,
        COMPRESSION_RATIO_EXCEEDED,
        MEMBER_READ_ERROR,
        DIST_INFO_MISSING,
        DIST_INFO_AMBIGUOUS,
        METADATA_MISSING,
        METADATA_DECODE_ERROR,
        WHEEL_MISSING,
        WHEEL_FILENAME_INVALID,
        RECORD_MISSING,
        RECORD_PARSE_ERROR,
        SBOM_PARSE_ERROR,
        ELF_PARSE_ERROR,
        MACHO_PARSE_ERROR,
        BINARY_TRUNCATED,
        BINARY_TOO_LARGE,
        BINARY_UNKNOWN_FORMAT,
        PYTHON_SYNTAX_ERROR,
        PYTHON_DECODE_ERROR,
        PYTHON_TOO_LARGE,
    }
)


class RulesetError(Exception):
    """The shipped or supplied ruleset is malformed. Raised at load time, never later."""


class WheelReadError(Exception):
    """A wheel could not be opened at all. Aborts that wheel, never the run."""
