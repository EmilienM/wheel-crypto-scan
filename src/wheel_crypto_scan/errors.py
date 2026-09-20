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
# An exception `_collect` did not specifically anticipate cut the read short before
# anything else ran: a `MemoryError` under load, a transient I/O error, an unforeseen
# bug. Distinct from `BAD_ZIP`, which is a specific, checked claim about the archive's
# own bytes (`zipfile.BadZipFile` or similar) -- this kind makes no claim about the
# wheel at all, so it must never be asserted for a wheel whose only problem was timing.
UNEXPECTED_ERROR = "unexpected_error"

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
PE_PARSE_ERROR = "pe_parse_error"
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
        UNEXPECTED_ERROR,
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
        PE_PARSE_ERROR,
        BINARY_TRUNCATED,
        BINARY_TOO_LARGE,
        BINARY_UNKNOWN_FORMAT,
        PYTHON_SYNTAX_ERROR,
        PYTHON_DECODE_ERROR,
        PYTHON_TOO_LARGE,
    }
)

# Archive- and member-stage kinds this scanner cannot yet prove are deterministic, so a
# record carrying one is not a final answer for its wheel -- caching it, or treating it
# as already done on `--resume`, risks serving a transient failure forever, the bug #64
# was filed about. Not exhaustive: binfmt's own parse-error kinds share this risk one
# layer down and are out of this set's scope for now (#97).
#
# `BAD_ZIP` and `UNEXPECTED_ERROR` abort `_collect` outright: nothing past the open
# ever ran, from a catch (in `wheelfile.WheelArchive.__init__` and `scan.scan_wheel`
# respectively) broad enough to admit it does not know what went wrong. `MEMBER_READ_ERROR`
# does *not* abort anything -- a scan that hits it keeps going and still reports
# whatever else it read -- but every site that records it (`wheelfile.read`,
# `layers/binaries.py`, `layers/metadata.py`, `layers/python_ast.py`) reaches it
# through a catch just as broad, wide enough to admit a transient `MemoryError` or
# `OSError` alongside a genuinely corrupt member, with nothing downstream able to
# tell which one actually happened. What all three share is not "the scan was
# aborted" -- only two of them abort anything -- but "the code path that recorded
# this could not have told a content defect from an outside interruption apart."
#
# `DUPLICATE_MEMBER`, `SIZE_LIMIT_EXCEEDED`, `COMPRESSION_RATIO_EXCEEDED` and
# `BINARY_TOO_LARGE` are deliberately not in this set: each is a comparison or a dict
# lookup over zip metadata already fully in hand (a filename seen twice, a size field
# against a limit), with no I/O and no broad catch anywhere on the path that records
# it, so the same wheel's bytes always produce the same one and caching it is safe.
#
# See DECISIONS.md, "A record produced without reading the wheel is never cached."
SCAN_ABORTED_KINDS: frozenset[str] = frozenset({BAD_ZIP, UNEXPECTED_ERROR, MEMBER_READ_ERROR})


class RulesetError(Exception):
    """The shipped or supplied ruleset is malformed. Raised at load time, never later."""


class WheelReadError(Exception):
    """A wheel could not be opened at all. Aborts that wheel, never the run."""
