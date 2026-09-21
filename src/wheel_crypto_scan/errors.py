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
# An `ar`-format archive's (`.a`/`.lib`) member table could not be walked to
# completion. See evidence.PARTIAL_AR_MEMBER_TABLE_UNREAD.
AR_PARSE_ERROR = "ar_parse_error"

# Python source.
PYTHON_SYNTAX_ERROR = "python_syntax_error"
PYTHON_DECODE_ERROR = "python_decode_error"
PYTHON_TOO_LARGE = "python_too_large"
# The interpreter's own parsing stack exhausted during `ast.parse` or the tree walk,
# not a real syntax defect: whether it fires depends on the interpreter's stack depth
# at scan time, not the wheel's bytes, unlike every other `PYTHON_SYNTAX_ERROR`
# occurrence (a real `SyntaxError`, or the deliberate null-byte check), both genuinely
# deterministic. `RecursionError` and `MemoryError` both reach here: CPython's PEG
# parser signals its own stack exhaustion for deep *expression* nesting as the latter
# ("Parser stack overflowed - Python source too complex to parse", measured across the
# whole py311-py314 support matrix), never `RecursionError`, which is what other deep
# recursion in this layer (the tree walk) can still raise. A distinct kind, not a flag
# on `PYTHON_SYNTAX_ERROR`, so it alone -- not the wheel's permanent syntax errors
# alongside it -- can be excluded from caching.
PYTHON_RECURSION_LIMIT_EXCEEDED = "python_recursion_limit_exceeded"

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
        AR_PARSE_ERROR,
        PYTHON_SYNTAX_ERROR,
        PYTHON_DECODE_ERROR,
        PYTHON_TOO_LARGE,
        PYTHON_RECURSION_LIMIT_EXCEEDED,
    }
)

# Archive- and member-stage kinds this scanner cannot yet prove are deterministic, so a
# record carrying one is not a final answer for its wheel -- caching it, or treating it
# as already done on `--resume`, would serve a transient failure forever.
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
# `ELF_PARSE_ERROR`, `MACHO_PARSE_ERROR` and `PE_PARSE_ERROR` share the identical shape,
# one layer below `MEMBER_READ_ERROR`: `binfmt/elf.py`, `binfmt/macho.py` and
# `binfmt/pe.py` each record their kind from several sites. Most of those sites are, in
# fact, deterministic -- plain comparisons over data already fully in hand, the same
# shape as `DUPLICATE_MEMBER`/`SIZE_LIMIT_EXCEEDED` below, and `pe.py` even has a
# genuinely narrow, exception-type-specific catch (`except _Malformed`, raised only from
# pure comparisons, never wrapping another exception) -- but each reader ALSO has at
# least one real `except Exception`-shaped site that can record the identical token for
# a transient reason (`MemoryError`, a flaky read), and `ScanError.kind` is the only
# granularity this vocabulary offers: it cannot tell which site produced a given record.
# A kind reachable through a broad catch anywhere therefore belongs in this set
# entirely, not just the specific call that happened to raise on a given run -- at the
# real, accepted cost that the deterministic majority of occurrences also gets
# needlessly re-scanned on every run. DESIGN.md, "A record produced without reading the
# wheel is never cached", has the measurement.
#
# `DUPLICATE_MEMBER`, `SIZE_LIMIT_EXCEEDED`, `COMPRESSION_RATIO_EXCEEDED` and
# `BINARY_TOO_LARGE` are deliberately not in this set: each is a comparison or a dict
# lookup over zip metadata already fully in hand (a filename seen twice, a size field
# against a limit), with no I/O and no broad catch anywhere on the path that records
# it, so the same wheel's bytes always produce the same one and caching it is safe.
#
# `PYTHON_RECURSION_LIMIT_EXCEEDED` is split out of `PYTHON_SYNTAX_ERROR` so that it can
# join this set alone. Unlike `PYTHON_SYNTAX_ERROR`, which also fires for a genuine,
# permanent `SyntaxError` and for a deliberate null-byte check -- both deterministic,
# and needlessly re-scanned forever if the whole kind joined this set -- every site that
# records this kind is the identical `except (RecursionError, MemoryError)`, catching a
# parsing-stack failure that depends on the interpreter's state at scan time, not the
# wheel's bytes alone: the same source can cross the threshold on one interpreter in the
# support matrix and not another. A kind reachable only through that catch belongs here
# outright, the same reasoning that puts the three `*_parse_error` kinds above here for
# a broad `except Exception`, just for a catch narrower still.
#
# For a *fixed* interpreter this cause is fully deterministic, so a wheel that
# genuinely, permanently exhausts the parsing stack pays the same re-scan-forever
# cost the three `*_parse_error` kinds pay, for the same reason: there is no cheaper
# way to split a deterministic occurrence of this kind from one that would resolve
# differently on a different run without a narrower token than `ScanError.kind`
# offers today.
#
# `layers/metadata.py`'s SBOM reader catches `RecursionError` too (deeply nested
# CycloneDX JSON), recording `SBOM_PARSE_ERROR` alongside four deterministic causes in
# the same broad `except` -- the identical shape, not split out. Left open: the split
# covers `layers/python_ast.py` only, and the blast radius differs (one SBOM, not the
# whole wheel's Python evidence).
#
# See DESIGN.md, "A record produced without reading the wheel is never cached."
SCAN_ABORTED_KINDS: frozenset[str] = frozenset(
    {
        BAD_ZIP,
        UNEXPECTED_ERROR,
        MEMBER_READ_ERROR,
        ELF_PARSE_ERROR,
        MACHO_PARSE_ERROR,
        PE_PARSE_ERROR,
        PYTHON_RECURSION_LIMIT_EXCEEDED,
    }
)


class RulesetError(Exception):
    """The shipped or supplied ruleset is malformed. Raised at load time, never later."""


class WheelReadError(Exception):
    """A wheel could not be opened at all. Aborts that wheel, never the run."""
