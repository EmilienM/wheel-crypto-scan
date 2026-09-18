"""Format sniffing from a handful of leading bytes.

Detection never opens the object itself: it looks only at magic numbers, so it works
identically whether `stream` is a real file, a `BytesIO`, or a zip member wrapper that
has not been asked to seek yet.
"""

from __future__ import annotations

from .. import evidence

# Four bytes is enough to tell ELF, Mach-O (thin or fat, either byte order) and PE
# apart; nothing here needs to look past the magic number.
SNIFF_BYTES = 4

_ELF_MAGIC = b"\x7fELF"

# Mach-O thin magics, 32- and 64-bit, both byte orders, plus the fat (universal)
# magic. The "swapped" forms are what a little-endian host's raw bytes look like for
# a magic that is conventionally quoted big-endian, and vice versa.
_MACHO_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",  # MH_MAGIC (32-bit, big-endian header fields)
        b"\xce\xfa\xed\xfe",  # MH_CIGAM (32-bit, little-endian header fields)
        b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 (64-bit, big-endian header fields)
        b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 (64-bit, little-endian header fields)
        b"\xca\xfe\xba\xbe",  # FAT_MAGIC (universal binary; fat header is big-endian)
        b"\xbe\xba\xfe\xca",  # FAT_CIGAM (defensive: the byte-swapped form)
    }
)

_PE_MAGIC = b"MZ"


def detect_format(head: bytes) -> str:
    """Classify an object from its leading bytes alone.

    `head` should hold at least `SNIFF_BYTES` bytes; a shorter head simply fails every
    check and falls through to `FORMAT_UNKNOWN`, which is the safe default: an object
    we cannot identify still gets scanned for strings rather than skipped.
    """
    if head.startswith(_ELF_MAGIC):
        return evidence.FORMAT_ELF
    if head[:4] in _MACHO_MAGICS:
        return evidence.FORMAT_MACHO
    if head.startswith(_PE_MAGIC):
        return evidence.FORMAT_PE
    return evidence.FORMAT_UNKNOWN
