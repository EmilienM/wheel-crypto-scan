"""Deterministic, dependency-free `ar`-format archive writer for `binfmt.ar` tests.

Built byte-for-byte with plain string formatting, the same "no compiler, no network,
nothing committed as a binary blob" contract `helpers.binfmt`'s other writers keep --
verified during development against real GNU `ar` 2.46 output (this repo's own
`ar rcs` on the host that wrote this file), not merely against the documented format.
"""

from __future__ import annotations

from dataclasses import dataclass

MAGIC = b"!<arch>\n"


def _field(value: str, width: int) -> bytes:
    text = value.encode("ascii")
    if len(text) > width:
        raise ValueError(f"{value!r} does not fit in {width} bytes")
    return text.ljust(width, b" ")


def _header(name_field: str, size: int) -> bytes:
    return (
        _field(name_field, 16)
        + _field("0", 12)  # mtime
        + _field("0", 6)  # uid
        + _field("0", 6)  # gid
        + _field("0", 8)  # mode
        + _field(str(size), 10)  # size
        + b"\x60\x0a"  # end-of-header magic
    )


@dataclass
class ArMember:
    """One real object to embed. `name` is what `read_ar_members` should recover,
    whatever convention (short inline, GNU long-name table, BSD `#1/N`) carries it."""

    name: str
    data: bytes


def build_ar(members: list[ArMember], *, name_style: str = "gnu") -> bytes:
    """Build a minimal, real `ar`-format archive holding `members` in order.

    `name_style`:
      - `"gnu"`: a name of 15 characters or fewer goes inline (`name/`, space-padded
        to the 16-byte field); a longer one goes through a GNU long-name table (a
        `//` pseudo-member holding every long name back to back, each terminated
        `/\\n`), referenced as `/<byte-offset-into-that-table>`. Matches real GNU
        `ar`'s own choice of convention per name.
      - `"bsd"`: every name goes through BSD's `#1/<N>` extended-name convention
        regardless of length -- the real name is the first `N` bytes of the
        member's own data, and the object's true content follows those bytes. A
        real BSD `ar` only does this for a name its short form cannot hold; this
        writer always does, so the convention is exercised however short the name.
    """
    body = bytearray()

    if name_style == "gnu":
        long_names = [member.name for member in members if len(member.name) > 15]
        offsets: dict[str, int] = {}
        table = bytearray()
        for name in long_names:
            if name not in offsets:
                offsets[name] = len(table)
                table += (name + "/\n").encode("ascii")
        if table:
            body += _header("//", len(table))
            body += table
            if len(table) % 2:
                body += b"\n"

    for member in members:
        data = member.data
        if name_style == "bsd":
            name_bytes = member.name.encode("utf-8")
            name_field = f"#1/{len(name_bytes)}"
            data = name_bytes + data
        elif name_style == "gnu" and len(member.name) > 15:
            name_field = f"/{offsets[member.name]}"
        else:
            name_field = member.name + "/"
        body += _header(name_field, len(data))
        body += data
        if len(data) % 2:
            body += b"\n"

    return MAGIC + bytes(body)


def gnu_symbol_table_member(symbol_names: list[str]) -> bytes:
    """The GNU `/` pseudo-member's own header, standing in for a real symbol table.

    `read_ar_members` never reads this member's *content* -- it exists only so a
    test can confirm the member named bare `/` is skipped rather than misread as a
    real object. The content shape (a big-endian count, big-endian offsets, then
    NUL-terminated names) is real GNU `ar`'s own, for readability; a `read_ar_members`
    caller has no use for it, and being real is not load-bearing here.
    """
    body = b"\x00" * 4
    for name in symbol_names:
        body += name.encode("ascii") + b"\x00"
    return _header("/", len(body)) + body + (b"\n" if len(body) % 2 else b"")


def pseudo_member(name: str, size: int = 4) -> bytes:
    """A whole-header-plus-data pseudo-member with an arbitrary `ar` index name
    (`__.SYMDEF`, `__.SYMDEF SORTED`, `__.SYMDEF_64`, `/SYM64/`, ...), content not
    load-bearing -- `read_ar_members` recognises these by name alone and never
    reads what they hold.
    """
    body = b"\x00" * size
    return _header(name, len(body)) + body + (b"\n" if len(body) % 2 else b"")
