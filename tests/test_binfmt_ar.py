"""Behaviour of `binfmt.ar.read_ar_members`.

Verified during development against real archives from GNU `ar` 2.46 (magic, header
layout, the `//` long-name table's `name/\\n` entries, odd-size padding) before this
suite was written; these tests pin that understanding with synthesized bytes, the same
"no compiler, no network, nothing committed as a binary blob" contract every other
binfmt test file keeps.
"""

from __future__ import annotations

import io

from helpers.binfmt import (
    AR_MAGIC,
    ET_REL,
    ArMember,
    DynSym,
    ElfBuilder,
    build_ar,
    gnu_symbol_table_member,
    pseudo_member,
)
from wheel_crypto_scan import evidence
from wheel_crypto_scan.binfmt.ar import read_ar_members
from wheel_crypto_scan.errors import AR_PARSE_ERROR
from wheel_crypto_scan.ruleset_loader import load_ruleset

PATTERNS = load_ruleset().compile_patterns().binary

IMPORTED_OPENSSL = DynSym("EVP_DigestInit_ex", defined=False)
DEFINED_OPENSSL = DynSym("EVP_DigestInit_ex", defined=True)


def _read(data: bytes, path: str = "pkg/lib.a", *, vendored: bool = False):
    return read_ar_members(io.BytesIO(data), path, PATTERNS, vendored=vendored)


# --- the container: members become separate objects --------------------------------


def test_a_single_member_archive_is_read_as_one_object() -> None:
    member = ElfBuilder(dynsyms=(IMPORTED_OPENSSL,)).build()
    data = build_ar([ArMember("a.o", member)])
    binaries, errors = _read(data)

    assert errors == ()
    assert len(binaries) == 1
    assert binaries[0].path == "pkg/lib.a(a.o)"
    assert binaries[0].format == evidence.FORMAT_ELF
    assert {m.name for m in binaries[0].matched_symbols} == {"EVP_DigestInit_ex"}


def test_multiple_members_each_become_their_own_object() -> None:
    a = ElfBuilder(dynsyms=(IMPORTED_OPENSSL,)).build()
    b = ElfBuilder(rodata=b"nothing crypto here\x00").build()
    data = build_ar([ArMember("a.o", a), ArMember("b.o", b)])
    binaries, errors = _read(data)

    assert errors == ()
    assert [b.path for b in binaries] == ["pkg/lib.a(a.o)", "pkg/lib.a(b.o)"]
    assert binaries[0].matched_symbols
    assert not binaries[1].matched_symbols


def test_vendored_propagates_to_every_member() -> None:
    data = build_ar([ArMember("a.o", ElfBuilder().build()), ArMember("b.o", ElfBuilder().build())])
    binaries, _errors = read_ar_members(
        io.BytesIO(data), "pkg/.libs/lib.a", PATTERNS, vendored=True
    )
    assert all(b.vendored_path for b in binaries)


def test_an_odd_sized_member_is_padded_and_the_next_member_still_reads() -> None:
    """`ar` pads odd-sized member data with one `\\n` byte; the offset math for the
    *next* header must account for it or the walk desyncs onto that padding byte.
    """
    odd = ElfBuilder(rodata=b"OpenSSL 3.0.14\x00").build()
    assert len(odd) % 2 == 1, "the fixture itself needs to be odd-sized for this test"
    clean = ElfBuilder(dynsyms=(IMPORTED_OPENSSL,)).build()
    data = build_ar([ArMember("odd.o", odd), ArMember("clean.o", clean)])
    binaries, errors = _read(data)

    assert errors == ()
    assert len(binaries) == 2
    assert binaries[1].path == "pkg/lib.a(clean.o)"
    assert binaries[1].matched_symbols


# --- GNU and BSD naming conventions -------------------------------------------------


def test_a_gnu_long_name_resolves_through_the_table() -> None:
    long_name = "this_is_a_very_long_object_file_name_past_fifteen_chars.o"
    data = build_ar(
        [ArMember(long_name, ElfBuilder(dynsyms=(IMPORTED_OPENSSL,)).build())], name_style="gnu"
    )
    binaries, errors = _read(data)

    assert errors == ()
    assert binaries[0].path == f"pkg/lib.a({long_name})"


def test_two_gnu_long_names_share_one_table_entry_when_identical() -> None:
    """`build_ar`'s own table-building only writes a repeated long name once; confirms
    `read_ar_members` still resolves both references correctly, not just the first."""
    long_name = "this_is_a_very_long_object_file_name_past_fifteen_chars.o"
    a = ElfBuilder(dynsyms=(IMPORTED_OPENSSL,)).build()
    b = ElfBuilder(rodata=b"second copy\x00").build()
    data = build_ar([ArMember(long_name, a), ArMember(long_name, b)], name_style="gnu")
    binaries, errors = _read(data)

    assert errors == ()
    assert [b.path for b in binaries] == [
        f"pkg/lib.a({long_name})",
        f"pkg/lib.a({long_name}#2)",
    ]


def test_a_bsd_extended_name_resolves_from_the_members_own_data() -> None:
    data = build_ar(
        [ArMember("bsd_extended_name.o", ElfBuilder(dynsyms=(IMPORTED_OPENSSL,)).build())],
        name_style="bsd",
    )
    binaries, errors = _read(data)

    assert errors == ()
    assert binaries[0].path == "pkg/lib.a(bsd_extended_name.o)"
    assert binaries[0].matched_symbols


def test_the_gnu_symbol_table_member_is_skipped_not_read_as_an_object() -> None:
    """The bare `/` member is `ar`'s own symbol index, not a real object; a reader
    that mistook it for one would add a spurious, low-value `FORMAT_UNKNOWN` entry.
    """
    real = ElfBuilder(dynsyms=(IMPORTED_OPENSSL,)).build()
    data = AR_MAGIC + gnu_symbol_table_member(["EVP_DigestInit_ex"])
    header = build_ar([ArMember("a.o", real)])[len(AR_MAGIC) :]
    data += header
    binaries, errors = _read(data)

    assert errors == ()
    assert len(binaries) == 1
    assert binaries[0].path == "pkg/lib.a(a.o)"


def test_bsd_symdef_variants_and_gnu_sym64_are_also_skipped() -> None:
    """#99's adversarial review: every real index/padding convention a real
    toolchain writes, not just GNU's bare `/`. Before this fix, an ordinary macOS
    (`__.SYMDEF`) or GNU 64-bit (`/SYM64/`) archive -- the everyday shape, not a
    crafted one -- picked up a spurious `FORMAT_UNKNOWN` entry per index member and
    the `BIN_PARTIAL_FORMAT` verdict hit that comes with it.
    """
    real = ElfBuilder(dynsyms=(IMPORTED_OPENSSL,)).build()
    for index_name in ("__.SYMDEF", "__.SYMDEF SORTED", "__.SYMDEF_64", "/SYM64/"):
        data = (
            AR_MAGIC
            + pseudo_member(index_name)
            + build_ar([ArMember("a.o", real)])[len(AR_MAGIC) :]
        )
        binaries, errors = _read(data)

        assert errors == (), index_name
        assert len(binaries) == 1, index_name
        assert binaries[0].path == "pkg/lib.a(a.o)", index_name


# --- a name that cannot be resolved is still read, never silently dropped ----------


def test_an_out_of_range_gnu_offset_is_still_read_under_a_synthetic_path() -> None:
    """#99's adversarial review: an earlier version of this module dropped the whole
    member -- no evidence, no error -- when its name could not be resolved. A wheel
    whose only crypto evidence was in that member read `NO_CRYPTO_DETECTED` with an
    empty `errors[]`, the exact thing "unreadable means OPAQUE, never
    NO_CRYPTO_DETECTED" exists to prevent. The member's bytes are read and reported
    under `member@<offset>` instead, with its own `AR_PARSE_ERROR`.
    """
    member = ElfBuilder(rodata=b"OpenSSL 3.0.14 4 Jun 2024\x00").build()
    data = bytearray(build_ar([ArMember("a.o", member)], name_style="gnu"))
    # `a.o` is short, so `build_ar` wrote it inline (no `//` table exists at all);
    # point the name field at a GNU long-name reference regardless, which
    # `_resolve_name` must refuse since `long_names` is empty.
    name_field_start = len(AR_MAGIC)
    data[name_field_start : name_field_start + 16] = b"/0".ljust(16, b" ")
    binaries, errors = _read(bytes(data))

    assert len(binaries) == 1
    assert binaries[0].path == "pkg/lib.a(member@8)"
    assert any("OpenSSL 3." in m.value for m in binaries[0].matched_strings)
    assert [e.kind for e in errors] == [AR_PARSE_ERROR]
    assert "unresolvable name" in errors[0].message


def test_an_oversized_bsd_length_is_still_read_under_a_synthetic_path() -> None:
    member = ElfBuilder(rodata=b"OpenSSL 3.0.14 4 Jun 2024\x00").build()
    data = bytearray(build_ar([ArMember("x", member)], name_style="bsd"))
    name_field_start = len(AR_MAGIC)
    data[name_field_start : name_field_start + 16] = b"#1/999999".ljust(16, b" ")
    binaries, errors = _read(bytes(data))

    assert len(binaries) == 1
    assert binaries[0].path == "pkg/lib.a(member@8)"
    assert any("OpenSSL 3." in m.value for m in binaries[0].matched_strings)
    assert [e.kind for e in errors] == [AR_PARSE_ERROR]


def test_an_unterminated_long_name_entry_is_unresolvable_not_truncated() -> None:
    """Reporting the rest of the table as the name -- what an earlier version of
    this module did when a `/\\n` terminator never appeared -- is the same "a name
    reported is a name read in full" failure this repo's other binary readers were
    both found and fixed for. A `/<offset>` into a run with no terminator must be
    unresolvable, not a name nobody wrote.
    """
    member = ElfBuilder(rodata=b"OpenSSL 3.0.14 4 Jun 2024\x00").build()
    long_name = "this_is_a_very_long_object_file_name_past_fifteen_chars.o"
    data = bytearray(build_ar([ArMember(long_name, member)], name_style="gnu"))
    # Find the `//` table (right after the magic) and corrupt its terminator.
    table_start = len(AR_MAGIC) + 60
    table = bytes(data[table_start : table_start + len(long_name) + 2])
    assert table == (long_name + "/\n").encode("ascii")
    data[table_start + len(long_name)] = ord("X")  # was "/", now never terminates
    binaries, errors = _read(bytes(data))

    assert len(binaries) == 1
    assert not binaries[0].path.startswith(f"pkg/lib.a({long_name}")
    assert [e.kind for e in errors] == [AR_PARSE_ERROR]


def test_an_archive_with_only_pseudo_members_still_produces_a_fallback_record() -> None:
    """No real object at all, and no walk failure either -- the fallback must not
    depend on `table_errors` being non-empty, only on no real member being found.
    """
    data = AR_MAGIC + gnu_symbol_table_member(["EVP_DigestInit_ex"])
    binaries, errors = _read(data)

    assert errors == ()
    assert len(binaries) == 1
    assert binaries[0].path == "pkg/lib.a"
    assert binaries[0].format == evidence.FORMAT_AR
    assert binaries[0].partial_reasons == (evidence.PARTIAL_AR_MEMBER_TABLE_UNREAD,)


def test_the_member_cap_bounds_dispatch_work_not_just_output_length(monkeypatch) -> None:
    """Per this repo's "break a guard to see whether it guards" rule: a cap that
    only trims the *output* after every member was already dispatched would pass
    `test_more_than_the_member_cap_truncates_rather_than_hangs` just as well as one
    that actually stops the work. Count real dispatches directly.
    """
    import wheel_crypto_scan.binfmt.ar as ar_module

    calls = {"n": 0}
    real_read_binary = ar_module.read_binary

    def counting_read_binary(*args, **kwargs):
        calls["n"] += 1
        return real_read_binary(*args, **kwargs)

    monkeypatch.setattr(ar_module, "read_binary", counting_read_binary)
    tiny = ElfBuilder().build()
    members = [ArMember(f"m{i}.o", tiny) for i in range(4200)]
    data = build_ar(members)
    binaries, _errors = _read(data)

    assert len(binaries) == 4096
    assert calls["n"] == 4096


# --- the documented gap: .symtab-only definitions are invisible to matching --------


def test_a_symtab_only_definition_is_matched_through_an_archive_member() -> None:
    """#117, closed: `binfmt.elf` now also matches crypto symbol groups against
    `.symtab` when `.dynsym` is absent -- exactly the relocatable-object shape every
    member of a real static archive has. `binfmt.ar` itself needed no change: once
    `binfmt.elf` reads the member's `.symtab`, the archive layer above it inherits the
    fix for free, the same as it did for every earlier `binfmt.elf` improvement.
    """
    member = ElfBuilder(
        e_type=ET_REL, dynsyms=(), with_symtab=True, symtab_syms=(DEFINED_OPENSSL,)
    ).build()
    data = build_ar([ArMember("crypto.o", member)])
    binaries, errors = _read(data)

    assert errors == ()
    assert binaries[0].symtab_count > 0
    assert evidence.SymbolMatch("EVP_DigestInit_ex", "openssl", evidence.BINDING_DEFINED) in (
        binaries[0].matched_symbols
    )


def test_a_banner_string_in_a_relocatable_object_is_still_found() -> None:
    """Strings-based detection reads every section regardless of symbol table, so a
    relocatable object without a matching symbol is still not `NO_CRYPTO_DETECTED`
    purely for that reason.
    """
    member = ElfBuilder(e_type=ET_REL, rodata=b"OpenSSL 3.0.14 4 Jun 2024\x00").build()
    data = build_ar([ArMember("crypto.o", member)])
    binaries, errors = _read(data)

    assert errors == ()
    assert any("OpenSSL 3." in m.value for m in binaries[0].matched_strings)


# --- a member table that cannot be walked ------------------------------------------


def test_a_truncated_header_falls_back_to_one_whole_archive_strings_record() -> None:
    data = AR_MAGIC + b"short"
    binaries, errors = _read(data)

    assert len(binaries) == 1
    assert binaries[0].path == "pkg/lib.a"
    assert binaries[0].format == evidence.FORMAT_AR
    assert binaries[0].partial_analysis is True
    assert binaries[0].partial_reasons == (evidence.PARTIAL_AR_MEMBER_TABLE_UNREAD,)
    assert [e.kind for e in errors] == [AR_PARSE_ERROR]


def test_the_whole_archive_fallback_still_finds_a_banner() -> None:
    """The fallback is `read_strings_only` over the raw archive bytes, so evidence a
    member would have carried is not necessarily lost even when the table itself
    cannot be walked -- the same "structure lost, evidence kept" contract every other
    reader's own fallback keeps.
    """
    data = AR_MAGIC + b"short but with a banner: OpenSSL 3.0.14 4 Jun 2024"
    binaries, _errors = _read(data)
    assert any("OpenSSL 3." in m.value for m in binaries[0].matched_strings)


def test_a_non_numeric_size_field_stops_the_walk_and_keeps_earlier_members() -> None:
    good = ElfBuilder(dynsyms=(IMPORTED_OPENSSL,)).build()
    second = ElfBuilder(rodata=b"unreachable\x00").build()
    data = bytearray(build_ar([ArMember("a.o", good), ArMember("b.o", second)]))
    # The second member's header starts right after the first member's own header
    # (60 bytes) and data, padded to an even offset.
    first_header_size = 60 + len(good) + (len(good) % 2)
    size_field_start = len(AR_MAGIC) + first_header_size + 48
    data[size_field_start : size_field_start + 10] = b"not-a-num "
    binaries, errors = _read(bytes(data))

    assert len(binaries) == 1
    assert binaries[0].path == "pkg/lib.a(a.o)"
    assert [e.kind for e in errors] == [AR_PARSE_ERROR]
    assert "non-numeric size" in errors[0].message


def test_a_size_overrunning_the_archive_stops_the_walk() -> None:
    """No member survives long enough to be read, so this hits the same whole-archive
    fallback the truncated-header and non-numeric-size cases do.
    """
    good = ElfBuilder(dynsyms=(IMPORTED_OPENSSL,)).build()
    data = bytearray(build_ar([ArMember("a.o", good)]))
    size_field_start = len(AR_MAGIC) + 48
    data[size_field_start : size_field_start + 10] = str(len(good) + 10_000).ljust(10).encode()
    binaries, errors = _read(bytes(data))

    assert len(binaries) == 1
    assert binaries[0].format == evidence.FORMAT_AR
    assert binaries[0].partial_reasons == (evidence.PARTIAL_AR_MEMBER_TABLE_UNREAD,)
    assert [e.kind for e in errors] == [AR_PARSE_ERROR]
    assert "past the end of the archive" in errors[0].message


def test_more_than_the_member_cap_truncates_rather_than_hangs() -> None:
    """A crafted archive with many tiny members must not cost one `read_binary`
    dispatch per member unboundedly; the cap truncates and says so, the same "capped,
    not silent" shape every other per-object limit in this tool takes.
    """
    tiny = b"\x00" * 4
    members = [ArMember(f"m{i}.bin", tiny) for i in range(4100)]
    data = build_ar(members)
    binaries, errors = _read(data)

    assert len(binaries) == 4096
    assert any(e.kind == AR_PARSE_ERROR and "members" in e.message for e in errors)
