"""`partial_reasons`: the tokens that say *why* an object was not read in full.

`partial_analysis` is one boolean with a dozen causes behind it, and five of them record
no `ScanError` at all, so a record could read `partial_analysis: true, errors: []` with
no way to tell which applied. Two of the five are the common case rather than an exotic
one: a stripped Mach-O, which is every release macOS wheel, and an ordinal-only PE
import, because `WS2_32` is normally bound by ordinal. Both read identically to "we
could parse nothing at all".

These tests hold the two fields to agreeing with each other, and hold every token the
readers can emit to being one the vocabulary declares.
"""

from __future__ import annotations

import io
import json
import tomllib
from importlib.resources import files
from pathlib import Path

import pytest

from helpers.binfmt import (
    E_SHNUM_OFFSET,
    SHF_COMPRESSED,
    DynSym,
    ElfBuilder,
    MachOBuilder,
    MachOSym,
    PEBuilder,
    PEExport,
    PEImport,
    append_duplicate_dynsym_section,
    build_fat,
    patch_header_field,
    patch_section_header,
    patch_u16,
)
from helpers.binfmt.macho import LC_LOAD_DYLIB
from wheel_crypto_scan import evidence
from wheel_crypto_scan.binfmt import elf as elf_module
from wheel_crypto_scan.binfmt import read_binary
from wheel_crypto_scan.binfmt.elf import read_elf
from wheel_crypto_scan.engine import apply_rules
from wheel_crypto_scan.evidence import ArtifactInventory, Evidence
from wheel_crypto_scan.errors import RulesetError
from wheel_crypto_scan.linkage import resolve_linkage
from wheel_crypto_scan.ruleset_loader import load_ruleset, parse_ruleset, routine_reasons

PATTERNS = load_ruleset().compile_patterns().binary


def _read(data: bytes, path: str = "obj"):
    return read_binary(io.BytesIO(data), path, PATTERNS, vendored=False)


def _reasons(data: bytes) -> list[str]:
    ev, _ = _read(data)
    return list(ev.partial_reasons)


def _read_bounded(data: bytes, budget: int, path: str = "obj"):
    """Read with a byte budget small enough to stop short of the object's end.

    The real budget is 64 MiB, so a fixture that reached it by being large would be a
    64 MiB fixture. Every reader takes the bound as an argument for exactly this.
    """
    return read_binary(io.BytesIO(data), path, PATTERNS, vendored=False, max_strings_bytes=budget)


# --- the two fields can never disagree ---------------------------------------

_CASES: dict[str, bytes] = {
    "clean elf": ElfBuilder(dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),)).build(),
    "elf header unread": b"\x7fELF" + b"\x00" * 12 + b"OpenSSL 3.0.14 4 Jun 2024",
    "elf section table truncated": patch_u16(
        ElfBuilder(rodata=b"OpenSSL 3.0.14 4 Jun 2024\x00").build(),
        E_SHNUM_OFFSET[64],
        0xFFFF,
        big_endian=False,
    ),
    "clean macho": MachOBuilder(
        id_dylib="libfoo.dylib", symbols=(MachOSym("_EVP_DigestInit_ex", defined=False),)
    ).build(),
    "macho stripped": MachOBuilder(id_dylib="libfoo.dylib").build(),
    "macho header unread": b"\xca\xfe\xba\xbe" + b"OpenSSL 3.0.14 4 Jun 2024",
    "pe header unread": b"MZ" + b"\x00" * 8,
    "pe with imports": PEBuilder(
        imports=(PEImport("libcrypto-3-x64.dll", names=("EVP_DigestInit_ex",)),),
        dll_name="_ext.pyd",
        exports=(PEExport("PyInit__ext"),),
    ).build(),
    "pe ordinal import": PEBuilder(
        imports=(PEImport("WS2_32.dll", ordinals=(115,)),), dll_name="_ext.pyd"
    ).build(),
    "unknown format": b"\x00\x01\x02\x03 OpenSSL 3.0.14 4 Jun 2024 ",
}


# One object per cause, so `test_every_reason_is_reachable_from_some_object` proves the
# vocabulary is live rather than merely declared.
_REACHABILITY: dict[str, bytes] = {
    "pe section table truncated": PEBuilder(
        imports=(PEImport("libcrypto-3-x64.dll", names=("EVP_DigestInit_ex",)),),
        dll_name="_ext.pyd",
        truncate_to=0x150,
    ).build(),
    "pe import directory unwalkable": PEBuilder(
        imports=(PEImport("libcrypto-3-x64.dll", names=("EVP_DigestInit_ex",)),),
        dll_name="_ext.pyd",
        declared_import_rva=0x7F000000,
    ).build(),
    "pe export directory unreadable": PEBuilder(
        dll_name="_ext.pyd",
        exports=(PEExport("PyInit__ext"),),
        declared_export_rva=0x7F000000,
    ).build(),
    "pe ordinal export": PEBuilder(
        imports=(PEImport("libcrypto-3-x64.dll", names=("EVP_DigestInit_ex",)),),
        dll_name="_ext.pyd",
        exports=(PEExport("PyInit__ext"),),
        unnamed_exports=1,
    ).build(),
    "pe delay load": PEBuilder(
        imports=(PEImport("libcrypto-3-x64.dll", names=("EVP_DigestInit_ex",)),),
        dll_name="_ext.pyd",
        delay_import_directory=True,
    ).build(),
    # `e_shoff == 0`: a loadable object with no section header table at all, not a
    # table that failed to read. #56.
    "elf section table absent": patch_header_field(
        patch_header_field(
            ElfBuilder(rodata=b"OpenSSL 3.0.14 4 Jun 2024\x00").build(), "e_shnum", 0
        ),
        "e_shoff",
        0,
    ),
    # Two `SHT_DYNSYM` sections: which one is real cannot be told from the type alone.
    "elf section type ambiguous": append_duplicate_dynsym_section(
        ElfBuilder(
            needed=("libc.so.6",), dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),)
        ).build()
    ),
    # `.dynamic` whose bytes lie outside the object: the handler the motivating case
    # for this field was described by, reached without a monkeypatch.
    "elf dynamic section unreadable": patch_section_header(
        ElfBuilder(
            needed=("libcrypto.so.3",),
            dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
        ).build(),
        ".dynamic",
        "sh_offset",
        1 << 30,
    ),
    # `e_shnum == 0` skips the proactive truncation check, so the section count is read
    # from a header table that is not there.
    "elf section count unreadable": patch_header_field(
        patch_header_field(
            ElfBuilder(rodata=b"OpenSSL 3.0.14 4 Jun 2024\x00").build(), "e_shnum", 0
        ),
        "e_shoff",
        1 << 30,
    ),
    # A section flagged compressed over bytes that are not: the first 24 bytes of
    # this text decode as a `Chdr` whose `ch_size` is some large accident of the
    # ASCII (~3.76 * 10^18 here), well over the budget, so `_bounded_section_data`
    # refuses it before `.data()` is ever called. Before that guard existed, this
    # used to reach `.data()`, which raised there instead -- either way this was once
    # the one failure in the reader that recorded nothing at all.
    "elf section data unreadable": patch_section_header(
        ElfBuilder(
            rodata=b"OpenSSL 3.0.14 4 Jun 2024\x00",
            dynsyms=(DynSym("memcpy", defined=False),),
        ).build(),
        ".rodata",
        "sh_flags",
        SHF_COMPRESSED,
        bitwise_or=True,
    ),
    # `pyelftools` raises here, which is where its failures actually surface: a
    # `.dynamic` naming a string table that does not exist takes the section header
    # with it, and `needed` comes back empty from a read that failed rather than from
    # an object with no dependencies.
    "elf section header unreadable": ElfBuilder(
        needed=("libcrypto.so.3",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
        dynamic_strtab_broken=True,
    ).build(),
    # The one cause both readers name the same way: a count that understates the rows,
    # told once with `sh_size` and once with `nsyms`.
    "elf dynsym understates rows": patch_section_header(
        ElfBuilder(
            needed=("libcrypto.so.3",),
            dynsyms=(
                DynSym("PyInit__ext", defined=True),
                DynSym("EVP_DigestInit_ex", defined=False),
            ),
        ).build(),
        ".dynsym",
        "sh_size",
        24,
    ),
    "macho symtab understates rows": MachOBuilder(
        id_dylib="_ext.so",
        load_dylibs=("/usr/lib/libSystem.B.dylib",),
        symbols=(MachOSym("_EVP_DigestInit_ex", defined=False),),
        declared_nsyms=0,
    ).build(),
    "macho fat slice unread": build_fat(
        [
            MachOBuilder(
                id_dylib="libfoo.dylib", symbols=(MachOSym("_EVP_DigestInit_ex", defined=False),)
            ).build(),
            b"\x00" * 64,
        ]
    ),
    # #59: a dylib-loading command whose name offset lands outside its own body. No
    # name payload at all, so the offset has nothing to point at.
    "macho dylib name unread": MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("_EVP_DigestInit_ex", defined=False),),
        malformed_dylib_cmd=LC_LOAD_DYLIB,
        malformed_dylib_name_offset=1000,
    ).build(),
    # #84: a `cmdsize` claiming to run past the load commands, so the walk stops
    # rather than trusting a value that already lied about its own extent.
    "macho load command walk truncated": MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("_EVP_DigestInit_ex", defined=False),),
        poison_cmdsize=0x10000,
    ).build(),
}


def test_the_boolean_and_the_reasons_never_disagree() -> None:
    """`partial_reasons` is non-empty exactly when `partial_analysis` is true.

    Consumers filter on the boolean, so a reader that set one without the other would
    either hide a cause or invent one.
    """
    for name, data in {**_CASES, **_REACHABILITY}.items():
        ev, _ = _read(data)
        assert bool(ev.partial_reasons) is ev.partial_analysis, name


def test_every_reason_a_reader_emits_is_one_the_vocabulary_declares() -> None:
    """A typo'd token is a record nothing downstream can key on."""
    for name, data in {**_CASES, **_REACHABILITY}.items():
        ev, _ = _read(data)
        assert set(ev.partial_reasons) <= evidence.PARTIAL_REASONS, name


def test_reasons_are_sorted_and_deduplicated() -> None:
    """The record is byte-identical run to run, so this cannot come back in set order."""
    for name, data in {**_CASES, **_REACHABILITY}.items():
        ev, _ = _read(data)
        assert list(ev.partial_reasons) == sorted(set(ev.partial_reasons)), name


# --- the causes each name themselves -----------------------------------------


def test_a_format_with_no_structural_reader_names_that_cause() -> None:
    """The token names the cause, not the coping.

    Every object whose header would not parse is read for strings alone too, so a token
    called `strings_only` would not tell those records apart from this one.
    """
    assert _reasons(_CASES["unknown format"]) == [evidence.PARTIAL_NO_STRUCTURAL_READER]


def test_an_elf_header_that_would_not_parse_says_so() -> None:
    assert _reasons(_CASES["elf header unread"]) == [evidence.PARTIAL_ELF_HEADER_UNREAD]


def test_a_truncated_elf_section_table_is_its_own_cause() -> None:
    """The header parsed. Only what it pointed at did not, which is a different fact.

    The record carries `machine`, `bits`, `endian` and `elf_type` read from that header,
    so a token saying the header was unread would contradict the record beside it. PE
    has always given this shape its own name.
    """
    ev, _ = _read(_CASES["elf section table truncated"])
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_SECTION_TABLE_TRUNCATED]
    assert ev.machine == "EM_X86_64"


def test_a_macho_header_that_would_not_parse_says_so() -> None:
    assert _reasons(_CASES["macho header unread"]) == [evidence.PARTIAL_MACHO_HEADER_UNREAD]


def test_a_stripped_macho_says_its_symbol_table_was_not_read() -> None:
    """No `LC_SYMTAB` is the Mach-O spelling of an unread imported/defined split."""
    assert _reasons(_CASES["macho stripped"]) == [evidence.PARTIAL_MACHO_SYMTAB_INCOMPLETE]


def test_an_unreadable_fat_slice_says_so() -> None:
    thin = MachOBuilder(
        id_dylib="libfoo.dylib", symbols=(MachOSym("_EVP_DigestInit_ex", defined=False),)
    ).build()
    assert _reasons(build_fat([thin, b"\x00" * 64])) == [evidence.PARTIAL_MACHO_FAT_SLICE_UNREAD]


def test_a_pe_header_that_would_not_parse_says_so() -> None:
    assert _reasons(_CASES["pe header unread"]) == [evidence.PARTIAL_PE_HEADER_UNREAD]


def test_an_ordinal_only_pe_import_is_named_rather_than_left_to_the_boolean() -> None:
    """The case the issue was filed for: routine on Windows, and it recorded no error.

    `WS2_32` is normally bound by ordinal, so this is the typical `.pyd` record. It has
    always been `partial_analysis: true` with `errors: []`, indistinguishable from an
    object nothing could be read from.
    """
    ev, errors = _read(_CASES["pe ordinal import"])
    assert ev.partial_analysis is True
    assert errors == ()  # still no error: an ordinal import is routine, not a failure
    assert evidence.PARTIAL_PE_ORDINAL_IMPORT in ev.partial_reasons


def test_a_readable_object_names_no_reasons() -> None:
    for name in ("clean elf", "clean macho", "pe with imports"):
        ev, _ = _read(_CASES[name])
        assert ev.partial_analysis is False, name
        assert ev.partial_reasons == (), name


def test_several_causes_are_all_reported() -> None:
    """The point of an array: the boolean collapsed a seven-clause conjunction."""
    data = PEBuilder(
        imports=(PEImport("WS2_32.dll", ordinals=(115,)),),
        dll_name="_ext.pyd",
        delay_import_directory=True,
    ).build()
    ev, _ = _read(data)
    assert evidence.PARTIAL_PE_ORDINAL_IMPORT in ev.partial_reasons
    assert evidence.PARTIAL_PE_DELAY_LOAD in ev.partial_reasons
    assert len(ev.partial_reasons) >= 2


# --- a reading gap is a cause; a recording cap is not ------------------------

# The last thing in the object, so a budget can be set to stop short of it. It is also
# the entire crypto evidence a `cryptography` 42 extension carries: OpenSSL is compiled
# in, so there is no library file, no dependency and no exported symbol to find.
_BANNER = b"OpenSSL 3.0.14 4 Jun 2024\x00"
_BANNER_AT_THE_END = PEBuilder(
    dll_name="_ext.pyd",
    imports=(PEImport("python311.dll", names=("Py_Initialize",)),),
    exports=(PEExport("PyInit__ext"),),
    trailing=b"\x00" * 4096 + _BANNER,
).build()


def test_a_budget_that_stops_short_of_the_banner_says_so() -> None:
    """The object is the same object; only how much of it we read changed.

    `strings_truncated` said so all along and nothing downstream could see it, because
    it is not `partial_analysis` and no policy is written over it. So the record read
    `partial_analysis: false, partial_reasons: []` beside a field saying the pass never
    reached the end of the object.
    """
    whole, _ = _read_bounded(_BANNER_AT_THE_END, len(_BANNER_AT_THE_END))
    assert whole.partial_reasons == ()
    assert [m.group for m in whole.matched_strings] == ["openssl_banner"]

    cut, _ = _read_bounded(_BANNER_AT_THE_END, len(_BANNER_AT_THE_END) - 2048)
    assert cut.matched_strings == (), "the fixture must not keep the banner in reach"
    assert cut.strings_truncated is True
    assert cut.partial_analysis is True
    assert evidence.PARTIAL_STRINGS_BYTES_UNREAD in cut.partial_reasons


def test_the_object_whose_banner_was_cut_does_not_read_clean() -> None:
    """The whole point of the cause, at the far end of the chain."""
    cut, errors = _read_bounded(_BANNER_AT_THE_END, len(_BANNER_AT_THE_END) - 2048)
    ruleset = load_ruleset()
    e = Evidence(
        filename="demo-1.0-win_amd64.whl",
        sha256="0" * 64,
        size_bytes=1,
        artifacts=ArtifactInventory(),
        binaries=(cut,),
        errors=errors,
    )
    linkage = resolve_linkage(ruleset, e)
    assert linkage["openssl"] == "unknown"
    assert "BIN_PARTIAL_FORMAT" in {f.rule_id for f in apply_rules(ruleset, e, linkage)}


# One object per reader, each with something for a budget to stop inside. Built here
# rather than taken from `_CASES` because `binfmt.elf` bounds the sections it
# concatenates rather than the file, so an object with no `.rodata` has nothing its
# budget could run short of however small the budget is.
_PER_READER: dict[str, bytes] = {
    "elf": ElfBuilder(rodata=_BANNER * 8).build(),
    # Mach-O and PE bound the object they read rather than the sections, so the whole
    # file is what the budget is measured against.
    "macho": MachOBuilder(id_dylib="libfoo.dylib").build(),
    "pe": PEBuilder(
        dll_name="_ext.pyd",
        imports=(PEImport("python311.dll", names=("Py_Initialize",)),),
        exports=(PEExport("PyInit__ext"),),
        trailing=_BANNER * 8,
    ).build(),
    "unknown": b"\x00\x01\x02\x03" + _BANNER * 8,
}


@pytest.mark.parametrize("name", sorted(_PER_READER))
def test_every_reader_names_a_reading_gap(name) -> None:
    """All four bound the bytes they pull in, so all four can run short of an object."""
    data = _PER_READER[name]
    # The boundary, not a comfortable margin: every reader compares `size >` its budget,
    # so a budget of exactly the object's length must still read as complete.
    exact, _ = _read_bounded(data, len(data))
    assert evidence.PARTIAL_STRINGS_BYTES_UNREAD not in exact.partial_reasons, name
    cut, _ = _read_bounded(data, 8)
    assert evidence.PARTIAL_STRINGS_BYTES_UNREAD in cut.partial_reasons, name


@pytest.mark.parametrize("name", sorted(_PER_READER))
def test_a_recording_cap_is_not_a_reading_gap(name) -> None:
    """A cap on what is *kept* is not a claim about what was *read*, in any reader.

    `strings_truncated` is set by both, and only one of them is a partial read, so
    wiring the token to the wrong one of `StringsPass`'s flags would be invisible in
    three readers out of four if this were written against ELF alone.

    What a cap costs instead is a separate matter and a worse one: it can drop crypto
    evidence that sorts late. `DECISIONS.md` has the reproduction. This test pins only
    that a cap is not spelled as a partial read, which is what the vocabulary means.
    """
    limit = PATTERNS.limits.max_strings_per_binary
    banners = b"".join(b"OpenSSL 3.0.%d 4 Jun 2024\x00" % n for n in range(limit + 5))
    data = {
        "elf": lambda: ElfBuilder(rodata=banners).build(),
        "macho": lambda: MachOBuilder(id_dylib="libfoo.dylib").build() + banners,
        "pe": lambda: PEBuilder(
            dll_name="_ext.pyd",
            imports=(PEImport("python311.dll", names=("Py_Initialize",)),),
            exports=(PEExport("PyInit__ext"),),
            trailing=banners,
        ).build(),
        "unknown": lambda: b"\x00\x01\x02\x03" + banners,
    }[name]()
    ev, _ = _read(data)
    assert ev.strings_truncated is True, f"{name}: the recording cap did not fire"
    assert len(ev.matched_strings) == limit, name
    assert evidence.PARTIAL_STRINGS_BYTES_UNREAD not in ev.partial_reasons, name


def test_a_pe_whose_header_would_not_parse_still_names_the_unread_bytes() -> None:
    """Both of `binfmt.pe`'s hand-built early returns, not just the one with a test.

    That reader writes its failure records out field by field instead of calling
    `binfmt.fallback`, so each exit is its own chance to forget a cause. The two are
    symmetric code and only one of them was covered.
    """
    # `_Malformed` and the bare `except Exception` are reached by different objects:
    # a header chain that parses into nonsense, and one that raises on the way.
    for label, data in (
        ("malformed", b"MZ" + b"\x00" * 60 + b"OpenSSL 3.0.14 4 Jun 2024\x00" * 4),
        ("unreadable e_lfanew", b"MZ" + b"\x00" * 58 + b"\xff\xff\xff\xff" + b"pad" * 40),
    ):
        ev, _ = _read_bounded(data, 8, path="stub.pyd")
        assert evidence.PARTIAL_PE_HEADER_UNREAD in ev.partial_reasons, label
        assert evidence.PARTIAL_STRINGS_BYTES_UNREAD in ev.partial_reasons, label
        assert list(ev.partial_reasons) == sorted(set(ev.partial_reasons)), label


def test_every_cause_that_records_no_error_says_so_in_the_schema() -> None:
    """The other marker `SCHEMA.md` carries per row, and the one nothing held.

    The routine marker has a drift guard and this did not, which is how the new cause
    arrived as the only no-error row not saying it. Derived by running the fixtures
    rather than from a list, so a cause that starts or stops recording an error is
    caught by the same test.
    """
    silent: set[str] = set()
    noisy: set[str] = set()
    for data in {**_CASES, **_REACHABILITY}.values():
        ev, errors = _read(data)
        (silent if not errors else noisy).update(ev.partial_reasons)
    # A budget that cuts into the trailing run and nothing else, so the new cause is
    # reached on its own: `binfmt.pe` resolves its directories inside this same buffer,
    # so a deeper cut would take the export directory with it and record an error.
    pe = _PER_READER["pe"]
    ev, errors = _read_bounded(pe, len(pe) - len(_BANNER))
    assert not errors and ev.partial_reasons == (evidence.PARTIAL_STRINGS_BYTES_UNREAD,)
    silent.update(ev.partial_reasons)
    assert silent, "no cause was reached without an error"
    documented = Path("SCHEMA.md").read_text(encoding="utf-8").splitlines()
    for token in sorted(silent - noisy):
        row = next(ln for ln in documented if ln.startswith(f"| `{token}` |"))
        assert "records no error" in row, token


# --- the vocabulary must be live, and must be the same in all three places ----


def test_every_declared_reason_is_actually_emitted_somewhere() -> None:
    """A token nothing produces is a value consumers would filter on and never match.

    The same shape as `test_every_error_kind_is_actually_emitted_somewhere`: every
    constant has to appear at its definition and at least once more.
    """
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in Path("src/wheel_crypto_scan").rglob("*.py")
    )
    names = {
        name: value
        for name, value in vars(evidence).items()
        if name.startswith("PARTIAL_") and isinstance(value, str)
    }
    assert set(names.values()) == evidence.PARTIAL_REASONS
    dead = {value for name, value in names.items() if source.count(name) < 2}
    assert dead == set()


def test_every_reason_is_reachable_from_some_object() -> None:
    """Coverage of the constant is not coverage of the cause: build one of each."""
    produced: set[str] = set()
    for data in _CASES.values():
        ev, _ = _read(data)
        produced |= set(ev.partial_reasons)
    for data in _REACHABILITY.values():
        ev, _ = _read(data)
        produced |= set(ev.partial_reasons)
    # A budget rather than a fixture: reaching the real one by size would mean a 64 MiB
    # object in the suite.
    ev, _ = _read_bounded(_BANNER_AT_THE_END, len(_BANNER_AT_THE_END) - 2048)
    produced |= set(ev.partial_reasons)
    # The handlers bytes cannot reach, run for real rather than named as literals: a
    # token asserted into this set could not fail the guard it exists for.
    with pytest.MonkeyPatch.context() as patch:
        for section in _UNREADABLE_SECTION:
            _explode(patch, section)
            ev, _ = read_elf(io.BytesIO(_readable_elf()), "m.so", PATTERNS, vendored=False)
            produced |= set(ev.partial_reasons)
    assert produced == evidence.PARTIAL_REASONS


def test_the_schema_documents_every_reason_it_can_emit() -> None:
    """Three copies of this list exist. Nothing else holds them together."""
    schema = json.loads(Path("src/wheel_crypto_scan/data/schema.json").read_text(encoding="utf-8"))
    described = schema["properties"]["binaries"]["items"]["properties"]["partial_reasons"]["items"][
        "description"
    ]
    for token in sorted(evidence.PARTIAL_REASONS):
        assert token in described, token

    documented = Path("SCHEMA.md").read_text(encoding="utf-8")
    for token in sorted(evidence.PARTIAL_REASONS):
        assert f"`{token}`" in documented, token


# --- sections whose read fails, which bytes alone cannot express --------------
#
# `pyelftools` tolerates every corruption these synthesised fixtures can express, so
# `binfmt.elf`'s defensive handlers cannot be reached with bytes. They exist for the
# objects that do make it raise, and this stands in for one.


class _Exploding:
    """A section that parsed, wrapped so the named reads of it raise.

    Which reads matters: `.dynsym` is read twice, once for its symbol count and once
    for its entries, and a wrapper that raised from both would let either handler
    satisfy a test meant for the other.
    """

    def __init__(
        self, inner, methods: frozenset[str] = frozenset({"data", "num_symbols", "iter_tags"})
    ) -> None:
        self._inner = inner
        self._methods = methods

    def __getitem__(self, key):
        return self._inner[key]

    @property
    def name(self) -> str:
        return self._inner.name

    @property
    def compressed(self):
        # `_bounded_section_data` reads this before ever calling `.data()`, so it has
        # to reach the real, uncompressed fixture underneath -- forwarding it is what
        # keeps `methods` precise about which read actually explodes.
        return self._inner.compressed

    @property
    def data_size(self):
        return self._inner.data_size

    def _fail(self, method: str):
        if method in self._methods:
            raise ValueError("unreadable section")

    def data(self):
        self._fail("data")
        return self._inner.data()

    def num_symbols(self):
        self._fail("num_symbols")
        return self._inner.num_symbols()

    def iter_tags(self, *args, **kwargs):
        self._fail("iter_tags")
        return self._inner.iter_tags(*args, **kwargs)


GO_BUILDINFO = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16 + b"\x08go1.22.3"

_UNREADABLE_SECTION = {
    # Exploding `.dynamic` also costs `.dynsym`: no readable `DT_STRTAB` to
    # corroborate `.dynsym`'s own `sh_link` against (#56 round 4).
    ".dynamic": (evidence.PARTIAL_ELF_DYNAMIC_UNREAD, evidence.PARTIAL_ELF_DYNSYM_UNREAD),
    ".dynsym": (evidence.PARTIAL_ELF_DYNSYM_UNREAD,),
    ".symtab": (evidence.PARTIAL_ELF_SYMTAB_UNREAD,),
    ".go.buildinfo": (evidence.PARTIAL_ELF_GO_BUILDINFO_UNREAD,),
}


def _readable_elf() -> bytes:
    return ElfBuilder(
        needed=("libcrypto.so.3",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
        with_symtab=True,
        go_buildinfo=GO_BUILDINFO,
    ).build()


# `.dynamic`, `.dynsym` and `.symtab` are found by `sh_type` now, not by name (#56), so
# exploding them has to patch that lookup instead of `_find_section`. `.go.buildinfo`
# is still name-based, out of scope for that issue, and stays on the original helper.
_TYPE_LOOKUP_NAMES = {".dynamic": "SHT_DYNAMIC", ".dynsym": "SHT_DYNSYM", ".symtab": "SHT_SYMTAB"}


def _explode(monkeypatch, section_name: str, methods: frozenset[str] | None = None) -> None:
    which = methods or frozenset({"data", "num_symbols", "iter_tags"})
    sh_type = _TYPE_LOOKUP_NAMES.get(section_name)
    if sh_type is not None:
        real_by_type = elf_module._find_section_by_type

        def patched_by_type(sections, type_name):
            section, ambiguous = real_by_type(sections, type_name)
            if type_name == sh_type and section is not None:
                return _Exploding(section, which), ambiguous
            return section, ambiguous

        monkeypatch.setattr(elf_module, "_find_section_by_type", patched_by_type)
        return

    real = elf_module._find_section

    def patched(sections, name):
        found = real(sections, name)
        if name == section_name and found is not None:
            return _Exploding(found, which)
        return found

    monkeypatch.setattr(elf_module, "_find_section", patched)


@pytest.mark.parametrize("method", ["num_symbols", "data"])
def test_both_dynsym_reads_name_the_same_cause(monkeypatch, method) -> None:
    """`.dynsym` is read twice, and each read has its own handler."""
    _explode(monkeypatch, ".dynsym", frozenset({method}))
    ev, errors = read_elf(io.BytesIO(_readable_elf()), "m.so", PATTERNS, vendored=False)
    assert errors != ()
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_DYNSYM_UNREAD]


@pytest.mark.parametrize(("section", "reasons"), sorted(_UNREADABLE_SECTION.items()))
def test_each_unread_elf_section_names_the_evidence_it_cost(monkeypatch, section, reasons) -> None:
    """Which area failed is what a consumer needs: they invalidate different fields."""
    _explode(monkeypatch, section)
    ev, errors = read_elf(io.BytesIO(_readable_elf()), "m.so", PATTERNS, vendored=False)
    assert errors != ()
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == sorted(reasons)
    assert bool(ev.partial_reasons) is ev.partial_analysis


# --- each byte-reachable cause names exactly its own token --------------------
#
# The reachability guard only asks that every token is produced by *something*, so two
# causes sharing a token hide each other from it. This pins the mapping per cause.

_BYTE_REACHABLE = {
    "elf header unread": [evidence.PARTIAL_ELF_HEADER_UNREAD],
    "elf section table truncated": [evidence.PARTIAL_ELF_SECTION_TABLE_TRUNCATED],
    "elf section table absent": [evidence.PARTIAL_ELF_SECTION_TABLE_ABSENT],
    "elf section type ambiguous": [evidence.PARTIAL_ELF_SECTION_TYPE_AMBIGUOUS],
    # `.dynamic`'s own sh_link is broken here, so `.dynsym`'s string table has no
    # `DT_STRTAB` to corroborate against either (#56 round 4) -- this fixture costs
    # both, not just the section list.
    "elf section header unreadable": [
        evidence.PARTIAL_ELF_DYNSYM_UNREAD,
        evidence.PARTIAL_ELF_SECTIONS_UNREAD,
    ],
    "elf section count unreadable": [evidence.PARTIAL_ELF_SECTIONS_UNREAD],
    # Same cascade: `.dynamic` unreadable costs `.dynsym`'s corroboration too.
    "elf dynamic section unreadable": [
        evidence.PARTIAL_ELF_DYNAMIC_UNREAD,
        evidence.PARTIAL_ELF_DYNSYM_UNREAD,
    ],
    "elf section data unreadable": [evidence.PARTIAL_ELF_SECTION_DATA_UNREAD],
    "macho header unread": [evidence.PARTIAL_MACHO_HEADER_UNREAD],
    "macho stripped": [evidence.PARTIAL_MACHO_SYMTAB_INCOMPLETE],
    "macho fat slice unread": [evidence.PARTIAL_MACHO_FAT_SLICE_UNREAD],
    "macho dylib name unread": [evidence.PARTIAL_MACHO_LOAD_COMMAND_STRING_UNREAD],
    "pe header unread": [evidence.PARTIAL_PE_HEADER_UNREAD],
    "pe ordinal import": [evidence.PARTIAL_PE_ORDINAL_IMPORT],
    "unknown format": [evidence.PARTIAL_NO_STRUCTURAL_READER],
}


@pytest.mark.parametrize(("case", "expected"), sorted(_BYTE_REACHABLE.items()))
def test_each_cause_names_exactly_its_own_token(case, expected) -> None:
    data = {**_CASES, **_REACHABILITY}[case]
    ev, _ = _read(data)
    assert list(ev.partial_reasons) == expected
    assert ev.partial_analysis is True


# --- the ruleset can tell a routine cause from a failure ----------------------


def _findings(data: bytes, path: str = "demo/_ext.pyd"):
    ruleset = load_ruleset()
    ev, _ = read_binary(io.BytesIO(data), path, PATTERNS, vendored=False)
    evidence = Evidence(
        filename="demo-1.0-win_amd64.whl",
        sha256="0" * 64,
        size_bytes=1,
        artifacts=ArtifactInventory(),
        binaries=(ev,),
    )
    found = apply_rules(ruleset, evidence, resolve_linkage(ruleset, evidence))
    return {f.rule_id: f for f in found if f.rule_id.startswith("BIN_PARTIAL")}


def test_an_ordinal_import_alone_is_not_opacity() -> None:
    """`WS2_32` is normally bound by ordinal, so this is the ordinary Windows record.

    Treating it as opacity put every Windows wheel that touches sockets on the README's
    `OPAQUE` triage list, for a linker convention rather than anything unread about the
    wheel. The evidence really is incomplete, so it is still recorded; it just is not a
    reason for a human to look.
    """
    data = PEBuilder(
        imports=(PEImport("WS2_32.dll", ordinals=(115,)),), dll_name="_ext.pyd"
    ).build()
    found = _findings(data)
    assert set(found) == {"BIN_PARTIAL_ROUTINE"}
    assert found["BIN_PARTIAL_ROUTINE"].verdict is None
    assert found["BIN_PARTIAL_ROUTINE"].needs_human_review is False


def test_a_real_failure_is_still_opacity() -> None:
    data = PEBuilder(
        imports=(PEImport("KERNEL32.dll", names=("GetLastError",)),),
        dll_name="_ext.pyd",
        truncate_to=0x150,
    ).build()
    found = _findings(data)
    assert set(found) == {"BIN_PARTIAL_FORMAT"}
    assert found["BIN_PARTIAL_FORMAT"].verdict == "OPAQUE"


def test_both_kinds_of_cause_are_reported_separately() -> None:
    """Each rule names only the causes it speaks for, and the failure still wins."""
    data = PEBuilder(
        imports=(PEImport("WS2_32.dll", ordinals=(115,)),),
        dll_name="_ext.pyd",
        exports=(PEExport("PyInit__ext"),),
        declared_export_rva=0x7F000000,
    ).build()
    found = _findings(data)
    assert set(found) == {"BIN_PARTIAL_FORMAT", "BIN_PARTIAL_ROUTINE"}
    assert found["BIN_PARTIAL_FORMAT"].verdict == "OPAQUE"
    assert "pe_export_incomplete" in found["BIN_PARTIAL_FORMAT"].locations[0].evidence
    assert "pe_ordinal_import" not in found["BIN_PARTIAL_FORMAT"].locations[0].evidence
    assert "pe_ordinal_import" in found["BIN_PARTIAL_ROUTINE"].locations[0].evidence


def test_every_reason_is_claimed_by_some_rule() -> None:
    """A token no rule matches is a cause that would report nothing at all.

    The shape of `test_every_error_kind_is_covered_by_a_rule`, one level down. Asserting
    that the strict rule's exclusions are claimed elsewhere is not the same thing and
    goes vacuously true the moment someone empties `exclude_reasons`: what matters is
    that every token in the vocabulary fires something.
    """
    ruleset = load_ruleset()
    matches = [match for _, match in ruleset.matches_for_kind("partial_binary")]
    assert matches, "no rule matches partial_binary at all"
    for token in sorted(evidence.PARTIAL_REASONS):
        claimed = [
            match
            for match in matches
            if token in match.get("reasons", ())
            or ("reasons" not in match and token not in match.get("exclude_reasons", ()))
        ]
        assert claimed, f"{token} is claimed by no rule"


def test_a_routine_cause_still_leaves_the_dependency_name_in_the_record() -> None:
    """Why the ordinal import is routine and `pe_delay_load` is not.

    An ordinal import loses a function name inside a DLL the record still names, so a
    crypto dependency bound that way is caught by the same rule that catches any other
    `needed` entry. A delay-load directory loses the dependency name itself, and
    nothing downstream recovers it, so it stays with the strict rule. The ordinal
    export was once on this side of the line and is not: it names no dependency for
    this argument to be about.
    """
    data = PEBuilder(
        imports=(PEImport("libcrypto-3-x64.dll", ordinals=(1,)),),
        dll_name="_ext.pyd",
        exports=(PEExport("PyInit__ext"),),
    ).build()
    ev, _ = read_binary(io.BytesIO(data), "demo/_ext.pyd", PATTERNS, vendored=False)
    assert ev.partial_reasons == (evidence.PARTIAL_PE_ORDINAL_IMPORT,)
    assert ev.needed == ("libcrypto-3-x64.dll",)
    assert "BIN_NEEDED_SYSTEM_OPENSSL" in _findings_all(data)


def test_an_ordinal_import_from_an_unrecognised_dll_answers_nothing() -> None:
    """The residual under the ordinal-import exemption, named rather than assumed away.

    "The DLL it names survives in `needed`" only rescues the case where that name is a
    soname the ruleset knows, and that case answers definitely without any help. The
    branch that needs help is the other one -- `linkage._binary_posture` returns
    `unknown` for an object calling a library it neither ships nor declares -- and an
    ordinal import erases exactly the imported symbol that branch reads.

    So the exemption costs this shape: by name it is `unknown` and a finding, by
    ordinal it is `none` and no verdict at all. Kept, because costing the answer for
    every ordinal import is the noise removed when the split was drawn for verdicts,
    and `WS2_32` is bound this way on every Windows extension that touches sockets.
    Pinned here so it is a known hole rather than an assumed non-hole.
    """
    named = PEBuilder(
        dll_name="_ext.pyd",
        imports=(PEImport("mycrypto.dll", names=("EVP_DigestInit_ex",)),),
        exports=(PEExport("PyInit__ext"),),
    ).build()
    by_ordinal = PEBuilder(
        dll_name="_ext.pyd",
        imports=(PEImport("mycrypto.dll", ordinals=(1,)),),
        exports=(PEExport("PyInit__ext"),),
    ).build()
    assert "BIN_OPENSSL_LINKAGE_UNKNOWN" in _findings_all(named)
    assert _findings_all(by_ordinal) == {"BIN_PARTIAL_ROUTINE"}


def test_an_understated_export_name_count_does_not_read_clean() -> None:
    """The shape that made an ordinal export a failure rather than a convention.

    `NumberOfNames` is a count the object keeps about itself, and PE has no string
    table to check it against. Understate it and the names stop being walked, every
    address slot becomes one no name points at, and `unnamed` fires -- so the cause
    is recorded. What used to happen next is the whole of the problem: the cause was
    claimed by the verdict-less rule, so a statically linked OpenSSL came back with no
    verdict, `openssl_linkage: none` and `needs_human_review: false`.

    Three counts, one object, no OpenSSL banner in it to fall back on.
    """

    ruleset = load_ruleset()

    def build(**declared):
        return PEBuilder(
            dll_name="_ext.pyd",
            imports=(PEImport("python311.dll", names=("Py_Initialize",)),),
            exports=(
                PEExport("PyInit__ext"),
                PEExport("EVP_DigestInit_ex"),
                PEExport("SSL_new"),
            ),
            **declared,
        ).build()

    def linkage_of(data: bytes):
        ev, _ = read_binary(io.BytesIO(data), "demo/_ext.pyd", PATTERNS, vendored=False)
        return resolve_linkage(
            ruleset,
            Evidence(
                filename="demo-1.0-win_amd64.whl",
                sha256="0" * 64,
                size_bytes=1,
                artifacts=ArtifactInventory(),
                binaries=(ev,),
            ),
        )

    assert "BIN_STATIC_OPENSSL" in _findings_all(build())
    # The harm was never which rule fired. It was the three fields a consumer reads.
    rule = ruleset.rule("BIN_PARTIAL_FORMAT")
    assert rule.verdict == "OPAQUE"
    assert rule.needs_human_review is True
    for declared in ({"declared_name_count": 0}, {"declared_name_count": 1}):
        data = build(**declared)
        found = _findings_all(data)
        assert "BIN_PARTIAL_FORMAT" in found, declared
        assert "BIN_PARTIAL_ROUTINE" not in found, declared
        assert "BIN_OPENSSL_LINKAGE_UNKNOWN" in found, declared
        assert linkage_of(data)["openssl"] == "unknown", declared


def test_a_delay_load_directory_is_not_treated_as_routine() -> None:
    """It loses the dependency name, and no other rule recovers it."""
    data = PEBuilder(
        imports=(PEImport("KERNEL32.dll", names=("GetLastError",)),),
        dll_name="_ext.pyd",
        exports=(PEExport("PyInit__ext"),),
        delay_import_directory=True,
    ).build()
    found = _findings(data)
    assert set(found) == {"BIN_PARTIAL_FORMAT"}
    assert found["BIN_PARTIAL_FORMAT"].verdict == "OPAQUE"


def _findings_all(data: bytes) -> set[str]:
    ruleset = load_ruleset()
    ev, _ = read_binary(io.BytesIO(data), "demo/_ext.pyd", PATTERNS, vendored=False)
    e = Evidence(
        filename="demo-1.0-win_amd64.whl",
        sha256="0" * 64,
        size_bytes=1,
        artifacts=ArtifactInventory(),
        binaries=(ev,),
    )
    return {f.rule_id for f in apply_rules(ruleset, e, resolve_linkage(ruleset, e))}


def test_the_documented_linkage_exemptions_are_the_ones_the_ruleset_claims() -> None:
    """The same prose-versus-policy drift guard, for the second split over one vocabulary.

    Two lists are drawn over `PARTIAL_REASONS` now and they are deliberately not the
    same list: `elf_symtab_unread` is worth a verdict and costs linkage nothing. A
    reader deciding whether a `none` can be trusted reads the table, so the table has
    to be the ruleset.
    """
    excluded = load_ruleset().linkage_policy.exclude_reasons
    assert excluded, "the ruleset exempts no cause from costing linkage an answer"
    documented = Path("SCHEMA.md").read_text(encoding="utf-8").splitlines()
    for token in sorted(evidence.PARTIAL_REASONS):
        row = next(ln for ln in documented if ln.startswith(f"| `{token}` |"))
        assert ("Does not cost the linkage answer" in row) is (token in excluded), token


def test_exactly_one_cause_is_recorded_without_a_verdict() -> None:
    """`AGENTS.md` and `README.md` both state this count in prose and no test read it.

    A second routine cause could be added, `SCHEMA.md` updated, the linkage exact-set
    literal updated, and the whole suite stays green while the two files an agent reads
    first say "one cause" and "one carve-out". The linkage exemptions already have a pin
    of this shape in `tests/test_linkage.py`; this is the one the verdict side was
    missing.

    Changing this number means changing an invariant, so it should take editing a test
    that says where the prose lives.
    """
    routine = routine_reasons(load_ruleset().rules)
    assert routine == frozenset({evidence.PARTIAL_PE_ORDINAL_IMPORT}), (
        "the carve-out list changed; AGENTS.md's invariant and README.md's "
        "'One carve-out' paragraph both state its membership in prose"
    )


def test_the_two_splits_over_one_vocabulary_are_not_the_same_list() -> None:
    """Why linkage got a list of its own rather than reusing the verdict-less one.

    If these ever coincide, the mechanism is a rename and the simpler thing is to say
    so. Today they do not: a cause can be worth a verdict and cost linkage nothing.
    Asserted as a non-empty difference rather than as the exact sets, which the two
    tests either side of this one already pin.
    """
    ruleset = load_ruleset()
    assert ruleset.linkage_policy.exclude_reasons - routine_reasons(ruleset.rules), (
        "the linkage list adds nothing to the verdict-less one"
    )


def test_a_verdict_less_cause_that_costs_the_linkage_answer_is_refused() -> None:
    """The containment is a load-time refusal, not a property of the shipped file.

    A cause recorded without a verdict promises the wheel is not on its own worth a
    human's time. Letting it cost the linkage answer puts it back on the triage list
    through `BIN_OPENSSL_LINKAGE_UNKNOWN`, which carries `OPAQUE`. Asserting that only
    over `load_ruleset()` left every `--ruleset` user outside the guard.
    """
    data = tomllib.loads(
        files("wheel_crypto_scan").joinpath("data/ruleset.toml").read_text(encoding="utf-8")
    )
    data["linkage_policy"]["exclude_reasons"] = [
        reason
        for reason in data["linkage_policy"]["exclude_reasons"]
        if reason != evidence.PARTIAL_PE_ORDINAL_IMPORT
    ]
    with pytest.raises(RulesetError, match="recorded without a verdict"):
        parse_ruleset(data)


def test_a_ruleset_with_no_linkage_policy_still_agrees_with_its_own_rules() -> None:
    """Absence derives the exemptions rather than emptying them.

    An empty default would have made every ruleset supplied through `--ruleset` report
    `openssl_linkage: unknown` for an ordinary ordinal import, which is both the noise
    #32 removed and the contradiction the load-time check refuses.
    """
    data = tomllib.loads(
        files("wheel_crypto_scan").joinpath("data/ruleset.toml").read_text(encoding="utf-8")
    )
    del data["linkage_policy"]
    derived = parse_ruleset(data).linkage_policy
    assert derived.exclude_reasons == routine_reasons(load_ruleset().rules)
    assert not derived.costs_an_answer((evidence.PARTIAL_PE_ORDINAL_IMPORT,))


def test_the_documented_routine_causes_are_the_ones_the_ruleset_claims() -> None:
    """Three copies of this list exist and nothing held the prose to the rule.

    `SCHEMA.md` listed `pe_delay_load` as routine after the ruleset had stopped
    treating it as such, which is exactly the drift a reader would act on.

    Read off `verdict is None` rather than off the rule id: the id is one spelling of
    the property, and a second verdict-less rule would slip past a name.
    """
    ruleset = load_ruleset()
    routine = routine_reasons(ruleset.rules)
    assert routine, "no rule claims any routine cause"
    documented = Path("SCHEMA.md").read_text(encoding="utf-8").splitlines()
    for token in sorted(evidence.PARTIAL_REASONS):
        row = next(ln for ln in documented if ln.startswith(f"| `{token}` |"))
        assert ("BIN_PARTIAL_ROUTINE" in row) is (token in routine), token
