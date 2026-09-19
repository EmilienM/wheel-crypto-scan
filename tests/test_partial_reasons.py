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
    build_fat,
    patch_header_field,
    patch_section_header,
    patch_u16,
)
from wheel_crypto_scan import evidence
from wheel_crypto_scan.binfmt import elf as elf_module
from wheel_crypto_scan.binfmt import read_binary
from wheel_crypto_scan.binfmt.elf import read_elf
from wheel_crypto_scan.engine import apply_rules
from wheel_crypto_scan.evidence import ArtifactInventory, Evidence
from wheel_crypto_scan.linkage import resolve_linkage
from wheel_crypto_scan.ruleset import load_ruleset

PATTERNS = load_ruleset().compile_patterns().binary


def _read(data: bytes, path: str = "obj"):
    return read_binary(io.BytesIO(data), path, PATTERNS, vendored=False)


def _reasons(data: bytes) -> list[str]:
    ev, _ = _read(data)
    return list(ev.partial_reasons)


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
    # A section flagged compressed over bytes that are not: the read raises, and this
    # used to be the one failure in the reader that recorded nothing at all.
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
    ".dynamic": evidence.PARTIAL_ELF_DYNAMIC_UNREAD,
    ".dynsym": evidence.PARTIAL_ELF_DYNSYM_UNREAD,
    ".symtab": evidence.PARTIAL_ELF_SYMTAB_UNREAD,
    ".go.buildinfo": evidence.PARTIAL_ELF_GO_BUILDINFO_UNREAD,
}


def _readable_elf() -> bytes:
    return ElfBuilder(
        needed=("libcrypto.so.3",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
        with_symtab=True,
        go_buildinfo=GO_BUILDINFO,
    ).build()


def _explode(monkeypatch, section_name: str, methods: frozenset[str] | None = None) -> None:
    real = elf_module._find_section
    which = methods or frozenset({"data", "num_symbols", "iter_tags"})

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


@pytest.mark.parametrize(("section", "reason"), sorted(_UNREADABLE_SECTION.items()))
def test_each_unread_elf_section_names_the_evidence_it_cost(monkeypatch, section, reason) -> None:
    """Which area failed is what a consumer needs: they invalidate different fields."""
    _explode(monkeypatch, section)
    ev, errors = read_elf(io.BytesIO(_readable_elf()), "m.so", PATTERNS, vendored=False)
    assert errors != ()
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [reason]
    assert bool(ev.partial_reasons) is ev.partial_analysis


# --- each byte-reachable cause names exactly its own token --------------------
#
# The reachability guard only asks that every token is produced by *something*, so two
# causes sharing a token hide each other from it. This pins the mapping per cause.

_BYTE_REACHABLE = {
    "elf header unread": [evidence.PARTIAL_ELF_HEADER_UNREAD],
    "elf section table truncated": [evidence.PARTIAL_ELF_SECTION_TABLE_TRUNCATED],
    "elf section header unreadable": [evidence.PARTIAL_ELF_SECTIONS_UNREAD],
    "elf section count unreadable": [evidence.PARTIAL_ELF_SECTIONS_UNREAD],
    "elf dynamic section unreadable": [evidence.PARTIAL_ELF_DYNAMIC_UNREAD],
    "elf section data unreadable": [evidence.PARTIAL_ELF_SECTION_DATA_UNREAD],
    "macho header unread": [evidence.PARTIAL_MACHO_HEADER_UNREAD],
    "macho stripped": [evidence.PARTIAL_MACHO_SYMTAB_INCOMPLETE],
    "macho fat slice unread": [evidence.PARTIAL_MACHO_FAT_SLICE_UNREAD],
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
    """Why the two ordinal causes are routine and `pe_delay_load` is not.

    An ordinal import loses a function name inside a DLL the record still names, so a
    crypto dependency bound that way is caught by the same rule that catches any other
    `needed` entry. A delay-load directory loses the dependency name itself, and
    nothing downstream recovers it, so it stays with the strict rule.
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


def test_the_documented_routine_causes_are_the_ones_the_ruleset_claims() -> None:
    """Three copies of this list exist and nothing held the prose to the rule.

    `SCHEMA.md` listed `pe_delay_load` as routine after the ruleset had stopped
    treating it as such, which is exactly the drift a reader would act on.
    """
    ruleset = load_ruleset()
    routine = {
        reason
        for rule, match in ruleset.matches_for_kind("partial_binary")
        if rule.id == "BIN_PARTIAL_ROUTINE"
        for reason in match.get("reasons", ())
    }
    assert routine, "no rule claims any routine cause"
    documented = Path("SCHEMA.md").read_text(encoding="utf-8").splitlines()
    for token in sorted(evidence.PARTIAL_REASONS):
        row = next(ln for ln in documented if ln.startswith(f"| `{token}` |"))
        assert ("BIN_PARTIAL_ROUTINE" in row) is (token in routine), token
