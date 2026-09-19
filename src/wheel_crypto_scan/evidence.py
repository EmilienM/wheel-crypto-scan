"""Extraction contracts shared by the three scan layers.

These types are pure data. Extractors fill them in; they never reference rules and
never assign severity, verdict or meaning. Interpretation happens in `engine` and
`verdict`.

Every sequence field is a tuple that the producing extractor has already sorted by a
stable key, because the JSON record is emitted in this order and must be byte-identical
across runs, hosts and interpreter versions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

BINDING_IMPORTED = "imported"
BINDING_DEFINED = "defined"

FORMAT_ELF = "elf"
FORMAT_MACHO = "macho"
FORMAT_PE = "pe"
FORMAT_UNKNOWN = "unknown"

# Why one object was not read in full. `BinaryEvidence.partial_analysis` is a single
# boolean with a score of causes behind it, and six of them record no `ScanError` at
# all,
# so a record could read `partial_analysis: true, errors: []` with no way to tell which
# applied. Two of those six are the common case rather than an exotic one: a stripped
# Mach-O, which is every release macOS wheel, and an ordinal-only PE import, because
# `WS2_32` is normally bound by ordinal. Both read identically to "we could parse
# nothing at all".
#
# These are facts about what a reader did, not policy, so they live here beside the
# field rather than in `ruleset.toml`, the way `FORMAT_*` and `STAGE_*` do. They are
# part of the output contract: adding one is not a `schema_version` bump, renaming one
# is. Each names a cause, never the method used to cope with it -- every object whose
# header would not parse is also read for strings alone, so "strings only" would not
# tell those records apart from the ones that have no reader at all.

# No reader for this format. The object was still scanned for strings.
PARTIAL_NO_STRUCTURAL_READER = "no_structural_reader"
# The ELF header itself would not parse.
PARTIAL_ELF_HEADER_UNREAD = "elf_header_unread"
# The ELF header parsed; the section header table it points at does not fit the object.
PARTIAL_ELF_SECTION_TABLE_TRUNCATED = "elf_section_table_truncated"
# A section header could not be read. A section we cannot name is a section we cannot
# use, so anything derived from the section list may be missing rather than absent:
# `needed`, `soname`, `rpath`, `runpath`, the symbol counts and the strings alike.
PARTIAL_ELF_SECTIONS_UNREAD = "elf_sections_unread"
# A section's bytes could not be read, so the strings pass ran over less than the
# object holds. On its own this used to be silent, which made a wheel whose only
# evidence was a `.rodata` banner able to come back with no findings at all.
PARTIAL_ELF_SECTION_DATA_UNREAD = "elf_section_data_unread"
# `.dynamic` would not resolve, so `needed`, `soname`, `rpath` and `runpath` are empty
# because they could not be read, not because the object declares none.
PARTIAL_ELF_DYNAMIC_UNREAD = "elf_dynamic_unread"
# `.dynsym` would not read, named strings `.dynstr` does not hold, or declared fewer
# entries than `.dynstr` holds names for, so the imported-versus-defined split is
# missing or partial.
PARTIAL_ELF_DYNSYM_UNREAD = "elf_dynsym_unread"
# `.symtab` would not read, so `stripped` and `symbol_counts.symtab` describe a table we
# failed on rather than one the object does not have.
PARTIAL_ELF_SYMTAB_UNREAD = "elf_symtab_unread"
# `.go.buildinfo` would not read, so Go toolchain provenance is missing.
PARTIAL_ELF_GO_BUILDINFO_UNREAD = "elf_go_buildinfo_unread"
# The Mach-O header, or a fat header, would not parse.
PARTIAL_MACHO_HEADER_UNREAD = "macho_header_unread"
# `LC_SYMTAB` was absent, declared no entries, or declared entries this reader could not
# take at their word: unreachable, naming strings it does not hold, holding nothing but
# debug records, or declaring fewer entries than the string table holds names for. It
# records an error unless the table left nothing unexplained -- an absent `LC_SYMTAB`,
# or one declaring no entries over a string table holding no name it failed to account
# for, which is what `strip` leaves behind and normal for a release wheel. Every other
# way of falling short records which way.
PARTIAL_MACHO_SYMTAB_INCOMPLETE = "macho_symtab_incomplete"
# A slice of a universal binary could not be read, or its header named one it did not
# describe, so an architecture is unknown rather than clean.
PARTIAL_MACHO_FAT_SLICE_UNREAD = "macho_fat_slice_unread"
# The PE header chain would not parse.
PARTIAL_PE_HEADER_UNREAD = "pe_header_unread"
# The section table was cut short, so an address may resolve to the wrong bytes.
PARTIAL_PE_SECTION_TABLE_TRUNCATED = "pe_section_table_truncated"
# No import directory, or one naming no DLL: this object declared no dependency.
# Records no error.
PARTIAL_PE_NO_IMPORT_DIRECTORY = "pe_no_import_directory"
# An import directory that was there and could not be walked to its terminator.
PARTIAL_PE_IMPORT_INCOMPLETE = "pe_import_incomplete"
# An export directory that was there and could not be read in full.
PARTIAL_PE_EXPORT_INCOMPLETE = "pe_export_incomplete"
# An import named by ordinal alone, so its function has no name to match. Records no
# error: routine on Windows, where `WS2_32` is normally bound this way.
PARTIAL_PE_ORDINAL_IMPORT = "pe_ordinal_import"
# An export the name table never points at: a definition with no name. Records no error.
PARTIAL_PE_ORDINAL_EXPORT = "pe_ordinal_export"
# A delay-load import directory, which this reader does not parse, so the libraries it
# names are undeclared dependencies. Records no error.
PARTIAL_PE_DELAY_LOAD = "pe_delay_load"
# A symbol table declared fewer entries than the string table it points into holds names
# for, so symbols the object carries were never looked at. Not a corrupt object: every
# structural check passes, and the count is simply not the truth. Format-independent,
# because the lie and the check are the same in ELF and Mach-O, and the one cause a
# consumer is most likely to want to filter an index on.
PARTIAL_SYMTAB_UNDERSTATES_ROWS = "symtab_understates_rows"
# Bytes the strings pass never saw, because the reader's budget ran out before the
# object did. Records no error. Format-independent, because every reader bounds what it
# pulls into memory and each one can run short.
#
# It is not the same thing as `strings_truncated`, which is also set when a *recording*
# cap was hit -- more group matches or more cargo paths than the limits keep. A
# recording cap is not a partial read at all: the object was read, and what was capped
# is what got written down, so it is not a member of the class this vocabulary
# enumerates. This token is the other case, where nothing was found in a region because
# nothing was looked at. A `cryptography` 42 extension has its version banner and
# nothing else, so a budget stopping short of the banner is the difference between
# `static` and a clean bill.
PARTIAL_STRINGS_BYTES_UNREAD = "strings_bytes_unread"

PARTIAL_REASONS: frozenset[str] = frozenset(
    {
        PARTIAL_NO_STRUCTURAL_READER,
        PARTIAL_ELF_HEADER_UNREAD,
        PARTIAL_ELF_SECTION_TABLE_TRUNCATED,
        PARTIAL_ELF_SECTIONS_UNREAD,
        PARTIAL_ELF_SECTION_DATA_UNREAD,
        PARTIAL_ELF_DYNAMIC_UNREAD,
        PARTIAL_ELF_DYNSYM_UNREAD,
        PARTIAL_ELF_SYMTAB_UNREAD,
        PARTIAL_ELF_GO_BUILDINFO_UNREAD,
        PARTIAL_MACHO_HEADER_UNREAD,
        PARTIAL_MACHO_SYMTAB_INCOMPLETE,
        PARTIAL_MACHO_FAT_SLICE_UNREAD,
        PARTIAL_PE_HEADER_UNREAD,
        PARTIAL_PE_SECTION_TABLE_TRUNCATED,
        PARTIAL_PE_NO_IMPORT_DIRECTORY,
        PARTIAL_PE_IMPORT_INCOMPLETE,
        PARTIAL_PE_EXPORT_INCOMPLETE,
        PARTIAL_PE_ORDINAL_IMPORT,
        PARTIAL_PE_ORDINAL_EXPORT,
        PARTIAL_PE_DELAY_LOAD,
        PARTIAL_SYMTAB_UNDERSTATES_ROWS,
        PARTIAL_STRINGS_BYTES_UNREAD,
    }
)

STAGE_ARCHIVE = "archive"
STAGE_METADATA = "metadata"
STAGE_BINARY = "binary"
STAGE_PYTHON = "python"


@dataclass(frozen=True, slots=True)
class ScanError:
    """A non-fatal problem. Recorded, never raised past the wheel being scanned.

    `message` must be deterministic and must never contain a host path.
    """

    stage: str
    kind: str
    message: str
    path: str | None = None

    def sort_key(self) -> tuple[str, str, str, str]:
        return (self.stage, self.path or "", self.kind, self.message)


@dataclass(frozen=True, slots=True)
class SymbolMatch:
    """A dynamic symbol matching one of the ruleset's symbol groups.

    `binding` is the whole point: an imported symbol means the wheel calls into a
    library it does not ship, a defined symbol means it carries that code itself.
    """

    name: str
    group: str
    binding: str

    def sort_key(self) -> tuple[str, str, str]:
        return (self.group, self.name, self.binding)


@dataclass(frozen=True, slots=True)
class StringMatch:
    """A read-only-data string matching one of the ruleset's string patterns."""

    group: str
    value: str

    def sort_key(self) -> tuple[str, str]:
        return (self.group, self.value)


@dataclass(frozen=True, slots=True)
class RustCrate:
    """A crate inferred from an embedded cargo registry path."""

    name: str
    version: str

    def sort_key(self) -> tuple[str, str]:
        return (self.name, self.version)


@dataclass(frozen=True, slots=True)
class GoBuildInfo:
    """Go toolchain provenance, when the binary carries it."""

    go_version: str | None = None
    boring_crypto: bool = False
    markers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BinaryEvidence:
    """Normalised evidence for one native object inside the wheel."""

    path: str
    format: str
    # True when the object lives in an auditwheel `*.libs/` or delocate `.dylibs/`
    # directory, i.e. the wheel ships it rather than borrowing it from the system.
    vendored_path: bool = False
    machine: str | None = None
    bits: int | None = None
    endian: str | None = None
    elf_type: str | None = None
    soname: str | None = None
    needed: tuple[str, ...] = ()
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()
    stripped: bool = False
    dynsym_count: int = 0
    symtab_count: int = 0
    matched_symbols: tuple[SymbolMatch, ...] = ()
    matched_strings: tuple[StringMatch, ...] = ()
    rust_crates: tuple[RustCrate, ...] = ()
    go: GoBuildInfo | None = None
    # A recording cap, and deliberately not a `partial_reasons` cause: see
    # `strings_truncated` below.
    symbols_truncated: bool = False
    # More matches than the limits keep. A recording cap, never a partial read: the
    # object was read, and what was capped is what got written down, so neither of
    # these two fields is a cause and neither should become one. Bytes that went
    # unread are a different fact and carry `strings_bytes_unread`.
    strings_truncated: bool = False
    # Set when part of the object was not read: a format with no structural reader; a
    # ELF whose header, section headers, `.dynamic`, symbol tables, section data or
    # `.go.buildinfo` would not read; a PE whose section table was truncated, whose
    # import directory was absent or could not be walked, that named something by
    # ordinal alone, or that carries a delay-load import directory, which is not
    # parsed; a Mach-O whose `LC_SYMTAB` could not be read
    # in full; or a slice of a fat binary that could not be read. A wheel can never
    # look clean merely because we read less of it than usual.
    partial_analysis: bool = False
    # Which of the causes above applied, sorted. Empty when `partial_analysis` is
    # false, and never the other way round: a reader that sets the boolean names its
    # reason. Filter on the boolean; read this to find out what to do about it.
    partial_reasons: tuple[str, ...] = ()

    @property
    def is_opaque(self) -> bool:
        """True when the object told us nothing at all.

        Which count means "we read some symbols" is per format, and testing the wrong
        one is indistinguishable from reading nothing. `binfmt.elf` reports `.dynsym`
        in `dynsym_count`; Mach-O's `LC_SYMTAB` and PE's named entries land in
        `symtab_count`, and neither format ever sets `dynsym_count`. Keying on that
        field alone made the symbols invisible to this property for both formats.

        `needed` is tested first and rescued most real objects: every loadable dylib
        links `libSystem` and every `.pyd` imports its `pythonXY.dll`, so they were
        never opaque. What was left wrongly opaque is the object that declares no
        dependency at all -- a Mach-O `MH_OBJECT`, a statically linked extension, a
        resource-only DLL -- which reported having told us nothing while carrying the
        symbols it told us.

        Reading less than usual is still caught, by a different route: any failed read
        sets `partial_analysis`, which fires a rule whose verdict is `OPAQUE` whatever
        this property says. That backstop is why widening this is safe.

        Testing both counts for every format would fix those two by changing a third:
        an ELF with a `.symtab` and no `.dynsym`, which is the ordinary shape of a
        static executable, would stop being opaque. Whether *that* object has told us
        anything is a separate question, and not one this property should answer by
        accident, so the count is chosen by format instead.
        """
        symbols = self.dynsym_count if self.format == FORMAT_ELF else self.symtab_count
        return not (
            self.needed
            or self.matched_symbols
            or self.matched_strings
            or self.rust_crates
            or symbols
        )


@dataclass(frozen=True, slots=True)
class PySite:
    """One source location in a `.py` file that matched a Layer 3 pattern.

    `detail` is synthesised from the matched pattern, never from `ast.unparse`, whose
    output varies between interpreter versions and would break determinism.
    `attrs` carries structured extras as sorted key/value pairs, for example
    ("algorithm", "md5") or ("usedforsecurity", "absent").
    """

    path: str
    line: int
    kind: str
    target: str
    detail: str
    attrs: tuple[tuple[str, str], ...] = ()

    def sort_key(self) -> tuple[str, str, int, str]:
        return (self.kind, self.path, self.line, self.target)


@dataclass(frozen=True, slots=True)
class SbomComponent:
    """A component declared by a PEP 770 SBOM shipped in the wheel."""

    name: str
    version: str | None
    purl: str | None
    source: str

    def sort_key(self) -> tuple[str, str, str, str]:
        # Total over every field that `==` compares, so deduplicating by set and then
        # sorting cannot leave two entries tied and let hash order pick the winner.
        return (self.name, self.version or "", self.purl or "", self.source)


@dataclass(frozen=True, slots=True)
class MetadataEvidence:
    """Layer 1 evidence: what the wheel says about itself."""

    name: str
    canonical_name: str
    version: str
    tags: tuple[str, ...] = ()
    platform_tags: tuple[str, ...] = ()
    generator_raw: str | None = None
    generator_name: str | None = None
    generator_version: str | None = None
    requires_python: str | None = None
    requires_dist: tuple[str, ...] = ()
    # Canonicalised project names extracted from requires_dist, for rule matching.
    requires_dist_names: tuple[str, ...] = ()
    root_is_purelib: bool = False
    dist_info_dir: str | None = None
    record_entries: int = 0
    record_mismatches: tuple[str, ...] = ()
    sbom_paths: tuple[str, ...] = ()
    sbom_components: tuple[SbomComponent, ...] = ()


@dataclass(frozen=True, slots=True)
class ArtifactInventory:
    """What the archive contains, independent of any rule."""

    py_files: int = 0
    pyc_files: int = 0
    source_available: bool = True
    extensions: tuple[tuple[str, str], ...] = ()
    bundled_libs: tuple[str, ...] = ()
    sboms: tuple[str, ...] = ()
    symlinks: tuple[tuple[str, str], ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()
    total_uncompressed_bytes: int = 0
    record_entries: int = 0
    # Number of .py files that could not be parsed. When every one of them failed,
    # the absence of Python findings says nothing.
    py_files_unparsed: int = 0
    # Set when the binaries list was capped, so a wheel with thousands of objects
    # cannot produce an unbounded single JSON line.
    binaries_truncated: bool = False


@dataclass(frozen=True, slots=True)
class Evidence:
    """Everything the three layers extracted from one wheel."""

    filename: str
    sha256: str
    size_bytes: int
    artifacts: ArtifactInventory
    metadata: MetadataEvidence | None = None
    binaries: tuple[BinaryEvidence, ...] = ()
    py_sites: tuple[PySite, ...] = ()
    errors: tuple[ScanError, ...] = field(default_factory=tuple)
