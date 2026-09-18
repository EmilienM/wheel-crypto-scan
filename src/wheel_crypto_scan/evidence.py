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
    symbols_truncated: bool = False
    strings_truncated: bool = False
    # Set when part of the object was not read: a format with no structural reader; a
    # PE whose section table was truncated, whose import directory was absent or could
    # not be walked, that named something by ordinal alone, or that carries a delay-load
    # import directory, which is not parsed; a Mach-O whose `LC_SYMTAB` could not be read
    # in full; or a slice of a fat binary that could not be read. A wheel can never
    # look clean merely because we read less of it than usual.
    partial_analysis: bool = False

    @property
    def is_opaque(self) -> bool:
        """True when the object told us nothing at all."""
        return not (
            self.needed
            or self.matched_symbols
            or self.matched_strings
            or self.rust_crates
            or self.dynsym_count
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
