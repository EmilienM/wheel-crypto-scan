"""`Conventions`/`SonameInfo`, structural facts about how build tools lay wheels out,
and the `[conventions]` parser that builds one from the ruleset TOML.

The object model and its parser live together because nothing else reads either
without the other: `ruleset_loader.parse_ruleset` builds a `Conventions` from the
`[conventions]` table right after checking its shape, and every other module that
reads a soname or a vendor path goes through the object, never the raw regex. See
`DESIGN.md`, "`Conventions`/`SonameInfo` and their `[conventions]` parser move to
`conventions.py`", for why the model and parser are not part of `ruleset.py` and
`ruleset_loader.py` instead.

`_require` and `_refuse_unknown_keys` restate two checks `ruleset_loader` also
defines, rather than importing them from there: `ruleset_loader.parse_ruleset` needs
`Conventions` and `parse_conventions` from here to build a `Ruleset`, so importing
`ruleset_loader` from here too would make the two modules import each other.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any

from .errors import RulesetError

_VERSION_SUFFIX = re.compile(r"\.\d+$")

_CONVENTIONS_KEYS = frozenset(
    {
        "vendor_dir_globs",
        "mangled_soname_regex",
        "windows_version_suffix_regex",
        "cargo_path_regex",
        "cargo_vendor_path_regex",
        "weak_hash_algorithms",
        "library_suffixes",
        "windows_library_suffixes",
        "go_boring_group",
        "go_stock_group",
        "go_fips140_group",
    }
)


def _require(mapping: Mapping[str, Any], key: str, where: str) -> Any:
    try:
        return mapping[key]
    except KeyError:
        raise RulesetError(f"{where}: missing required field '{key}'") from None


def _refuse_unknown_keys(data: Mapping[str, Any], allowed: Iterable[str], where: str) -> None:
    unknown_keys = sorted(set(data) - set(allowed))
    if unknown_keys:
        raise RulesetError(f"{where}: unknown keys {unknown_keys}")


def _check_string_sequence(value: Any, label: str, where: str) -> None:
    """Restates `ruleset_loader._check_string_sequence`, not imported for the same
    reason `_require`/`_refuse_unknown_keys` above are restated instead of imported.

    Every list-valued `[conventions]` key feeds a `tuple(...)` or `frozenset(...)`
    call, and both happily iterate a bare string character by character instead of
    refusing it: `vendor_dir_globs = "abc"` would load clean as the three
    single-character globs `('a', 'b', 'c')` rather than the one three-character glob
    the ruleset writer meant.
    """
    if not isinstance(value, (list, tuple)):
        raise RulesetError(f"{where}: {label} must be a list of strings")
    for item in value:
        if not isinstance(item, str):
            raise RulesetError(f"{where}: {label} must be a list of strings")


@dataclass(frozen=True, slots=True)
class SonameInfo:
    """A library file name reduced to its base name, plus whether it was renamed.

    auditwheel, delocate and delvewheel append a content hash to every library they
    vendor, so a mangled name is itself evidence that the wheel carries its own copy.
    """

    base: str
    mangled: bool
    original: str


@dataclass(frozen=True, slots=True)
class Conventions:
    """How build tools lay wheels out. Structural facts, not policy."""

    vendor_dir_globs: tuple[str, ...]
    mangled_soname_regex: re.Pattern[str]
    windows_version_suffix_regex: re.Pattern[str]
    cargo_path_regex: re.Pattern[str]
    cargo_vendor_path_regex: re.Pattern[str]
    weak_hash_algorithms: frozenset[str]
    # No defaults, and ahead of the defaulted fields for that reason: the loader
    # refuses a ruleset whose go_boring_group/go_stock_group name no string group, and
    # a default here would let a directly built Conventions point at groups that need
    # not exist -- reinstating the silently-false boring_crypto the loader check exists
    # to prevent, wearing a dataclass default as a disguise.
    go_boring_group: str
    go_stock_group: str
    go_fips140_group: str
    library_suffixes: tuple[str, ...] = (".so", ".dylib", ".dll", ".pyd")
    windows_library_suffixes: tuple[str, ...] = (".dll", ".pyd")

    def is_vendor_path(self, path: str) -> bool:
        """True when any directory component is an auditwheel or delocate vendor dir."""
        parts = path.split("/")[:-1]
        return any(fnmatch(part, glob) for part in parts for glob in self.vendor_dir_globs)

    def _reduced_stem(self, name: str) -> tuple[str, bool]:
        """Strip path, version suffix and library extension. Shared by
        `normalise_soname` (also undoes a hash rename) and `raw_stem` (does not)."""
        stem = name.split("/")[-1]
        windows = False
        while True:
            stripped = _VERSION_SUFFIX.sub("", stem)
            for suffix in self.library_suffixes:
                # Only a Windows suffix is matched without regard to case, because only
                # Windows file names are case-insensitive. A Linux `libcrypto.SO.3` is
                # a file genuinely called that, and reducing it would be inventing one.
                on_windows = suffix in self.windows_library_suffixes
                matched = (
                    stripped.casefold().endswith(suffix.casefold())
                    if on_windows
                    else stripped.endswith(suffix)
                )
                if matched:
                    stripped = stripped[: -len(suffix)]
                    windows = windows or on_windows
                    break
            if stripped == stem:
                break
            stem = stripped
        if windows:
            stem = stem.casefold()
        return stem, windows

    def normalise_soname(self, name: str) -> SonameInfo:
        """Reduce `libcrypto-3a1f2b4c.so.3` or `libcrypto-3-x64.dll` to `libcrypto`."""
        stem, windows = self._reduced_stem(name)
        match = self.mangled_soname_regex.match(stem)  # pylint: disable=no-member
        mangled = match is not None
        if match is not None:
            stem = match.group("stem")
        if windows:
            # After the hash, so a vendored `libcrypto-3-x64-<hash>.dll` loses the hash
            # first and is still recognised as the vendored copy it is.
            decorated = self.windows_version_suffix_regex.match(stem)  # pylint: disable=no-member
            if decorated is not None:
                stem = decorated.group("stem")
        return SonameInfo(base=stem, mangled=mangled, original=name)

    def own_base(self, soname: str | None, path: str) -> str:
        """The library an object claims to be: its DT_SONAME, else its file name.

        An object that declares no SONAME is still the library its file name says it
        is, which is how a vendored copy gets recognised when the build stripped the
        declaration out.
        """
        return self.normalise_soname(soname or path.rsplit("/", 1)[-1]).base

    def raw_stem(self, soname: str | None, path: str) -> str:
        """Like `own_base`, but keeps a content-hash rename instead of undoing it, so a
        plain `needed` entry cannot match a same-family copy renamed elsewhere."""
        stem, _ = self._reduced_stem(soname or path.rsplit("/", 1)[-1])
        return stem


def parse_conventions(data: Mapping[str, Any]) -> Conventions:
    where = "[conventions]"
    if not isinstance(data, Mapping):
        raise RulesetError(f"{where}: must be a table")
    _refuse_unknown_keys(data, _CONVENTIONS_KEYS, where)
    try:
        mangled = re.compile(str(_require(data, "mangled_soname_regex", where)))
        windows = re.compile(str(_require(data, "windows_version_suffix_regex", where)))
        cargo = re.compile(str(_require(data, "cargo_path_regex", where)))
        cargo_vendor = re.compile(str(_require(data, "cargo_vendor_path_regex", where)))
    except re.error as exc:
        raise RulesetError(f"{where}: invalid regular expression: {exc}") from None
    for pattern, group in ((mangled, "stem"), (windows, "stem")):
        if group not in pattern.groupindex:
            raise RulesetError(f"{where}: pattern {pattern.pattern!r} needs a '{group}' group")
    # Both cargo conventions feed `find_rust_crates`, which reads both groups off
    # whichever one matched, so each pattern must declare both here even when a layout
    # never fills `version`: a declared-but-unmatched `version` group is how a layout
    # that names no version (`cargo vendor` without versioned directories) is told
    # apart from a pattern that forgot the group, which `find_rust_crates` would only
    # catch as an IndexError at scan time.
    for pattern in (cargo, cargo_vendor):
        for group in ("name", "version"):
            if group not in pattern.groupindex:
                raise RulesetError(f"{where}: pattern {pattern.pattern!r} needs a '{group}' group")
    vendor_dir_globs = _require(data, "vendor_dir_globs", where)
    _check_string_sequence(vendor_dir_globs, "vendor_dir_globs", where)
    weak_hash_algorithms = _require(data, "weak_hash_algorithms", where)
    _check_string_sequence(weak_hash_algorithms, "weak_hash_algorithms", where)
    raw_suffixes = _require(data, "library_suffixes", where)
    _check_string_sequence(raw_suffixes, "library_suffixes", where)
    raw_windows_suffixes = _require(data, "windows_library_suffixes", where)
    _check_string_sequence(raw_windows_suffixes, "windows_library_suffixes", where)
    suffixes = tuple(raw_suffixes)
    windows_suffixes = tuple(raw_windows_suffixes)
    # A Windows suffix that is not also stripped would never be seen, so the reduction
    # it is meant to trigger would silently never happen.
    unknown = sorted(set(windows_suffixes) - set(suffixes))
    if unknown:
        raise RulesetError(f"{where}: windows_library_suffixes {unknown} are not library_suffixes")
    return Conventions(
        vendor_dir_globs=tuple(vendor_dir_globs),
        mangled_soname_regex=mangled,
        windows_version_suffix_regex=windows,
        cargo_path_regex=cargo,
        cargo_vendor_path_regex=cargo_vendor,
        weak_hash_algorithms=frozenset(weak_hash_algorithms),
        library_suffixes=suffixes,
        windows_library_suffixes=windows_suffixes,
        go_boring_group=str(_require(data, "go_boring_group", where)),
        go_stock_group=str(_require(data, "go_stock_group", where)),
        go_fips140_group=str(_require(data, "go_fips140_group", where)),
    )
