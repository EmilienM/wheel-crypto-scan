"""Layer 3: what a wheel's Python source actually does with crypto.

Layers 1 and 2 read declarations and binaries; this layer reads code. The reason it
exists at all is that a dependency graph or a symbol table cannot tell you that a
function calls `hashlib.md5()` without `usedforsecurity=False`, or that a TLS context
turns off certificate verification. Only walking the AST can, because only the AST
resolves `import hashlib as h` into the fact that `h.md5()` and `hashlib.md5()` are the
same call. A regex over the source text cannot do that: it would need to already know
every alias a file happens to use.

This layer is deliberately shallow about scope. It builds one alias table for the whole
module from every `import` it finds, rather than tracking per-function bindings, so a
local variable that reuses an imported name (a parameter called `md5`, say) is not
recognised as shadowing the import. That trade-off is explicit, not an oversight: real
scope tracking means modelling every binding form in the grammar (parameters, `for`
targets, `with` targets, comprehension scopes, `global`/`nonlocal`) to get a handful of
adversarial cases right, and a wrong resolution here only ever adds a finding for a
human to dismiss, it never removes one that mattered. `test_python_ast.py` pins this
choice down with a test rather than leaving it implicit.

Every extractor here reads, it never judges: matching a name against
`patterns.py_call_targets` says nothing about whether that call is a problem, only that
the ruleset wants to know about it. `detail` is built from the pieces we already matched
on, never from `ast.unparse`, because unparse output is not guaranteed stable across
interpreter versions and this tool's whole contract is a byte-identical record for the
same input on every Python in the support matrix.
"""

from __future__ import annotations

import ast
import io
import tokenize
import warnings
from collections.abc import Iterator

from .. import errors
from ..evidence import (
    STAGE_PYTHON,
    USED_FOR_SECURITY_ABSENT,
    USED_FOR_SECURITY_FALSE,
    USED_FOR_SECURITY_TRUE,
    USED_FOR_SECURITY_UNRESOLVED,
    PySite,
    ScanError,
)
from ..ruleset import PythonPatterns
from ..wheelfile import WheelArchive

# A note on determinism. `ast.parse` follows the grammar of the interpreter running it,
# and `feature_version` only gates a subset of it, so a wheel using syntax newer than
# the running interpreter parses on one version and not another. Pinning the scanner's
# interpreter is what makes output byte-identical across hosts; see docs/index.md.
#
# What matters more is that the difference is never silently favourable. A file that
# fails to parse is counted in `artifacts.py_files_unparsed`, and a wheel whose every
# source file failed reports `source_available: false`, so an older interpreter reads
# such a wheel as OPAQUE rather than as clean.

# ctypes entry points that load a shared library by name. Not ruleset data: these are
# the fixed set of stdlib call shapes the `py_ctypes_load` matcher understands, whereas
# the library *names* worth flagging in their first argument come from
# `patterns.ctypes_substrings`.
_CTYPES_LOAD_TARGETS = frozenset(
    {"ctypes.CDLL", "ctypes.WinDLL", "ctypes.PyDLL", "ctypes.cdll.LoadLibrary"}
)

# hashlib constructors that get algorithm/usedforsecurity attrs. Also ruleset-adjacent
# but fixed: these three names are the only ones with the special constructor shape this
# matcher understands (a first argument or fixed name that names an algorithm, and an
# optional `usedforsecurity` keyword).
_HASHLIB_TARGETS = frozenset({"hashlib.md5", "hashlib.sha1", "hashlib.new"})

_DEFAULT_MAX_BYTES = 8 * 1024 * 1024

_SOURCE_SUFFIX = ".py"

# Both sites below record this. `RecursionError` is the exception CPython's own
# documentation names for exhausting the interpreter's recursion limit, but for deep
# expression nesting specifically, `ast.parse` measured across the whole py311-py314
# support matrix raises `MemoryError("Parser stack overflowed - Python source too
# complex to parse")` instead -- CPython's PEG parser signals its own stack exhaustion
# that way, not as a `RecursionError`. Both are caught for exactly the same reason: a
# stack limit reached depends on the interpreter's state at scan time, not the wheel's
# bytes, and neither is caught anywhere shallower than these two `try` blocks: an
# uncaught one would propagate out of this whole layer, costing every other source
# file in the wheel its evidence too, not just this one.
_STACK_EXHAUSTED = "source nesting exhausted the interpreter's parsing stack"


class _DecodeFailure(Exception):
    """Internal signal only; never escapes `scan_python_source`."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def scan_python_files(
    archive: WheelArchive, patterns: PythonPatterns, *, max_bytes: int = _DEFAULT_MAX_BYTES
) -> tuple[tuple[PySite, ...], tuple[ScanError, ...]]:
    """Read every `.py` file in the wheel, in sorted site order.

    Symlinks are skipped for the same reason Layer 2 skips them: their content is a
    path string, not source. An oversized member is refused before it is decompressed,
    so a wheel cannot spend our memory on a file we were never going to parse.
    """
    sites: list[PySite] = []
    found: list[ScanError] = []
    for member in archive.members:
        if member.is_symlink or not member.name.endswith(_SOURCE_SUFFIX):
            continue
        if member.size > max_bytes:
            found.append(
                _error(member.name, errors.PYTHON_TOO_LARGE, f"source is {member.size} bytes")
            )
            continue
        try:
            source = archive.read(member.name)
        except errors.WheelReadError as exc:
            found.append(_error(member.name, errors.MEMBER_READ_ERROR, str(exc)))
            continue
        member_sites, member_errors = scan_python_source(
            source, member.name, patterns, max_bytes=max_bytes
        )
        sites.extend(member_sites)
        found.extend(member_errors)
    return tuple(sorted(sites, key=lambda site: site.sort_key())), tuple(found)


def scan_python_source(
    source: bytes, path: str, patterns: PythonPatterns, *, max_bytes: int = _DEFAULT_MAX_BYTES
) -> tuple[tuple[PySite, ...], tuple[ScanError, ...]]:
    """Extract Layer 3 evidence from one `.py` file's raw bytes.

    Never raises: every failure this function knows how to survive is turned into a
    `ScanError` and an empty result, because one unreadable file among thousands must
    not abort the wheel.
    """
    if len(source) > max_bytes:
        message = f"source is {len(source)} bytes, exceeds the {max_bytes}-byte limit"
        return (), (_error(path, errors.PYTHON_TOO_LARGE, message),)

    # Checked on the raw bytes, deterministically, before encoding detection ever
    # sees them: both `tokenize.detect_encoding` and `ast.parse` reject a null byte
    # themselves, but which exception type they raise for it is exactly the kind of
    # interpreter-specific behaviour this tool cannot let leak into the record.
    null_at = source.find(b"\x00")
    if null_at != -1:
        line = source.count(b"\n", 0, null_at) + 1
        message = f"syntax error at line {line}: source contains a null byte"
        return (), (_error(path, errors.PYTHON_SYNTAX_ERROR, message),)

    try:
        text = _decode(source)
    except _DecodeFailure as exc:
        return (), (_error(path, errors.PYTHON_DECODE_ERROR, exc.message),)

    try:
        with warnings.catch_warnings():
            # A wheel's source is data, and its warnings are not ours to print.
            # ast.parse emits SyntaxWarning for things like invalid escape sequences,
            # which on a real index meant hundreds of lines of someone else's lint
            # landing on our stderr and corrupting anything reading our output.
            warnings.simplefilter("ignore")
            tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        line = exc.lineno or 0
        return (), (_error(path, errors.PYTHON_SYNTAX_ERROR, f"syntax error at line {line}"),)
    except (RecursionError, MemoryError):
        # Not a syntax defect: whether this fires depends on the interpreter's stack
        # depth at scan time, not the wheel's bytes. A distinct kind from
        # PYTHON_SYNTAX_ERROR for exactly that reason -- see errors.SCAN_ABORTED_KINDS.
        return (), (_error(path, errors.PYTHON_RECURSION_LIMIT_EXCEEDED, _STACK_EXHAUSTED),)

    try:
        sites = _collect_sites(tree, path, patterns)
    except (RecursionError, MemoryError):
        return (), (_error(path, errors.PYTHON_RECURSION_LIMIT_EXCEEDED, _STACK_EXHAUSTED),)

    return sites, ()


def _decode(source: bytes) -> str:
    """Decode `source` using its PEP 263 coding declaration, defaulting to UTF-8.

    `tokenize.detect_encoding` is the stdlib's own implementation of the coding-cookie
    rules, including the BOM case, so re-deriving that logic here would just be a worse
    copy of it.
    """
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(source).readline)
    except (SyntaxError, UnicodeDecodeError):
        raise _DecodeFailure("unrecognised or invalid source encoding declaration") from None
    try:
        return source.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        raise _DecodeFailure(f"source is not valid {encoding} as declared") from None


def _error(path: str, kind: str, message: str) -> ScanError:
    return ScanError(stage=STAGE_PYTHON, kind=kind, message=message, path=path)


def _collect_sites(tree: ast.AST, path: str, patterns: PythonPatterns) -> tuple[PySite, ...]:
    """Walk the parsed module once for aliases, once for `py_attr`, once for the rest.

    Three passes over an iterative `ast.walk` rather than one recursive visitor: it
    keeps each pass simple to reason about, and it means the `py_attr`-vs-`py_constant`
    double-count suppression (below) does not depend on which order a single combined
    visitor happens to reach nodes in.
    """
    aliases = _build_alias_table(tree)
    attr_sites, suppressed = _collect_attr_sites(tree, path, patterns, aliases)
    other_sites = _collect_other_sites(tree, path, patterns, aliases, suppressed)

    limit = patterns.limits.max_evidence_chars
    deduped: dict[tuple[str, str, int, str, tuple[tuple[str, str], ...]], PySite] = {}
    for site in (*attr_sites, *other_sites):
        clipped = PySite(
            path=site.path,
            line=site.line,
            kind=site.kind,
            target=site.target,
            detail=_clip(site.detail, limit),
            attrs=site.attrs,
        )
        key = (clipped.kind, clipped.path, clipped.line, clipped.target, clipped.attrs)
        deduped.setdefault(key, clipped)
    return tuple(sorted(deduped.values(), key=lambda site: site.sort_key()))


def _clip(text: str, limit: int) -> str:
    """Bound a detail string to printable ASCII, capped at `limit` characters.

    A wheel's own strings feed into `detail` (a library name, an algorithm name), and
    this is the one place every one of them passes through before becoming a `PySite`,
    so it is where a hostile literal gets neutralised rather than passed on verbatim.
    """
    ascii_text = text.encode("ascii", "replace").decode("ascii")
    safe = "".join(char if char.isprintable() else "?" for char in ascii_text)
    return safe[:limit]


# --------------------------- alias table (whole module) ---------------------------


def _build_alias_table(tree: ast.AST) -> dict[str, str]:
    """Map every name an `import` binds to the dotted path it actually refers to.

    One flat table for the whole file, per the module docstring's note on scope: this
    is what makes `h.md5()` resolve to `hashlib.md5` after `import hashlib as h`, and
    what makes a bare `import hashlib` self-map so a later reassignment of the name
    `hashlib` is (knowingly) not distinguished from the untouched module.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                qualified = alias.name if alias.asname else bound
                aliases[bound] = qualified
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                aliases[bound] = f"{node.module}.{alias.name}"
    return aliases


def _literal_chain(expr: ast.expr) -> list[str] | None:
    """Split a `Name`/`Attribute` chain into its dotted parts, root first.

    Returns `None` for anything else (a call result, a subscript, ...), since there is
    no stable dotted name to report for those.
    """
    parts: list[str] = []
    cur: ast.expr = expr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    parts.append(cur.id)
    parts.reverse()
    return parts


def _resolve_name_chain(expr: ast.expr, aliases: dict[str, str]) -> str | None:
    """Resolve a `Name`/`Attribute` chain to its fully qualified dotted name."""
    parts = _literal_chain(expr)
    if parts is None:
        return None
    root, *rest = parts
    resolved_root = aliases.get(root, root)
    return ".".join([resolved_root, *rest]) if rest else resolved_root


def _resolve_call_target(expr: ast.expr, aliases: dict[str, str]) -> tuple[str, str] | None:
    """Resolve a call's callee both through aliases and as written.

    Returning both lets the caller note "via alias ..." exactly when they differ,
    without re-walking the chain a second time.
    """
    parts = _literal_chain(expr)
    if parts is None:
        return None
    literal = ".".join(parts)
    root, *rest = parts
    resolved_root = aliases.get(root, root)
    resolved = ".".join([resolved_root, *rest]) if rest else resolved_root
    return resolved, literal


def _module_match(dotted: str, modules: tuple[str, ...]) -> str | None:
    """The ruleset module name that `dotted` matches, by dotted-prefix, or `None`."""
    for entry in modules:
        if dotted == entry or dotted.startswith(entry + "."):
            return entry
    return None


# ------------------------------- py_attr (+ suppression) -------------------------------


# Augmented assignment operators, spelled out so `detail` never depends on how a given
# interpreter version happens to render an AST node.
_AUG_OPERATORS: dict[type, str] = {
    ast.Add: "+",
    ast.BitAnd: "&",
    ast.BitOr: "|",
    ast.BitXor: "^",
    ast.Sub: "-",
}


def _flatten_targets(targets: list[ast.expr]) -> Iterator[ast.expr]:
    """Yield assignment targets, descending into tuple and list unpacking."""
    for target in targets:
        if isinstance(target, (ast.Tuple, ast.List)):
            yield from _flatten_targets(list(target.elts))
        elif isinstance(target, ast.Starred):
            yield from _flatten_targets([target.value])
        else:
            yield target


def _collect_attr_sites(
    tree: ast.AST, path: str, patterns: PythonPatterns, aliases: dict[str, str]
) -> tuple[list[PySite], set[int]]:
    """Find `py_attr` sites and the value nodes they already accounted for.

    The returned id-set feeds `_collect_other_sites`, so that `ctx.verify_mode =
    ssl.CERT_NONE` is not reported a second time as a bare `py_constant` reference to
    `ssl.CERT_NONE`: it is the same piece of evidence seen from the assignment's target
    versus its value, and the engine would double-count it if we emitted both.
    """
    sites: list[PySite] = []
    suppressed: set[int] = set()
    for node in ast.walk(tree):
        operator = ""
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            if node.value is None:
                continue
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.AugAssign):
            # `ctx.options |= ssl.OP_NO_TLSv1_1` is how TLS options are set in
            # practice, far more often than a plain assignment, so an assignment
            # scanner that only understood `=` would miss the common case.
            targets = [node.target]
            value = node.value
            operator = _AUG_OPERATORS.get(type(node.op), "op")
        else:
            continue

        matches: list[tuple[str, int]] = []
        for target in _flatten_targets(targets):
            name: str | None = None
            if isinstance(target, ast.Attribute):
                name = target.attr
            elif isinstance(target, ast.Name):
                name = target.id
            if name is not None and name in patterns.py_attributes:
                matches.append((name, target.lineno))
        if not matches:
            continue

        value_text = _assigned_value_text(value, aliases)
        if isinstance(value, (ast.Attribute, ast.Name)):
            suppressed.add(id(value))
        for name, line in matches:
            detail = f"{name} {operator}= {value_text}" if operator else f"{name} = {value_text}"
            sites.append(
                PySite(
                    path=path,
                    line=line,
                    kind="py_attr",
                    target=name,
                    detail=detail,
                    attrs=(("value", value_text),),
                )
            )
    return sites, suppressed


def _assigned_value_text(value: ast.expr, aliases: dict[str, str]) -> str:
    """Plain-text rendering of an assigned value, for `py_attr`'s `attrs`/`detail`.

    A constant renders with `str()`, deliberately not `repr()`, so `"CERT_NONE"` reads
    as `CERT_NONE` rather than `'CERT_NONE'` -- there is no ambiguity to resolve since
    this is evidence text, not code.
    """
    if isinstance(value, ast.Constant):
        return str(value.value)
    resolved = _resolve_name_chain(value, aliases)
    return resolved if resolved is not None else "unresolved"


# --------------------------- everything else: one combined walk ---------------------------


def _collect_other_sites(
    tree: ast.AST,
    path: str,
    patterns: PythonPatterns,
    aliases: dict[str, str],
    suppressed: set[int],
) -> list[PySite]:
    """Find `py_import`, `py_call`, `py_ctypes_load` and `py_constant` sites."""
    sites: list[PySite] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            sites.extend(_import_sites(node, path, patterns))
        elif isinstance(node, ast.ImportFrom):
            sites.extend(_import_from_sites(node, path, patterns))
        elif isinstance(node, ast.Call):
            sites.extend(_call_sites(node, path, patterns, aliases))
        elif isinstance(node, (ast.Attribute, ast.Name)) and isinstance(node.ctx, ast.Load):
            if id(node) in suppressed:
                continue
            resolved = _resolve_name_chain(node, aliases)
            if resolved is not None and resolved in patterns.py_constants:
                sites.append(
                    PySite(
                        path=path,
                        line=node.lineno,
                        kind="py_constant",
                        target=resolved,
                        detail=resolved,
                    )
                )
    return sites


def _import_sites(node: ast.Import, path: str, patterns: PythonPatterns) -> list[PySite]:
    sites: list[PySite] = []
    for alias in node.names:
        matched = _module_match(alias.name, patterns.py_modules)
        if matched is None:
            continue
        detail = f"import {alias.name}"
        if alias.asname:
            detail += f" as {alias.asname}"
        line = getattr(alias, "lineno", node.lineno)
        sites.append(PySite(path=path, line=line, kind="py_import", target=matched, detail=detail))
    return sites


def _import_from_sites(node: ast.ImportFrom, path: str, patterns: PythonPatterns) -> list[PySite]:
    if node.module is None:
        return []
    matched = _module_match(node.module, patterns.py_modules)
    if matched is None:
        return []
    sites: list[PySite] = []
    for alias in node.names:
        detail = f"from {node.module} import {alias.name}"
        if alias.asname:
            detail += f" as {alias.asname}"
        line = getattr(alias, "lineno", node.lineno)
        sites.append(PySite(path=path, line=line, kind="py_import", target=matched, detail=detail))
    return sites


def _call_sites(
    call: ast.Call, path: str, patterns: PythonPatterns, aliases: dict[str, str]
) -> list[PySite]:
    resolved_pair = _resolve_call_target(call.func, aliases)
    if resolved_pair is None:
        return []
    resolved, literal = resolved_pair

    sites: list[PySite] = []
    if resolved in _CTYPES_LOAD_TARGETS:
        sites.extend(_ctypes_load_sites(call, path, resolved, patterns))

    matched_target = _match_call_target(resolved, patterns.py_call_targets)
    if matched_target is not None:
        sites.append(_call_site(call, path, matched_target, resolved, literal))
    return sites


def _match_call_target(resolved: str, targets: tuple[str, ...]) -> str | None:
    """The ruleset target string a resolved callee matches, exact or `*.method`."""
    if resolved in targets:
        return resolved
    for target in targets:
        if target.startswith("*.") and resolved.endswith("." + target[2:]):
            return target
    return None


def _call_site(
    call: ast.Call, path: str, matched_target: str, resolved: str, literal: str
) -> PySite:
    attrs: tuple[tuple[str, str], ...] = ()
    extras: list[str] = []
    if matched_target in _HASHLIB_TARGETS:
        algorithm = _hashlib_algorithm(matched_target, call)
        used = _hashlib_usedforsecurity(call)
        attrs = tuple(sorted({"algorithm": algorithm, "usedforsecurity": used}.items()))
        if matched_target == "hashlib.new":
            extras.append(f"algorithm={algorithm}")
        extras.append(f"usedforsecurity={used}")

    alias_note = "" if literal == resolved else f" via alias {literal}"
    tail = f", {', '.join(extras)}" if extras else ""
    detail = f"{resolved}(...)" + alias_note + tail
    return PySite(
        path=path,
        line=call.lineno,
        kind="py_call",
        target=matched_target,
        detail=detail,
        attrs=attrs,
    )


def _hashlib_algorithm(matched_target: str, call: ast.Call) -> str:
    if matched_target in ("hashlib.md5", "hashlib.sha1"):
        return matched_target.split(".")[1]
    # hashlib.new(name, ...): only a literal first argument tells us the algorithm.
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.lower()
    return "unresolved"


def _hashlib_usedforsecurity(call: ast.Call) -> str:
    for keyword in call.keywords:
        if keyword.arg != "usedforsecurity":
            continue
        if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, bool):
            return USED_FOR_SECURITY_TRUE if keyword.value.value else USED_FOR_SECURITY_FALSE
        return USED_FOR_SECURITY_UNRESOLVED
    return USED_FOR_SECURITY_ABSENT


def _ctypes_load_sites(
    call: ast.Call, path: str, resolved: str, patterns: PythonPatterns
) -> list[PySite]:
    if not call.args:
        return []
    first = call.args[0]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return []
    literal_value = first.value
    sites: list[PySite] = []
    for substring in patterns.ctypes_substrings:
        if substring in literal_value:
            detail = f'{resolved}("{literal_value}")'
            sites.append(
                PySite(
                    path=path,
                    line=call.lineno,
                    kind="py_ctypes_load",
                    target=substring,
                    detail=detail,
                    attrs=(("library", literal_value),),
                )
            )
    return sites
