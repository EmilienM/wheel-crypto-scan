"""Tests for the Layer 3 (Python source) AST scanner.

Every source is an inline `bytes` literal: this layer never touches the filesystem, so
neither should its tests. The one exception is `scan_python_files`, whose whole job is
the archive walk, so its test builds a real wheel. Detail strings are asserted verbatim
wherever the spec commits to a shape, precisely so a future change to synthesis (or a
slide back to `ast.unparse`) gets caught here rather than discovered downstream.
"""

from __future__ import annotations

import pytest

from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan.evidence import USED_FOR_SECURITY_VALUES
from wheel_crypto_scan.layers import python_ast
from wheel_crypto_scan.layers.python_ast import scan_python_files, scan_python_source
from wheel_crypto_scan.ruleset import PythonPatterns
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.wheelfile import WheelArchive

PATTERNS: PythonPatterns = load_ruleset().compile_patterns().python


def _kinds(sites, kind):
    return [site for site in sites if site.kind == kind]


# --------------------------------- py_import ---------------------------------


def test_import_hashlib_reported_json_not():
    src = b"import hashlib\nimport json\n"
    sites, scan_errors = scan_python_source(src, "pkg/mod.py", PATTERNS)

    assert scan_errors == ()
    imports = _kinds(sites, "py_import")
    assert len(imports) == 1
    site = imports[0]
    assert site.target == "hashlib"
    assert site.line == 1
    assert site.detail == "import hashlib"
    assert not any(site.target == "json" for site in sites)


def test_import_submodule_matches_dotted_prefix():
    src = b"import nacl.secret\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    assert scan_errors == ()
    imports = _kinds(sites, "py_import")
    assert len(imports) == 1
    assert imports[0].target == "nacl"
    assert imports[0].detail == "import nacl.secret"


def test_from_import_matches_module_name():
    src = b"from nacl import utils\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    assert scan_errors == ()
    imports = _kinds(sites, "py_import")
    assert len(imports) == 1
    assert imports[0].target == "nacl"
    assert imports[0].detail == "from nacl import utils"


# ---------------------------------- py_call: hashlib ----------------------------------


def test_md5_call_usedforsecurity_absent():
    src = b"import hashlib\nhashlib.md5()\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    assert scan_errors == ()
    calls = _kinds(sites, "py_call")
    assert len(calls) == 1
    site = calls[0]
    assert site.target == "hashlib.md5"
    assert site.line == 2
    assert site.attrs == (("algorithm", "md5"), ("usedforsecurity", "absent"))
    assert site.detail == "hashlib.md5(...), usedforsecurity=absent"


def test_md5_call_usedforsecurity_false():
    src = b"import hashlib\nhashlib.md5(usedforsecurity=False)\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    calls = _kinds(sites, "py_call")
    assert len(calls) == 1
    assert calls[0].attrs == (("algorithm", "md5"), ("usedforsecurity", "false"))
    assert calls[0].detail == "hashlib.md5(...), usedforsecurity=false"


def test_md5_call_usedforsecurity_true():
    src = b"import hashlib\nhashlib.md5(usedforsecurity=True)\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    calls = _kinds(sites, "py_call")
    assert calls[0].attrs == (("algorithm", "md5"), ("usedforsecurity", "true"))
    assert calls[0].detail == "hashlib.md5(...), usedforsecurity=true"


def test_md5_call_usedforsecurity_unresolved():
    src = b"import hashlib\nflag = True\nhashlib.md5(usedforsecurity=flag)\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    calls = _kinds(sites, "py_call")
    assert len(calls) == 1
    assert calls[0].attrs == (("algorithm", "md5"), ("usedforsecurity", "unresolved"))
    assert calls[0].detail == "hashlib.md5(...), usedforsecurity=unresolved"


def test_every_usedforsecurity_shape_produces_a_value_ruleset_loader_accepts():
    """`ruleset_loader` refuses a `usedforsecurity` value outside
    `evidence.USED_FOR_SECURITY_VALUES` (#82), on the assumption that those are the
    only values `_hashlib_usedforsecurity` can ever produce. The four tests above pin
    each shape's literal string; this pins that the four literals are exactly that
    set, not a superset or a subset of it, so a fifth shape added to
    `_hashlib_usedforsecurity` without a matching update to `USED_FOR_SECURITY_VALUES`
    fails here instead of making the loader wrongly refuse (or wrongly accept) a
    value the extractor can genuinely produce.
    """
    absent = b"import hashlib\nhashlib.md5()\n"
    false = b"import hashlib\nhashlib.md5(usedforsecurity=False)\n"
    true = b"import hashlib\nhashlib.md5(usedforsecurity=True)\n"
    unresolved = b"import hashlib\nflag = True\nhashlib.md5(usedforsecurity=flag)\n"

    produced = set()
    for src in (absent, false, true, unresolved):
        sites, _errors = scan_python_source(src, "m.py", PATTERNS)
        produced.add(dict(_kinds(sites, "py_call")[0].attrs)["usedforsecurity"])

    assert produced == USED_FOR_SECURITY_VALUES


def test_hashlib_new_literal_and_variable_algorithm():
    src = b"import hashlib\nname = 'x'\nhashlib.new('MD5')\nhashlib.new(name)\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    calls = sorted(_kinds(sites, "py_call"), key=lambda site: site.line)
    assert len(calls) == 2
    assert calls[0].line == 3
    assert calls[0].attrs == (("algorithm", "md5"), ("usedforsecurity", "absent"))
    assert calls[0].detail == "hashlib.new(...), algorithm=md5, usedforsecurity=absent"
    assert calls[1].line == 4
    assert calls[1].attrs == (("algorithm", "unresolved"), ("usedforsecurity", "absent"))
    assert calls[1].detail == "hashlib.new(...), algorithm=unresolved, usedforsecurity=absent"


def test_import_alias_resolves_call():
    src = b"import hashlib as h\nh.md5()\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    calls = _kinds(sites, "py_call")
    assert len(calls) == 1
    assert calls[0].target == "hashlib.md5"
    assert calls[0].detail == "hashlib.md5(...) via alias h.md5, usedforsecurity=absent"


def test_from_import_alias_resolves_call():
    src = b"from hashlib import md5 as m\nm()\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    calls = _kinds(sites, "py_call")
    assert len(calls) == 1
    assert calls[0].target == "hashlib.md5"
    assert calls[0].detail == "hashlib.md5(...) via alias m, usedforsecurity=absent"


def test_local_shadow_of_import_is_not_tracked():
    """Documents the shadowing decision: out of scope.

    This layer resolves calls through one whole-module alias table (see the module
    docstring in `python_ast.py`). It does not model per-scope bindings, so a parameter
    that reuses an imported name is not recognised as shadowing it, and the call below
    is (incorrectly, but knowingly) still reported as `hashlib.md5`. If a future change
    adds real scope tracking, this test should start failing and should be updated
    rather than silently continuing to pass.
    """
    src = b"from hashlib import md5\n\n\ndef make_digest(md5):\n    return md5()\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    calls = _kinds(sites, "py_call")
    assert len(calls) == 1
    assert calls[0].target == "hashlib.md5"
    assert calls[0].line == 5


# ------------------------------- py_call: TLS policy -------------------------------


def test_set_ciphers_wildcard_matches_any_receiver():
    src = b"import ssl\nctx = ssl.SSLContext()\nctx.set_ciphers('RC4')\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    wildcard_calls = [s for s in _kinds(sites, "py_call") if s.target == "*.set_ciphers"]
    assert len(wildcard_calls) == 1
    site = wildcard_calls[0]
    assert site.line == 3
    assert site.attrs == ()
    assert site.detail == "ctx.set_ciphers(...)"


# ------------------------------------ py_attr ------------------------------------


def test_check_hostname_false():
    src = b"ctx.check_hostname = False\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    attr_sites = _kinds(sites, "py_attr")
    assert len(attr_sites) == 1
    site = attr_sites[0]
    assert site.target == "check_hostname"
    assert site.line == 1
    assert site.attrs == (("value", "False"),)
    assert site.detail == "check_hostname = False"


def test_verify_mode_cert_none_has_no_duplicate_constant():
    src = b"import ssl\nctx.verify_mode = ssl.CERT_NONE\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    attr_sites = _kinds(sites, "py_attr")
    assert len(attr_sites) == 1
    assert attr_sites[0].target == "verify_mode"
    assert attr_sites[0].attrs == (("value", "ssl.CERT_NONE"),)
    assert attr_sites[0].detail == "verify_mode = ssl.CERT_NONE"

    # The point of the test: ssl.CERT_NONE is itself a py_constants entry, so a naive
    # implementation would also report it as a standalone py_constant on this line.
    assert _kinds(sites, "py_constant") == []


# ---------------------------------- py_constant ----------------------------------


def test_legacy_tls_protocol_constant_referenced():
    src = b"import ssl\nproto = ssl.PROTOCOL_TLSv1\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    const_sites = _kinds(sites, "py_constant")
    assert len(const_sites) == 1
    assert const_sites[0].target == "ssl.PROTOCOL_TLSv1"
    assert const_sites[0].line == 2
    assert const_sites[0].detail == "ssl.PROTOCOL_TLSv1"


# --------------------------------- py_ctypes_load ---------------------------------


def test_ctypes_cdll_matches_known_substring_only():
    src = (
        b"import ctypes\n"
        b'ctypes.CDLL("libcrypto.so.3")\n'
        b'ctypes.CDLL("libc.so.6")\n'
        b"name = 'libcrypto.so.3'\n"
        b"ctypes.CDLL(name)\n"
    )
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    loads = _kinds(sites, "py_ctypes_load")
    assert len(loads) == 1
    site = loads[0]
    assert site.line == 2
    assert site.target == "libcrypto"
    assert site.attrs == (("library", "libcrypto.so.3"),)
    assert site.detail == 'ctypes.CDLL("libcrypto.so.3")'


def test_ctypes_cdll_load_library_via_alias():
    src = b'from ctypes import CDLL\nCDLL("libssl.so.3")\n'
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    loads = _kinds(sites, "py_ctypes_load")
    assert len(loads) == 1
    assert loads[0].target == "libssl"
    assert loads[0].detail == 'ctypes.CDLL("libssl.so.3")'


# ------------------------------------ line numbers ------------------------------------


def test_line_numbers_on_multiline_source():
    src = b"import hashlib\n\n\ndef f():\n    hashlib.md5()\n\n\n    hashlib.sha1()\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    calls = {site.target: site.line for site in _kinds(sites, "py_call")}
    assert calls["hashlib.md5"] == 5
    assert calls["hashlib.sha1"] == 8
    assert _kinds(sites, "py_import")[0].line == 1


# ------------------------------------ robustness ------------------------------------


def test_syntax_error_is_recorded_not_raised():
    src = b"def f(:\n    pass\n"
    sites, scan_errors = scan_python_source(src, "bad.py", PATTERNS)

    assert sites == ()
    assert len(scan_errors) == 1
    error = scan_errors[0]
    assert error.stage == "python"
    assert error.kind == "python_syntax_error"
    assert error.path == "bad.py"


def test_deeply_nested_parens_hit_the_syntax_guard_not_the_stack_limit():
    # Well past the parser's own "too many nested parentheses" guard, which this
    # interpreter (and, per the guard's own name, presumably every interpreter in the
    # support matrix) reaches before nesting could ever exhaust the parsing stack.
    # This is the deterministic, permanent-defect case; see the stack-exhaustion
    # tests below for the genuinely non-deterministic one, which parenthesized
    # nesting specifically never reaches.
    src = b"x = " + b"(" * 300 + b"1" + b")" * 300 + b"\n"
    sites, scan_errors = scan_python_source(src, "deep.py", PATTERNS)

    assert sites == ()
    assert len(scan_errors) == 1
    assert scan_errors[0].kind == "python_syntax_error"


def test_deeply_nested_non_paren_expressions_exhaust_the_parsing_stack():
    """#109's real-world reproduction: CPython's PEG parser signals its own stack
    exhaustion for deep *non-paren* expression nesting as `MemoryError` ("Parser
    stack overflowed - Python source too complex to parse"), not `RecursionError` --
    measured across the whole py311-py314 support matrix. Before this fix, nothing in
    this layer caught it: it propagated out of `scan_python_source` (whose own
    docstring promises "Never raises"), past `scan_python_files`, and cost every
    other source file in the wheel its evidence too, not just this one -- the
    "one bad file never costs more than itself" invariant broken outright for a
    23 KiB file. A natural reproduction, not a monkeypatch, since this is the shape
    that actually happens.
    """
    src = b"x = " + b"not " * 6000 + b"1\n"
    sites, scan_errors = scan_python_source(src, "deep.py", PATTERNS)

    assert sites == ()
    assert len(scan_errors) == 1
    error = scan_errors[0]
    assert error.kind == "python_recursion_limit_exceeded"
    assert error.path == "deep.py"


def test_a_recursion_error_from_ast_parse_gets_its_own_kind(monkeypatch):
    """#109: unlike the `SyntaxError` case above -- a real, permanent defect in the
    wheel's own bytes -- a `RecursionError` or `MemoryError` here depends on the
    interpreter's stack depth at scan time, not the source. It must not share
    `python_syntax_error`'s kind, since that kind stays outside
    `errors.SCAN_ABORTED_KINDS` precisely because most of its occurrences ARE
    permanent and must not be re-scanned forever; sharing the kind would mean this
    genuinely transient cause can never safely leave the cache.

    `RecursionError` specifically is monkeypatched rather than triggered naturally:
    the test above already gives the real, naturally-occurring `MemoryError` shape a
    natural reproduction; nothing found in this codebase or interpreter matrix
    naturally raises `RecursionError` from `ast.parse` itself, so this pins the
    `except` clause covers it too, defensively, without depending on one existing.
    """

    def _raise(*_args, **_kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(python_ast.ast, "parse", _raise)
    src = b"import hashlib\nhashlib.md5()\n"
    sites, scan_errors = scan_python_source(src, "deep.py", PATTERNS)

    assert sites == ()
    assert len(scan_errors) == 1
    error = scan_errors[0]
    assert error.kind == "python_recursion_limit_exceeded"
    assert error.path == "deep.py"
    assert "stack" in error.message


def test_a_recursion_error_from_the_tree_walk_gets_its_own_kind(monkeypatch):
    """The second site: a `RecursionError` raised by `_collect_sites` walking an
    already-successfully-parsed tree, not by `ast.parse` itself. Both sites share
    the same kind and the same message, so a consumer cannot tell them apart -- both
    are equally "not the wheel's bytes deciding this" either way. `_collect_sites`
    itself is iterative (built on `ast.walk`), so this too has no known natural
    trigger and is pinned defensively, the same as the `RecursionError` case above.
    """

    def _raise(*_args, **_kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(python_ast, "_collect_sites", _raise)
    src = b"import hashlib\nhashlib.md5()\n"
    sites, scan_errors = scan_python_source(src, "deep.py", PATTERNS)

    assert sites == ()
    assert len(scan_errors) == 1
    assert scan_errors[0].kind == "python_recursion_limit_exceeded"


def test_null_byte_is_recorded_not_raised():
    src = b"x = 1\x00\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    assert sites == ()
    assert len(scan_errors) == 1
    assert scan_errors[0].kind == "python_syntax_error"


def test_source_too_large_is_recorded_and_nothing_is_scanned():
    src = b"import hashlib\nhashlib.md5()\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS, max_bytes=5)

    assert sites == ()
    assert len(scan_errors) == 1
    assert scan_errors[0].kind == "python_too_large"


def test_empty_file_is_survived():
    sites, scan_errors = scan_python_source(b"", "m.py", PATTERNS)
    assert sites == ()
    assert scan_errors == ()


def test_comments_only_file_is_survived():
    src = b"# nothing here\n# still nothing\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)
    assert sites == ()
    assert scan_errors == ()


def test_future_annotations_is_survived():
    src = b"from __future__ import annotations\n\n\ndef f(x: int) -> int:\n    return x\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)
    assert scan_errors == ()


def test_latin1_coding_declaration_decodes():
    text = "# coding: latin-1\nname = 'café'\nimport hashlib\n"
    src = text.encode("latin-1")
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    assert scan_errors == ()
    assert any(site.target == "hashlib" for site in _kinds(sites, "py_import"))


def test_utf8_bom_decodes():
    src = b"\xef\xbb\xbfimport hashlib\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    assert scan_errors == ()
    imports = _kinds(sites, "py_import")
    assert len(imports) == 1
    assert imports[0].target == "hashlib"
    assert imports[0].line == 1


# ------------------------------------ determinism ------------------------------------


def test_deterministic_and_sorted():
    src = b"import hashlib\nimport ssl\nhashlib.sha1()\nhashlib.md5()\nctx.check_hostname = False\n"
    sites_a, errors_a = scan_python_source(src, "m.py", PATTERNS)
    sites_b, errors_b = scan_python_source(src, "m.py", PATTERNS)

    assert sites_a == sites_b
    assert errors_a == errors_b
    assert list(sites_a) == sorted(sites_a, key=lambda site: site.sort_key())


def test_detail_is_synthesised_not_unparsed():
    src = b"import hashlib as h\nh.md5()\n"
    sites, scan_errors = scan_python_source(src, "m.py", PATTERNS)

    call = _kinds(sites, "py_call")[0]
    # ast.unparse would render this call site as "h.md5()": no alias note, no
    # usedforsecurity annotation. Assert the synthesised text instead so a refactor
    # toward ast.unparse fails this test rather than silently changing the record.
    assert call.detail == "hashlib.md5(...) via alias h.md5, usedforsecurity=absent"
    assert call.detail != "h.md5()"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_augmented_assignment_to_a_tracked_attribute_is_found() -> None:
    """`ctx.options |= ...` is how TLS options are set far more often than `=`."""
    source = b"import ssl\nctx = ssl.SSLContext()\nctx.options |= ssl.OP_NO_TLSv1_1\n"
    sites, found = scan_python_source(source, "pkg/m.py", PATTERNS)
    assert found == ()
    attrs = [site for site in sites if site.kind == "py_attr"]
    assert len(attrs) == 1
    assert attrs[0].target == "options"
    assert attrs[0].line == 3
    assert attrs[0].detail == "options |= ssl.OP_NO_TLSv1_1"


def test_an_augmented_assignment_records_the_operator_deterministically() -> None:
    source = b"import ssl\nctx = ssl.SSLContext()\nctx.options &= ssl.OP_NO_TLSv1_1\n"
    sites, _ = scan_python_source(source, "pkg/m.py", PATTERNS)
    assert [site.detail for site in sites if site.kind == "py_attr"] == [
        "options &= ssl.OP_NO_TLSv1_1"
    ]


def test_a_tracked_attribute_inside_tuple_unpacking_is_found() -> None:
    source = b"import ssl\nctx = ssl.SSLContext()\na, ctx.check_hostname = 1, False\n"
    sites, _ = scan_python_source(source, "pkg/m.py", PATTERNS)
    assert [site.target for site in sites if site.kind == "py_attr"] == ["check_hostname"]


def test_an_untracked_augmented_assignment_is_ignored() -> None:
    source = b"total = 0\ntotal += 1\n"
    sites, _ = scan_python_source(source, "pkg/m.py", PATTERNS)
    assert [site for site in sites if site.kind == "py_attr"] == []


# --------------------------- walking the archive ---------------------------


def test_every_source_member_is_read_in_archive_order(tmp_path) -> None:
    """`scan_python_files` picks the members; everything above tests one file's bytes."""
    wheel = build_wheel(
        tmp_path / "demo-1.0-py3-none-any.whl",
        name="demo",
        version="1.0",
        files={
            "demo/b.py": b"import hashlib\n",
            "demo/a.py": b"import ssl\n",
            "demo/data.txt": b"import hashlib\n",
        },
    )
    with WheelArchive.open(wheel) as archive:
        sites, scan_errors = scan_python_files(archive, PATTERNS)

    assert scan_errors == ()
    assert [(site.path, site.target) for site in sites] == [
        ("demo/a.py", "ssl"),
        ("demo/b.py", "hashlib"),
    ]
