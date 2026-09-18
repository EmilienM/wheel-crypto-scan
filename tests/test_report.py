"""The human-readable summary table."""

from __future__ import annotations

from wheel_crypto_scan.report import render_markdown


def record(name: str, klass: str, linkage: str, review: bool = True) -> dict:
    return {
        "wheel": {"filename": f"{name}-1.0-py3-none-any.whl", "name": name, "version": "1.0"},
        "verdict": {
            "class": klass,
            "classes": [klass],
            "conditions": {"openssl_linkage": linkage},
            "needs_human_review": review,
            "reasons": [f"RULE_{klass}: {name}"],
            "rule_ids": [f"RULE_{klass}"],
        },
        "findings": [],
    }


def test_markdown_has_a_row_per_wheel() -> None:
    table = render_markdown([record("a", "CONDITIONAL", "bundled"), record("b", "OPAQUE", "none")])
    assert table.count("\n| ") >= 2
    assert "a-1.0-py3-none-any.whl" in table
    assert "b-1.0-py3-none-any.whl" in table


def test_markdown_shows_the_class_and_the_openssl_linkage() -> None:
    table = render_markdown([record("cryptography", "CONDITIONAL", "bundled")])
    assert "CONDITIONAL" in table
    assert "bundled" in table


def test_markdown_marks_wheels_needing_review() -> None:
    table = render_markdown([record("a", "CONDITIONAL", "bundled", review=True)])
    assert "yes" in table


def test_markdown_rows_are_sorted_by_filename() -> None:
    table = render_markdown([record("z", "OPAQUE", "none"), record("a", "OPAQUE", "none")])
    assert table.index("a-1.0") < table.index("z-1.0")


def test_markdown_handles_an_empty_run() -> None:
    assert "no wheels" in render_markdown([]).lower()


def test_markdown_never_claims_compliance() -> None:
    table = render_markdown([record("a", "NO_CRYPTO_DETECTED", "none", review=False)])
    assert "compliant" not in table.lower()
    assert "compatible" not in table.lower()
