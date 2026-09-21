"""tox.ini's lint gate and docs/contributing.md's copy of it stay in step.

PLC0415 ("import should be at the top level of a file") only became a stable, non-preview
ruff rule in 0.12.0. On any ruff from 0.6 to 0.11, `--select` naming it prints a warning
and matches nothing, so the lint gate passes even over an in-function import: the
`ruff>=` floor in `[testenv:lint]` (and `[testenv:format]`, kept identical to it) has to
keep the rule enforceable, and docs/contributing.md's copy of the `tox -e lint` comment
has to keep matching the real command in tox.ini rather than silently drifting from it.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOX_INI = ROOT / "tox.ini"
CONTRIBUTING = ROOT / "docs" / "contributing.md"

# ruff made PLC0415 a stable (non-preview) rule in 0.12.0.
_MIN_RUFF_FOR_PLC0415 = (0, 12)


def _env_block(text: str, name: str) -> str:
    match = re.search(rf"\[testenv:{name}\](.*?)(?=\n\[|\Z)", text, re.DOTALL)
    assert match, f"no [testenv:{name}] section in tox.ini"
    return match.group(1)


def _ruff_floor(block: str) -> tuple[int, int]:
    match = re.search(r"ruff>=(\d+)\.(\d+)", block)
    assert match, f"no ruff>=X.Y floor found in:\n{block}"
    return int(match.group(1)), int(match.group(2))


def _select_arg(text: str) -> str:
    match = re.search(r"ruff check --select=(\S+)", text)
    assert match, f"no 'ruff check --select=...' found in:\n{text}"
    return match.group(1).rstrip(",")


def test_lint_ruff_floor_supports_plc0415() -> None:
    lint_block = _env_block(TOX_INI.read_text(encoding="utf-8"), "lint")
    assert _ruff_floor(lint_block) >= _MIN_RUFF_FOR_PLC0415


def test_format_env_ruff_floor_matches_lint() -> None:
    tox_ini = TOX_INI.read_text(encoding="utf-8")
    assert _ruff_floor(_env_block(tox_ini, "format")) == _ruff_floor(_env_block(tox_ini, "lint"))


def test_contributing_lint_comment_matches_tox_command() -> None:
    lint_block = _env_block(TOX_INI.read_text(encoding="utf-8"), "lint")
    contributing = CONTRIBUTING.read_text(encoding="utf-8")
    assert _select_arg(contributing) == _select_arg(lint_block)
