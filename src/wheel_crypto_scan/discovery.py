"""Turns inputs (files, directories, listings, index URLs) into a deterministic wheel list.

Scan order has to be stable across hosts, because the output is JSONL in scan order and
"same input, same bytes" has to hold on a laptop and on a builder. So results are sorted
by wheel filename, with the archive-relative path as a tie-break, never by the order the
filesystem happened to hand them over.

This is also the only module that may touch the network, and only when explicitly asked
to with an index URL. Downloading the wheels themselves is the single exception to the
tool being offline; nothing else here reaches out.
"""

from __future__ import annotations

import re
import urllib.parse
import urllib.request
from collections.abc import Sequence
from pathlib import Path

WHEEL_SUFFIX = ".whl"
_HREF = re.compile(r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_USER_AGENT = "wheel-crypto-scan"


def discover(
    inputs: Sequence[str],
    *,
    from_file: Path | str | None = None,
    index_url: str | None = None,
    download_dir: Path | str | None = None,
    timeout: float = 30.0,
) -> list[Path]:
    """Resolve every input to a sorted, deduplicated list of wheel paths."""
    candidates: list[Path] = []
    for raw in list(inputs) + _read_listing(from_file):
        candidates.extend(_expand(Path(raw).expanduser()))

    if index_url is not None:
        if download_dir is None:
            raise ValueError("an index URL needs a download directory")
        candidates.extend(download_index(index_url, Path(download_dir), timeout=timeout))

    unique = {path.resolve(): path for path in candidates}
    return [unique[key] for key in sorted(unique, key=_sort_key)]


def _sort_key(path: Path) -> tuple[str, str]:
    return (path.name, path.as_posix())


def _expand(path: Path) -> list[Path]:
    if path.is_dir():
        return sorted(
            (child for child in path.rglob(f"*{WHEEL_SUFFIX}") if child.is_file()),
            key=_sort_key,
        )
    if path.is_file():
        return [path] if path.name.endswith(WHEEL_SUFFIX) else []
    raise FileNotFoundError(f"no such file or directory: {path}")


def _read_listing(from_file: Path | str | None) -> list[str]:
    if from_file is None:
        return []
    text = Path(from_file).expanduser().read_text(encoding="utf-8")
    lines = (line.strip() for line in text.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def parse_simple_index(page: str, base_url: str) -> list[str]:
    """Absolute URLs of every wheel linked from a PEP 503 simple page, sorted."""
    urls = set()
    for href in _HREF.findall(page):
        absolute = urllib.parse.urljoin(base_url, href)
        cleaned = urllib.parse.urldefrag(absolute).url
        if cleaned.endswith(WHEEL_SUFFIX):
            urls.add(cleaned)
    return sorted(urls)


def download_index(index_url: str, download_dir: Path, *, timeout: float = 30.0) -> list[Path]:
    """Fetch a simple index page and download every wheel it lists. Opt-in; uses the network."""
    download_dir.mkdir(parents=True, exist_ok=True)
    page = _fetch(index_url, timeout).decode("utf-8", errors="replace")
    downloaded = []
    for url in parse_simple_index(page, index_url):
        name = Path(urllib.parse.urlparse(url).path).name
        destination = download_dir / name
        if not destination.exists():
            destination.write_bytes(_fetch(url, timeout))
        downloaded.append(destination)
    return downloaded


def _fetch(url: str, timeout: float) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"refusing to fetch a non-http(s) URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.read()
