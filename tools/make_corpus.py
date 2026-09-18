"""Build a corpus of synthetic wheels for the determinism gate.

Kept out of `tests/` because it is a CI helper rather than a test, but it reuses the
same deterministic builders so the corpus is byte-identical wherever it is generated.

    python tools/make_corpus.py OUT_DIR [COUNT]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from helpers.binfmt import DynSym, ElfBuilder  # noqa: E402
from helpers.wheelbuilder import build_wheel  # noqa: E402

MANYLINUX = "cp39-abi3-manylinux_2_28_x86_64"
BANNER = b"OpenSSL 3.0.14 4 Jun 2024\x00"
CARGO = b"/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs\x00"
SOURCE = b"""import hashlib
import ssl


def fingerprint(data):
    return hashlib.md5(data).hexdigest()


def checksum(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.options |= ssl.OP_NO_TLSv1_1
    ctx.check_hostname = False
    return ctx
"""


def _system(directory: Path, name: str) -> None:
    build_wheel(
        directory / f"{name}-1.0-{MANYLINUX}.whl",
        name=name,
        version="1.0",
        tags=(MANYLINUX,),
        files={
            f"{name}/__init__.py": SOURCE,
            f"{name}/_ext.abi3.so": ElfBuilder(
                needed=("libcrypto.so.3", "libssl.so.3", "libc.so.6"),
                dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
            ).build(),
        },
    )


def _bundled(directory: Path, name: str) -> None:
    build_wheel(
        directory / f"{name}-1.0-{MANYLINUX}.whl",
        name=name,
        version="1.0",
        tags=(MANYLINUX,),
        files={
            f"{name}/__init__.py": SOURCE,
            f"{name}/_ext.abi3.so": ElfBuilder(
                needed=("libcrypto-3a1f2b4c.so.3", "libc.so.6"),
                dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
            ).build(),
            f"{name}.libs/libcrypto-3a1f2b4c.so.3": ElfBuilder(
                soname="libcrypto-3a1f2b4c.so.3",
                dynsyms=(DynSym("EVP_DigestInit_ex", defined=True),),
                rodata=BANNER,
            ).build(),
        },
    )


def _rust(directory: Path, name: str) -> None:
    build_wheel(
        directory / f"{name}-1.0-{MANYLINUX}.whl",
        name=name,
        version="1.0",
        tags=(MANYLINUX,),
        generator="maturin (1.7.0)",
        files={
            f"{name}/__init__.py": SOURCE,
            f"{name}/_rust.abi3.so": ElfBuilder(
                needed=("libc.so.6",), rodata=BANNER + CARGO
            ).build(),
        },
    )


def _pure(directory: Path, name: str) -> None:
    build_wheel(
        directory / f"{name}-1.0-py3-none-any.whl",
        name=name,
        version="1.0",
        files={f"{name}/data.py": b"ROWS = [1, 2, 3]\n"},
    )


MAKERS = (_system, _bundled, _rust, _pure)


def main() -> int:
    out = Path(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    out.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        MAKERS[index % len(MAKERS)](out, f"corpus{index:03d}")
    print(f"built {count} wheels in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
