"""Tests for the PyPI launcher against GoReleaser snapshot archives.

Run: WARDMAP_DIST=dist python -B -m unittest discover -s packaging/pypi/tests
Writes its own _release.py into a temporary copy of the package.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DIST = Path(os.environ.get("WARDMAP_DIST", Path(__file__).resolve().parents[3] / "dist"))
SRC = Path(__file__).resolve().parents[1] / "src" / "wardmap"

PLAT = {"darwin": "darwin", "linux": "linux", "win32": "windows"}[sys.platform]
CPU = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}[platform.machine().lower()]
EXT = "zip" if PLAT == "windows" else "tar.gz"
HOST = next(DIST.glob(f"wardmap_*_{PLAT}_{CPU}.{EXT}"))
VERSION = HOST.name[len("wardmap_"):-len(f"_{PLAT}_{CPU}.{EXT}")]
ARCHIVE = HOST.read_bytes()
GOOD = hashlib.sha256(ARCHIVE).hexdigest()


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def load(pin: str, served: dict):
    """Return a fresh launcher module pinned to `pin`, downloading served['b']."""
    root = Path(tempfile.mkdtemp(prefix="wardmap-py-"))
    shutil.copytree(SRC, root / "wardmap")
    (root / "wardmap" / "_release.py").write_text(f"VERSION = {VERSION!r}\nCHECKSUMS = {{{HOST.name!r}: {pin!r}}}\n")
    os.environ["WARDMAP_PY_CACHE"] = tempfile.mkdtemp(prefix="wardmap-cache-")
    for name in [m for m in sys.modules if m == "wardmap" or m.startswith("wardmap.")]:
        del sys.modules[name]
    sys.path.insert(0, str(root))
    try:
        mod = importlib.import_module("wardmap.__main__")
    finally:
        sys.path.remove(str(root))
    mod.urllib.request.urlopen = lambda url, timeout=0: _Resp(served["b"])
    return mod


class LauncherTest(unittest.TestCase):
    def test_extract(self):
        mod = load(GOOD, {"b": ARCHIVE})
        tgz = next(DIST.glob("wardmap_*_linux_arm64.tar.gz")).read_bytes()
        self.assertEqual(mod.extract(tgz, "wardmap", "tar.gz")[:4], b"\x7fELF")
        zip_ = next(DIST.glob("wardmap_*_windows_amd64.zip")).read_bytes()
        self.assertEqual(mod.extract(zip_, "wardmap.exe", "zip")[:2], b"MZ")
        with self.assertRaises(RuntimeError):
            mod.target("freebsd", "x86_64")

    def test_genuine_download_runs(self):
        mod = load(GOOD, {"b": ARCHIVE})
        out = subprocess.check_output([str(mod.ensure_binary()), "version"]).decode()
        self.assertIn(VERSION.split("-")[0], out)

    def test_tampered_download_refused(self):
        mod = load(GOOD, {"b": ARCHIVE + b"x"})
        with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
            mod.ensure_binary()

    def test_wrong_pin_refused(self):
        with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
            load("0" * 64, {"b": ARCHIVE}).ensure_binary()
        with self.assertRaisesRegex(RuntimeError, "no checksum recorded"):
            load("short", {"b": ARCHIVE}).ensure_binary()

    def test_tampered_cache_refetched(self):
        served = {"b": ARCHIVE}
        mod = load(GOOD, served)
        binary = mod.ensure_binary()
        with open(binary, "ab") as f:
            f.write(b"tamper")
        calls = []
        mod.urllib.request.urlopen = lambda url, timeout=0: calls.append(url) or _Resp(ARCHIVE)
        mod.ensure_binary()
        self.assertEqual(len(calls), 1, "a cached binary whose hash changed must be replaced")


if __name__ == "__main__":
    unittest.main()
