"""Fetch, verify, cache and run the Wardmap binary.

The release archive for this platform is downloaded from GitHub and checked
against the SHA-256 in _release.py, which was copied from the release's
Sigstore-verified checksums.txt when this package was built in CI. Only the
wardmap binary is extracted, into a per-user cache, and its hash is checked
again on every run. Standard library only; nothing runs at install time.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from ._release import CHECKSUMS, VERSION

REPO = "Breaktroughf1/wardmap"


def target(system: str | None = None, machine: str | None = None) -> tuple[str, str, str]:
    system = (system or sys.platform).lower()
    machine = (machine or platform.machine()).lower()
    plat = {"darwin": "darwin", "linux": "linux", "win32": "windows"}.get(system)
    cpu = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if plat is None or cpu is None:
        raise RuntimeError(f"unsupported platform {system}/{machine}")
    ext = "zip" if plat == "windows" else "tar.gz"
    exe = "wardmap.exe" if plat == "windows" else "wardmap"
    return f"wardmap_{VERSION}_{plat}_{cpu}.{ext}", exe, ext


def cache_dir() -> Path:
    if os.environ.get("WARDMAP_PY_CACHE"):
        return Path(os.environ["WARDMAP_PY_CACHE"])
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "wardmap" / "pypi"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "wardmap" / "pypi"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "wardmap" / "pypi"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract(archive: bytes, exe: str, ext: str) -> bytes:
    if ext == "zip":
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            return z.read(exe)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as t:
        for member in t.getmembers():
            if member.isreg() and member.name in (exe, f"./{exe}"):
                f = t.extractfile(member)
                if f is not None:
                    return f.read()
    raise RuntimeError(f"{exe} not found in the release archive")


def ensure_binary() -> Path:
    archive_name, exe, ext = target()
    want = CHECKSUMS.get(archive_name, "")
    if len(want) != 64:
        raise RuntimeError(f"no checksum recorded for {archive_name}")
    directory = cache_dir() / VERSION
    binary = directory / exe
    marker = directory / f"{exe}.sha256"
    if binary.is_file() and marker.is_file() and sha256(binary.read_bytes()) == marker.read_text().strip():
        return binary
    url = f"https://github.com/{REPO}/releases/download/v{VERSION}/{archive_name}"
    if not url.startswith("https://"):
        raise RuntimeError("refusing a non-HTTPS download URL")
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 - fixed https URL
        archive = resp.read()
    got = sha256(archive)
    if got != want:
        raise RuntimeError(f"checksum mismatch for {archive_name}: expected {want}, got {got}; refusing to run it")
    data = extract(archive, exe, ext)
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{exe}.")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, 0o755)
    os.replace(tmp, binary)
    marker.write_text(sha256(data) + "\n")
    return binary


def main() -> None:
    try:
        binary = ensure_binary()
    except Exception as err:  # noqa: BLE001 - report any failure as Wardmap's error exit code (2)
        print(f"wardmap (pypi): {err}", file=sys.stderr)
        sys.exit(2)
    args = [str(binary), *sys.argv[1:]]
    if sys.platform == "win32":
        sys.exit(subprocess.call(args))
    os.execv(args[0], args)


if __name__ == "__main__":
    main()
