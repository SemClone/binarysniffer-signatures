"""
Signature manifest: per-file integrity metadata for the packaged and downloaded
signature sets.

The manifest lists every signature file with its SHA-256 and size. It is the
authoritative index for updates: the updater downloads the files named here and
verifies each against its recorded hash, so corruption or tampering in transit
is rejected before import. Signing the manifest itself (so its hashes are also
authenticated) is the follow-on step; a signed manifest secures the whole set
through one signature because it carries every file's hash.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

MANIFEST_NAME = "manifest.json"
_CHUNK = 64 * 1024


def file_sha256(path: Path) -> str:
    """SHA-256 hex digest of a file, read in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_files_index(data_dir: Path) -> dict[str, dict[str, Any]]:
    """Map each signature JSON (excluding the manifest) to its sha256 and size."""
    index: dict[str, dict[str, Any]] = {}
    for path in sorted(data_dir.glob("*.json")):
        if path.name == MANIFEST_NAME:
            continue
        index[path.name] = {"sha256": file_sha256(path), "size": path.stat().st_size}
    return index


def build_manifest(data_dir: Path, base: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a manifest dict, preserving non-file fields from ``base``."""
    manifest = dict(base or {})
    manifest.pop("files", None)
    files = build_files_index(data_dir)
    manifest["files"] = files
    manifest["total_signature_files"] = len(files)
    return manifest


def write_manifest(data_dir: Path) -> dict[str, Any]:
    """Regenerate <data_dir>/manifest.json with fresh per-file hashes."""
    path = data_dir / MANIFEST_NAME
    base: dict[str, Any] = {}
    if path.exists():
        with open(path, encoding="utf-8") as f:
            base = json.load(f)
    manifest = build_manifest(data_dir, base)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    return manifest


def verify_directory(data_dir: Path, manifest: dict[str, Any]) -> list[str]:
    """Verify files in a directory against a manifest's file hashes.

    Returns a list of human-readable problems (empty if everything matches).
    Extra files not in the manifest are reported but are not fatal on their own.
    """
    problems: list[str] = []
    files = manifest.get("files") or {}
    if not files:
        return ["manifest has no file hashes"]
    for name, meta in files.items():
        path = data_dir / name
        if not path.exists():
            problems.append(f"missing file: {name}")
            continue
        actual = file_sha256(path)
        expected = meta.get("sha256")
        if actual != expected:
            problems.append(f"hash mismatch: {name}")
    return problems
