"""
Signature bundles: a single signed artifact for distributing the signature set.

A bundle is a deterministic zip of the signature JSONs plus their manifest. It
is signed with an Ed25519 detached signature so the client can verify it fully
offline with only the trusted public key baked into the package - no network
call to a transparency log, and a tiny dependency footprint.

Trust chain on update:
  1. verify the Ed25519 signature over the zip bytes against a trusted key,
  2. unzip (member names are validated to be plain in-directory JSON files),
  3. verify every file against the in-zip manifest's SHA-256.

Signing/verification needs the optional ``cryptography`` dependency (the
``update`` extra); building/extracting a bundle does not.
"""

from __future__ import annotations

import base64
import json
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

from .manifest import MANIFEST_NAME, validate_relative_name, verify_directory, write_manifest

# Fixed timestamp for deterministic archives (zip epoch minimum).
_ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)


def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - exercised via the CLI hint
        raise RuntimeError(
            "Signing/verification requires the 'cryptography' package. "
            "Install it with: pip install 'binarysniffer[update]'"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey


def build_bundle(data_dir: Path, out_zip: Path) -> Path:
    """Build a deterministic zip of the signature set (regenerating the manifest).

    Every ``*.json`` under ``data_dir`` is included, subdirectories and all, so the
    bundle carries the same set the manifest covers. Member names are POSIX paths
    relative to ``data_dir``; entries are sorted and given a fixed timestamp so the
    archive bytes are reproducible for a given input.
    """
    write_manifest(data_dir)
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    members = sorted(data_dir.rglob("*.json"))
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in members:
            name = path.relative_to(data_dir).as_posix()
            info = zipfile.ZipInfo(name, date_time=_ZIP_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, path.read_bytes())
    return out_zip


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair, returned as (private_b64, public_b64)."""
    from cryptography.hazmat.primitives import serialization

    priv_cls, _ = _ed25519()
    key = priv_cls.generate()
    priv_raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(priv_raw).decode(), base64.b64encode(pub_raw).decode()


def sign_bytes(data: bytes, private_key_b64: str) -> str:
    """Return a base64 Ed25519 signature over ``data``."""
    priv_cls, _ = _ed25519()
    key = priv_cls.from_private_bytes(base64.b64decode(private_key_b64))
    return base64.b64encode(key.sign(data)).decode()


def verify_bytes(data: bytes, signature_b64: str, public_keys_b64: list[str]) -> bool:
    """True if ``signature_b64`` verifies over ``data`` for any trusted key."""
    from cryptography.exceptions import InvalidSignature

    _, pub_cls = _ed25519()
    signature = base64.b64decode(signature_b64)
    for public_key_b64 in public_keys_b64:
        key = pub_cls.from_public_bytes(base64.b64decode(public_key_b64))
        try:
            key.verify(signature, data)
            return True
        except InvalidSignature:
            continue
    return False


def sign_bundle(zip_path: Path, private_key_b64: str, sig_path: Path | None = None) -> Path:
    """Write a detached ``.sig`` (base64 signature) next to the bundle."""
    sig_path = sig_path or zip_path.with_suffix(zip_path.suffix + ".sig")
    signature = sign_bytes(zip_path.read_bytes(), private_key_b64)
    sig_path.write_text(signature + "\n", encoding="utf-8")
    return sig_path


def verify_bundle_signature(zip_path: Path, sig_path: Path, public_keys_b64: list[str]) -> bool:
    """Verify a bundle's detached signature against the trusted keys."""
    signature_b64 = sig_path.read_text(encoding="utf-8").strip()
    return verify_bytes(zip_path.read_bytes(), signature_b64, public_keys_b64)


def _check_member_name(name: str) -> None:
    """Bundle-member wrapper around the shared manifest-name guard."""
    try:
        validate_relative_name(name)
    except ValueError as exc:
        raise ValueError(f"unsafe bundle member: {name}") from exc


def extract_and_verify(zip_path: Path, dest_dir: Path) -> list[str]:
    """Extract a bundle into ``dest_dir`` and verify files against its manifest.

    Member names are validated to be plain in-directory JSON filenames before
    extraction, so a malicious archive cannot escape the destination. Returns
    the list of integrity problems (empty if the bundle is internally consistent).
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        for name in names:
            _check_member_name(name)
        if MANIFEST_NAME not in names:
            raise ValueError("bundle has no manifest")
        zf.extractall(dest_dir)

    with open(dest_dir / MANIFEST_NAME, encoding="utf-8") as f:
        manifest = json.load(f)
    return verify_directory(dest_dir, manifest)
