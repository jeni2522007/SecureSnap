"""Cryptographic fingerprinting for evidence files.

Every evidence item is fingerprinted with two independent algorithms so that a
later integrity re-check can prove the file has not changed since intake.
"""

import hashlib
import hmac
import os
from pathlib import Path

CHUNK_SIZE = 65536


def calculate_sha256(file_path):
    """Return the SHA-256 hex digest of a file."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def calculate_sha512(file_path):
    """Return the SHA-512 hex digest of a file."""
    digest = hashlib.sha512()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint(file_path):
    """Return every fingerprint for a file in a single structure."""
    return {
        "sha256": calculate_sha256(file_path),
        "sha512": calculate_sha512(file_path),
        "size_bytes": os.path.getsize(file_path),
    }


def compare_fingerprints(original, candidate):
    """Compare two fingerprint dictionaries field by field.

    Returns a dictionary describing whether the candidate matches the
    original, and which fields differ.
    """
    differences = {}
    for field in ("sha256", "sha512", "size_bytes"):
        if original.get(field) != candidate.get(field):
            differences[field] = {
                "original": original.get(field),
                "candidate": candidate.get(field),
            }

    return {
        "match": not differences,
        "differences": differences,
        "checked_fields": ["sha256", "sha512", "size_bytes"],
    }


def sign_digest(digest, key):
    """Produce a keyed HMAC over a digest (used for sealed manifests)."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(digest, str):
        digest = digest.encode("utf-8")
    return hmac.new(key, digest, hashlib.sha256).hexdigest()


def key_fingerprint(key):
    """Return a short, non-reversible identifier for a key."""
    return hashlib.sha256(key).hexdigest()[:16] if isinstance(key, bytes) \
        else hashlib.sha256(key.encode()).hexdigest()[:16]


def ensure_key(key_path):
    """Load the evidence sealing key, generating one on first use."""
    key_path = Path(key_path)
    if key_path.exists():
        return key_path.read_bytes().strip()

    from cryptography.fernet import Fernet

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    key_path.write_bytes(key)

    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass  # Windows permissions are handled by the OS profile.

    return key
