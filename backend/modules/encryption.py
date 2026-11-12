"""Evidence sealing.

The original file is never modified. A sealed copy is produced with Fernet
(AES-128-CBC with an HMAC-SHA256 authentication tag) and stored separately.
The sealing operation is what allows the app to state, years later, that the
working copy was not silently edited during the examination.
"""

import os

from cryptography.fernet import Fernet, InvalidToken


def generate_key():
    """Generate a new Fernet key."""
    return Fernet.generate_key()


def seal_file(file_path, output_folder, key):
    """Encrypt a file and write the sealed copy to disk.

    Returns the path of the sealed file.
    """
    os.makedirs(output_folder, exist_ok=True)

    if isinstance(key, str):
        key = key.encode("utf-8")

    cipher = Fernet(key)

    with open(file_path, "rb") as handle:
        data = handle.read()

    sealed = cipher.encrypt(data)

    sealed_path = os.path.join(
        output_folder, os.path.basename(file_path) + ".sealed"
    )

    with open(sealed_path, "wb") as handle:
        handle.write(sealed)

    return sealed_path


def unseal_file(sealed_path, key, output_path):
    """Decrypt a sealed file back to readable form."""
    if isinstance(key, str):
        key = key.encode("utf-8")

    cipher = Fernet(key)

    with open(sealed_path, "rb") as handle:
        sealed = handle.read()

    try:
        data = cipher.decrypt(sealed)
    except InvalidToken as error:
        raise ValueError(
            "The sealed file could not be authenticated. It has been "
            "tampered with, or the wrong key was used."
        ) from error

    with open(output_path, "wb") as handle:
        handle.write(data)

    return output_path


def verify_sealed(sealed_path, key, expected_sha256):
    """Verify a sealed file decrypts and still matches a recorded hash."""
    import hashlib

    if isinstance(key, str):
        key = key.encode("utf-8")

    cipher = Fernet(key)

    with open(sealed_path, "rb") as handle:
        sealed = handle.read()

    try:
        data = cipher.decrypt(sealed)
    except InvalidToken as error:
        raise ValueError(
            "The sealed file could not be authenticated. It has been "
            "tampered with, or the wrong key was used."
        ) from error

    actual = hashlib.sha256(data).hexdigest()

    return {
        "authenticated": True,
        "sha256": actual,
        "matches_original": actual == expected_sha256,
    }
