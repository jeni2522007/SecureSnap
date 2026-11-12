"""Central configuration for SecureSnap.

Every path is resolved relative to the project root so the application can be
started from any working directory.
"""

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SECURESNAP_DATA_DIR", BASE_DIR / "data"))


def _load_secret_key():
    """Return the session signing key.

    The key is taken from the environment when one is set. Otherwise a random
    key is generated once and stored on disk, so that restarting the
    application does not invalidate any open session.
    """
    from_environment = os.environ.get("SECURESNAP_SECRET_KEY")
    if from_environment:
        return from_environment

    key_file = DATA_DIR / "secret.key"
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if key_file.exists():
            return key_file.read_text(encoding="utf-8").strip()
        key = secrets.token_hex(32)
        key_file.write_text(key, encoding="utf-8")
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        return key
    except OSError:
        # A read-only installation still gets a working, if ephemeral, key.
        return secrets.token_hex(32)


class Config:
    """Runtime configuration for the SecureSnap forensic workbench."""

    SECRET_KEY = _load_secret_key()

    # Debug mode exposes the Werkzeug console, which allows arbitrary code
    # execution. It is off unless it is explicitly asked for.
    DEBUG = os.environ.get("SECURESNAP_DEBUG", "").lower() in ("1", "true", "yes")

    # The host the application is expected to be reached on. Requests with a
    # different Host or Origin header are refused.
    ALLOWED_HOSTS = [
        host.strip()
        for host in os.environ.get(
            "SECURESNAP_ALLOWED_HOSTS", "127.0.0.1,localhost"
        ).split(",")
        if host.strip()
    ]

    DATA_DIR = DATA_DIR
    DATABASE_PATH = DATA_DIR / "securesnap.db"

    # Original evidence is never modified. We store a sealed (encrypted) copy
    # plus derived analysis artefacts.
    EVIDENCE_FOLDER = DATA_DIR / "evidence"
    SEALED_FOLDER = DATA_DIR / "sealed"
    ANALYSIS_FOLDER = DATA_DIR / "analysis"

    # Evidence key material (Fernet). Generated on first run.
    KEY_FILE = DATA_DIR / "evidence.key"

    MAX_CONTENT_LENGTH = 25 * 1024 * 1024  # 25 MB

    # The largest image the pipeline will decode. A file that claims to be a
    # far larger image is rejected before it can exhaust memory.
    MAX_PIXEL_COUNT = 50_000_000

    # Extensions we *accept* from the operator. The real format is always
    # detected from magic bytes, this list only controls the upload dialog.
    ALLOWED_EXTENSIONS = {
        "jpg", "jpeg", "png", "webp", "gif", "bmp",
        "tif", "tiff", "heic", "avif", "mp4", "mov",
        "mkv", "avi", "mp3", "wav", "pdf",
    }

    # Formats that are considered "still image" for the analysis pipeline.
    IMAGE_EXTENSIONS = {
        "jpg", "jpeg", "png", "webp", "bmp", "tif", "tiff", "gif",
    }

    ENGINE_VERSION = "2.0.0"

    @classmethod
    def ensure_directories(cls):
        for folder in (
            cls.DATA_DIR,
            cls.EVIDENCE_FOLDER,
            cls.SEALED_FOLDER,
            cls.ANALYSIS_FOLDER,
        ):
            Path(folder).mkdir(parents=True, exist_ok=True)
