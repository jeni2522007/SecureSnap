"""Central configuration for SecureSnap.

Every path is resolved relative to the project root so the application can be
started from any working directory.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SECURESNAP_DATA_DIR", BASE_DIR / "data"))


class Config:
    """Runtime configuration for the SecureSnap forensic workbench."""

    SECRET_KEY = os.environ.get(
        "SECURESNAP_SECRET_KEY",
        "securesnap-local-development-key-change-me",
    )

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
