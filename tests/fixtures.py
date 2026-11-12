"""Shared test fixtures for the SecureSnap test suite."""

import os
import sys
import tempfile
from pathlib import Path

BACKEND_FOLDER = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_FOLDER) not in sys.path:
    sys.path.insert(0, str(BACKEND_FOLDER))

import numpy as np  # noqa: E402
from PIL import Image  # noqa: E402


def make_test_image(path, size=(320, 240), seed=7, with_exif=False):
    """Create a deterministic test image with genuine texture.

    Random texture is used rather than a flat colour so that the compression
    and noise tests have something realistic to work with.
    """
    generator = np.random.default_rng(seed)
    width, height = size

    base = generator.integers(40, 210, size=(height // 8, width // 8, 3), dtype=np.uint8)
    image = Image.fromarray(base, "RGB").resize(size, Image.BICUBIC)

    # Add smooth structure so the picture is not pure noise.
    pixels = np.asarray(image).astype(np.float32)
    yy = np.linspace(0, 1, height)[:, None, None]
    xx = np.linspace(0, 1, width)[None, :, None]
    gradient = (yy * 60 + xx * 40)
    pixels = np.clip(pixels + gradient, 0, 255).astype(np.uint8)

    image = Image.fromarray(pixels, "RGB")

    if with_exif:
        exif = image.getexif()
        exif[271] = "Canon"           # Make
        exif[272] = "Canon EOS 5D"    # Model
        exif[305] = "GIMP 2.10"       # Software
        exif[306] = "2024:01:15 10:30:00"
        exif[36867] = "2024:01:15 10:00:00"   # DateTimeOriginal
        exif[36868] = "2024:01:15 10:30:00"   # DateTimeDigitized
        image.save(path, "JPEG", quality=92, exif=exif)
    else:
        image.save(path, "JPEG", quality=92)

    return path


def make_renamed_file(source, target):
    """Copy a file while giving the copy a misleading extension."""
    import shutil
    shutil.copy2(source, target)
    return target


def make_png(path, size=(200, 200)):
    """Create a small PNG test image."""
    generator = np.random.default_rng(11)
    array = generator.integers(0, 255, size=(size[1], size[0], 3), dtype=np.uint8)
    Image.fromarray(array, "RGB").save(path, "PNG")
    return path


def make_fake_jpeg(path):
    """Create a file that claims to be a JPEG but is not one."""
    with open(path, "wb") as handle:
        handle.write(b"this is definitely not an image, not even close\n" * 4)
    return path


class TempDir:
    """Small helper that behaves like a temporary directory."""

    def __init__(self):
        self.path = tempfile.mkdtemp(prefix="securesnap_test_")

    def file(self, name):
        return os.path.join(self.path, name)

    def cleanup(self):
        import shutil
        shutil.rmtree(self.path, ignore_errors=True)
