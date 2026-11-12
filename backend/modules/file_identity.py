"""True file-format identification and structural anomaly detection.

Uploading a file is not the same as accepting its claim. This module looks at
the raw bytes to determine what the file *actually* is, and reports mismatches
between the claimed extension and the real container. That check is what stops
a `.jpg` that is really a PDF (or an executable) from entering the register.
"""

import math
import os
from collections import Counter

# (magic bytes, offset, label, extension, category)
SIGNATURES = [
    (b"\xff\xd8\xff", 0, "JPEG image", "jpg", "image"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image", "png", "image"),
    (b"GIF87a", 0, "GIF image", "gif", "image"),
    (b"GIF89a", 0, "GIF image", "gif", "image"),
    (b"BM", 0, "BMP image", "bmp", "image"),
    (b"II*\x00", 0, "TIFF image", "tif", "image"),
    (b"MM\x00*", 0, "TIFF image", "tif", "image"),
    (b"%PDF-", 0, "PDF document", "pdf", "document"),
    (b"PK\x03\x04", 0, "ZIP archive", "zip", "archive"),
    (b"Rar!\x1a\x07", 0, "RAR archive", "rar", "archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive", "7z", "archive"),
    (b"\x1f\x8b", 0, "GZIP archive", "gz", "archive"),
    (b"MZ", 0, "Windows executable", "exe", "executable"),
    (b"\x7fELF", 0, "ELF executable", "elf", "executable"),
    (b"\xca\xfe\xba\xbe", 0, "Java class / Mach-O fat binary", "class", "executable"),
    (b"OggS", 0, "Ogg container", "ogg", "media"),
    (b"ID3", 0, "MP3 audio", "mp3", "media"),
    (b"\x1aE\xdf\xa3", 0, "Matroska / WebM container", "mkv", "media"),
    (b"RIFF", 0, "RIFF container", "riff", "container"),
    (b"FLV\x01", 0, "Flash video", "flv", "media"),
]

# Extensions that are dangerous to accept as "evidence media".
EXECUTABLE_CATEGORIES = {"executable"}


def read_head(file_path, size=4096):
    """Read the first bytes of a file."""
    with open(file_path, "rb") as handle:
        return handle.read(size)


def detect_format(file_path):
    """Identify the real format of a file from its magic bytes.

    Returns a dictionary describing the detected format, the confidence basis
    and any container that was found embedded inside the file.
    """
    head = read_head(file_path, 4096)

    detected = {
        "format": "Unknown",
        "extension": None,
        "category": "unknown",
        "basis": "no known signature",
        "mime": "application/octet-stream",
    }

    for magic, offset, label, extension, category in SIGNATURES:
        if head[offset:offset + len(magic)] != magic:
            continue

        detected.update({
            "format": label,
            "extension": extension,
            "category": category,
            "basis": f"magic bytes at offset {offset}",
        })

        if detected["format"] == "RIFF container":
            riff_type = head[8:12]
            if riff_type == b"WEBP":
                detected.update({
                    "format": "WebP image", "extension": "webp",
                    "category": "image", "mime": "image/webp",
                })
            elif riff_type == b"WAVE":
                detected.update({
                    "format": "WAV audio", "extension": "wav",
                    "category": "media", "mime": "audio/wav",
                })
            elif riff_type == b"AVI ":
                detected.update({
                    "format": "AVI video", "extension": "avi",
                    "category": "media", "mime": "video/x-msvideo",
                })

        if detected["format"] == "MP3 audio":
            detected["mime"] = "audio/mpeg"

        break

    # ISO base media (MP4 / MOV / HEIC / AVIF) all use the `ftyp` box.
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        brand_map = {
            b"qt  ": ("QuickTime video", "mov", "media", "video/quicktime"),
            b"heic": ("HEIC image", "heic", "image", "image/heic"),
            b"heix": ("HEIC image", "heic", "image", "image/heic"),
            b"mif1": ("HEIF image", "heic", "image", "image/heic"),
            b"avif": ("AVIF image", "avif", "image", "image/avif"),
            b"M4V ": ("M4V video", "m4v", "media", "video/x-m4v"),
            b"isom": ("MP4 container", "mp4", "media", "video/mp4"),
            b"mp42": ("MP4 container", "mp4", "media", "video/mp4"),
            b"dash": ("MPEG-DASH stream", "mp4", "media", "video/mp4"),
        }
        if brand in brand_map:
            label, extension, category, mime = brand_map[brand]
            detected.update({
                "format": label, "extension": extension,
                "category": category, "mime": mime,
                "basis": f"ISO base media brand {brand.decode(errors='replace')}",
            })
        else:
            detected.update({
                "format": "ISO base media file",
                "extension": "mp4", "category": "media",
                "mime": "video/mp4",
                "basis": "ISO base media ftyp box",
            })

    detected["mime"] = detected.get("mime", MIME_BY_EXTENSION.get(
        detected.get("extension"), "application/octet-stream"
    ))

    detected["embedded_payloads"] = scan_embedded(file_path)
    return detected


MIME_BY_EXTENSION = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "gif": "image/gif", "bmp": "image/bmp", "tif": "image/tiff",
    "tiff": "image/tiff", "webp": "image/webp", "heic": "image/heic",
    "avif": "image/avif", "pdf": "application/pdf", "mp4": "video/mp4",
    "mov": "video/quicktime", "mkv": "video/x-matroska", "avi": "video/x-msvideo",
    "mp3": "audio/mpeg", "wav": "audio/wav",
}


def scan_embedded(file_path):
    """Search the file body for appended or embedded secondary files.

    A polyglot (a valid JPEG that also contains a ZIP or a PDF) is a common
    way to smuggle content past naive upload filters, so it is worth flagging.

    Only strong signatures are used, and the search starts after the header
    region, because the compressed body of an image can easily contain a
    byte sequence that looks like a weak magic number by chance.
    """
    findings = []
    file_size = os.path.getsize(file_path)

    markers = [
        (b"PK\x03\x04", "ZIP archive"),
        (b"%PDF-", "PDF document"),
        (b"\x7fELF", "ELF executable"),
        (b"MZ\x90\x00", "Windows executable"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
    ]

    # Start the search past the header so a file that legitimately begins
    # with the same signature is not reported against itself.
    start = min(max(64, file_size // 100), file_size)

    with open(file_path, "rb") as handle:
        handle.seek(start)
        window = handle.read()

    for marker, label in markers:
        offset = window.find(marker)
        if offset == -1:
            continue
        findings.append({
            "type": label,
            "offset": start + offset,
            "description": f"Embedded {label} detected at byte offset {start + offset}",
        })

    return findings


def shannon_entropy(data):
    """Return the Shannon entropy (0-8 bits per byte) of a byte sequence."""
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def analyse_entropy(file_path):
    """Estimate the entropy profile of the file.

    High whole-file entropy with an image header is a sign of compressed or
    encrypted content, which matters when triaging suspicious uploads.
    """
    file_size = os.path.getsize(file_path)

    with open(file_path, "rb") as handle:
        head = handle.read(65536)
        handle.seek(max(0, file_size - 65536))
        tail = handle.read(65536)

    overall = shannon_entropy(open(file_path, "rb").read())
    head_entropy = shannon_entropy(head)
    tail_entropy = shannon_entropy(tail)

    return {
        "overall_bits_per_byte": overall,
        "head_bits_per_byte": head_entropy,
        "tail_bits_per_byte": tail_entropy,
        "head_tail_difference": round(abs(head_entropy - tail_entropy), 4),
        "interpretation": _entropy_interpretation(overall, head_entropy, tail_entropy),
    }


def _entropy_interpretation(overall, head, tail):
    if overall > 7.9 and abs(head - tail) < 0.3:
        return (
            "Very high, uniform entropy across the whole file - consistent with "
            "encrypted or strongly compressed data."
        )
    if abs(head - tail) > 1.5:
        return (
            "Entropy differs strongly between the start and end of the file - "
            "the tail may contain an appended payload."
        )
    if overall < 4.0:
        return "Low entropy - the file contains large repetitive regions."
    return "Entropy profile is consistent with a normal encoded media file."


def compare_claim(file_path, original_filename):
    """Compare the claimed file identity against the real one.

    Returns a dictionary of discrepancies plus an overall verdict of how
    serious the mismatch is for evidence handling.
    """
    detected = detect_format(file_path)
    claimed_extension = os.path.splitext(original_filename or "")[1].lower().lstrip(".")

    mismatches = []
    severity = "NONE"

    if claimed_extension and detected["extension"] and \
            claimed_extension != detected["extension"]:
        mismatches.append({
            "field": "extension",
            "claimed": claimed_extension,
            "actual": detected["extension"],
            "severity": "HIGH",
            "explanation": (
                f"The file is named '.{claimed_extension}' but the bytes are a "
                f"{detected['format']}. The extension is not trustworthy."
            ),
        })
        severity = "HIGH"

    if detected["category"] in EXECUTABLE_CATEGORIES:
        mismatches.append({
            "field": "content_type",
            "claimed": claimed_extension or "unknown",
            "actual": detected["format"],
            "severity": "CRITICAL",
            "explanation": (
                "The content is an executable program. Executables must never be "
                "opened on an analysis workstation."
            ),
        })
        severity = "CRITICAL"

    if detected["embedded_payloads"]:
        mismatches.append({
            "field": "embedded_payloads",
            "claimed": "single file",
            "actual": ", ".join(p["type"] for p in detected["embedded_payloads"]),
            "severity": "HIGH",
            "explanation": (
                "Additional file structures are embedded inside this file. This "
                "is a polyglot pattern used to hide content."
            ),
        })
        if severity in ("NONE",):
            severity = "HIGH"

    return {
        "claimed_extension": claimed_extension or None,
        "detected": detected,
        "mismatches": mismatches,
        "severity": severity,
        "identity_trusted": severity == "NONE",
    }
