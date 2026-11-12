"""Embedded metadata forensics (EXIF, XMP, IPTC).

Camera metadata is the single richest source of truth in an image
investigation: it carries the capture time, the device, the GPS position and
often the editing history. This module extracts it and, more importantly,
checks it for *internal contradictions* - a set of dates that disagree, an
editing tool named in the software field, a camera serial that does not match
the recorded custody, and so on.
"""

import re
from datetime import datetime

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

# Editing applications that leave a trace in the software / creator fields.
EDITING_SOFTWARE = [
    "photoshop", "adobe photoshop", "lightroom", "gimp", "pixelmator",
    "affinity photo", "canva", "snapseed", "faceapp", "remove.bg",
    "picsart", "paintshop", "inkscape", "krita", "luminar", "topaz",
    "illustrator", "paint.net", "corel", "fody",
]

# Tools that are commonly used for synthetic / deepfake media.
SYNTHETIC_MARKERS = [
    "stable diffusion", "midjourney", "dall-e", "firefly", "imagen",
    "flux", "comfyui", "automatic1111", "invokeai", "novelai",
    "leonardo.ai", "dreamstudio", "gemini", "chatgpt", "sora",
    "runway", "heygen", "faceapp", "roop", "deepfake",
]

# Smartphones that normally record EXIF including GPS.
SMARTPHONE_MAKERS = {"apple", "samsung", "xiaomi", "oneplus", "oppo", "vivo",
                      "realme", "huawei", "motorola", "nokia", "google"}

STUDIO_CAMERA_MAKERS = {"canon", "nikon", "sony", "fujifilm", "panasonic",
                         "olympus", "pentax", "leica", "hasselblad"}


def _to_text(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        for encoding in ("utf-8", "latin-1"):
            try:
                return value.decode(encoding).strip().strip("\x00")
            except UnicodeDecodeError:
                continue
        return None
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value if item is not None)
    return str(value).strip()


def _parse_exif_datetime(value):
    """Parse an EXIF date string ('YYYY:MM:DD HH:MM:SS')."""
    if not value:
        return None
    text = str(value).strip().replace("\x00", "")
    for pattern in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y:%m:%d %H:%M",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, pattern)
        except ValueError:
            continue
    return None


def _extract_gps(exif):
    """Pull the GPS block out of an EXIF structure."""
    gps = {}
    try:
        gps_ifd = exif.get_ifd(0x8825) if hasattr(exif, "get_ifd") else {}
    except Exception:
        gps_ifd = {}

    if not gps_ifd:
        return gps

    for tag_id, value in gps_ifd.items():
        tag_name = GPSTAGS.get(tag_id, tag_id)
        gps[tag_name] = value

    latitude = _gps_coordinate(gps.get("GPSLatitudeRef"), gps.get("GPSLatitude"))
    longitude = _gps_coordinate(gps.get("GPSLongitudeRef"), gps.get("GPSLongitude"))

    if latitude is not None and longitude is not None:
        gps["latitude"] = latitude
        gps["longitude"] = longitude
        gps["map_url"] = (
            f"https://www.openstreetmap.org/?mlat={latitude}&mlon={longitude}"
            "#map=16/{latitude}/{longitude}"
        )

    altitude = gps.get("GPSAltitude")
    if altitude is not None:
        try:
            gps["altitude_metres"] = round(float(altitude), 2)
        except (TypeError, ValueError):
            pass

    return gps


def _gps_coordinate(reference, values):
    if not values:
        return None
    try:
        degrees = float(values[0])
        minutes = float(values[1])
        seconds = float(values[2])
    except (TypeError, ValueError, IndexError):
        return None

    coordinate = degrees + minutes / 60 + seconds / 3600
    if reference and str(reference).upper() in ("S", "W"):
        coordinate = -coordinate
    return round(coordinate, 6)


def _extract_xmp(raw_bytes):
    """Extract a plain-text XMP packet if the file contains one."""
    try:
        text = raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return {}

    start = text.find("<x:xmpmeta")
    if start == -1:
        return {}

    end = text.find("</x:xmpmeta>", start)
    if end == -1:
        return {}

    packet = text[start:end]

    xmp = {}
    for key in ("xmp:CreatorTool", "photoshop:Credit", "xmp:CreateDate",
                "xmp:ModifyDate", "photoshop:DateCreated",
                "photoshop:HistorySoftwareAgent", "dc:creator",
                "dc:rights", "dc:title", "xmpMM:DocumentID",
                "photoshop:ColorMode", "tiff:Make", "tiff:Model"):
        match = re.search(
            r"<{0}[^>]*>(.*?)</{0}>".format(re.escape(key)), packet, re.DOTALL
        )
        if match:
            xmp[key] = match.group(1).strip()

    # Lightroom / Photoshop history actions reveal the editing pipeline.
    history = re.findall(
        r'stAction="([^"]+)"[^>]*?stActionType="([^"]+)"', packet
    )
    if history:
        xmp["history_actions"] = [
            f"{action_type}: {action}" for action, action_type in history[:25]
        ]

    return xmp


def _extract_iptc(image):
    """Extract basic IPTC caption fields when present."""
    captions = {}
    try:
        iptc = image.info.get("iptc")
    except Exception:
        return captions

    if not iptc:
        return captions

    # iptc can be a dict or a PngInfo object depending on the source.
    try:
        items = iptc.items()
    except AttributeError:
        return captions

    for key, value in items:
        try:
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="ignore")
            captions[str(key)] = str(value).strip()
        except Exception:
            continue

    return captions


def extract_metadata(file_path):
    """Extract and sanity-check all embedded metadata.

    Returns a structure with the raw metadata, the normalised fields and a
    list of anomalies that the investigator should look at.
    """
    result = {
        "available": False,
        "format": None,
        "camera": {},
        "timestamps": {},
        "gps": {},
        "software": [],
        "xmp": {},
        "iptc": {},
        "image_properties": {},
        "raw_tags": {},
        "anomalies": [],
    }

    try:
        with Image.open(file_path) as image:
            image.load()
            result["format"] = image.format
            result["image_properties"] = {
                "width": image.width,
                "height": image.height,
                "mode": image.mode,
                "format": image.format,
                "has_animation": getattr(image, "is_animated", False),
                "n_frames": getattr(image, "n_frames", 1),
            }

            exif = image.getexif()
            if exif:
                result["available"] = True
                raw = {}
                for tag_id, value in exif.items():
                    raw[TAGS.get(tag_id, tag_id)] = _to_text(value)
                result["raw_tags"] = raw

                result["camera"] = {
                    "make": raw.get("Make"),
                    "model": raw.get("Model"),
                    "lens": raw.get("LensModel") or raw.get("Lens"),
                    "software": raw.get("Software"),
                    "body_serial": raw.get("SerialNumber"),
                    "owner_name": raw.get("Artist") or raw.get("OwnerName"),
                    "copyright": raw.get("Copyright"),
                    "description": raw.get("ImageDescription"),
                    "orientation": raw.get("Orientation"),
                }

                result["timestamps"] = {
                    "datetime_original": raw.get("DateTimeOriginal"),
                    "datetime_digitized": raw.get("DateTimeDigitized"),
                    "datetime": raw.get("DateTime"),
                    "offset_time": raw.get("OffsetTime"),
                    "offset_time_original": raw.get("OffsetTimeOriginal"),
                }

                result["gps"] = _extract_gps(exif)
                result["iptc"] = _extract_iptc(image)

            # PNG / WebP textual metadata.
            for key in ("description", "comment", "author", "title",
                        "creation_time", "software", "parameters"):
                if key in image.info:
                    result["xmp"].setdefault("png_text", {})[key] = _to_text(
                        image.info[key]
                    )

    except Exception as error:  # pragma: no cover - defensive
        result["error"] = f"Metadata could not be read: {error}"
        return result

    # XMP packets live in the raw bytes, not in the EXIF structure.
    try:
        with open(file_path, "rb") as handle:
            raw_bytes = handle.read(4 * 1024 * 1024)
        xmp = _extract_xmp(raw_bytes)
        if xmp:
            result["available"] = True
            result["xmp"].update(xmp)
    except OSError:
        pass

    result["software"] = _collect_software(result)
    result["anomalies"] = detect_anomalies(result)
    return result


def _collect_software(result):
    """Gather every software/agent name mentioned anywhere in the metadata."""
    names = []

    camera_software = result["camera"].get("software")
    if camera_software:
        names.append(camera_software)

    xmp_creator = result["xmp"].get("xmp:CreatorTool")
    if xmp_creator:
        names.append(xmp_creator)

    for action in result["xmp"].get("history_actions", []):
        # e.g. "savedAs: Adobe Photoshop"
        if ":" in action:
            candidate = action.split(":", 1)[1].strip()
            if candidate:
                names.append(candidate)

    unique = []
    for name in names:
        cleaned = str(name).strip()
        if cleaned and cleaned not in unique:
            unique.append(cleaned)

    return unique


def detect_anomalies(result):
    """Find contradictions and suspicious signals inside the metadata."""
    anomalies = []

    def add(severity, code, title, explanation):
        anomalies.append({
            "severity": severity,
            "code": code,
            "title": title,
            "explanation": explanation,
        })

    camera = result["camera"]
    timestamps = result["timestamps"]

    if not result.get("available"):
        add(
            "MEDIUM", "NO_METADATA",
            "No embedded metadata found",
            "The file carries no EXIF, XMP or IPTC metadata. Modern camera and "
            "phone images normally contain extensive metadata, so its absence "
            "suggests the file was re-encoded, exported from a messaging app, "
            "or deliberately stripped before circulation.",
        )
        return anomalies

    # 1. Editing software named in the file.
    for software in result.get("software", []):
        lowered = software.lower()
        if any(marker in lowered for marker in EDITING_SOFTWARE):
            add(
                "HIGH", "EDITING_SOFTWARE",
                f"Editing software recorded: {software}",
                "The file names an image editing application. The image has been "
                "opened and saved by an editing tool after capture. This does "
                "not prove manipulation, but the original and the edited "
                "version should both be obtained and compared.",
            )
            break

    for software in result.get("software", []):
        lowered = software.lower()
        if any(marker in lowered for marker in SYNTHETIC_MARKERS):
            add(
                "HIGH", "SYNTHETIC_MARKER",
                f"Synthetic-media tool recorded: {software}",
                "The metadata names a generative or deepfake tool. Treat the "
                "content as synthetic until independently verified.",
            )
            break

    # 2. Timestamp contradictions.
    original = _parse_exif_datetime(timestamps.get("datetime_original"))
    modified = _parse_exif_datetime(timestamps.get("datetime_digitized"))
    generic = _parse_exif_datetime(timestamps.get("datetime"))

    if original and generic and generic < original:
        add(
            "HIGH", "TIMESTAMP_REGRESSION",
            "File modified before it was captured",
            f"DateTimeOriginal ({timestamps.get('datetime_original')}) is later "
            f"than DateTime ({timestamps.get('datetime')}). A file cannot be "
            "modified before it exists; this indicates a rewritten or fabricated "
            "timestamp field.",
        )

    if original and modified and modified < original:
        add(
            "MEDIUM", "DIGITIZE_BEFORE_CAPTURE",
            "Digitisation timestamp precedes capture timestamp",
            f"DateTimeDigitized ({timestamps.get('datetime_digitized')}) is "
            f"earlier than DateTimeOriginal ({timestamps.get('datetime_original')}). "
            "This usually means the file was assembled from other material.",
        )

    if original and original.year > datetime.now().year + 1:
        add(
            "HIGH", "FUTURE_TIMESTAMP",
            "Capture timestamp is in the future",
            f"The recorded capture time ({timestamps.get('datetime_original')}) "
            "is in the future, which indicates a clock error or a fabricated "
            "timestamp.",
        )

    if original and original.year < 1990:
        add(
            "HIGH", "IMPLAUSIBLE_TIMESTAMP",
            "Implausibly old capture timestamp",
            f"The recorded capture time ({timestamps.get('datetime_original')}) "
            "predates modern digital cameras. The timestamp has probably been "
            "altered.",
        )

    # 3. Missing capture time on an otherwise complete EXIF block.
    if not timestamps.get("datetime_original") and timestamps.get("datetime"):
        add(
            "LOW", "NO_ORIGINAL_TIMESTAMP",
            "Original capture time is missing",
            "The file records a modification time but no DateTimeOriginal, so "
            "the moment of capture cannot be established from metadata.",
        )

    # 4. Geometry mismatch: EXIF dimensions vs decoded dimensions.
    width = result["image_properties"].get("width")
    height = result["image_properties"].get("height")
    exif_width = result["raw_tags"].get("ExifImageWidth")
    exif_height = result["raw_tags"].get("ExifImageLength")

    if width and height and exif_width and exif_height:
        try:
            if abs(int(exif_width) - width) > 2 or abs(int(exif_height) - height) > 2:
                add(
                    "MEDIUM", "DIMENSION_MISMATCH",
                    "Image was resized after capture",
                    f"The EXIF block records {exif_width}x{exif_height} but the "
                    f"stored image is {width}x{height}. The pixels were "
                    "resampled, which affects both authenticity and any "
                    "distance/geometry analysis.",
                )
        except (TypeError, ValueError):
            pass

    # 5. Missing serial number on a professional camera.
    make = (camera.get("make") or "").lower()
    if make in STUDIO_CAMERA_MAKERS and not camera.get("body_serial"):
        add(
            "LOW", "MISSING_BODY_SERIAL",
            "Camera body serial number not recorded",
            f"A {camera.get('make')} camera is recorded but no body serial "
            "number is present, so the device cannot be tied to a specific "
            "camera body or a known stolen-camera list.",
        )

    # 6. GPS without capture time, or GPS present at all.
    if result["gps"].get("latitude") is not None:
        add(
            "INFO", "GPS_PRESENT",
            "Geographic position recorded",
            "The file contains GPS coordinates. These can be correlated with "
            "cell-site and camera-registration records to test the stated "
            "location of capture.",
        )

    # 7. Orientation tag inconsistent with actual geometry (rare, but a
    #    common artefact of manual metadata editing).
    orientation = camera.get("orientation")
    if orientation is not None and width and height:
        try:
            orientation_value = int(orientation)
        except (TypeError, ValueError):
            orientation_value = None

        if orientation_value in (5, 6, 7, 8) and width > height:
            add(
                "MEDIUM", "ORIENTATION_CONFLICT",
                "Orientation tag conflicts with image geometry",
                "The orientation tag says the image is stored rotated, but the "
                "pixel geometry says otherwise. This is often seen when "
                "metadata is edited by hand.",
            )

    # 8. Owner / creator fields that contradict each other.
    if camera.get("owner_name") and camera.get("copyright"):
        owner = camera["owner_name"].lower()
        copyright_text = camera["copyright"].lower()
        if len(owner) > 3 and owner not in copyright_text and \
                len(copyright_text) > 3 and copyright_text not in owner:
            add(
                "LOW", "CREATOR_CONFLICT",
                "Author and copyright fields disagree",
                f"The artist field says '{camera['owner_name']}' while the "
                f"copyright field says '{camera['copyright']}'. One of the two "
                "was edited.",
            )

    return anomalies
