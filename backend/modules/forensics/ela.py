"""Error Level Analysis (ELA).

ELA is a classic forensic technique. An image is re-compressed at a known
quality level; the difference between the original and the re-compressed
version is largest in regions that have been edited, because edited regions
carry compression artefacts that do not match their surroundings.

ELA is an *indicator*, never proof. It produces a heat map and a set of
measurements that the investigator interprets together with everything else.
"""

import os

import cv2
import numpy as np
from PIL import Image

BLOCK_SIZE = 8
DEFAULT_QUALITY = 75


def _load_rgb(path):
    image = Image.open(path)
    if image.mode != "RGB":
        image = image.convert("RGB")
    return image


def error_map(file_path, quality=DEFAULT_QUALITY):
    """Return the raw per-pixel compression error surface for an image.

    This is the numeric form of the ELA heat map and is useful when a
    particular region needs to be examined on its own.
    """
    original = _load_rgb(file_path)
    buffer = np.asarray(original).astype(np.float32)

    reencoded_buffer = io_bytes(original, quality)
    recompressed = cv2.imdecode(
        np.frombuffer(reencoded_buffer, dtype=np.uint8), cv2.IMREAD_COLOR
    )
    if recompressed is None:
        raise ValueError("Image could not be re-encoded for ELA")

    recompressed = cv2.cvtColor(recompressed, cv2.COLOR_BGR2RGB).astype(np.float32)

    if buffer.shape != recompressed.shape:
        recompressed = cv2.resize(
            recompressed, (buffer.shape[1], buffer.shape[0])
        ).astype(np.float32)

    return np.abs(buffer - recompressed).mean(axis=2)


def compute_ela(file_path, output_folder, quality=DEFAULT_QUALITY):
    """Run Error Level Analysis over an image.

    Returns measurements plus the filename of the generated heat map.
    """
    os.makedirs(output_folder, exist_ok=True)

    original = _load_rgb(file_path)
    buffer = np.asarray(original).astype(np.float32)

    # Re-compress at a fixed quality so we can measure the compression error.
    reencoded_buffer = io_bytes(original, quality)
    recompressed = cv2.imdecode(
        np.frombuffer(reencoded_buffer, dtype=np.uint8),
        cv2.IMREAD_COLOR,
    )
    if recompressed is None:
        raise ValueError("Image could not be re-encoded for ELA")

    recompressed = cv2.cvtColor(recompressed, cv2.COLOR_BGR2RGB).astype(np.float32)

    if buffer.shape != recompressed.shape:
        recompressed = cv2.resize(
            recompressed, (buffer.shape[1], buffer.shape[0])
        ).astype(np.float32)

    error = np.abs(buffer - recompressed).mean(axis=2)

    # Scale so the heat map is readable.
    scale = 20.0
    scaled = np.clip(error * scale, 0, 255).astype(np.uint8)
    heat = cv2.applyColorMap(scaled, cv2.COLORMAP_JET)

    # Per-block statistics, mirroring the JPEG 8x8 grid.
    height, width = error.shape
    block_rows = height // BLOCK_SIZE
    block_cols = width // BLOCK_SIZE

    measurements = {
        "quality": quality,
        "mean_error": round(float(error.mean()), 3),
        "std_error": round(float(error.std()), 3),
        "max_error": round(float(error.max()), 3),
    }

    if block_rows > 0 and block_cols > 0:
        cropped = error[:block_rows * BLOCK_SIZE, :block_cols * BLOCK_SIZE]
        blocks = cropped.reshape(block_rows, BLOCK_SIZE, block_cols, BLOCK_SIZE)
        block_means = blocks.mean(axis=(1, 3))

        threshold = float(np.mean(block_means) + 2 * np.std(block_means))
        hot_blocks = int((block_means > threshold).sum())
        total_blocks = int(block_means.size)

        measurements.update({
            "block_size": BLOCK_SIZE,
            "blocks_total": total_blocks,
            "blocks_above_threshold": hot_blocks,
            "hot_block_ratio": round(hot_blocks / total_blocks, 4) if total_blocks else 0.0,
            "block_error_threshold": round(threshold, 3),
            "block_grid": [block_rows, block_cols],
        })

        # Group the hottest blocks into candidate regions of interest.
        measurements["hot_regions"] = _find_hot_regions(
            block_means, threshold, BLOCK_SIZE
        )

        # An unnaturally uniform error surface is itself a signal: genuine
        # photographs have textured error, flat graphics have almost none.
        uniformity = float(np.std(block_means) / (np.mean(block_means) + 1e-6))
        measurements["error_uniformity"] = round(uniformity, 4)
        measurements["uniformity_ratio"] = round(uniformity / 0.5, 4)

    base_name = os.path.splitext(os.path.basename(file_path))[0]
    heatmap_path = os.path.join(output_folder, f"{base_name}_ela.jpg")
    cv2.imwrite(heatmap_path, cv2.cvtColor(heat, cv2.COLOR_BGR2RGB))

    return {
        "measurements": measurements,
        "heatmap": os.path.basename(heatmap_path),
        "notes": [
            "ELA highlights regions whose compression error differs from the "
            "rest of the image. Edited regions normally appear brighter.",
            "A uniformly bright image means the whole frame was recompressed - "
            "that indicates re-saving rather than localised editing.",
            "ELA output is an investigative lead, not a finding on its own.",
        ],
    }


def io_bytes(image, quality):
    """Re-encode a PIL image to JPEG bytes at the given quality."""
    import io

    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=quality)
    return buffer.getvalue()


def _find_hot_regions(block_means, threshold, block_size):
    """Cluster the hottest blocks into rectangular candidate regions."""
    hot_mask = (block_means > threshold).astype(np.uint8)

    if hot_mask.sum() == 0:
        return []

    contours, _ = cv2.findContours(
        hot_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
    )

    regions = []
    for contour in contours:
        x, y, width, height = cv2.boundingRect(contour)
        area = width * height
        if area < 4:
            continue

        regions.append({
            "x": int(x * block_size),
            "y": int(y * block_size),
            "width": int(width * block_size),
            "height": int(height * block_size),
            "block_area": int(area),
            "mean_error": round(float(block_means[y:y + height, x:x + width].mean()), 3),
        })

    regions.sort(key=lambda region: region["block_area"], reverse=True)
    return regions[:12]
