"""JPEG structure, noise and resampling analysis.

Three separate questions are answered here:

1. Has this JPEG been saved more than once (double compression)? The
   quantization tables leave a fingerprint of the encoder that wrote them.
2. Are the noise characteristics of different parts of the frame different?
   Spliced regions carry noise from a different source image.
3. Was the image enlarged? Upscaling is what happens before content is
   published at a larger size, and it destroys the fine grain that forensics
   relies on.
"""

import cv2
import numpy as np
from PIL import Image

# The luminance quantization table used by the standard IJG/libjpeg encoder.
# Its presence with a small quality index is a strong hint of re-encoding.
STANDARD_LUMA_TABLE = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]


def analyse_jpeg_structure(file_path):
    """Inspect the JPEG quantization tables and estimate re-compression.

    Returns a dictionary describing the tables, whether they match the
    standard encoder table, and an estimate of the likely quality factor.
    """
    result = {
        "is_jpeg": False,
        "tables": [],
        "matches_standard_table": False,
        "estimated_quality": None,
        "double_compression_suspected": False,
        "notes": [],
    }

    try:
        with Image.open(file_path) as image:
            result["is_jpeg"] = image.format == "JPEG"
            tables = getattr(image, "quantization", None)

            if tables:
                for table_id, table in tables.items():
                    result["tables"].append({
                        "id": int(table_id),
                        "length": len(table),
                        "head": [int(value) for value in list(table)[:8]],
                    })

            if result["is_jpeg"] and tables:
                luma_table = None
                for table_id, table in tables.items():
                    if len(table) >= 64:
                        luma_table = [int(value) for value in table[:64]]
                        break

                if luma_table:
                    match = luma_table == STANDARD_LUMA_TABLE
                    result["matches_standard_table"] = match
                    result["estimated_quality"] = _estimate_quality(luma_table)
                    result["double_compression_suspected"] = not match

                    if match:
                        result["notes"].append(
                            "Quantization tables match the standard libjpeg "
                            "encoder exactly - the image was written by a "
                            "conventional JPEG encoder."
                        )
                    else:
                        result["notes"].append(
                            "Quantization tables do not match the standard "
                            "encoder table, which is consistent with the file "
                            "having been re-compressed (for example after "
                            "messaging-app resizing or platform re-encoding)."
                        )

                    if result["estimated_quality"]:
                        result["notes"].append(
                            f"Estimated final JPEG quality factor: "
                            f"~{result['estimated_quality']}."
                        )
    except Exception as error:  # pragma: no cover - defensive
        result["error"] = str(error)

    return result


def _estimate_quality(luma_table):
    """Estimate the JPEG quality factor from the first quantization value."""
    if not luma_table:
        return None

    first = luma_table[0]
    if first == 0:
        return None

    # Standard inverse of the IJG quality scale.
    quality = 100 - (first * 200) // (first + 100) * 2
    quality = max(1, min(100, quality))
    return quality


def analyse_noise_regions(file_path):
    """Measure noise statistics across the frame.

    Splicing two different images leaves a discontinuity in the local noise
    level. The frame is divided into blocks and the standard deviation of a
    high-pass residual is compared across neighbouring blocks.
    """
    image = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
    if image is None:
        return {"available": False, "reason": "Image could not be decoded"}

    height, width = image.shape
    block = 16
    block_rows = max(1, height // block)
    block_cols = max(1, width // block)

    cropped = image[:block_rows * block, :block_cols * block]
    blocks = cropped.reshape(block_rows, block, block_cols, block).transpose(0, 2, 1, 3)
    blocks = blocks.reshape(block_rows, block_cols, block, block)

    # High-pass residual: removes smooth luminance, keeps sensor/encoder grain.
    # The 3x3 mean is computed per block with plain array slicing.
    padded = np.pad(blocks, ((1, 1), (1, 1), (0, 0), (0, 0)), mode="edge")
    mean = np.zeros(blocks.shape, dtype=np.float64)
    for row_offset in range(3):
        for column_offset in range(3):
            mean += padded[
                row_offset:row_offset + block_rows,
                column_offset:column_offset + block_cols,
            ]
    mean /= 9.0

    residual = blocks - mean

    std_map = residual.std(axis=(2, 3))
    mean_map = residual.mean(axis=(2, 3))

    horizontal = np.abs(np.diff(std_map, axis=1))
    vertical = np.abs(np.diff(std_map, axis=0))

    edges = []
    for row, column in zip(*np.where(horizontal > 1.2)):
        edges.append({
            "type": "vertical",
            "x": int((column + 1) * block),
            "y": int(row * block),
            "length": int(block),
            "delta": round(float(horizontal[row, column]), 3),
        })
    for row, column in zip(*np.where(vertical > 1.2)):
        edges.append({
            "type": "horizontal",
            "x": int(column * block),
            "y": int((row + 1) * block),
            "length": int(block),
            "delta": round(float(vertical[row, column]), 3),
        })

    std_values = std_map.flatten()
    global_std = float(std_values.mean())
    deviations = np.abs(std_values - global_std)

    return {
        "available": True,
        "block_size": block,
        "grid": [block_rows, block_cols],
        "global_noise_std": round(global_std, 3),
        "noise_std_min": round(float(std_values.min()), 3),
        "noise_std_max": round(float(std_values.max()), 3),
        "max_neighbour_deviation": round(float(deviations.max()), 3),
        "discontinuity_count": int(len(edges)),
        "candidate_boundaries": sorted(
            edges, key=lambda edge: edge["delta"], reverse=True
        )[:20],
        "residual_mean_min": round(float(mean_map.min()), 3),
        "residual_mean_max": round(float(mean_map.max()), 3),
    }


def detect_resampling(file_path):
    """Detect whether the image has been resampled.

    Two fingerprints are used: the drop of high-frequency energy that comes
    with upscaling, and the periodic peaks in the power spectrum that
    interpolation artefacts leave behind.
    """
    image = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
    if image is None:
        return {"available": False, "reason": "Image could not be decoded"}

    height, width = image.shape
    if height < 16 or width < 16:
        return {"available": False, "reason": "Image is too small to analyse"}

    # Work on a square, centred crop so the spectrum is comparable.
    size = min(height, width, 1024)
    top = (height - size) // 2
    left = (width - size) // 2
    crop = image[top:top + size, left:left + size].astype(np.float64)

    crop = crop - crop.mean()
    spectrum = np.abs(np.fft.fftshift(np.fft.fft2(crop))) ** 2
    spectrum /= (spectrum.sum() + 1e-12)

    rows, columns = spectrum.shape
    center_row, center_column = rows // 2, columns // 2

    yy, xx = np.ogrid[:rows, :columns]
    radius = np.sqrt((yy - center_row) ** 2 + (xx - center_column) ** 2)
    max_radius = radius.max()

    high_energy = float(spectrum[radius > 0.5 * max_radius].sum())
    low_energy = float(spectrum[radius <= 0.25 * max_radius].sum())

    # Look for periodic peaks in the radial profile, which interpolation
    # (especially nearest-neighbour and bilinear) tends to create.
    profile = []
    for band in range(1, int(max_radius)):
        mask = (radius >= band - 0.5) & (radius < band + 0.5)
        if mask.sum() == 0:
            continue
        profile.append(float(spectrum[mask].mean()))

    profile_array = np.array(profile) if profile else np.zeros(1)
    if len(profile_array) > 4:
        differences = np.diff(profile_array)
        peak_count = int(np.count_nonzero(
            (differences[:-1] > 0) & (differences[1:] < 0)
        ))
        periodicity = peak_count / len(profile_array)
    else:
        peak_count = 0
        periodicity = 0.0

    ratio = high_energy / (low_energy + 1e-12)

    # A strongly upscaled image carries very little energy in the outer half
    # of the spectrum. The measured ratio separates an enlarged frame from an
    # ordinary compressed photograph by roughly an order of magnitude.
    upscaled = ratio < 0.0025

    return {
        "available": True,
        "high_frequency_energy_ratio": round(ratio, 6),
        "spectrum_periodicity": round(periodicity, 4),
        "spectral_peaks": peak_count,
        "upscaling_suspected": bool(upscaled),
        "dimensions": [int(width), int(height)],
        "interpretation": (
            "The frequency profile shows the regular banding typical of "
            "image interpolation - the frame was enlarged after capture."
            if upscaled else
            "The frequency profile is consistent with an image that was not "
            "resampled, or was resampled by a method that leaves little "
            "spectral trace."
        ),
    }
