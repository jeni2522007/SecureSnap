"""Steganography and data-hiding indicators.

Two questions are checked:

* Is there statistical evidence that the least significant bit plane of the
  image has been modified (classic LSB steganography)?
* Does the container carry data appended after the end of the real media
  stream?
"""

import math
import os
from collections import Counter

import cv2
import numpy as np
from PIL import Image


def analyse_lsb(file_path, output_folder):
    """Run the chi-square attack against the LSB plane.

    The chi-square statistic measures how evenly the LSB values are
    distributed across neighbouring pixel pairs. Natural images have a
    spiky distribution; an LSB-embedded image is flattened out.
    """
    os.makedirs(output_folder, exist_ok=True)

    try:
        image = Image.open(file_path).convert("RGB")
    except Exception as error:
        return {"available": False, "reason": f"Image could not be read: {error}"}

    pixels = np.asarray(image, dtype=np.uint8)

    results = []
    channel_names = ("red", "green", "blue")

    for index, channel_name in enumerate(channel_names):
        channel = pixels[:, :, index]
        statistic, suspicious = _chi_square(channel)
        results.append({
            "channel": channel_name,
            "chi_square": round(statistic, 4),
            "suspicious": bool(suspicious),
        })

    # Visualise the least significant bit plane.
    lsb_plane = ((pixels & 1) * 255).astype(np.uint8)
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    plane_path = os.path.join(output_folder, f"{base_name}_lsb.png")
    cv2.imwrite(plane_path, lsb_plane)

    # A genuinely random LSB plane is visually noisy; a natural image that
    # has not been tampered with shows visible structure.
    plane_entropy = _entropy(lsb_plane.flatten())

    suspicious_channels = [r["channel"] for r in results if r["suspicious"]]

    return {
        "available": True,
        "channels": results,
        "lsb_plane": os.path.basename(plane_path),
        "lsb_plane_entropy": round(plane_entropy, 4),
        "suspicious": bool(suspicious_channels),
        "suspicious_channels": suspicious_channels,
        "interpretation": (
            "The least-significant-bit plane shows the flat statistical "
            "signature of hidden data in the "
            f"{', '.join(suspicious_channels)} channel(s)."
            if suspicious_channels else
            "The least-significant-bit plane shows the normal statistical "
            "profile of an unaltered image. No classic LSB payload detected."
        ),
    }


def _chi_square(channel):
    """Chi-square test over adjacent pixel pairs of one colour channel."""
    flat = channel.flatten()
    pairs = flat[:len(flat) - (len(flat) % 2)].reshape(-1, 2)

    if pairs.shape[0] == 0:
        return 0.0, False

    # Separate pairs by the value of their first element (0 or 1).
    group_zero = pairs[pairs[:, 0] == 0][:, 1]
    group_one = pairs[pairs[:, 0] == 1][:, 1]

    if group_zero.size == 0 or group_one.size == 0:
        return 0.0, False

    histogram_zero = np.bincount(group_zero, minlength=256).astype(np.float64)
    histogram_one = np.bincount(group_one, minlength=256).astype(np.float64)

    total = histogram_zero.sum() + histogram_one.sum()
    if total == 0:
        return 0.0, False

    # Expected distribution: average the two histograms.
    expected = (histogram_zero / max(histogram_zero.sum(), 1)) / 2 + \
        (histogram_one / max(histogram_one.sum(), 1)) / 2

    statistic = 0.0
    for index in range(256):
        observed = (histogram_zero[index] + histogram_one[index]) / total
        if expected[index] > 0:
            statistic += ((observed - expected[index]) ** 2) / expected[index]

    # A very low statistic means the LSBs are evenly distributed, which is
    # the signature of embedded data.
    suspicious = statistic < 30
    return statistic, suspicious


def _entropy(values):
    counts = Counter(values.tolist())
    total = len(values)
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def detect_appended_data(file_path):
    """Check whether data is appended after the end of the media stream."""
    result = {
        "checked": True,
        "trailing_bytes": 0,
        "appended_payload": False,
        "notes": [],
    }

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return result

    with open(file_path, "rb") as handle:
        head = handle.read(min(file_size, 1024 * 1024))

    if head[:3] == b"\xff\xd8\xff":
        # Walk the JPEG marker segments to find the true end of the image.
        offset = 2
        true_end = file_size
        length = len(head)

        while offset < length - 3:
            if head[offset] != 0xFF:
                offset += 1
                continue

            marker = head[offset + 1]
            if marker in (0xD8, 0xD9):
                offset += 2
                continue
            if marker == 0xDA:  # Start of scan - image data follows.
                break
            if 0xD0 <= marker <= 0xD7:
                offset += 2
                continue

            if offset + 4 > length:
                break

            segment_length = int.from_bytes(head[offset + 2:offset + 4], "big")
            offset += 2 + segment_length

        # Scan forward for the end-of-image marker.
        with open(file_path, "rb") as handle:
            handle.seek(max(0, offset))
            tail = handle.read()

        end_marker = tail.find(b"\xff\xd9")
        if end_marker != -1:
            true_end = offset + end_marker + 2

        trailing = file_size - true_end
        result["trailing_bytes"] = int(trailing)
        result["appended_payload"] = trailing > 0
        if trailing > 0:
            result["notes"].append(
                f"{trailing} bytes follow the end of the JPEG image stream. "
                "Payloads are commonly hidden in this region."
            )

    elif head[:4] == b"\x89PNG":
        # The PNG IEND chunk should be the last thing in the file.
        end_marker = head.rfind(b"IEND")
        if end_marker != -1:
            true_end = end_marker + 8  # IEND + CRC
            trailing = file_size - true_end
            result["trailing_bytes"] = int(trailing)
            result["appended_payload"] = trailing > 0
            if trailing > 0:
                result["notes"].append(
                    f"{trailing} bytes follow the PNG end marker."
                )

    if result["appended_payload"]:
        result["notes"].append(
            "Extract the trailing region separately and examine it as an "
            "independent artefact."
        )

    return result
