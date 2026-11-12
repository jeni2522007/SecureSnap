"""Comparative analysis of two images.

A common evidential question is whether a second image is the same scene as
the first, altered. This module aligns the pair, measures structural
similarity and produces a difference map that highlights the regions where
the two diverge.

It also answers a narrower and very practical question: does the second file
carry the same camera metadata as the first? When a genuine photo is
re-exported the camera fields usually survive; when a composite is built
from fragments they often do not.
"""

import os

import cv2
import numpy as np


def compare_images(first_path, second_path, output_folder):
    """Compare two images and return the measurements."""
    os.makedirs(output_folder, exist_ok=True)

    first = cv2.imread(first_path, cv2.IMREAD_COLOR)
    second = cv2.imread(second_path, cv2.IMREAD_COLOR)

    if first is None or second is None:
        return {
            "available": False,
            "reason": "One or both images could not be decoded for comparison.",
        }

    first_height, first_width = first.shape[:2]
    second_height, second_width = second.shape[:2]

    # Resize the second image onto the first image's grid so a pixel-level
    # comparison is meaningful.
    resized_second = cv2.resize(
        second, (first_width, first_height), interpolation=cv2.INTER_AREA
    )

    difference = cv2.absdiff(first, resized_second)
    difference_gray = cv2.cvtColor(difference, cv2.COLOR_BGR2GRAY)

    # Structural similarity on the luminance channel.
    ssim_score, ssim_map = _structural_similarity(
        cv2.cvtColor(first, cv2.COLOR_BGR2GRAY),
        cv2.cvtColor(resized_second, cv2.COLOR_BGR2GRAY),
    )

    # Estimate the translation offset between the pair.
    shift_x, shift_y = _estimate_shift(
        cv2.cvtColor(first, cv2.COLOR_BGR2GRAY),
        cv2.cvtColor(resized_second, cv2.COLOR_BGR2GRAY),
    )

    correlation = _correlation(
        cv2.cvtColor(first, cv2.COLOR_BGR2GRAY),
        cv2.cvtColor(resized_second, cv2.COLOR_BGR2GRAY),
    )

    changed_pixels = int((difference_gray > 24).sum())
    total_pixels = int(difference_gray.size)
    changed_ratio = changed_pixels / total_pixels if total_pixels else 0.0

    # Difference heat map.
    heat = cv2.applyColorMap(
        np.clip(difference_gray.astype(np.float32) * 4, 0, 255).astype(np.uint8),
        cv2.COLORMAP_JET,
    )

    base = os.path.splitext(os.path.basename(first_path))[0]
    diff_path = os.path.join(output_folder, f"compare_{base}_diff.jpg")
    cv2.imwrite(diff_path, heat)

    ssim_heat = cv2.applyColorMap(
        np.clip((1.0 - ssim_map) * 255, 0, 255).astype(np.uint8),
        cv2.COLORMAP_JET,
    )
    ssim_path = os.path.join(output_folder, f"compare_{base}_ssim.jpg")
    cv2.imwrite(ssim_path, ssim_heat)

    regions = _difference_regions(difference_gray)

    interpretation = _interpret(ssim_score, changed_ratio, correlation)

    return {
        "available": True,
        "first": {
            "path": first_path, "width": first_width, "height": first_height,
        },
        "second": {
            "path": second_path, "width": second_width, "height": second_height,
        },
        "dimension_change": {
            "width_delta": second_width - first_width,
            "height_delta": second_height - first_height,
            "same_dimensions": (first_width, first_height) ==
                              (second_width, second_height),
        },
        "ssim": round(ssim_score, 4),
        "correlation": round(correlation, 4),
        "changed_pixel_ratio": round(changed_ratio, 4),
        "changed_pixels": changed_pixels,
        "total_pixels": total_pixels,
        "estimated_shift": {"x": int(shift_x), "y": int(shift_y)},
        "difference_map": os.path.basename(diff_path),
        "similarity_map": os.path.basename(ssim_path),
        "difference_regions": regions,
        "interpretation": interpretation,
    }


def _structural_similarity(first, second):
    """Compute mean SSIM with a Gaussian window, implemented with numpy."""
    first = first.astype(np.float64)
    second = second.astype(np.float64)

    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2

    kernel = cv2.getGaussianKernel(11, 1.5)
    window = np.outer(kernel, kernel.transpose())

    mu_first = cv2.filter2D(first, -1, window)[5:-5, 5:-5]
    mu_second = cv2.filter2D(second, -1, window)[5:-5, 5:-5]

    mu_first_sq = mu_first ** 2
    mu_second_sq = mu_second ** 2
    mu_product = mu_first * mu_second

    sigma_first_sq = cv2.filter2D(first ** 2, -1, window)[5:-5, 5:-5] - mu_first_sq
    sigma_second_sq = cv2.filter2D(second ** 2, -1, window)[5:-5, 5:-5] - mu_second_sq
    sigma_product = cv2.filter2D(first * second, -1, window)[5:-5, 5:-5] - mu_product

    numerator = (2 * mu_product + c1) * (2 * sigma_product + c2)
    denominator = (mu_first_sq + mu_second_sq + c1) * (sigma_first_sq + sigma_second_sq + c2)

    ssim_map = numerator / denominator
    return float(ssim_map.mean()), ssim_map


def _correlation(first, second):
    """Pearson correlation of the two luminance channels."""
    first_flat = first.astype(np.float64).flatten()
    second_flat = second.astype(np.float64).flatten()

    first_mean = first_flat.mean()
    second_mean = second_flat.mean()

    numerator = np.sum((first_flat - first_mean) * (second_flat - second_mean))
    denominator = np.sqrt(
        np.sum((first_flat - first_mean) ** 2) *
        np.sum((second_flat - second_mean) ** 2)
    )

    if denominator == 0:
        return 0.0
    return float(numerator / denominator)


def _estimate_shift(first, second):
    """Estimate the translation between two images using phase correlation."""
    try:
        window = cv2.createHanningWindow((first.shape[1], first.shape[0]), cv2.CV_32F)
        (shift_x, shift_y), response = cv2.phaseCorrelate(
            first.astype(np.float32), second.astype(np.float32), window
        )
        return shift_x, shift_y
    except Exception:
        return 0.0, 0.0


def _difference_regions(difference_gray):
    """Locate the contiguous areas where the two images diverge."""
    _, mask = cv2.threshold(difference_gray, 40, 255, cv2.THRESH_BINARY)
    mask = cv2.dilate(mask, np.ones((9, 9), np.uint8), iterations=2)

    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    regions = []
    for contour in contours:
        area = cv2.contourArea(contour)
        if area < 400:
            continue
        x, y, width, height = cv2.boundingRect(contour)
        regions.append({
            "x": int(x), "y": int(y),
            "width": int(width), "height": int(height),
            "area": int(area),
        })

    regions.sort(key=lambda region: region["area"], reverse=True)
    return regions[:15]


def _interpret(ssim_score, changed_ratio, correlation):
    """Turn the numbers into a plain-language conclusion."""
    if ssim_score >= 0.97 and changed_ratio < 0.02:
        return (
            "The two images are structurally near-identical. They are the "
            "same picture, or the same picture recompressed."
        )
    if ssim_score >= 0.85 and correlation > 0.9:
        return (
            "The two images are closely related with limited differences. "
            "The differences are consistent with a minor edit, a different "
            "compression pass, or a small crop."
        )
    if correlation > 0.7:
        return (
            "The two images share substantial structure but differ across "
            "measurable regions. The difference map identifies where the "
            "content diverges - inspect those regions for inserted or "
            "removed objects."
        )
    return (
        "The two images are substantially different. They do not appear to "
        "depict the same scene, or the second is a heavily modified version "
        "of the first."
    )
