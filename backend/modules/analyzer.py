"""The forensic analysis pipeline.

`analyse_file` runs every applicable technique against a file and returns a
single structure that contains:

* the raw measurements from each technique,
* the derived findings,
* the risk score and verdict,
* the flattened *facts* dictionary that the rule engine evaluates.

Keeping the facts flat and explicitly named means a rule can be written
against a stable, documented field name.
"""

import os
import shutil
import uuid
from datetime import datetime, timezone

from modules import file_identity, metadata as metadata_module
from modules.ai_classifier import check_metadata_consistency, classify_image
from modules.forensics import copy_move, ela, noise, scoring, steganography

ANALYSABLE_IMAGE_FORMATS = {"JPEG", "PNG", "WEBP", "BMP", "TIFF", "GIF"}


def analyse_file(file_path, analysis_folder, original_filename=None,
                 progress=None):
    """Run the complete analysis pipeline over a file.

    `progress` is an optional callable that receives a short status string,
    used to report progress during a long analysis.
    """
    os.makedirs(analysis_folder, exist_ok=True)

    def report(status):
        if progress:
            progress(status)

    report("Identifying file format")
    identity = file_identity.compare_claim(
        file_path, original_filename or os.path.basename(file_path)
    )
    format_info = identity["detected"]

    report("Fingerprinting file")
    entropy = file_identity.analyse_entropy(file_path)

    report("Extracting embedded metadata")
    meta = metadata_module.extract_metadata(file_path)

    report("Inspecting JPEG structure")
    jpeg = noise.analyse_jpeg_structure(file_path)

    results = {
        "engine_version": "2.0.0",
        "analysed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "identity": identity,
        "format": format_info,
        "entropy": entropy,
        "metadata": meta,
        "jpeg": jpeg,
    }

    is_analysable_image = format_info.get("format") in \
        ANALYSABLE_IMAGE_FORMATS or format_info.get("category") == "image"

    if is_analysable_image:
        run_id = uuid.uuid4().hex[:12]
        artefact_folder = os.path.join(analysis_folder, run_id)

        report("Running error level analysis")
        try:
            results["ela"] = ela.compute_ela(file_path, artefact_folder)
        except Exception as error:
            results["ela"] = {"error": str(error), "measurements": {}}

        report("Searching for duplicated regions")
        try:
            results["copy_move"] = copy_move.detect_copy_move(
                file_path, artefact_folder
            )
        except Exception as error:
            results["copy_move"] = {"available": False, "reason": str(error)}

        report("Measuring noise and resampling signatures")
        try:
            results["noise"] = noise.analyse_noise_regions(file_path)
        except Exception as error:
            results["noise"] = {"available": False, "reason": str(error)}

        try:
            results["resampling"] = noise.detect_resampling(file_path)
        except Exception as error:
            results["resampling"] = {"available": False, "reason": str(error)}

        report("Testing for hidden data")
        try:
            results["steganography"] = steganography.analyse_lsb(
                file_path, artefact_folder
            )
            results["steganography"]["appended_payload"] = \
                steganography.detect_appended_data(file_path)["appended_payload"]
            results["steganography"]["container_notes"] = \
                steganography.detect_appended_data(file_path)["notes"]
        except Exception as error:
            results["steganography"] = {
                "available": False, "reason": str(error), "suspicious": False,
                "appended_payload": False,
            }

        report("Classifying content")
        classification = classify_image(file_path)
        classification["consistency_warnings"] = check_metadata_consistency(
            classification, meta
        )
        results["classification"] = classification

        # The folder name is what the browser needs in order to fetch the
        # generated images; the absolute path is kept separately for
        # server-side use only.
        results["artefact_folder"] = run_id
        results["artefact_path"] = artefact_folder
    else:
        report("Skipping pixel analysis - not an image file")
        results["ela"] = {"measurements": {}, "notes": [
            "Pixel-level analysis was not performed because the file is not a "
            "still image."
        ]}
        results["copy_move"] = {"available": False, "detected": False,
                                "reason": "Not a still image"}
        results["noise"] = {"available": False}
        results["resampling"] = {"available": False}
        results["steganography"] = {"available": False, "suspicious": False,
                                   "appended_payload": False}
        results["classification"] = {
            "available": False, "predictions": [], "tags": [],
            "top_confidence": 0.0, "consistency_warnings": [],
            "reason": "Content classification applies to images only.",
        }

    report("Synthesising findings")
    findings = scoring.build_findings(results)
    score_result = scoring.score(findings)
    verdict_result = scoring.verdict(score_result["score"], findings)

    results["findings"] = findings
    results["risk"] = score_result
    results["verdict"] = verdict_result
    results["summary"] = scoring.summarise(findings, score_result, verdict_result)
    results["facts"] = build_facts(results)

    return results


def build_facts(results):
    """Flatten the analysis results into the namespaced fact structure.

    The rule language addresses these names directly, so this mapping is the
    documented contract between the analysis pipeline and the rules.
    """
    identity = results.get("identity", {})
    format_info = results.get("format", {})
    meta = results.get("metadata", {})
    ela_results = results.get("ela", {}) or {}
    ela_measurements = ela_results.get("measurements", {}) or {}
    copy_move_results = results.get("copy_move", {}) or {}
    noise_results = results.get("noise", {}) or {}
    resampling_results = results.get("resampling", {}) or {}
    steganography_results = results.get("steganography", {}) or {}
    jpeg_results = results.get("jpeg", {}) or {}
    classification = results.get("classification", {}) or {}

    software_names = " | ".join(meta.get("software", []) or []).lower()
    editing_markers = [
        "photoshop", "lightroom", "gimp", "pixelmator", "affinity", "canva",
        "snapseed", "faceapp", "remove.bg", "picsart", "paintshop", "inkscape",
        "krita", "luminar", "topaz", "illustrator", "paint.net", "corel",
    ]
    synthetic_markers = [
        "stable diffusion", "midjourney", "dall-e", "firefly", "imagen",
        "flux", "comfyui", "automatic1111", "invokeai", "novelai", "leonardo",
        "dreamstudio", "gemini", "chatgpt", "sora", "runway", "heygen", "roop",
    ]

    timestamp_anomalies = [
        anomaly for anomaly in (meta.get("anomalies", []) or [])
        if anomaly.get("code", "").startswith("TIMESTAMP")
        or anomaly.get("code", "") in ("FUTURE_TIMESTAMP", "IMPLAUSIBLE_TIMESTAMP",
                                       "DIGITIZE_BEFORE_CAPTURE")
    ]

    gps = meta.get("gps", {}) or {}

    return {
        "format": {
            "name": format_info.get("format"),
            "extension": format_info.get("extension"),
            "category": format_info.get("category"),
            "mime": format_info.get("mime"),
        },
        "identity": {
            "claimed_extension": identity.get("claimed_extension"),
            "detected_extension": format_info.get("extension"),
            "claim_mismatch_count": len(identity.get("mismatches", []) or []),
            "identity_trusted": identity.get("identity_trusted", False),
            "embedded_payload_count": len(
                format_info.get("embedded_payloads", []) or []
            ),
        },
        "entropy": {
            "overall": results.get("entropy", {}).get("overall_bits_per_byte"),
            "head": results.get("entropy", {}).get("head_bits_per_byte"),
            "tail": results.get("entropy", {}).get("tail_bits_per_byte"),
        },
        "metadata": {
            "available": bool(meta.get("available", False)),
            "camera_make": (meta.get("camera", {}) or {}).get("make"),
            "camera_model": (meta.get("camera", {}) or {}).get("model"),
            "software_mentions_editing": any(
                marker in software_names for marker in editing_markers
            ),
            "software_mentions_synthetic": any(
                marker in software_names for marker in synthetic_markers
            ),
            "timestamp_anomaly_count": len(timestamp_anomalies),
            "anomaly_count": len(meta.get("anomalies", []) or []),
            "gps": {
                "latitude": gps.get("latitude"),
                "longitude": gps.get("longitude"),
                "altitude": gps.get("altitude_metres"),
            },
        },
        "ela": {
            "hot_block_ratio": ela_measurements.get("hot_block_ratio", 0.0),
            "mean_error": ela_measurements.get("mean_error", 0.0),
            "error_uniformity": ela_measurements.get("error_uniformity", 0.0),
            "hot_region_count": len(ela_measurements.get("hot_regions", []) or []),
        },
        "copy_move": {
            "detected": bool(copy_move_results.get("detected", False)),
            "regions_count": len(copy_move_results.get("regions", []) or []),
            "match_count": copy_move_results.get("match_count", 0),
            "duplicated_area_ratio": copy_move_results.get(
                "duplicated_area_ratio", 0.0
            ),
        },
        "noise": {
            "discontinuity_count": noise_results.get("discontinuity_count", 0),
            "global_noise_std": noise_results.get("global_noise_std"),
        },
        "resampling": {
            "upscaling_suspected": bool(
                resampling_results.get("upscaling_suspected", False)
            ),
            "periodicity": resampling_results.get("spectrum_periodicity"),
        },
        "steganography": {
            "suspicious": bool(steganography_results.get("suspicious", False)),
            "appended_payload": bool(
                steganography_results.get("appended_payload", False)
            ),
            "lsb_plane_entropy": steganography_results.get("lsb_plane_entropy"),
        },
        "jpeg": {
            "double_compression_suspected": bool(
                jpeg_results.get("double_compression_suspected", False)
            ),
            "estimated_quality": jpeg_results.get("estimated_quality"),
        },
        "classification": {
            "top_label": (
                classification.get("predictions", [{}])[0].get("label")
                if classification.get("predictions") else None
            ),
            "top_confidence": classification.get("top_confidence", 0.0),
            "scene_likelihood": classification.get("scene_likelihood", 0.0),
        },
        "risk": {
            "score": results.get("risk", {}).get("score", 0.0),
            "band": results.get("verdict", {}).get("risk_band"),
        },
    }


def copy_artefacts(results, destination):
    """Copy the generated heat maps and diagnostic images to a report folder."""
    os.makedirs(destination, exist_ok=True)

    copied = {}
    artefacts = {
        "ela": results.get("ela", {}).get("heatmap"),
        "copy_move": results.get("copy_move", {}).get("match_map"),
        "lsb_plane": results.get("steganography", {}).get("lsb_plane"),
    }

    source_folder = results.get("artefact_path") or results.get("artefact_folder")
    if not source_folder:
        return copied

    for label, filename in artefacts.items():
        if not filename:
            continue
        source = os.path.join(source_folder, filename)
        if not os.path.exists(source):
            continue
        target = os.path.join(destination, filename)
        shutil.copy2(source, target)
        copied[label] = filename

    return copied
