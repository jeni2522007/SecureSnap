"""Risk scoring and finding synthesis.

Each forensic technique produces its own measurements. This module turns
them into a single, explainable picture for the investigator:

* a 0-100 authenticity risk score,
* a plain-language verdict,
* an ordered list of findings, each with a severity, an explanation and the
  evidence that produced it.

The score is a triage aid. It is deliberately transparent - every point that
was added can be traced back to a named measurement - so that the number can
be defended rather than simply asserted.
"""

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

SEVERITY_LABEL = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Informational",
}


def _finding(severity, code, title, explanation, weight, source):
    """Build a single finding record."""
    return {
        "severity": severity,
        "severity_label": SEVERITY_LABEL.get(severity, severity),
        "code": code,
        "title": title,
        "explanation": explanation,
        "weight": weight,
        "source": source,
    }


def build_findings(results):
    """Derive human-readable findings from the raw analysis results."""
    findings = []

    identity = results.get("identity", {})
    format_info = results.get("format", {})
    metadata = results.get("metadata", {})
    ela = results.get("ela", {})
    copy_move = results.get("copy_move", {})
    noise = results.get("noise", {})
    resampling = results.get("resampling", {})
    steganography = results.get("steganography", {})
    jpeg = results.get("jpeg", {})
    classification = results.get("classification", {})

    # -- File identity ----------------------------------------------------

    for mismatch in identity.get("mismatches", []):
        findings.append(_finding(
            mismatch.get("severity", "HIGH"),
            "IDENTITY_MISMATCH",
            f"File extension does not match content ({mismatch.get('field')})",
            mismatch.get("explanation", ""),
            18 if mismatch.get("severity") in ("HIGH", "CRITICAL") else 10,
            "file identity",
        ))

    if format_info.get("category") == "executable":
        findings.append(_finding(
            "CRITICAL", "EXECUTABLE_CONTENT",
            "Submitted file is an executable program",
            "The bytes are a runnable program, not media. It must not be "
            "opened on an analysis workstation.",
            40, "file identity",
        ))

    for payload in format_info.get("embedded_payloads", []) or []:
        findings.append(_finding(
            "HIGH", "POLYGLOT_CONTENT",
            "Secondary file structure embedded in the file",
            payload.get("description", ""),
            16, "file identity",
        ))

    entropy = results.get("entropy", {})
    if entropy.get("overall_bits_per_byte", 0) > 7.9:
        findings.append(_finding(
            "MEDIUM", "HIGH_ENTROPY_FILE",
            "File entropy is near-maximum",
            entropy.get("interpretation", ""),
            10, "entropy analysis",
        ))

    # -- Metadata ----------------------------------------------------------

    for anomaly in metadata.get("anomalies", []):
        severity = anomaly.get("severity", "MEDIUM")
        weight = {
            "CRITICAL": 30, "HIGH": 16, "MEDIUM": 9, "LOW": 4, "INFO": 0,
        }.get(severity, 8)

        findings.append(_finding(
            severity,
            anomaly.get("code", "METADATA_ANOMALY"),
            anomaly.get("title", "Metadata anomaly"),
            anomaly.get("explanation", ""),
            weight,
            "metadata forensics",
        ))

    # -- Error Level Analysis ---------------------------------------------

    ela_measurements = ela.get("measurements", {}) or {}

    hot_ratio = ela_measurements.get("hot_block_ratio", 0.0)
    if hot_ratio > 0.12:
        findings.append(_finding(
            "MEDIUM", "ELA_LOCALISED_ANOMALY",
            "Localized compression error detected",
            f"{hot_ratio * 100:.1f}% of the compression blocks show an error "
            "level significantly above the image average. These are candidate "
            "edited regions - inspect the ELA heat map.",
            14, "error level analysis",
        ))

    uniformity = ela_measurements.get("error_uniformity", 0.0)
    if uniformity > 0.85:
        findings.append(_finding(
            "LOW", "ELA_UNIFORM",
            "Whole frame was recompressed",
            "Compression error is uniform across the frame, which points to a "
            "re-save of the entire image rather than a local edit.",
            5, "error level analysis",
        ))

    hot_regions = ela_measurements.get("hot_regions", []) or []
    if hot_regions:
        largest = hot_regions[0]
        findings.append(_finding(
            "INFO", "ELA_HOT_REGION",
            f"{len(hot_regions)} candidate edited region(s) located",
            f"The largest candidate region is {largest['width']}x"
            f"{largest['height']} pixels at ({largest['x']}, {largest['y']}) "
            "with a mean error level of "
            f"{largest.get('mean_error', 0)}.",
            0, "error level analysis",
        ))

    # -- Copy-move ---------------------------------------------------------

    if copy_move.get("detected"):
        regions = copy_move.get("regions", []) or []
        area_ratio = copy_move.get("duplicated_area_ratio", 0.0)
        findings.append(_finding(
            "HIGH" if area_ratio > 0.02 else "MEDIUM",
            "COPY_MOVE_DETECTED",
            "Duplicated regions found within the image",
            f"{len(regions)} duplicated region(s) were matched, covering "
            f"{area_ratio * 100:.2f}% of the frame. Copy-move duplication is a "
            "standard way of concealing an object in a photograph. Note that "
            "repetitive scene structure - a row of windows, a fence, a crowd - "
            "can also produce this pattern, so the regions must be inspected "
            "before the result is relied upon.",
            20 if area_ratio > 0.02 else 12,
            "copy-move detection",
        ))

    # -- Noise / splicing --------------------------------------------------

    discontinuities = noise.get("discontinuity_count", 0)
    if discontinuities > 8:
        findings.append(_finding(
            "MEDIUM", "NOISE_DISCONTINUITY",
            "Abrupt changes in image noise detected",
            f"{discontinuities} block boundaries show a sudden change in "
            "noise level. Content joined from a different source usually "
            "produces this signature.",
            13, "noise analysis",
        ))

    if resampling.get("upscaling_suspected"):
        findings.append(_finding(
            "MEDIUM", "UPSCALED_IMAGE",
            "Image appears to have been enlarged",
            resampling.get("interpretation", ""),
            11, "resampling analysis",
        ))

    # -- Steganography -----------------------------------------------------

    if steganography.get("suspicious"):
        findings.append(_finding(
            "HIGH", "STEGANOGRAPHY_SUSPECTED",
            "Statistical evidence of hidden data",
            steganography.get("interpretation", ""),
            22, "steganography analysis",
        ))

    if steganography.get("appended_payload"):
        findings.append(_finding(
            "HIGH", "APPENDED_PAYLOAD",
            "Data appended after the image stream",
            " ".join(steganography.get("notes", []) or [
                "The file carries data beyond the end of the image stream."
            ]),
            20, "steganography analysis",
        ))

    # -- JPEG structure ----------------------------------------------------

    if jpeg.get("double_compression_suspected"):
        findings.append(_finding(
            "LOW", "DOUBLE_COMPRESSION",
            "JPEG re-compression detected",
            "The quantization tables do not match a standard single-save "
            "encoder, indicating the file was written at least twice.",
            4, "jpeg structure analysis",
        ))

    # -- Content classification -------------------------------------------

    for warning in classification.get("consistency_warnings", []) or []:
        findings.append(_finding(
            warning.get("severity", "INFO"),
            warning.get("code", "CONTENT_WARNING"),
            warning.get("title", "Content warning"),
            warning.get("explanation", ""),
            {"HIGH": 14, "MEDIUM": 9, "LOW": 4, "INFO": 0}.get(
                warning.get("severity", "INFO"), 0),
            "content classification",
        ))

    findings.sort(
        key=lambda finding: (-SEVERITY_ORDER.get(finding["severity"], 0),
                              -finding["weight"])
    )
    return findings


def score(findings):
    """Turn findings into a 0-100 risk score with a defensible breakdown.

    The score grows with the severity of the findings but is damped so that a
    long list of trivial observations cannot push an image to the top of the
    scale on its own.
    """
    total = sum(finding["weight"] for finding in findings)

    # Diminishing returns: 100 raw points reach roughly 78 on the scale.
    score_value = 100 * (1 - pow(2.718281828, -total / 45.0))

    # A single critical finding forces the score into the top band.
    if any(finding["severity"] == "CRITICAL" for finding in findings):
        score_value = max(score_value, 70)

    score_value = round(min(100.0, score_value), 1)

    return {
        "score": score_value,
        "raw_points": total,
        "breakdown": [
            {
                "code": finding["code"],
                "title": finding["title"],
                "severity": finding["severity"],
                "points": finding["weight"],
            }
            for finding in findings
        ],
    }


def verdict(score_value, findings):
    """Assign an overall verdict with the reasoning that produced it."""
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]

    if critical:
        label = "CONTENT UNSAFE TO RELY ON"
        reasoning = (
            "A critical finding was recorded. The file must not be opened or "
            "relied upon until it has been escalated to a specialist "
            "laboratory."
        )
    elif score_value >= 60 or len(high) >= 3:
        label = "LIKELY ALTERED - SECOND OPINION REQUIRED"
        reasoning = (
            f"The combined risk score is {score_value} with {len(high)} high "
            "severity finding(s). Independent expert verification is advised "
            "before this image is used in evidence."
        )
    elif score_value >= 35 or len(high) >= 1:
        label = "INDICATORS PRESENT - VERIFY MANUALLY"
        reasoning = (
            f"The combined risk score is {score_value}. The findings above "
            "identify specific areas to verify against the original media."
        )
    elif score_value >= 15:
        label = "NO CONTRADICTIONS FOUND"
        reasoning = (
            f"The combined risk score is {score_value}. Nothing found "
            "contradicts the provenance of the file, although the absence of "
            "a finding is not proof of authenticity."
        )
    else:
        label = "CONSISTENT WITH ORIGINAL CAPTURE"
        reasoning = (
            "The analysis produced no material indicators against the "
            "authenticity of the file. Continue to corroborate with other "
            "evidence."
        )

    return {
        "label": label,
        "reasoning": reasoning,
        "risk_band": _band(score_value),
    }


def _band(score_value):
    """Map a score to a risk band."""
    if score_value >= 60:
        return "Elevated"
    if score_value >= 35:
        return "Moderate"
    if score_value >= 15:
        return "Low"
    return "Minimal"


def summarise(findings, score_result, verdict_result):
    """Produce the compact summary shown at the top of the report."""
    by_severity = {}
    for finding in findings:
        by_severity.setdefault(finding["severity"], 0)
        by_severity[finding["severity"]] += 1

    return {
        "score": score_result["score"],
        "verdict": verdict_result["label"],
        "reasoning": verdict_result["reasoning"],
        "risk_band": verdict_result["risk_band"],
        "finding_count": len(findings),
        "by_severity": by_severity,
        "critical_count": by_severity.get("CRITICAL", 0),
        "high_count": by_severity.get("HIGH", 0),
    }
