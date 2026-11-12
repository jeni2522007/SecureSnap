"""The built-in forensic rule set.

These rules encode the checks a digital-image examiner would normally carry
out by hand. They ship enabled and can be edited, disabled or extended by the
investigator.
"""

BUILTIN_RULES = [
    {
        "name": "MetadataStripped",
        "condition": 'metadata.available == false AND format.category == "image"',
        "action": "ESCALATE_UNVERIFIED_SOURCE",
        "severity": "MEDIUM",
        "description": (
            "The image carries no EXIF/XMP metadata. Common for images that "
            "have been re-saved, sent through a messaging app, or published "
            "on a social platform. Obtain the original file from the device."
        ),
    },
    {
        "name": "EditingSoftwareRecorded",
        "condition": 'metadata.software_mentions_editing == true',
        "action": "REQUEST_UNEDITED_ORIGINAL",
        "severity": "HIGH",
        "description": (
            "The metadata names an image editing application, so the file has "
            "been edited after capture. Both the edited and unedited versions "
            "should be obtained."
        ),
    },
    {
        "name": "SyntheticMediaTool",
        "condition": 'metadata.software_mentions_synthetic == true',
        "action": "ESCALATE_SYNTHETIC_MEDIA",
        "severity": "HIGH",
        "description": (
            "The metadata names a generative or deepfake tool. Treat the "
            "content as synthetic until independently verified."
        ),
    },
    {
        "name": "TimestampContradiction",
        "condition": "metadata.timestamp_anomaly_count > 0",
        "action": "CHALLENGE_TIMESTAMP_EVIDENCE",
        "severity": "HIGH",
        "description": (
            "The recorded capture and modification times contradict each "
            "other or are implausible. The timestamp cannot be relied on "
            "without corroboration."
        ),
    },
    {
        "name": "GpsLocationPresent",
        "condition": "metadata.gps.latitude EXISTS",
        "action": "VERIFY_LOCATION_CLAIM",
        "severity": "INFO",
        "description": (
            "GPS coordinates are embedded in the file. Cross-check them "
            "against the stated location of capture, cell-site data and "
            "camera registration records."
        ),
    },
    {
        "name": "GpsAbsent",
        "condition": "metadata.gps.latitude EXISTS == false AND metadata.available == true",
        "action": "NOTE_GPS_ABSENT",
        "severity": "LOW",
        "description": (
            "No GPS coordinates are present even though other metadata is "
            "intact. Common for images transferred off a device or cropped "
            "from a screenshot."
        ),
    },
    {
        "name": "ExtensionMismatch",
        "condition": "identity.claim_mismatch_count > 0",
        "action": "QUARANTINE_AND_RECLASSIFY",
        "severity": "HIGH",
        "description": (
            "The file extension does not match its actual content. The file "
            "must be reclassified by its true format and handled as a "
            "possible polyglot."
        ),
    },
    {
        "name": "ExecutableContent",
        "condition": 'format.category == "executable"',
        "action": "STOP_ANALYSIS_ESCALATE_TO_FORENSICS",
        "severity": "CRITICAL",
        "description": (
            "The submitted file is an executable program. Do not open it on "
            "an analysis workstation; escalate to a forensics laboratory."
        ),
    },
    {
        "name": "HighElaResponse",
        "condition": "ela.hot_block_ratio > 0.12",
        "action": "REVIEW_ELASTIC_REGIONS",
        "severity": "MEDIUM",
        "description": (
            "A significant proportion of the frame shows an abnormal "
            "compression error. Inspect the ELA heat map for locally edited "
            "regions."
        ),
    },
    {
        "name": "UniformRecompression",
        "condition": "ela.error_uniformity > 0.85",
        "action": "NOTE_WHOLE_FRAME_RECOMPRESSED",
        "severity": "LOW",
        "description": (
            "Compression error is uniform across the frame, which indicates "
            "the whole image was re-saved rather than locally edited."
        ),
    },
    {
        "name": "CopyMoveDetected",
        "condition": "copy_move.detected == true AND copy_move.regions_count > 0",
        "action": "EXAMINE_DUPLICATED_REGIONS",
        "severity": "HIGH",
        "description": (
            "Blocks of the image appear duplicated elsewhere in the same "
            "frame. This is the signature of copy-move cloning used to "
            "conceal an object."
        ),
    },
    {
        "name": "DoubleCompression",
        "condition": "jpeg.double_compression_suspected == true",
        "action": "NOTE_RECOMPRESSION_HISTORY",
        "severity": "LOW",
        "description": (
            "The JPEG quantization tables indicate the file was re-compressed "
            "after its first save. Expect a small quality loss."
        ),
    },
    {
        "name": "UpscalingDetected",
        "condition": "resampling.upscaling_suspected == true",
        "action": "CAUTION_ON_FINE_DETAIL",
        "severity": "MEDIUM",
        "description": (
            "The frame shows the spectral signature of an enlarged image. "
            "Fine detail and small objects cannot be measured reliably, so "
            "do not rely on this copy for identification."
        ),
    },
    {
        "name": "SteganographySuspected",
        "condition": "steganography.suspicious == true",
        "action": "EXAMINE_LSB_PLANE_AND_CONTAINER",
        "severity": "HIGH",
        "description": (
            "The least-significant-bit plane carries the statistical "
            "signature of embedded data. Treat as a possible covert channel "
            "and refer to a forensics laboratory."
        ),
    },
    {
        "name": "AppendedPayload",
        "condition": "steganography.appended_payload == true",
        "action": "EXTRACT_AND_SEPARATELY_ANALYSE_TRAILER",
        "severity": "HIGH",
        "description": (
            "Data is appended after the end of the image stream. The trailer "
            "must be extracted and examined as an independent artefact."
        ),
    },
    {
        "name": "NoiseDiscontinuity",
        "condition": "noise.discontinuity_count > 8",
        "action": "REVIEW_CANDIDATE_SPLICE_LINES",
        "severity": "MEDIUM",
        "description": (
            "Noise levels change abruptly across several block boundaries, "
            "which is consistent with content from two different sources "
            "being joined."
        ),
    },
    {
        "name": "ContentClassifiedUnconfident",
        "condition": "classification.top_confidence < 25.0",
        "action": "MANUAL_CONTENT_REVIEW",
        "severity": "INFO",
        "description": (
            "The content classifier could not identify the scene with "
            "confidence. A human review of the subject matter is required."
        ),
    },
    {
        "name": "DuplicateOfExistingEvidence",
        "condition": "register.duplicate_matches > 0",
        "action": "LINK_TO_EXISTING_EVIDENCE_ITEM",
        "severity": "INFO",
        "description": (
            "An identical file already exists in the register. The items must "
            "be linked rather than logged as separate evidence."
        ),
    },
    {
        "name": "ElevatedOverallRisk",
        "condition": "risk.score >= 60",
        "action": "ESCALATE_FOR_SECOND_EXPERT_REVIEW",
        "severity": "HIGH",
        "description": (
            "The combined authenticity risk score is elevated. The image "
            "should be referred for a second expert opinion before it is "
            "relied upon in any proceeding."
        ),
    },
]
