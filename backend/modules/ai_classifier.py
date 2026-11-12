"""Content classification for evidence triage.

A pretrained MobileNetV2 model is used to describe what is in the frame. The
classifier never decides whether an image is authentic - it only supplies
content tags, and it cross-checks those tags against the recorded metadata to
surface contradictions (for example, a frame classified as a screen capture
but stamped with a DSLR's camera fields).

The model is loaded lazily and the whole module degrades gracefully when
torch or torchvision are unavailable, so the rest of the forensic pipeline
still runs on a minimal installation.
"""

import threading

_MODEL = None
_CATEGORIES = None
_LOCK = threading.Lock()
_LOAD_ERROR = None

# ImageNet classes that indicate the frame is a picture *of* a screen or a
# device rather than a camera photograph.
SCREEN_RELATED = {
    "monitor", "desktop computer", "screen", "laptop", "notebook computer",
    "cellular telephone", "hand-held computer", "television", "web site",
    "menu", "envelope", "book jacket", "packet", "packet", "envelope",
}

# Classes that normally appear in a genuine camera photograph.
SCENE_CLASSES = {
    "street", "sidewalk", "building", "house", "door", "window", "parking lot",
    "motorcycle", "car", "minivan", "bus", "truck", "traffic light", "stop sign",
    "fire hydrant", "park", "fence", "balcony", "bridge", "runway", "beam",
    "cliff", "coast", "sandbar", "seashore", "valley", "mountain", "sky",
}


def _ensure_model():
    """Load the classifier once, recording any failure for later checks."""
    global _MODEL, _CATEGORIES, _LOAD_ERROR

    if _MODEL is not None or _LOAD_ERROR is not None:
        return _MODEL is not None

    with _LOCK:
        if _MODEL is not None or _LOAD_ERROR is not None:
            return _MODEL is not None

        try:
            import torch
            from torchvision.models import mobilenet_v2, MobileNet_V2_Weights

            weights = MobileNet_V2_Weights.DEFAULT
            model = mobilenet_v2(weights=weights)
            model.eval()
            _MODEL = model
            _CATEGORIES = weights.meta["categories"]
            torch.set_num_threads(max(1, (torch.get_num_threads() or 1)))
        except Exception as error:  # pragma: no cover - environment dependent
            _LOAD_ERROR = str(error)

    return _MODEL is not None


def classifier_available():
    """Return True when the model could be loaded."""
    return _ensure_model()


def classifier_error():
    """Return the reason the classifier is unavailable, if any."""
    _ensure_model()
    return _LOAD_ERROR


def classify_image(image_path, top_k=5):
    """Classify the content of an image.

    Returns a dictionary with the predictions, the content tags used for
    triage and any consistency warnings raised against the metadata.
    """
    if not _ensure_model():
        return {
            "available": False,
            "reason": _LOAD_ERROR or "The classification model is unavailable",
            "predictions": [],
            "tags": [],
            "top_confidence": 0.0,
            "consistency_warnings": [],
        }

    import torch
    from PIL import Image

    try:
        image = Image.open(image_path).convert("RGB")
    except Exception as error:
        return {
            "available": False,
            "reason": f"Image could not be opened: {error}",
            "predictions": [],
            "tags": [],
            "top_confidence": 0.0,
            "consistency_warnings": [],
        }

    weights_transform = None
    try:
        from torchvision.models import MobileNet_V2_Weights
        weights_transform = MobileNet_V2_Weights.DEFAULT.transforms()
    except Exception:
        pass

    if weights_transform is not None:
        tensor = weights_transform(image).unsqueeze(0)
    else:
        tensor = torch.from_numpy(
            __import__("numpy").array(image.resize((224, 224)))
        ).permute(2, 0, 1).float().div(255).unsqueeze(0)

    with torch.inference_mode():
        output = _MODEL(tensor)

    probabilities = torch.nn.functional.softmax(output[0], dim=0)
    top = torch.topk(probabilities, min(top_k, len(_CATEGORIES)))

    predictions = []
    for score, index in zip(top.values, top.indices):
        predictions.append({
            "label": _CATEGORIES[index.item()],
            "confidence": round(score.item() * 100, 2),
        })

    tags = [p["label"] for p in predictions if p["confidence"] >= 10.0]

    return {
        "available": True,
        "reason": None,
        "predictions": predictions,
        "tags": tags,
        "top_confidence": predictions[0]["confidence"] if predictions else 0.0,
        "scene_likelihood": round(_scene_score(predictions), 2),
        "consistency_warnings": [],
    }


def _scene_score(predictions):
    """Estimate how much the frame looks like a real-world photograph."""
    score = 0.0
    for prediction in predictions:
        if prediction["label"] in SCENE_CLASSES:
            score += prediction["confidence"]
        if prediction["label"] in SCREEN_RELATED:
            score -= prediction["confidence"]
    return max(0.0, score)


def check_metadata_consistency(classification, metadata):
    """Cross-check the classified content against the recorded metadata.

    Returns a list of warnings describing contradictions between what the
    picture shows and what the metadata claims about it.
    """
    warnings = []

    if not classification.get("available") or not metadata:
        return warnings

    predictions = classification.get("predictions", [])
    top_label = predictions[0]["label"].lower() if predictions else ""
    top_confidence = predictions[0]["confidence"] if predictions else 0.0

    camera = metadata.get("camera", {}) or {}
    # A frame whose dominant content is a screen is rarely a direct camera
    # photograph, even if it carries camera metadata.
    if top_label in SCREEN_RELATED and top_confidence > 45:
        if camera.get("make"):
            warnings.append({
                "severity": "MEDIUM",
                "code": "CONTENT_METADATA_CONFLICT",
                "title": "Picture content contradicts the recorded camera",
                "explanation": (
                    f"The frame is dominated by a '{predictions[0]['label']}' "
                    f"({top_confidence}% confidence) yet the metadata records "
                    f"a {camera.get('make')} camera. A screenshot or a "
                    "photograph of a display may have been given camera "
                    "fields."
                ),
            })
        else:
            warnings.append({
                "severity": "LOW",
                "code": "SCREEN_CAPTURE_LIKELY",
                "title": "Content appears to be a screen capture",
                "explanation": (
                    f"The classifier identifies a '{predictions[0]['label']}' "
                    f"({top_confidence}% confidence). Screen captures never "
                    "carry original camera metadata or original pixel noise."
                ),
            })

    # An image whose top class is a studio object but which has no
    # photographic scene content is worth a note for the examiner.
    if classification.get("scene_likelihood", 0) < 5 and top_confidence > 55:
        warnings.append({
            "severity": "INFO",
            "code": "LOW_SCENE_CONFIDENCE",
            "title": "Scene content is weakly photographic",
            "explanation": (
                "The frame does not resemble an ordinary camera scene. It may "
                "be a rendering, a synthetic image, or a tightly cropped "
                "object. Confirm manually before relying on environmental "
                "detail."
            ),
        })

    return warnings
