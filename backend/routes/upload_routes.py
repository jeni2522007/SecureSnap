
import os
import uuid

from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from PIL import Image, UnidentifiedImageError

from modules.hashing import calculate_sha256
from modules.encryption import encrypt_image
from modules.image_processing import process_image
from modules.ai_classifier import classify_image
from modules.rule_compiler import execute_rule


upload_bp = Blueprint("upload", __name__)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}

SECURITY_RULE = "IF image_size > 5000000 THEN FLAG_IMAGE"


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@upload_bp.route("/upload", methods=["POST"])
def upload_image():

    # 1. Check file selection
    if "image" not in request.files:
        return jsonify({"error": "No image selected"}), 400

    file = request.files["image"]

    if file.filename == "":
        return jsonify({"error": "Please select an image"}), 400

    # 2. Validate file extension
    if not allowed_file(file.filename):
        return jsonify({
            "error": "Only JPG, JPEG and PNG files are allowed"
        }), 400

    # 3. Validate actual image content
    try:
        image = Image.open(file)
        image.verify()
        file.seek(0)

    except (UnidentifiedImageError, OSError):
        return jsonify({
            "error": "Invalid or corrupted image"
        }), 400

    # 4. Generate unique filename
    original_name = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{original_name}"

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)

    save_path = os.path.join(upload_folder, unique_name)

    # 5. Save original image
    file.save(save_path)

    try:
        # 6. Get image size
        image_size = os.path.getsize(save_path)

        # 7. Execute Compiler Design security rule
        security_result = execute_rule(
            SECURITY_RULE,
            image_size
        )

        # 8. Calculate SHA-256 fingerprint
        image_hash = calculate_sha256(save_path)

        # 9. Encrypt image
        encrypted_folder = os.path.abspath(
            os.path.join(current_app.root_path, "..", "encrypted")
        )

        encrypted_path, encryption_key = encrypt_image(
            save_path,
            encrypted_folder
        )

        # 10. OpenCV image processing
        processed_folder = os.path.abspath(
            os.path.join(current_app.root_path, "..", "processed")
        )

        processed_files = process_image(
            save_path,
            processed_folder
        )

        # 11. Deep Learning classification
        ai_predictions = classify_image(save_path)

        # 12. Return complete analysis
        return jsonify({
            "status": "success",
            "message": "Image secured and analyzed successfully!",

            "filename": unique_name,

            "image_size_bytes": image_size,

            "security_rule": SECURITY_RULE,

            "compiler_result": security_result,

            "sha256": image_hash,

            "encryption": "AES-based Fernet encryption successful",

            "encrypted_file": os.path.basename(encrypted_path),

            "image_processing": processed_files,

            "ai_predictions": ai_predictions

        }), 200

    except Exception:
        current_app.logger.exception("Image analysis failed")

        return jsonify({
            "error": "Image analysis failed. Check server logs."
        }), 500
