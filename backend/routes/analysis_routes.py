"""Analysis endpoints: single-file forensic analysis and image comparison."""

import os
import shutil
import tempfile
import uuid

from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from db import get_db, log_audit, transaction, utc_now
from modules import analyzer, compare as compare_module
from modules.hashing import ensure_key, fingerprint
from modules.rule_service import load_rules, run_rules, summarise

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.route("/analysis/<path:filename>")
def analysis_artefact(filename):
    """Serve a generated diagnostic image (ELA heat map, LSB plane, …)."""
    from flask import send_from_directory
    return send_from_directory(current_app.config["ANALYSIS_FOLDER"], filename)


def _safe_name(filename, fallback="upload"):
    """Reduce a client-supplied filename to a safe name on disk.

    The name supplied in the multipart header is entirely under the control
    of the client and may contain path separators or traversal sequences, so
    it is never used to build a path directly.
    """
    cleaned = secure_filename(filename or "")
    if not cleaned:
        cleaned = fallback
    return cleaned[:120]


@analysis_bp.route("/api/analyze", methods=["POST"])
def analyze():
    """Analyse a submitted file and optionally register it as evidence."""
    if "image" not in request.files:
        return jsonify({"error": "No file was submitted"}), 400

    uploaded = request.files["image"]
    if uploaded.filename == "":
        return jsonify({"error": "No file was selected"}), 400

    # The filename in the multipart header is chosen by the client, so it is
    # never used to build a path. Only its extension is inspected.
    safe_name = _safe_name(uploaded.filename)

    extension = os.path.splitext(safe_name)[1].lower()
    if extension and extension.lstrip(".") not in current_app.config["ALLOWED_EXTENSIONS"]:
        return jsonify({
            "error": (
                f"Files of type '{extension}' are not accepted. Supported "
                f"types: {', '.join(sorted(current_app.config['ALLOWED_EXTENSIONS']))}."
            )
        }), 400

    work_dir = tempfile.mkdtemp(prefix="securesnap_")

    try:
        work_path = os.path.join(work_dir, safe_name)
        uploaded.save(work_path)

        analysis_folder = current_app.config["ANALYSIS_FOLDER"]
        results = analyzer.analyse_file(
            work_path,
            analysis_folder,
            original_filename=uploaded.filename,
        )

        # Run the policy rule set against the produced facts.
        connection = get_db()
        rules = load_rules(connection)
        rule_outcome = run_rules(rules, results["facts"])
        results["rules"] = rule_outcome
        results["rule_summary"] = summarise(rule_outcome["triggered"])

        # Register the duplicate-evidence fact so the register rules fire.
        results["facts"]["register"] = {
            "duplicate_matches": 0,
        }

        # The absolute location of the generated artefacts is an internal
        # detail and is not sent to the browser.
        results.pop("artefact_path", None)

        file_fingerprints = fingerprint(work_path)

        response = {
            "status": "success",
            "filename": uploaded.filename,
            "analysis": results,
            "fingerprints": file_fingerprints,
            "rules": rule_outcome,
        }

        if request.form.get("save") == "true":
            response["evidence"] = _register_evidence(
                safe_name, work_path, results, file_fingerprints
            )

        return jsonify(response), 200

    except Exception:
        current_app.logger.exception("Analysis failed")
        # The detail stays in the server log; the client is told only that
        # the examination could not be completed.
        return jsonify({
            "error": (
                "The examination could not be completed. Check the server log "
                "for the reason."
            ),
        }), 500

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _register_evidence(original_filename, work_path, results, file_fingerprints):
    """Store the evidence file, seal it and write the register entry."""
    evidence_folder = current_app.config["EVIDENCE_FOLDER"]
    sealed_folder = current_app.config["SEALED_FOLDER"]
    key = ensure_key(current_app.config["KEY_FILE"])

    unique_name = f"{uuid.uuid4().hex}_{_safe_name(original_filename, 'evidence')}"
    stored_path = os.path.join(evidence_folder, unique_name)
    shutil.copy2(work_path, stored_path)

    from modules.encryption import seal_file
    seal_file(stored_path, sealed_folder, key)

    summary = results["summary"]
    now = utc_now()

    connection = get_db()

    with transaction() as tx:
        cursor = tx.execute(
            """
            INSERT INTO evidence
                (case_ref, exhibit_ref, title, description, source,
                 collected_by, collected_at, original_filename, stored_filename,
                 sha256, sha512, size_bytes, detected_format, risk_score,
                 verdict, analysis_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.form.get("case_ref", "UNASSIGNED").strip() or "UNASSIGNED",
                request.form.get("exhibit_ref", "").strip() or None,
                request.form.get("title", "").strip()
                or os.path.basename(original_filename),
                request.form.get("description", "").strip() or None,
                request.form.get("source", "").strip() or None,
                request.form.get("collected_by", "").strip() or None,
                request.form.get("collected_at", "").strip() or now,
                os.path.basename(original_filename),
                unique_name,
                file_fingerprints["sha256"],
                file_fingerprints["sha512"],
                file_fingerprints["size_bytes"],
                results["format"].get("format"),
                summary["score"],
                summary["verdict"],
                _analysis_payload(results),
                now,
                now,
            ),
        )
        evidence_id = cursor.lastrowid

        tx.execute(
            """
            INSERT INTO analysis_runs
                (evidence_id, engine_version, risk_score, verdict,
                 summary_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                results.get("engine_version", "2.0.0"),
                summary["score"],
                summary["verdict"],
                _summary_payload(results),
                now,
            ),
        )

    # Detect identical files already in the register.
    duplicates = connection.execute(
        "SELECT id, case_ref, title FROM evidence "
        "WHERE sha256 = ? AND id != ?",
        (file_fingerprints["sha256"], evidence_id),
    ).fetchall()

    log_audit(
        "evidence_registered",
        entity="evidence",
        entity_id=evidence_id,
        detail=(
            f"Registered '{os.path.basename(original_filename)}' under case "
            f"{request.form.get('case_ref', 'UNASSIGNED')} with risk score "
            f"{summary['score']}."
        ),
    )

    return {
        "id": evidence_id,
        "stored_filename": unique_name,
        "sha256": file_fingerprints["sha256"],
        "duplicate_count": len(duplicates),
        "duplicates": [dict(row) for row in duplicates],
    }


def _analysis_payload(results):
    """Store the analysis with the volatile artefact paths removed."""
    import json

    stored = dict(results)
    folder = stored.pop("artefact_folder", None)
    stored.pop("artefact_path", None)
    if folder:
        stored["artefact_folder"] = os.path.basename(folder)

    # The generated heat maps are referenced by the report, so keep the file
    # names but drop the absolute location.
    stored["artefacts"] = {
        "ela": results.get("ela", {}).get("heatmap"),
        "copy_move": results.get("copy_move", {}).get("match_map"),
        "lsb_plane": results.get("steganography", {}).get("lsb_plane"),
    }

    return json.dumps(stored, default=str)


def _summary_payload(results):
    import json
    return json.dumps(results.get("summary", {}), default=str)


@analysis_bp.route("/api/compare", methods=["POST"])
def compare():
    """Compare two images for structural similarity and divergence."""
    if "first" not in request.files or "second" not in request.files:
        return jsonify({"error": "Two files are required for a comparison"}), 400

    first_file = request.files["first"]
    second_file = request.files["second"]

    if not first_file.filename or not second_file.filename:
        return jsonify({"error": "Two files are required for a comparison"}), 400

    work_dir = tempfile.mkdtemp(prefix="securesnap_cmp_")

    try:
        first_path = os.path.join(work_dir, "first_" + _safe_name(first_file.filename, "a.jpg"))
        second_path = os.path.join(work_dir, "second_" + _safe_name(second_file.filename, "b.jpg"))

        first_file.save(first_path)
        second_file.save(second_path)

        output_folder = os.path.join(current_app.config["ANALYSIS_FOLDER"], "compare")
        outcome = compare_module.compare_images(first_path, second_path, output_folder)

        log_audit(
            "comparison_performed",
            entity="comparison",
            detail=(
                f"Compared '{first_file.filename}' with "
                f"'{second_file.filename}'. SSIM {outcome.get('ssim')}."
            ),
        )

        return jsonify({"status": "success", "comparison": outcome}), 200

    except Exception:
        current_app.logger.exception("Comparison failed")
        return jsonify({
            "error": (
                "The comparison could not be completed. Check the server log "
                "for the reason."
            ),
        }), 500

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
