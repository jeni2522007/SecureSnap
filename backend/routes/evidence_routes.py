"""Evidence register endpoints."""

import json
import os

from flask import Blueprint, current_app, jsonify, request

from db import get_db, log_audit, transaction, utc_now
from modules.hashing import calculate_sha256, calculate_sha512, ensure_key

evidence_bp = Blueprint("evidence", __name__)


@evidence_bp.route("/api/evidence")
def list_evidence():
    """Return the evidence register, optionally filtered."""
    connection = get_db()

    query = "SELECT * FROM evidence WHERE 1 = 1"
    parameters = []

    case_ref = request.args.get("case_ref", "").strip()
    if case_ref:
        query += " AND case_ref = ?"
        parameters.append(case_ref)

    search = request.args.get("q", "").strip()
    if search:
        query += (
            " AND (title LIKE ? OR description LIKE ? OR original_filename LIKE ?"
            " OR sha256 LIKE ?)"
        )
        like = f"%{search}%"
        parameters.extend([like, like, like, like])

    verdict = request.args.get("verdict", "").strip()
    if verdict:
        query += " AND verdict LIKE ?"
        parameters.append(f"%{verdict}%")

    query += " ORDER BY datetime(created_at) DESC"

    rows = connection.execute(query, parameters).fetchall()

    return jsonify({
        "status": "success",
        "count": len(rows),
        "items": [_evidence_row(row) for row in rows],
    })


@evidence_bp.route("/api/evidence/<int:evidence_id>")
def get_evidence(evidence_id):
    """Return a single evidence item with its full analysis."""
    connection = get_db()
    row = connection.execute(
        "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "Evidence item not found"}), 404

    item = _evidence_row(row)

    analysis = None
    if row["analysis_json"]:
        try:
            analysis = json.loads(row["analysis_json"])
        except json.JSONDecodeError:
            analysis = None
    item["analysis"] = analysis

    runs = connection.execute(
        "SELECT * FROM analysis_runs WHERE evidence_id = ? ORDER BY id",
        (evidence_id,),
    ).fetchall()
    item["analysis_runs"] = [dict(run) for run in runs]

    return jsonify({"status": "success", "evidence": item})


@evidence_bp.route("/api/evidence/<int:evidence_id>", methods=["PATCH"])
def update_evidence(evidence_id):
    """Update the descriptive fields of an evidence item."""
    connection = get_db()
    row = connection.execute(
        "SELECT id FROM evidence WHERE id = ?", (evidence_id,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "Evidence item not found"}), 404

    payload = request.get_json(silent=True) or {}

    editable = {
        "case_ref", "exhibit_ref", "title", "description",
        "source", "collected_by", "collected_at",
    }

    updates = {
        key: payload[key] for key in editable if key in payload
    }
    if not updates:
        return jsonify({"error": "No updatable fields were supplied"}), 400

    assignments = ", ".join(f"{key} = ?" for key in updates)
    values = list(updates.values()) + [utc_now(), evidence_id]

    with transaction() as tx:
        tx.execute(
            f"UPDATE evidence SET {assignments}, updated_at = ? WHERE id = ?",
            values,
        )

    log_audit(
        "evidence_updated",
        entity="evidence",
        entity_id=evidence_id,
        detail=", ".join(f"{key} updated" for key in updates),
    )

    return jsonify({"status": "success", "updated": list(updates.keys())})


@evidence_bp.route("/api/evidence/<int:evidence_id>", methods=["DELETE"])
def delete_evidence(evidence_id):
    """Remove an evidence item from the register.

    The stored file is deliberately left on disk so that the deletion is
    recoverable and the audit trail remains meaningful.
    """
    connection = get_db()
    row = connection.execute(
        "SELECT id, title FROM evidence WHERE id = ?", (evidence_id,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "Evidence item not found"}), 404

    with transaction() as tx:
        tx.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))

    log_audit(
        "evidence_deleted",
        entity="evidence",
        entity_id=evidence_id,
        detail=f"Register entry '{row['title']}' deleted.",
    )

    return jsonify({
        "status": "success",
        "message": (
            "The register entry was removed. The stored file and its sealed "
            "copy were left on disk."
        ),
    })


@evidence_bp.route("/api/evidence/<int:evidence_id>/verify", methods=["POST"])
def verify_evidence(evidence_id):
    """Re-verify the integrity of a stored evidence item.

    The working copy is hashed again, the sealed copy is decrypted and
    authenticated, and both are compared against the hashes recorded at
    intake. This is the check that proves the file has not changed.
    """
    connection = get_db()
    row = connection.execute(
        "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "Evidence item not found"}), 404

    stored_path = os.path.join(
        current_app.config["UPLOAD_FOLDER"], row["stored_filename"]
    )

    if not os.path.exists(stored_path):
        return jsonify({
            "error": "The stored working copy is no longer present on disk.",
            "intact": False,
        }), 404

    checks = []
    intact = True

    current_sha256 = calculate_sha256(stored_path)
    current_sha512 = calculate_sha512(stored_path)

    sha256_ok = current_sha256 == row["sha256"]
    checks.append({
        "check": "SHA-256 of the working copy",
        "expected": row["sha256"],
        "actual": current_sha256,
        "passed": sha256_ok,
    })
    intact = intact and sha256_ok

    sha512_ok = current_sha512 == row["sha512"]
    checks.append({
        "check": "SHA-512 of the working copy",
        "expected": row["sha512"],
        "actual": current_sha512,
        "passed": sha512_ok,
    })
    intact = intact and sha512_ok

    # Authenticate the sealed copy.
    sealed_path = os.path.join(
        current_app.config["SEALED_FOLDER"], row["stored_filename"] + ".sealed"
    )

    sealed_result = {"available": False}
    if os.path.exists(sealed_path):
        try:
            key = ensure_key(current_app.config["KEY_FILE"])
            from modules.encryption import verify_sealed
            sealed_result = verify_sealed(sealed_path, key, row["sha256"])
            sealed_result["available"] = True
            sealed_ok = sealed_result["authenticated"] and \
                sealed_result["matches_original"]
            checks.append({
                "check": "Sealed copy decrypts and matches the intake hash",
                "expected": row["sha256"],
                "actual": sealed_result.get("sha256"),
                "passed": bool(sealed_ok),
            })
            intact = intact and bool(sealed_ok)
        except Exception as error:
            checks.append({
                "check": "Sealed copy decrypts and matches the intake hash",
                "expected": row["sha256"],
                "actual": str(error),
                "passed": False,
            })
            intact = False
    else:
        checks.append({
            "check": "Sealed copy present",
            "expected": "sealed copy on disk",
            "actual": "not found",
            "passed": False,
        })
        intact = False

    log_audit(
        "evidence_verified",
        entity="evidence",
        entity_id=evidence_id,
        detail=(
            "Integrity re-check passed - the file is unchanged."
            if intact else
            "Integrity re-check FAILED - the file no longer matches intake."
        ),
    )

    return jsonify({
        "status": "success",
        "intact": intact,
        "verdict": (
            "UNALTERED - the file matches the fingerprints recorded at intake."
            if intact else
            "INTEGRITY FAILURE - the file no longer matches the fingerprints "
            "recorded at intake. Do not rely on it."
        ),
        "checks": checks,
        "verified_at": utc_now(),
    })


@evidence_bp.route("/api/evidence/duplicates")
def list_duplicates():
    """List files that appear more than once in the register."""
    connection = get_db()

    rows = connection.execute(
        """
        SELECT sha256, COUNT(*) AS copies,
               GROUP_CONCAT(id) AS ids,
               GROUP_CONCAT(case_ref) AS cases,
               MIN(original_filename) AS filename
        FROM evidence
        GROUP BY sha256
        HAVING copies > 1
        ORDER BY copies DESC
        """
    ).fetchall()

    groups = []
    for row in rows:
        groups.append({
            "sha256": row["sha256"],
            "copies": row["copies"],
            "evidence_ids": [int(value) for value in row["ids"].split(",")],
            "case_refs": row["cases"].split(","),
            "filename": row["filename"],
        })

    return jsonify({
        "status": "success",
        "count": len(groups),
        "groups": groups,
    })


@evidence_bp.route("/api/evidence/stats")
def evidence_stats():
    """Return headline figures for the dashboard."""
    connection = get_db()

    total = connection.execute(
        "SELECT COUNT(*) AS count FROM evidence"
    ).fetchone()["count"]

    cases = connection.execute(
        "SELECT COUNT(DISTINCT case_ref) AS count FROM evidence"
    ).fetchone()["count"]

    flagged = connection.execute(
        "SELECT COUNT(*) AS count FROM evidence WHERE risk_score >= 35"
    ).fetchone()["count"]

    average = connection.execute(
        "SELECT AVG(risk_score) AS average FROM evidence"
    ).fetchone()["average"]

    recent = connection.execute(
        """
        SELECT id, case_ref, title, verdict, risk_score, created_at
        FROM evidence ORDER BY datetime(created_at) DESC LIMIT 8
        """
    ).fetchall()

    return jsonify({
        "status": "success",
        "stats": {
            "total_evidence": total,
            "cases": cases,
            "flagged": flagged,
            "average_risk": round(average, 1) if average else 0.0,
        },
        "recent": [dict(row) for row in recent],
    })


def _evidence_row(row):
    """Convert a database row into the shape returned by the API."""
    return {
        "id": row["id"],
        "case_ref": row["case_ref"],
        "exhibit_ref": row["exhibit_ref"],
        "title": row["title"],
        "description": row["description"],
        "source": row["source"],
        "collected_by": row["collected_by"],
        "collected_at": row["collected_at"],
        "original_filename": row["original_filename"],
        "stored_filename": row["stored_filename"],
        "sha256": row["sha256"],
        "sha512": row["sha512"],
        "size_bytes": row["size_bytes"],
        "detected_format": row["detected_format"],
        "risk_score": row["risk_score"],
        "verdict": row["verdict"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
