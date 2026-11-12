"""Report rendering and export endpoints."""

import csv
import io
import json

from flask import Blueprint, Response, jsonify, render_template

from db import get_db, log_audit, utc_now

report_bp = Blueprint("reports", __name__)


@report_bp.route("/report/<int:evidence_id>")
def render_report(evidence_id):
    """Render the printable court report for an evidence item."""
    connection = get_db()
    row = connection.execute(
        "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
    ).fetchone()

    if row is None:
        return render_template("report.html", evidence_id=evidence_id,
                               evidence=None, analysis=None), 404

    analysis = None
    if row["analysis_json"]:
        try:
            analysis = json.loads(row["analysis_json"])
        except json.JSONDecodeError:
            analysis = None

    runs = connection.execute(
        "SELECT * FROM analysis_runs WHERE evidence_id = ? ORDER BY id",
        (evidence_id,)
    ).fetchall()

    return render_template(
        "report.html",
        evidence_id=evidence_id,
        evidence=dict(row),
        analysis=analysis,
        runs=[dict(run) for run in runs],
        generated_at=utc_now(),
    )


@report_bp.route("/api/report/<int:evidence_id>/json")
def export_json(evidence_id):
    """Export the full analysis of an evidence item as JSON."""
    connection = get_db()
    row = connection.execute(
        "SELECT * FROM evidence WHERE id = ?", (evidence_id,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "Evidence item not found"}), 404

    analysis = None
    if row["analysis_json"]:
        try:
            analysis = json.loads(row["analysis_json"])
        except json.JSONDecodeError:
            analysis = None

    payload = {
        "report": {
            "title": "SecureSnap Media Authenticity Report",
            "generated_at": utc_now(),
            "engine_version": "2.0.0",
        },
        "evidence": {
            "id": row["id"],
            "case_ref": row["case_ref"],
            "exhibit_ref": row["exhibit_ref"],
            "title": row["title"],
            "description": row["description"],
            "source": row["source"],
            "collected_by": row["collected_by"],
            "collected_at": row["collected_at"],
            "original_filename": row["original_filename"],
            "sha256": row["sha256"],
            "sha512": row["sha512"],
            "size_bytes": row["size_bytes"],
            "detected_format": row["detected_format"],
            "risk_score": row["risk_score"],
            "verdict": row["verdict"],
            "created_at": row["created_at"],
        },
        "analysis": analysis,
    }

    log_audit(
        "report_exported", entity="evidence", entity_id=evidence_id,
        detail="JSON report exported.",
    )

    return Response(
        json.dumps(payload, indent=2, default=str),
        mimetype="application/json",
        headers={
            "Content-Disposition":
                f"attachment; filename=securesnap_report_{evidence_id}.json"
        },
    )


@report_bp.route("/api/export/evidence.csv")
def export_csv():
    """Export the whole evidence register as a CSV file."""
    connection = get_db()
    rows = connection.execute(
        "SELECT * FROM evidence ORDER BY datetime(created_at) DESC"
    ).fetchall()

    buffer = io.StringIO()
    writer = csv.writer(buffer)

    writer.writerow([
        "ID", "Case reference", "Exhibit", "Title", "Description", "Source",
        "Collected by", "Collected at", "Original filename", "Detected format",
        "Size (bytes)", "SHA-256", "SHA-512", "Risk score", "Verdict",
        "Registered at",
    ])

    for row in rows:
        writer.writerow([
            row["id"], row["case_ref"], row["exhibit_ref"] or "",
            row["title"], row["description"] or "", row["source"] or "",
            row["collected_by"] or "", row["collected_at"] or "",
            row["original_filename"], row["detected_format"] or "",
            row["size_bytes"], row["sha256"], row["sha512"] or "",
            row["risk_score"], row["verdict"] or "", row["created_at"],
        ])

    log_audit(
        "register_exported", entity="register",
        detail=f"Evidence register exported ({len(rows)} items).",
    )

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=securesnap_evidence_register.csv"
        },
    )


@report_bp.route("/api/audit")
def audit_trail():
    """Return the append-only audit trail."""
    connection = get_db()

    limit = min(int(request_limit()), 500)
    rows = connection.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()

    return jsonify({
        "status": "success",
        "count": len(rows),
        "entries": [dict(row) for row in rows],
    })


def request_limit():
    """Read the optional limit argument."""
    from flask import request
    try:
        return int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        return 100
