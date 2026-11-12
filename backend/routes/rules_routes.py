"""Rule set management endpoints."""

from flask import Blueprint, jsonify, request

from db import get_db, log_audit, transaction, utc_now
from modules.rule_engine.evaluator import validate_rule
from modules.rule_service import load_rules, run_rules

rules_bp = Blueprint("rules", __name__)


@rules_bp.route("/api/rules")
def list_rules():
    """Return the full rule set."""
    connection = get_db()
    rows = connection.execute(
        "SELECT * FROM rules ORDER BY builtin DESC, "
        "CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
        "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC, name"
    ).fetchall()

    return jsonify({
        "status": "success",
        "count": len(rows),
        "rules": [dict(row) for row in rows],
    })


@rules_bp.route("/api/rules", methods=["POST"])
def create_rule():
    """Add a new rule to the set."""
    payload = request.get_json(silent=True) or {}

    name = (payload.get("name") or "").strip()
    condition = (payload.get("condition") or "").strip()
    action = (payload.get("action") or "").strip()
    severity = (payload.get("severity") or "MEDIUM").strip().upper()
    description = (payload.get("description") or "").strip()

    if not name or not condition or not action:
        return jsonify({
            "error": "A rule needs a name, a condition and an action.",
        }), 400

    validation = validate_rule(condition)
    if not validation["valid"]:
        return jsonify({
            "error": f"The condition could not be parsed: {validation['error']}",
        }), 400

    if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"):
        return jsonify({"error": f"Unknown severity '{severity}'"}), 400

    now = utc_now()
    connection = get_db()

    with transaction() as tx:
        cursor = tx.execute(
            """
            INSERT INTO rules
                (name, condition, action, severity, description, enabled,
                 builtin, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
            """,
            (name, condition, action, severity, description,
             1 if payload.get("enabled", True) else 0, now, now),
        )
        rule_id = cursor.lastrowid

    log_audit(
        "rule_created", entity="rule", entity_id=rule_id,
        detail=f"Rule '{name}' added to the policy set.",
    )

    row = connection.execute(
        "SELECT * FROM rules WHERE id = ?", (rule_id,)
    ).fetchone()

    return jsonify({"status": "success", "rule": dict(row)}), 201


@rules_bp.route("/api/rules/<int:rule_id>", methods=["PUT"])
def update_rule(rule_id):
    """Edit an existing rule."""
    connection = get_db()
    row = connection.execute(
        "SELECT * FROM rules WHERE id = ?", (rule_id,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "Rule not found"}), 404

    payload = request.get_json(silent=True) or {}

    name = (payload.get("name") or row["name"]).strip()
    condition = (payload.get("condition") or row["condition"]).strip()
    action = (payload.get("action") or row["action"]).strip()
    severity = (payload.get("severity") or row["severity"]).strip().upper()
    description = payload.get("description", row["description"]) or ""
    enabled = payload.get("enabled", bool(row["enabled"]))

    validation = validate_rule(condition)
    if not validation["valid"]:
        return jsonify({
            "error": f"The condition could not be parsed: {validation['error']}",
        }), 400

    with transaction() as tx:
        tx.execute(
            """
            UPDATE rules
            SET name = ?, condition = ?, action = ?, severity = ?,
                description = ?, enabled = ?, updated_at = ?
            WHERE id = ?
            """,
            (name, condition, action, severity, description,
             1 if enabled else 0, utc_now(), rule_id),
        )

    log_audit(
        "rule_updated", entity="rule", entity_id=rule_id,
        detail=f"Rule '{name}' updated.",
    )

    updated = connection.execute(
        "SELECT * FROM rules WHERE id = ?", (rule_id,)
    ).fetchone()

    return jsonify({"status": "success", "rule": dict(updated)})


@rules_bp.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    """Remove a rule from the set."""
    connection = get_db()
    row = connection.execute(
        "SELECT * FROM rules WHERE id = ?", (rule_id,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "Rule not found"}), 404

    with transaction() as tx:
        tx.execute("DELETE FROM rules WHERE id = ?", (rule_id,))

    log_audit(
        "rule_deleted", entity="rule", entity_id=rule_id,
        detail=f"Rule '{row['name']}' removed from the policy set.",
    )

    return jsonify({"status": "success", "message": f"Rule '{row['name']}' removed."})


@rules_bp.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id):
    """Enable or disable a rule."""
    connection = get_db()
    row = connection.execute(
        "SELECT * FROM rules WHERE id = ?", (rule_id,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "Rule not found"}), 404

    new_state = 0 if row["enabled"] else 1

    with transaction() as tx:
        tx.execute(
            "UPDATE rules SET enabled = ?, updated_at = ? WHERE id = ?",
            (new_state, utc_now(), rule_id),
        )

    log_audit(
        "rule_toggled", entity="rule", entity_id=rule_id,
        detail=(
            f"Rule '{row['name']}' "
            f"{'enabled' if new_state else 'disabled'}."
        ),
    )

    return jsonify({"status": "success", "enabled": bool(new_state)})


@rules_bp.route("/api/rules/validate", methods=["POST"])
def validate():
    """Validate a condition without saving it."""
    payload = request.get_json(silent=True) or {}
    condition = (payload.get("condition") or "").strip()

    if not condition:
        return jsonify({"error": "A condition is required"}), 400

    return jsonify({"status": "success", **validate_rule(condition)})


@rules_bp.route("/api/rules/test", methods=["POST"])
def test_rules():
    """Dry-run the rule set against a supplied set of facts."""
    payload = request.get_json(silent=True) or {}
    facts = payload.get("facts") or {}

    connection = get_db()
    rules = load_rules(connection)

    outcome = run_rules(rules, facts)

    return jsonify({
        "status": "success",
        "evaluated": outcome["evaluated"],
        "triggered": outcome["triggered"],
        "errors": outcome["errors"],
    })
