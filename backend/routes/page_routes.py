"""Page routes for the SecureSnap interface."""

from flask import Blueprint, render_template

page_bp = Blueprint("pages", __name__)


@page_bp.route("/")
def dashboard():
    """Landing page and workbench overview."""
    return render_template("dashboard.html")


@page_bp.route("/analyze")
def analyze():
    """Single-file analysis workbench."""
    return render_template("analyze.html")


@page_bp.route("/compare")
def compare():
    """Two-image comparative analysis."""
    return render_template("compare.html")


@page_bp.route("/evidence")
def evidence():
    """Evidence register."""
    return render_template("evidence.html")


@page_bp.route("/evidence/<int:evidence_id>")
def evidence_detail(evidence_id):
    """Detail view for a single evidence item."""
    return render_template("evidence_detail.html", evidence_id=evidence_id)


@page_bp.route("/rules")
def rules():
    """Policy rule set editor."""
    return render_template("rules.html")
