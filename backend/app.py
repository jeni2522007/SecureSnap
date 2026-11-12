"""SecureSnap - Media Authenticity & Forensic Analysis Workbench.

A single-application forensic workbench for examining images and video stills
that are placed in evidence. Every submission is fingerprinted, its embedded
metadata is read and cross-checked, and a set of independent manipulation
tests is run against it. The results are scored, checked against a policy
rule set and written to a court-ready report.

The application runs entirely on the local machine. Evidence never leaves
the workstation.
"""

import os
import sys

from flask import Flask, jsonify

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from config import Config  # noqa: E402
from db import init_db  # noqa: E402


def create_app(config_object=Config):
    """Build and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=os.path.join(BACKEND_DIR, "..", "frontend", "templates"),
        static_folder=os.path.join(BACKEND_DIR, "..", "frontend", "static"),
    )

    app.config.from_object(config_object)
    app.config["UPLOAD_FOLDER"] = str(config_object.EVIDENCE_FOLDER)
    app.config["SEALED_FOLDER"] = str(config_object.SEALED_FOLDER)
    app.config["ANALYSIS_FOLDER"] = str(config_object.ANALYSIS_FOLDER)
    app.config["DATABASE_PATH"] = str(config_object.DATABASE_PATH)

    config_object.ensure_directories()
    init_db(app)

    from routes.analysis_routes import analysis_bp
    from routes.evidence_routes import evidence_bp
    from routes.page_routes import page_bp
    from routes.report_routes import report_bp
    from routes.rules_routes import rules_bp

    app.register_blueprint(page_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(report_bp)

    @app.route("/health")
    def health():
        """Liveness probe."""
        return {
            "status": "success",
            "application": "SecureSnap Forensic Workbench",
            "engine_version": app.config.get("ENGINE_VERSION", "2.0.0"),
        }

    register_error_handlers(app)

    return app


def register_error_handlers(app):
    """Return JSON for API errors and HTML for page errors."""

    @app.errorhandler(413)
    def file_too_large(error):
        limit_mb = app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)
        return jsonify({
            "error": f"File is too large. The maximum accepted size is {limit_mb:.0f} MB."
        }), 413

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "The requested resource was not found"}), 404

    @app.errorhandler(500)
    def server_error(error):
        return jsonify({
            "error": "An internal error occurred. Check the server log for details."
        }), 500

    @app.errorhandler(Exception)
    def unhandled_error(error):
        from werkzeug.exceptions import HTTPException

        if isinstance(error, HTTPException):
            return error

        app.logger.exception("Unhandled error")
        return jsonify({
            "error": "An internal error occurred. Check the server log for details."
        }), 500


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, port=5000)
