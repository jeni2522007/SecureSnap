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
import secrets
import sys

from flask import Flask, jsonify, request, session

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from config import Config  # noqa: E402
from db import init_db  # noqa: E402

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
CSRF_HEADER = "X-CSRF-Token"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "object-src 'none'"
    ),
}


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
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SECURE"] = False  # served over plain HTTP locally
    app.config["PERMANENT_SESSION_LIFETIME"] = 3600 * 8

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

    register_security(app)
    register_error_handlers(app)

    return app


def register_security(app):
    """Install the cross-site request forgery and host checks."""

    @app.before_request
    def protect_against_cross_site_requests():
        """Refuse requests that did not originate from this application.

        Two independent checks are applied. The Host header must be one this
        workstation is expected to be reached on, which stops a web page on
        another site from using the application as a springboard. Any
        state-changing request must additionally carry the session token
        that was issued when the page was served.
        """
        if request.method in SAFE_METHODS:
            return None

        allowed_hosts = app.config.get("ALLOWED_HOSTS") or []
        if allowed_hosts:
            host = request.host.split(":")[0]
            if host not in allowed_hosts:
                app.logger.warning(
                    "Refused a %s request with an unexpected Host header: %s",
                    request.method, request.host,
                )
                return jsonify({
                    "error": "This request did not come from the SecureSnap workstation."
                }), 403

        origin = request.headers.get("Origin")
        if origin:
            origin_host = origin.split("//")[-1].split("/")[0]
            if origin_host.split(":")[0] not in allowed_hosts:
                app.logger.warning(
                    "Refused a %s request from an unexpected origin: %s",
                    request.method, origin,
                )
                return jsonify({
                    "error": "Cross-origin requests are not accepted."
                }), 403

        token = request.headers.get(CSRF_HEADER) or request.form.get("csrf_token")
        expected = session.get("csrf_token")

        if not expected or not token or not secrets.compare_digest(
                str(token), str(expected)):
            app.logger.warning(
                "Refused a %s request with a missing or invalid CSRF token.",
                request.method,
            )
            return jsonify({
                "error": (
                    "The request could not be verified. Reload the page and "
                    "try again."
                )
            }), 403

        return None

    @app.after_request
    def add_security_headers(response):
        """Attach hardening headers to every response."""
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    @app.context_processor
    def inject_csrf_token():
        """Make the session token available to every template."""
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["csrf_token"]}


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

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            "error": "The request was refused by the security checks."
        }), 403

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


def _port_is_free(host, port):
    """Return True when the given address is not already in use.

    Without this check a second copy of the application can start on the same
    port, and requests are then split between an old and a new version of
    the code, which is both confusing and a security risk.
    """
    import socket

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind((host, port))
    except OSError:
        return False
    finally:
        probe.close()
    return True


if __name__ == "__main__":
    host = os.environ.get("SECURESNAP_HOST", "127.0.0.1")
    port = int(os.environ.get("SECURESNAP_PORT", 5000))
    debug = app.config.get("DEBUG", False)

    if not _port_is_free(host, port):
        print(
            f"SecureSnap cannot start: {host}:{port} is already in use.\n"
            "Another copy of the application is probably still running. "
            "Stop it first, or set SECURESNAP_PORT to a free port.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    app.run(debug=debug, host=host, port=port, use_reloader=debug)
