"""SQLite persistence layer.

SecureSnap runs entirely on the local machine, so a single SQLite file is
enough for the evidence register, analysis history, rule set and audit trail.
All writes go through this module so that the audit log is never bypassed.
"""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import current_app, g

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS evidence (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    case_ref          TEXT    NOT NULL,
    exhibit_ref       TEXT,
    title             TEXT    NOT NULL,
    description       TEXT,
    source            TEXT,
    collected_by      TEXT,
    collected_at      TEXT,
    original_filename TEXT,
    stored_filename   TEXT,
    sha256            TEXT    NOT NULL,
    sha512            TEXT,
    size_bytes        INTEGER,
    detected_format   TEXT,
    risk_score        REAL,
    verdict           TEXT,
    analysis_json     TEXT,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_case   ON evidence(case_ref);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);

CREATE TABLE IF NOT EXISTS analysis_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     INTEGER NOT NULL,
    engine_version  TEXT    NOT NULL,
    risk_score      REAL,
    verdict         TEXT,
    summary_json    TEXT,
    created_at      TEXT    NOT NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_runs_evidence ON analysis_runs(evidence_id);

CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    condition   TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'MEDIUM',
    description TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    builtin     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    entity     TEXT,
    entity_id  INTEGER,
    detail     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
"""


def utc_now():
    """Return an ISO-8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    """Return the request-scoped SQLite connection, creating it if needed."""
    if "db" not in g:
        database_path = current_app.config["DATABASE_PATH"]
        connection = sqlite3.connect(str(database_path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        g.db = connection
    return g.db


def close_db(exception=None):
    """Close the request-scoped SQLite connection."""
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


@contextmanager
def transaction():
    """Context manager wrapping a write in a transaction."""
    connection = get_db()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def init_db(app):
    """Create the schema and seed the built-in rules."""
    for key in ("DATA_DIR", "EVIDENCE_FOLDER", "SEALED_FOLDER", "ANALYSIS_FOLDER"):
        os.makedirs(app.config[key], exist_ok=True)

    database_path = app.config["DATABASE_PATH"]
    connection = sqlite3.connect(str(database_path))
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(SCHEMA)
        connection.commit()
        _seed_builtin_rules(connection)
        connection.commit()
    finally:
        connection.close()

    app.teardown_appcontext(close_db)


def _seed_builtin_rules(connection):
    """Insert the default forensic rule set if the table is empty."""
    existing = connection.execute(
        "SELECT COUNT(*) AS count FROM rules"
    ).fetchone()["count"]

    if existing:
        return

    from modules.rule_engine.defaults import BUILTIN_RULES

    now = utc_now()
    connection.executemany(
        """
        INSERT INTO rules
            (name, condition, action, severity, description, enabled,
             builtin, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)
        """,
        [
            (
                rule["name"],
                rule["condition"],
                rule["action"],
                rule["severity"],
                rule["description"],
                now,
                now,
            )
            for rule in BUILTIN_RULES
        ],
    )


def log_audit(action, entity=None, entity_id=None, detail=None, actor="officer"):
    """Append an entry to the append-only audit trail."""
    connection = get_db()
    connection.execute(
        """
        INSERT INTO audit_log (timestamp, actor, action, entity, entity_id, detail)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (utc_now(), actor, action, entity, entity_id, detail),
    )
    connection.commit()
