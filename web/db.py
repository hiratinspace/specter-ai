"""
db.py — SQLite-backed scan storage for the web dashboard.

Replaces the old in-memory `scans` dict + scan_history.json file. Fixes a
real bug: previously, any completed scan became permanently stuck on the
"loading" page after a process restart, since only a thin summary was
persisted to disk while the full result lived in memory only. Now the full
result is written to SQLite as soon as a scan finishes, so it survives
restarts (on hosts with persistent disk) and reads are consistent across
whichever process/thread serves a given request.

Live scan progress (the in-memory SSE queues in web/app.py) is
intentionally NOT moved here — that's an inherently ephemeral,
per-connection concern tied to a live browser connection, not something
that benefits from durable storage.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "scans.db"


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id                TEXT PRIMARY KEY,
                session_id        TEXT NOT NULL,
                target            TEXT NOT NULL,
                mode              TEXT NOT NULL,
                status            TEXT NOT NULL,
                started_at        TEXT NOT NULL,
                finished_at       TEXT,
                error             TEXT,
                risk_level        TEXT DEFAULT 'unknown',
                open_ports_count  INTEGER DEFAULT 0,
                subdomains_count  INTEGER DEFAULT 0,
                findings_count    INTEGER DEFAULT 0,
                report_path       TEXT,
                aggregated_json   TEXT,
                ai_analysis_json  TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id)")


def create_scan(scan_id, session_id, target, mode):
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, session_id, target, mode, status, started_at) "
            "VALUES (?, ?, ?, ?, 'starting', ?)",
            (scan_id, session_id, target, mode, datetime.now(tz=timezone.utc).isoformat()),
        )


def mark_running(scan_id):
    with _connect() as conn:
        conn.execute("UPDATE scans SET status = 'running' WHERE id = ?", (scan_id,))


def complete_scan(scan_id, aggregated, ai_analysis, report_path):
    with _connect() as conn:
        conn.execute(
            """
            UPDATE scans SET
                status = 'complete',
                finished_at = ?,
                risk_level = ?,
                open_ports_count = ?,
                subdomains_count = ?,
                findings_count = ?,
                report_path = ?,
                aggregated_json = ?,
                ai_analysis_json = ?
            WHERE id = ?
            """,
            (
                datetime.now(tz=timezone.utc).isoformat(),
                ai_analysis.get("risk_level", "unknown"),
                aggregated["ports"].get("open_count", 0),
                len(aggregated["dns"].get("subdomains", [])),
                len(ai_analysis.get("key_findings", [])),
                report_path,
                json.dumps(aggregated),
                json.dumps(ai_analysis),
                scan_id,
            ),
        )


def fail_scan(scan_id, error):
    with _connect() as conn:
        conn.execute(
            "UPDATE scans SET status = 'error', finished_at = ?, error = ? WHERE id = ?",
            (datetime.now(tz=timezone.utc).isoformat(), str(error), scan_id),
        )


def get_scan(scan_id):
    """Return a dict matching the shape the old in-memory `scans[scan_id]` used, or None."""
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None

    scan = dict(row)
    scan["aggregated"] = json.loads(scan.pop("aggregated_json")) if scan.get("aggregated_json") else None
    scan["ai_analysis"] = json.loads(scan.pop("ai_analysis_json")) if scan.get("ai_analysis_json") else None
    return scan


def get_recent_scans(session_id, limit=10):
    """Summary rows for this browser session's scan history, newest first."""
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, target, mode, status, risk_level, started_at,
                   open_ports_count, subdomains_count, findings_count
            FROM scans
            WHERE session_id = ?
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (session_id, limit),
        ).fetchall()

    return [
        {
            "id":         r["id"],
            "target":     r["target"],
            "mode":       r["mode"],
            "status":     r["status"],
            "risk_level": r["risk_level"] or "unknown",
            "started_at": r["started_at"],
            "open_ports": r["open_ports_count"],
            "subdomains": r["subdomains_count"],
            "findings":   r["findings_count"],
        }
        for r in rows
    ]


def prune_old_scans(max_rows=500):
    """Delete the oldest completed/error scans beyond `max_rows`, to bound DB growth."""
    with _connect() as conn:
        conn.execute(
            """
            DELETE FROM scans WHERE id IN (
                SELECT id FROM scans
                WHERE status IN ('complete', 'error')
                ORDER BY started_at DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (max_rows,),
        )
