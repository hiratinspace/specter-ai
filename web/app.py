"""
web/app.py — Specter AI Web Dashboard
Run with: python web/app.py
Serves the dashboard at http://localhost:5000
"""

import json
import os
import queue
import re
import secrets
import threading
import time
import uuid
from collections import defaultdict
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, send_file, session, stream_with_context
from werkzeug.middleware.proxy_fix import ProxyFix

import db
from specter_ai.core.pipeline import run_scan
from specter_ai.core.validation import is_safe_target
from specter_ai.report.generator import generate_report

app = Flask(__name__)
# Render sits behind a reverse proxy — without this, request.remote_addr is
# the proxy's address for every visitor, which breaks per-IP rate limiting.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

db.init_db()

# ── Scan state storage ────────────────────────────────────────────────────────
# Completed/errored scan results live in SQLite (db.py) so they survive
# restarts. Live SSE progress is inherently tied to an active browser
# connection within this process, so it stays in-memory.
scan_queues = {}    # scan_id → queue of SSE events
queues_lock = threading.Lock()

MAX_SCANS_STORED = 500  # prune oldest completed/error scans beyond this limit

# ── Session helpers ───────────────────────────────────────────────────────────

def get_session_id():
    """Return (and create if needed) a stable anonymous session ID for this browser."""
    if "uid" not in session:
        session["uid"] = secrets.token_hex(16)
    return session["uid"]


# ── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_WINDOW = 60   # seconds
RATE_LIMIT_MAX    = 5    # max scans per IP per window
_rate_counts = defaultdict(list)  # ip → [timestamp, ...]
_rate_lock = threading.Lock()


def _is_rate_limited(ip):
    now = time.time()
    with _rate_lock:
        timestamps = _rate_counts[ip]
        # Drop entries outside the window
        _rate_counts[ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_counts[ip]) >= RATE_LIMIT_MAX:
            return True
        _rate_counts[ip].append(now)
        return False


VALID_TARGET_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    r"|^(?:\d{1,3}\.){3}\d{1,3}$"
)


def push_event(scan_id, event_type, data):
    """Push an SSE event to the scan's queue."""
    q = scan_queues.get(scan_id)
    if q:
        q.put({"type": event_type, "data": data})


MODULE_PROGRESS_PCT = {"dns": 25, "ports": 50, "http": 70, "ssl": 85}


def run_scan_thread(scan_id, target, mode, skip_ai, session_id):
    """Full scan pipeline running in a background thread."""
    db.mark_running(scan_id)

    def emit(msg, status="progress", pct=None):
        payload = {"message": msg, "status": status}
        if pct is not None:
            payload["pct"] = pct
        push_event(scan_id, "progress", payload)

    def on_module_start(key, label):
        emit(f"{label}...", pct=MODULE_PROGRESS_PCT[key] - 5)

    def on_module_done(key, label, result, success):
        pct = MODULE_PROGRESS_PCT[key]
        if success:
            emit(f"{label} — done ✓", status="done", pct=pct)
        else:
            emit(f"{label} — failed ✗ ({result.get('error')})", status="error", pct=pct)

    try:
        emit("Initializing scan...", pct=2)

        aggregated, ai_analysis = run_scan(
            target,
            mode,
            skip_ai=skip_ai,
            on_module_start=on_module_start,
            on_module_done=on_module_done,
            on_aggregate_start=lambda: emit("Aggregating results...", pct=88),
            on_ai_start=lambda: emit("Sending to Claude for AI analysis...", pct=92),
            on_ai_done=lambda _: emit("AI analysis complete ✓", status="done", pct=97),
        )

        emit("Generating report...", pct=98)
        report_dir = Path(__file__).parent / "reports"
        report_dir.mkdir(exist_ok=True)
        report_path = report_dir / f"{scan_id}.md"
        generate_report(target, aggregated, ai_analysis, str(report_path))

        db.complete_scan(scan_id, aggregated, ai_analysis, str(report_path))

        emit("Scan complete!", status="complete", pct=100)
        push_event(scan_id, "complete", {"scan_id": scan_id})

    except Exception as e:
        db.fail_scan(scan_id, str(e))
        emit(f"Scan failed: {e}", status="error", pct=100)
        push_event(scan_id, "error", {"message": str(e)})

    finally:
        # No more events will ever be pushed to this queue once the scan
        # is done — free it immediately rather than waiting on a count-based prune.
        with queues_lock:
            scan_queues.pop(scan_id, None)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    uid = get_session_id()
    recent = db.get_recent_scans(uid, limit=10)
    return render_template("index.html", recent_scans=recent)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    client_ip = request.remote_addr or "unknown"
    if _is_rate_limited(client_ip):
        return jsonify({"error": "Rate limit exceeded — try again shortly"}), 429

    data = request.json or {}
    target = (data.get("target") or "").strip().lower()
    target = target.removeprefix("http://").removeprefix("https://").rstrip("/")
    mode = data.get("mode", "quick")
    skip_ai = data.get("skip_ai", False)

    if not target:
        return jsonify({"error": "Target is required"}), 400
    if not VALID_TARGET_RE.match(target):
        return jsonify({"error": "Invalid target — must be a valid domain or IP address"}), 400
    if mode not in ("quick", "full"):
        return jsonify({"error": "mode must be 'quick' or 'full'"}), 400

    safe, _resolved_ips, safety_error = is_safe_target(target)
    if not safe:
        return jsonify({"error": safety_error}), 400

    uid = get_session_id()
    scan_id = str(uuid.uuid4())[:8]
    with queues_lock:
        scan_queues[scan_id] = queue.Queue()
    db.create_scan(scan_id, uid, target, mode)
    db.prune_old_scans(MAX_SCANS_STORED)

    thread = threading.Thread(target=run_scan_thread, args=(scan_id, target, mode, skip_ai, uid), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>/stream")
def scan_stream(scan_id):
    """Server-Sent Events stream for live scan progress."""
    def generate():
        q = scan_queues.get(scan_id)
        if not q:
            # No live queue in this process — e.g. a page refresh after the
            # scan already finished. Resolve immediately from the DB instead
            # of leaving the client stuck on "scan not found".
            scan = db.get_scan(scan_id)
            if scan and scan["status"] == "complete":
                yield f"data: {json.dumps({'type': 'complete', 'data': {'scan_id': scan_id}})}\n\n"
            elif scan and scan["status"] == "error":
                yield f"data: {json.dumps({'type': 'error', 'data': {'message': scan.get('error') or 'Scan failed'}})}\n\n"
            else:
                yield f"data: {json.dumps({'type': 'error', 'data': {'message': 'Scan not found'}})}\n\n"
            return

        while True:
            try:
                event = q.get(timeout=30)
                yield f"data: {json.dumps(event)}\n\n"
                if event["type"] in ("complete", "error"):
                    break
            except queue.Empty:
                yield "data: {\"type\": \"ping\"}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/scan/<scan_id>")
def scan_result(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return "Scan not found", 404

    if scan["status"] in ("starting", "running"):
        return render_template("loading.html", scan_id=scan_id)

    return render_template("report.html", scan=scan)


@app.route("/api/scan/<scan_id>/json")
def scan_json(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    # Return serializable subset
    return jsonify({
        "id":          scan["id"],
        "target":      scan["target"],
        "status":      scan["status"],
        "aggregated":  scan.get("aggregated"),
        "ai_analysis": scan.get("ai_analysis"),
    })


@app.route("/scan/<scan_id>/download")
def download_report(scan_id):
    """Download the markdown report for a completed scan."""
    # Sanitize: scan_id must be hex chars only (matches how we generate them)
    if not re.match(r"^[0-9a-f]{8}$", scan_id):
        return "Invalid scan ID", 400
    report_path = (Path(__file__).parent / "reports" / f"{scan_id}.md").resolve()
    reports_dir = (Path(__file__).parent / "reports").resolve()
    # Guard against path traversal
    if not str(report_path).startswith(str(reports_dir)):
        return "Forbidden", 403
    if not report_path.exists():
        return "Report not found", 404
    scan = db.get_scan(scan_id)
    target = scan["target"] if scan else scan_id
    filename = f"specter_{target.replace('.', '_')}_{scan_id}.md"
    return send_file(report_path, as_attachment=True, download_name=filename, mimetype="text/markdown")


if __name__ == "__main__":
    print("\n  SPECTERAI  —  Attack Surface Intelligence")
    print("  ──────────────────────────────────────────")
    print("  Running at: http://localhost:5000\n")
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, port=5000, threaded=True)