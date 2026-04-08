"""
web/app.py — Specter AI Web Dashboard
Run with: python web/app.py
Serves the dashboard at http://localhost:5000
"""

import json
import os
import queue
import re
import sys
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

# Add parent directory to path so we can import our modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.dns_enum import run_dns_enum
from modules.http_probe import run_http_probe
from modules.port_scan import run_port_scan
from modules.ssl_check import run_ssl_check
from core.aggregator import aggregate_results
from core.ai_analyst import run_ai_analysis
from report.generator import generate_report

app = Flask(__name__)

# ── Scan state storage ────────────────────────────────────────────────────────
# In production you'd use Redis/DB; a dict is fine for a portfolio tool
scans = {}          # scan_id → scan result dict
scan_queues = {}    # scan_id → queue of SSE events
scans_lock = threading.Lock()

SCANS_FILE = Path(__file__).parent / "scan_history.json"
MAX_SCANS_IN_MEMORY = 50  # prune oldest completed scans beyond this limit

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


def _prune_scans():
    """Remove oldest completed scans from memory when limit is exceeded."""
    with scans_lock:
        completed = [
            (sid, s) for sid, s in scans.items()
            if s.get("status") in ("complete", "error")
        ]
        if len(scans) > MAX_SCANS_IN_MEMORY:
            completed.sort(key=lambda x: x[1].get("finished_at", ""))
            for sid, _ in completed[:len(scans) - MAX_SCANS_IN_MEMORY]:
                scans.pop(sid, None)
                scan_queues.pop(sid, None)


def load_history():
    if SCANS_FILE.exists():
        try:
            with open(SCANS_FILE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_history(scan_id, scan_data):
    history = load_history()
    # Store only serialisable summary (not full raw data)
    history[scan_id] = {
        "id":         scan_id,
        "target":     scan_data.get("target"),
        "mode":       scan_data.get("mode"),
        "started_at": scan_data.get("started_at"),
        "finished_at":scan_data.get("finished_at"),
        "status":     scan_data.get("status"),
        "risk_level": scan_data.get("risk_level", "unknown"),
        "open_ports": scan_data.get("open_ports_count", 0),
        "subdomains": scan_data.get("subdomains_count", 0),
        "findings":   scan_data.get("findings_count", 0),
    }
    with open(SCANS_FILE, "w") as f:
        json.dump(history, f, indent=2)


def push_event(scan_id, event_type, data):
    """Push an SSE event to the scan's queue."""
    q = scan_queues.get(scan_id)
    if q:
        q.put({"type": event_type, "data": data})


def run_scan_thread(scan_id, target, mode, skip_ai):
    """Full scan pipeline running in a background thread."""
    scans[scan_id]["status"] = "running"

    def emit(msg, status="progress", pct=None):
        payload = {"message": msg, "status": status}
        if pct is not None:
            payload["pct"] = pct
        push_event(scan_id, "progress", payload)

    try:
        emit("Initializing scan...", pct=2)
        module_results = {}
        errors = {}

        # Run modules with individual progress updates
        def run_module(name, fn, args, label, pct_done):
            emit(f"{label}...", pct=pct_done - 5)
            try:
                result = fn(*args)
                module_results[name] = result
                emit(f"{label} — done ✓", status="done", pct=pct_done)
            except Exception as e:
                errors[name] = str(e)
                module_results[name] = {"error": str(e)}
                emit(f"{label} — failed ✗ ({e})", status="error", pct=pct_done)

        threads = [
            threading.Thread(target=run_module, args=("dns",   run_dns_enum,  (target,),       "DNS / WHOIS enumeration", 25)),
            threading.Thread(target=run_module, args=("ports", run_port_scan, (target, mode),  "Port scanning",           50)),
            threading.Thread(target=run_module, args=("http",  run_http_probe,(target,),       "HTTP analysis",           70)),
            threading.Thread(target=run_module, args=("ssl",   run_ssl_check, (target,),       "SSL/TLS inspection",      85)),
        ]
        for t in threads: t.start()
        for t in threads: t.join()

        emit("Aggregating results...", pct=88)
        aggregated = aggregate_results(target, mode, module_results)

        ai_analysis = {"skipped": True, "executive_summary": "AI analysis skipped.", "risk_level": "unknown", "key_findings": [], "next_steps": []}
        if not skip_ai:
            emit("Sending to Claude for AI analysis...", pct=92)
            ai_analysis = run_ai_analysis(aggregated)
            emit("AI analysis complete ✓", status="done", pct=97)

        emit("Generating report...", pct=98)
        report_dir = Path(__file__).parent / "reports"
        report_dir.mkdir(exist_ok=True)
        report_path = report_dir / f"{scan_id}.md"
        generate_report(target, aggregated, ai_analysis, str(report_path))

        # Store full result
        scans[scan_id].update({
            "status":           "complete",
            "finished_at":      datetime.now(tz=timezone.utc).isoformat(),
            "aggregated":       aggregated,
            "ai_analysis":      ai_analysis,
            "report_path":      str(report_path),
            "risk_level":       ai_analysis.get("risk_level", "unknown"),
            "open_ports_count": aggregated["ports"].get("open_count", 0),
            "subdomains_count": len(aggregated["dns"].get("subdomains", [])),
            "findings_count":   len(ai_analysis.get("key_findings", [])),
        })
        save_history(scan_id, scans[scan_id])

        emit("Scan complete!", status="complete", pct=100)
        push_event(scan_id, "complete", {"scan_id": scan_id})

    except Exception as e:
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = str(e)
        emit(f"Scan failed: {e}", status="error", pct=100)
        push_event(scan_id, "error", {"message": str(e)})


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    history = load_history()
    recent = sorted(history.values(), key=lambda x: x.get("started_at", ""), reverse=True)[:10]
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

    scan_id = str(uuid.uuid4())[:8]
    with scans_lock:
        scan_queues[scan_id] = queue.Queue()
        scans[scan_id] = {
            "id":         scan_id,
            "target":     target,
            "mode":       mode,
            "started_at": datetime.now(tz=timezone.utc).isoformat(),
            "status":     "starting",
        }

    _prune_scans()
    thread = threading.Thread(target=run_scan_thread, args=(scan_id, target, mode, skip_ai), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>/stream")
def scan_stream(scan_id):
    """Server-Sent Events stream for live scan progress."""
    def generate():
        q = scan_queues.get(scan_id)
        if not q:
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
    scan = scans.get(scan_id)
    if not scan:
        # Try loading from history (page refresh)
        history = load_history()
        if scan_id not in history:
            return "Scan not found", 404
        return render_template("loading.html", scan_id=scan_id)

    if scan["status"] in ("starting", "running"):
        return render_template("loading.html", scan_id=scan_id)

    return render_template("report.html", scan=scan)


@app.route("/api/scan/<scan_id>/json")
def scan_json(scan_id):
    scan = scans.get(scan_id)
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


if __name__ == "__main__":
    print("\n  SPECTER.AI  —  Attack Surface Intelligence")
    print("  ──────────────────────────────────────────")
    print("  Running at: http://localhost:5000\n")
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, port=5000, threaded=True)