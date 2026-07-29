import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))
import db as webdb


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setattr(webdb, "DB_PATH", tmp_path / "test_scans.db")
    webdb.init_db()
    return webdb


def _complete(db, scan_id, open_ports=0, subdomains=None, findings=None, risk_level="low"):
    db.complete_scan(
        scan_id,
        {"ports": {"open_count": open_ports}, "dns": {"subdomains": subdomains or []}},
        {"risk_level": risk_level, "key_findings": findings or []},
        "/tmp/report.md",
    )


def test_create_and_get_scan(fresh_db):
    fresh_db.create_scan("abc123", "session1", "example.com", "quick")
    scan = fresh_db.get_scan("abc123")
    assert scan is not None
    assert scan["status"] == "starting"
    assert scan["target"] == "example.com"
    assert scan["aggregated"] is None


def test_get_scan_returns_none_for_missing(fresh_db):
    assert fresh_db.get_scan("does-not-exist") is None


def test_mark_running_updates_status(fresh_db):
    fresh_db.create_scan("abc123", "session1", "example.com", "quick")
    fresh_db.mark_running("abc123")
    assert fresh_db.get_scan("abc123")["status"] == "running"


def test_complete_scan_stores_full_result_and_summary_counts(fresh_db):
    fresh_db.create_scan("abc123", "session1", "example.com", "quick")
    aggregated = {"ports": {"open_count": 2}, "dns": {"subdomains": ["a.example.com", "b.example.com"]}}
    ai_analysis = {"risk_level": "high", "key_findings": [{"title": "x"}]}
    fresh_db.complete_scan("abc123", aggregated, ai_analysis, "/tmp/report.md")

    scan = fresh_db.get_scan("abc123")
    assert scan["status"] == "complete"
    assert scan["risk_level"] == "high"
    assert scan["open_ports_count"] == 2
    assert scan["subdomains_count"] == 2
    assert scan["findings_count"] == 1
    assert scan["aggregated"] == aggregated
    assert scan["ai_analysis"] == ai_analysis
    assert scan["report_path"] == "/tmp/report.md"


def test_fail_scan_stores_error_and_status(fresh_db):
    fresh_db.create_scan("abc123", "session1", "example.com", "quick")
    fresh_db.fail_scan("abc123", "boom")
    scan = fresh_db.get_scan("abc123")
    assert scan["status"] == "error"
    assert scan["error"] == "boom"


def test_get_recent_scans_filters_by_session(fresh_db):
    fresh_db.create_scan("s1", "session1", "a.com", "quick")
    fresh_db.create_scan("s2", "session2", "b.com", "quick")
    fresh_db.create_scan("s3", "session1", "c.com", "quick")

    recent = fresh_db.get_recent_scans("session1", limit=10)
    ids = {r["id"] for r in recent}
    assert ids == {"s1", "s3"}


def test_get_recent_scans_summary_shape_matches_template_expectations(fresh_db):
    fresh_db.create_scan("s1", "session1", "a.com", "quick")
    _complete(fresh_db, "s1", open_ports=3, subdomains=["x.a.com"], findings=[{"title": "f"}], risk_level="medium")

    recent = fresh_db.get_recent_scans("session1")
    assert recent[0]["target"] == "a.com"
    assert recent[0]["risk_level"] == "medium"
    assert recent[0]["open_ports"] == 3
    assert recent[0]["subdomains"] == 1
    assert recent[0]["findings"] == 1


def test_prune_old_scans_bounds_row_count(fresh_db):
    for i in range(5):
        fresh_db.create_scan(f"s{i}", "session1", f"target{i}.com", "quick")
        _complete(fresh_db, f"s{i}")

    fresh_db.prune_old_scans(max_rows=2)
    assert len(fresh_db.get_recent_scans("session1", limit=10)) == 2
