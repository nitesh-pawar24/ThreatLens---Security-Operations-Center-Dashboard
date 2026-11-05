"""
ThreatLens – API Integration Tests (Phase 3)
=============================================
Tests FastAPI endpoints:
- Health checks (GET /api/health)
- Summary stats (GET /api/summary)
- Alerts retrieval & filtering (GET /api/alerts)
- Logs retrieval (GET /api/logs)
- Valid CSV upload (POST /api/analyze)
- Invalid CSV uploads: non-csv extension, empty file, missing columns, bad timestamps
- Reset endpoint (POST /api/reset)

Run with:
    python -m pytest backend/tests/test_api.py -v
"""

from __future__ import annotations

import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.api import app, state

client = TestClient(app)

SAMPLE_CSV_PATH = Path(__file__).parent.parent / "data" / "sample_logs.csv"


@pytest.fixture(autouse=True)
def reset_state_before_each_test():
    """Ensure every test runs with the clean default state."""
    state.reset_to_sample()
    yield
    state.reset_to_sample()


class TestHealthEndpoint:
    def test_health_check_returns_ok(self):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "threatlens-api"
        assert data["engine"] == "ready"
        assert data["dataset_loaded"] is True
        assert data["total_rows"] > 0
        assert data["total_alerts"] > 0


class TestSummaryEndpoint:
    def test_summary_returns_expected_structure(self):
        resp = client.get("/api/summary")
        assert resp.status_code == 200
        data = resp.json()

        assert "summaryStats" in data
        stats = data["summaryStats"]
        assert "totalEvents" in stats
        assert "threatsDetected" in stats
        assert "criticalAlerts" in stats
        assert "uniqueIPs" in stats
        assert stats["totalEvents"] == 40
        assert stats["threatsDetected"] == 6

        assert "severityData" in data
        assert len(data["severityData"]) == 4

        assert "activityData" in data
        assert isinstance(data["activityData"], list)

        assert "suspiciousIPs" in data
        assert isinstance(data["suspiciousIPs"], list)
        assert len(data["suspiciousIPs"]) > 0

        assert "metadata" in data
        assert data["metadata"]["isSample"] is True


class TestAlertsEndpoint:
    def test_get_all_alerts(self):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 6
        assert len(data["alerts"]) == 6

        alert = data["alerts"][0]
        assert "id" in alert
        assert "sourceIP" in alert
        assert "eventType" in alert
        assert "severity" in alert
        assert "details" in alert
        assert "evidence" in alert

    def test_filter_by_severity(self):
        resp = client.get("/api/alerts?severity=Critical")
        assert resp.status_code == 200
        data = resp.json()
        assert all(a["severity"] == "Critical" for a in data["alerts"])
        assert data["total"] >= 1

    def test_filter_by_search_query(self):
        resp = client.get("/api/alerts?search=203.0.113.42")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert all("203.0.113.42" in a["sourceIP"] for a in data["alerts"])

    def test_filter_by_nonexistent_search(self):
        resp = client.get("/api/alerts?search=nonexistent-host-999")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["alerts"] == []


class TestLogsEndpoint:
    def test_get_logs_default(self):
        resp = client.get("/api/logs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 40
        assert len(data["logs"]) == 40
        assert "message" in data["logs"][0]
        assert "source" in data["logs"][0]
        assert "level" in data["logs"][0]

    def test_filter_logs_by_level(self):
        resp = client.get("/api/logs?level=CRITICAL")
        assert resp.status_code == 200
        data = resp.json()
        assert all(l["level"] == "CRITICAL" for l in data["logs"])
        assert data["total"] >= 1

    def test_filter_logs_by_search(self):
        resp = client.get("/api/logs?search=alice")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any("alice" in l["message"].lower() for l in data["logs"])


class TestAnalyzeEndpoint:
    def test_analyze_valid_csv(self):
        csv_content = (
            "timestamp,source_ip,event_type,username,status\n"
            "2026-10-20 10:00:00,192.0.2.50,LOGIN_FAILURE,root,FAILURE\n"
            "2026-10-20 10:00:05,192.0.2.50,LOGIN_FAILURE,root,FAILURE\n"
            "2026-10-20 10:00:10,192.0.2.50,LOGIN_FAILURE,root,FAILURE\n"
            "2026-10-20 10:00:15,192.0.2.50,LOGIN_FAILURE,root,FAILURE\n"
            "2026-10-20 10:00:20,192.0.2.50,LOGIN_FAILURE,root,FAILURE\n"
            "2026-10-20 10:00:25,192.0.2.50,LOGIN_SUCCESS,root,SUCCESS\n"
        )
        files = {"file": ("test_logs.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
        resp = client.post("/api/analyze", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["filename"] == "test_logs.csv"
        assert data["rows_processed"] == 6
        assert data["alerts_detected"] == 1
        # BruteForce must fire; AccountBruteForce may also fire and be merged
        assert "BruteForce" in data["alerts"][0]["rules_matched"]
        assert data["summary"]["metadata"]["isSample"] is False

    def test_analyze_sample_csv_file(self):
        with open(SAMPLE_CSV_PATH, "rb") as f:
            files = {"file": ("sample_logs.csv", f, "text/csv")}
            resp = client.post("/api/analyze", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["rows_processed"] == 40
        assert data["alerts_detected"] == 6

    def test_reject_non_csv_file(self):
        files = {"file": ("test.txt", io.BytesIO(b"hello world"), "text/plain")}
        resp = client.post("/api/analyze", files=files)
        assert resp.status_code == 400
        assert "Only CSV files" in resp.json()["detail"]

    def test_reject_empty_file(self):
        files = {"file": ("empty.csv", io.BytesIO(b""), "text/csv")}
        resp = client.post("/api/analyze", files=files)
        assert resp.status_code == 400
        assert "empty" in resp.json()["detail"].lower()

    def test_reject_missing_required_columns(self):
        bad_csv = "timestamp,source_ip,username\n2026-10-20 10:00:00,192.0.2.1,admin\n"
        files = {"file": ("bad_columns.csv", io.BytesIO(bad_csv.encode("utf-8")), "text/csv")}
        resp = client.post("/api/analyze", files=files)
        assert resp.status_code == 400
        assert "missing required columns" in resp.json()["detail"].lower()

    def test_reject_unparseable_timestamps(self):
        bad_ts_csv = (
            "timestamp,source_ip,event_type,username,status\n"
            "NOT_A_TIMESTAMP,192.0.2.1,LOGIN_SUCCESS,admin,SUCCESS\n"
        )
        files = {"file": ("bad_ts.csv", io.BytesIO(bad_ts_csv.encode("utf-8")), "text/csv")}
        resp = client.post("/api/analyze", files=files)
        assert resp.status_code == 400
        assert "unparseable timestamps" in resp.json()["detail"].lower()


class TestResetEndpoint:
    def test_reset_dataset(self):
        # First mutate state with custom CSV
        csv_content = (
            "timestamp,source_ip,event_type,username,status\n"
            "2026-10-20 10:00:00,192.0.2.99,MALWARE_DETECTED,attacker,BLOCKED\n"
        )
        files = {"file": ("custom.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
        resp = client.post("/api/analyze", files=files)
        assert resp.status_code == 200
        assert resp.json()["rows_processed"] == 1

        # Now reset (Live Mode reset clears data to clean empty state)
        reset_resp = client.post("/api/reset")
        assert reset_resp.status_code == 200
        assert reset_resp.json()["success"] is True

        # Verify state is clean and empty
        summary_resp = client.get("/api/summary")
        assert summary_resp.json()["summaryStats"]["totalEvents"] == 0

    def test_reset_dataset_with_sample_param(self):
        # Reset with sample=True explicitly restores the demonstration dataset
        reset_resp = client.post("/api/reset?sample=true")
        assert reset_resp.status_code == 200
        assert reset_resp.json()["success"] is True

        summary_resp = client.get("/api/summary")
        assert summary_resp.json()["summaryStats"]["totalEvents"] == 40
