"""
ThreatLens – Mode Isolation & Backend Data Separation Tests
============================================================
Verifies that:
  1. Empty backend startup: Live Mode backend starts with zero data by default.
  2. Empty backend reset: POST /api/reset returns to clean empty state (not sample data).
  3. Real CSV upload: uploading user CSV populates the backend with actual analyzed data.
  4. Demo data loading: dedicated mechanisms (POST /api/sample)
     allow explicit loading of sample datasets without polluting default startup.
  5. Demo reset behavior: after loading sample data, a Live reset completely clears it back to 0.
  6. No sample data leaking into live API responses when in the empty state.
  7. API metadata contracts: health dataset_loaded flag, summary isSample flag, non-negative stats.
"""

import io
import pytest
from fastapi.testclient import TestClient

from backend.api import app, state

client = TestClient(app)


# ── Helpers ────────────────────────────────────────────────────────────────────

MINIMAL_CSV = (
    "timestamp,source_ip,event_type,username,status\n"
    "2024-01-15 09:00:00,10.0.0.1,LOGIN_SUCCESS,alice,success\n"
    "2024-01-15 09:01:00,10.0.0.2,LOGIN_FAILURE,bob,failure\n"
)


def _reset_empty():
    """Reset the backend to the clean empty state."""
    r = client.post("/api/reset")
    assert r.status_code == 200, f"Reset to empty failed: {r.text}"
    return r.json()


def _get_summary():
    r = client.get("/api/summary")
    assert r.status_code == 200, f"Summary fetch failed: {r.text}"
    return r.json()


def _upload_custom_csv(csv_text: str = MINIMAL_CSV):
    """Upload a minimal custom CSV and return the JSON response."""
    file_bytes = csv_text.encode("utf-8")
    files = {"file": ("custom_log.csv", io.BytesIO(file_bytes), "text/csv")}
    r = client.post("/api/analyze", files=files)
    assert r.status_code == 200, f"Upload failed ({r.status_code}): {r.text}"
    return r.json()


# ── Mode Isolation & Data Separation Tests ────────────────────────────────────

class TestModeIsolationBackendContract:
    """
    Backend contract tests for Live/Demo mode isolation and empty startup.
    """

    def setup_method(self):
        """Ensure clean empty state before every test."""
        _reset_empty()

    # ── Test 1: Empty backend startup ──────────────────────────────────────────
    def test_empty_backend_startup(self):
        """
        Requirement 1, 2, 3:
        When backend starts, it must contain NO automatically loaded sample security events.
        Dashboard statistics must start at zero.
        Alerts and logs must start as empty collections.
        """
        # Ensure fresh empty state
        state.reset_to_empty()

        # Health endpoint
        health_resp = client.get("/api/health")
        assert health_resp.status_code == 200
        health = health_resp.json()
        assert health["status"] == "ok"
        assert health["dataset_loaded"] is False, "dataset_loaded should be False at startup"
        assert health["total_rows"] == 0, "total_rows should be 0 at startup"
        assert health["total_alerts"] == 0, "total_alerts should be 0 at startup"

        # Summary endpoint: statistics start at zero
        summary = _get_summary()
        stats = summary["summaryStats"]
        assert stats["totalEvents"] == 0, f"totalEvents should be 0, got: {stats['totalEvents']}"
        assert stats["threatsDetected"] == 0, f"threatsDetected should be 0, got: {stats['threatsDetected']}"
        assert stats["criticalAlerts"] == 0, f"criticalAlerts should be 0, got: {stats['criticalAlerts']}"
        assert stats["uniqueIPs"] == 0, f"uniqueIPs should be 0, got: {stats['uniqueIPs']}"
        assert stats.get("highPriorityAlerts") == 0, "highPriorityAlerts should be 0"

        # Charts: empty collections
        assert summary["activityData"] == [], "activityData should be empty"
        assert summary["suspiciousIPs"] == [], "suspiciousIPs should be empty"
        assert summary["topRules"] == [], "topRules should be empty"
        assert all(sev["value"] == 0 for sev in summary["severityData"]), "all severity values should be 0"

        # Metadata
        meta = summary["metadata"]
        assert meta["rowsProcessed"] == 0
        assert meta["alertsDetected"] == 0
        assert meta["isSample"] is False

        # Alerts: empty collection
        alerts_resp = client.get("/api/alerts")
        assert alerts_resp.status_code == 200
        alerts_body = alerts_resp.json()
        assert alerts_body["total"] == 0
        assert alerts_body["alerts"] == []

        # Logs: empty collection
        logs_resp = client.get("/api/logs")
        assert logs_resp.status_code == 200
        logs_body = logs_resp.json()
        assert logs_body["total"] == 0
        assert logs_body["logs"] == []

    # ── Test 2: Empty backend reset ────────────────────────────────────────────
    def test_empty_backend_reset(self):
        """
        Requirement 5:
        Resetting LIVE MODE (POST /api/reset) must return the backend to an empty state,
        NOT reload sample data.
        """
        # Upload real data first
        _upload_custom_csv()
        summary_after_upload = _get_summary()
        assert summary_after_upload["summaryStats"]["totalEvents"] == 2

        # Reset Live Mode
        reset_resp = client.post("/api/reset")
        assert reset_resp.status_code == 200
        body = reset_resp.json()
        assert body["success"] is True

        # Verify summary returns all zeros
        summary = _get_summary()
        assert summary["summaryStats"]["totalEvents"] == 0
        assert summary["summaryStats"]["threatsDetected"] == 0
        assert summary["metadata"]["rowsProcessed"] == 0

        # Verify health confirms dataset is not loaded
        health = client.get("/api/health").json()
        assert health["dataset_loaded"] is False
        assert health["total_rows"] == 0
        assert health["total_alerts"] == 0

        # Verify alerts and logs are empty
        assert client.get("/api/alerts").json()["alerts"] == []
        assert client.get("/api/logs").json()["logs"] == []

    # ── Test 3: Real CSV upload populates backend ──────────────────────────────
    def test_real_csv_upload_populates_backend(self):
        """
        Requirement 4:
        Uploading a real supported CSV populates the backend with actual analyzed data.
        """
        result = _upload_custom_csv()
        assert result["success"] is True
        assert result["rows_processed"] == 2
        assert result["summary"]["metadata"]["isSample"] is False

        # Health now reports loaded
        health = client.get("/api/health").json()
        assert health["dataset_loaded"] is True
        assert health["total_rows"] == 2

        # Summary now reflects uploaded rows
        summary = _get_summary()
        assert summary["summaryStats"]["totalEvents"] == 2
        assert summary["summaryStats"]["uniqueIPs"] == 2
        assert summary["metadata"]["isSample"] is False
        assert summary["metadata"]["rowsProcessed"] == 2

        # Logs endpoint returns the 2 entries
        logs = client.get("/api/logs").json()
        assert logs["total"] == 2
        assert len(logs["logs"]) == 2

    # ── Test 4: Demo data loading mechanism ────────────────────────────────────
    def test_demo_data_loading(self):
        """
        Requirement 6 & 8:
        Explicit demo data loading via POST /api/sample or POST /api/reset?sample=true
        populates the sample dataset without contaminating default startup.
        """
        # Dedicated sample loading endpoint
        resp = client.post("/api/sample")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["summary"]["metadata"]["isSample"] is True
        assert data["summary"]["summaryStats"]["totalEvents"] == 40
        assert data["summary"]["summaryStats"]["threatsDetected"] == 6

        # Health confirms 40 rows
        health = client.get("/api/health").json()
        assert health["dataset_loaded"] is True
        assert health["total_rows"] == 40

    # ── Test 5: Demo reset behavior ────────────────────────────────────────────
    def test_demo_reset_behavior(self):
        """
        Requirement 7:
        After loading sample data, resetting LIVE MODE completely clears it back
        to zero, ensuring demo data does not linger in the live backend.
        Calling reset with ?sample=true restores the sample data when explicitly requested.
        """
        # Load sample data
        client.post("/api/sample")
        assert _get_summary()["summaryStats"]["totalEvents"] == 40

        # Live reset clears sample data completely
        _reset_empty()
        assert _get_summary()["summaryStats"]["totalEvents"] == 0
        assert client.get("/api/alerts").json()["alerts"] == []

        # Reset with sample=True restores sample data
        r = client.post("/api/reset?sample=true")
        assert r.status_code == 200
        assert _get_summary()["summaryStats"]["totalEvents"] == 40

    # ── Test 6: No sample data leaking into live API responses ─────────────────
    def test_no_sample_data_leaking_into_live_api_responses(self):
        """
        In the clean/empty state, verify no sample IP addresses (203.0.113.42, 192.0.2.1),
        sample usernames (alice, bob, attacker), or sample alerts leak into API responses.
        """
        _reset_empty()

        # Check alerts
        alerts_body = client.get("/api/alerts").json()
        assert alerts_body["total"] == 0
        assert len(alerts_body["alerts"]) == 0

        # Check logs
        logs_body = client.get("/api/logs").json()
        assert logs_body["total"] == 0
        assert len(logs_body["logs"]) == 0

        # Check suspicious IPs
        summary = _get_summary()
        assert len(summary["suspiciousIPs"]) == 0
        assert len(summary["topRules"]) == 0

        # Check search in alerts on empty state returns 0
        search_alert = client.get("/api/alerts?search=203.0.113.42").json()
        assert search_alert["total"] == 0

        # Check search in logs on empty state returns 0
        search_log = client.get("/api/logs?search=alice").json()
        assert search_log["total"] == 0

    # ── Contract helper tests ──────────────────────────────────────────────────
    def test_health_endpoint_returns_dataset_loaded_flag(self):
        r = client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert "dataset_loaded" in body
        assert isinstance(body["dataset_loaded"], bool)

    def test_summary_metadata_has_is_sample_flag(self):
        body = _get_summary()
        assert "metadata" in body
        meta = body["metadata"]
        assert "isSample" in meta
        assert isinstance(meta["isSample"], bool)

    def test_summary_stats_are_numeric_and_non_negative(self):
        body = _get_summary()
        stats = body.get("summaryStats", {})
        expected_keys = ["totalEvents", "threatsDetected", "criticalAlerts", "uniqueIPs", "highPriorityAlerts"]
        for key in expected_keys:
            assert key in stats, f"summaryStats is missing '{key}'."
            val = stats[key]
            assert isinstance(val, (int, float))
            assert val >= 0, f"summaryStats.{key} must be >= 0, got: {val}"

    def test_alerts_endpoint_returns_list(self):
        r = client.get("/api/alerts")
        assert r.status_code == 200
        body = r.json()
        assert "alerts" in body
        assert isinstance(body["alerts"], list)

    def test_logs_endpoint_returns_list(self):
        r = client.get("/api/logs")
        assert r.status_code == 200
        body = r.json()
        assert "logs" in body
        assert isinstance(body["logs"], list)
