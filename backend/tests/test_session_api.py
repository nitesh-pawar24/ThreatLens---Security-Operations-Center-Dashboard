"""
ThreatLens – Integration tests for per-visitor sessions (MULTI_TENANT_SESSIONS)
================================================================================
Exercises the real FastAPI app end to end:

- session issuance, capability discovery and deletion
- invalid / malformed / unknown / expired sessions (always 401, never another dataset)
- visitor isolation for summaries, alerts, logs, uploads, Windows uploads, resets,
  sample loading and detection configuration
- upload, row, memory, session-count and concurrent-analysis limits
- same-session and cross-session concurrency
- emergency read-only protection (independent of session mode)
- client-IP handling for rate limiting (spoofed X-Forwarded-For must not help)
- the event loop stays responsive while an upload is being analysed
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import backend.api as api
from backend.session import SessionManager, validate_session_token

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
HEADER = "X-Session-ID"
UNKNOWN_TOKEN = "tl_sess_" + "0" * 64


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_csv(failures: int, ip: str, user: str = "alice") -> bytes:
    """`failures` LOGIN_FAILURE rows from one IP within a minute (>=5 triggers BruteForce)."""
    lines = ["timestamp,source_ip,event_type,username,status"]
    for i in range(failures):
        lines.append(f"2026-11-04 10:00:{i % 60:02d},{ip},LOGIN_FAILURE,{user},FAILURE")
    return ("\n".join(lines) + "\n").encode()


def upload(client, token, content, name="data.csv", path="/api/analyze", **kw):
    return client.post(path, files={"file": (name, content, "text/csv")}, headers={HEADER: token}, **kw)


def new_session(client) -> str:
    res = client.post("/api/session")
    assert res.status_code == 201, res.text
    return res.json()["session_id"]


def h(token):
    return {HEADER: token}


@pytest.fixture
def mt(monkeypatch):
    """Multi-tenant mode on, write-protection off, fresh isolated session manager."""
    mgr = SessionManager(
        ttl_minutes=30, empty_ttl_minutes=5, max_sessions=50,
        max_session_memory_mb=35, max_total_memory_mb=220, max_concurrent_analyses=4,
    )
    monkeypatch.setattr(api, "session_manager", mgr)
    monkeypatch.setattr(api, "MULTI_TENANT_SESSIONS", True)
    monkeypatch.setattr(api, "PORTFOLIO_READ_ONLY", False)
    monkeypatch.setattr(api, "ADMIN_API_KEY", "")
    api.state.reset_to_empty()
    client = TestClient(api.app)
    yield SimpleNamespace(mgr=mgr, client=client, monkeypatch=monkeypatch)
    api.state.reset_to_empty()


def idle(mgr, token, seconds):
    mgr._sessions[token].last_accessed -= seconds


# ── Session issuance and capabilities ─────────────────────────────────────────

class TestSessionIssuance:
    def test_create_session_returns_secure_unique_tokens(self, mt):
        a = mt.client.post("/api/session")
        b = mt.client.post("/api/session")
        assert a.status_code == b.status_code == 201
        ta, tb = a.json()["session_id"], b.json()["session_id"]
        assert validate_session_token(ta) and validate_session_token(tb)
        assert ta != tb
        assert a.headers["cache-control"] == "no-store"
        assert a.json()["idle_timeout_seconds"] == 30 * 60

    def test_session_endpoints_404_when_feature_disabled(self, mt):
        mt.monkeypatch.setattr(api, "MULTI_TENANT_SESSIONS", False)
        assert mt.client.post("/api/session").status_code == 404
        assert mt.client.delete("/api/session", headers=h(UNKNOWN_TOKEN)).status_code == 404

    def test_health_advertises_capabilities_without_leaking_data(self, mt):
        token = new_session(mt.client)
        assert upload(mt.client, token, make_csv(8, "192.0.2.10")).status_code == 200
        body = mt.client.get("/api/health").json()
        assert body["multi_tenant"] is True
        assert body["uploads_enabled"] is True
        assert body["read_only"] is False
        assert body["mode"] == "multi_tenant_sessions"
        assert body["limits"]["max_upload_rows"] == api.MAX_UPLOAD_ROWS
        # Nothing about any visitor's data on an unauthenticated endpoint
        for leaked in ("dataset_loaded", "total_rows", "total_alerts", "log_format"):
            assert leaked not in body

    def test_health_works_without_a_session(self, mt):
        assert mt.client.get("/api/health").status_code == 200

    def test_delete_session_frees_it_and_is_idempotent(self, mt):
        token = new_session(mt.client)
        upload(mt.client, token, make_csv(6, "192.0.2.10"))
        assert mt.client.delete("/api/session", headers=h(token)).json() == {"success": True, "deleted": True}
        assert mt.client.get("/api/summary", headers=h(token)).status_code == 401
        assert mt.client.delete("/api/session", headers=h(token)).json()["deleted"] is False
        assert mt.mgr.get_metrics()["committed_memory_bytes"] == 0

    def test_session_capacity_limit(self, mt):
        mt.monkeypatch.setattr(api, "session_manager", SessionManager(max_sessions=2))
        assert mt.client.post("/api/session").status_code == 201
        assert mt.client.post("/api/session").status_code == 201
        res = mt.client.post("/api/session")
        assert res.status_code == 503
        assert res.headers["retry-after"]
        assert "capacity" in res.json()["detail"].lower()


# ── Invalid and expired sessions ──────────────────────────────────────────────

DATA_REQUESTS = [
    ("GET", "/api/summary", {}),
    ("GET", "/api/alerts", {}),
    ("GET", "/api/logs", {}),
    ("GET", "/api/detection/config", {}),
    ("PUT", "/api/detection/config", {"json": {"brute_force_threshold": 4}}),
    ("POST", "/api/reset", {}),
    ("POST", "/api/sample", {}),
    ("POST", "/api/analyze", {"files": {"file": ("a.csv", b"timestamp,source_ip,event_type,username,status\n", "text/csv")}}),
    ("POST", "/api/analyze/windows", {"files": {"file": ("a.csv", b"x", "text/csv")}}),
]


class TestInvalidSessions:
    @pytest.mark.parametrize("method,path,kwargs", DATA_REQUESTS)
    def test_missing_session_header_is_401(self, mt, method, path, kwargs):
        assert mt.client.request(method, path, **kwargs).status_code == 401

    @pytest.mark.parametrize("bad", [
        "garbage", "tl_sess_short", "tl_sess_" + "g" * 64, "tl_sess_" + "A" * 64,
        "tl_sess_" + "0" * 63, "tl_sess_" + "0" * 65, UNKNOWN_TOKEN,
    ])
    @pytest.mark.parametrize("method,path,kwargs", DATA_REQUESTS)
    def test_malformed_or_unknown_token_is_401(self, mt, method, path, kwargs, bad):
        res = mt.client.request(method, path, headers=h(bad), **kwargs)
        assert res.status_code == 401
        assert "session" in res.json()["detail"].lower()

    def test_bad_token_never_falls_back_to_the_global_dataset(self, mt):
        # Put real data into the process-wide state; a bad token must not expose it.
        api.state.reset_to_sample()
        assert api.state.df is not None
        for bad in (None, "nope", UNKNOWN_TOKEN):
            headers = h(bad) if bad else {}
            assert mt.client.get("/api/summary", headers=headers).status_code == 401
            assert mt.client.get("/api/alerts", headers=headers).status_code == 401
            assert mt.client.get("/api/logs", headers=headers).status_code == 401

    def test_one_character_off_token_does_not_reach_another_visitors_data(self, mt):
        victim = new_session(mt.client)
        upload(mt.client, victim, make_csv(8, "192.0.2.10"))
        flipped = victim[:-1] + ("0" if victim[-1] != "0" else "1")
        assert mt.client.get("/api/summary", headers=h(flipped)).status_code == 401


class TestExpiry:
    def test_idle_session_with_data_expires_and_data_is_freed(self, mt):
        token = new_session(mt.client)
        upload(mt.client, token, make_csv(8, "192.0.2.10"))
        assert mt.client.get("/api/summary", headers=h(token)).status_code == 200
        idle(mt.mgr, token, 31 * 60)
        for method, path, kwargs in DATA_REQUESTS:
            assert mt.client.request(method, path, headers=h(token), **kwargs).status_code == 401
        assert mt.mgr.get_metrics()["committed_memory_bytes"] == 0

    def test_expired_token_cannot_be_reused_to_upload(self, mt):
        token = new_session(mt.client)
        upload(mt.client, token, make_csv(8, "192.0.2.10"))
        idle(mt.mgr, token, 31 * 60)
        assert upload(mt.client, token, make_csv(8, "192.0.2.10")).status_code == 401
        assert mt.mgr.get_metrics()["active_sessions"] == 0

    def test_empty_sessions_expire_sooner_than_sessions_with_data(self, mt):
        empty, used = new_session(mt.client), new_session(mt.client)
        upload(mt.client, used, make_csv(8, "192.0.2.10"))
        idle(mt.mgr, empty, 6 * 60)
        idle(mt.mgr, used, 6 * 60)
        assert mt.client.get("/api/summary", headers=h(empty)).status_code == 401
        assert mt.client.get("/api/summary", headers=h(used)).status_code == 200

    def test_activity_keeps_a_session_alive(self, mt):
        token = new_session(mt.client)
        upload(mt.client, token, make_csv(8, "192.0.2.10"))
        idle(mt.mgr, token, 20 * 60)
        assert mt.client.get("/api/summary", headers=h(token)).status_code == 200  # touches
        idle(mt.mgr, token, 20 * 60)  # only 20 min since the touch
        assert mt.client.get("/api/summary", headers=h(token)).status_code == 200

    def test_expiry_frees_session_capacity(self, mt):
        mt.monkeypatch.setattr(api, "session_manager", SessionManager(max_sessions=1, empty_ttl_minutes=1))
        token = new_session(mt.client)
        assert mt.client.post("/api/session").status_code == 503
        idle(api.session_manager, token, 120)
        assert mt.client.post("/api/session").status_code == 201


# ── Isolation ─────────────────────────────────────────────────────────────────

class TestVisitorIsolation:
    def test_summaries_alerts_and_logs_are_private(self, mt):
        a, b, c = (new_session(mt.client) for _ in range(3))
        assert upload(mt.client, a, make_csv(8, "192.0.2.10", "alice"), "a.csv").status_code == 200
        assert upload(mt.client, b, make_csv(3, "198.51.100.77", "bob"), "b.csv").status_code == 200

        sa = mt.client.get("/api/summary", headers=h(a)).json()
        sb = mt.client.get("/api/summary", headers=h(b)).json()
        sc = mt.client.get("/api/summary", headers=h(c)).json()
        assert sa["metadata"]["datasetName"] == "a.csv" and sa["summaryStats"]["totalEvents"] == 8
        assert sb["metadata"]["datasetName"] == "b.csv" and sb["summaryStats"]["totalEvents"] == 3
        assert sc["summaryStats"]["totalEvents"] == 0 and sc["metadata"]["rowsProcessed"] == 0
        assert [x["ip"] for x in sa["suspiciousIPs"]] == ["192.0.2.10"]
        assert [x["ip"] for x in sb["suspiciousIPs"]] == ["198.51.100.77"]

        al_a = mt.client.get("/api/alerts", headers=h(a)).json()
        al_b = mt.client.get("/api/alerts", headers=h(b)).json()
        al_c = mt.client.get("/api/alerts", headers=h(c)).json()
        assert al_a["dataset_total"] >= 1 and al_b["dataset_total"] == 0 and al_c["dataset_total"] == 0
        assert {x["source_ip"] for x in al_a["alerts"]} == {"192.0.2.10"}

        lg_a = mt.client.get("/api/logs", headers=h(a)).json()
        lg_b = mt.client.get("/api/logs", headers=h(b)).json()
        assert lg_a["total"] == 8 and {x["source"] for x in lg_a["logs"]} == {"192.0.2.10"}
        assert lg_b["total"] == 3 and {x["source"] for x in lg_b["logs"]} == {"198.51.100.77"}
        assert mt.client.get("/api/logs", headers=h(c)).json() == {"total": 0, "logs": []}

        # alert filters operate inside the caller's session only
        assert mt.client.get("/api/alerts", params={"source_ip": "198.51"}, headers=h(a)).json()["total"] == 0

    def test_uploads_never_touch_the_global_dataset(self, mt):
        token = new_session(mt.client)
        assert upload(mt.client, token, make_csv(8, "192.0.2.10")).status_code == 200
        assert api.state.df is None and api.state.alerts == []

    def test_visitor_b_upload_does_not_overwrite_visitor_a(self, mt):
        a, b = new_session(mt.client), new_session(mt.client)
        upload(mt.client, a, make_csv(8, "192.0.2.10"), "a.csv")
        before = mt.client.get("/api/summary", headers=h(a)).json()
        upload(mt.client, b, make_csv(20, "203.0.113.5"), "b.csv")
        assert mt.client.get("/api/summary", headers=h(a)).json() == before

    def test_windows_upload_is_session_specific(self, mt):
        a, b = new_session(mt.client), new_session(mt.client)
        win = (DATA_DIR / "sample_windows_security_log.csv").read_bytes()
        res = upload(mt.client, a, win, "win.csv", path="/api/analyze/windows")
        assert res.status_code == 200 and res.json()["format"] == "windows_event_viewer"
        sa = mt.client.get("/api/summary", headers=h(a)).json()
        assert sa["metadata"]["logFormat"] == "windows_event_viewer"
        assert mt.client.get("/api/summary", headers=h(b)).json()["summaryStats"]["totalEvents"] == 0
        assert mt.client.get("/api/logs", headers=h(a)).json()["total"] > 0
        assert mt.client.get("/api/logs", headers=h(b)).json()["total"] == 0

    def test_standard_endpoint_autodetects_windows_for_the_callers_session_only(self, mt):
        a, b = new_session(mt.client), new_session(mt.client)
        win = (DATA_DIR / "sample_windows_security_log.csv").read_bytes()
        res = upload(mt.client, a, win, "win.csv")
        assert res.status_code == 200 and res.json()["format"] == "windows_event_viewer"
        assert mt.client.get("/api/summary", headers=h(b)).json()["summaryStats"]["totalEvents"] == 0

    def test_reset_is_scoped_to_the_caller(self, mt):
        a, b = new_session(mt.client), new_session(mt.client)
        upload(mt.client, a, make_csv(8, "192.0.2.10"))
        upload(mt.client, b, make_csv(9, "198.51.100.77"))
        res = mt.client.post("/api/reset", headers=h(a))
        assert res.status_code == 200 and res.json()["summary"]["summaryStats"]["totalEvents"] == 0
        assert mt.client.get("/api/summary", headers=h(a)).json()["summaryStats"]["totalEvents"] == 0
        assert mt.client.get("/api/summary", headers=h(b)).json()["summaryStats"]["totalEvents"] == 9
        assert mt.mgr._sessions[a].memory_bytes == 0 and mt.mgr._sessions[b].memory_bytes > 0

    def test_sample_loading_is_scoped_and_marked_as_sample(self, mt):
        a, b = new_session(mt.client), new_session(mt.client)
        res = mt.client.post("/api/sample", headers=h(a))
        assert res.status_code == 200
        assert res.json()["summary"]["metadata"]["isSample"] is True
        assert res.json()["summary"]["summaryStats"]["totalEvents"] > 0
        assert mt.client.get("/api/summary", headers=h(b)).json()["summaryStats"]["totalEvents"] == 0
        assert api.state.df is None
        # reset?sample=true is the same path
        res = mt.client.post("/api/reset", params={"sample": "true"}, headers=h(b))
        assert res.status_code == 200 and res.json()["summary"]["metadata"]["isSample"] is True
        # and a plain reset empties it again
        mt.client.post("/api/reset", headers=h(a))
        assert mt.client.get("/api/summary", headers=h(a)).json()["summaryStats"]["totalEvents"] == 0

    def test_sample_summary_matches_single_tenant_sample(self, mt):
        token = new_session(mt.client)
        mt_summary = mt.client.post("/api/sample", headers=h(token)).json()["summary"]
        mt.monkeypatch.setattr(api, "MULTI_TENANT_SESSIONS", False)
        api.state.reset_to_sample()
        st_summary = mt.client.get("/api/summary").json()
        for key in ("summaryStats", "severityData", "activityData", "topRules"):
            assert mt_summary[key] == st_summary[key]
        assert mt_summary["metadata"]["rowsProcessed"] == st_summary["metadata"]["rowsProcessed"]

    def test_detection_config_is_per_session(self, mt):
        a, b = new_session(mt.client), new_session(mt.client)
        res = mt.client.put("/api/detection/config", json={"brute_force_threshold": 2}, headers=h(a))
        assert res.status_code == 200
        assert mt.client.get("/api/detection/config", headers=h(a)).json()["config"]["brute_force_threshold"] == 2
        assert mt.client.get("/api/detection/config", headers=h(b)).json()["config"]["brute_force_threshold"] == 5
        assert api.state.config.brute_force_threshold == 5

        three_failures = make_csv(3, "192.0.2.50")  # below default threshold (5), above A's (2)
        upload(mt.client, a, three_failures)
        upload(mt.client, b, three_failures)
        a_brute = [x for x in mt.client.get("/api/alerts", headers=h(a)).json()["alerts"] if "BruteForce" in x["rules_matched"]]
        b_brute = [x for x in mt.client.get("/api/alerts", headers=h(b)).json()["alerts"] if "BruteForce" in x["rules_matched"]]
        assert len(a_brute) == 1 and len(b_brute) == 0

    def test_config_validation_leaves_session_config_unchanged(self, mt):
        a = new_session(mt.client)
        for body in ({"brute_force_threshold": 0}, {"brute_force_threshold": True},
                     {"enable_multi_account_changes": "yes"}, {"port_scan_window_seconds": 5}):
            res = mt.client.put("/api/detection/config", json=body, headers=h(a))
            assert res.status_code in (400, 422), body
        assert mt.client.put("/api/detection/config", json={"nope": 1}, headers=h(a)).status_code == 400
        assert mt.client.get("/api/detection/config", headers=h(a)).json()["config"] == api.DetectorConfig.defaults()

    def test_visitors_do_not_need_the_admin_key_to_tune_their_session(self, mt):
        mt.monkeypatch.setattr(api, "ADMIN_API_KEY", "server-side-secret")
        a = new_session(mt.client)
        res = mt.client.put("/api/detection/config", json={"brute_force_threshold": 3}, headers=h(a))
        assert res.status_code == 200

    def test_single_tenant_mode_is_unchanged(self, mt):
        mt.monkeypatch.setattr(api, "MULTI_TENANT_SESSIONS", False)
        res = mt.client.post("/api/analyze", files={"file": ("x.csv", make_csv(8, "192.0.2.10"), "text/csv")})
        assert res.status_code == 200
        assert api.state.df is not None and len(api.state.df) == 8
        assert mt.client.get("/api/summary").json()["summaryStats"]["totalEvents"] == 8


# ── Uploads, limits and accounting ────────────────────────────────────────────

class TestUploadsAndLimits:
    def test_upload_response_shape_and_cached_summary_matches(self, mt):
        token = new_session(mt.client)
        res = upload(mt.client, token, make_csv(8, "192.0.2.10"), "shape.csv")
        body = res.json()
        assert res.status_code == 200
        assert {"success", "filename", "rows_processed", "alerts_detected", "summary", "alerts"} <= set(body)
        assert body["filename"] == "shape.csv" and body["rows_processed"] == 8
        assert mt.client.get("/api/summary", headers=h(token)).json() == body["summary"]
        assert len(mt.client.get("/api/alerts", headers=h(token)).json()["alerts"]) == len(body["alerts"])

    def test_summary_is_computed_once_per_upload_not_per_request(self, mt):
        calls = []
        orig = api.compute_summary
        mt.monkeypatch.setattr(api, "compute_summary", lambda *a, **k: (calls.append(1), orig(*a, **k))[1])
        token = new_session(mt.client)
        upload(mt.client, token, make_csv(8, "192.0.2.10"))
        for _ in range(5):
            assert mt.client.get("/api/summary", headers=h(token)).status_code == 200
        assert len(calls) == 1

    def test_invalid_extension_and_empty_file_rejected(self, mt):
        token = new_session(mt.client)
        assert upload(mt.client, token, b"x", "evil.exe").status_code == 400
        assert upload(mt.client, token, b"", "empty.csv").status_code == 400
        assert upload(mt.client, token, b"x", "a.txt", path="/api/analyze/windows").status_code == 400

    def test_malformed_csv_is_rejected_and_keeps_previous_data(self, mt):
        token = new_session(mt.client)
        upload(mt.client, token, make_csv(8, "192.0.2.10"), "good.csv")
        res = upload(mt.client, token, b"not,a,valid\nlog,file,here\n", "bad.csv")
        assert res.status_code == 400
        assert mt.client.get("/api/summary", headers=h(token)).json()["metadata"]["datasetName"] == "good.csv"
        assert mt.mgr.get_metrics()["reserved_memory_bytes"] == 0

    def test_file_size_limit_413(self, mt):
        token = new_session(mt.client)
        mt.monkeypatch.setattr(api, "MAX_UPLOAD_SIZE_BYTES", 500)
        # Declared length rejected before the body is processed
        res = upload(mt.client, token, make_csv(300, "192.0.2.10"))
        assert res.status_code == 413
        # Streaming backstop (envelope large enough to let the declared length through)
        mt.monkeypatch.setattr(api, "UPLOAD_ENVELOPE_BYTES", 10_000_000)
        res = upload(mt.client, token, make_csv(300, "192.0.2.10"))
        assert res.status_code == 413
        assert "limit" in res.json()["detail"].lower()
        assert mt.mgr.get_metrics()["reserved_memory_bytes"] == 0

    def test_upload_without_content_length_is_refused(self, mt):
        token = new_session(mt.client)
        boundary = "tlboundary"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.csv\"\r\n"
                f"Content-Type: text/csv\r\n\r\n").encode() + make_csv(8, "192.0.2.10") + f"\r\n--{boundary}--\r\n".encode()
        res = mt.client.post(
            "/api/analyze", content=iter([body]),
            headers={HEADER: token, "content-type": f"multipart/form-data; boundary={boundary}"},
        )
        assert res.status_code == 411

    def test_row_limit_enforced_without_changing_session_data(self, mt):
        token = new_session(mt.client)
        upload(mt.client, token, make_csv(8, "192.0.2.10"), "keep.csv")
        mt.monkeypatch.setattr(api, "MAX_UPLOAD_ROWS", 5)
        res = upload(mt.client, token, make_csv(10, "192.0.2.10"))
        assert res.status_code == 400 and "limit of 5 rows" in res.json()["detail"]
        assert mt.client.get("/api/summary", headers=h(token)).json()["metadata"]["datasetName"] == "keep.csv"

    def test_row_limit_is_checked_before_the_expensive_detection_step(self, mt):
        token = new_session(mt.client)
        mt.monkeypatch.setattr(api, "MAX_UPLOAD_ROWS", 5)
        ran = []
        mt.monkeypatch.setattr(api, "run_detection", lambda *a, **k: ran.append(1) or [])
        assert upload(mt.client, token, make_csv(10, "192.0.2.10")).status_code == 400
        assert ran == []

    def test_replacement_upload_replaces_memory_instead_of_accumulating(self, mt):
        token = new_session(mt.client)
        upload(mt.client, token, make_csv(400, "192.0.2.10"))
        big = mt.mgr._sessions[token].memory_bytes
        upload(mt.client, token, make_csv(6, "192.0.2.11"))
        small = mt.mgr._sessions[token].memory_bytes
        assert 0 < small < big
        assert mt.mgr.get_metrics()["committed_memory_bytes"] == small
        assert mt.mgr.get_metrics()["reserved_memory_bytes"] == 0

    def test_per_session_memory_limit_413_keeps_existing_data(self, mt):
        mt.monkeypatch.setattr(api, "session_manager", SessionManager(max_session_memory_mb=1, max_total_memory_mb=50))
        token = new_session(mt.client)
        assert upload(mt.client, token, make_csv(8, "192.0.2.10"), "small.csv").status_code == 200
        too_big = make_csv(30_000, "192.0.2.10")  # ~1.9 MB raw -> estimated well above 1 MB
        res = upload(mt.client, token, too_big, "huge.csv")
        assert res.status_code == 413 and "too large" in res.json()["detail"].lower()
        assert mt.client.get("/api/summary", headers=h(token)).json()["metadata"]["datasetName"] == "small.csv"
        assert api.session_manager.get_metrics()["reserved_memory_bytes"] == 0

    def test_global_memory_budget_returns_503_with_retry_after(self, mt):
        mt.monkeypatch.setattr(api, "session_manager", SessionManager(max_session_memory_mb=5, max_total_memory_mb=1))
        token = new_session(mt.client)
        res = upload(mt.client, token, make_csv(5000, "192.0.2.10"))  # ~300 KB raw -> ~1.5 MB reservation > 1 MB budget
        assert res.status_code == 503
        assert res.headers["retry-after"]
        assert api.session_manager.get_metrics()["reserved_memory_bytes"] == 0

    def test_post_analysis_memory_check_rejects_datasets_that_expand_beyond_the_ceiling(self, mt):
        mt.monkeypatch.setattr(api, "session_manager", SessionManager(max_session_memory_mb=5, max_total_memory_mb=50))
        token = new_session(mt.client)
        # The pre-parse estimate passes, but the real analysed size must also be enforced.
        mt.monkeypatch.setattr(api, "estimate_dataset_memory", lambda df, alerts: 6 * 1024 * 1024)
        res = upload(mt.client, token, make_csv(8, "192.0.2.10"))
        assert res.status_code == 413
        assert api.session_manager.get_metrics()["reserved_memory_bytes"] == 0
        assert api.session_manager.get_metrics()["committed_memory_bytes"] == 0


# ── Concurrency ───────────────────────────────────────────────────────────────

class _Gate:
    """Pauses _parse_and_detect inside the worker thread until released."""

    def __init__(self, monkeypatch):
        self.entered = threading.Event()
        self.release = threading.Event()
        orig = api._parse_and_detect

        def gated(*a, **k):
            self.entered.set()
            assert self.release.wait(15), "gate was never released"
            return orig(*a, **k)

        monkeypatch.setattr(api, "_parse_and_detect", gated)


def _bg(fn):
    box = {}
    t = threading.Thread(target=lambda: box.update(res=fn()))
    t.start()
    return t, box


class TestConcurrency:
    def test_many_visitors_uploading_at_once_stay_isolated(self, mt):
        mt.monkeypatch.setattr(api, "session_manager", SessionManager(max_concurrent_analyses=16, max_sessions=50))
        n = 12
        tokens = [new_session(mt.client) for _ in range(n)]

        def go(i):
            c = TestClient(api.app)
            return upload(c, tokens[i], make_csv(10 + i, f"203.0.113.{i + 1}", f"user{i}"), f"v{i}.csv")

        with ThreadPoolExecutor(max_workers=n) as pool:
            results = list(pool.map(go, range(n)))
        assert [r.status_code for r in results] == [200] * n

        for i, token in enumerate(tokens):
            s = mt.client.get("/api/summary", headers=h(token)).json()
            assert s["metadata"]["datasetName"] == f"v{i}.csv"
            assert s["summaryStats"]["totalEvents"] == 10 + i
            assert [x["ip"] for x in s["suspiciousIPs"]] == [f"203.0.113.{i + 1}"]
            logs = mt.client.get("/api/logs", headers=h(token)).json()
            assert {x["username"] for x in logs["logs"]} == {f"user{i}"}
        m = api.session_manager.get_metrics()
        assert m["reserved_memory_bytes"] == 0 and m["active_sessions"] == n

    def test_analysis_slot_limit_returns_503_then_recovers(self, mt):
        mt.monkeypatch.setattr(api, "session_manager", SessionManager(max_concurrent_analyses=1))
        a, b = new_session(mt.client), new_session(mt.client)
        gate = _Gate(mt.monkeypatch)
        t, box = _bg(lambda: upload(TestClient(api.app), a, make_csv(8, "192.0.2.10")))
        assert gate.entered.wait(10)

        busy = upload(mt.client, b, make_csv(8, "198.51.100.1"))
        assert busy.status_code == 503
        assert busy.headers["retry-after"] == "5"
        assert "busy" in busy.json()["detail"].lower()
        # Resets are cheap and do not need an analysis slot
        assert mt.client.post("/api/reset", headers=h(b)).status_code == 200

        gate.release.set()
        t.join(15)
        assert box["res"].status_code == 200
        assert upload(mt.client, b, make_csv(8, "198.51.100.1")).status_code == 200  # slot freed
        assert api.session_manager.get_metrics()["reserved_memory_bytes"] == 0

    def test_slot_is_released_after_failed_analysis(self, mt):
        mt.monkeypatch.setattr(api, "session_manager", SessionManager(max_concurrent_analyses=1))
        token = new_session(mt.client)
        for _ in range(3):
            assert upload(mt.client, token, b"junk\nrows\n").status_code == 400
        assert upload(mt.client, token, make_csv(8, "192.0.2.10")).status_code == 200

    def test_concurrent_upload_and_reset_on_the_same_session_conflict(self, mt):
        mt.monkeypatch.setattr(api, "SESSION_TXN_TIMEOUT_SECONDS", 0.2)
        token = new_session(mt.client)
        gate = _Gate(mt.monkeypatch)
        t, box = _bg(lambda: upload(TestClient(api.app), token, make_csv(8, "192.0.2.10"), "first.csv"))
        assert gate.entered.wait(10)

        assert mt.client.post("/api/reset", headers=h(token)).status_code == 409
        second = upload(mt.client, token, make_csv(9, "192.0.2.11"), "second.csv")
        assert second.status_code == 409
        assert "in progress" in second.json()["detail"].lower()

        gate.release.set()
        t.join(15)
        assert box["res"].status_code == 200
        assert mt.client.get("/api/summary", headers=h(token)).json()["metadata"]["datasetName"] == "first.csv"
        assert api.session_manager.get_metrics()["reserved_memory_bytes"] == 0

    def test_session_deleted_mid_analysis_is_never_resurrected(self, mt):
        token = new_session(mt.client)
        gate = _Gate(mt.monkeypatch)
        t, box = _bg(lambda: upload(TestClient(api.app), token, make_csv(8, "192.0.2.10")))
        assert gate.entered.wait(10)
        assert mt.client.delete("/api/session", headers=h(token)).json()["deleted"] is True
        gate.release.set()
        t.join(15)
        assert box["res"].status_code == 401
        assert mt.client.get("/api/summary", headers=h(token)).status_code == 401
        m = api.session_manager.get_metrics()
        assert m["active_sessions"] == 0 and m["reserved_memory_bytes"] == 0 and m["committed_memory_bytes"] == 0

    def test_event_loop_stays_responsive_while_an_upload_is_analysed(self, mt):
        token = new_session(mt.client)
        orig = api._parse_and_detect

        def slow(*a, **k):
            time.sleep(1.2)  # stand-in for heavy parsing/detection
            return orig(*a, **k)

        mt.monkeypatch.setattr(api, "_parse_and_detect", slow)
        with TestClient(api.app) as shared:  # one event loop shared by both threads
            t, box = _bg(lambda: upload(shared, token, make_csv(8, "192.0.2.10")))
            time.sleep(0.3)
            start = time.time()
            assert shared.get("/api/health").status_code == 200
            health_latency = time.time() - start
            t.join(15)
        assert box["res"].status_code == 200
        assert health_latency < 0.6, f"health blocked for {health_latency:.2f}s during analysis"


# ── Emergency read-only protection ────────────────────────────────────────────

class TestReadOnlyKillSwitch:
    @pytest.fixture
    def ro(self, mt):
        mt.monkeypatch.setattr(api, "PORTFOLIO_READ_ONLY", True)
        return mt

    def test_health_reports_uploads_disabled(self, ro):
        body = ro.client.get("/api/health").json()
        assert body["read_only"] is True and body["uploads_enabled"] is False
        assert body["mode"] == "portfolio_read_only" and body["multi_tenant"] is True

    def test_all_writes_blocked_even_with_a_valid_session(self, ro):
        token = new_session(ro.client)  # sessions can still be issued (reads are fine)
        csv = make_csv(8, "192.0.2.10")
        assert upload(ro.client, token, csv).status_code == 403
        assert upload(ro.client, token, (DATA_DIR / "sample_windows_security_log.csv").read_bytes(),
                      path="/api/analyze/windows").status_code == 403
        assert ro.client.post("/api/reset", headers=h(token)).status_code == 403
        assert ro.client.post("/api/reset", params={"sample": "true"}, headers=h(token)).status_code == 403
        assert ro.client.post("/api/sample", headers=h(token)).status_code == 403
        assert ro.client.put("/api/detection/config", json={"brute_force_threshold": 3}, headers=h(token)).status_code == 403
        assert ro.mgr._sessions[token].df is None

    def test_reads_still_work(self, ro):
        token = new_session(ro.client)
        for path in ("/api/summary", "/api/alerts", "/api/logs", "/api/detection/config"):
            assert ro.client.get(path, headers=h(token)).status_code == 200

    def test_flipping_the_switch_blocks_new_uploads_but_keeps_existing_data_readable(self, mt):
        token = new_session(mt.client)
        assert upload(mt.client, token, make_csv(8, "192.0.2.10")).status_code == 200
        mt.monkeypatch.setattr(api, "PORTFOLIO_READ_ONLY", True)
        assert upload(mt.client, token, make_csv(9, "192.0.2.11")).status_code == 403
        assert mt.client.get("/api/summary", headers=h(token)).json()["summaryStats"]["totalEvents"] == 8

    def test_admin_key_can_write_but_only_into_its_own_session(self, ro):
        ro.monkeypatch.setattr(api, "ADMIN_API_KEY", "admin-secret")
        admin, visitor = new_session(ro.client), new_session(ro.client)
        res = ro.client.post("/api/analyze", files={"file": ("a.csv", make_csv(8, "192.0.2.10"), "text/csv")},
                             headers={**h(admin), "X-Admin-Key": "admin-secret"})
        assert res.status_code == 200
        assert ro.client.get("/api/summary", headers=h(visitor)).json()["summaryStats"]["totalEvents"] == 0
        assert api.state.df is None
        wrong = ro.client.post("/api/analyze", files={"file": ("a.csv", make_csv(8, "192.0.2.10"), "text/csv")},
                               headers={**h(visitor), "X-Admin-Key": "wrong"})
        assert wrong.status_code == 403

    def test_read_only_without_sessions_is_unchanged(self, ro):
        ro.monkeypatch.setattr(api, "MULTI_TENANT_SESSIONS", False)
        res = ro.client.post("/api/analyze", files={"file": ("a.csv", make_csv(8, "192.0.2.10"), "text/csv")})
        assert res.status_code == 403
        assert api.state.df is None


class TestWriteProtectionGuardRail:
    @pytest.mark.parametrize("read_only,multi,public,allow,expected", [
        (False, False, True, False, (True, True)),    # public host, shared global, writable -> forced read-only
        (False, True, True, False, (False, False)),   # per-visitor sessions make writes safe
        (True, False, True, False, (True, False)),
        (True, True, True, False, (True, False)),
        (False, False, True, True, (False, False)),   # explicit operator override
        (False, False, False, False, (False, False)), # local development
    ])
    def test_resolve_write_protection(self, read_only, multi, public, allow, expected):
        assert api.resolve_write_protection(read_only, multi, public, allow) == expected

    @staticmethod
    def _flags(**env):
        base = {k: v for k, v in os.environ.items()
                if k not in ("RENDER", "PORTFOLIO_READ_ONLY", "PUBLIC_DEMO_MODE", "MULTI_TENANT_SESSIONS", "ALLOW_SHARED_GLOBAL_STATE")}
        base.update(env)
        out = subprocess.run(
            [sys.executable, "-c", "import backend.api as a; print(a.PORTFOLIO_READ_ONLY, a.MULTI_TENANT_SESSIONS)"],
            capture_output=True, text=True, env=base, cwd=Path(__file__).resolve().parents[2], timeout=120,
        )
        assert out.returncode == 0, out.stderr
        return out.stdout.strip().splitlines()[-1]

    def test_render_with_only_read_only_false_is_forced_read_only_at_startup(self):
        assert self._flags(RENDER="true", PORTFOLIO_READ_ONLY="false") == "True False"

    def test_render_with_sessions_enabled_allows_uploads_at_startup(self):
        assert self._flags(RENDER="true", PORTFOLIO_READ_ONLY="false", MULTI_TENANT_SESSIONS="true") == "False True"

    def test_local_default_is_unchanged(self):
        assert self._flags() == "False False"


# ── Rate limiting and client IP ───────────────────────────────────────────────

class TestRateLimitingClientIp:
    @pytest.fixture
    def limited(self, mt):
        mt.monkeypatch.setattr(api, "_is_test_client", lambda request: False)
        mt.monkeypatch.setattr(api, "RATE_LIMIT_ENABLED", True)
        mt.monkeypatch.setattr(api, "rate_limiter", api.SlidingWindowRateLimiter(default_limit=3, upload_limit=2, session_limit=2))
        mt.monkeypatch.setattr(api, "CLIENT_IP_HEADER", "")
        return mt

    def test_spoofed_x_forwarded_for_cannot_evade_or_bypass_the_limit(self, limited):
        statuses = []
        for i in range(6):
            headers = {"X-Forwarded-For": "testclient" if i == 0 else f"203.0.113.{i}"}  # rotating + the old magic value
            statuses.append(limited.client.get("/api/health", headers=headers).status_code)
        assert statuses[:3] == [200, 200, 200]
        assert set(statuses[3:]) == {429}

    def test_429_includes_retry_after(self, limited):
        for _ in range(3):
            limited.client.get("/api/health")
        res = limited.client.get("/api/health")
        assert res.status_code == 429 and int(res.headers["retry-after"]) >= 1

    def test_session_creation_has_its_own_tighter_limit(self, limited):
        assert [limited.client.post("/api/session").status_code for _ in range(3)] == [201, 201, 429]

    def test_trusted_client_ip_header_separates_visitors(self, limited):
        limited.monkeypatch.setattr(api, "CLIENT_IP_HEADER", "true-client-ip")
        for _ in range(3):
            assert limited.client.get("/api/health", headers={"True-Client-IP": "198.51.100.1"}).status_code == 200
        assert limited.client.get("/api/health", headers={"True-Client-IP": "198.51.100.1"}).status_code == 429
        assert limited.client.get("/api/health", headers={"True-Client-IP": "198.51.100.2"}).status_code == 200

    def test_test_client_detection_ignores_headers(self, limited):
        # A header claiming to be the test client must not switch rate limiting off.
        limited.monkeypatch.undo()
        limited.monkeypatch.setattr(api, "MULTI_TENANT_SESSIONS", True)
        scope = {"type": "http", "headers": [(b"x-forwarded-for", b"testclient")], "client": ("203.0.113.9", 1234)}
        from starlette.requests import Request
        assert api._is_test_client(Request(scope)) is False
        assert api._is_test_client(Request({**scope, "client": ("testclient", 5)})) is True

    def test_limiter_memory_is_bounded_and_new_ips_are_still_limited(self):
        limiter = api.SlidingWindowRateLimiter(default_limit=1)
        for i in range(2500):
            limiter.is_allowed(f"10.0.{i // 250}.{i % 250}")
        assert len(limiter._stores["default"]) <= 2500  # sweep only drops quiet keys; all are still active
        # An IP seen after the table is large is still tracked (previously its history was discarded)
        assert limiter.is_allowed("192.0.2.200")[0] is True
        assert limiter.is_allowed("192.0.2.200")[0] is False


# ── CORS for the session header ───────────────────────────────────────────────

class TestCorsSessionHeader:
    def test_preflight_allows_session_header_for_the_configured_frontend_origin(self, mt):
        origin = "http://localhost:5173"
        res = mt.client.options(
            "/api/summary",
            headers={"Origin": origin, "Access-Control-Request-Method": "GET",
                     "Access-Control-Request-Headers": "x-session-id"},
        )
        assert res.status_code == 200
        assert res.headers["access-control-allow-origin"] == origin
        assert "x-session-id" in res.headers["access-control-allow-headers"].lower()

    def test_preflight_is_refused_for_unknown_origins(self, mt):
        res = mt.client.options(
            "/api/summary",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET",
                     "Access-Control-Request-Headers": "x-session-id"},
        )
        assert res.headers.get("access-control-allow-origin") != "https://evil.example"


# ── Cross-session isolation regression test ───────────────────────────────────

class TestCrossSessionDataIsolation:
    """Regression test: verify two independent browser sessions never leak data."""

    def test_independent_sessions_cannot_see_each_others_uploaded_data(self, mt):
        # 1. Issue Session A and Session B tokens
        token_a = new_session(mt.client)
        token_b = new_session(mt.client)
        assert token_a != token_b

        # 2. Session A uploads 20 rows of security logs
        csv_data = make_csv(failures=20, ip="198.51.100.42", user="admin")
        upload_res = upload(mt.client, token_a, csv_data, name="threatlens_live_engine_test.csv")
        assert upload_res.status_code == 200
        assert upload_res.json()["rows_processed"] == 20

        # 3. Verify Session A sees its uploaded data
        summary_a = mt.client.get("/api/summary", headers=h(token_a)).json()
        logs_a = mt.client.get("/api/logs", headers=h(token_a)).json()
        alerts_a = mt.client.get("/api/alerts", headers=h(token_a)).json()

        assert summary_a["summaryStats"]["totalEvents"] == 20
        assert len(logs_a["logs"]) == 20
        assert len(alerts_a["alerts"]) > 0

        # 4. Verify Session B receives an empty dataset and cannot access Session A's records
        summary_b = mt.client.get("/api/summary", headers=h(token_b)).json()
        logs_b = mt.client.get("/api/logs", headers=h(token_b)).json()
        alerts_b = mt.client.get("/api/alerts", headers=h(token_b)).json()

        assert summary_b["summaryStats"]["totalEvents"] == 0
        assert summary_b["metadata"]["rowsProcessed"] == 0
        assert len(logs_b["logs"]) == 0
        assert len(alerts_b["alerts"]) == 0

        # 5. Verify unauthenticated requests (no session header) receive 401
        assert mt.client.get("/api/summary").status_code == 401
        assert mt.client.get("/api/logs").status_code == 401
        assert mt.client.get("/api/alerts").status_code == 401

    def test_session_deletion_and_recovery_contract(self, mt):
        """Verify the contract used by the frontend to detect session expiry and recover."""
        # 1. User creates session and uploads CSV
        token = new_session(mt.client)
        csv_data = make_csv(failures=10, ip="192.0.2.1", user="bob")
        upload_res = upload(mt.client, token, csv_data)
        assert upload_res.status_code == 200

        # 2. Delete session (simulates user or idle expiry)
        del_res = mt.client.delete("/api/session", headers=h(token))
        assert del_res.status_code == 200
        assert del_res.json() == {"success": True, "deleted": True}

        # 3. Request with deleted session token returns 401 with invalid/expired message
        res = mt.client.get("/api/summary", headers=h(token))
        assert res.status_code == 401
        assert "expired" in res.json()["detail"].lower()

        # 4. Client creates fresh session (recovering from 401)
        recovered_token = new_session(mt.client)
        assert recovered_token != token

        # 5. Recovered session is clean and empty (0 rows, 0 alerts)
        recovered_summary = mt.client.get("/api/summary", headers=h(recovered_token)).json()
        assert recovered_summary["summaryStats"]["totalEvents"] == 0
        assert recovered_summary["metadata"]["rowsProcessed"] == 0


