"""
ThreatLens – Tests for Windows Security Event Log Importer (Phase 5)
=====================================================================
Covers:
- load_windows_log() CSV parsing and schema normalization
- Event ID mapping across all 10 supported Windows event IDs
- Handling of skipped unsupported event IDs
- Extraction of IPv4 and username from Description
- Semicolon-delimited file support
- Error handling (empty file, missing columns, bad timestamps)
- Import report accuracy (total, imported, skipped, rejected)
- Integration with detection engine (AccountCreated, AccountDeleted,
  GroupMemberAdded, AuditLogCleared, PrivEsc, LogonAfterBruteForce)
- FastAPI endpoints: /api/analyze/windows, /api/windows/supported-events
"""

import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.api import app
from backend.windows_log_importer import (
    EVENT_ID_MAP,
    WindowsImportReport,
    get_supported_event_ids,
    is_windows_log,
    load_windows_log,
)
from backend.detector import DetectorConfig, run_detection

client = TestClient(app)
SAMPLE_WIN_CSV_PATH = Path(__file__).parent.parent / "data" / "sample_windows_security_log.csv"


# ── Sample Data Fixtures ──────────────────────────────────────────────────────

SAMPLE_WIN_CSV = (
    "Level,Date and Time,Source,Event ID,Task Category,Computer,User,Description\n"
    "Information,2026-10-25 08:00:00,Microsoft-Windows-Security-Auditing,4625,Logon,DC01.corp.local,SYSTEM,\"An account failed to log on. Subject: Account Name: - Account For Which Logon Failed: Account Name: Administrator Network Information: Source Network Address: 198.51.100.24\"\n"
    "Information,2026-10-25 08:00:05,Microsoft-Windows-Security-Auditing,4625,Logon,DC01.corp.local,SYSTEM,\"An account failed to log on. Subject: Account Name: - Account For Which Logon Failed: Account Name: Administrator Network Information: Source Network Address: 198.51.100.24\"\n"
    "Information,2026-10-25 08:00:10,Microsoft-Windows-Security-Auditing,4625,Logon,DC01.corp.local,SYSTEM,\"An account failed to log on. Subject: Account Name: - Account For Which Logon Failed: Account Name: Administrator Network Information: Source Network Address: 198.51.100.24\"\n"
    "Information,2026-10-25 08:00:20,Microsoft-Windows-Security-Auditing,4624,Logon,DC01.corp.local,Administrator,\"An account was successfully logged on. New Logon: Account Name: Administrator Network Information: Source Network Address: 198.51.100.24\"\n"
    "Information,2026-10-25 08:00:22,Microsoft-Windows-Security-Auditing,4672,Special Logon,DC01.corp.local,Administrator,\"Special privileges assigned to new logon. Account Name: Administrator Privileges: SeDebugPrivilege\"\n"
    "Information,2026-10-25 08:01:00,Microsoft-Windows-Security-Auditing,4720,User Account Management,DC01.corp.local,Administrator,\"A user account was created. Target Account Name: backdoor_adm\"\n"
    "Information,2026-10-25 08:01:30,Microsoft-Windows-Security-Auditing,4732,Security Group Management,DC01.corp.local,Administrator,\"A member was added to a security-enabled local group. Target Account Name: backdoor_adm\"\n"
    "Information,2026-10-25 08:02:00,Microsoft-Windows-Security-Auditing,4688,Process Creation,DC01.corp.local,Administrator,\"New Process Name: C:\\Windows\\System32\\cmd.exe\"\n"
    "Information,2026-10-25 08:03:00,Microsoft-Windows-Security-Auditing,4648,Logon,DC01.corp.local,Administrator,\"A logon was attempted using explicit credentials. Account Name: Administrator\"\n"
    "Information,2026-10-25 08:04:00,Microsoft-Windows-Security-Auditing,4726,User Account Management,DC01.corp.local,Administrator,\"A user account was deleted. Target Account Name: temp_user\"\n"
    "Audit Success,2026-10-25 08:05:00,Microsoft-Windows-Eventlog,1102,Log clear,DC01.corp.local,Administrator,\"The audit log was cleared.\"\n"
    "Information,2026-10-25 08:06:00,Microsoft-Windows-Security-Auditing,4634,Logoff,DC01.corp.local,Administrator,\"An account was logged off. Account Name: Administrator\"\n"
    "Information,2026-10-25 08:07:00,Microsoft-Windows-Security-Auditing,5058,Other,DC01.corp.local,SYSTEM,\"Unsupported noise event 5058\"\n"
)


# ── Test Suite 1: Log Parser & Normalization ───────────────────────────────────

class TestWindowsLogParser:
    def test_is_windows_log_detection(self):
        assert is_windows_log(io.StringIO(SAMPLE_WIN_CSV)) is True
        native_csv = "timestamp,source_ip,event_type,username,status\n2026-10-20,1.2.3.4,LOGIN_SUCCESS,u,SUCCESS\n"
        assert is_windows_log(io.StringIO(native_csv)) is False

    def test_load_valid_windows_csv(self):
        df, report = load_windows_log(io.StringIO(SAMPLE_WIN_CSV))
        assert not df.empty
        # 13 rows total: 12 supported, 1 unsupported (5058)
        assert report.total_rows == 13
        assert report.imported_rows == 12
        assert report.skipped_rows == 1
        assert 5058 in report.unsupported_ids
        assert set(df.columns).issuperset({"timestamp", "source_ip", "event_type", "username", "status"})

    def test_all_ten_supported_event_ids_normalized(self):
        df, _ = load_windows_log(io.StringIO(SAMPLE_WIN_CSV))
        event_types = set(df["event_type"].unique())
        expected = {
            "LOGIN_FAILURE",        # 4625
            "LOGIN_SUCCESS",        # 4624
            "PRIVILEGE_ESCALATION", # 4672
            "ACCOUNT_CREATED",      # 4720
            "GROUP_MEMBER_ADDED",   # 4732
            "PROCESS_CREATED",      # 4688
            "EXPLICIT_CRED_LOGON",  # 4648
            "ACCOUNT_DELETED",      # 4726
            "AUDIT_LOG_CLEARED",    # 1102
            "LOGOFF",               # 4634
        }
        assert expected.issubset(event_types)

    def test_ip_extracted_from_description(self):
        df, _ = load_windows_log(io.StringIO(SAMPLE_WIN_CSV))
        # Rows with 198.51.100.24
        ips = df["source_ip"].tolist()
        assert "198.51.100.24" in ips

    def test_username_extracted_when_user_is_generic(self):
        # 4625 had User='SYSTEM', but Description had 'Account Name: Administrator'
        df, _ = load_windows_log(io.StringIO(SAMPLE_WIN_CSV))
        f_row = df[df["event_type"] == "LOGIN_FAILURE"].iloc[0]
        assert f_row["username"] == "Administrator"

    def test_semicolon_delimited_csv(self):
        semi_csv = (
            "Level;Date and Time;Source;Event ID;Task Category;User;Description\n"
            "Information;2026-10-25 09:00:00;Security;4624;Logon;alice;Successful logon\n"
        )
        df, report = load_windows_log(io.StringIO(semi_csv))
        assert len(df) == 1
        assert df["event_type"].iloc[0] == "LOGIN_SUCCESS"
        assert df["username"].iloc[0] == "alice"

    def test_minimal_headers_without_optional_columns(self):
        # Windows export with only Date and Time and Event ID
        minimal_csv = (
            "Date and Time,Event ID\n"
            "2026-10-25 10:00:00,4624\n"
            "2026-10-25 10:01:00,4625\n"
        )
        df, report = load_windows_log(io.StringIO(minimal_csv))
        assert len(df) == 2
        assert report.imported_rows == 2
        assert df["source_ip"].iloc[0] == "0.0.0.0"

    def test_reject_empty_csv(self):
        with pytest.raises(ValueError, match="empty or contains no data"):
            load_windows_log(io.StringIO(""))

    def test_reject_missing_required_columns(self):
        bad_csv = "Source,Level,User\nSecurity,Info,alice\n"
        with pytest.raises(ValueError, match="missing required columns"):
            load_windows_log(io.StringIO(bad_csv))

    def test_reject_when_no_supported_events(self):
        unsupported_csv = (
            "Date and Time,Event ID\n"
            "2026-10-25 10:00:00,9999\n"
            "2026-10-25 10:01:00,8888\n"
        )
        with pytest.raises(ValueError, match="No rows matched the supported Windows Security event IDs"):
            load_windows_log(io.StringIO(unsupported_csv))

    def test_unparseable_rows_rejected_and_reported(self):
        dirty_csv = (
            "Date and Time,Event ID\n"
            "NOT_A_TIMESTAMP,4624\n"
            "2026-10-25 10:00:00,NOT_AN_ID\n"
            "2026-10-25 10:00:00,4624\n"
        )
        df, report = load_windows_log(io.StringIO(dirty_csv))
        assert len(df) == 1
        assert report.rejected_rows == 2
        assert len(report.warnings) == 2

    def test_load_sample_file_from_disk(self):
        assert SAMPLE_WIN_CSV_PATH.exists()
        df, report = load_windows_log(SAMPLE_WIN_CSV_PATH)
        assert len(df) >= 10
        assert report.imported_rows >= 10
        assert report.skipped_rows >= 1


# ── Test Suite 2: Detection Engine on Windows Logs ─────────────────────────────

class TestWindowsDetectionRules:
    def test_detect_audit_log_cleared_critical(self):
        csv_data = (
            "Date and Time,Event ID,User\n"
            "2026-10-25 12:00:00,1102,Administrator\n"
        )
        df, _ = load_windows_log(io.StringIO(csv_data))
        alerts = run_detection(df)
        assert any("AuditLogCleared" in a.rules_matched for a in alerts)
        audit_alert = next(a for a in alerts if "AuditLogCleared" in a.rules_matched)
        assert audit_alert.severity == "Critical"

    def test_detect_account_created_and_deleted(self):
        csv_data = (
            "Date and Time,Event ID,User\n"
            "2026-10-25 12:00:00,4720,bad_user\n"
            "2026-10-25 12:05:00,4726,bad_user\n"
        )
        df, _ = load_windows_log(io.StringIO(csv_data))
        alerts = run_detection(df)
        rules = {r for a in alerts for r in a.rules_matched}
        assert "AccountCreated" in rules
        assert "AccountDeleted" in rules

    def test_detect_group_member_added(self):
        csv_data = (
            "Date and Time,Event ID,User\n"
            "2026-10-25 12:00:00,4732,target_user\n"
        )
        df, _ = load_windows_log(io.StringIO(csv_data))
        alerts = run_detection(df)
        assert any("GroupMemberAdded" in a.rules_matched for a in alerts)

    def test_detect_logon_after_brute_force(self):
        # 3 failures followed by success within 300s from same IP
        csv_data = (
            "Date and Time,Event ID,User,Description\n"
            "2026-10-25 12:00:00,4625,SYSTEM,\"Source Network Address: 203.0.113.77\"\n"
            "2026-10-25 12:00:05,4625,SYSTEM,\"Source Network Address: 203.0.113.77\"\n"
            "2026-10-25 12:00:10,4625,SYSTEM,\"Source Network Address: 203.0.113.77\"\n"
            "2026-10-25 12:00:15,4624,Administrator,\"Source Network Address: 203.0.113.77\"\n"
        )
        df, _ = load_windows_log(io.StringIO(csv_data))
        alerts = run_detection(df)
        assert any("LogonAfterBruteForce" in a.rules_matched for a in alerts)
        corr_alert = next(a for a in alerts if "LogonAfterBruteForce" in a.rules_matched)
        assert corr_alert.severity == "High"
        assert corr_alert.source_ip == "203.0.113.77"

    def test_detect_suspicious_account_lifecycle(self):
        # Account created then immediately assigned to group within 900s
        csv_data = (
            "Date and Time,Event ID,User,Description\n"
            "2026-10-25 12:00:00,4720,backdoor_adm,\"A user account was created\"\n"
            "2026-10-25 12:01:00,4732,backdoor_adm,\"Member added to Administrators group\"\n"
        )
        df, _ = load_windows_log(io.StringIO(csv_data))
        alerts = run_detection(df)
        assert any("SuspiciousAccountLifecycle" in a.rules_matched for a in alerts)

    def test_sample_windows_log_produces_alerts(self):
        df, report = load_windows_log(SAMPLE_WIN_CSV_PATH)
        alerts = run_detection(df)
        assert len(alerts) >= 3
        # Check critical alert present (AuditLogCleared or PrivEsc)
        assert any(a.severity == "Critical" for a in alerts)


# ── Test Suite 3: FastAPI Endpoints ───────────────────────────────────────────

class TestWindowsApiEndpoints:
    def test_get_windows_supported_events(self):
        resp = client.get("/api/windows/supported-events")
        assert resp.status_code == 200
        data = resp.json()
        assert "supported_event_ids" in data
        assert len(data["supported_event_ids"]) == 10
        assert 4624 in data["supported_event_ids"]
        assert 1102 in data["supported_event_ids"]

    def test_analyze_windows_endpoint_success(self):
        files = {"file": ("win_log.csv", io.BytesIO(SAMPLE_WIN_CSV.encode("utf-8")), "text/csv")}
        resp = client.post("/api/analyze/windows", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["format"] == "windows_event_viewer"
        assert data["rows_processed"] == 12
        assert data["alerts_detected"] >= 2
        assert "import_report" in data
        assert data["import_report"]["total_rows"] == 13
        assert data["import_report"]["skipped_rows"] == 1

    def test_analyze_windows_endpoint_rejects_non_csv(self):
        files = {"file": ("win_log.evtx", io.BytesIO(b"binary evtx content"), "application/octet-stream")}
        resp = client.post("/api/analyze/windows", files=files)
        assert resp.status_code == 400
        assert "Only Windows Event Viewer CSV exports" in resp.json()["detail"]

    def test_analyze_windows_endpoint_rejects_empty_file(self):
        files = {"file": ("empty.csv", io.BytesIO(b""), "text/csv")}
        resp = client.post("/api/analyze/windows", files=files)
        assert resp.status_code == 400
        assert "empty" in resp.json()["detail"].lower()

    def test_auto_detect_windows_format_in_generic_analyze(self):
        # POST to /api/analyze with Windows CSV should auto-detect and return import report
        files = {"file": ("win_log_auto.csv", io.BytesIO(SAMPLE_WIN_CSV.encode("utf-8")), "text/csv")}
        resp = client.post("/api/analyze", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["format"] == "windows_event_viewer"
        assert "import_report" in data

    def test_logs_endpoint_includes_windows_event_id(self):
        # After Windows upload, /api/logs should contain win_event_id
        files = {"file": ("win_log.csv", io.BytesIO(SAMPLE_WIN_CSV.encode("utf-8")), "text/csv")}
        client.post("/api/analyze/windows", files=files)
        resp = client.get("/api/logs")
        assert resp.status_code == 200
        logs = resp.json()["logs"]
        assert len(logs) > 0
        # Check that at least one entry has win_event_id
        assert any("win_event_id" in entry for entry in logs)

    def test_summary_includes_log_format_and_import_report(self):
        files = {"file": ("win_log.csv", io.BytesIO(SAMPLE_WIN_CSV.encode("utf-8")), "text/csv")}
        client.post("/api/analyze/windows", files=files)
        resp = client.get("/api/summary")
        assert resp.status_code == 200
        meta = resp.json()["metadata"]
        assert meta["logFormat"] == "windows_event_viewer"
        assert meta["importReport"]["total_rows"] == 13
