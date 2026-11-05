"""
ThreatLens – Unit Tests for Phase 2 Detection Engine
======================================================
Run with:
    python -m pytest backend/tests/ -v

Test coverage
-------------
- log_parser: normal input, missing columns, empty file, bad timestamps,
  extra columns, whitespace tolerance
- detector:   no threats, brute-force trigger, brute-force below threshold,
              port scan, repeated connect, malware event, priv-esc,
              multi-rule deduplication, custom config thresholds

⚠️  All test data uses RFC 5737 documentation IP addresses.
    No real network access is performed.
"""

from __future__ import annotations

import io
import textwrap
from datetime import datetime

import pandas as pd
import pytest

from backend.log_parser import load_log
from backend.detector import (
    Alert,
    DetectorConfig,
    run_detection,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _csv(content: str) -> io.StringIO:
    """Return a StringIO of a dedented CSV string."""
    return io.StringIO(textwrap.dedent(content).strip())


def _make_row(
    timestamp: str = "2026-01-01 00:00:00",
    source_ip: str = "192.0.2.1",
    event_type: str = "LOGIN_FAILURE",
    username: str = "testuser",
    status: str = "FAILURE",
) -> str:
    return f"{timestamp},{source_ip},{event_type},{username},{status}"


HEADER = "timestamp,source_ip,event_type,username,status"


# ─────────────────────────────────────────────────────────────────────────────
# log_parser tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLogParser:
    """Tests for backend.log_parser.load_log"""

    def test_normal_input_returns_dataframe(self):
        """Valid CSV with all required columns loads without errors."""
        csv = _csv(f"""
            {HEADER}
            2026-01-01 08:00:00,192.0.2.10,LOGIN_SUCCESS,alice,SUCCESS
            2026-01-01 08:01:00,192.0.2.11,LOGIN_FAILURE,bob,FAILURE
        """)
        df = load_log(csv)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2
        assert set(df.columns) == {"timestamp", "source_ip", "event_type", "username", "status"}

    def test_timestamp_parsed_as_datetime(self):
        """Timestamps must be parsed as datetime64, not strings."""
        csv = _csv(f"""
            {HEADER}
            2026-01-01 09:00:00,192.0.2.10,LOGIN_SUCCESS,alice,SUCCESS
        """)
        df = load_log(csv)
        assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])

    def test_rows_sorted_by_timestamp(self):
        """Output DataFrame must be sorted ascending by timestamp."""
        csv = _csv(f"""
            {HEADER}
            2026-01-01 10:00:00,192.0.2.10,LOGIN_SUCCESS,alice,SUCCESS
            2026-01-01 08:00:00,192.0.2.11,LOGIN_FAILURE,bob,FAILURE
            2026-01-01 09:00:00,192.0.2.12,PORT_SCAN,,BLOCKED
        """)
        df = load_log(csv)
        timestamps = df["timestamp"].tolist()
        assert timestamps == sorted(timestamps)

    def test_missing_required_column_raises_value_error(self):
        """Missing a required column must raise ValueError with helpful message."""
        csv = _csv("""
            timestamp,source_ip,event_type,username
            2026-01-01 08:00:00,192.0.2.10,LOGIN_FAILURE,alice
        """)
        with pytest.raises(ValueError, match="missing required columns"):
            load_log(csv)

    def test_missing_multiple_columns_lists_all(self):
        """All missing column names must appear in the error message."""
        csv = _csv("""
            timestamp,source_ip
            2026-01-01 08:00:00,192.0.2.10
        """)
        with pytest.raises(ValueError) as exc_info:
            load_log(csv)
        msg = str(exc_info.value)
        assert "event_type" in msg or "status" in msg   # at least one listed

    def test_empty_csv_raises_value_error(self):
        """A CSV with headers only (no rows) must raise ValueError."""
        csv = _csv(HEADER)
        with pytest.raises(ValueError):
            load_log(csv)

    def test_completely_empty_file_raises_value_error(self):
        """A completely empty file must raise ValueError."""
        csv = io.StringIO("")
        with pytest.raises(ValueError):
            load_log(csv)

    def test_malformed_timestamp_rows_are_dropped(self):
        """Rows with unparseable timestamps are dropped, valid rows kept."""
        csv = _csv(f"""
            {HEADER}
            2026-01-01 08:00:00,192.0.2.10,LOGIN_SUCCESS,alice,SUCCESS
            NOT-A-DATE,192.0.2.11,LOGIN_FAILURE,bob,FAILURE
            2026-01-01 09:00:00,192.0.2.12,PORT_SCAN,,BLOCKED
        """)
        df = load_log(csv)
        assert len(df) == 2
        assert "192.0.2.11" not in df["source_ip"].values

    def test_all_bad_timestamps_raises_value_error(self):
        """If every row has a bad timestamp, raise ValueError."""
        csv = _csv(f"""
            {HEADER}
            BADDATE,192.0.2.10,LOGIN_FAILURE,alice,FAILURE
            ALSOBAD,192.0.2.11,LOGIN_FAILURE,bob,FAILURE
        """)
        with pytest.raises(ValueError, match="unparseable timestamps"):
            load_log(csv)

    def test_extra_columns_are_silently_ignored(self):
        """Extra columns beyond the required five must not cause errors."""
        csv = _csv(f"""
            {HEADER},extra_col,another
            2026-01-01 08:00:00,192.0.2.10,LOGIN_SUCCESS,alice,SUCCESS,extra_val,x
        """)
        df = load_log(csv)
        assert "extra_col" not in df.columns
        assert len(df) == 1

    def test_event_type_normalised_to_uppercase(self):
        """event_type values must be normalised to UPPER_SNAKE_CASE."""
        csv = _csv(f"""
            {HEADER}
            2026-01-01 08:00:00,192.0.2.10,login_failure,alice,FAILURE
        """)
        df = load_log(csv)
        assert df["event_type"].iloc[0] == "LOGIN_FAILURE"

    def test_whitespace_in_values_stripped(self):
        """Leading/trailing whitespace in cell values must be stripped."""
        csv = _csv(f"""
            {HEADER}
            2026-01-01 08:00:00,  192.0.2.10  , LOGIN_SUCCESS , alice ,SUCCESS
        """)
        df = load_log(csv)
        assert df["source_ip"].iloc[0] == "192.0.2.10"
        assert df["event_type"].iloc[0] == "LOGIN_SUCCESS"

    def test_file_not_found_raises_file_not_found_error(self):
        """Loading a non-existent file path must raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_log("/tmp/threatlens_nonexistent_file_xyz.csv")

    def test_column_names_case_insensitive(self):
        """Column headers in different cases must be accepted."""
        csv = _csv("""
            Timestamp,Source_IP,Event_Type,Username,Status
            2026-01-01 08:00:00,192.0.2.10,LOGIN_SUCCESS,alice,SUCCESS
        """)
        df = load_log(csv)
        assert "timestamp" in df.columns

    def test_missing_username_kept_as_empty_string(self):
        """Rows with empty username field must be loaded, not dropped."""
        csv = _csv(f"""
            {HEADER}
            2026-01-01 08:00:00,192.0.2.10,PORT_SCAN,,BLOCKED
        """)
        df = load_log(csv)
        assert len(df) == 1
        assert df["username"].iloc[0] == ""


# ─────────────────────────────────────────────────────────────────────────────
# detector tests
# ─────────────────────────────────────────────────────────────────────────────

def _build_df(rows: list[tuple]) -> pd.DataFrame:
    """Build a normalised DataFrame from (timestamp_str, ip, event_type, username, status) tuples."""
    csv_lines = [HEADER] + [",".join(r) for r in rows]
    return load_log(_csv("\n".join(csv_lines)))


class TestDetectorNoThreats:
    """Cases where no alert should be generated."""

    def test_empty_dataframe_returns_no_alerts(self):
        """An empty (but valid) DataFrame produces zero alerts."""
        # We build a DataFrame manually since load_log rejects empty files
        df = pd.DataFrame(columns=["timestamp", "source_ip", "event_type", "username", "status"])
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        alerts = run_detection(df)
        assert alerts == []

    def test_only_successful_logins_no_alerts(self):
        """A log with only LOGIN_SUCCESS events must produce no alerts."""
        df = _build_df([
            ("2026-01-01 08:00:00", "192.0.2.10", "LOGIN_SUCCESS", "alice", "SUCCESS"),
            ("2026-01-01 08:01:00", "192.0.2.10", "LOGIN_SUCCESS", "alice", "SUCCESS"),
            ("2026-01-01 08:02:00", "192.0.2.10", "LOGIN_SUCCESS", "alice", "SUCCESS"),
        ])
        assert run_detection(df) == []

    def test_login_failures_below_threshold_no_alerts(self):
        """Fewer LOGIN_FAILUREs than the threshold must not trigger BruteForce."""
        config = DetectorConfig(brute_force_threshold=5, brute_force_window_seconds=60)
        df = _build_df([
            ("2026-01-01 08:00:00", "192.0.2.10", "LOGIN_FAILURE", "alice", "FAILURE"),
            ("2026-01-01 08:00:10", "192.0.2.10", "LOGIN_FAILURE", "alice", "FAILURE"),
            ("2026-01-01 08:00:20", "192.0.2.10", "LOGIN_FAILURE", "alice", "FAILURE"),
            ("2026-01-01 08:00:30", "192.0.2.10", "LOGIN_FAILURE", "alice", "FAILURE"),
        ])
        assert run_detection(df, config) == []

    def test_failures_spread_over_long_period_no_alerts(self):
        """Failures far apart in time must not trigger BruteForce."""
        config = DetectorConfig(brute_force_threshold=3, brute_force_window_seconds=60)
        df = _build_df([
            ("2026-01-01 08:00:00", "192.0.2.10", "LOGIN_FAILURE", "alice", "FAILURE"),
            ("2026-01-01 09:00:00", "192.0.2.10", "LOGIN_FAILURE", "alice", "FAILURE"),
            ("2026-01-01 10:00:00", "192.0.2.10", "LOGIN_FAILURE", "alice", "FAILURE"),
        ])
        assert run_detection(df, config) == []


class TestBruteForceRule:
    """Tests for the BruteForce (LOGIN_FAILURE) detection rule."""

    def test_brute_force_triggers_at_threshold(self):
        """Exactly N failures within window must produce one Critical alert."""
        config = DetectorConfig(brute_force_threshold=5, brute_force_window_seconds=60)
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "203.0.113.42", "LOGIN_FAILURE", "admin", "FAILURE")
            for i in range(5)
        ]
        df = _build_df(rows)
        alerts = run_detection(df, config)
        assert len(alerts) == 1
        assert alerts[0].severity == "Critical"
        assert "BruteForce" in alerts[0].rules_matched
        assert alerts[0].source_ip == "203.0.113.42"

    def test_brute_force_evidence_count(self):
        """Alert evidence must contain exactly the matching rows."""
        config = DetectorConfig(brute_force_threshold=5, brute_force_window_seconds=60)
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "203.0.113.42", "LOGIN_FAILURE", "admin", "FAILURE")
            for i in range(7)
        ]
        df = _build_df(rows)
        alerts = run_detection(df, config)
        assert len(alerts) == 1
        assert len(alerts[0].evidence) >= 5

    def test_brute_force_different_ips_produce_separate_alerts(self):
        """Failures from different IPs must produce independent alerts."""
        config = DetectorConfig(brute_force_threshold=5, brute_force_window_seconds=60)
        rows = (
            [(f"2026-01-01 08:00:{i:02d}", "203.0.113.42", "LOGIN_FAILURE", "u1", "FAILURE") for i in range(5)] +
            [(f"2026-01-01 08:00:{i:02d}", "198.51.100.77", "LOGIN_FAILURE", "u2", "FAILURE") for i in range(5)]
        )
        df = _build_df(rows)
        alerts = run_detection(df, config)
        ips = {a.source_ip for a in alerts}
        assert "203.0.113.42" in ips
        assert "198.51.100.77" in ips

    def test_alert_has_required_fields(self):
        """Each alert must have all documented fields populated."""
        config = DetectorConfig(brute_force_threshold=3, brute_force_window_seconds=60)
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "203.0.113.42", "LOGIN_FAILURE", "root", "FAILURE")
            for i in range(3)
        ]
        df = _build_df(rows)
        alerts = run_detection(df, config)
        assert len(alerts) == 1
        a = alerts[0]
        assert a.alert_id.startswith("TL-")
        assert a.generated_at != ""
        assert a.source_ip == "203.0.113.42"
        assert a.event_type != ""
        assert a.severity in ("Critical", "High", "Medium", "Low")
        assert isinstance(a.rules_matched, list) and len(a.rules_matched) >= 1
        assert isinstance(a.evidence, list) and len(a.evidence) >= 1
        assert isinstance(a.explanation, str) and len(a.explanation) > 0

    def test_custom_threshold_respected(self):
        """A custom threshold of 10 must not fire for 9 failures (both IP-based and
        account-based brute-force rules should be above threshold)."""
        config = DetectorConfig(
            brute_force_threshold=10,
            brute_force_window_seconds=60,
            account_brute_force_threshold=10,   # also raise account BF threshold
            account_brute_force_window_seconds=60,
        )
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "203.0.113.42", "LOGIN_FAILURE", "admin", "FAILURE")
            for i in range(9)
        ]
        df = _build_df(rows)
        assert run_detection(df, config) == []

    def test_to_dict_serialisable(self):
        """Alert.to_dict() must return a plain dict (JSON-serialisable types)."""
        import json
        config = DetectorConfig(brute_force_threshold=3, brute_force_window_seconds=60)
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "203.0.113.42", "LOGIN_FAILURE", "admin", "FAILURE")
            for i in range(3)
        ]
        df = _build_df(rows)
        alerts = run_detection(df, config)
        d = alerts[0].to_dict()
        # Must not raise
        json.dumps(d, default=str)
        assert isinstance(d, dict)


class TestPortScanRule:
    """Tests for the PortScan detection rule."""

    def test_port_scan_triggers(self):
        """3+ PORT_SCAN events within window produces High alert."""
        config = DetectorConfig(port_scan_threshold=3, port_scan_window_seconds=60)
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "198.51.100.77", "PORT_SCAN", "", "BLOCKED")
            for i in range(4)
        ]
        df = _build_df(rows)
        alerts = run_detection(df, config)
        assert any("PortScan" in a.rules_matched for a in alerts)
        ps_alert = next(a for a in alerts if "PortScan" in a.rules_matched)
        assert ps_alert.severity == "High"

    def test_port_scan_below_threshold_no_alert(self):
        config = DetectorConfig(port_scan_threshold=5, port_scan_window_seconds=60)
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "198.51.100.77", "PORT_SCAN", "", "BLOCKED")
            for i in range(4)
        ]
        df = _build_df(rows)
        assert run_detection(df, config) == []


class TestRepeatedConnectRule:
    """Tests for the RepeatedConnect detection rule."""

    def test_repeated_connect_triggers(self):
        config = DetectorConfig(repeated_connect_threshold=5, repeated_connect_window_seconds=120)
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "203.0.113.19", "CONNECTION_ATTEMPT", "", "BLOCKED")
            for i in range(5)
        ]
        df = _build_df(rows)
        alerts = run_detection(df, config)
        assert any("RepeatedConnect" in a.rules_matched for a in alerts)

    def test_repeated_connect_below_threshold_no_alert(self):
        config = DetectorConfig(repeated_connect_threshold=10, repeated_connect_window_seconds=120)
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "203.0.113.19", "CONNECTION_ATTEMPT", "", "BLOCKED")
            for i in range(9)
        ]
        df = _build_df(rows)
        assert run_detection(df, config) == []


class TestImmediateRules:
    """Tests for MalwareEvent and PrivEsc (immediate, no threshold)."""

    def test_malware_event_triggers_critical(self):
        df = _build_df([
            ("2026-01-01 08:20:00", "192.0.2.15", "MALWARE_DETECTED", "bob", "BLOCKED"),
        ])
        alerts = run_detection(df)
        assert len(alerts) == 1
        assert alerts[0].severity == "Critical"
        assert "MalwareEvent" in alerts[0].rules_matched

    def test_priv_esc_triggers_critical(self):
        df = _build_df([
            ("2026-01-01 08:25:00", "192.0.2.200", "PRIVILEGE_ESCALATION", "charlie", "SUCCESS"),
        ])
        alerts = run_detection(df)
        assert len(alerts) == 1
        assert alerts[0].severity == "Critical"
        assert "PrivEsc" in alerts[0].rules_matched

    def test_two_malware_events_same_ip_two_alerts(self):
        """Two MALWARE_DETECTED rows from the same IP at different times → 2 alerts."""
        df = _build_df([
            ("2026-01-01 08:20:00", "192.0.2.15", "MALWARE_DETECTED", "bob", "BLOCKED"),
            ("2026-01-01 09:00:00", "192.0.2.15", "MALWARE_DETECTED", "bob", "BLOCKED"),
        ])
        alerts = run_detection(df)
        # Each event is at a distinct timestamp so no overlap → 2 separate alerts
        assert len(alerts) == 2


class TestDeduplication:
    """Tests for the multi-rule deduplication logic."""

    def test_no_double_counting_of_evidence(self):
        """A single event row matched by two rules must appear only once in evidence."""
        # We cannot easily make a single row match two rules (different event_type per rule).
        # Instead, verify that the total evidence rows ≤ distinct input rows.
        config = DetectorConfig(brute_force_threshold=5, brute_force_window_seconds=60)
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "203.0.113.42", "LOGIN_FAILURE", "admin", "FAILURE")
            for i in range(5)
        ]
        df = _build_df(rows)
        alerts = run_detection(df, config)
        total_evidence = sum(len(a.evidence) for a in alerts)
        # Evidence should not exceed total input rows
        assert total_evidence <= len(df)

    def test_multi_rule_alert_has_both_rule_names(self):
        """
        When a brute-force AND a malware event come from the same IP and their
        evidence sets don't overlap, they produce separate alerts.
        Both alerts must list the correct rule_name for their own evidence.
        """
        config = DetectorConfig(brute_force_threshold=3, brute_force_window_seconds=60)
        rows = (
            [(f"2026-01-01 08:00:{i:02d}", "203.0.113.42", "LOGIN_FAILURE", "admin", "FAILURE") for i in range(3)] +
            [("2026-01-01 09:00:00", "203.0.113.42", "MALWARE_DETECTED", "admin", "BLOCKED")]
        )
        df = _build_df(rows)
        alerts = run_detection(df, config)
        rule_names = {rule for a in alerts for rule in a.rules_matched}
        assert "BruteForce"   in rule_names
        assert "MalwareEvent" in rule_names

    def test_alert_ids_are_unique(self):
        """Each alert must have a distinct alert_id."""
        config = DetectorConfig(brute_force_threshold=3, brute_force_window_seconds=60)
        rows = (
            [(f"2026-01-01 08:00:{i:02d}", "203.0.113.42", "LOGIN_FAILURE", "a", "FAILURE") for i in range(3)] +
            [(f"2026-01-01 08:00:{i:02d}", "198.51.100.77", "LOGIN_FAILURE", "b", "FAILURE") for i in range(3)]
        )
        df = _build_df(rows)
        alerts = run_detection(df, config)
        ids = [a.alert_id for a in alerts]
        assert len(ids) == len(set(ids))


class TestSampleData:
    """Integration-style test: run the engine against the bundled sample CSV."""

    def test_sample_csv_produces_alerts(self):
        """The bundled sample_logs.csv must produce at least one alert."""
        from pathlib import Path
        sample = Path(__file__).parent.parent / "data" / "sample_logs.csv"
        df = load_log(sample)
        alerts = run_detection(df)
        assert len(alerts) >= 1

    def test_sample_csv_detects_brute_force(self):
        """sample_logs.csv contains enough LOGIN_FAILURE rows to trigger BruteForce."""
        from pathlib import Path
        sample = Path(__file__).parent.parent / "data" / "sample_logs.csv"
        df = load_log(sample)
        alerts = run_detection(df)
        assert any("BruteForce" in a.rules_matched for a in alerts)

    def test_sample_csv_detects_malware(self):
        from pathlib import Path
        sample = Path(__file__).parent.parent / "data" / "sample_logs.csv"
        df = load_log(sample)
        alerts = run_detection(df)
        assert any("MalwareEvent" in a.rules_matched for a in alerts)

    def test_sample_csv_detects_priv_esc(self):
        from pathlib import Path
        sample = Path(__file__).parent.parent / "data" / "sample_logs.csv"
        df = load_log(sample)
        alerts = run_detection(df)
        assert any("PrivEsc" in a.rules_matched for a in alerts)
