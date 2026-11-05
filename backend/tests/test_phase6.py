"""
ThreatLens – Phase 6 Tests: Advanced Threat Detection and Alert Prioritization
===============================================================================
Covers:
- Advanced brute-force detection (IP-based and account-based)
- Successful logon after brute-force correlation (LogonAfterBruteForce)
- Account lifecycle events (AccountCreated, AccountDeleted, GroupMemberAdded)
- SuspiciousAccountLifecycle correlation
- MultiAccountChanges rule
- PrivilegeAssigned rule
- AuditLogCleared detection
- Risk scoring (0-100 scale), priority labels, and scoring factors
- Alert deduplication (fingerprint and overlap)
- Investigation steps and limitations fields
- Configurable thresholds with validation
- GET /api/detection/config and PUT /api/detection/config endpoints
- New alert fields in API responses
- Existing endpoint compatibility regression
- Missing or unknown identifiers handled gracefully

All test fixtures use synthetic data only. No real credentials are used.
All IP addresses are from RFC 5737 documentation ranges.
"""

from __future__ import annotations

import io
import textwrap
from datetime import datetime, timedelta

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from backend.api import app
from backend.detector import (
    Alert,
    DetectorConfig,
    _compute_risk_score,
    _score_to_priority,
    run_detection,
)
from backend.log_parser import load_log

client = TestClient(app)

# ── Helpers ───────────────────────────────────────────────────────────────────

HEADER = "timestamp,source_ip,event_type,username,status"


def _csv(content: str) -> io.StringIO:
    return io.StringIO(textwrap.dedent(content).strip())


def _make_df(rows: list[tuple]) -> pd.DataFrame:
    """Build a minimal normalised DataFrame from (timestamp, ip, event_type, user, status) tuples."""
    data = [
        {
            "timestamp": pd.to_datetime(r[0]),
            "source_ip": r[1],
            "event_type": r[2],
            "username": r[3],
            "status": r[4],
        }
        for r in rows
    ]
    df = pd.DataFrame(data)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def _rows_at_seconds(
    base: str,
    n: int,
    ip: str = "192.0.2.10",
    event: str = "LOGIN_FAILURE",
    user: str = "testuser",
    status: str = "FAILURE",
) -> list[tuple]:
    return [
        (f"{base}:{i:02d}", ip, event, user, status)
        for i in range(n)
    ]


# ── Tests: Risk Scoring ───────────────────────────────────────────────────────

class TestRiskScoring:
    def test_critical_severity_base_score(self):
        score, label, factors = _compute_risk_score("Critical", 1, 1)
        assert score >= 70
        assert label in ("High", "Critical")
        assert any("Critical" in f for f in factors)

    def test_high_severity_base_score(self):
        score, label, factors = _compute_risk_score("High", 1, 1)
        assert score >= 50
        assert label in ("High", "Critical")

    def test_medium_severity_base_score(self):
        score, label, factors = _compute_risk_score("Medium", 1, 1)
        assert score >= 25

    def test_low_severity_base_score(self):
        score, label, factors = _compute_risk_score("Low", 1, 1)
        assert score == 10
        assert label == "Low"

    def test_evidence_bonus_increases_score(self):
        score_single, _, _ = _compute_risk_score("High", 1, 1)
        score_many, _, _ = _compute_risk_score("High", 20, 1)
        assert score_many > score_single

    def test_correlation_bonus_increases_score(self):
        score_one_rule, _, _ = _compute_risk_score("High", 5, 1)
        score_two_rules, _, _ = _compute_risk_score("High", 5, 2)
        assert score_two_rules > score_one_rule

    def test_score_capped_at_100(self):
        score, _, _ = _compute_risk_score("Critical", 100, 10)
        assert score <= 100

    def test_score_non_negative(self):
        score, _, _ = _compute_risk_score("Low", 0, 1)
        assert score >= 0

    def test_score_factors_are_strings(self):
        _, _, factors = _compute_risk_score("Critical", 10, 2)
        assert all(isinstance(f, str) for f in factors)
        assert len(factors) >= 1

    def test_priority_thresholds(self):
        assert _score_to_priority(80) == "Critical"
        assert _score_to_priority(79) == "High"
        assert _score_to_priority(50) == "High"
        assert _score_to_priority(49) == "Medium"
        assert _score_to_priority(25) == "Medium"
        assert _score_to_priority(24) == "Low"
        assert _score_to_priority(0) == "Low"

    def test_alert_has_risk_score_field(self):
        rows = _rows_at_seconds("2026-01-01 08:00", 5)
        df = _make_df(rows)
        alerts = run_detection(df)
        assert len(alerts) >= 1
        a = alerts[0]
        assert hasattr(a, "risk_score")
        assert isinstance(a.risk_score, int)
        assert 0 <= a.risk_score <= 100

    def test_alert_has_priority_label_field(self):
        rows = _rows_at_seconds("2026-01-01 08:00", 5)
        df = _make_df(rows)
        alerts = run_detection(df)
        a = alerts[0]
        assert a.priority_label in ("Low", "Medium", "High", "Critical")

    def test_alert_has_score_factors_list(self):
        rows = _rows_at_seconds("2026-01-01 08:00", 5)
        df = _make_df(rows)
        alerts = run_detection(df)
        a = alerts[0]
        assert isinstance(a.score_factors, list)
        assert len(a.score_factors) >= 1


# ── Tests: Investigation Steps and Limitations ───────────────────────────────

class TestInvestigationSteps:
    def test_brute_force_has_investigation_steps(self):
        rows = _rows_at_seconds("2026-01-01 08:00", 5)
        df = _make_df(rows)
        alerts = run_detection(df)
        bf_alerts = [a for a in alerts if "BruteForce" in a.rules_matched]
        assert len(bf_alerts) >= 1
        a = bf_alerts[0]
        assert isinstance(a.investigation_steps, list)
        assert len(a.investigation_steps) >= 1
        assert all(isinstance(s, str) for s in a.investigation_steps)

    def test_audit_log_cleared_has_investigation_steps(self):
        rows = [("2026-01-01 08:00:00", "192.0.2.10", "AUDIT_LOG_CLEARED", "admin", "SUCCESS")]
        df = _make_df(rows)
        alerts = run_detection(df)
        ac_alerts = [a for a in alerts if "AuditLogCleared" in a.rules_matched]
        assert len(ac_alerts) >= 1
        steps = ac_alerts[0].investigation_steps
        assert len(steps) >= 1

    def test_alert_has_limitations_field(self):
        rows = _rows_at_seconds("2026-01-01 08:00", 5)
        df = _make_df(rows)
        alerts = run_detection(df)
        a = alerts[0]
        assert isinstance(a.limitations, str)
        assert len(a.limitations) > 0

    def test_limitations_mentions_rule_based(self):
        rows = _rows_at_seconds("2026-01-01 08:00", 5)
        df = _make_df(rows)
        alerts = run_detection(df)
        a = alerts[0]
        # Must not claim to be an IDS or validated system
        assert "rule-based" in a.limitations.lower()

    def test_to_dict_includes_phase6_fields(self):
        import json
        rows = _rows_at_seconds("2026-01-01 08:00", 5)
        df = _make_df(rows)
        alerts = run_detection(df)
        d = alerts[0].to_dict()
        json.dumps(d, default=str)  # must not raise
        assert "risk_score" in d
        assert "priority_label" in d
        assert "score_factors" in d
        assert "investigation_steps" in d
        assert "affected_account" in d
        assert "limitations" in d


# ── Tests: Advanced Brute-Force Detection ────────────────────────────────────

class TestAdvancedBruteForce:
    def test_ip_brute_force_fires_above_threshold(self):
        rows = _rows_at_seconds("2026-01-01 08:00", 5, ip="192.0.2.20")
        df = _make_df(rows)
        alerts = run_detection(df)
        assert any("BruteForce" in a.rules_matched for a in alerts)

    def test_ip_brute_force_below_threshold_no_alert(self):
        config = DetectorConfig(
            brute_force_threshold=10,
            account_brute_force_threshold=10,
        )
        rows = _rows_at_seconds("2026-01-01 08:00", 4, ip="192.0.2.20", user="uniqueuser")
        df = _make_df(rows)
        alerts = run_detection(df, config)
        # No brute force should fire with threshold=10 and only 4 failures
        bf = [a for a in alerts if "BruteForce" in a.rules_matched or "AccountBruteForce" in a.rules_matched]
        assert len(bf) == 0

    def test_different_ips_produce_separate_alerts(self):
        rows = (
            _rows_at_seconds("2026-01-01 08:00", 5, ip="192.0.2.10", user="alice") +
            _rows_at_seconds("2026-01-01 08:00", 5, ip="198.51.100.5", user="bob")
        )
        df = _make_df(rows)
        alerts = run_detection(df)
        bf_alerts = [a for a in alerts if "BruteForce" in a.rules_matched]
        source_ips = {a.source_ip for a in bf_alerts}
        assert len(source_ips) >= 2

    def test_account_brute_force_fires_on_same_account(self):
        """Multiple failures against one account should fire AccountBruteForce."""
        rows = [
            ("2026-01-01 08:00:01", "192.0.2.10", "LOGIN_FAILURE", "victimuser", "FAILURE"),
            ("2026-01-01 08:00:05", "192.0.2.11", "LOGIN_FAILURE", "victimuser", "FAILURE"),
            ("2026-01-01 08:00:10", "192.0.2.12", "LOGIN_FAILURE", "victimuser", "FAILURE"),
            ("2026-01-01 08:00:15", "192.0.2.13", "LOGIN_FAILURE", "victimuser", "FAILURE"),
            ("2026-01-01 08:00:20", "192.0.2.14", "LOGIN_FAILURE", "victimuser", "FAILURE"),
        ]
        df = _make_df(rows)
        alerts = run_detection(df)
        ab_alerts = [a for a in alerts if "AccountBruteForce" in a.rules_matched]
        assert len(ab_alerts) >= 1

    def test_account_brute_force_records_account(self):
        rows = [
            ("2026-01-01 08:00:0" + str(i), "192.0.2." + str(i + 10), "LOGIN_FAILURE", "targetaccount", "FAILURE")
            for i in range(5)
        ]
        df = _make_df(rows)
        alerts = run_detection(df)
        ab_alerts = [a for a in alerts if "AccountBruteForce" in a.rules_matched]
        assert len(ab_alerts) >= 1
        assert ab_alerts[0].affected_account == "targetaccount"

    def test_account_brute_force_disabled_when_no_usernames(self):
        """Failures without any username should not produce AccountBruteForce alerts."""
        rows = [
            (f"2026-01-01 08:00:{i:02d}", "192.0.2.10", "LOGIN_FAILURE", "", "FAILURE")
            for i in range(5)
        ]
        df = _make_df(rows)
        alerts = run_detection(df)
        ab_alerts = [a for a in alerts if "AccountBruteForce" in a.rules_matched]
        assert len(ab_alerts) == 0

    def test_account_brute_force_different_accounts_separate(self):
        """Failures against different accounts from different IPs must produce separate alerts."""
        rows = (
            [("2026-01-01 08:00:0" + str(i), "192.0.2.10", "LOGIN_FAILURE", "accountA", "FAILURE") for i in range(5)] +
            [("2026-01-01 09:00:0" + str(i), "192.0.2.20", "LOGIN_FAILURE", "accountB", "FAILURE") for i in range(5)]
        )
        df = _make_df(rows)
        alerts = run_detection(df)
        ab_alerts = [a for a in alerts if "AccountBruteForce" in a.rules_matched]
        accounts = {a.affected_account for a in ab_alerts}
        assert "accountA" in accounts
        assert "accountB" in accounts

    def test_logon_after_brute_force_with_config(self):
        """LogonAfterBruteForce should fire when enabled for standard logs."""
        config = DetectorConfig(
            enable_logon_after_brute_force=True,
            logon_after_failures_threshold=3,
            logon_after_failures_window_seconds=120,
        )
        rows = (
            _rows_at_seconds("2026-01-01 08:00", 3, ip="192.0.2.10", event="LOGIN_FAILURE", user="admin") +
            [("2026-01-01 08:01:00", "192.0.2.10", "LOGIN_SUCCESS", "admin", "SUCCESS")]
        )
        df = _make_df(rows)
        alerts = run_detection(df, config)
        lab_alerts = [a for a in alerts if "LogonAfterBruteForce" in a.rules_matched]
        assert len(lab_alerts) >= 1

    def test_logon_after_brute_force_no_fire_without_failures(self):
        """LogonAfterBruteForce should NOT fire on a solitary successful logon."""
        config = DetectorConfig(enable_logon_after_brute_force=True)
        rows = [("2026-01-01 08:00:00", "192.0.2.10", "LOGIN_SUCCESS", "admin", "SUCCESS")]
        df = _make_df(rows)
        alerts = run_detection(df, config)
        lab_alerts = [a for a in alerts if "LogonAfterBruteForce" in a.rules_matched]
        assert len(lab_alerts) == 0

    def test_logon_after_brute_force_skips_missing_ip(self):
        """Events with no source IP (0.0.0.0) should be skipped by correlation."""
        config = DetectorConfig(enable_logon_after_brute_force=True, logon_after_failures_threshold=3)
        rows = (
            [("2026-01-01 08:00:0" + str(i), "0.0.0.0", "LOGIN_FAILURE", "user", "FAILURE") for i in range(3)] +
            [("2026-01-01 08:01:00", "0.0.0.0", "LOGIN_SUCCESS", "user", "SUCCESS")]
        )
        df = _make_df(rows)
        alerts = run_detection(df, config)
        lab_alerts = [a for a in alerts if "LogonAfterBruteForce" in a.rules_matched]
        assert len(lab_alerts) == 0


# ── Tests: Account Lifecycle ─────────────────────────────────────────────────

class TestAccountLifecycle:
    def test_account_created_fires(self):
        rows = [("2026-01-01 08:00:00", "192.0.2.10", "ACCOUNT_CREATED", "newuser", "SUCCESS")]
        df = _make_df(rows)
        alerts = run_detection(df)
        ac = [a for a in alerts if "AccountCreated" in a.rules_matched]
        assert len(ac) >= 1

    def test_account_deleted_fires(self):
        rows = [("2026-01-01 08:00:00", "192.0.2.10", "ACCOUNT_DELETED", "olduser", "SUCCESS")]
        df = _make_df(rows)
        alerts = run_detection(df)
        ad = [a for a in alerts if "AccountDeleted" in a.rules_matched]
        assert len(ad) >= 1

    def test_group_member_added_fires(self):
        rows = [("2026-01-01 08:00:00", "192.0.2.10", "GROUP_MEMBER_ADDED", "someuser", "SUCCESS")]
        df = _make_df(rows)
        alerts = run_detection(df)
        gma = [a for a in alerts if "GroupMemberAdded" in a.rules_matched]
        assert len(gma) >= 1

    def test_audit_log_cleared_is_critical(self):
        rows = [("2026-01-01 08:00:00", "192.0.2.10", "AUDIT_LOG_CLEARED", "admin", "SUCCESS")]
        df = _make_df(rows)
        alerts = run_detection(df)
        ac = [a for a in alerts if "AuditLogCleared" in a.rules_matched]
        assert len(ac) >= 1
        assert ac[0].severity == "Critical"

    def test_account_brute_force_not_fired_on_single_creation(self):
        """A single ACCOUNT_CREATED event should not trigger AccountBruteForce."""
        rows = [("2026-01-01 08:00:00", "192.0.2.10", "ACCOUNT_CREATED", "legit_user", "SUCCESS")]
        df = _make_df(rows)
        alerts = run_detection(df)
        bf = [a for a in alerts if "AccountBruteForce" in a.rules_matched or "BruteForce" in a.rules_matched]
        assert len(bf) == 0

    def test_multi_account_changes_fires(self):
        """MultiAccountChanges should fire on 3+ account-management events within window."""
        rows = [
            ("2026-01-01 08:00:00", "192.0.2.10", "ACCOUNT_CREATED", "user1", "SUCCESS"),
            ("2026-01-01 08:00:30", "192.0.2.10", "ACCOUNT_CREATED", "user2", "SUCCESS"),
            ("2026-01-01 08:01:00", "192.0.2.10", "ACCOUNT_DELETED", "user3", "SUCCESS"),
        ]
        df = _make_df(rows)
        config = DetectorConfig(
            multi_account_changes_threshold=3,
            multi_account_changes_window_seconds=300,
        )
        alerts = run_detection(df, config)
        mac = [a for a in alerts if "MultiAccountChanges" in a.rules_matched]
        assert len(mac) >= 1

    def test_multi_account_changes_below_threshold(self):
        rows = [
            ("2026-01-01 08:00:00", "192.0.2.10", "ACCOUNT_CREATED", "user1", "SUCCESS"),
            ("2026-01-01 08:01:00", "192.0.2.10", "ACCOUNT_DELETED", "user2", "SUCCESS"),
        ]
        df = _make_df(rows)
        config = DetectorConfig(multi_account_changes_threshold=3)
        alerts = run_detection(df, config)
        mac = [a for a in alerts if "MultiAccountChanges" in a.rules_matched]
        assert len(mac) == 0

    def test_suspicious_account_lifecycle_fires(self):
        """Account created then added to group in same window should trigger correlation."""
        rows = [
            ("2026-01-01 08:00:00", "192.0.2.10", "ACCOUNT_CREATED", "backdoor_user", "SUCCESS"),
            ("2026-01-01 08:00:30", "192.0.2.10", "GROUP_MEMBER_ADDED", "backdoor_user", "SUCCESS"),
        ]
        df = _make_df(rows)
        df["win_event_id"] = None  # simulate Windows log context
        config = DetectorConfig(account_lifecycle_window_seconds=900)
        alerts = run_detection(df, config)
        sal = [a for a in alerts if "SuspiciousAccountLifecycle" in a.rules_matched]
        assert len(sal) >= 1

    def test_rapid_account_create_delete_in_evidence(self):
        """ACCOUNT_CREATED followed by ACCOUNT_DELETED for different users should be tracked."""
        rows = [
            ("2026-01-01 08:00:00", "192.0.2.10", "ACCOUNT_CREATED", "temp_user_a", "SUCCESS"),
            ("2026-01-01 08:01:00", "192.0.2.10", "ACCOUNT_DELETED", "temp_user_a", "SUCCESS"),
        ]
        df = _make_df(rows)
        alerts = run_detection(df)
        ac = [a for a in alerts if "AccountCreated" in a.rules_matched]
        ad = [a for a in alerts if "AccountDeleted" in a.rules_matched]
        assert len(ac) >= 1
        assert len(ad) >= 1


# ── Tests: Deduplication ─────────────────────────────────────────────────────

class TestDeduplication:
    def test_same_dataset_twice_no_duplicate_alerts(self):
        """Running detection twice on the same data should not add alert count."""
        rows = _rows_at_seconds("2026-01-01 08:00", 5, ip="192.0.2.10", user="dedupuser")
        df = _make_df(rows)
        alerts_first = run_detection(df)
        alerts_second = run_detection(df)
        assert len(alerts_first) == len(alerts_second)

    def test_dedup_within_run(self):
        """Identical evidence rows from the same rule should not produce two alerts."""
        rows = _rows_at_seconds("2026-01-01 08:00", 5, ip="192.0.2.10", user="dedupuser2")
        df = _make_df(rows)
        alerts = run_detection(df)
        bf_from_ip = [a for a in alerts if "BruteForce" in a.rules_matched and a.source_ip == "192.0.2.10"]
        # Should produce exactly one BruteForce alert for this IP
        assert len(bf_from_ip) == 1

    def test_different_ips_not_merged(self):
        """Alerts from different source IPs must remain separate."""
        rows = (
            _rows_at_seconds("2026-01-01 08:00", 5, ip="192.0.2.10", user="userA") +
            _rows_at_seconds("2026-01-01 08:00", 5, ip="192.0.2.20", user="userB")
        )
        df = _make_df(rows)
        alerts = run_detection(df)
        bf_alerts = [a for a in alerts if "BruteForce" in a.rules_matched]
        source_ips = {a.source_ip for a in bf_alerts}
        assert len(source_ips) >= 2

    def test_evidence_retained_after_dedup(self):
        """After deduplication, evidence rows must still be present."""
        rows = _rows_at_seconds("2026-01-01 08:00", 5, ip="192.0.2.10")
        df = _make_df(rows)
        alerts = run_detection(df)
        bf = [a for a in alerts if "BruteForce" in a.rules_matched]
        assert len(bf) >= 1
        assert len(bf[0].evidence) >= 5

    def test_alert_ids_are_unique(self):
        rows = (
            _rows_at_seconds("2026-01-01 08:00", 5, ip="192.0.2.10") +
            _rows_at_seconds("2026-01-01 08:00", 5, ip="192.0.2.20")
        )
        df = _make_df(rows)
        alerts = run_detection(df)
        ids = [a.alert_id for a in alerts]
        assert len(ids) == len(set(ids))


# ── Tests: Configuration ─────────────────────────────────────────────────────

class TestDetectorConfig:
    def test_default_config_validates(self):
        config = DetectorConfig()
        assert config.validate() == []

    def test_to_dict_has_all_keys(self):
        config = DetectorConfig()
        d = config.to_dict()
        assert "brute_force_threshold" in d
        assert "account_brute_force_threshold" in d
        assert "enable_account_brute_force" in d
        assert "dedup_window_seconds" in d
        assert "enable_multi_account_changes" in d
        assert "account_lifecycle_window_seconds" in d

    def test_from_dict_roundtrip(self):
        config = DetectorConfig(brute_force_threshold=8)
        d = config.to_dict()
        restored = DetectorConfig.from_dict(d)
        assert restored.brute_force_threshold == 8

    def test_invalid_threshold_raises_validation_error(self):
        config = DetectorConfig(brute_force_threshold=0)
        errors = config.validate()
        assert len(errors) >= 1
        assert any("brute_force_threshold" in e for e in errors)

    def test_negative_threshold_raises_error(self):
        config = DetectorConfig(brute_force_threshold=-1)
        errors = config.validate()
        assert len(errors) >= 1

    def test_window_below_minimum_raises_error(self):
        config = DetectorConfig(brute_force_window_seconds=5)
        errors = config.validate()
        assert any("brute_force_window_seconds" in e for e in errors)

    def test_window_above_maximum_raises_error(self):
        config = DetectorConfig(brute_force_window_seconds=90000)
        errors = config.validate()
        assert any("brute_force_window_seconds" in e for e in errors)

    def test_negative_dedup_window_raises_error(self):
        config = DetectorConfig(dedup_window_seconds=-1)
        errors = config.validate()
        assert any("dedup_window_seconds" in e for e in errors)

    def test_zero_dedup_window_is_valid(self):
        config = DetectorConfig(dedup_window_seconds=0)
        assert config.validate() == []

    def test_from_dict_ignores_unknown_keys(self):
        """from_dict should silently ignore keys that are not DetectorConfig fields."""
        config = DetectorConfig.from_dict({"brute_force_threshold": 7, "unknown_key": 999})
        assert config.brute_force_threshold == 7

    def test_defaults_match_dataclass_defaults(self):
        defaults = DetectorConfig.defaults()
        config = DetectorConfig()
        assert defaults["brute_force_threshold"] == config.brute_force_threshold
        assert defaults["dedup_window_seconds"] == config.dedup_window_seconds

    def test_configurable_brute_force_threshold(self):
        config_low = DetectorConfig(
            brute_force_threshold=3,
            account_brute_force_threshold=3,
        )
        config_high = DetectorConfig(
            brute_force_threshold=10,
            account_brute_force_threshold=10,
        )
        rows = _rows_at_seconds("2026-01-01 08:00", 5, user="uniqueuser99")
        df = _make_df(rows)
        alerts_low = run_detection(df, config_low)
        alerts_high = run_detection(df, config_high)
        # Lower threshold fires, higher threshold should not
        assert len(alerts_low) >= 1
        assert len(alerts_high) == 0

    def test_configurable_time_window(self):
        """Events spread over 200 s should not trigger a 60 s window rule."""
        rows = [
            ("2026-01-01 08:00:00", "192.0.2.10", "LOGIN_FAILURE", "timeuser", "FAILURE"),
            ("2026-01-01 08:01:00", "192.0.2.10", "LOGIN_FAILURE", "timeuser", "FAILURE"),
            ("2026-01-01 08:02:00", "192.0.2.10", "LOGIN_FAILURE", "timeuser", "FAILURE"),
            ("2026-01-01 08:03:00", "192.0.2.10", "LOGIN_FAILURE", "timeuser", "FAILURE"),
            ("2026-01-01 08:04:00", "192.0.2.10", "LOGIN_FAILURE", "timeuser", "FAILURE"),
        ]
        config = DetectorConfig(
            brute_force_threshold=5,
            brute_force_window_seconds=60,
            account_brute_force_threshold=5,
            account_brute_force_window_seconds=60,
        )
        df = _make_df(rows)
        alerts = run_detection(df, config)
        bf_alerts = [a for a in alerts if "BruteForce" in a.rules_matched or "AccountBruteForce" in a.rules_matched]
        # Spread over 240s, window 60s → should not trigger
        assert len(bf_alerts) == 0

    def test_missing_timestamps_handled_safely(self):
        """DataFrames with no valid timestamps should not crash the engine."""
        df = pd.DataFrame(
            columns=["timestamp", "source_ip", "event_type", "username", "status"]
        )
        alerts = run_detection(df)
        assert alerts == []


# ── Tests: API – Detection Config Endpoints ──────────────────────────────────

class TestDetectionConfigEndpoints:
    def test_get_config_returns_200(self):
        resp = client.get("/api/detection/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "config" in data
        assert "defaults" in data

    def test_get_config_has_expected_fields(self):
        resp = client.get("/api/detection/config")
        cfg = resp.json()["config"]
        assert "brute_force_threshold" in cfg
        assert "dedup_window_seconds" in cfg
        assert "enable_account_brute_force" in cfg

    def test_put_config_valid_update(self):
        resp = client.put("/api/detection/config", json={"brute_force_threshold": 8})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["config"]["brute_force_threshold"] == 8
        # Reset to default for test isolation
        client.put("/api/detection/config", json={"brute_force_threshold": 5})

    def test_put_config_rejects_unknown_field(self):
        resp = client.put("/api/detection/config", json={"unknown_parameter": 99})
        assert resp.status_code == 400
        assert "unknown" in resp.json()["detail"].lower()

    def test_put_config_rejects_invalid_threshold(self):
        resp = client.put("/api/detection/config", json={"brute_force_threshold": 0})
        assert resp.status_code == 422

    def test_put_config_rejects_negative_threshold(self):
        resp = client.put("/api/detection/config", json={"brute_force_threshold": -5})
        assert resp.status_code == 422

    def test_put_config_rejects_excessively_large_window(self):
        resp = client.put("/api/detection/config", json={"brute_force_window_seconds": 100000})
        assert resp.status_code == 422

    def test_put_config_does_not_partially_apply_invalid_values(self):
        """An invalid config update must not partially modify any fields."""
        # Get current threshold
        get_resp = client.get("/api/detection/config")
        original_threshold = get_resp.json()["config"]["brute_force_threshold"]
        # Send invalid update
        client.put("/api/detection/config", json={"brute_force_threshold": -999})
        # Check threshold unchanged
        get_resp2 = client.get("/api/detection/config")
        assert get_resp2.json()["config"]["brute_force_threshold"] == original_threshold

    def test_put_config_valid_boolean_field(self):
        resp = client.put("/api/detection/config", json={"enable_account_brute_force": False})
        assert resp.status_code == 200
        assert resp.json()["config"]["enable_account_brute_force"] is False
        # Restore
        client.put("/api/detection/config", json={"enable_account_brute_force": True})


# ── Tests: API – Alert Fields ────────────────────────────────────────────────

class TestAlertApiFields:
    def test_alerts_endpoint_has_risk_score(self):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        data = resp.json()
        if data["alerts"]:
            a = data["alerts"][0]
            assert "risk_score" in a
            assert isinstance(a["risk_score"], int)

    def test_alerts_endpoint_has_priority_label(self):
        resp = client.get("/api/alerts")
        data = resp.json()
        if data["alerts"]:
            a = data["alerts"][0]
            assert "priority_label" in a
            assert a["priority_label"] in ("Low", "Medium", "High", "Critical")

    def test_alerts_endpoint_has_investigation_steps(self):
        resp = client.get("/api/alerts")
        data = resp.json()
        if data["alerts"]:
            a = data["alerts"][0]
            assert "investigation_steps" in a
            assert isinstance(a["investigation_steps"], list)

    def test_alerts_endpoint_has_limitations(self):
        resp = client.get("/api/alerts")
        data = resp.json()
        if data["alerts"]:
            a = data["alerts"][0]
            assert "limitations" in a

    def test_alerts_endpoint_has_first_and_last_seen(self):
        resp = client.get("/api/alerts")
        data = resp.json()
        if data["alerts"]:
            a = data["alerts"][0]
            assert "first_seen" in a
            assert "last_seen" in a

    def test_alert_filter_by_rule(self):
        """New 'rule' filter parameter must work."""
        resp = client.get("/api/alerts?rule=BruteForce")
        assert resp.status_code == 200
        data = resp.json()
        for a in data["alerts"]:
            assert "BruteForce" in " ".join(a["rules_matched"])

    def test_alert_filter_by_priority_label(self):
        """New 'priority_label' filter parameter must work."""
        resp = client.get("/api/alerts?priority_label=Critical")
        assert resp.status_code == 200
        data = resp.json()
        for a in data["alerts"]:
            assert a["priority_label"] == "Critical"

    def test_alert_filter_by_affected_account(self):
        resp = client.get("/api/alerts?affected_account=alice")
        assert resp.status_code == 200  # Must not crash; may return 0 results


# ── Tests: API – Summary Fields ──────────────────────────────────────────────

class TestSummaryApiFields:
    def test_summary_has_high_priority_alerts_count(self):
        resp = client.get("/api/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "summaryStats" in data
        assert "highPriorityAlerts" in data["summaryStats"]

    def test_summary_has_top_rules(self):
        resp = client.get("/api/summary")
        data = resp.json()
        assert "topRules" in data
        assert isinstance(data["topRules"], list)


# ── Tests: Regression – Existing Endpoints Unchanged ─────────────────────────

class TestRegressionExistingEndpoints:
    def test_health_endpoint_still_works(self):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_summary_endpoint_still_works(self):
        resp = client.get("/api/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "summaryStats" in data
        assert "severityData" in data
        assert "activityData" in data

    def test_alerts_endpoint_still_works(self):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        assert "alerts" in resp.json()

    def test_logs_endpoint_still_works(self):
        resp = client.get("/api/logs")
        assert resp.status_code == 200
        assert "logs" in resp.json()

    def test_windows_supported_events_still_works(self):
        resp = client.get("/api/windows/supported-events")
        assert resp.status_code == 200
        data = resp.json()
        assert "supported_event_ids" in data

    def test_reset_endpoint_still_works(self):
        resp = client.post("/api/reset")
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_analyze_still_returns_rules_matched(self):
        csv_content = (
            "timestamp,source_ip,event_type,username,status\n"
            "2026-10-20 10:00:00,192.0.2.50,LOGIN_FAILURE,root,FAILURE\n"
            "2026-10-20 10:00:05,192.0.2.50,LOGIN_FAILURE,root,FAILURE\n"
            "2026-10-20 10:00:10,192.0.2.50,LOGIN_FAILURE,root,FAILURE\n"
            "2026-10-20 10:00:15,192.0.2.50,LOGIN_FAILURE,root,FAILURE\n"
            "2026-10-20 10:00:20,192.0.2.50,LOGIN_FAILURE,root,FAILURE\n"
        )
        files = {"file": ("test_logs.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
        resp = client.post("/api/analyze", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["alerts"]) >= 1
        # BruteForce must still be fired (it may be merged with AccountBruteForce)
        all_rules = set()
        for a in data["alerts"]:
            all_rules.update(a.get("rules_matched", []))
        assert "BruteForce" in all_rules

    def test_existing_phase4_fields_present(self):
        resp = client.get("/api/alerts")
        data = resp.json()
        if data["alerts"]:
            a = data["alerts"][0]
            # Original fields must still be present
            assert "id" in a
            assert "severity" in a
            assert "rules_matched" in a
            assert "evidence" in a
            assert "explanation" in a
