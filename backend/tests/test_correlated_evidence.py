"""
ThreatLens – Tests for Correlated Contextual Supporting Evidence
================================================================
Verifies:
1. Successful logon following failed attempts is identified and included as
   correlated contextual evidence in investigation dossiers.
2. Triggering evidence (LOGIN_FAILURE) is distinguished from correlated
   contextual evidence (LOGIN_SUCCESS) via 'evidence_role'.
3. Successful logon is not counted as a failed attempt and does not artificially
   inflate the brute-force evidence strength bonus.
4. Risk score correlation bonus is transparently justified by multi-rule correlation.
5. Successful logon without prior failures generates no false alerts.
6. API serialization exposes 'triggering_count', 'context_count', and 'evidence_role'.
7. Windows Security Event Log correlation preserves event metadata alongside evidence role.
"""

from __future__ import annotations

import io
import textwrap
from datetime import datetime, timezone
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from backend.api import app, format_alert
from backend.detector import Alert, DetectorConfig, run_detection
from backend.log_parser import load_log
from backend.windows_log_importer import load_windows_log

client = TestClient(app)


def _make_alice_df() -> pd.DataFrame:
    """Create the test dataset for Alice: 6 failed logins and 1 successful login from 192.0.2.45."""
    csv_data = textwrap.dedent("""
        timestamp,source_ip,event_type,username,status
        2026-11-04 09:00:01,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
        2026-11-04 09:00:07,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
        2026-11-04 09:00:14,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
        2026-11-04 09:00:22,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
        2026-11-04 09:00:29,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
        2026-11-04 09:00:36,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
        2026-11-04 09:01:10,192.0.2.45,LOGIN_SUCCESS,Alice,SUCCESS
    """).strip()
    return load_log(io.StringIO(csv_data))


class TestCorrelatedSupportingEvidence:
    """Tests for correlated contextual evidence in alert dossiers."""

    def test_alice_scenario_correlates_successful_login(self) -> None:
        """Alice's 6 failed logins followed by 1 successful login must trigger correlation."""
        df = _make_alice_df()
        alerts = run_detection(df)

        # Must generate at least one merged alert for 192.0.2.45
        assert len(alerts) >= 1
        alice_alert = next((a for a in alerts if a.source_ip == "192.0.2.45"), None)
        assert alice_alert is not None

        # Both BruteForce and LogonAfterBruteForce rules must be matched
        assert "BruteForce" in alice_alert.rules_matched
        assert "LogonAfterBruteForce" in alice_alert.rules_matched

        # Total evidence count is 7 (6 failures + 1 success)
        assert len(alice_alert.evidence) == 7
        assert alice_alert.affected_account == "Alice"

        # Evidence breakdown: 6 triggering, 1 correlated context
        triggering = [e for e in alice_alert.evidence if e.get("evidence_role") == "triggering"]
        context = [e for e in alice_alert.evidence if e.get("evidence_role") == "correlated_context"]

        assert len(triggering) == 6
        assert len(context) == 1

        # The 6 triggering events must all be LOGIN_FAILURE
        for ev in triggering:
            assert ev["event_type"] == "LOGIN_FAILURE"
            assert ev["status"] == "FAILURE"

        # The correlated contextual event must be LOGIN_SUCCESS
        assert context[0]["event_type"] == "LOGIN_SUCCESS"
        assert context[0]["status"] == "SUCCESS"
        assert context[0]["timestamp"] == "2026-11-04 09:01:10"

    def test_successful_login_does_not_inflate_evidence_strength(self) -> None:
        """The successful login must not increase the brute-force evidence count or inflate score."""
        df = _make_alice_df()
        alerts = run_detection(df)
        alice_alert = next(a for a in alerts if a.source_ip == "192.0.2.45")

        # In scoring: 6 triggering events (threshold 5-9) awards +10 bonus points
        # If 7 events were erroneously counted, it's still +10, but the explanation must state 6 events
        score_factor_text = " ".join(alice_alert.score_factors)
        assert "Evidence strength (6 events): +10" in score_factor_text

        # Rules matched: BruteForce, AccountBruteForce, LogonAfterBruteForce
        assert len(alice_alert.rules_matched) == 3
        assert "Rule correlation (3 rules): +10" in score_factor_text

        # Base severity for Critical is 70; total score is 70 + 10 + 10 = 90
        assert alice_alert.risk_score == 90
        assert alice_alert.priority_label == "Critical"

        # Also test with config where enable_account_brute_force=False so exactly 2 rules fire
        cfg_2rules = DetectorConfig(enable_account_brute_force=False)
        alerts_2 = run_detection(df, cfg_2rules)
        alert_2 = next(a for a in alerts_2 if a.source_ip == "192.0.2.45")
        assert len(alert_2.rules_matched) == 2
        score_factor_text_2 = " ".join(alert_2.score_factors)
        assert "Evidence strength (6 events): +10" in score_factor_text_2
        assert "Rule correlation (2 rules): +5" in score_factor_text_2
        assert alert_2.risk_score == 85

    def test_alert_properties_and_to_dict(self) -> None:
        """Alert dataclass properties triggering_count and context_count are serialized."""
        df = _make_alice_df()
        alerts = run_detection(df)
        alice_alert = next(a for a in alerts if a.source_ip == "192.0.2.45")

        assert alice_alert.triggering_count == 6
        assert alice_alert.context_count == 1

        d = alice_alert.to_dict()
        assert d["triggering_count"] == 6
        assert d["context_count"] == 1
        assert d["evidence_count"] == 7

    def test_format_alert_api_serialization(self) -> None:
        """format_alert helper includes triggering_count and context_count."""
        df = _make_alice_df()
        alerts = run_detection(df)
        alice_alert = next(a for a in alerts if a.source_ip == "192.0.2.45")

        formatted = format_alert(alice_alert)
        assert formatted["triggering_count"] == 6
        assert formatted["context_count"] == 1
        assert formatted["evidence_count"] == 7
        assert formatted["first_seen"] == "2026-11-04 09:00:01"
        assert formatted["last_seen"] == "2026-11-04 09:01:10"

        # Check each evidence item has evidence_role
        for ev in formatted["evidence"]:
            assert "evidence_role" in ev
            assert ev["evidence_role"] in ("triggering", "correlated_context")

    def test_isolated_successful_login_produces_no_alerts(self) -> None:
        """A normal successful login with no prior failures must not produce alerts."""
        csv_data = textwrap.dedent("""
            timestamp,source_ip,event_type,username,status
            2026-11-04 09:00:01,192.0.2.50,LOGIN_SUCCESS,Bob,SUCCESS
            2026-11-04 09:00:15,192.0.2.50,LOGIN_SUCCESS,Bob,SUCCESS
        """).strip()
        df = load_log(io.StringIO(csv_data))
        alerts = run_detection(df)
        assert len(alerts) == 0

    def test_insufficient_failures_does_not_fire_logon_after_brute_force(self) -> None:
        """Only 2 failures followed by 1 success is below threshold (3) -> no LogonAfterBruteForce."""
        csv_data = textwrap.dedent("""
            timestamp,source_ip,event_type,username,status
            2026-11-04 09:00:01,192.0.2.60,LOGIN_FAILURE,Charlie,FAILURE
            2026-11-04 09:00:05,192.0.2.60,LOGIN_FAILURE,Charlie,FAILURE
            2026-11-04 09:00:10,192.0.2.60,LOGIN_SUCCESS,Charlie,SUCCESS
        """).strip()
        df = load_log(io.StringIO(csv_data))
        alerts = run_detection(df)
        assert len(alerts) == 0

    def test_windows_log_importer_correlation_roles(self) -> None:
        """Windows log importer correlates 4625 failures with 4624 success and assigns roles."""
        win_csv = textwrap.dedent("""
            Date and Time,Event ID,User,Computer,Description
            2026-11-04 10:00:01,4625,admin,DC-01,"Source Network Address: 192.0.2.80"
            2026-11-04 10:00:05,4625,admin,DC-01,"Source Network Address: 192.0.2.80"
            2026-11-04 10:00:10,4625,admin,DC-01,"Source Network Address: 192.0.2.80"
            2026-11-04 10:00:15,4625,admin,DC-01,"Source Network Address: 192.0.2.80"
            2026-11-04 10:00:20,4625,admin,DC-01,"Source Network Address: 192.0.2.80"
            2026-11-04 10:00:30,4624,admin,DC-01,"Source Network Address: 192.0.2.80"
        """).strip()
        df, report = load_windows_log(io.StringIO(win_csv))
        alerts = run_detection(df)

        win_alert = next((a for a in alerts if a.source_ip == "192.0.2.80"), None)
        assert win_alert is not None
        assert "LogonAfterBruteForce" in win_alert.rules_matched
        assert win_alert.triggering_count == 5
        assert win_alert.context_count == 1

        # Check Windows event metadata is preserved
        success_ev = next(e for e in win_alert.evidence if e.get("evidence_role") == "correlated_context")
        assert success_ev["win_event_id"] == 4624
        assert success_ev["win_computer"] == "DC-01"


class TestAnalyzeEndpointWithAliceData:
    """Test full API analysis pipeline with Alice's dataset."""

    def test_analyze_endpoint_alice_csv(self) -> None:
        """POST /api/analyze with Alice's CSV returns proper alert and evidence roles."""
        csv_bytes = textwrap.dedent("""
            timestamp,source_ip,event_type,username,status
            2026-11-04 09:00:01,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
            2026-11-04 09:00:07,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
            2026-11-04 09:00:14,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
            2026-11-04 09:00:22,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
            2026-11-04 09:00:29,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
            2026-11-04 09:00:36,192.0.2.45,LOGIN_FAILURE,Alice,FAILURE
            2026-11-04 09:01:10,192.0.2.45,LOGIN_SUCCESS,Alice,SUCCESS
        """).strip().encode("utf-8")

        response = client.post(
            "/api/analyze",
            files={"file": ("alice_test.csv", csv_bytes, "text/csv")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

        alerts = data["alerts"]
        assert len(alerts) >= 1
        alice_alert = next((a for a in alerts if a["source_ip"] == "192.0.2.45"), None)
        assert alice_alert is not None
        assert alice_alert["triggering_count"] == 6
        assert alice_alert["context_count"] == 1
        assert alice_alert["evidence_count"] == 7
        assert "BruteForce" in alice_alert["rules_matched"]
        assert "LogonAfterBruteForce" in alice_alert["rules_matched"]

        # GET /api/alerts also reflects these properties
        alerts_resp = client.get("/api/alerts?source_ip=192.0.2.45")
        assert alerts_resp.status_code == 200
        get_data = alerts_resp.json()
        assert get_data["total"] >= 1
        retrieved_alert = get_data["alerts"][0]
        assert retrieved_alert["triggering_count"] == 6
        assert retrieved_alert["context_count"] == 1
