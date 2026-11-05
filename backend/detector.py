"""
ThreatLens – Detection Rules
=============================
Implements transparent, rule-based detection over a normalised log DataFrame.

Rules implemented
-----------------
1.  BruteForce         – N+ LOGIN_FAILURE events from the same IP within T seconds.
2.  PortScan           – N+ PORT_SCAN events from the same IP within T seconds.
3.  RepeatedConnect    – N+ CONNECTION_ATTEMPT events from the same IP within T seconds.
4.  MalwareEvent       – Any MALWARE_DETECTED event (immediate, no threshold).
5.  PrivEsc            – Any PRIVILEGE_ESCALATION event (immediate, no threshold).

Phase 5 – Windows-specific rules
---------------------------------
6.  AccountCreated     – Any ACCOUNT_CREATED event (Windows 4720).
7.  AccountDeleted     – Any ACCOUNT_DELETED event (Windows 4726).
8.  GroupMemberAdded   – Any GROUP_MEMBER_ADDED event (Windows 4732).
9.  AuditLogCleared    – Any AUDIT_LOG_CLEARED event (Windows 1102) — Critical.
10. PrivilegeAssigned  – N+ PRIVILEGE_ESCALATION events from same IP within T seconds
    (sliding-window variant to catch repeated privilege assignments).

Phase 6 – Advanced rules
--------------------------
11. LogonAfterBruteForce – Successful logon (4624) following N+ failed logons (4625)
    from the same IP within a configurable window.
12. SuspiciousAccountLifecycle – Account created and rapidly elevated or added to group.
13. AccountBruteForce  – Multiple failed logons targeting the same *account* (across
    potentially different or unknown source IPs).
14. MultiAccountChanges – Multiple distinct account-management events within a window.

De-duplication
--------------
Within a single analysis run, matches are de-duplicated using two strategies:

1. **Overlap merging** – matches sharing the same source IP *and* at least one common
   (timestamp, event_type) evidence row are merged into a single Alert that records all
   contributing rule names.

2. **Fingerprint deduplication** – matches from the same rule, targeting the same IP /
   account, within the configured ``dedup_window_seconds`` are collapsed to one Alert.
   This prevents the same attack sequence producing many near-identical alerts when a
   dataset is analysed repeatedly or when overlapping windows fire multiple times.

Deduplication occurs *within a single run*. It does not require persistent storage and
resets when the backend restarts.

Risk scoring (Phase 6)
-----------------------
Each alert carries an integer ``risk_score`` (0–100) and a ``priority_label``
("Low" | "Medium" | "High" | "Critical").

The score is computed from three transparent factors:

  base_score  – derived from alert severity (Critical=70, High=50, Medium=30, Low=10)
  evidence_bonus – extra points for stronger evidence (up to 20 points)
  correlation_bonus – extra points when multiple rules fired (up to 10 points)

  risk_score = min(100, base_score + evidence_bonus + correlation_bonus)

Priority labels:
  0–24   → Low
  25–49  → Medium
  50–79  → High
  80–100 → Critical

The score is a heuristic indicator of investigation priority, not a probability.

⚠️  This module performs no network access or real monitoring.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

# ── Alert severity levels (ordered low → high) ────────────────────────────────
SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

# ── Risk score → priority label mapping ───────────────────────────────────────
PRIORITY_THRESHOLDS = [
    (80, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (0,  "Low"),
]


def _max_severity(*severities: str) -> str:
    """Return the highest severity from a collection of severity strings."""
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))


def _score_to_priority(score: int) -> str:
    """Map a numeric risk score (0–100) to a human-readable priority label."""
    for threshold, label in PRIORITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


def _compute_risk_score(
    severity: str,
    evidence_count: int,
    rule_count: int,
) -> tuple[int, str, list[str]]:
    """
    Compute a transparent risk score from severity, evidence strength, and
    the number of correlated rules.

    Returns (risk_score, priority_label, score_factors) where score_factors
    is a human-readable list of contributing factors.
    """
    base_scores = {"Critical": 70, "High": 50, "Medium": 30, "Low": 10}
    base = base_scores.get(severity, 10)

    # Evidence bonus: more log rows = stronger evidence, up to 20 extra points
    if evidence_count >= 20:
        ev_bonus = 20
    elif evidence_count >= 10:
        ev_bonus = 14
    elif evidence_count >= 5:
        ev_bonus = 10
    elif evidence_count >= 3:
        ev_bonus = 6
    elif evidence_count >= 2:
        ev_bonus = 3
    else:
        ev_bonus = 0

    # Correlation bonus: multiple rules fired on the same evidence set
    corr_bonus = min(10, (rule_count - 1) * 5) if rule_count > 1 else 0

    risk_score = min(100, base + ev_bonus + corr_bonus)
    priority_label = _score_to_priority(risk_score)

    factors = [f"Base severity ({severity}): {base}"]
    if ev_bonus > 0:
        factors.append(f"Evidence strength ({evidence_count} events): +{ev_bonus}")
    if corr_bonus > 0:
        factors.append(f"Rule correlation ({rule_count} rules): +{corr_bonus}")

    return risk_score, priority_label, factors


# ── Investigation steps by rule name ─────────────────────────────────────────

_INVESTIGATION_STEPS: dict[str, list[str]] = {
    "BruteForce": [
        "Review all failed-logon events from this source IP and note the targeted accounts.",
        "Check whether any subsequent successful logon occurred from the same IP.",
        "Determine whether the source IP is internal, known, or previously unseen.",
        "Verify that the targeted accounts are not shared or service accounts.",
        "Consider temporary IP-level blocking if the activity is ongoing.",
    ],
    "AccountBruteForce": [
        "Identify the targeted account and check whether it is a privileged or shared account.",
        "Review the source IPs involved and determine whether they are related.",
        "Check whether the account was locked out and whether the lockout policy is appropriate.",
        "Determine whether a successful logon for this account followed the failures.",
        "Notify the account owner and confirm whether the logon attempts were expected.",
    ],
    "LogonAfterBruteForce": [
        "Confirm the source IP and user account involved in both the failures and the success.",
        "Examine what actions were performed during the session following the successful logon.",
        "Check for privilege use, lateral movement, or data access following the logon.",
        "Determine whether the credentials may have been compromised.",
        "Review recent password changes or MFA status for the affected account.",
    ],
    "PortScan": [
        "Review the full list of destination IPs and ports targeted from this source.",
        "Determine whether this source is an authorised scanning tool or an unexpected host.",
        "Check for follow-up connection or exploitation attempts after the scan.",
        "Review firewall or IDS logs for complementary evidence.",
    ],
    "RepeatedConnect": [
        "Examine the frequency and destination of connection attempts from this IP.",
        "Determine whether the destination service is publicly exposed.",
        "Review related logs for authentication attempts or session establishment.",
        "Consider whether automated tooling or misconfigured software may be the cause.",
    ],
    "MalwareEvent": [
        "Isolate the affected host if the malware indicator is confirmed.",
        "Review process execution and file system activity on the affected machine.",
        "Check for lateral movement indicators from the same source IP.",
        "Engage your incident response process if the indicator is confirmed.",
    ],
    "PrivEsc": [
        "Verify that the privilege-escalation event was authorised and expected.",
        "Review the account involved and the specific privileges assigned.",
        "Check for subsequent use of elevated privileges.",
        "Confirm whether this account should have access to elevated privileges.",
    ],
    "PrivilegeAssigned": [
        "Review the account that received the privilege assignment (Windows 4672).",
        "Confirm that repeated privilege assignments from this IP are expected administrative activity.",
        "Check whether the assigned privileges include SeDebugPrivilege or similar high-risk rights.",
        "Review surrounding logon and account activity for the same session.",
    ],
    "AccountCreated": [
        "Verify that the account creation was authorised by an administrator.",
        "Confirm the account name does not resemble a backdoor or evasion pattern.",
        "Check whether the account was subsequently granted elevated privileges or group membership.",
        "Review the creating account and host for signs of compromise.",
    ],
    "AccountDeleted": [
        "Confirm the deletion was performed by an authorised administrator.",
        "Review whether the deleted account had recent logon or activity.",
        "Determine whether the deletion is part of a planned offboarding process.",
        "Check whether the account was recently created and immediately deleted.",
    ],
    "GroupMemberAdded": [
        "Confirm that the group membership change was authorised.",
        "Identify the group and determine its privilege level.",
        "Review the account that was added and verify it is a known, expected user.",
        "Check for concurrent account creation or privilege escalation events.",
    ],
    "AuditLogCleared": [
        "Identify who cleared the audit log and from which machine.",
        "Review any available logs from before the clearing event for signs of prior activity.",
        "Determine whether log clearing is part of an authorised maintenance procedure.",
        "Check whether other security logs were cleared around the same time.",
        "Escalate immediately if this event occurred during or after a suspicious session.",
    ],
    "SuspiciousAccountLifecycle": [
        "Verify that the account creation and subsequent privilege or group changes were authorised.",
        "Confirm the new account name is not a backdoor or persistence mechanism.",
        "Review the session and host from which these events originated.",
        "Check for logon activity using the newly created account.",
    ],
    "MultiAccountChanges": [
        "Review all account-management events in the indicated time window.",
        "Determine whether bulk account changes are part of a scheduled or authorised process.",
        "Check for concurrent authentication anomalies from the same host.",
        "Verify that each change was performed by an authorised administrator.",
    ],
}

_DEFAULT_INVESTIGATION_STEPS = [
    "Review the supporting evidence log entries.",
    "Determine whether the activity originated from a known and authorised source.",
    "Check for related activity in surrounding log entries.",
    "Escalate if the activity cannot be explained by expected operations.",
]


def _get_investigation_steps(rules_matched: list[str]) -> list[str]:
    """Return investigation steps relevant to the matched rules."""
    if not rules_matched:
        return _DEFAULT_INVESTIGATION_STEPS
    # Use steps from the first (highest-severity) rule; list additional rules if more exist
    primary_steps = _INVESTIGATION_STEPS.get(rules_matched[0], _DEFAULT_INVESTIGATION_STEPS)
    return primary_steps


# ── Alert dataclass ────────────────────────────────────────────────────────────

@dataclass
class Alert:
    """A structured security alert produced by one or more detection rules."""

    alert_id: str
    generated_at: str          # ISO-8601 UTC string
    source_ip: str
    event_type: str            # Primary event category that triggered the alert
    severity: str              # Critical | High | Medium | Low
    rules_matched: list[str]   # All rule names that contributed to this alert
    evidence: list[dict]       # Subset of log rows that constitute the evidence
    explanation: str           # Human-readable description
    # Phase 6 fields
    risk_score: int = 0                # 0–100 heuristic investigation-priority score
    priority_label: str = "Low"        # Low | Medium | High | Critical
    score_factors: list[str] = field(default_factory=list)  # transparent scoring factors
    investigation_steps: list[str] = field(default_factory=list)  # recommended next steps
    affected_account: str = ""         # primary target account when determinable
    limitations: str = ""              # known gaps in the evidence

    @property
    def triggering_count(self) -> int:
        return sum(1 for e in self.evidence if e.get("evidence_role") != "correlated_context")

    @property
    def context_count(self) -> int:
        return sum(1 for e in self.evidence if e.get("evidence_role") == "correlated_context")

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id":             self.alert_id,
            "generated_at":         self.generated_at,
            "source_ip":            self.source_ip,
            "event_type":           self.event_type,
            "severity":             self.severity,
            "rules_matched":        self.rules_matched,
            "evidence":             self.evidence,
            "evidence_count":       len(self.evidence),
            "triggering_count":     self.triggering_count,
            "context_count":        self.context_count,
            "explanation":          self.explanation,
            "risk_score":           self.risk_score,
            "priority_label":       self.priority_label,
            "score_factors":        self.score_factors,
            "investigation_steps":  self.investigation_steps,
            "affected_account":     self.affected_account,
            "limitations":          self.limitations,
        }


# ── Configuration dataclass ────────────────────────────────────────────────────

@dataclass
class DetectorConfig:
    """
    Tunable thresholds for each detection rule.

    All duration values are in seconds. All counts are inclusive minimums.
    Default values represent sensible starting points for a typical environment;
    they should be adjusted to match your log volume and risk tolerance.
    """

    # BruteForce: LOGIN_FAILURE from same IP
    # Default: 5 failures within 60 s
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 60

    # AccountBruteForce: LOGIN_FAILURE targeting the same *account* (across IPs)
    # Default: 5 failures against one account within 60 s
    account_brute_force_threshold: int = 5
    account_brute_force_window_seconds: int = 60
    enable_account_brute_force: bool = True

    # PortScan: PORT_SCAN events
    port_scan_threshold: int = 3
    port_scan_window_seconds: int = 60

    # RepeatedConnect: CONNECTION_ATTEMPT events
    repeated_connect_threshold: int = 10
    repeated_connect_window_seconds: int = 120

    # PrivilegeAssigned (Windows): repeated PRIVILEGE_ESCALATION in a window
    priv_assigned_threshold: int = 3
    priv_assigned_window_seconds: int = 300  # 5-minute window

    # LogonAfterBruteForce: successful logon after repeated failures within window
    # Enabled by default for all logs (Windows and standard CSV)
    enable_logon_after_brute_force: bool = True
    logon_after_failures_threshold: int = 3
    logon_after_failures_window_seconds: int = 300

    # SuspiciousAccountLifecycle: account created then rapidly elevated
    # (active automatically for Windows logs)
    account_lifecycle_window_seconds: int = 900  # 15 minutes

    # MultiAccountChanges: multiple distinct account-management events in a window
    multi_account_changes_threshold: int = 3
    multi_account_changes_window_seconds: int = 300
    enable_multi_account_changes: bool = True

    # Alert deduplication within a single analysis run
    # Matches from the same rule targeting the same IP/account within this window
    # are collapsed to one alert.
    dedup_window_seconds: int = 3600  # 1 hour

    def validate(self) -> list[str]:
        """
        Validate configuration values. Returns a list of error messages (empty
        when the configuration is valid).

        Rules:
          - Integer counts must be ≥ 1.
          - Window durations must be ≥ 10 s.
          - Window durations must be ≤ 86400 s (24 h) to avoid runaway windows.
          - Deduplication window must be ≥ 0.
        """
        errors: list[str] = []

        int_fields_min1 = [
            ("brute_force_threshold", self.brute_force_threshold),
            ("account_brute_force_threshold", self.account_brute_force_threshold),
            ("port_scan_threshold", self.port_scan_threshold),
            ("repeated_connect_threshold", self.repeated_connect_threshold),
            ("priv_assigned_threshold", self.priv_assigned_threshold),
            ("logon_after_failures_threshold", self.logon_after_failures_threshold),
            ("multi_account_changes_threshold", self.multi_account_changes_threshold),
        ]
        for name, val in int_fields_min1:
            if not isinstance(val, int) or val < 1:
                errors.append(f"'{name}' must be an integer ≥ 1 (got {val!r}).")

        window_fields = [
            ("brute_force_window_seconds", self.brute_force_window_seconds),
            ("account_brute_force_window_seconds", self.account_brute_force_window_seconds),
            ("port_scan_window_seconds", self.port_scan_window_seconds),
            ("repeated_connect_window_seconds", self.repeated_connect_window_seconds),
            ("priv_assigned_window_seconds", self.priv_assigned_window_seconds),
            ("logon_after_failures_window_seconds", self.logon_after_failures_window_seconds),
            ("account_lifecycle_window_seconds", self.account_lifecycle_window_seconds),
            ("multi_account_changes_window_seconds", self.multi_account_changes_window_seconds),
        ]
        for name, val in window_fields:
            if not isinstance(val, int):
                errors.append(f"'{name}' must be an integer (got {val!r}).")
            elif val < 10:
                errors.append(f"'{name}' must be ≥ 10 seconds (got {val}).")
            elif val > 86400:
                errors.append(f"'{name}' must be ≤ 86400 seconds / 24 h (got {val}).")

        if not isinstance(self.dedup_window_seconds, int) or self.dedup_window_seconds < 0:
            errors.append(
                f"'dedup_window_seconds' must be a non-negative integer (got {self.dedup_window_seconds!r})."
            )

        return errors

    def to_dict(self) -> dict[str, Any]:
        """Serialise configuration to a dictionary suitable for API responses."""
        return {
            "brute_force_threshold":                self.brute_force_threshold,
            "brute_force_window_seconds":           self.brute_force_window_seconds,
            "account_brute_force_threshold":        self.account_brute_force_threshold,
            "account_brute_force_window_seconds":   self.account_brute_force_window_seconds,
            "enable_account_brute_force":           self.enable_account_brute_force,
            "port_scan_threshold":                  self.port_scan_threshold,
            "port_scan_window_seconds":             self.port_scan_window_seconds,
            "repeated_connect_threshold":           self.repeated_connect_threshold,
            "repeated_connect_window_seconds":      self.repeated_connect_window_seconds,
            "priv_assigned_threshold":              self.priv_assigned_threshold,
            "priv_assigned_window_seconds":         self.priv_assigned_window_seconds,
            "enable_logon_after_brute_force":       self.enable_logon_after_brute_force,
            "logon_after_failures_threshold":       self.logon_after_failures_threshold,
            "logon_after_failures_window_seconds":  self.logon_after_failures_window_seconds,
            "account_lifecycle_window_seconds":     self.account_lifecycle_window_seconds,
            "enable_multi_account_changes":         self.enable_multi_account_changes,
            "multi_account_changes_threshold":      self.multi_account_changes_threshold,
            "multi_account_changes_window_seconds": self.multi_account_changes_window_seconds,
            "dedup_window_seconds":                 self.dedup_window_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DetectorConfig":
        """Create a DetectorConfig from a dictionary, ignoring unknown keys."""
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)

    @classmethod
    def defaults(cls) -> dict[str, Any]:
        """Return default values as a dictionary (useful for documentation)."""
        return cls().to_dict()


# ── Individual rule functions ──────────────────────────────────────────────────

def _row_to_evidence(row: Any, evidence_role: str = "triggering") -> dict:
    """Extract evidence fields from a DataFrame row, preserving Windows event metadata and evidence role."""
    ev = {
        "timestamp": str(row["timestamp"]),
        "source_ip": str(row["source_ip"]),
        "event_type": str(row["event_type"]),
        "username": str(row["username"]) if pd.notna(row["username"]) else "",
        "status": str(row["status"]),
        "evidence_role": evidence_role,
    }
    if "win_event_id" in row and pd.notna(row["win_event_id"]):
        try:
            ev["win_event_id"] = int(row["win_event_id"])
        except (ValueError, TypeError):
            pass
    if "win_label" in row and pd.notna(row["win_label"]):
        ev["win_label"] = str(row["win_label"])
    if "win_computer" in row and pd.notna(row["win_computer"]):
        ev["win_computer"] = str(row["win_computer"])
    return ev


def _sliding_window_rule(
    df: pd.DataFrame,
    event_type_filter: str,
    threshold: int,
    window_seconds: int,
    rule_name: str,
    severity: str,
    explanation_template: str,
) -> list[dict]:
    """
    Generic sliding-window rule.

    Scans rows matching *event_type_filter* for each source IP. For each IP,
    finds every contiguous window of *threshold* or more events within
    *window_seconds*. Returns a list of ``_match`` dicts (internal format).
    """
    subset = df[df["event_type"] == event_type_filter].copy()
    if subset.empty:
        return []

    matches = []

    for ip, group in subset.groupby("source_ip"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        timestamps = group["timestamp"].tolist()
        n = len(timestamps)

        i = 0
        while i < n:
            window_end = timestamps[i] + timedelta(seconds=window_seconds)
            j = i
            while j < n and timestamps[j] <= window_end:
                j += 1
            count = j - i
            if count >= threshold:
                evidence_rows = group.iloc[i:j]
                evidence = [_row_to_evidence(r) for _, r in evidence_rows.iterrows()]
                matches.append({
                    "source_ip":  ip,
                    "rule_name":  rule_name,
                    "severity":   severity,
                    "event_type": event_type_filter,
                    "evidence":   evidence,
                    "explanation": explanation_template.format(
                        ip=ip, count=count, window=window_seconds
                    ),
                    "affected_account": "",
                })
                # Advance past this window
                i = j
            else:
                i += 1

    return matches


def _immediate_rule(
    df: pd.DataFrame,
    event_type_filter: str,
    rule_name: str,
    severity: str,
    explanation_template: str,
) -> list[dict]:
    """
    Immediate rule – fires for every individual event matching the filter.
    No time-window logic; each matching row produces one match.
    """
    subset = df[df["event_type"] == event_type_filter]
    if subset.empty:
        return []

    matches = []
    for _, row in subset.iterrows():
        evidence = [_row_to_evidence(row)]
        username = str(row["username"]) if pd.notna(row["username"]) else ""
        matches.append({
            "source_ip":  row["source_ip"],
            "rule_name":  rule_name,
            "severity":   severity,
            "event_type": event_type_filter,
            "evidence":   evidence,
            "explanation": explanation_template.format(
                ip=row["source_ip"],
                ts=str(row["timestamp"]),
                username=username,
            ),
            "affected_account": username,
        })
    return matches


def _account_brute_force_rule(
    df: pd.DataFrame,
    threshold: int = 5,
    window_seconds: int = 60,
) -> list[dict]:
    """
    Detect repeated failed logons targeting the same *account name*, regardless
    of source IP.

    This complements BruteForce (which groups by IP). A password-spray attack
    typically fails from many IPs against one or few accounts.
    """
    failures = df[df["event_type"] == "LOGIN_FAILURE"].copy()
    if failures.empty:
        return []

    # Only meaningful when there are actual usernames
    failures = failures[failures["username"].notna() & (failures["username"].str.strip() != "")]
    if failures.empty:
        return []

    matches = []
    for account, group in failures.groupby("username"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        timestamps = group["timestamp"].tolist()
        n = len(timestamps)

        i = 0
        while i < n:
            window_end = timestamps[i] + timedelta(seconds=window_seconds)
            j = i
            while j < n and timestamps[j] <= window_end:
                j += 1
            count = j - i
            if count >= threshold:
                evidence_rows = group.iloc[i:j]
                evidence = [_row_to_evidence(r) for _, r in evidence_rows.iterrows()]
                # Use the most common IP as the alert "source_ip" (may be "" if unknown)
                ip_values = [e["source_ip"] for e in evidence if e["source_ip"] not in ("", "-", "0.0.0.0")]
                primary_ip = max(set(ip_values), key=ip_values.count) if ip_values else "0.0.0.0"
                matches.append({
                    "source_ip":  primary_ip,
                    "rule_name":  "AccountBruteForce",
                    "severity":   "High",
                    "event_type": "LOGIN_FAILURE",
                    "evidence":   evidence,
                    "explanation": (
                        f"AccountBruteForce: Possible brute-force activity against account "
                        f"'{account}' — {count} failed logon events within {window_seconds} seconds. "
                        f"The failures may originate from one or more source IPs. "
                        f"Review whether the account was successfully compromised."
                    ),
                    "affected_account": str(account),
                })
                i = j
            else:
                i += 1

    return matches


def _logon_after_failures_rule(
    df: pd.DataFrame,
    failure_threshold: int = 3,
    window_seconds: int = 300,
) -> list[dict]:
    """
    Correlation rule: Detects a successful logon (LOGIN_SUCCESS) following
    repeated failed logons (LOGIN_FAILURE) from the same source IP within a
    rolling time window.

    Important: a successful logon after failures is suspicious but not
    conclusive. The explanation uses "possible" language accordingly.
    """
    matches = []
    for ip, group in df.groupby("source_ip"):
        if ip in ("0.0.0.0", "-", ""):
            continue
        group = group.sort_values("timestamp").reset_index(drop=True)
        failures: list[Any] = []
        for _, row in group.iterrows():
            etype = row["event_type"]
            ts = row["timestamp"]
            if etype == "LOGIN_FAILURE":
                failures.append(row)
            elif etype == "LOGIN_SUCCESS":
                window_start = ts - timedelta(seconds=window_seconds)
                recent_failures = [f for f in failures if f["timestamp"] >= window_start]
                if len(recent_failures) >= failure_threshold:
                    evidence = []
                    for r in recent_failures:
                        evidence.append(_row_to_evidence(r, evidence_role="triggering"))
                    # Correlated contextual evidence: successful logon following the failures
                    evidence.append(_row_to_evidence(row, evidence_role="correlated_context"))
                    user = row["username"] or (recent_failures[-1]["username"] if recent_failures else "")
                    matches.append({
                        "source_ip": ip,
                        "rule_name": "LogonAfterBruteForce",
                        "severity": "High",
                        "event_type": "LOGIN_SUCCESS",
                        "evidence": evidence,
                        "explanation": (
                            f"LogonAfterBruteForce: Successful logon from {ip} "
                            f"(account: {user or 'unknown'}) following "
                            f"{len(recent_failures)} failed logon attempts within "
                            f"{window_seconds} seconds. Possible indicator of "
                            f"successful credential guessing. Verify whether this "
                            f"logon was authorised."
                        ),
                        "affected_account": str(user) if user else "",
                    })
                    failures = []
    return matches


def _suspicious_account_lifecycle_rule(
    df: pd.DataFrame,
    window_seconds: int = 900,
) -> list[dict]:
    """
    Correlation rule: Detects a user account created and rapidly granted
    elevated privileges or added to a security group within *window_seconds*.

    Flags account-creation events (ACCOUNT_CREATED) that are followed by
    GROUP_MEMBER_ADDED or PRIVILEGE_ESCALATION for the *same* user within
    the window.
    """
    matches = []
    created_events = df[df["event_type"] == "ACCOUNT_CREATED"]
    if created_events.empty:
        return []
    elev_events = df[df["event_type"].isin(["GROUP_MEMBER_ADDED", "PRIVILEGE_ESCALATION"])]
    if elev_events.empty:
        return []

    for _, c_row in created_events.iterrows():
        c_ts = c_row["timestamp"]
        c_ip = c_row["source_ip"]
        c_user = c_row["username"]
        window_end = c_ts + timedelta(seconds=window_seconds)
        matching_elev = elev_events[
            (elev_events["timestamp"] >= c_ts) &
            (elev_events["timestamp"] <= window_end)
        ]
        if c_user:
            user_elev = matching_elev[matching_elev["username"] == c_user]
            if not user_elev.empty:
                matching_elev = user_elev
        if not matching_elev.empty:
            for _, e_row in matching_elev.iterrows():
                evidence = [_row_to_evidence(c_row), _row_to_evidence(e_row)]
                elapsed = int((e_row["timestamp"] - c_ts).total_seconds())
                matches.append({
                    "source_ip": c_ip,
                    "rule_name": "SuspiciousAccountLifecycle",
                    "severity": "High",
                    "event_type": "ACCOUNT_CREATED",
                    "evidence": evidence,
                    "explanation": (
                        f"SuspiciousAccountLifecycle: Account '{c_user or 'new_user'}' "
                        f"was created and then received elevated privileges or group "
                        f"membership ({e_row['event_type']}) within {elapsed}s. "
                        f"Verify that this account provisioning was authorised."
                    ),
                    "affected_account": str(c_user) if c_user else "",
                })
    return matches


def _multi_account_changes_rule(
    df: pd.DataFrame,
    threshold: int = 3,
    window_seconds: int = 300,
) -> list[dict]:
    """
    Detect a burst of account-management events (any combination of
    ACCOUNT_CREATED, ACCOUNT_DELETED, GROUP_MEMBER_ADDED) within a short
    rolling window from the same source IP.

    Ordinary administration may involve a few account changes. A large number
    of changes in quick succession is worth reviewing.
    """
    acct_types = {"ACCOUNT_CREATED", "ACCOUNT_DELETED", "GROUP_MEMBER_ADDED"}
    subset = df[df["event_type"].isin(acct_types)].copy()
    if subset.empty:
        return []

    matches = []
    for ip, group in subset.groupby("source_ip"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        timestamps = group["timestamp"].tolist()
        n = len(timestamps)

        i = 0
        while i < n:
            window_end = timestamps[i] + timedelta(seconds=window_seconds)
            j = i
            while j < n and timestamps[j] <= window_end:
                j += 1
            count = j - i
            if count >= threshold:
                evidence_rows = group.iloc[i:j]
                evidence = [_row_to_evidence(r) for _, r in evidence_rows.iterrows()]
                involved_types = sorted({e["event_type"] for e in evidence})
                matches.append({
                    "source_ip":  ip,
                    "rule_name":  "MultiAccountChanges",
                    "severity":   "Medium",
                    "event_type": "ACCOUNT_CREATED",
                    "evidence":   evidence,
                    "explanation": (
                        f"MultiAccountChanges: {count} account-management events "
                        f"({', '.join(involved_types)}) from {ip} within "
                        f"{window_seconds} seconds. Bulk account changes may indicate "
                        f"automated provisioning or suspicious administrative activity. "
                        f"Verify that all changes were authorised."
                    ),
                    "affected_account": "",
                })
                i = j
            else:
                i += 1

    return matches


# ── De-duplication / merge logic ───────────────────────────────────────────────

def _fingerprint(match: dict, dedup_window_seconds: int) -> str:
    """
    Compute a stable fingerprint for deduplication.

    Matches that share the same rule, source IP, and account, AND whose
    earliest evidence timestamp falls within the same dedup bucket, are
    considered duplicates.

    This prevents the same attack sequence generating many identical alerts
    when overlapping sliding windows fire or when analysis is repeated.
    """
    rule = match.get("rule_name", "")
    ip = match.get("source_ip", "")
    account = match.get("affected_account", "")
    if match["evidence"] and dedup_window_seconds > 0:
        try:
            first_ts_str = min(e["timestamp"] for e in match["evidence"])
            first_ts = pd.to_datetime(first_ts_str)
            bucket = int(first_ts.timestamp()) // dedup_window_seconds
        except Exception:
            bucket = 0
    else:
        bucket = 0
    return f"{rule}|{ip}|{account}|{bucket}"


def _merge_matches(raw_matches: list[dict], dedup_window_seconds: int = 3600) -> list[Alert]:
    """
    Convert raw rule matches into deduplicated Alert objects.

    Two-phase deduplication:

    Phase 1 – Fingerprint deduplication:
        Collapse matches with the same (rule_name, source_ip, affected_account,
        time bucket) into one match by keeping the one with the most evidence.

    Phase 2 – Overlap merging:
        Two matches are merged when they share the same source_ip AND their
        evidence sets overlap (at least one identical timestamp+event_type row
        in common). The merged alert carries:
          • all distinct evidence rows (union)
          • all rule names that contributed
          • the highest severity of the contributing rules
          • a combined explanation

    Matches that do not overlap are kept as separate Alerts.
    """
    if not raw_matches:
        return []

    # ── Phase 1: fingerprint deduplication ────────────────────────────────────
    seen_fingerprints: dict[str, dict] = {}
    deduped_raw: list[dict] = []
    for m in raw_matches:
        fp = _fingerprint(m, dedup_window_seconds)
        if fp not in seen_fingerprints:
            seen_fingerprints[fp] = m
            deduped_raw.append(m)
        else:
            # Keep the match with more evidence
            if len(m["evidence"]) > len(seen_fingerprints[fp]["evidence"]):
                idx = deduped_raw.index(seen_fingerprints[fp])
                deduped_raw[idx] = m
                seen_fingerprints[fp] = m

    # ── Phase 2: overlap merging ───────────────────────────────────────────────
    def ev_set(match: dict) -> frozenset:
        return frozenset(
            (e["timestamp"], e["event_type"]) for e in match["evidence"]
        )

    by_ip: dict[str, list[dict]] = defaultdict(list)
    for m in deduped_raw:
        by_ip[m["source_ip"]].append(m)

    alerts: list[Alert] = []
    now_utc = datetime.now(tz=timezone.utc).isoformat()

    for ip, ip_matches in by_ip.items():
        groups: list[list[dict]] = [[m] for m in ip_matches]

        merged = True
        while merged:
            merged = False
            new_groups: list[list[dict]] = []
            used = [False] * len(groups)
            for i in range(len(groups)):
                if used[i]:
                    continue
                current = groups[i][:]
                current_ev = set()
                for m in current:
                    current_ev |= ev_set(m)
                for j in range(i + 1, len(groups)):
                    if used[j]:
                        continue
                    other_ev = set()
                    for m in groups[j]:
                        other_ev |= ev_set(m)
                    if current_ev & other_ev:          # overlap → merge
                        current.extend(groups[j])
                        current_ev |= other_ev
                        used[j] = True
                        merged = True
                new_groups.append(current)
                used[i] = True
            groups = new_groups

        # Convert each merged group into an Alert
        for group in groups:
            all_rules      = sorted({m["rule_name"]  for m in group})
            all_severities = [m["severity"] for m in group]
            top_severity   = _max_severity(*all_severities)

            # Deduplicate evidence rows by (timestamp, event_type)
            # If an evidence row is marked as triggering in any match, ensure it is triggering;
            # if it is only marked as correlated_context, preserve correlated_context.
            ev_map: dict[tuple, dict] = {}
            for m in group:
                for ev in m["evidence"]:
                    key = (ev["timestamp"], ev["event_type"])
                    if key not in ev_map:
                        ev_map[key] = dict(ev)
                    else:
                        if ev.get("evidence_role") == "triggering":
                            ev_map[key]["evidence_role"] = "triggering"

            deduped_evidence = list(ev_map.values())
            deduped_evidence.sort(key=lambda e: e["timestamp"])

            # Pick primary event type from the highest-severity match in the group
            primary_match = max(
                group,
                key=lambda m: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(m["severity"], 0)
            )
            primary_event_type = primary_match["event_type"]

            # Resolve affected account: use first non-empty account across matches
            affected_account = next(
                (m.get("affected_account", "") for m in group if m.get("affected_account")),
                "",
            )

            if len(all_rules) == 1:
                explanation = group[0]["explanation"]
            else:
                explanations = " | ".join(m["explanation"] for m in group)
                explanation = (
                    f"Multiple rules fired for {ip}: {', '.join(all_rules)}. "
                    f"Details: {explanations}"
                )

            # Phase 6 & 7: compute risk score and investigation steps
            # Do not count correlated contextual evidence (such as subsequent successful logins)
            # towards the triggering evidence count for score bonuses.
            triggering_evidence_count = sum(
                1 for e in deduped_evidence if e.get("evidence_role") != "correlated_context"
            )
            score_evidence_count = (
                triggering_evidence_count if triggering_evidence_count > 0 else len(deduped_evidence)
            )

            risk_score, priority_label, score_factors = _compute_risk_score(
                severity=top_severity,
                evidence_count=score_evidence_count,
                rule_count=len(all_rules),
            )
            investigation_steps = _get_investigation_steps(all_rules)

            # Limitations statement
            has_ip = ip not in ("0.0.0.0", "-", "")
            limitations_parts = []
            if not has_ip:
                limitations_parts.append(
                    "Source IP was not available in the log data; IP-based correlation "
                    "could not be performed."
                )
            if not affected_account:
                limitations_parts.append(
                    "No account name was extracted from the evidence; account-level "
                    "correlation may be incomplete."
                )
            limitations_parts.append(
                "ThreatLens is a rule-based analysis tool and is not a validated "
                "intrusion-detection system. Alerts indicate suspicious patterns; "
                "investigation is required to confirm or dismiss each finding."
            )
            limitations = " ".join(limitations_parts)

            alerts.append(Alert(
                alert_id             = f"TL-{uuid.uuid4().hex[:8].upper()}",
                generated_at         = now_utc,
                source_ip            = ip,
                event_type           = primary_event_type,
                severity             = top_severity,
                rules_matched        = all_rules,
                evidence             = deduped_evidence,
                explanation          = explanation,
                risk_score           = risk_score,
                priority_label       = priority_label,
                score_factors        = score_factors,
                investigation_steps  = investigation_steps,
                affected_account     = affected_account,
                limitations          = limitations,
            ))

    return alerts


# ── Public detector API ────────────────────────────────────────────────────────

def run_detection(
    df: pd.DataFrame,
    config: DetectorConfig | None = None,
) -> list[Alert]:
    """
    Run all detection rules against a normalised log DataFrame.

    Parameters
    ----------
    df:
        Output of ``log_parser.load_log()`` or ``windows_log_importer.load_windows_log()``.
    config:
        Optional :class:`DetectorConfig`. Defaults are used when ``None``.

    Returns
    -------
    list[Alert]
        Zero or more deduplicated alerts, sorted by risk_score descending then
        by source IP ascending.
    """
    if config is None:
        config = DetectorConfig()

    raw: list[dict] = []

    # Rule 1 – Brute Force (LOGIN_FAILURE grouped by IP)
    raw.extend(_sliding_window_rule(
        df,
        event_type_filter    = "LOGIN_FAILURE",
        threshold            = config.brute_force_threshold,
        window_seconds       = config.brute_force_window_seconds,
        rule_name            = "BruteForce",
        severity             = "Critical",
        explanation_template = (
            "BruteForce: Possible brute-force activity — {count} LOGIN_FAILURE events "
            "from {ip} within {window} seconds. Review the targeted accounts and check "
            "for any subsequent successful logon from this IP."
        ),
    ))

    # Rule 2 – Account Brute Force (LOGIN_FAILURE grouped by account name)
    if config.enable_account_brute_force:
        raw.extend(_account_brute_force_rule(
            df,
            threshold      = config.account_brute_force_threshold,
            window_seconds = config.account_brute_force_window_seconds,
        ))

    # Rule 3 – Port Scan (PORT_SCAN)
    raw.extend(_sliding_window_rule(
        df,
        event_type_filter    = "PORT_SCAN",
        threshold            = config.port_scan_threshold,
        window_seconds       = config.port_scan_window_seconds,
        rule_name            = "PortScan",
        severity             = "High",
        explanation_template = (
            "PortScan: {count} PORT_SCAN events from {ip} within {window} seconds."
        ),
    ))

    # Rule 4 – Repeated Connection Attempts (CONNECTION_ATTEMPT)
    raw.extend(_sliding_window_rule(
        df,
        event_type_filter    = "CONNECTION_ATTEMPT",
        threshold            = config.repeated_connect_threshold,
        window_seconds       = config.repeated_connect_window_seconds,
        rule_name            = "RepeatedConnect",
        severity             = "Medium",
        explanation_template = (
            "RepeatedConnect: {count} CONNECTION_ATTEMPT events from {ip} within {window} seconds."
        ),
    ))

    # Rule 5 – Malware Detected (immediate)
    raw.extend(_immediate_rule(
        df,
        event_type_filter    = "MALWARE_DETECTED",
        rule_name            = "MalwareEvent",
        severity             = "Critical",
        explanation_template = (
            "MalwareEvent: MALWARE_DETECTED event from {ip} at {ts} (user: {username})."
        ),
    ))

    # Rule 6 – Privilege Escalation (immediate)
    raw.extend(_immediate_rule(
        df,
        event_type_filter    = "PRIVILEGE_ESCALATION",
        rule_name            = "PrivEsc",
        severity             = "Critical",
        explanation_template = (
            "PrivEsc: PRIVILEGE_ESCALATION event from {ip} at {ts} "
            "(user: {username}). Verify that this privilege use was authorised."
        ),
    ))

    # ── Phase 5: Windows-specific rules ──────────────────────────────────────

    # Rule 7 – Account Created (Windows 4720, immediate)
    raw.extend(_immediate_rule(
        df,
        event_type_filter    = "ACCOUNT_CREATED",
        rule_name            = "AccountCreated",
        severity             = "Medium",
        explanation_template = (
            "AccountCreated: A new user account was created (Windows Event 4720) "
            "from {ip} at {ts} (account: {username}). Verify that this account "
            "creation was authorised."
        ),
    ))

    # Rule 8 – Account Deleted (Windows 4726, immediate)
    raw.extend(_immediate_rule(
        df,
        event_type_filter    = "ACCOUNT_DELETED",
        rule_name            = "AccountDeleted",
        severity             = "Medium",
        explanation_template = (
            "AccountDeleted: A user account was deleted (Windows Event 4726) "
            "from {ip} at {ts} (account: {username}). Verify that this deletion "
            "was authorised."
        ),
    ))

    # Rule 9 – Group Membership Changed (Windows 4732, immediate)
    raw.extend(_immediate_rule(
        df,
        event_type_filter    = "GROUP_MEMBER_ADDED",
        rule_name            = "GroupMemberAdded",
        severity             = "Low",
        explanation_template = (
            "GroupMemberAdded: A member was added to a security-enabled local "
            "group (Windows Event 4732) from {ip} at {ts} (account: {username}). "
            "Confirm this group-membership change was authorised."
        ),
    ))

    # Rule 10 – Audit Log Cleared (Windows 1102, immediate, Critical)
    raw.extend(_immediate_rule(
        df,
        event_type_filter    = "AUDIT_LOG_CLEARED",
        rule_name            = "AuditLogCleared",
        severity             = "Critical",
        explanation_template = (
            "AuditLogCleared: The Windows Security audit log was cleared "
            "(Windows Event 1102) from {ip} at {ts} (user: {username}). "
            "Audit log clearing removes evidence of prior activity and warrants "
            "immediate investigation. Confirm whether this was an authorised "
            "administrative operation."
        ),
    ))

    # Rule 11 – Repeated privilege assignments in a short window
    raw.extend(_sliding_window_rule(
        df,
        event_type_filter    = "PRIVILEGE_ESCALATION",
        threshold            = config.priv_assigned_threshold,
        window_seconds       = config.priv_assigned_window_seconds,
        rule_name            = "PrivilegeAssigned",
        severity             = "High",
        explanation_template = (
            "PrivilegeAssigned: {count} special-privilege assignments (Windows "
            "Event 4672) from {ip} within {window} seconds. Repeated privilege "
            "assignments in a short window may indicate lateral movement or "
            "unexpected session activity. Review the account and session context."
        ),
    ))

    # Phase 5/6 – Correlation rules (Windows logs, or explicit config)
    is_windows = ("win_event_id" in df.columns)
    if is_windows or config.enable_logon_after_brute_force:
        raw.extend(_logon_after_failures_rule(
            df,
            failure_threshold = config.logon_after_failures_threshold,
            window_seconds    = config.logon_after_failures_window_seconds,
        ))

    if is_windows:
        raw.extend(_suspicious_account_lifecycle_rule(
            df,
            window_seconds = config.account_lifecycle_window_seconds,
        ))

    # Phase 6 – Multi-account changes
    if config.enable_multi_account_changes:
        raw.extend(_multi_account_changes_rule(
            df,
            threshold      = config.multi_account_changes_threshold,
            window_seconds = config.multi_account_changes_window_seconds,
        ))

    alerts = _merge_matches(raw, dedup_window_seconds=config.dedup_window_seconds)

    # Sort: highest risk_score first, then source IP ascending
    alerts.sort(
        key=lambda a: (-a.risk_score, a.source_ip)
    )
    return alerts
