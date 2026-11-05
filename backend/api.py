"""
ThreatLens – FastAPI Backend API
=================================
REST API layer exposing the ThreatLens detection engine to the frontend.

Endpoints:
    GET  /api/health      - System health status and engine readiness
    GET  /api/summary     - Summary metrics, chart series, and IP stats
    GET  /api/alerts      - Filterable list of security alerts
    GET  /api/logs        - Filterable list of parsed log rows
    POST /api/analyze     - Upload and analyze a CSV log file
    POST /api/reset       - Reset to default sample dataset

⚠️  All log data and alerts are simulated for demonstration purposes.
    No live network monitoring, packet capture, or external calls are made.
"""

from __future__ import annotations

import io
import hmac
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd
from fastapi import FastAPI, File, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.detector import Alert, DetectorConfig, SEVERITY_RANK, run_detection
from backend.log_parser import load_log
from backend.windows_log_importer import (
    EVENT_ID_MAP,
    load_windows_log,
    is_windows_log,
    get_supported_event_ids,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threatlens.api")

app = FastAPI(
    title="ThreatLens SOC API",
    description="Security Operations Center log parsing and threat detection API.",
    version="1.0.0",
)

# ── Production Environment Settings ───────────────────────────────────────────
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024
MAX_UPLOAD_ROWS = int(os.getenv("MAX_UPLOAD_ROWS", "50000"))
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() in ("true", "1", "yes")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
PORTFOLIO_READ_ONLY = os.getenv("PORTFOLIO_READ_ONLY", os.getenv("PUBLIC_DEMO_MODE", "false")).lower() in ("true", "1", "yes")
SAMPLE_CSV_PATH = Path(__file__).parent / "data" / "sample_logs.csv"


def _verify_write_permission(
    x_admin_key: Optional[str] = None,
    authorization: Optional[str] = None,
    action: str = "Live log analysis and state changes are",
) -> None:
    """
    Validates whether write operations are permitted.
    In local development (PORTFOLIO_READ_ONLY=False), write operations are unrestricted.
    In public portfolio mode (PORTFOLIO_READ_ONLY=True), only requests with a valid
    ADMIN_API_KEY via the X-Admin-Key or Authorization header are permitted.
    """
    if not PORTFOLIO_READ_ONLY:
        return

    token = authorization.replace("Bearer ", "").strip() if authorization and "Bearer " in authorization else None
    key = x_admin_key or token

    if ADMIN_API_KEY and key and hmac.compare_digest(key, ADMIN_API_KEY):
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            f"{action} disabled in this public portfolio deployment to prevent "
            "shared state modification. Please switch to Demo Mode in the top navigation to explore "
            "all SOC dashboard features, or run ThreatLens locally for full custom log analysis."
        ),
    )

# ── CORS Configuration ────────────────────────────────────────────────────────
# Local development origins always supported
LOCAL_DEV_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Production frontend origins via environment variable (comma-separated supported)
# e.g. FRONTEND_ORIGIN="https://threatlens.vercel.app"
_custom_origins_raw = os.getenv("FRONTEND_ORIGIN", "") or os.getenv("ALLOWED_ORIGINS", "")
_custom_origins = [
    orig.strip().rstrip("/")
    for orig in _custom_origins_raw.split(",")
    if orig.strip() and orig.strip() != "*"
]

ALLOWED_ORIGINS = list(dict.fromkeys(LOCAL_DEV_ORIGINS + _custom_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Rate Limiter & Security Safeguards ─────────────────────────────────────────
class SlidingWindowRateLimiter:
    """
    In-memory rate limiter per client IP.
    Bypassed during automated testing and when RATE_LIMIT_ENABLED is disabled.
    """
    def __init__(self, default_limit: int = 120, upload_limit: int = 20) -> None:
        self.default_limit = default_limit
        self.upload_limit = upload_limit
        self._history: dict[str, list[float]] = defaultdict(list)
        self._upload_history: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, ip: str, is_upload: bool = False) -> tuple[bool, int]:
        now = time.time()
        window = 60.0
        limit = self.upload_limit if is_upload else self.default_limit
        store = self._upload_history if is_upload else self._history
        hist = store[ip]

        # Prune entries older than 60 seconds
        cutoff = now - window
        hist[:] = [t for t in hist if t > cutoff]

        # Prevent unbounded dictionary memory growth from inactive IPs
        if not hist and len(store) > 1000:
            store.pop(ip, None)

        if len(hist) >= limit:
            retry_after = int(window - (now - hist[0])) + 1
            return False, max(1, retry_after)

        hist.append(now)
        return True, 0


rate_limiter = SlidingWindowRateLimiter()


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    # Preflight OPTIONS requests skip rate limiting
    if request.method == "OPTIONS":
        return await call_next(request)

    client_ip = _get_client_ip(request)
    is_test = client_ip in ("testclient",) or os.getenv("TESTING") == "true"

    if RATE_LIMIT_ENABLED and not is_test:
        is_upload = request.url.path in ("/api/analyze", "/api/analyze/windows")
        allowed, retry_after = rate_limiter.is_allowed(client_ip, is_upload=is_upload)
        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many requests. Please slow down and try again shortly."},
                headers={"Retry-After": str(retry_after)},
            )

    response = await call_next(request)

    # Standard security headers on all responses
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )
    logger.error("Unhandled error on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected server error occurred while processing log data. Details logged safely to the server."},
    )


# ── Alert transformation ──────────────────────────────────────────────────────

def format_alert(alert: Alert) -> dict[str, Any]:
    """Convert an Alert dataclass into a frontend-friendly dictionary."""
    ts = alert.generated_at
    if alert.evidence and "timestamp" in alert.evidence[0]:
        ts = str(alert.evidence[0]["timestamp"])

    # Determine first/last observed from evidence timestamps
    evidence_timestamps = [e.get("timestamp", "") for e in alert.evidence if e.get("timestamp")]
    first_seen = min(evidence_timestamps) if evidence_timestamps else ts
    last_seen  = max(evidence_timestamps) if evidence_timestamps else ts

    triggering_count = getattr(
        alert,
        "triggering_count",
        sum(1 for e in alert.evidence if e.get("evidence_role") != "correlated_context"),
    )
    context_count = getattr(
        alert,
        "context_count",
        sum(1 for e in alert.evidence if e.get("evidence_role") == "correlated_context"),
    )

    return {
        "id":                   alert.alert_id,
        "timestamp":            ts,
        "first_seen":           first_seen,
        "last_seen":            last_seen,
        "sourceIP":             alert.source_ip,
        "source_ip":            alert.source_ip,
        "eventType":            alert.event_type,
        "event_type":           alert.event_type,
        "severity":             alert.severity,
        "status":               "Open",
        "details":              alert.explanation,
        "explanation":          alert.explanation,
        "rules_matched":        alert.rules_matched,
        "evidence":             alert.evidence,
        "evidence_count":       len(alert.evidence),
        "triggering_count":     triggering_count,
        "context_count":        context_count,
        # Phase 6 fields
        "risk_score":           alert.risk_score,
        "priority_label":       alert.priority_label,
        "score_factors":        alert.score_factors,
        "investigation_steps":  alert.investigation_steps,
        "affected_account":     alert.affected_account,
        "limitations":          alert.limitations,
    }


# ── In-memory state ───────────────────────────────────────────────────────────

class StateManager:
    """
    Manages currently analyzed logs, generated alerts, and detection config
    in memory.

    Note: configuration is stored in memory only and resets when the backend
    restarts. There is no authentication on the config endpoint; it is intended
    for use on localhost only.
    """

    def __init__(self) -> None:
        self.df: Optional[pd.DataFrame] = None
        self.alerts: list[Alert] = []
        self.dataset_name: str = "None"
        self.analyzed_at: str = datetime.now(timezone.utc).isoformat()
        self.is_sample: bool = False
        self.log_format: str = "standard"
        self.import_report: Optional[dict] = None
        self.config: DetectorConfig = DetectorConfig()  # Phase 6: shared config
        # Clean startup: backend starts with an empty dataset by default.
        # Live mode displays zero metrics until the user uploads logs.

    def reset_to_empty(self) -> None:
        """Clear all active data, returning to a clean empty state (Live Mode reset)."""
        self.df = None
        self.alerts = []
        self.dataset_name = "None"
        self.analyzed_at = datetime.now(timezone.utc).isoformat()
        self.is_sample = False
        self.log_format = "standard"
        self.import_report = None
        logger.info("Reset backend state to clean empty dataset.")

    def reset_to_sample(self) -> None:
        """Explicitly load the synthetic sample_logs.csv dataset (demo / test mechanism)."""
        if SAMPLE_CSV_PATH.exists():
            try:
                self.df = load_log(SAMPLE_CSV_PATH)
                self.alerts = run_detection(self.df, self.config)
                self.dataset_name = "sample_logs.csv (Simulated Demo)"
                self.analyzed_at = datetime.now(timezone.utc).isoformat()
                self.is_sample = True
                self.log_format = "standard"
                self.import_report = None
                logger.info("Loaded sample dataset: %d rows, %d alerts.", len(self.df), len(self.alerts))
            except Exception as exc:
                logger.warning("Failed to load sample data: %s", exc)
                self.reset_to_empty()

    def _load_initial_data(self) -> None:
        """Load default sample_logs.csv if explicitly requested."""
        self.reset_to_sample()

    def set_data(
        self,
        df: pd.DataFrame,
        alerts: list[Alert],
        filename: str,
        is_sample: bool = False,
        log_format: str = "standard",
        import_report: Optional[dict] = None,
    ) -> None:
        self.df = df
        self.alerts = alerts
        self.dataset_name = filename
        self.analyzed_at = datetime.now(timezone.utc).isoformat()
        self.is_sample = is_sample
        self.log_format = log_format
        self.import_report = import_report


state = StateManager()


# ── Helper to build summary stats and charts ──────────────────────────────────

def compute_summary(
    df: Optional[pd.DataFrame],
    alerts: list[Alert],
    dataset_name: str,
    analyzed_at: str,
    is_sample: bool,
    log_format: str = "standard",
    import_report: Optional[dict] = None,
) -> dict[str, Any]:
    if df is None or df.empty:
        return {
            "summaryStats": {
                "totalEvents": 0,
                "threatsDetected": 0,
                "criticalAlerts": 0,
                "uniqueIPs": 0,
                "highPriorityAlerts": 0,
            },
            "severityData": [
                {"name": "Critical", "value": 0, "color": "#ef4444"},
                {"name": "High", "value": 0, "color": "#f97316"},
                {"name": "Medium", "value": 0, "color": "#eab308"},
                {"name": "Low", "value": 0, "color": "#22c55e"},
            ],
            "activityData": [],
            "suspiciousIPs": [],
            "topRules": [],
            "metadata": {
                "datasetName": dataset_name,
                "analyzedAt": analyzed_at,
                "isSample": is_sample,
                "rowsProcessed": 0,
                "alertsDetected": 0,
                "logFormat": log_format,
                "importReport": import_report,
            },
        }

    total_events = len(df)
    threats_detected = len(alerts)
    critical_alerts = sum(1 for a in alerts if a.severity == "Critical")
    unique_ips = int(df["source_ip"].nunique())

    # Severity distribution
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in alerts:
        if a.severity in sev_counts:
            sev_counts[a.severity] += 1
        else:
            sev_counts["Low"] += 1

    severity_data = [
        {"name": "Critical", "value": sev_counts["Critical"], "color": "#ef4444"},
        {"name": "High", "value": sev_counts["High"], "color": "#f97316"},
        {"name": "Medium", "value": sev_counts["Medium"], "color": "#eab308"},
        {"name": "Low", "value": sev_counts["Low"], "color": "#22c55e"},
    ]

    # Activity timeline: group events by time buckets
    df_sorted = df.sort_values("timestamp")
    time_span_seconds = (df_sorted["timestamp"].max() - df_sorted["timestamp"].min()).total_seconds()

    # Alert timestamps map
    alert_times: list[pd.Timestamp] = []
    for a in alerts:
        for ev in a.evidence:
            try:
                alert_times.append(pd.to_datetime(ev["timestamp"]))
            except Exception:
                pass

    activity_data = []
    if time_span_seconds > 86400 * 2:
        # Group by day
        freq = "1D"
        fmt = "%b %d"
    elif time_span_seconds > 3600 * 3:
        # Group by hour
        freq = "1h"
        fmt = "%H:00"
    else:
        # Short duration: 5 or 10 min buckets
        freq = "5min"
        fmt = "%H:%M"

    try:
        grouped = df_sorted.set_index("timestamp").resample(freq).size()
        for ts, count in grouped.items():
            bucket_end = ts + pd.Timedelta(freq)
            # Count alerts in this bucket
            bucket_threats = sum(1 for at in alert_times if ts <= at < bucket_end)
            activity_data.append({
                "date": ts.strftime(fmt),
                "events": int(count),
                "threats": bucket_threats,
            })
    except Exception:
        activity_data = []

    # Suspicious IPs list
    ip_events = df["source_ip"].value_counts().to_dict()
    ip_alerts: dict[str, list[Alert]] = {}
    for a in alerts:
        ip_alerts.setdefault(a.source_ip, []).append(a)

    suspicious_ips = []
    # Rank IPs that have alerts first, then highest event counts
    all_ips = set(ip_events.keys()) | set(ip_alerts.keys())
    for ip in all_ips:
        al_list = ip_alerts.get(ip, [])
        sev_rank = max([SEVERITY_RANK.get(a.severity, 0) for a in al_list], default=-1)
        sev_label = "Low"
        for k, v in SEVERITY_RANK.items():
            if v == sev_rank:
                sev_label = k
                break
        if sev_rank == -1:
            sev_label = "Normal"

        status_str = "Active Threat" if al_list else "Monitoring"
        ip_rows = df[df["source_ip"] == ip]
        last_seen = str(ip_rows["timestamp"].max()) if not ip_rows.empty else ""
        first_seen = str(ip_rows["timestamp"].min()) if not ip_rows.empty else ""
        top_threat = al_list[0].event_type if al_list else "Normal Traffic"
        event_cnt = int(ip_events.get(ip, 0))

        suspicious_ips.append({
            "ip": ip,
            "events": event_cnt,
            "eventCount": event_cnt,
            "threats": len(al_list),
            "threatLevel": sev_label,
            "severity": sev_label if sev_label != "Normal" else "Low",
            "topThreat": top_threat,
            "status": status_str,
            "firstSeen": first_seen,
            "lastSeen": last_seen,
            "hasAlerts": len(al_list) > 0,
        })

    suspicious_ips.sort(key=lambda item: (-item["threats"], -item["events"]))
    suspicious_ips = suspicious_ips[:10]

    # Top rules by alert count
    rule_counts: dict[str, int] = {}
    high_priority_count = 0
    for a in alerts:
        for r in a.rules_matched:
            rule_counts[r] = rule_counts.get(r, 0) + 1
        if getattr(a, "priority_label", a.severity) in ("High", "Critical"):
            high_priority_count += 1

    top_rules = [
        {"rule": rule, "count": count}
        for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:5]
    ]

    return {
        "summaryStats": {
            "totalEvents": total_events,
            "threatsDetected": threats_detected,
            "criticalAlerts": critical_alerts,
            "uniqueIPs": unique_ips,
            "highPriorityAlerts": high_priority_count,
        },
        "severityData": severity_data,
        "activityData": activity_data,
        "suspiciousIPs": suspicious_ips,
        "topRules": top_rules,
        "metadata": {
            "datasetName": dataset_name,
            "analyzedAt": analyzed_at,
            "isSample": is_sample,
            "rowsProcessed": total_events,
            "alertsDetected": threats_detected,
            "logFormat": log_format,
            "importReport": import_report,
        },
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
def get_health() -> dict[str, Any]:
    """Health check endpoint confirming API service and detection engine status."""
    return {
        "status": "ok",
        "service": "threatlens-api",
        "version": "1.0.0",
        "engine": "ready",
        "dataset_loaded": state.df is not None and not state.df.empty,
        "total_rows": len(state.df) if state.df is not None else 0,
        "total_alerts": len(state.alerts),
        "log_format": state.log_format,
        "read_only": PORTFOLIO_READ_ONLY,
        "mode": "portfolio_read_only" if PORTFOLIO_READ_ONLY else "full_access",
    }


@app.get("/api/summary")
def get_summary() -> dict[str, Any]:
    """Return summary metrics, charts, and suspicious IP rankings for current dataset."""
    return compute_summary(
        state.df,
        state.alerts,
        state.dataset_name,
        state.analyzed_at,
        state.is_sample,
        state.log_format,
        state.import_report,
    )


@app.get("/api/alerts")
def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity: Critical, High, Medium, Low"),
    status: Optional[str] = Query(None, description="Filter by status: Open, Investigating, Resolved, etc."),
    event_type: Optional[str] = Query(None, description="Filter by event type, e.g. LOGIN_FAILURE"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP address (partial match)"),
    search: Optional[str] = Query(None, description="Free text search across IP, event_type, details, rule"),
    rule: Optional[str] = Query(None, description="Filter by detection rule name, e.g. BruteForce"),
    priority_label: Optional[str] = Query(None, description="Filter by priority label: Low, Medium, High, Critical"),
    affected_account: Optional[str] = Query(None, description="Filter by affected account (partial match)"),
) -> dict[str, Any]:
    """Retrieve structured alerts with optional severity, status, event_type, source_ip, rule, priority, account, and text search filters."""
    formatted = [format_alert(a) for a in state.alerts]

    results = []
    for item in formatted:
        # Severity filter
        if severity and severity.lower() != "all" and item["severity"].lower() != severity.lower():
            continue

        # Status filter
        if status and status.lower() != "all" and item["status"].lower() != status.lower():
            continue

        # Event type filter
        if event_type and event_type.lower() != "all":
            item_et = (item.get("eventType") or item.get("event_type") or "").lower()
            if event_type.lower() not in item_et:
                continue

        # Source IP filter (partial match)
        if source_ip and source_ip.lower() != "all":
            item_ip = (item.get("sourceIP") or item.get("source_ip") or "").lower()
            if source_ip.lower() not in item_ip:
                continue

        # Rule name filter (exact or partial)
        if rule and rule.lower() != "all":
            item_rules = " ".join(item.get("rules_matched") or []).lower()
            if rule.lower() not in item_rules:
                continue

        # Priority label filter
        if priority_label and priority_label.lower() != "all":
            if item.get("priority_label", "").lower() != priority_label.lower():
                continue

        # Affected account filter (partial match)
        if affected_account and affected_account.strip():
            if affected_account.lower() not in (item.get("affected_account") or "").lower():
                continue

        # Search filter
        if search:
            q = search.lower().strip()
            rules_str = " ".join(item.get("rules_matched") or [])
            text_corpus = (
                f"{item['id']} {item['sourceIP']} {item['eventType']} "
                f"{item['details']} {rules_str} {item.get('affected_account', '')}"
            ).lower()
            if q not in text_corpus:
                continue

        results.append(item)

    return {
        "total": len(results),
        "dataset_total": len(formatted),
        "alerts": results,
    }


@app.get("/api/logs")
def get_logs(
    level: Optional[str] = Query(None, description="Filter by level: ALL, CRITICAL, ERROR, WARN, INFO"),
    search: Optional[str] = Query(None, description="Search in source IP, event_type, message"),
    limit: int = Query(200, ge=1, le=1000, description="Max logs to return"),
) -> dict[str, Any]:
    """Return parsed log entries formatted for the Log Analysis viewer."""
    if state.df is None or state.df.empty:
        return {"total": 0, "logs": []}

    # Map event_types and statuses to log levels
    logs = []
    for idx, row in state.df.iterrows():
        event_type = str(row["event_type"])
        status_val = str(row["status"])
        source_ip = str(row["source_ip"])
        username = str(row["username"])
        timestamp = str(row["timestamp"])

        if event_type in ("MALWARE_DETECTED", "PRIVILEGE_ESCALATION"):
            lvl = "CRITICAL"
        elif status_val in ("FAILURE", "BLOCKED") or event_type in ("PORT_SCAN", "LOGIN_FAILURE"):
            lvl = "WARN"
        elif status_val == "ERROR":
            lvl = "ERROR"
        else:
            lvl = "INFO"

        win_eid = row.get("win_event_id") if "win_event_id" in row and pd.notna(row["win_event_id"]) else None
        msg_user = f" user: {username}" if username else ""
        if win_eid:
            msg = f"[Event {int(win_eid)}: {event_type}] from {source_ip}{msg_user} – Status: {status_val}"
        else:
            msg = f"[{event_type}] from {source_ip}{msg_user} – Status: {status_val}"

        entry = {
            "id": f"LOG-{idx + 1:04d}",
            "timestamp": timestamp,
            "source": source_ip,
            "level": lvl,
            "message": msg,
            "event_type": event_type,
            "username": username,
            "status": status_val,
        }
        if win_eid:
            entry["win_event_id"] = int(win_eid)
        if "win_label" in row and pd.notna(row["win_label"]) and row["win_label"]:
            entry["win_label"] = str(row["win_label"])
        if "win_computer" in row and pd.notna(row["win_computer"]) and row["win_computer"]:
            entry["win_computer"] = str(row["win_computer"])
        if "win_description" in row and pd.notna(row["win_description"]) and row["win_description"]:
            entry["win_description"] = str(row["win_description"])

        # Level filter
        if level and level.upper() != "ALL" and entry["level"] != level.upper():
            continue

        # Search filter
        if search:
            q = search.lower().strip()
            win_extra = f"{entry.get('win_event_id', '')} {entry.get('win_label', '')} {entry.get('win_computer', '')}".lower()
            corpus = f"{entry['id']} {entry['source']} {entry['message']} {entry['event_type']} {entry['username']} {win_extra}".lower()
            if q not in corpus:
                continue

        logs.append(entry)

    total_matched = len(logs)
    return {
        "total": total_matched,
        "logs": logs[:limit],
    }


@app.get("/api/windows/supported-events")
def get_windows_supported_events() -> dict[str, Any]:
    """Return supported Windows Security event IDs and their ThreatLens mappings."""
    event_ids = get_supported_event_ids()
    events = []
    for eid, info in EVENT_ID_MAP.items():
        events.append({
            "event_id": eid,
            "event_type": info["event_type"],
            "status": info["status"],
            "label": info["label"],
        })
    return {
        "supported_event_ids": sorted(list(event_ids.keys())),
        "events": events,
    }


async def _read_upload_file_safe(file: UploadFile, max_bytes: int) -> bytes:
    """
    Safely reads an uploaded file in chunks up to max_bytes without buffering
    excessive memory, and ensures temporary file handles are always closed.
    """
    chunks: list[bytes] = []
    total_bytes = 0
    chunk_size = 64 * 1024  # 64 KB chunks

    try:
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum size limit of {max_bytes // (1024 * 1024)} MB.",
                )
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        await file.close()


@app.post("/api/analyze/windows")
async def analyze_windows_file(
    file: UploadFile = File(...),
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None),
) -> dict[str, Any]:
    """Import and analyze an exported Windows Security event log CSV file."""
    _verify_write_permission(x_admin_key, authorization, action="Windows log upload and analysis is")
    raw_filename = file.filename or "windows_security_log.csv"
    filename = os.path.basename(raw_filename)
    if not filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only Windows Event Viewer CSV exports (.csv) are accepted. Native .evtx files are not supported.",
        )

    try:
        content_bytes = await _read_upload_file_safe(file, MAX_UPLOAD_SIZE_BYTES)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read file content: {exc}",
        )

    if len(content_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded Windows log file is empty.",
        )

    try:
        text_content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text_content = content_bytes.decode("utf-16")
        except UnicodeDecodeError:
            try:
                text_content = content_bytes.decode("latin-1")
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File encoding error: {exc}. Please upload a UTF-8 or UTF-16 encoded CSV file.",
                )

    try:
        df, report = load_windows_log(io.StringIO(text_content))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Windows log import error: {exc}",
        )
    except Exception as exc:
        logger.error("Unexpected parsing error in Windows log: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unexpected error parsing the Windows CSV file. Please ensure the file is a properly formatted Windows Event Viewer CSV export.",
        )

    if len(df) > MAX_UPLOAD_ROWS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Uploaded log contains {len(df)} rows, exceeding the portfolio analysis limit of {MAX_UPLOAD_ROWS} rows. Please upload a smaller log extract.",
        )

    try:
        alerts = run_detection(df, state.config)
    except Exception as exc:
        logger.error("Detection engine error in Windows analysis: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Detection engine encountered an internal error during analysis.",
        )

    report_dict = report.to_dict()
    state.set_data(
        df=df,
        alerts=alerts,
        filename=filename,
        is_sample=False,
        log_format="windows_event_viewer",
        import_report=report_dict,
    )

    summary = compute_summary(
        df=df,
        alerts=alerts,
        dataset_name=filename,
        analyzed_at=state.analyzed_at,
        is_sample=False,
        log_format="windows_event_viewer",
        import_report=report_dict,
    )
    formatted_alerts = [format_alert(a) for a in alerts]

    return {
        "success": True,
        "filename": filename,
        "format": "windows_event_viewer",
        "rows_processed": len(df),
        "alerts_detected": len(alerts),
        "import_report": report_dict,
        "summary": summary,
        "alerts": formatted_alerts,
    }


@app.post("/api/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    log_format: Optional[str] = Query(None, description="Optional log format: 'standard' or 'windows'"),
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None),
) -> dict[str, Any]:
    """Analyze an uploaded CSV security log file and return structured detection results."""
    _verify_write_permission(x_admin_key, authorization, action="Live CSV log upload and analysis is")
    # 1. Validate filename
    raw_filename = file.filename or "uploaded.csv"
    filename = os.path.basename(raw_filename)
    if not filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only CSV files (.csv) are accepted.",
        )

    # 2. Read contents with streaming size restriction and handle cleanup
    try:
        content_bytes = await _read_upload_file_safe(file, MAX_UPLOAD_SIZE_BYTES)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read file content: {exc}",
        )

    if len(content_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file is empty.",
        )

    # 3. Decode as text
    try:
        text_content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text_content = content_bytes.decode("latin-1")
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File encoding error: {exc}. Please upload a UTF-8 encoded CSV file.",
            )

    # 4. Parse using appropriate parser
    report_dict = None
    format_name = "standard"
    if log_format == "windows" or (log_format is None and is_windows_log(io.StringIO(text_content))):
        try:
            df, report = load_windows_log(io.StringIO(text_content))
            report_dict = report.to_dict()
            format_name = "windows_event_viewer"
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Windows log import error: {exc}",
            )
        except Exception as exc:
            logger.error("Unexpected parsing error in Windows log: %s", exc, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unexpected error parsing the Windows CSV file. Please ensure the file is a properly formatted Windows Event Viewer CSV export.",
            )
    else:
        try:
            df = load_log(io.StringIO(text_content))
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"CSV validation error: {exc}",
            )
        except Exception as exc:
            logger.error("Unexpected parsing error in standard log: %s", exc, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unexpected error parsing the CSV file. Please ensure the file is a properly formatted CSV.",
            )

    if len(df) > MAX_UPLOAD_ROWS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Uploaded log contains {len(df)} rows, exceeding the portfolio analysis limit of {MAX_UPLOAD_ROWS} rows. Please upload a smaller log extract.",
        )

    # 5. Run detection rules
    try:
        alerts = run_detection(df, state.config)
    except Exception as exc:
        logger.error("Detection engine error during standard analysis: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Detection engine encountered an internal error during analysis.",
        )

    # 6. Update in-memory state
    state.set_data(
        df=df,
        alerts=alerts,
        filename=filename,
        is_sample=False,
        log_format=format_name,
        import_report=report_dict,
    )

    summary = compute_summary(
        df=df,
        alerts=alerts,
        dataset_name=filename,
        analyzed_at=state.analyzed_at,
        is_sample=False,
        log_format=format_name,
        import_report=report_dict,
    )
    formatted_alerts = [format_alert(a) for a in alerts]

    res = {
        "success": True,
        "filename": filename,
        "rows_processed": len(df),
        "alerts_detected": len(alerts),
        "summary": summary,
        "alerts": formatted_alerts,
    }
    if report_dict:
        res["import_report"] = report_dict
        res["format"] = format_name

    return res


@app.post("/api/reset")
def reset_dataset(
    sample: bool = Query(
        False,
        description="If True, reloads the sample_logs.csv dataset. Defaults to False (resets to clean empty state for Live Mode).",
    ),
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None),
) -> dict[str, Any]:
    """
    Reset active analysis state.

    By default, resets to a clean empty state for Live Mode (0 events, 0 alerts).
    If ?sample=true is passed, restores the synthetic demonstration dataset.
    """
    _verify_write_permission(x_admin_key, authorization, action="Resetting active analysis data is")
    if sample:
        state.reset_to_sample()
        msg = "Reset to default sample dataset."
    else:
        state.reset_to_empty()
        msg = "Reset to clean empty state."

    return {
        "success": True,
        "message": msg,
        "summary": compute_summary(
            state.df,
            state.alerts,
            state.dataset_name,
            state.analyzed_at,
            state.is_sample,
            state.log_format,
            state.import_report,
        ),
    }


@app.post("/api/sample")
def load_sample_dataset(
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None),
) -> dict[str, Any]:
    """
    Dedicated endpoint to explicitly load the synthetic sample_logs.csv dataset.

    Provides an isolated mechanism for demonstration or testing without
    contaminating live backend startup state.
    """
    _verify_write_permission(x_admin_key, authorization, action="Loading sample datasets via the API is")
    state.reset_to_sample()
    return {
        "success": True,
        "message": "Loaded standard sample dataset.",
        "summary": compute_summary(
            state.df,
            state.alerts,
            state.dataset_name,
            state.analyzed_at,
            state.is_sample,
            state.log_format,
            state.import_report,
        ),
    }


# ── Phase 6: Detection configuration endpoints ────────────────────────────────

@app.get("/api/detection/config")
def get_detection_config() -> dict[str, Any]:
    """
    Retrieve the current detection configuration.

    Configuration is stored in memory and resets to defaults when the backend
    restarts. This endpoint is intended for localhost use only; there is no
    authentication.
    """
    return {
        "config": state.config.to_dict(),
        "defaults": DetectorConfig.defaults(),
        "note": (
            "Configuration is stored in memory only and resets to defaults on "
            "backend restart. No authentication is required for this endpoint."
        ),
    }


@app.put("/api/detection/config")
def update_detection_config(
    body: dict,
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None),
) -> dict[str, Any]:
    """
    Update detection configuration thresholds.

    Only recognised field names from DetectorConfig are accepted; unrecognised
    keys are rejected. Invalid values are validated and rejected before any
    changes are applied.

    Configuration changes take effect on the next analysis request. The currently
    loaded alerts are NOT automatically re-computed; upload or reset to apply
    new thresholds to existing data.

    Configuration is stored in memory only and resets on backend restart.
    If ADMIN_API_KEY is configured in the environment, requests must provide
    the matching key via the X-Admin-Key or Authorization header.
    """
    _verify_write_permission(x_admin_key, authorization, action="Modifying detection thresholds is")
    if ADMIN_API_KEY:
        token = authorization.replace("Bearer ", "").strip() if authorization and "Bearer " in authorization else None
        key = x_admin_key or token
        if not key or not hmac.compare_digest(key, ADMIN_API_KEY):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrative authorization required to modify detection configuration in this deployment.",
            )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be a JSON object.",
        )

    known_fields = set(DetectorConfig.__dataclass_fields__.keys())  # type: ignore[attr-defined]
    unknown = set(body.keys()) - known_fields
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown configuration fields: {sorted(unknown)}. "
                   f"Accepted fields: {sorted(known_fields)}.",
        )

    # Build a merged dict: current config overridden by request body
    merged = state.config.to_dict()
    merged.update(body)

    try:
        candidate = DetectorConfig.from_dict(merged)
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid configuration value: {exc}",
        )

    errors = candidate.validate()
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "Configuration validation failed.", "errors": errors},
        )

    state.config = candidate
    logger.info("Detection configuration updated: %s", body)

    return {
        "success": True,
        "message": "Configuration updated. Re-upload or reset data to apply new thresholds.",
        "config": state.config.to_dict(),
    }
