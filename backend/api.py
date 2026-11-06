"""
ThreatLens – FastAPI Backend API
=================================
REST API layer exposing the ThreatLens detection engine to the frontend.

Endpoints:
    GET    /api/health      - Health, capabilities (uploads enabled, session mode, limits)
    POST   /api/session     - Issue a visitor session token (MULTI_TENANT_SESSIONS only)
    DELETE /api/session     - End the caller's visitor session
    GET    /api/summary     - Summary metrics, chart series, and IP stats
    GET    /api/alerts      - Filterable list of security alerts
    GET    /api/logs        - Filterable list of parsed log rows
    POST   /api/analyze     - Upload and analyze a CSV log file
    POST   /api/analyze/windows - Import a Windows Event Viewer CSV export
    POST   /api/reset       - Reset the dataset (empty, or ?sample=true)
    POST   /api/sample      - Load the synthetic sample dataset
    GET/PUT /api/detection/config - Detection thresholds

Data scoping
------------
* MULTI_TENANT_SESSIONS=false (local development, tests): one process-wide
  dataset in ``state`` – exactly the historical behaviour.
* MULTI_TENANT_SESSIONS=true (public deployment): there is NO shared dataset.
  Every data endpoint requires an ``X-Session-ID`` header naming a visitor
  session issued by ``POST /api/session``. Summaries, alerts, logs, uploads,
  resets, sample loading and detection configuration all act on that
  session's private state only. A missing, malformed, unknown or expired token
  gets HTTP 401 - there is never a fallback to another dataset.
* PORTFOLIO_READ_ONLY=true is an emergency kill switch that blocks every write
  (uploads, resets, sample loading, config changes) in both modes unless the
  ADMIN_API_KEY is presented. It is independent of MULTI_TENANT_SESSIONS.

⚠️  All log data and alerts are simulated for demonstration purposes.
    No live network monitoring, packet capture, or external calls are made.
"""

from __future__ import annotations

import io
import hmac
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple, Optional, Union

import pandas as pd
from fastapi import FastAPI, File, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.detector import Alert, DetectorConfig, SEVERITY_RANK, run_detection
from backend.log_parser import load_log
from backend.session import (
    DataSnapshot,
    SessionCapacityError,
    SessionConcurrencyError,
    SessionConflictError,
    SessionError,
    SessionInvalidTokenError,
    SessionMemoryError,
    SessionState,
    estimate_dataset_memory,
    estimate_incoming_bytes,
    session_manager,
)
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
def _env_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("true", "1", "yes")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024
MAX_UPLOAD_ROWS = int(os.getenv("MAX_UPLOAD_ROWS", "50000"))
RATE_LIMIT_ENABLED = _env_flag("RATE_LIMIT_ENABLED", "true")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
SAMPLE_CSV_PATH = Path(__file__).parent / "data" / "sample_logs.csv"
SAMPLE_DATASET_NAME = "sample_logs.csv (Simulated Demo)"

# Per-visitor session mode. When true, every data endpoint is scoped to an
# X-Session-ID session and the shared global dataset is never served.
MULTI_TENANT_SESSIONS = _env_flag("MULTI_TENANT_SESSIONS", "false")
# How long a second mutation on the same session waits before reporting a conflict.
SESSION_TXN_TIMEOUT_SECONDS = _env_float("SESSION_TXN_TIMEOUT_SECONDS", 2.0)
# Extra bytes allowed on top of MAX_UPLOAD_SIZE_BYTES for multipart framing.
UPLOAD_ENVELOPE_BYTES = 256 * 1024
UPLOAD_PATHS = ("/api/analyze", "/api/analyze/windows")

_ON_PUBLIC_HOST = _env_flag("RENDER")  # Render sets RENDER=true on every service
_ALLOW_SHARED_GLOBAL_STATE = _env_flag("ALLOW_SHARED_GLOBAL_STATE")


def resolve_write_protection(
    read_only: bool, multi_tenant: bool, public_host: bool, allow_shared: bool
) -> tuple[bool, bool]:
    """
    Decide the effective read-only flag.

    Guard rail: on a public host (Render) with neither read-only mode nor
    per-visitor sessions, every visitor would share, and be able to overwrite,
    one in-memory dataset. That combination is forced back to read-only unless
    ALLOW_SHARED_GLOBAL_STATE=true is set explicitly.

    Returns (effective_read_only, was_forced).
    """
    if public_host and not multi_tenant and not read_only and not allow_shared:
        return True, True
    return read_only, False


_requested_read_only = os.getenv("PORTFOLIO_READ_ONLY", os.getenv("PUBLIC_DEMO_MODE", "false")).strip().lower() in (
    "true", "1", "yes",
)
PORTFOLIO_READ_ONLY, _READ_ONLY_FORCED = resolve_write_protection(
    _requested_read_only, MULTI_TENANT_SESSIONS, _ON_PUBLIC_HOST, _ALLOW_SHARED_GLOBAL_STATE
)
if _READ_ONLY_FORCED:
    logger.warning(
        "PORTFOLIO_READ_ONLY=false without MULTI_TENANT_SESSIONS=true on a public host would let "
        "visitors overwrite one shared dataset. Forcing read-only mode. Set MULTI_TENANT_SESSIONS=true "
        "to enable per-visitor uploads."
    )
logger.info(
    "ThreatLens write protection: read_only=%s multi_tenant_sessions=%s", PORTFOLIO_READ_ONLY, MULTI_TENANT_SESSIONS
)


def _verify_write_permission(
    x_admin_key: Optional[str] = None,
    authorization: Optional[str] = None,
    action: str = "Live log analysis and state changes are",
) -> None:
    """
    Validates whether write operations are permitted.
    With PORTFOLIO_READ_ONLY=False, writes are allowed (to the caller's own session in
    MULTI_TENANT_SESSIONS mode, to the process-wide dataset otherwise).
    With PORTFOLIO_READ_ONLY=True (emergency kill switch), only requests with a valid
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
    In-memory sliding-window limiter per client IP, with separate budgets for
    normal requests, uploads, and visitor-session creation.
    """
    _MAX_TRACKED_KEYS = 1000

    def __init__(self, default_limit: int = 120, upload_limit: int = 20, session_limit: int = 10) -> None:
        self.default_limit = default_limit
        self.upload_limit = upload_limit
        self.session_limit = session_limit
        self._stores: dict[str, dict[str, list[float]]] = {"default": {}, "upload": {}, "session": {}}
        self._lock = threading.Lock()

    def is_allowed(self, ip: str, is_upload: bool = False, is_session: bool = False) -> tuple[bool, int]:
        kind = "session" if is_session else ("upload" if is_upload else "default")
        limit = {"session": self.session_limit, "upload": self.upload_limit, "default": self.default_limit}[kind]
        window = 60.0
        now = time.time()
        cutoff = now - window

        with self._lock:
            store = self._stores[kind]
            # Bound memory: when many distinct keys accumulate, drop the ones that went quiet.
            if len(store) > self._MAX_TRACKED_KEYS:
                for key in [k for k, h in store.items() if not h or h[-1] <= cutoff]:
                    store.pop(key, None)

            hist = store.setdefault(ip, [])
            hist[:] = [t for t in hist if t > cutoff]
            if len(hist) >= limit:
                return False, max(1, int(window - (now - hist[0])) + 1)
            hist.append(now)
            return True, 0


def _env_int_setting(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


rate_limiter = SlidingWindowRateLimiter(
    default_limit=_env_int_setting("RATE_LIMIT_PER_MIN", 120),
    upload_limit=_env_int_setting("UPLOAD_RATE_LIMIT_PER_MIN", 20),
    session_limit=_env_int_setting("SESSION_CREATE_LIMIT_PER_MIN", 10),
)

# Which request header carries the real client IP. X-Forwarded-For is NOT trusted by
# default: Render appends to a client-supplied value, so its left-most entry is spoofable.
# Behind Render, Cloudflare sets True-Client-IP itself, so that is the default there.
# Set CLIENT_IP_HEADER (e.g. "true-client-ip", "cf-connecting-ip") to match your proxy.
CLIENT_IP_HEADER = os.getenv("CLIENT_IP_HEADER", "").strip().lower() or ("true-client-ip" if _ON_PUBLIC_HOST else "")


def _get_client_ip(request: Request) -> str:
    if CLIENT_IP_HEADER:
        value = request.headers.get(CLIENT_IP_HEADER, "").strip()
        if value:
            return value.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def _is_test_client(request: Request) -> bool:
    """Starlette's TestClient reports its socket peer as 'testclient'. Headers are never consulted."""
    return bool(request.client and request.client.host == "testclient")


def _json_error(status_code: int, detail: str, headers: Optional[dict[str, str]] = None) -> JSONResponse:
    resp = JSONResponse(status_code=status_code, content={"detail": detail}, headers=headers)
    return _with_security_headers(resp)


def _with_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    # Preflight OPTIONS requests skip rate limiting
    if request.method == "OPTIONS":
        return await call_next(request)

    path = request.url.path
    is_post = request.method == "POST"
    is_upload = is_post and path in UPLOAD_PATHS
    is_session_create = is_post and path == "/api/session"

    if RATE_LIMIT_ENABLED and not _is_test_client(request):
        allowed, retry_after = rate_limiter.is_allowed(
            _get_client_ip(request), is_upload=is_upload, is_session=is_session_create
        )
        if not allowed:
            return _json_error(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many requests. Please slow down and try again shortly.",
                headers={"Retry-After": str(retry_after)},
            )

    # Reject oversized uploads from the declared length, before the multipart body is
    # spooled to disk. The streaming check in _read_upload_file_safe remains the backstop.
    if is_upload:
        declared = request.headers.get("content-length")
        if declared is None:
            return _json_error(status.HTTP_411_LENGTH_REQUIRED, "A Content-Length header is required for file uploads.")
        try:
            too_big = int(declared) > MAX_UPLOAD_SIZE_BYTES + UPLOAD_ENVELOPE_BYTES
        except ValueError:
            return _json_error(status.HTTP_400_BAD_REQUEST, "Invalid Content-Length header.")
        if too_big:
            return _json_error(
                413,
                f"File exceeds maximum size limit of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB.",
            )

    response = await call_next(request)
    return _with_security_headers(response)


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


# ── In-memory state (single-tenant mode only) ─────────────────────────────────

class StateManager:
    """
    Process-wide dataset used when MULTI_TENANT_SESSIONS is false (local development
    and tests). In multi-tenant mode this object is never read or written by any
    endpoint; each visitor has a SessionState instead.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.df: Optional[pd.DataFrame] = None
        self.alerts: list[Alert] = []
        self.dataset_name: str = "None"
        self.analyzed_at: str = datetime.now(timezone.utc).isoformat()
        self.is_sample: bool = False
        self.log_format: str = "standard"
        self.import_report: Optional[dict] = None
        self.config: DetectorConfig = DetectorConfig()
        # Clean startup: backend starts with an empty dataset by default.

    def snapshot(self) -> DataSnapshot:
        with self._lock:
            return DataSnapshot(
                self.df, self.alerts, self.dataset_name, self.analyzed_at,
                self.is_sample, self.log_format, self.import_report, None,
            )

    def reset_to_empty(self) -> None:
        """Clear all active data, returning to a clean empty state (Live Mode reset)."""
        with self._lock:
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
                df = load_log(SAMPLE_CSV_PATH)
                alerts = run_detection(df, self.config)
                self.set_data(df, alerts, SAMPLE_DATASET_NAME, is_sample=True)
                logger.info("Loaded sample dataset: %d rows, %d alerts.", len(df), len(alerts))
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
        with self._lock:
            self.df = df
            self.alerts = alerts
            self.dataset_name = filename
            self.analyzed_at = datetime.now(timezone.utc).isoformat()
            self.is_sample = is_sample
            self.log_format = log_format
            self.import_report = import_report


state = StateManager()

DataContext = Union[StateManager, SessionState]


# ── Helper to build summary stats and charts ──────────────────────────────────

MAX_ACTIVITY_BUCKETS = 2000


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

    # Alert timestamps (parsed in one vectorised call; unparseable values are skipped)
    raw_alert_times = [ev["timestamp"] for a in alerts for ev in a.evidence if ev.get("timestamp")]
    try:
        alert_times = pd.to_datetime(pd.Series(raw_alert_times, dtype="object"), errors="coerce").dropna()
    except Exception:
        alert_times = pd.Series([], dtype="datetime64[ns]")

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
        # Guard: timestamps spread over decades would create a huge number of empty buckets.
        bucket_seconds = pd.Timedelta(freq).total_seconds()
        if time_span_seconds / bucket_seconds > MAX_ACTIVITY_BUCKETS:
            raise ValueError("time span too wide for an activity timeline")
        grouped = df_sorted.set_index("timestamp").resample(freq).size()
        for ts, count in grouped.items():
            bucket_end = ts + pd.Timedelta(freq)
            # Count alerts in this bucket
            bucket_threats = int(((alert_times >= ts) & (alert_times < bucket_end)).sum())
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

    # First/last seen per IP from one groupby (a per-IP full-frame filter is O(IPs x rows)).
    ts_bounds = df.groupby("source_ip")["timestamp"].agg(["min", "max"])
    first_by_ip = ts_bounds["min"].to_dict()
    last_by_ip = ts_bounds["max"].to_dict()

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
        last_seen = str(last_by_ip[ip]) if ip in last_by_ip else ""
        first_seen = str(first_by_ip[ip]) if ip in first_by_ip else ""
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

SESSION_INVALID_MESSAGE = (
    "Your visitor session is missing, invalid or has expired. "
    "A fresh session starts empty; re-upload your CSV to continue."
)


def _session_error_to_http(exc: SessionError) -> HTTPException:
    """Map session-manager failures onto stable HTTP statuses."""
    if isinstance(exc, SessionInvalidTokenError):
        return HTTPException(status.HTTP_401_UNAUTHORIZED, detail=SESSION_INVALID_MESSAGE)
    if isinstance(exc, SessionConflictError):
        return HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    if isinstance(exc, SessionMemoryError):
        return HTTPException(413, detail=str(exc))
    if isinstance(exc, SessionConcurrencyError):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc), headers={"Retry-After": "5"})
    if isinstance(exc, SessionCapacityError):
        return HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc), headers={"Retry-After": "30"})
    return HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Session error.")


def _resolve_context(x_session_id: Optional[str]) -> DataContext:
    """
    The dataset a request operates on.

    Multi-tenant mode: the caller's own session, or HTTP 401. There is deliberately no
    fallback to the shared ``state`` - a bad token must never expose another dataset.
    """
    if not MULTI_TENANT_SESSIONS:
        return state
    session = session_manager.get_session(x_session_id, touch=True)
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=SESSION_INVALID_MESSAGE)
    return session


def _summary_from_snapshot(snap: DataSnapshot) -> dict[str, Any]:
    """Cached summary when the session has one (computed once at upload); else compute."""
    if snap.summary is not None:
        return snap.summary
    return compute_summary(
        snap.df, snap.alerts, snap.dataset_name, snap.analyzed_at,
        snap.is_sample, snap.log_format, snap.import_report,
    )


def _limits_payload() -> dict[str, Any]:
    return {
        "max_upload_size_mb": MAX_UPLOAD_SIZE_BYTES // (1024 * 1024),
        "max_upload_rows": MAX_UPLOAD_ROWS,
        "session_idle_timeout_minutes": int(session_manager.ttl_seconds // 60),
    }


@app.get("/api/health")
def get_health() -> dict[str, Any]:
    """
    Health check and capability discovery.

    In multi-tenant mode this reports nothing about any visitor's data.
    ``uploads_enabled`` is the single flag the frontend uses to enable upload controls.
    """
    if PORTFOLIO_READ_ONLY:
        mode = "portfolio_read_only"
    elif MULTI_TENANT_SESSIONS:
        mode = "multi_tenant_sessions"
    else:
        mode = "full_access"

    payload: dict[str, Any] = {
        "status": "ok",
        "service": "threatlens-api",
        "version": "1.0.0",
        "engine": "ready",
        "read_only": PORTFOLIO_READ_ONLY,
        "mode": mode,
        "multi_tenant": MULTI_TENANT_SESSIONS,
        "uploads_enabled": not PORTFOLIO_READ_ONLY,
        "limits": _limits_payload(),
    }
    if not MULTI_TENANT_SESSIONS:
        snap = state.snapshot()
        payload.update({
            "dataset_loaded": snap.df is not None and not snap.df.empty,
            "total_rows": len(snap.df) if snap.df is not None else 0,
            "total_alerts": len(snap.alerts),
            "log_format": snap.log_format,
        })
    return payload


@app.post("/api/session")
def create_visitor_session() -> JSONResponse:
    """Issue a new visitor session. The token is a bearer credential for X-Session-ID."""
    if not MULTI_TENANT_SESSIONS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Visitor sessions are not enabled on this deployment.")
    try:
        session = session_manager.create_session()
    except SessionError as exc:
        raise _session_error_to_http(exc)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "session_id": session.session_id,
            "idle_timeout_seconds": int(session_manager.ttl_seconds),
            "limits": _limits_payload(),
        },
        headers={"Cache-Control": "no-store"},
    )


@app.delete("/api/session")
def end_visitor_session(
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
) -> dict[str, Any]:
    """End the caller's own session and free its data. Idempotent."""
    if not MULTI_TENANT_SESSIONS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Visitor sessions are not enabled on this deployment.")
    return {"success": True, "deleted": session_manager.delete_session(x_session_id)}


@app.get("/api/summary")
def get_summary(
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
) -> dict[str, Any]:
    """Return summary metrics, charts, and suspicious IP rankings for the caller's dataset."""
    ctx = _resolve_context(x_session_id)
    return _summary_from_snapshot(ctx.snapshot())


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
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
) -> dict[str, Any]:
    """Retrieve structured alerts with optional severity, status, event_type, source_ip, rule, priority, account, and text search filters."""
    ctx = _resolve_context(x_session_id)
    formatted = [format_alert(a) for a in ctx.snapshot().alerts]

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
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
) -> dict[str, Any]:
    """Return parsed log entries formatted for the Log Analysis viewer."""
    ctx = _resolve_context(x_session_id)
    log_df = ctx.snapshot().df
    if log_df is None or log_df.empty:
        return {"total": 0, "logs": []}

    # Map event_types and statuses to log levels
    logs = []
    for idx, row in log_df.iterrows():
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



# ── Upload pipeline ───────────────────────────────────────────────────────────

class _Parsed(NamedTuple):
    df: pd.DataFrame
    alerts: list
    format_name: str
    report_dict: Optional[dict]


def _validate_upload_filename(file: UploadFile, windows_only: bool) -> str:
    raw_filename = file.filename or ("windows_security_log.csv" if windows_only else "uploaded.csv")
    filename = os.path.basename(raw_filename)[:255]
    if not filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid file format. Only Windows Event Viewer CSV exports (.csv) are accepted. "
                "Native .evtx files are not supported."
                if windows_only
                else "Invalid file format. Only CSV files (.csv) are accepted."
            ),
        )
    return filename


async def _read_upload_bytes(file: UploadFile, windows_only: bool) -> bytes:
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
            detail="The uploaded Windows log file is empty." if windows_only else "The uploaded file is empty.",
        )
    return content_bytes


def _decode_upload(content_bytes: bytes, windows_only: bool) -> str:
    try:
        return content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if windows_only:
        try:
            return content_bytes.decode("utf-16")
        except UnicodeDecodeError:
            pass
    try:
        return content_bytes.decode("latin-1")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File encoding error: {exc}. Please upload a UTF-8 or UTF-16 encoded CSV file."
            if windows_only
            else f"File encoding error: {exc}. Please upload a UTF-8 encoded CSV file.",
        )


def _parse_and_detect(
    content_bytes: bytes,
    windows_only: bool,
    log_format: Optional[str],
    config: DetectorConfig,
) -> _Parsed:
    """
    CPU-bound: decode, parse, enforce the row limit, run detection.
    Always executed in a worker thread (never on the event loop). The row limit is
    enforced after parsing but before detection, which is the expensive step.
    """
    text_content = _decode_upload(content_bytes, windows_only)

    report_dict: Optional[dict] = None
    format_name = "standard"
    use_windows = windows_only or log_format == "windows" or (
        log_format is None and is_windows_log(io.StringIO(text_content))
    )

    if use_windows:
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

    try:
        alerts = run_detection(df, config)
    except Exception as exc:
        logger.error("Detection engine error during analysis: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Detection engine encountered an internal error during analysis.",
        )

    return _Parsed(df, alerts, format_name, report_dict)


def _build_upload_response(
    filename: str, windows_only: bool, parsed: _Parsed, summary: dict[str, Any]
) -> dict[str, Any]:
    """Response shapes match the historical single-tenant API exactly."""
    formatted_alerts = [format_alert(a) for a in parsed.alerts]
    if windows_only:
        return {
            "success": True,
            "filename": filename,
            "format": "windows_event_viewer",
            "rows_processed": len(parsed.df),
            "alerts_detected": len(parsed.alerts),
            "import_report": parsed.report_dict,
            "summary": summary,
            "alerts": formatted_alerts,
        }
    res: dict[str, Any] = {
        "success": True,
        "filename": filename,
        "rows_processed": len(parsed.df),
        "alerts_detected": len(parsed.alerts),
        "summary": summary,
        "alerts": formatted_alerts,
    }
    if parsed.report_dict:
        res["import_report"] = parsed.report_dict
        res["format"] = parsed.format_name
    return res


def _commit_single_tenant(
    content: bytes, filename: str, windows_only: bool, log_format: Optional[str]
) -> dict[str, Any]:
    """Single-tenant path (worker thread): analyse, then replace the process-wide dataset."""
    parsed = _parse_and_detect(content, windows_only, log_format, state.config)
    state.set_data(
        df=parsed.df, alerts=parsed.alerts, filename=filename, is_sample=False,
        log_format=parsed.format_name, import_report=parsed.report_dict,
    )
    snap = state.snapshot()
    summary = compute_summary(
        parsed.df, parsed.alerts, filename, snap.analyzed_at, False, parsed.format_name, parsed.report_dict
    )
    return _build_upload_response(filename, windows_only, parsed, summary)


def _commit_session_upload(
    session: SessionState,
    content: bytes,
    filename: str,
    windows_only: bool,
    log_format: Optional[str],
    is_sample: bool = False,
) -> dict[str, Any]:
    """
    Multi-tenant path (worker thread). Under the session's mutation lock and a memory
    reservation: analyse, compute the summary once, then commit everything to the
    caller's session in one atomic step. Any failure leaves the session's previous
    dataset untouched and releases the reservation.
    """
    try:
        with session.transaction(timeout=SESSION_TXN_TIMEOUT_SECONDS):
            reservation = session_manager.reserve_upload_memory(
                session.session_id, estimate_incoming_bytes(len(content))
            )
            with reservation:
                parsed = _parse_and_detect(content, windows_only, log_format, session.config)
                analyzed_at = datetime.now(timezone.utc).isoformat()
                summary = compute_summary(
                    parsed.df, parsed.alerts, filename, analyzed_at, is_sample,
                    parsed.format_name, parsed.report_dict,
                )
                final_bytes = estimate_dataset_memory(parsed.df, parsed.alerts)
                reservation.commit(final_bytes)
                session.set_data(
                    df=parsed.df, alerts=parsed.alerts, filename=filename, is_sample=is_sample,
                    log_format=parsed.format_name, import_report=parsed.report_dict,
                    memory_bytes=final_bytes, analyzed_at=analyzed_at, summary=summary,
                )
    except SessionError as exc:
        raise _session_error_to_http(exc)
    return _build_upload_response(filename, windows_only, parsed, summary)


def _session_upload_worker(lease, slot, *args: Any) -> dict[str, Any]:
    """Run a session commit and always give back the lease and analysis slot."""
    try:
        return _commit_session_upload(lease.session, *args)
    finally:
        slot.release()
        lease.release()


async def _process_upload(
    file: UploadFile,
    *,
    windows_only: bool,
    log_format: Optional[str],
    x_session_id: Optional[str],
) -> dict[str, Any]:
    filename = _validate_upload_filename(file, windows_only)

    if not MULTI_TENANT_SESSIONS:
        content = await _read_upload_bytes(file, windows_only)
        return await run_in_threadpool(_commit_single_tenant, content, filename, windows_only, log_format)

    # Multi-tenant: pin the session, take an analysis slot (no waiting: fail fast with 503
    # so uploads can never queue unboundedly), then read the body. At most
    # MAX_CONCURRENT_ANALYSES uploads ever hold their bytes in memory.
    lease = session_manager.acquire_lease(x_session_id)
    if lease is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=SESSION_INVALID_MESSAGE)
    try:
        slot = session_manager.acquire_analysis_slot()
    except SessionError as exc:
        lease.release()
        raise _session_error_to_http(exc)

    handed_off = False
    try:
        content = await _read_upload_bytes(file, windows_only)
        handed_off = True
        # The worker owns lease+slot from here, even if the client disconnects mid-analysis.
        return await run_in_threadpool(
            _session_upload_worker, lease, slot, content, filename, windows_only, log_format
        )
    finally:
        if not handed_off:
            slot.release()
            lease.release()


@app.post("/api/analyze/windows")
async def analyze_windows_file(
    file: UploadFile = File(...),
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
) -> dict[str, Any]:
    """Import and analyze an exported Windows Security event log CSV file."""
    _verify_write_permission(x_admin_key, authorization, action="Windows log upload and analysis is")
    return await _process_upload(file, windows_only=True, log_format=None, x_session_id=x_session_id)


@app.post("/api/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    log_format: Optional[str] = Query(None, description="Optional log format: 'standard' or 'windows'"),
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
) -> dict[str, Any]:
    """Analyze an uploaded CSV security log file and return structured detection results."""
    _verify_write_permission(x_admin_key, authorization, action="Live CSV log upload and analysis is")
    return await _process_upload(file, windows_only=False, log_format=log_format, x_session_id=x_session_id)


def _load_sample_into_session(token: Optional[str]) -> None:
    """Load the synthetic sample into the caller's session through the same limited pipeline."""
    lease = session_manager.acquire_lease(token)
    if lease is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=SESSION_INVALID_MESSAGE)
    try:
        slot = session_manager.acquire_analysis_slot()
    except SessionError as exc:
        lease.release()
        raise _session_error_to_http(exc)
    try:
        if not SAMPLE_CSV_PATH.exists():
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="The sample dataset is not available on this server.")
        content = SAMPLE_CSV_PATH.read_bytes()
    except BaseException:
        slot.release()
        lease.release()
        raise
    _session_upload_worker(lease, slot, content, SAMPLE_DATASET_NAME, False, None, True)


@app.post("/api/reset")
def reset_dataset(
    sample: bool = Query(
        False,
        description="If True, reloads the sample_logs.csv dataset. Defaults to False (resets to clean empty state for Live Mode).",
    ),
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
) -> dict[str, Any]:
    """
    Reset the caller's active analysis state (their session in multi-tenant mode).

    By default, resets to a clean empty state for Live Mode (0 events, 0 alerts).
    If ?sample=true is passed, restores the synthetic demonstration dataset.
    """
    _verify_write_permission(x_admin_key, authorization, action="Resetting active analysis data is")
    if MULTI_TENANT_SESSIONS:
        session = session_manager.get_session(x_session_id, touch=True)
        if session is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=SESSION_INVALID_MESSAGE)
        if sample:
            _load_sample_into_session(x_session_id)
        else:
            try:
                session.reset_to_empty(timeout=SESSION_TXN_TIMEOUT_SECONDS)
            except SessionError as exc:
                raise _session_error_to_http(exc)
        ctx: DataContext = session
    else:
        if sample:
            state.reset_to_sample()
        else:
            state.reset_to_empty()
        ctx = state

    return {
        "success": True,
        "message": "Reset to default sample dataset." if sample else "Reset to clean empty state.",
        "summary": _summary_from_snapshot(ctx.snapshot()),
    }


@app.post("/api/sample")
def load_sample_dataset(
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
) -> dict[str, Any]:
    """
    Dedicated endpoint to explicitly load the synthetic sample_logs.csv dataset
    into the caller's own dataset.
    """
    _verify_write_permission(x_admin_key, authorization, action="Loading sample datasets via the API is")
    if MULTI_TENANT_SESSIONS:
        if session_manager.get_session(x_session_id, touch=True) is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=SESSION_INVALID_MESSAGE)
        _load_sample_into_session(x_session_id)
        ctx = _resolve_context(x_session_id)
    else:
        state.reset_to_sample()
        ctx = state
    return {
        "success": True,
        "message": "Loaded standard sample dataset.",
        "summary": _summary_from_snapshot(ctx.snapshot()),
    }


# ── Phase 6: Detection configuration endpoints ────────────────────────────────

@app.get("/api/detection/config")
def get_detection_config(
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
) -> dict[str, Any]:
    """Retrieve the detection configuration in effect for the caller (their session in multi-tenant mode)."""
    ctx = _resolve_context(x_session_id)
    if MULTI_TENANT_SESSIONS:
        note = (
            "These thresholds apply to your visitor session only and are cleared when the "
            "session expires. Other visitors are not affected."
        )
    else:
        note = (
            "Configuration is stored in memory only and resets to defaults on "
            "backend restart. No authentication is required for this endpoint."
        )
    return {
        "config": ctx.config.to_dict(),
        "defaults": DetectorConfig.defaults(),
        "note": note,
    }


@app.put("/api/detection/config")
def update_detection_config(
    body: dict,
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key"),
    authorization: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
) -> dict[str, Any]:
    """
    Update detection configuration thresholds.

    Only recognised field names from DetectorConfig are accepted; unrecognised
    keys are rejected. Invalid values are validated and rejected before any
    changes are applied.

    In multi-tenant mode the change applies to the caller's session only, so no admin
    key is needed (and none is ever sent by the frontend). In single-tenant mode the
    change is process-wide, and ADMIN_API_KEY (when configured) is required.

    Changes take effect on the next analysis; loaded alerts are NOT recomputed.
    """
    _verify_write_permission(x_admin_key, authorization, action="Modifying detection thresholds is")
    if ADMIN_API_KEY and not MULTI_TENANT_SESSIONS:
        token = authorization.replace("Bearer ", "").strip() if authorization and "Bearer " in authorization else None
        key = x_admin_key or token
        if not key or not hmac.compare_digest(key, ADMIN_API_KEY):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrative authorization required to modify detection configuration in this deployment.",
            )

    ctx = _resolve_context(x_session_id)

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
    merged = ctx.config.to_dict()
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

    ctx.config = candidate
    logger.info("Detection configuration updated: %s", body)

    return {
        "success": True,
        "message": "Configuration updated. Re-upload or reset data to apply new thresholds.",
        "config": ctx.config.to_dict(),
    }
