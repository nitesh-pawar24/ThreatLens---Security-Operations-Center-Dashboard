"""
ThreatLens – Windows Security Event Log Importer
=================================================
Converts Windows Security event log CSV files (exported from Windows Event
Viewer via "Save All Events As…" → CSV) into the ThreatLens normalized log
schema so they can be analyzed by the existing detection engine.

Supported export format
-----------------------
Windows Event Viewer exports CSV files with these column headers
(column names are semi-colon or comma delimited depending on locale):

    Level, Date and Time, Source, Event ID, Task Category

Some exports also include additional columns. This module accepts either the
standard Event Viewer export or an extended export that includes:

    Log Name, Source, Date and Time, Event ID, Task Category, Level,
    Keywords, User, Computer, Description

The importer is resilient to missing optional columns and will normalize
whichever fields are available.

ThreatLens Normalized Schema (output)
--------------------------------------
    timestamp   – datetime64[ns] parsed from "Date and Time"
    source_ip   – IPv4 extracted from Description field or "–" placeholder
    event_type  – Mapped from Event ID (see EVENT_ID_MAP below)
    username    – "User" column or extracted from Description
    status      – Derived from Event ID semantics

Windows Security Event IDs Supported
--------------------------------------
    4624 – Successful logon            → LOGIN_SUCCESS
    4625 – Failed logon                → LOGIN_FAILURE
    4634 – Logoff                      → LOGOFF
    4648 – Logon with explicit creds   → EXPLICIT_CRED_LOGON
    4672 – Special privileges assigned → PRIVILEGE_ESCALATION
    4688 – New process created         → PROCESS_CREATED
    4720 – User account created        → ACCOUNT_CREATED
    4726 – User account deleted        → ACCOUNT_DELETED
    4732 – Member added to local group → GROUP_MEMBER_ADDED
    1102 – Audit log cleared           → AUDIT_LOG_CLEARED

Limitations
-----------
- Native .evtx files are NOT supported; only CSV exports are accepted.
- IP address extraction from the Description field is best-effort; many
  events do not include an IP address.
- Fields not present in the export are filled with empty strings or
  sensible placeholders; no values are invented.
- The Description column is optional; if absent, metadata is limited.

⚠️  This module does NOT access any real network or system resources.
"""

from __future__ import annotations

import io
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

import pandas as pd

logger = logging.getLogger(__name__)

# ── Windows event ID → ThreatLens event_type mapping ─────────────────────────

EVENT_ID_MAP: dict[int, dict] = {
    4624: {"event_type": "LOGIN_SUCCESS",         "status": "SUCCESS",  "label": "Successful logon"},
    4625: {"event_type": "LOGIN_FAILURE",          "status": "FAILURE",  "label": "Failed logon"},
    4634: {"event_type": "LOGOFF",                 "status": "SUCCESS",  "label": "Logoff"},
    4648: {"event_type": "EXPLICIT_CRED_LOGON",    "status": "SUCCESS",  "label": "Logon with explicit credentials"},
    4672: {"event_type": "PRIVILEGE_ESCALATION",   "status": "SUCCESS",  "label": "Special privileges assigned"},
    4688: {"event_type": "PROCESS_CREATED",        "status": "SUCCESS",  "label": "New process created"},
    4720: {"event_type": "ACCOUNT_CREATED",        "status": "SUCCESS",  "label": "User account created"},
    4726: {"event_type": "ACCOUNT_DELETED",        "status": "SUCCESS",  "label": "User account deleted"},
    4732: {"event_type": "GROUP_MEMBER_ADDED",     "status": "SUCCESS",  "label": "Member added to local group"},
    1102: {"event_type": "AUDIT_LOG_CLEARED",      "status": "SUCCESS",  "label": "Audit log cleared"},
}

# Event IDs we recognise but deliberately skip (e.g. very noisy / low value)
SKIPPED_EVENT_IDS: frozenset[int] = frozenset()

# ── Column name aliases ────────────────────────────────────────────────────────
# Windows Event Viewer uses different column names across Windows versions and
# locales. We normalise them to canonical names before processing.

_COL_ALIASES: dict[str, str] = {
    # Timestamp variants
    "date and time":      "win_timestamp",
    "datetime":           "win_timestamp",
    "date/time":          "win_timestamp",
    "time generated":     "win_timestamp",
    # Event ID variants
    "event id":           "win_event_id",
    "eventid":            "win_event_id",
    "id":                 "win_event_id",
    # User variants
    "user":               "win_user",
    "username":           "win_user",
    "account name":       "win_user",
    # Computer variants
    "computer":           "win_computer",
    "computer name":      "win_computer",
    # Description / message
    "description":        "win_description",
    "message":            "win_description",
    # Level / severity
    "level":              "win_level",
    # Source
    "source":             "win_source",
    "source name":        "win_source",
    # Task category
    "task category":      "win_task",
    "task":               "win_task",
}

# Minimum required canonical columns after alias normalization
_REQUIRED_WIN_COLS = {"win_timestamp", "win_event_id"}


# ── IP extraction ─────────────────────────────────────────────────────────────

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_LOOPBACK_RE = re.compile(r"^127\.\d+\.\d+\.\d+$")
_LINK_LOCAL_RE = re.compile(r"^169\.254\.\d+\.\d+$")
_UNSPECIFIED_RE = re.compile(r"^0\.0\.0\.0$")

def _extract_ip(text: str) -> str:
    """
    Extract the first non-loopback, non-link-local IPv4 from a text string.
    Returns empty string if none found.
    """
    if not text or pd.isna(text):
        return ""
    for match in _IPV4_RE.finditer(str(text)):
        ip = match.group()
        if _LOOPBACK_RE.match(ip) or _LINK_LOCAL_RE.match(ip) or _UNSPECIFIED_RE.match(ip):
            continue
        return ip
    return ""


def _extract_username(text: str) -> str:
    """
    Attempt best-effort extraction of an account name from the Description field
    when the 'User' column is empty or generic (e.g. SYSTEM, N/A).
    """
    if not text or pd.isna(text):
        return ""
    text_str = str(text)

    # 1. High-priority targeted section patterns
    targeted_patterns = [
        r"Account For Which Logon Failed:[^:]*?Account Name:\s*([^\r\n\t\s]+)",
        r"Target Account Name:\s*([^\r\n\t\s]+)",
        r"TargetUserName\s*:\s*([^\r\n\t\s]+)",
        r"New Account:[^:]*?Account Name:\s*([^\r\n\t\s]+)",
        r"Target Account:[^:]*?Account Name:\s*([^\r\n\t\s]+)",
    ]
    for pat in targeted_patterns:
        m = re.search(pat, text_str, re.IGNORECASE | re.DOTALL)
        if m:
            val = m.group(1).strip()
            if val and val not in ("-", "–", "N/A", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                return val

    # 2. Iterate through all Account Name / User Name instances and pick first real account
    for m in re.finditer(r"(?:Account Name|User Name)\s*:\s*([^\r\n\t\s]+)", text_str, re.IGNORECASE):
        val = m.group(1).strip()
        if val and val not in ("-", "–", "N/A", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            return val

    return ""


# ── Import report ─────────────────────────────────────────────────────────────

@dataclass
class WindowsImportReport:
    """Summary of what the Windows log importer processed."""
    total_rows:        int = 0
    imported_rows:     int = 0
    skipped_rows:      int = 0
    rejected_rows:     int = 0
    unsupported_ids:   list[int] = field(default_factory=list)
    warnings:          list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_rows":        self.total_rows,
            "imported_rows":     self.imported_rows,
            "skipped_rows":      self.skipped_rows,
            "rejected_rows":     self.rejected_rows,
            "unsupported_event_ids": sorted(set(self.unsupported_ids)),
            "warnings":          self.warnings,
        }


# ── Public API ─────────────────────────────────────────────────────────────────

def is_windows_log(source: Union[str, Path, io.StringIO]) -> bool:
    """
    Heuristic check: return True if the CSV looks like a Windows Event Viewer
    export rather than a ThreatLens native CSV.

    Checks for the presence of 'Event ID' or 'EventID' column headers.
    Does NOT consume the full file.
    """
    try:
        if isinstance(source, io.StringIO):
            pos = source.tell()
            header_line = source.readline()
            source.seek(pos)
        else:
            with open(source, encoding="utf-8", errors="replace") as fh:
                header_line = fh.readline()
        header_lower = header_line.lower()
        return "event id" in header_lower or "eventid" in header_lower
    except Exception:
        return False


def load_windows_log(
    source: Union[str, Path, io.StringIO],
) -> tuple[pd.DataFrame, WindowsImportReport]:
    """
    Parse a Windows Security event log CSV export and return a normalized
    ThreatLens DataFrame plus an import report.

    Parameters
    ----------
    source:
        Path to a CSV file, or a ``io.StringIO`` object.

    Returns
    -------
    (df, report) where:
        df     – ThreatLens-normalized DataFrame ready for ``run_detection()``.
                 Columns: timestamp, source_ip, event_type, username, status.
        report – :class:`WindowsImportReport` with counts and warnings.

    Raises
    ------
    FileNotFoundError
        If *source* is a path that does not exist.
    ValueError
        If the file is empty, not parseable as CSV, or missing required columns.
    """
    report = WindowsImportReport()

    # ── Step 1: read raw CSV ─────────────────────────────────────────────────
    try:
        sep = ","
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                raise FileNotFoundError(f"Log file not found: {path}")
            with open(path, encoding="utf-8", errors="replace") as fh:
                first_line = fh.readline()
            if ";" in first_line and "," not in first_line:
                sep = ";"
            raw = pd.read_csv(path, sep=sep, dtype=str, encoding="utf-8", on_bad_lines="warn")
        else:
            pos = source.tell()
            first_line = source.readline()
            source.seek(pos)
            if ";" in first_line and "," not in first_line:
                sep = ";"
            raw = pd.read_csv(source, sep=sep, dtype=str, encoding="utf-8", on_bad_lines="warn")
    except pd.errors.EmptyDataError as exc:
        raise ValueError("The Windows log file is empty or contains no data.") from exc
    except pd.errors.ParserError as exc:
        raise ValueError(f"CSV parse error in Windows log file: {exc}") from exc

    if raw.empty:
        raise ValueError("The Windows log file contains no rows.")

    report.total_rows = len(raw)

    # ── Step 2: normalise column names ───────────────────────────────────────
    # Strip whitespace, lowercase, apply alias mapping
    raw.columns = raw.columns.str.strip().str.lower()
    col_map = {}
    for col in raw.columns:
        canonical = _COL_ALIASES.get(col)
        if canonical:
            col_map[col] = canonical
    raw = raw.rename(columns=col_map)

    # Check required columns after aliasing
    present = set(raw.columns)
    missing = _REQUIRED_WIN_COLS - present
    if missing:
        raise ValueError(
            f"Windows log CSV is missing required columns: {sorted(missing)}. "
            f"Expected 'Event ID' and 'Date and Time' (or equivalent). "
            f"Found columns: {sorted(raw.columns.tolist())}"
        )

    # ── Step 3: fill optional columns with empty strings ────────────────────
    for opt_col in ("win_user", "win_computer", "win_description", "win_level", "win_source", "win_task"):
        if opt_col not in raw.columns:
            raw[opt_col] = ""

    # Strip whitespace from all string columns
    for col in raw.columns:
        raw[col] = raw[col].fillna("").astype(str).str.strip()

    # ── Step 4: parse Event IDs ──────────────────────────────────────────────
    raw["_event_id_int"] = pd.to_numeric(raw["win_event_id"], errors="coerce")
    bad_ids = raw["_event_id_int"].isna()
    if bad_ids.any():
        n_bad = int(bad_ids.sum())
        report.rejected_rows += n_bad
        report.warnings.append(
            f"{n_bad} row(s) had non-numeric Event IDs and were rejected."
        )
        raw = raw[~bad_ids].copy()
    raw["_event_id_int"] = raw["_event_id_int"].astype(int)

    # ── Step 5: parse timestamps ─────────────────────────────────────────────
    raw["_parsed_ts"] = pd.to_datetime(raw["win_timestamp"], errors="coerce", format="mixed")
    bad_ts = raw["_parsed_ts"].isna()
    if bad_ts.any():
        n_bad = int(bad_ts.sum())
        report.rejected_rows += n_bad
        report.warnings.append(
            f"{n_bad} row(s) had unparseable timestamps and were rejected."
        )
        raw = raw[~bad_ts].copy()

    if raw.empty:
        raise ValueError(
            "No rows with valid Event IDs and timestamps remain after validation. "
            "Check that the file is a Windows Event Viewer CSV export."
        )

    # ── Step 6: filter to supported event IDs ───────────────────────────────
    supported_mask = raw["_event_id_int"].isin(EVENT_ID_MAP.keys())
    unsupported = raw[~supported_mask]
    if not unsupported.empty:
        unsupported_ids = unsupported["_event_id_int"].unique().tolist()
        report.skipped_rows += len(unsupported)
        report.unsupported_ids.extend([int(x) for x in unsupported_ids])
        logger.info(
            "Skipped %d row(s) with unsupported Event IDs: %s",
            len(unsupported),
            sorted(set(int(x) for x in unsupported_ids)),
        )

    supported = raw[supported_mask].copy()
    if supported.empty:
        raise ValueError(
            "No rows matched the supported Windows Security event IDs "
            f"({sorted(EVENT_ID_MAP.keys())}). "
            "Ensure you are uploading a Windows Security event log (not Application or System)."
        )

    # ── Step 7: normalise to ThreatLens schema ───────────────────────────────
    rows = []
    for _, row in supported.iterrows():
        eid  = int(row["_event_id_int"])
        meta = EVENT_ID_MAP[eid]

        # Username: prefer win_user, fall back to extraction from description
        username = row["win_user"]
        if not username or username in ("-", "N/A", "N/A.", "–", "SYSTEM"):
            extracted_u = _extract_username(row.get("win_description", ""))
            if extracted_u:
                username = extracted_u
            elif username in ("-", "N/A", "N/A.", "–"):
                username = ""

        # Source IP: attempt extraction from description field
        source_ip = _extract_ip(row.get("win_description", ""))
        if not source_ip:
            source_ip = _extract_ip(row.get("win_computer", ""))
        # Fallback placeholder so the schema constraint is met
        if not source_ip:
            source_ip = "0.0.0.0"

        rows.append({
            "timestamp":        row["_parsed_ts"],
            "source_ip":        source_ip,
            "event_type":       meta["event_type"],
            "username":         username,
            "status":           meta["status"],
            # Extra metadata preserved for investigation context & frontend display
            "win_event_id":     eid,
            "win_label":        meta["label"],
            "win_computer":     row.get("win_computer", ""),
            "win_task":         row.get("win_task", ""),
            "win_level":        row.get("win_level", ""),
            "win_source":       row.get("win_source", ""),
            "win_description":  row.get("win_description", "")[:500],  # cap length
        })

    df_full = pd.DataFrame(rows)
    if df_full.empty:
        raise ValueError("Normalization produced no valid rows.")

    # Sort chronologically, preserving standard schema columns + Windows metadata
    df_normalized = df_full.sort_values("timestamp").reset_index(drop=True)

    report.imported_rows = len(df_normalized)
    logger.info(
        "Windows log import: %d rows total, %d imported, %d skipped, %d rejected.",
        report.total_rows,
        report.imported_rows,
        report.skipped_rows,
        report.rejected_rows,
    )

    return df_normalized, report


def get_supported_event_ids() -> dict[int, str]:
    """Return a mapping of supported Event IDs to their human-readable labels."""
    return {eid: meta["label"] for eid, meta in EVENT_ID_MAP.items()}
