"""
ThreatLens – Log Parser
=======================
Responsible for loading, validating, and normalising a CSV log file into a
clean pandas DataFrame that all detection rules can consume.

CSV Schema (documented in backend/README.md):
    timestamp   – ISO-8601 datetime string, e.g. "2026-10-20 14:58:03"
    source_ip   – IPv4 address string (RFC 5737 ranges used in samples)
    event_type  – Short event category, e.g. "LOGIN_FAILURE"
    username    – Account name involved (may be empty)
    status      – Outcome: SUCCESS | FAILURE | BLOCKED | UNKNOWN

⚠️  This module does NOT access any real network or system.
"""

from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Union

import pandas as pd

logger = logging.getLogger(__name__)

# ── Required columns ──────────────────────────────────────────────────────────
REQUIRED_COLUMNS = {"timestamp", "source_ip", "event_type", "username", "status"}

# Accepted event_type values (open set – unrecognised values are kept but flagged)
KNOWN_EVENT_TYPES = {
    "LOGIN_FAILURE",
    "LOGIN_SUCCESS",
    "PORT_SCAN",
    "CONNECTION_ATTEMPT",
    "MALWARE_DETECTED",
    "PRIVILEGE_ESCALATION",
    "POLICY_VIOLATION",
    "DATA_TRANSFER",
    "DNS_QUERY",
    "FILE_ACCESS",
}


# ── Public API ────────────────────────────────────────────────────────────────

def load_log(source: Union[str, Path, io.StringIO]) -> pd.DataFrame:
    """Load a CSV log file (or StringIO object) and return a clean DataFrame.

    Steps performed:
        1. Read CSV – any file-not-found or parse errors are surfaced clearly.
        2. Validate that all required columns are present.
        3. Parse timestamps; rows with unparseable timestamps are dropped with
           a warning (they cannot be used in time-window analysis).
        4. Strip whitespace from string columns.
        5. Normalise ``event_type`` and ``status`` to UPPER_SNAKE_CASE.
        6. Log a warning for any unrecognised event_type values.

    Parameters
    ----------
    source:
        Path to a CSV file, or a ``io.StringIO`` object (useful in tests).

    Returns
    -------
    pd.DataFrame
        Columns: timestamp (datetime64[ns]), source_ip (str), event_type (str),
        username (str), status (str).
        Sorted ascending by timestamp.

    Raises
    ------
    FileNotFoundError
        If *source* is a path that does not exist.
    ValueError
        If required columns are missing, or if the file is empty / unreadable.
    """
    # ── Step 1: read CSV ──────────────────────────────────────────────────────
    try:
        if isinstance(source, (str, Path)):
            path = Path(source)
            if not path.exists():
                raise FileNotFoundError(f"Log file not found: {path}")
            df = pd.read_csv(path, dtype=str)
        else:
            # StringIO – reset position first so the caller can re-use it
            source.seek(0)
            df = pd.read_csv(source, dtype=str)
    except pd.errors.EmptyDataError as exc:
        raise ValueError("The log file is empty or contains no data.") from exc
    except pd.errors.ParserError as exc:
        raise ValueError(f"CSV parse error: {exc}") from exc

    if df.empty:
        raise ValueError("The log file contains no rows.")

    # ── Step 2: validate required columns ──────────────────────────────────────
    actual_cols = set(df.columns.str.strip().str.lower())
    # Rename columns to lowercase so comparisons work regardless of header case
    df.columns = df.columns.str.strip().str.lower()

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(
            f"Log file is missing required columns: {sorted(missing)}. "
            f"Found columns: {sorted(df.columns.tolist())}"
        )

    # Keep only the columns we care about (extra columns are silently ignored)
    df = df[list(REQUIRED_COLUMNS)].copy()

    # ── Step 3: strip whitespace from all string columns ──────────────────────
    for col in df.columns:
        df[col] = df[col].fillna("").str.strip()

    # ── Step 4: parse timestamps ──────────────────────────────────────────────
    original_len = len(df)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
    bad_ts = df["timestamp"].isna()
    if bad_ts.any():
        n_bad = bad_ts.sum()
        logger.warning(
            "%d row(s) had unparseable timestamps and were dropped.", n_bad
        )
        df = df[~bad_ts].copy()

    if df.empty:
        raise ValueError(
            "All rows had unparseable timestamps. "
            "Expected format: 'YYYY-MM-DD HH:MM:SS'."
        )

    rows_dropped = original_len - len(df)
    if rows_dropped:
        logger.info("Dropped %d malformed row(s); %d row(s) kept.", rows_dropped, len(df))

    # ── Step 5: normalise text columns ────────────────────────────────────────
    df["event_type"] = df["event_type"].str.upper().str.replace(" ", "_")
    df["status"]     = df["status"].str.upper()

    # ── Step 6: warn on unknown event types ───────────────────────────────────
    unknown = set(df["event_type"].unique()) - KNOWN_EVENT_TYPES
    if unknown:
        logger.warning("Unrecognised event_type value(s): %s", unknown)

    # ── Sort by time ──────────────────────────────────────────────────────────
    df = df.sort_values("timestamp").reset_index(drop=True)

    logger.info("Loaded %d log rows from source.", len(df))
    return df
