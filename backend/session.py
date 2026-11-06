"""
ThreatLens – Multi-Tenant In-Memory Session Management
======================================================
Ephemeral, isolated visitor sessions for log analysis. Each session owns an
independent DataFrame, alert list, detection configuration and cached summary.

Safeguards
----------
- Sessions are addressed by 256-bit random bearer tokens (``tl_sess_<64 hex>``).
- Idle sessions expire (``SESSION_TTL_MINUTES``). Sessions that never received
  data expire sooner (``SESSION_EMPTY_TTL_MINUTES``) so that a flood of empty
  sessions cannot hold session capacity for long. Expiry invalidates the
  session object itself, so a request that still holds a reference cannot
  commit data into an orphan.
- A hard cap on concurrent sessions (``MAX_ACTIVE_SESSIONS``).
- Memory budgets, enforced with reservations: per-session
  (``MAX_SESSION_MEMORY_MB``) and global (``MAX_TOTAL_MEMORY_MB``). While a
  replacement upload is analysed, the old and new datasets coexist, and the
  reservation accounts for that.
- A global analysis slot pool (``MAX_CONCURRENT_ANALYSES``) implemented with a
  plain ``threading.BoundedSemaphore``; it is loop-agnostic and never waits
  unless asked to.
- Per-session mutation transactions serialise upload/reset on one session and
  report a conflict instead of queueing forever.
- Leases keep a session alive (not expired, not destroyed) while a request is
  using it.

Memory measurement note
-----------------------
The byte counters estimate *application dataset* memory (deep DataFrame size
plus an alert estimate). They are not process RSS, which also contains the
interpreter, libraries and transient parsing buffers. Treat the configured
limits as budgets, not guarantees against container OOM.

Lock order (never acquire in the reverse direction):
    reservation._lock -> manager._lock -> session._state_lock
    session._transaction_lock -> session._state_lock
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, NamedTuple, Optional

import pandas as pd

from backend.detector import Alert, DetectorConfig

logger = logging.getLogger("threatlens.session")

# ── Token validation ──────────────────────────────────────────────────────────
SESSION_TOKEN_PREFIX = "tl_sess_"
SESSION_TOKEN_PATTERN = re.compile(r"tl_sess_[0-9a-f]{64}")


def validate_session_token(token: Optional[str]) -> bool:
    """True only for a token that strictly matches the issued format."""
    if not token or not isinstance(token, str):
        return False
    return SESSION_TOKEN_PATTERN.fullmatch(token) is not None


def mask_session_token(token: Optional[str]) -> str:
    """Masked token for logs; never log full tokens."""
    if not token or len(token) < 16:
        return "[none]"
    return f"tl_sess_...{token[-6:]}"


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    """Read a positive integer from the environment, falling back on bad input."""
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        logger.warning("Invalid value for %s; using default %s.", name, default)
        return default


# ── Exceptions ────────────────────────────────────────────────────────────────

class SessionError(Exception):
    """Base class for session errors."""


class SessionCapacityError(SessionError):
    """Session count or global memory capacity exhausted."""


class SessionMemoryError(SessionError):
    """A single session would exceed its memory ceiling."""


class SessionConcurrencyError(SessionError):
    """All analysis slots are busy."""


class SessionInvalidTokenError(SessionError):
    """Invalid, expired or deleted session."""


class SessionConflictError(SessionError):
    """A conflicting mutation is already running on the same session."""


class ReservationStatus(Enum):
    PENDING = "pending"
    COMMITTED = "committed"
    RELEASED = "released"


# ── Memory estimation ─────────────────────────────────────────────────────────
# Calibrated against measured deep sizes (Alert objects average ~1.15 KB with
# one evidence row; the constants below add ~40% margin).
ALERT_BASE_BYTES = 1000
ALERT_EVIDENCE_ROW_BYTES = 800
# Parsed DataFrame ≈ 4x the CSV bytes (measured 3.9x); 5x also covers transients.
INCOMING_MEMORY_FACTOR = 5
INCOMING_MEMORY_FLOOR = 256 * 1024


def estimate_dataset_memory(df: Optional[pd.DataFrame], alerts: list[Alert]) -> int:
    """Conservative size of a DataFrame plus its alerts."""
    df_mem = 0
    if df is not None and not df.empty:
        try:
            df_mem = int(df.memory_usage(deep=True).sum())
        except Exception:
            df_mem = int(len(df) * len(df.columns) * 64)
    alert_mem = sum(
        ALERT_BASE_BYTES + len(a.evidence) * ALERT_EVIDENCE_ROW_BYTES for a in alerts
    )
    return df_mem + alert_mem


def estimate_incoming_bytes(raw_size: int) -> int:
    """Pre-parse estimate of the in-memory size of an upload of ``raw_size`` bytes."""
    return max(INCOMING_MEMORY_FLOOR, int(raw_size) * INCOMING_MEMORY_FACTOR)


class DataSnapshot(NamedTuple):
    """Consistent point-in-time view of a dataset (all fields from one commit)."""

    df: Optional[pd.DataFrame]
    alerts: list
    dataset_name: str
    analyzed_at: str
    is_sample: bool
    log_format: str
    import_report: Optional[dict]
    summary: Optional[dict]


# ── Session state ─────────────────────────────────────────────────────────────

class SessionState:
    """Independent analysis state for one visitor session."""

    def __init__(self, session_id: str) -> None:
        self.session_id: str = session_id
        self.df: Optional[pd.DataFrame] = None
        self.alerts: list[Alert] = []
        self.dataset_name: str = "None"
        self.analyzed_at: str = datetime.now(timezone.utc).isoformat()
        self.is_sample: bool = False
        self.log_format: str = "standard"
        self.import_report: Optional[dict[str, Any]] = None
        self.summary: Optional[dict[str, Any]] = None  # cached at commit time
        self.config: DetectorConfig = DetectorConfig()
        self.created_at: float = time.time()
        self.last_accessed: float = time.time()
        self.upload_count: int = 0
        self.memory_bytes: int = 0

        self._active_leases: int = 0
        self._is_deleted: bool = False
        self._pending_delete: bool = False
        self._state_lock = threading.RLock()
        self._transaction_lock = threading.Lock()

    # -- helpers --------------------------------------------------------------
    def touch(self) -> None:
        with self._state_lock:
            self.last_accessed = time.time()

    @staticmethod
    def estimate_dataset_memory(df: Optional[pd.DataFrame], alerts: list[Alert]) -> int:
        return estimate_dataset_memory(df, alerts)

    def update_memory_estimate(self) -> int:
        with self._state_lock:
            self.memory_bytes = estimate_dataset_memory(self.df, self.alerts)
            return self.memory_bytes

    def _clear_internal(self) -> None:
        with self._state_lock:
            self.df = None
            self.alerts = []
            self.dataset_name = "None"
            self.analyzed_at = datetime.now(timezone.utc).isoformat()
            self.is_sample = False
            self.log_format = "standard"
            self.import_report = None
            self.summary = None
            self.memory_bytes = 0

    def _invalidate(self) -> None:
        """Mark the session dead (expired/deleted) and free its data."""
        with self._state_lock:
            self._is_deleted = True
            self._clear_internal()

    # -- data -----------------------------------------------------------------
    def snapshot(self) -> DataSnapshot:
        """Return a consistent view; DataFrames are replaced, never mutated in place."""
        with self._state_lock:
            return DataSnapshot(
                self.df, self.alerts, self.dataset_name, self.analyzed_at,
                self.is_sample, self.log_format, self.import_report, self.summary,
            )

    def set_data(
        self,
        df: pd.DataFrame,
        alerts: list[Alert],
        filename: str,
        is_sample: bool = False,
        log_format: str = "standard",
        import_report: Optional[dict[str, Any]] = None,
        memory_bytes: Optional[int] = None,
        analyzed_at: Optional[str] = None,
        summary: Optional[dict[str, Any]] = None,
    ) -> None:
        """Atomically replace the dataset. Rejected for deleted/expired sessions."""
        with self._state_lock:
            if self._is_deleted:
                raise SessionInvalidTokenError("Cannot commit data to a deleted or invalidated session.")
            self.df = df
            self.alerts = alerts
            self.dataset_name = filename
            self.analyzed_at = analyzed_at or datetime.now(timezone.utc).isoformat()
            self.is_sample = is_sample
            self.log_format = log_format
            self.import_report = import_report
            self.summary = summary
            self.upload_count += 1
            self.memory_bytes = (
                int(memory_bytes) if memory_bytes is not None
                else estimate_dataset_memory(df, alerts)
            )
            self.last_accessed = time.time()

    def reset_to_empty(self, timeout: float = 2.0) -> None:
        """Clear all data (serialised against uploads on this session)."""
        with self.transaction(timeout=timeout):
            self._clear_internal()
            self.touch()

    def transaction(self, timeout: float = 2.0) -> "SessionTransaction":
        return SessionTransaction(self, timeout=timeout)

    # -- properties -----------------------------------------------------------
    @property
    def is_active(self) -> bool:
        with self._state_lock:
            return not self._is_deleted

    @property
    def has_real_data(self) -> bool:
        with self._state_lock:
            return self.df is not None and not self.df.empty and not self.is_sample

    @property
    def row_count(self) -> int:
        with self._state_lock:
            return len(self.df) if self.df is not None else 0

    @property
    def alert_count(self) -> int:
        with self._state_lock:
            return len(self.alerts)


class SessionTransaction:
    """Exclusive mutation lock for one session, with a bounded wait."""

    def __init__(self, session: SessionState, timeout: float = 2.0) -> None:
        self.session = session
        self.timeout = timeout
        self._acquired = False

    def __enter__(self) -> SessionState:
        if not self.session._transaction_lock.acquire(blocking=True, timeout=self.timeout):
            raise SessionConflictError(
                "Another upload or modification is already in progress for this session. "
                "Please wait for it to finish."
            )
        self._acquired = True
        if not self.session.is_active:
            self.__exit__(None, None, None)
            raise SessionInvalidTokenError("Cannot modify a deleted or expired session.")
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._acquired:
            self._acquired = False
            self.session._transaction_lock.release()


class SessionLease:
    """Keeps a session from being expired or destroyed while a request uses it."""

    def __init__(self, manager: "SessionManager", session: SessionState) -> None:
        self.manager = manager
        self.session = session
        self._released = False
        self._lock = threading.Lock()

    def __enter__(self) -> SessionState:
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self.manager._release_session_lease(self.session)


class AnalysisSlot:
    """One unit of the global analysis concurrency budget. Release is idempotent."""

    def __init__(self, sem: threading.BoundedSemaphore) -> None:
        self._sem = sem
        self._released = False
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._sem.release()

    def __enter__(self) -> "AnalysisSlot":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


class MemoryReservation:
    """
    Atomic memory reservation for an in-flight upload.

    Terminal states are mutually exclusive (COMMITTED or RELEASED); a second
    release, or a release after commit, is a no-op that never touches counters.
    """

    def __init__(self, manager: "SessionManager", session_id: str, reserved_bytes: int, session_current_bytes: int) -> None:
        self.manager = manager
        self.session_id = session_id
        self.reserved_bytes = reserved_bytes
        self.session_current_bytes = session_current_bytes
        self.status = ReservationStatus.PENDING
        self._lock = threading.Lock()

    def commit(self, final_session_bytes: int) -> None:
        with self._lock:
            if self.status != ReservationStatus.PENDING:
                raise RuntimeError(f"Cannot commit reservation in status: {self.status.value}")
            self.manager._commit_reservation(self, final_session_bytes)

    def release(self) -> None:
        with self._lock:
            if self.status != ReservationStatus.PENDING:
                return
            self.status = ReservationStatus.RELEASED
            self.manager._release_reservation(self)

    def __enter__(self) -> "MemoryReservation":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.status == ReservationStatus.PENDING:
            self.release()


# ── Session manager ───────────────────────────────────────────────────────────

class SessionManager:
    """Thread-safe registry of visitor sessions with expiry, capacity and memory budgets."""

    def __init__(
        self,
        ttl_minutes: Optional[int] = None,
        max_sessions: Optional[int] = None,
        max_session_memory_mb: Optional[int] = None,
        max_total_memory_mb: Optional[int] = None,
        max_concurrent_analyses: Optional[int] = None,
        empty_ttl_minutes: Optional[int] = None,
    ) -> None:
        ttl_min = ttl_minutes if ttl_minutes is not None else _env_int("SESSION_TTL_MINUTES", 30)
        self.ttl_seconds: float = float(max(1, ttl_min) * 60)

        empty_min = empty_ttl_minutes if empty_ttl_minutes is not None else _env_int("SESSION_EMPTY_TTL_MINUTES", 5)
        self.empty_ttl_seconds: float = float(max(1, empty_min) * 60)

        self.max_sessions: int = max_sessions if max_sessions is not None else _env_int("MAX_ACTIVE_SESSIONS", 500)

        sess_mb = max_session_memory_mb if max_session_memory_mb is not None else _env_int("MAX_SESSION_MEMORY_MB", 35)
        self.max_session_memory_bytes: int = sess_mb * 1024 * 1024

        total_mb = max_total_memory_mb if max_total_memory_mb is not None else _env_int("MAX_TOTAL_MEMORY_MB", 220)
        self.max_total_memory_bytes: int = total_mb * 1024 * 1024

        concurrency = max_concurrent_analyses if max_concurrent_analyses is not None else _env_int("MAX_CONCURRENT_ANALYSES", 2)
        self.max_concurrent_analyses: int = max(1, concurrency)
        self._analysis_sem = threading.BoundedSemaphore(self.max_concurrent_analyses)

        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.RLock()
        self._reserved_memory_bytes: int = 0

    # -- tokens ---------------------------------------------------------------
    @staticmethod
    def generate_token() -> str:
        return f"{SESSION_TOKEN_PREFIX}{secrets.token_hex(32)}"

    @staticmethod
    def is_valid_token(token: Optional[str]) -> bool:
        return validate_session_token(token)

    # -- expiry (call with self._lock held) ------------------------------------
    def _is_expired(self, s: SessionState, now: float) -> bool:
        ttl = self.ttl_seconds if s.upload_count > 0 else min(self.ttl_seconds, self.empty_ttl_seconds)
        return (now - s.last_accessed) > ttl

    def _expire(self, token: str, s: SessionState) -> None:
        self._sessions.pop(token, None)
        s._invalidate()
        logger.info("Session %s expired.", mask_session_token(token))

    # -- lifecycle --------------------------------------------------------------
    def create_session(self) -> SessionState:
        with self._lock:
            self.prune_expired()
            if len(self._sessions) >= self.max_sessions:
                logger.warning("Session creation rejected: capacity reached (%d/%d).", len(self._sessions), self.max_sessions)
                raise SessionCapacityError(
                    "The server is at its visitor-session capacity right now. "
                    "Please try again in a few minutes, or explore Demo Mode."
                )
            token = self.generate_token()
            while token in self._sessions:
                token = self.generate_token()
            session = SessionState(token)
            self._sessions[token] = session
            logger.info("Created session %s (active: %d).", mask_session_token(token), len(self._sessions))
            return session

    def get_session(self, token: Optional[str], touch: bool = True) -> Optional[SessionState]:
        """Look up a live session. Expired sessions are invalidated and return None."""
        if not self.is_valid_token(token):
            return None
        with self._lock:
            session = self._sessions.get(token)  # type: ignore[arg-type]
            if session is None or not session.is_active:
                return None
            if self._is_expired(session, time.time()):
                with session._state_lock:
                    leased = session._active_leases > 0
                if not leased:
                    self._expire(token, session)  # type: ignore[arg-type]
                    return None
            if touch:
                session.touch()
            return session

    def acquire_lease(self, token: Optional[str]) -> Optional[SessionLease]:
        """Look up a live session and pin it for the duration of a request."""
        if not self.is_valid_token(token):
            return None
        with self._lock:
            session = self._sessions.get(token)  # type: ignore[arg-type]
            if session is None or not session.is_active:
                return None
            if self._is_expired(session, time.time()):
                with session._state_lock:
                    leased = session._active_leases > 0
                if not leased:
                    self._expire(token, session)  # type: ignore[arg-type]
                    return None
            with session._state_lock:
                session._active_leases += 1
                session.touch()
            return SessionLease(self, session)

    def acquire_transaction(self, token: Optional[str], timeout: float = 2.0) -> SessionTransaction:
        """Exclusive mutation transaction on the session identified by ``token``."""
        session = self.get_session(token, touch=True)
        if session is None:
            raise SessionInvalidTokenError("Target session does not exist or has expired.")
        return session.transaction(timeout=timeout)

    def _release_session_lease(self, session: SessionState) -> None:
        with session._state_lock:
            session._active_leases = max(0, session._active_leases - 1)
            cleanup = session._active_leases == 0 and session._pending_delete
        if cleanup:
            with self._lock:
                self._sessions.pop(session.session_id, None)
            session._invalidate()

    def delete_session(self, token: Optional[str]) -> bool:
        """End a session. If a request is using it, cleanup is deferred to lease release."""
        if not self.is_valid_token(token):
            return False
        with self._lock:
            session = self._sessions.pop(token, None)  # type: ignore[arg-type]
            if session is None:
                return False
            with session._state_lock:
                session._is_deleted = True
                if session._active_leases > 0:
                    session._pending_delete = True
                    return True
            session._invalidate()
            logger.info("Deleted session %s.", mask_session_token(token))
            return True

    def prune_expired(self) -> int:
        """Expire idle sessions that have no active lease."""
        with self._lock:
            now = time.time()
            victims = []
            for tok, s in self._sessions.items():
                if self._is_expired(s, now):
                    with s._state_lock:
                        if s._active_leases == 0:
                            victims.append((tok, s))
            for tok, s in victims:
                self._expire(tok, s)
            return len(victims)

    # -- analysis slots -----------------------------------------------------------
    def acquire_analysis_slot(self, timeout: float = 0.0) -> AnalysisSlot:
        """
        Take one analysis slot or raise SessionConcurrencyError.
        ``timeout=0`` never waits. Safe to call from any thread or from the event
        loop when ``timeout=0``.
        """
        if timeout and timeout > 0:
            ok = self._analysis_sem.acquire(timeout=timeout)
        else:
            ok = self._analysis_sem.acquire(blocking=False)
        if not ok:
            raise SessionConcurrencyError(
                "The analysis engine is busy with other uploads. Please retry in a few seconds."
            )
        return AnalysisSlot(self._analysis_sem)

    # -- memory reservations --------------------------------------------------------
    def _committed_bytes(self) -> int:
        return sum(s.memory_bytes for s in self._sessions.values())

    def reserve_upload_memory(self, session_id: str, estimated_incoming_bytes: int) -> MemoryReservation:
        """
        Reserve memory for an incoming dataset. The reservation is the full incoming
        estimate: while it is analysed, any existing dataset in the session is still
        resident, so a replacement is never assumed to be free.
        """
        with self._lock:
            self.prune_expired()
            session = self._sessions.get(session_id)
            if session is None or not session.is_active:
                raise SessionInvalidTokenError("Target session does not exist or has expired.")

            if estimated_incoming_bytes > self.max_session_memory_bytes:
                max_mb = self.max_session_memory_bytes // (1024 * 1024)
                raise SessionMemoryError(
                    f"This file is too large for a visitor session (limit about {max_mb} MB in memory). "
                    "Please upload a smaller log extract."
                )

            projected = self._committed_bytes() + self._reserved_memory_bytes + estimated_incoming_bytes
            if projected > self.max_total_memory_bytes:
                logger.warning("Global memory budget reached (%d / %d bytes).", projected, self.max_total_memory_bytes)
                raise SessionCapacityError(
                    "Server analysis capacity is temporarily full. "
                    "Please retry in a few minutes, or explore Demo Mode."
                )

            self._reserved_memory_bytes += estimated_incoming_bytes
            return MemoryReservation(self, session_id, estimated_incoming_bytes, session.memory_bytes)

    def _commit_reservation(self, reservation: MemoryReservation, final_session_bytes: int) -> None:
        """Convert a reservation into committed session memory, or release it on failure."""
        with self._lock:
            if reservation.status != ReservationStatus.PENDING:
                raise RuntimeError(f"Cannot commit reservation in status: {reservation.status.value}")

            def _fail(exc: Exception) -> None:
                self._reserved_memory_bytes = max(0, self._reserved_memory_bytes - reservation.reserved_bytes)
                reservation.status = ReservationStatus.RELEASED
                raise exc

            session = self._sessions.get(reservation.session_id)
            if session is None or not session.is_active:
                _fail(SessionInvalidTokenError("Target session does not exist or has expired."))
            assert session is not None

            if final_session_bytes > self.max_session_memory_bytes:
                max_mb = self.max_session_memory_bytes // (1024 * 1024)
                _fail(SessionMemoryError(
                    f"After analysis the dataset exceeds the per-session memory limit (about {max_mb} MB). "
                    "Please upload a smaller log extract."
                ))

            other = sum(s.memory_bytes for tok, s in self._sessions.items() if tok != reservation.session_id)
            new_reserved = max(0, self._reserved_memory_bytes - reservation.reserved_bytes)
            if other + final_session_bytes + new_reserved > self.max_total_memory_bytes:
                _fail(SessionCapacityError(
                    "The analysed dataset would exceed server capacity. Please retry in a few minutes."
                ))

            self._reserved_memory_bytes = new_reserved
            with session._state_lock:
                session.memory_bytes = int(final_session_bytes)
            reservation.status = ReservationStatus.COMMITTED

    def _release_reservation(self, reservation: MemoryReservation) -> None:
        with self._lock:
            self._reserved_memory_bytes = max(0, self._reserved_memory_bytes - reservation.reserved_bytes)

    # -- metrics --------------------------------------------------------------------
    def get_metrics(self) -> dict[str, Any]:
        """Aggregate, non-sensitive statistics."""
        with self._lock:
            self.prune_expired()
            committed = self._committed_bytes()
            total = committed + self._reserved_memory_bytes
            return {
                "active_sessions": len(self._sessions),
                "max_sessions": self.max_sessions,
                "ttl_minutes": int(self.ttl_seconds / 60),
                "committed_memory_bytes": committed,
                "reserved_memory_bytes": self._reserved_memory_bytes,
                "total_memory_bytes": total,
                "max_total_memory_bytes": self.max_total_memory_bytes,
                "memory_usage_pct": round(total / self.max_total_memory_bytes * 100, 1) if self.max_total_memory_bytes else 0.0,
            }


# Process-wide singleton. Visitor sessions live in this process only: run a single
# worker (see render.yaml) or move to an external store before scaling out.
session_manager = SessionManager()
