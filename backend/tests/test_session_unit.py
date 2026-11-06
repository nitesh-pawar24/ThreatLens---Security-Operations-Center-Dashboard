"""
ThreatLens – Comprehensive Unit Tests for backend/session.py
============================================================
Validates:
- Cryptographic token generation and strict regex validation.
- Thread-safe session creation, lookup, deletion, and TTL expiration.
- Atomic memory reservations: competing uploads, replacement uploads, error releases.
- Mutually exclusive reservation lifecycle: commit updates committed memory, failed commit
  releases exactly once without double-release and never consumes other sessions' reservations.
- Session lease mechanism: deferred deletion, deferred expiration during active operations.
- Prevention of invalidated sessions committing new data.
- Upload/mutation transactions: same-session serialization and conflict errors.
- Coexistence accounting: replacement uploads account for temporary incoming dataset memory.
- Analysis slots: limits, non-blocking behaviour, idempotent release.
- Expiry invalidates the session object; empty sessions expire sooner.
- Reservation and lease cleanup after every failure path.
"""

import asyncio
import threading
import time
from pathlib import Path

import pandas as pd
import pytest

from backend.detector import Alert, DetectorConfig
from backend.session import (
    MemoryReservation,
    ReservationStatus,
    SessionCapacityError,
    SessionConcurrencyError,
    SessionConflictError,
    SessionError,
    SessionInvalidTokenError,
    SessionManager,
    SessionMemoryError,
    SessionState,
    SessionTransaction,
    estimate_dataset_memory,
    estimate_incoming_bytes,
    mask_session_token,
    validate_session_token,
)


class TestTokenValidationAndMasking:
    def test_valid_tokens_accepted(self):
        token = SessionManager.generate_token()
        assert validate_session_token(token) is True
        assert token.startswith("tl_sess_")
        assert len(token) == 72

    def test_invalid_tokens_rejected(self):
        assert validate_session_token(None) is False
        assert validate_session_token("") is False
        assert validate_session_token("invalid_token") is False
        assert validate_session_token("tl_sess_short") is False
        assert validate_session_token("tl_sess_" + "a" * 63) is False
        assert validate_session_token("tl_sess_" + "a" * 65) is False
        assert validate_session_token("tl_sess_" + "G" * 64) is False
        assert validate_session_token("tl_sess_" + "a" * 63 + "!") is False
        assert validate_session_token("tl_sess_" + "A" * 64) is False

    def test_token_masking(self):
        assert mask_session_token(None) == "[none]"
        assert mask_session_token("") == "[none]"
        assert mask_session_token("short") == "[none]"
        token = "tl_sess_" + "1" * 58 + "abcdef"
        masked = mask_session_token(token)
        assert masked == "tl_sess_...abcdef"
        assert token not in masked


class TestSessionStateAndMemoryAccounting:
    def test_independent_session_initialization(self):
        s1 = SessionState("tl_sess_" + "a" * 64)
        s2 = SessionState("tl_sess_" + "b" * 64)

        assert s1.session_id != s2.session_id
        assert s1.df is None
        assert s1.alerts == []
        assert isinstance(s1.config, DetectorConfig)

        s1.config.brute_force_threshold = 99
        assert s2.config.brute_force_threshold == 5

    def test_set_data_and_alert_memory_estimation(self):
        session = SessionState("tl_sess_" + "c" * 64)
        df = pd.DataFrame({
            "timestamp": ["2026-10-20 10:00:00"],
            "source_ip": ["192.0.2.1"],
            "event_type": ["LOGIN_FAILURE"],
            "username": ["alice"],
            "status": ["FAILURE"],
        })
        alerts = [
            Alert(
                alert_id="ALT-001",
                source_ip="192.0.2.1",
                event_type="LOGIN_FAILURE",
                severity="High",
                rules_matched=["BruteForce"],
                evidence=[{"timestamp": "2026-10-20 10:00:00"}],
                explanation="Test alert",
                generated_at="2026-10-20T10:00:00Z",
            )
        ]

        session.set_data(df, alerts, "test.csv", is_sample=False)

        assert session.has_real_data is True
        assert session.row_count == 1
        assert session.alert_count == 1
        assert session.dataset_name == "test.csv"
        assert session.memory_bytes > 500

    def test_reset_to_empty(self):
        session = SessionState("tl_sess_" + "d" * 64)
        df = pd.DataFrame({"col": [1, 2, 3]})
        session.set_data(df, [], "active.csv")

        session.reset_to_empty()
        assert session.df is None
        assert session.alerts == []
        assert session.dataset_name == "None"
        assert session.has_real_data is False
        assert session.memory_bytes == 0

    def test_snapshot_is_consistent_and_cached_summary_cleared_on_reset(self):
        session = SessionState("tl_sess_" + "e" * 64)
        df = pd.DataFrame({"col": [1, 2]})
        session.set_data(df, [], "x.csv", summary={"cached": True}, analyzed_at="2026-01-01T00:00:00+00:00")
        snap = session.snapshot()
        assert snap.df is df
        assert snap.dataset_name == "x.csv"
        assert snap.summary == {"cached": True}
        assert snap.analyzed_at == "2026-01-01T00:00:00+00:00"

        session.reset_to_empty()
        snap2 = session.snapshot()
        assert snap2.df is None and snap2.summary is None
        # An earlier snapshot is unaffected by later mutation
        assert snap.df is df

    def test_memory_estimate_is_not_below_measured_alert_size(self):
        evidence = [{"timestamp": "2026-10-20 10:00:00", "source_ip": "192.0.2.1"}]
        alerts = [
            Alert(alert_id=f"A{i}", source_ip="192.0.2.1", event_type="LOGIN_FAILURE",
                  severity="High", rules_matched=["BruteForce"], evidence=evidence,
                  explanation="x", generated_at="2026-10-20T10:00:00Z")
            for i in range(100)
        ]
        # Measured ~1.15 KB per single-evidence alert; the estimate must stay above that.
        assert estimate_dataset_memory(None, alerts) >= 100 * 1150

    def test_incoming_estimate_has_floor_and_scales(self):
        assert estimate_incoming_bytes(10) == 256 * 1024
        assert estimate_incoming_bytes(4_000_000) == 20_000_000


class TestAtomicMemoryReservationsAndCommitLifecycle:
    def test_successful_commit_updates_committed_memory_correctly(self):
        manager = SessionManager(max_session_memory_mb=5, max_total_memory_mb=10)
        s = manager.create_session()

        # Reserve 1 MB
        with manager.reserve_upload_memory(s.session_id, estimated_incoming_bytes=1_000_000) as res:
            assert res.status == ReservationStatus.PENDING
            assert manager.get_metrics()["reserved_memory_bytes"] == 1_000_000
            assert manager.get_metrics()["committed_memory_bytes"] == 0

            # Commit final 800 KB
            res.commit(final_session_bytes=800_000)
            assert res.status == ReservationStatus.COMMITTED

        metrics = manager.get_metrics()
        assert metrics["reserved_memory_bytes"] == 0
        assert metrics["committed_memory_bytes"] == 800_000
        assert s.memory_bytes == 800_000

    def test_failed_commit_does_not_double_release(self):
        manager = SessionManager(max_session_memory_mb=2, max_total_memory_mb=10)
        s = manager.create_session()

        # Reserve 1 MB
        res = manager.reserve_upload_memory(s.session_id, estimated_incoming_bytes=1_000_000)
        assert manager.get_metrics()["reserved_memory_bytes"] == 1_000_000

        # Invalidate the session before commit to force commit failure
        manager.delete_session(s.session_id)

        # Attempt commit -> fails with SessionInvalidTokenError
        with pytest.raises(SessionInvalidTokenError):
            res.commit(800_000)

        # Status must transition to RELEASED on failure
        assert res.status == ReservationStatus.RELEASED
        # Reserved memory decremented back to 0
        assert manager.get_metrics()["reserved_memory_bytes"] == 0

        # Now simulate __exit__ or explicit release()
        res.release()
        # Must NOT double-decrement or go negative
        assert manager.get_metrics()["reserved_memory_bytes"] == 0
        assert res.status == ReservationStatus.RELEASED

    def test_one_visitor_failed_commit_cannot_consume_another_visitors_reservation(self):
        manager = SessionManager(max_session_memory_mb=5, max_total_memory_mb=10)
        sA = manager.create_session()
        sB = manager.create_session()

        # Visitor A reserves 500 KB
        resA = manager.reserve_upload_memory(sA.session_id, estimated_incoming_bytes=500_000)
        # Visitor B reserves 700 KB
        resB = manager.reserve_upload_memory(sB.session_id, estimated_incoming_bytes=700_000)

        assert manager.get_metrics()["reserved_memory_bytes"] == 1_200_000

        # Delete session A so A's commit fails
        manager.delete_session(sA.session_id)

        # Visitor A attempts commit -> raises
        with pytest.raises(SessionInvalidTokenError):
            resA.commit(500_000)

        # After A's failed commit, reserved memory must equal EXACTLY B's 700 KB!
        assert manager.get_metrics()["reserved_memory_bytes"] == 700_000
        assert resA.status == ReservationStatus.RELEASED

        # A's context exit calls release() again
        resA.release()
        # B's reservation remains completely untouched
        assert manager.get_metrics()["reserved_memory_bytes"] == 700_000

        # Visitor B can now commit successfully
        resB.commit(600_000)
        assert resB.status == ReservationStatus.COMMITTED
        assert manager.get_metrics()["reserved_memory_bytes"] == 0
        assert manager.get_metrics()["committed_memory_bytes"] == 600_000
        assert sB.memory_bytes == 600_000

    def test_two_uploads_to_different_sessions_cannot_exceed_limits(self):
        manager = SessionManager(max_session_memory_mb=2, max_total_memory_mb=2)
        s1 = manager.create_session()
        s2 = manager.create_session()

        # s1 reserves 1.2 MB successfully
        res1 = manager.reserve_upload_memory(s1.session_id, estimated_incoming_bytes=1_200_000)
        assert res1.reserved_bytes == 1_200_000
        assert manager.get_metrics()["reserved_memory_bytes"] == 1_200_000

        # s2 attempts to reserve 1.2 MB: total projected 2.4 MB > 2.0 MB ceiling -> must raise
        with pytest.raises(SessionCapacityError) as exc_info:
            manager.reserve_upload_memory(s2.session_id, estimated_incoming_bytes=1_200_000)

        assert "Server analysis capacity is temporarily full" in str(exc_info.value)

        # Release res1
        res1.release()
        assert manager.get_metrics()["reserved_memory_bytes"] == 0

        # Now s2 can reserve successfully
        res2 = manager.reserve_upload_memory(s2.session_id, estimated_incoming_bytes=1_200_000)
        assert res2.reserved_bytes == 1_200_000
        res2.release()

    def test_smaller_replacement_uploads_account_for_temporary_coexistence(self):
        # Global capacity 3 MB, session ceiling 2 MB
        manager = SessionManager(max_session_memory_mb=2, max_total_memory_mb=3)
        s = manager.create_session()

        # Initial upload: 2 MB committed
        with manager.reserve_upload_memory(s.session_id, estimated_incoming_bytes=2_000_000) as res1:
            res1.commit(final_session_bytes=2_000_000)

        assert manager.get_metrics()["committed_memory_bytes"] == 2_000_000
        assert s.memory_bytes == 2_000_000

        # Replacement upload with smaller dataset (1.5 MB):
        # During parsing, old 2.0 MB committed + new 1.5 MB incoming = 3.5 MB projected peak > 3.0 MB limit!
        # Because we do NOT assume zero temporary memory cost, this MUST raise SessionCapacityError!
        with pytest.raises(SessionCapacityError):
            manager.reserve_upload_memory(s.session_id, estimated_incoming_bytes=1_500_000)

        # If global limit is 4 MB instead:
        manager_4mb = SessionManager(max_session_memory_mb=2, max_total_memory_mb=4)
        s2 = manager_4mb.create_session()
        with manager_4mb.reserve_upload_memory(s2.session_id, 2_000_000) as res_init:
            res_init.commit(2_000_000)

        # With 4 MB ceiling: 2 MB committed + 1.5 MB temporary = 3.5 MB <= 4 MB: succeeds!
        with manager_4mb.reserve_upload_memory(s2.session_id, estimated_incoming_bytes=1_500_000) as res_rep:
            assert manager_4mb.get_metrics()["reserved_memory_bytes"] == 1_500_000
            assert manager_4mb.get_metrics()["committed_memory_bytes"] == 2_000_000
            # Commit new 1.5 MB dataset -> replaces old 2.0 MB
            res_rep.commit(final_session_bytes=1_500_000)

        assert manager_4mb.get_metrics()["committed_memory_bytes"] == 1_500_000
        assert manager_4mb.get_metrics()["reserved_memory_bytes"] == 0

    def test_double_commit_and_invalid_state_prevented(self):
        manager = SessionManager(max_session_memory_mb=5, max_total_memory_mb=10)
        s = manager.create_session()

        res = manager.reserve_upload_memory(s.session_id, 100_000)
        res.commit(100_000)
        assert res.status == ReservationStatus.COMMITTED

        # Second commit raises RuntimeError
        with pytest.raises(RuntimeError):
            res.commit(100_000)

        # Release on already committed reservation is safe no-op
        res.release()
        assert res.status == ReservationStatus.COMMITTED


class TestSameSessionConcurrentTransactions:
    def test_two_uploads_to_same_session_raise_conflict_error(self):
        manager = SessionManager()
        s = manager.create_session()

        # Transaction 1 starts
        tx1 = manager.acquire_transaction(s.session_id, timeout=0.1)
        tx1.__enter__()

        try:
            # Transaction 2 on same session must fail with SessionConflictError
            with pytest.raises(SessionConflictError) as exc_info:
                with manager.acquire_transaction(s.session_id, timeout=0.1):
                    pass
            assert "in progress" in str(exc_info.value).lower()
        finally:
            tx1.__exit__(None, None, None)

        # Once tx1 exits, a subsequent transaction succeeds immediately
        with manager.acquire_transaction(s.session_id, timeout=0.1) as sess:
            assert sess.session_id == s.session_id

    def test_reset_during_upload_transaction_is_blocked(self):
        manager = SessionManager()
        s = manager.create_session()

        # Thread 1 starts upload transaction
        tx = manager.acquire_transaction(s.session_id, timeout=1.0)
        tx.__enter__()

        reset_error = []

        def attempt_reset():
            try:
                # Thread 2 tries to reset while upload transaction is held
                s.reset_to_empty(timeout=0.1)
            except SessionConflictError as e:
                reset_error.append(e)

        t = threading.Thread(target=attempt_reset)
        t.start()
        t.join()

        # Clean up tx
        tx.__exit__(None, None, None)

        assert len(reset_error) == 1
        assert "in progress" in str(reset_error[0]).lower()

    def test_cancellation_during_upload_transaction_releases_locks_and_memory(self):
        manager = SessionManager(max_session_memory_mb=5, max_total_memory_mb=10)
        s = manager.create_session()

        try:
            with manager.acquire_transaction(s.session_id, timeout=1.0):
                with manager.reserve_upload_memory(s.session_id, 2_000_000):
                    assert manager.get_metrics()["reserved_memory_bytes"] == 2_000_000
                    # Simulate cancellation / unhandled exception
                    raise asyncio.CancelledError("Client disconnected")
        except asyncio.CancelledError:
            pass

        # Memory must be released
        assert manager.get_metrics()["reserved_memory_bytes"] == 0
        # Transaction lock must be released; next transaction must succeed
        with manager.acquire_transaction(s.session_id, timeout=0.1) as sess:
            assert sess.session_id == s.session_id


class TestSessionLifecycleAndLeases:
    def test_active_lease_prevents_ttl_expiration(self):
        manager = SessionManager(ttl_minutes=1)
        manager.ttl_seconds = 0.2  # 200 ms TTL
        s = manager.create_session()
        token = s.session_id

        # Acquire an active operation lease
        lease = manager.acquire_lease(token)
        assert lease is not None

        # Wait past TTL
        time.sleep(0.3)

        # prune_expired() must NOT evict a session that has an active lease
        pruned = manager.prune_expired()
        assert pruned == 0
        assert s.is_active is True

        # Now release the lease
        lease.release()

        # Once released, next prune cleans it up
        pruned_after = manager.prune_expired()
        assert pruned_after == 1
        assert manager.get_session(token) is None

    def test_deletion_attempted_during_active_operation(self):
        manager = SessionManager(ttl_minutes=30)
        s = manager.create_session()
        token = s.session_id

        # In-flight request acquires lease
        lease = manager.acquire_lease(token)
        assert lease is not None

        # Another request calls delete_session while lease is held
        deleted = manager.delete_session(token)
        assert deleted is True

        # New lookups immediately fail to see the session
        assert manager.get_session(token) is None
        assert manager.acquire_lease(token) is None

        # The active in-flight operation still holds valid session reference
        with lease as active_sess:
            assert active_sess.session_id == token
            assert active_sess._is_deleted is True

        # When the lease context exits, deferred cleanup triggers
        assert s.df is None
        assert s.memory_bytes == 0

    def test_deletion_during_outstanding_reservation(self):
        manager = SessionManager(max_session_memory_mb=5, max_total_memory_mb=10)
        s = manager.create_session()
        token = s.session_id

        # Start reservation
        res = manager.reserve_upload_memory(token, 100_000)

        # Session is invalidated/deleted before commit happens
        manager.delete_session(token)

        # Attempting to commit to the deleted session must fail
        with pytest.raises(SessionInvalidTokenError):
            res.commit(100_000)

        # Reservation is cleanly released and status is RELEASED
        assert res.status == ReservationStatus.RELEASED
        assert manager.get_metrics()["reserved_memory_bytes"] == 0

    def test_cleanup_after_every_failure_path(self):
        manager = SessionManager(max_session_memory_mb=2, max_total_memory_mb=3)
        s = manager.create_session()
        token = s.session_id

        # Path 1: Exceed session memory ceiling on reserve (e.g. 5 MB > 2 MB session ceiling)
        with pytest.raises(SessionMemoryError):
            manager.reserve_upload_memory(token, estimated_incoming_bytes=5_000_000)
        assert manager.get_metrics()["reserved_memory_bytes"] == 0

        # Path 2: Exceed global capacity on reserve without exceeding per-session ceiling
        # First commit 2 MB to another session
        s_base = manager.create_session()
        with manager.reserve_upload_memory(s_base.session_id, 2_000_000) as r_base:
            r_base.commit(2_000_000)

        # Now s attempts to reserve 1.5 MB (<= 2 MB session ceiling, but 2 MB + 1.5 MB = 3.5 MB > 3 MB global ceiling)
        with pytest.raises(SessionCapacityError):
            manager.reserve_upload_memory(token, estimated_incoming_bytes=1_500_000)
        assert manager.get_metrics()["reserved_memory_bytes"] == 0

        # Path 3: Invalid token on reserve
        with pytest.raises(SessionInvalidTokenError):
            manager.reserve_upload_memory("tl_sess_nonexistent0000000000000000000000000000000000000000000000000000", 100_000)
        assert manager.get_metrics()["reserved_memory_bytes"] == 0

        # Path 4: Exception inside parsing with context manager
        try:
            with manager.reserve_upload_memory(token, 500_000):
                raise ValueError("Parsing corrupted data")
        except ValueError:
            pass
        assert manager.get_metrics()["reserved_memory_bytes"] == 0

        # Path 5: Exceed session limit on commit
        with manager.reserve_upload_memory(token, 500_000) as res:
            with pytest.raises(SessionMemoryError):
                res.commit(final_session_bytes=3_000_000)
        assert manager.get_metrics()["reserved_memory_bytes"] == 0

        # Path 6: Exceed global limit on commit
        # s attempts to commit 1.5 MB (2.0 MB s_base + 1.5 MB = 3.5 MB > 3 MB global)
        with manager.reserve_upload_memory(token, 500_000) as res_overflow:
            with pytest.raises(SessionCapacityError):
                res_overflow.commit(final_session_bytes=1_500_000)
        assert manager.get_metrics()["reserved_memory_bytes"] == 0


class TestAnalysisSlots:
    def test_slots_limit_concurrency_and_never_wait_by_default(self):
        manager = SessionManager(max_concurrent_analyses=2)
        a = manager.acquire_analysis_slot()
        b = manager.acquire_analysis_slot()
        with pytest.raises(SessionConcurrencyError):
            manager.acquire_analysis_slot()  # non-blocking by default
        a.release()
        c = manager.acquire_analysis_slot()  # freed slot is reusable
        b.release()
        c.release()

    def test_timeout_waits_then_raises(self):
        manager = SessionManager(max_concurrent_analyses=1)
        held = manager.acquire_analysis_slot()
        start = time.time()
        with pytest.raises(SessionConcurrencyError):
            manager.acquire_analysis_slot(timeout=0.1)
        assert time.time() - start >= 0.09
        held.release()

    def test_release_is_idempotent_and_context_manager_releases_on_error(self):
        manager = SessionManager(max_concurrent_analyses=1)
        slot = manager.acquire_analysis_slot()
        slot.release()
        slot.release()  # second release must not over-release the semaphore
        with pytest.raises(RuntimeError):
            with manager.acquire_analysis_slot():
                raise RuntimeError("analysis failed")
        # Exactly one permit exists: first acquire works, second fails
        s1 = manager.acquire_analysis_slot()
        with pytest.raises(SessionConcurrencyError):
            manager.acquire_analysis_slot()
        s1.release()

    def test_limit_never_exceeded_across_threads(self):
        manager = SessionManager(max_concurrent_analyses=2)
        active = 0
        peak = 0
        lock = threading.Lock()

        def worker():
            nonlocal active, peak
            try:
                with manager.acquire_analysis_slot(timeout=2.0):
                    with lock:
                        active += 1
                        peak = max(peak, active)
                    time.sleep(0.03)
                    with lock:
                        active -= 1
            except SessionConcurrencyError:
                pass

        threads = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert peak == 2


class TestExpiry:
    def test_expiry_invalidates_the_session_object(self):
        manager = SessionManager(ttl_minutes=1)
        s = manager.create_session()
        s.set_data(pd.DataFrame({"a": [1]}), [], "x.csv")
        s.last_accessed -= 3600
        assert manager.get_session(s.session_id) is None
        assert s.is_active is False
        # A request that still holds the object must not be able to commit data into it
        with pytest.raises(SessionInvalidTokenError):
            s.set_data(pd.DataFrame({"a": [1]}), [], "late.csv")
        assert s.df is None and s.memory_bytes == 0

    def test_empty_sessions_expire_sooner_than_sessions_with_data(self):
        manager = SessionManager(ttl_minutes=30, empty_ttl_minutes=1)
        empty = manager.create_session()
        used = manager.create_session()
        used.set_data(pd.DataFrame({"a": [1]}), [], "x.csv")
        empty.last_accessed -= 120   # idle 2 min: beyond empty TTL (1), within TTL (30)
        used.last_accessed -= 120
        assert manager.get_session(empty.session_id) is None
        assert manager.get_session(used.session_id) is used

    def test_expired_sessions_free_capacity_for_new_sessions(self):
        manager = SessionManager(max_sessions=1, ttl_minutes=1, empty_ttl_minutes=1)
        s = manager.create_session()
        with pytest.raises(SessionCapacityError):
            manager.create_session()
        s.last_accessed -= 3600
        assert manager.create_session() is not None

    def test_whitespace_padded_token_is_rejected(self):
        token = SessionManager.generate_token()
        assert validate_session_token(f" {token} ") is False
        assert validate_session_token(f"{token}\n") is False

    def test_expired_session_is_not_resurrected_by_reservation(self):
        manager = SessionManager(ttl_minutes=1)
        s = manager.create_session()
        s.last_accessed -= 3600
        with pytest.raises(SessionInvalidTokenError):
            manager.reserve_upload_memory(s.session_id, 1000)
