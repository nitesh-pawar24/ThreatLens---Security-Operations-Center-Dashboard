"""
ThreatLens – Production Configuration & Security Safeguards Tests
==================================================================
Verifies:
1. Health check endpoint readiness for Render deployment.
2. Security response headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy).
3. CORS policy enforcement: local dev origins allowed, unknown origins rejected.
4. Row count guardrail preventing Denial-of-Service / OOM via oversized CSVs.
5. In-memory sliding-window rate limiter behavior.
6. Admin API key protection on PUT /api/detection/config when enabled.
"""

from __future__ import annotations

import io
import textwrap
import pytest
from fastapi.testclient import TestClient

from backend.api import (
    app,
    SlidingWindowRateLimiter,
    MAX_UPLOAD_ROWS,
)
import backend.api as api_module

client = TestClient(app)


class TestProductionHealthAndHeaders:
    """Verifies health check and security response headers."""

    def test_health_endpoint_for_render(self) -> None:
        """Render uses /api/health to confirm service is healthy."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["engine"] == "ready"

    def test_security_headers_present_on_responses(self) -> None:
        """Every API response must include standard defensive security headers."""
        response = client.get("/api/health")
        headers = response.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


class TestCorsConfiguration:
    """Verifies CORS behavior for local dev and production origins."""

    def test_localhost_origin_allowed(self) -> None:
        """Local development origin http://localhost:5173 must be allowed."""
        response = client.options(
            "/api/summary",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"

    def test_unknown_origin_not_allowed(self) -> None:
        """Arbitrary untrusted origin must not be granted CORS access."""
        response = client.options(
            "/api/summary",
            headers={
                "Origin": "https://unauthorized-attacker-site.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.headers.get("access-control-allow-origin") != "https://unauthorized-attacker-site.com"


class TestUploadGuardrails:
    """Verifies protection against oversized log uploads."""

    def test_rejects_excessive_row_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CSV uploads exceeding MAX_UPLOAD_ROWS are rejected before detection execution."""
        monkeypatch.setattr(api_module, "MAX_UPLOAD_ROWS", 5)

        # Generate 10 rows (exceeding limit of 5)
        lines = ["timestamp,source_ip,event_type,username,status"]
        for i in range(10):
            lines.append(f"2026-11-04 10:00:{i:02d},192.0.2.1,LOGIN_FAILURE,user,FAILURE")
        csv_bytes = "\n".join(lines).encode("utf-8")

        response = client.post(
            "/api/analyze",
            files={"file": ("large_test.csv", csv_bytes, "text/csv")},
        )
        assert response.status_code == 400
        assert "exceeding the portfolio analysis limit of 5 rows" in response.json()["detail"]


class TestRateLimiter:
    """Unit tests for the SlidingWindowRateLimiter."""

    def test_rate_limiter_allows_under_limit(self) -> None:
        limiter = SlidingWindowRateLimiter(default_limit=5, upload_limit=2)
        ip = "198.51.100.1"

        # 5 normal requests allowed
        for _ in range(5):
            allowed, _ = limiter.is_allowed(ip, is_upload=False)
            assert allowed is True

        # 6th request blocked
        allowed, retry_after = limiter.is_allowed(ip, is_upload=False)
        assert allowed is False
        assert retry_after > 0

    def test_rate_limiter_upload_limit_enforced(self) -> None:
        limiter = SlidingWindowRateLimiter(default_limit=10, upload_limit=2)
        ip = "198.51.100.2"

        # 2 upload requests allowed
        assert limiter.is_allowed(ip, is_upload=True)[0] is True
        assert limiter.is_allowed(ip, is_upload=True)[0] is True

        # 3rd upload request blocked
        allowed, retry_after = limiter.is_allowed(ip, is_upload=True)
        assert allowed is False
        assert retry_after > 0


class TestAdminApiKeyProtection:
    """Verifies that setting ADMIN_API_KEY protects PUT /api/detection/config."""

    def test_config_mutation_unprotected_when_admin_key_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "ADMIN_API_KEY", "")
        response = client.put(
            "/api/detection/config",
            json={"brute_force_threshold": 5},
        )
        assert response.status_code == 200

    def test_config_mutation_blocked_when_admin_key_set_and_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "ADMIN_API_KEY", "secret-portfolio-key-123")
        response = client.put(
            "/api/detection/config",
            json={"brute_force_threshold": 5},
        )
        assert response.status_code == 403
        assert "Administrative authorization required" in response.json()["detail"]

    def test_config_mutation_allowed_with_correct_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "ADMIN_API_KEY", "secret-portfolio-key-123")
        response = client.put(
            "/api/detection/config",
            json={"brute_force_threshold": 5},
            headers={"X-Admin-Key": "secret-portfolio-key-123"},
        )
        assert response.status_code == 200

    def test_config_mutation_blocked_with_wrong_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "ADMIN_API_KEY", "secret-portfolio-key-123")
        response = client.put(
            "/api/detection/config",
            json={"brute_force_threshold": 5},
            headers={"X-Admin-Key": "incorrect-password"},
        )
        assert response.status_code == 403
        assert "Administrative authorization required" in response.json()["detail"]

    def test_config_mutation_allowed_with_bearer_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "ADMIN_API_KEY", "secret-portfolio-key-123")
        response = client.put(
            "/api/detection/config",
            json={"brute_force_threshold": 5},
            headers={"Authorization": "Bearer secret-portfolio-key-123"},
        )
        assert response.status_code == 200

    def test_config_mutation_blocked_with_wrong_bearer_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "ADMIN_API_KEY", "secret-portfolio-key-123")
        response = client.put(
            "/api/detection/config",
            json={"brute_force_threshold": 5},
            headers={"Authorization": "Bearer bad-token"},
        )
        assert response.status_code == 403


class TestUploadHardening:
    """Tests for file upload safety, filename sanitization, and streaming limits."""

    def test_upload_filename_path_traversal_sanitized(self) -> None:
        csv_content = "timestamp,source_ip,event_type,username,status\n2026-03-30T09:00:00Z,192.0.2.1,LOGIN_FAILURE,alice,FAILURE\n"
        response = client.post(
            "/api/analyze",
            files={"file": ("../../etc/passwd.csv", csv_content.encode("utf-8"), "text/csv")},
        )
        assert response.status_code == 200
        # The filename in the response summary must be the basename only
        assert response.json()["filename"] == "passwd.csv"


class TestPortfolioReadOnlyAccess:
    """Verifies that PORTFOLIO_READ_ONLY protects all write endpoints from unauthenticated visitors."""

    SAMPLE_CSV = (
        "timestamp,source_ip,event_type,username,status\n"
        "2026-03-30T09:00:00Z,192.0.2.1,LOGIN_FAILURE,alice,FAILURE\n"
    )

    def test_health_indicates_read_only_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "PORTFOLIO_READ_ONLY", True)
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["read_only"] is True
        assert data["mode"] == "portfolio_read_only"

    def test_read_only_blocks_unauthenticated_analyze(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "PORTFOLIO_READ_ONLY", True)
        res = client.post(
            "/api/analyze",
            files={"file": ("test.csv", self.SAMPLE_CSV.encode("utf-8"), "text/csv")},
        )
        assert res.status_code == 403
        assert "disabled in this public portfolio deployment" in res.json()["detail"]

    def test_read_only_blocks_unauthenticated_analyze_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "PORTFOLIO_READ_ONLY", True)
        res = client.post(
            "/api/analyze/windows",
            files={"file": ("test.csv", self.SAMPLE_CSV.encode("utf-8"), "text/csv")},
        )
        assert res.status_code == 403
        assert "disabled in this public portfolio deployment" in res.json()["detail"]

    def test_read_only_blocks_unauthenticated_reset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "PORTFOLIO_READ_ONLY", True)
        res = client.post("/api/reset")
        assert res.status_code == 403
        assert "disabled in this public portfolio deployment" in res.json()["detail"]

    def test_read_only_blocks_unauthenticated_sample(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "PORTFOLIO_READ_ONLY", True)
        res = client.post("/api/sample")
        assert res.status_code == 403
        assert "disabled in this public portfolio deployment" in res.json()["detail"]

    def test_read_only_blocks_unauthenticated_config_update(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "PORTFOLIO_READ_ONLY", True)
        res = client.put("/api/detection/config", json={"brute_force_threshold": 3})
        assert res.status_code == 403
        assert "disabled in this public portfolio deployment" in res.json()["detail"]

    def test_read_only_permits_admin_key_authenticated_upload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "PORTFOLIO_READ_ONLY", True)
        monkeypatch.setattr(api_module, "ADMIN_API_KEY", "prod-secret-999")
        res = client.post(
            "/api/analyze",
            files={"file": ("test.csv", self.SAMPLE_CSV.encode("utf-8"), "text/csv")},
            headers={"X-Admin-Key": "prod-secret-999"},
        )
        assert res.status_code == 200
        assert res.json()["success"] is True

    def test_read_only_allows_all_public_read_endpoints(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "PORTFOLIO_READ_ONLY", True)
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/summary").status_code == 200
        assert client.get("/api/alerts").status_code == 200
        assert client.get("/api/logs").status_code == 200
        assert client.get("/api/detection/config").status_code == 200
        assert client.get("/api/windows/supported-events").status_code == 200

    def test_local_mode_allows_unauthenticated_write_operations(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(api_module, "PORTFOLIO_READ_ONLY", False)
        monkeypatch.setattr(api_module, "ADMIN_API_KEY", "")
        # Reset must work unrestricted without headers in local mode
        res = client.post("/api/reset")
        assert res.status_code == 200
        assert res.json()["success"] is True
