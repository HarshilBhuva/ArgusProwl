"""Tests for durable API-key revocation and authentication throttling."""

from __future__ import annotations

import pytest

from argusprowl.api.auth_store import ApiKeyRevocationStore, AuthAttemptLimiter


def test_api_key_revocation_survives_store_recreation(tmp_path) -> None:
    database_path = str(tmp_path / "auth-state.db")
    first = ApiKeyRevocationStore(database_path)
    assert first.revoke("analyst-1", revoked_by="admin-1") is True
    assert first.is_revoked("analyst-1") is True
    first.close()

    second = ApiKeyRevocationStore(database_path)
    assert second.is_revoked("analyst-1") is True
    assert second.revoke("analyst-1", revoked_by="admin-2") is False
    second.close()


def test_api_key_revocation_store_isolated_by_key_id(tmp_path) -> None:
    store = ApiKeyRevocationStore(str(tmp_path / "auth-state.db"))
    store.revoke("viewer-1", revoked_by="admin-1")
    assert store.is_revoked("viewer-1") is True
    assert store.is_revoked("viewer-2") is False
    store.close()


def test_auth_attempt_limiter_locks_out_after_threshold() -> None:
    limiter = AuthAttemptLimiter(max_attempts=2, window_seconds=60, lockout_seconds=30)
    assert limiter.is_blocked("192.0.2.10") is False
    assert limiter.record_failure("192.0.2.10") is False
    assert limiter.record_failure("192.0.2.10") is True
    assert limiter.is_blocked("192.0.2.10") is True
    assert 1 <= limiter.retry_after("192.0.2.10") <= 30


def test_auth_attempt_limiter_success_resets_failed_attempts() -> None:
    limiter = AuthAttemptLimiter(max_attempts=2, window_seconds=60, lockout_seconds=30)
    limiter.record_failure("192.0.2.11")
    limiter.record_success("192.0.2.11")
    assert limiter.record_failure("192.0.2.11") is False


def test_auth_attempt_limiter_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError):
        AuthAttemptLimiter(max_attempts=0)
