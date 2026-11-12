"""Persistent API-key revocation and bounded authentication throttling."""

from __future__ import annotations

import math
import sqlite3
import threading
import time
from collections import deque
from datetime import UTC, datetime
from pathlib import Path


class ApiKeyRevocationStore:
    """SQLite-backed API-key revocation store shared across process restarts."""

    def __init__(self, database_path: str = "data/audit.db") -> None:
        self._database_path = database_path
        self._lock = threading.RLock()
        if database_path != ":memory:":
            Path(database_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            database_path, timeout=5.0, check_same_thread=False
        )
        with self._lock, self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS api_key_revocations (
                    key_id TEXT PRIMARY KEY,
                    revoked_at TEXT NOT NULL,
                    revoked_by TEXT NOT NULL
                )
                """
            )

    def is_revoked(self, key_id: str) -> bool:
        """Check revocation state on every authentication attempt."""
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM api_key_revocations WHERE key_id = ?",
                (key_id,),
            ).fetchone()
        return row is not None

    def revoke(self, key_id: str, *, revoked_by: str) -> bool:
        """Persist a revocation idempotently; return whether this call inserted it."""
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO api_key_revocations (key_id, revoked_at, revoked_by)
                VALUES (?, ?, ?)
                """,
                (key_id, datetime.now(UTC).isoformat(), revoked_by),
            )
        return cursor.rowcount == 1

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._connection.close()


class AuthAttemptLimiter:
    """Bounded per-client sliding-window limiter with temporary lockout."""

    def __init__(
        self,
        *,
        max_attempts: int = 10,
        window_seconds: float = 60.0,
        lockout_seconds: float = 300.0,
        max_tracked_clients: int = 8192,
    ) -> None:
        if max_attempts < 1 or window_seconds <= 0 or lockout_seconds <= 0:
            raise ValueError("Authentication rate-limit settings must be positive.")
        if max_tracked_clients < 1:
            raise ValueError("max_tracked_clients must be positive.")
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._lockout_seconds = lockout_seconds
        self._max_tracked_clients = max_tracked_clients
        self._attempts: dict[str, deque[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def _client_key(self, client_ip: str | None) -> str:
        key = client_ip or "unknown"
        if (
            key not in self._attempts
            and key not in self._blocked_until
            and len(self._attempts) + len(self._blocked_until) >= self._max_tracked_clients
        ):
            now = time.monotonic()
            expired_lockouts = [
                tracked_key
                for tracked_key, blocked_until in self._blocked_until.items()
                if blocked_until <= now
            ]
            for expired_key in expired_lockouts:
                self._blocked_until.pop(expired_key, None)
            stale_keys = [
                tracked_key
                for tracked_key, attempts in self._attempts.items()
                if tracked_key not in self._blocked_until
                and (not attempts or now - attempts[-1] >= self._window_seconds)
            ]
            for stale_key in stale_keys:
                self._attempts.pop(stale_key, None)
            if (
                len(self._attempts) + len(self._blocked_until) >= self._max_tracked_clients
            ):
                return "__overflow__"
        return key

    def is_blocked(self, client_ip: str | None) -> bool:
        """Return true while the client is in lockout."""
        now = time.monotonic()
        with self._lock:
            key = self._client_key(client_ip)
            blocked_until = self._blocked_until.get(key)
            if blocked_until is None:
                return False
            if blocked_until <= now:
                self._blocked_until.pop(key, None)
                self._attempts.pop(key, None)
                return False
            return True

    def retry_after(self, client_ip: str | None) -> int:
        """Return remaining lockout duration in whole seconds."""
        now = time.monotonic()
        with self._lock:
            key = self._client_key(client_ip)
            return max(0, math.ceil(self._blocked_until.get(key, now) - now))

    def record_failure(self, client_ip: str | None) -> bool:
        """Record a failed attempt and activate lockout at the configured threshold."""
        now = time.monotonic()
        with self._lock:
            key = self._client_key(client_ip)
            blocked_until = self._blocked_until.get(key)
            if blocked_until is not None and blocked_until > now:
                return True
            if blocked_until is not None:
                self._blocked_until.pop(key, None)
            attempts = self._attempts.setdefault(key, deque())
            while attempts and now - attempts[0] >= self._window_seconds:
                attempts.popleft()
            attempts.append(now)
            if len(attempts) >= self._max_attempts:
                self._blocked_until[key] = now + self._lockout_seconds
                self._attempts.pop(key, None)
                return True
            return False

    def record_success(self, client_ip: str | None) -> None:
        """Reset failed-attempt state after a successful authentication."""
        with self._lock:
            key = self._client_key(client_ip)
            self._attempts.pop(key, None)
            self._blocked_until.pop(key, None)
