"""Persistent API-key revocation and bounded authentication throttling."""

from __future__ import annotations

import json
import math
import os
import secrets
import sqlite3
import stat
import threading
import time
from collections import deque
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


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



class FirstRunBootstrapStore:
    """One-time local bootstrap using owner-only token and credential files.

    The bootstrap token and generated API key are persisted with mode 0600.
    The token is deleted after successful creation; the API key is shown only
    in the successful bootstrap response and retained in the credential file
    for subsequent process starts.
    """

    def __init__(self, storage_directory: str | Path) -> None:
        self._directory = Path(storage_directory).expanduser()
        self._token_path = self._directory / "bootstrap-token"
        self._credentials_path = self._directory / "bootstrap-credentials.json"
        self._lock = threading.RLock()

    @property
    def token_path(self) -> Path:
        """Return the operator-readable path to the one-time setup token."""
        return self._token_path

    @staticmethod
    def _read_private_file(path: Path) -> str:
        """Read a private regular file, rejecting group/world-accessible files."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                raise RuntimeError(f"Bootstrap file must be a regular owner-only file: {path}")
            with os.fdopen(descriptor, encoding="utf-8") as handle:
                return handle.read()
        except Exception:
            with suppress(OSError):
                os.close(descriptor)
            raise

    def load_credentials(self) -> dict[str, dict[str, Any]]:
        """Load previously bootstrapped credentials from the private file."""
        with self._lock:
            if not self._credentials_path.exists():
                return {}
            raw = self._read_private_file(self._credentials_path)
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise RuntimeError("Bootstrap credential file must contain a JSON object.")
            for key_id, definition in value.items():
                if (
                    not isinstance(key_id, str)
                    or not isinstance(definition, dict)
                    or not isinstance(definition.get("secret"), str)
                    or len(definition.get("secret", "")) < 32
                    or not definition.get("secret", "").isascii()
                    or not isinstance(definition.get("subject"), str)
                    or not definition.get("subject", "").strip()
                    or definition.get("role") != "admin"
                    or not isinstance(definition.get("enabled", True), bool)
                ):
                    raise RuntimeError("Bootstrap credential file contains an invalid credential.")
            return value

    def ensure_token(self) -> bool:
        """Create the one-time bootstrap token if setup is still required."""
        with self._lock:
            self._directory.mkdir(parents=True, exist_ok=True)
            if self._credentials_path.exists():
                if self._token_path.exists():
                    self._token_path.unlink()
                return False
            if self._token_path.exists():
                self._read_private_file(self._token_path)
                return True
            token = secrets.token_urlsafe(48)
            descriptor = os.open(
                self._token_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(token)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(self._token_path, 0o600)
            return True

    def create_admin(self, supplied_token: str, subject: str) -> tuple[str, str] | None:
        """Consume the one-time token and persist a randomly generated admin key."""
        with self._lock:
            if self._credentials_path.exists() or not self._token_path.exists():
                return None
            expected_token = self._read_private_file(self._token_path).strip()
            if not supplied_token.isascii() or not secrets.compare_digest(
                supplied_token, expected_token
            ):
                return None
            key_id = f"bootstrap-admin-{secrets.token_hex(8)}"
            api_key = secrets.token_urlsafe(48)
            credentials = {
                key_id: {
                    "secret": api_key,
                    "subject": subject,
                    "role": "admin",
                    "enabled": True,
                }
            }
            self._directory.mkdir(parents=True, exist_ok=True)
            temporary_path = self._credentials_path.with_name(
                f".{self._credentials_path.name}.{secrets.token_hex(8)}.tmp"
            )
            descriptor = os.open(
                temporary_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(credentials, handle, separators=(",", ":"), sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_path, self._credentials_path)
                os.chmod(self._credentials_path, 0o600)
                self._token_path.unlink()
            finally:
                if temporary_path.exists():
                    temporary_path.unlink()
            return key_id, api_key
