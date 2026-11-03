"""Durable, hash-chained SQLite audit log for API activity."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/api/v1", tags=["Security Audit"])
_GENESIS_HASH = "0" * 64
_EVENT_FIELDS = (
    "id",
    "timestamp",
    "event_type",
    "actor_id",
    "role",
    "method",
    "path",
    "status_code",
    "request_id",
    "client_ip",
)


class AuditIntegrityError(RuntimeError):
    """Raised when the existing audit chain cannot safely be extended."""


class AuditLog:
    """Append-only SQLite audit event store with a SHA-256 hash chain."""

    def __init__(self, database_path: str = "data/audit.db") -> None:
        self._database_path = database_path
        self._lock = threading.Lock()
        if database_path != ":memory:":
            Path(database_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        with closing(self._connect()) as connection, connection:
            yield connection

    @staticmethod
    def _canonical_event(event: dict[str, Any]) -> bytes:
        payload = {field: event[field] for field in _EVENT_FIELDS}
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    @classmethod
    def _event_hash(cls, event: dict[str, Any], previous_hash: str) -> str:
        digest = hashlib.sha256()
        digest.update(previous_hash.encode("ascii"))
        digest.update(b"\n")
        digest.update(cls._canonical_event(event))
        return digest.hexdigest()

    def _initialize(self) -> None:
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS api_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    request_id TEXT NOT NULL,
                    client_ip TEXT,
                    previous_hash TEXT,
                    event_hash TEXT
                )
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(api_audit_events)")
            }
            migrated = False
            if "previous_hash" not in columns:
                connection.execute(
                    "ALTER TABLE api_audit_events ADD COLUMN previous_hash TEXT"
                )
                migrated = True
            if "event_hash" not in columns:
                connection.execute(
                    "ALTER TABLE api_audit_events ADD COLUMN event_hash TEXT"
                )
                migrated = True
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_api_audit_timestamp "
                "ON api_audit_events(timestamp DESC, id DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_api_audit_actor "
                "ON api_audit_events(actor_id, timestamp DESC)"
            )
            if migrated:
                self._backfill_legacy_chain(connection)

    def _backfill_legacy_chain(self, connection: sqlite3.Connection) -> None:
        """Chain pre-existing rows once, in immutable insertion order."""
        previous_hash = _GENESIS_HASH
        rows = connection.execute(
            f"SELECT {', '.join(_EVENT_FIELDS)} FROM api_audit_events ORDER BY id ASC"
        ).fetchall()
        for row in rows:
            event = dict(row)
            current_hash = self._event_hash(event, previous_hash)
            connection.execute(
                "UPDATE api_audit_events SET previous_hash = ?, event_hash = ? WHERE id = ?",
                (previous_hash, current_hash, event["id"]),
            )
            previous_hash = current_hash

    def append(
        self,
        *,
        event_type: str,
        actor_id: str,
        role: str,
        method: str,
        path: str,
        status_code: int,
        request_id: str,
        client_ip: str | None,
    ) -> int:
        """Append an event and its chain link in one SQLite transaction."""
        with self._lock, self._connection() as connection:
            latest = connection.execute(
                "SELECT event_hash FROM api_audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_hash = latest["event_hash"] if latest else _GENESIS_HASH
            if (
                not isinstance(previous_hash, str)
                or len(previous_hash) != 64
                or any(char not in "0123456789abcdef" for char in previous_hash)
            ):
                raise AuditIntegrityError(
                    "Audit chain tail is invalid; refusing to append"
                )

            timestamp = datetime.now(UTC).isoformat()
            cursor = connection.execute(
                """
                INSERT INTO api_audit_events (
                    timestamp, event_type, actor_id, role, method, path,
                    status_code, request_id, client_ip, previous_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    event_type,
                    actor_id,
                    role,
                    method,
                    path,
                    status_code,
                    request_id,
                    client_ip,
                    previous_hash,
                    "",
                ),
            )
            event = {
                "id": int(cursor.lastrowid),
                "timestamp": timestamp,
                "event_type": event_type,
                "actor_id": actor_id,
                "role": role,
                "method": method,
                "path": path,
                "status_code": status_code,
                "request_id": request_id,
                "client_ip": client_ip,
            }
            event_hash = self._event_hash(event, previous_hash)
            connection.execute(
                "UPDATE api_audit_events SET event_hash = ? WHERE id = ?",
                (event_hash, event["id"]),
            )
            return event["id"]

    def verify_integrity(self) -> dict[str, Any]:
        """Verify every row and link from the genesis hash to the current tail."""
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                f"SELECT {', '.join(_EVENT_FIELDS)}, previous_hash, event_hash "
                "FROM api_audit_events ORDER BY id ASC"
            ).fetchall()
            expected_previous = _GENESIS_HASH
            for index, row in enumerate(rows):
                event = {field: row[field] for field in _EVENT_FIELDS}
                actual_previous = row["previous_hash"]
                actual_hash = row["event_hash"]
                expected_hash = self._event_hash(event, expected_previous)
                if actual_previous != expected_previous or actual_hash != expected_hash:
                    return {
                        "valid": False,
                        "checked_count": index,
                        "first_invalid_id": event["id"],
                    }
                expected_previous = actual_hash
            return {
                "valid": True,
                "checked_count": len(rows),
                "first_invalid_id": None,
            }

    def list_events(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """Return newest audit events with bounded pagination."""
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, timestamp, event_type, actor_id, role, method, path,
                       status_code, request_id, client_ip, previous_hash, event_hash
                FROM api_audit_events
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            return [dict(row) for row in rows]

    def count_events(self) -> int:
        """Return the number of retained audit events."""
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM api_audit_events"
            ).fetchone()
            return int(row["total"])


@router.get("/audit", summary="Read security audit events")
def list_audit_events(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Return a bounded audit view; middleware restricts this route to admins."""
    audit_log: AuditLog = request.app.state.audit_log
    return {
        "events": audit_log.list_events(limit=limit, offset=offset),
        "total_count": audit_log.count_events(),
        "limit": limit,
        "offset": offset,
    }


@router.get("/audit/integrity", summary="Verify security audit chain")
def verify_audit_integrity(request: Request) -> dict[str, Any]:
    """Run the full audit-chain verification; middleware restricts this to admins."""
    audit_log: AuditLog = request.app.state.audit_log
    return audit_log.verify_integrity()
