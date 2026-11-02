"""Durable, append-only SQLite audit log for API activity."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/api/v1", tags=["Security Audit"])


class AuditLog:
    """Append-only audit event store backed by SQLite."""

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
                    client_ip TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_api_audit_timestamp "
                "ON api_audit_events(timestamp DESC, id DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_api_audit_actor "
                "ON api_audit_events(actor_id, timestamp DESC)"
            )

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
        """Append one event without recording credentials, query strings, or bodies."""
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO api_audit_events (
                    timestamp, event_type, actor_id, role, method, path,
                    status_code, request_id, client_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(UTC).isoformat(), event_type, actor_id, role, method,
                    path, status_code, request_id, client_ip,
                ),
            )
            return int(cursor.lastrowid)

    def list_events(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """Return newest audit events with bounded pagination."""
        with self._lock, self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, timestamp, event_type, actor_id, role, method, path,
                       status_code, request_id, client_ip
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
            row = connection.execute("SELECT COUNT(*) AS total FROM api_audit_events").fetchone()
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
