"""SQLite infrastructure adapter with indexed telemetry evidence queries."""

import base64
import json
import sqlite3
import threading
from pathlib import Path
from uuid import UUID

from argusprowl.exceptions.exceptions import StorageError
from argusprowl.interfaces.storage import Storage


class SQLiteAdapter(Storage):
    """Thread-safe JSON document storage with a transactional evidence index.

    The JSON record remains authoritative. The narrow index contains only
    normalized query dimensions and is maintained in the same SQLite transaction.
    """

    _EVIDENCE_COLLECTION = "telemetry_evidence"

    def __init__(self, database_path: str | Path) -> None:
        self._path = Path(database_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._path, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS records (collection TEXT NOT NULL, record_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(collection, record_id))"
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_records_collection_created ON records(collection, created_at DESC)"
        )
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS telemetry_evidence_index (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                hostname TEXT,
                username TEXT,
                process_name TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                event_type TEXT NOT NULL,
                source_type TEXT NOT NULL
            )"""
        )
        self._connection.execute("CREATE INDEX IF NOT EXISTS idx_evidence_time_id ON telemetry_evidence_index(timestamp, event_id)")
        for column in ("hostname", "username", "process_name", "src_ip", "dst_ip", "event_type", "source_type"):
            self._connection.execute(
                f"CREATE INDEX IF NOT EXISTS idx_evidence_{column}_time ON telemetry_evidence_index({column}, timestamp, event_id)"
            )
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)"
        )
        self._connection.commit()
        self._lock = threading.RLock()
        self._migrate_evidence_index()

    def _migrate_evidence_index(self) -> None:
        """Backfill the derived index once for databases created before this version."""
        with self._lock, self._connection:
            migrated = self._connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version=1"
            ).fetchone()
            if migrated:
                return
            rows = self._connection.execute(
                "SELECT record_id, payload FROM records WHERE collection=?",
                (self._EVIDENCE_COLLECTION,),
            ).fetchall()
            for record_id, raw_payload in rows:
                try:
                    payload = json.loads(raw_payload)
                    self._upsert_evidence_index(record_id, payload)
                except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                    # The evidence service reports malformed source records during
                    # recovery; do not make a partial migration look complete.
                    continue
            self._connection.execute(
                "INSERT INTO schema_migrations(version) VALUES(1)"
            )

    def _upsert_evidence_index(self, record_id: str, payload: dict[str, object]) -> None:
        event = payload.get("event")
        if not isinstance(event, dict):
            raise ValueError("Telemetry evidence payload must contain an event object.")
        event_id = str(event.get("event_id", ""))
        if event_id != record_id:
            raise ValueError("Telemetry evidence record ID does not match event ID.")
        timestamp = event.get("timestamp")
        event_type = event.get("event_type")
        source_type = event.get("source_type")
        if not all(isinstance(value, str) and value for value in (timestamp, event_type, source_type)):
            raise ValueError("Telemetry evidence index fields are incomplete.")
        self._connection.execute(
            """INSERT INTO telemetry_evidence_index
            (event_id, timestamp, hostname, username, process_name, src_ip, dst_ip, event_type, source_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                timestamp=excluded.timestamp, hostname=excluded.hostname,
                username=excluded.username, process_name=excluded.process_name,
                src_ip=excluded.src_ip, dst_ip=excluded.dst_ip,
                event_type=excluded.event_type, source_type=excluded.source_type""",
            (
                event_id, timestamp, event.get("hostname"), event.get("username"),
                event.get("process_name"), event.get("src_ip"), event.get("dst_ip"),
                event_type, source_type,
            ),
        )

    def save(self, collection: str, record_id: UUID, data: dict[str, object]) -> None:
        try:
            payload = json.dumps(data, default=str, separators=(",", ":"))
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT INTO records(collection, record_id, payload) VALUES(?, ?, ?) ON CONFLICT(collection, record_id) DO UPDATE SET payload=excluded.payload",
                    (collection, str(record_id), payload),
                )
                if collection == self._EVIDENCE_COLLECTION:
                    self._upsert_evidence_index(str(record_id), data)
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise StorageError("Unable to persist record", {"collection": collection}) from exc

    def load(self, collection: str, record_id: UUID) -> dict[str, object] | None:
        try:
            with self._lock:
                row = self._connection.execute(
                    "SELECT payload FROM records WHERE collection=? AND record_id=?",
                    (collection, str(record_id)),
                ).fetchone()
            return json.loads(row[0]) if row else None
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            raise StorageError("Unable to load record", {"collection": collection}) from exc

    def delete(self, collection: str, record_id: UUID) -> bool:
        try:
            with self._lock, self._connection:
                deleted = self._connection.execute(
                    "DELETE FROM records WHERE collection=? AND record_id=?",
                    (collection, str(record_id)),
                ).rowcount > 0
                if collection == self._EVIDENCE_COLLECTION:
                    self._connection.execute(
                        "DELETE FROM telemetry_evidence_index WHERE event_id=?",
                        (str(record_id),),
                    )
                return deleted
        except sqlite3.Error as exc:
            raise StorageError("Unable to delete record", {"collection": collection}) from exc

    def list_records(self, collection: str, limit: int = 100) -> list[dict[str, object]]:
        if limit < 1:
            return []
        try:
            with self._lock:
                rows = self._connection.execute(
                    "SELECT payload FROM records WHERE collection=? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                    (collection, limit),
                ).fetchall()
            return [json.loads(row[0]) for row in rows]
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            raise StorageError("Unable to list records", {"collection": collection}) from exc

    @staticmethod
    def _decode_cursor(cursor: str | None) -> tuple[str, str] | None:
        if cursor is None:
            return None
        try:
            raw = base64.urlsafe_b64decode(cursor.encode("ascii") + b"=" * (-len(cursor) % 4))
            value = json.loads(raw)
            timestamp, event_id = value["timestamp"], str(UUID(value["event_id"]))
            if not isinstance(timestamp, str) or not timestamp:
                raise ValueError
            return timestamp, event_id
        except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid evidence pagination cursor.") from exc

    @staticmethod
    def _encode_cursor(timestamp: str, event_id: str) -> str:
        raw = json.dumps({"timestamp": timestamp, "event_id": event_id}, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def search_telemetry_evidence(
        self,
        filters: dict[str, object],
        *,
        limit: int,
        cursor: str | None = None,
    ) -> dict[str, object]:
        """Search the durable evidence index with keyset pagination."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValueError("Evidence result limit must be between 1 and 500.")
        clauses: list[str] = []
        values: list[object] = []

        exact_fields = {
            "event_id": "i.event_id",
            "event_type": "i.event_type",
            "source_type": "i.source_type",
            "src_ip": "i.src_ip",
            "dst_ip": "i.dst_ip",
        }
        for key, column in exact_fields.items():
            value = filters.get(key)
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(str(value))
        for key, operator in (("start_time", ">="), ("end_time", "<=")):
            value = filters.get(key)
            if value is not None:
                clauses.append(f"i.timestamp {operator} ?")
                values.append(value.isoformat() if hasattr(value, "isoformat") else str(value))

        entity_type, entity_id = filters.get("entity_type"), filters.get("entity_id")
        if entity_type is not None or entity_id is not None:
            if not entity_type or not entity_id:
                clauses.append("0 = 1")
            else:
                entity_columns = {
                    "hostname": ("i.hostname",),
                    "host": ("i.hostname",),
                    "user": ("i.username",),
                    "process": ("i.process_name",),
                    "src_ip": ("i.src_ip", "i.dst_ip"),
                    "ip": ("i.src_ip", "i.dst_ip"),
                    "network": ("i.src_ip", "i.dst_ip"),
                }
                columns = entity_columns.get(str(entity_type).lower())
                if columns is None:
                    clauses.append("0 = 1")
                elif len(columns) == 1:
                    clauses.append(f"{columns[0]} = ? COLLATE NOCASE")
                    values.append(str(entity_id))
                else:
                    clauses.append(f"({columns[0]} = ? OR {columns[1]} = ?)")
                    values.extend((str(entity_id), str(entity_id)))

        domain = filters.get("domain")
        if domain is not None:
            clauses.append("(lower(i.hostname) LIKE ? OR lower(i.dst_ip) LIKE ?)")
            pattern = f"%{str(domain).lower()}%"
            values.extend((pattern, pattern))

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        decoded = self._decode_cursor(cursor)
        with self._lock:
            total_row = self._connection.execute(
                "SELECT COUNT(*) FROM telemetry_evidence_index i" + where, values
            ).fetchone()
            total_count = int(total_row[0]) if total_row else 0
            page_clauses = list(clauses)
            page_values = list(values)
            if decoded is not None:
                page_clauses.append("(i.timestamp > ? OR (i.timestamp = ? AND i.event_id > ?))")
                page_values.extend((decoded[0], decoded[0], decoded[1]))
            page_where = " WHERE " + " AND ".join(page_clauses) if page_clauses else ""
            rows = self._connection.execute(
                """SELECT r.payload, i.timestamp, i.event_id
                FROM telemetry_evidence_index i
                JOIN records r ON r.collection=? AND r.record_id=i.event_id"""
                + page_where
                + " ORDER BY i.timestamp ASC, i.event_id ASC LIMIT ?",
                [self._EVIDENCE_COLLECTION, *page_values, limit + 1],
            ).fetchall()
        has_more = len(rows) > limit
        selected = rows[:limit]
        next_cursor = self._encode_cursor(selected[-1][1], selected[-1][2]) if has_more and selected else None
        try:
            payloads = [json.loads(row[0]) for row in selected]
        except json.JSONDecodeError as exc:
            raise StorageError("Unable to decode indexed telemetry evidence", {"collection": self._EVIDENCE_COLLECTION}) from exc
        return {
            "records": payloads,
            "total_count": total_count,
            "returned_count": len(payloads),
            "truncated": has_more,
            "next_cursor": next_cursor,
        }

    def close(self) -> None:
        with self._lock:
            self._connection.close()


# Kept so existing imports and configuration wiring remain valid.
SQLiteStorage = SQLiteAdapter
