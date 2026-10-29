"""SQLite infrastructure adapter. Business services depend only on Storage."""

import json
import sqlite3
import threading
from pathlib import Path
from uuid import UUID

from argusprowl.exceptions.exceptions import StorageError
from argusprowl.interfaces.storage import Storage


class SQLiteAdapter(Storage):
    """Thread-safe JSON document storage for the Phase 1 local deployment.

    Collections are values rather than table names, avoiding dynamic SQL.
    """

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
        self._connection.commit()
        self._lock = threading.RLock()

    def save(self, collection: str, record_id: UUID, data: dict[str, object]) -> None:
        try:
            payload = json.dumps(data, default=str, separators=(",", ":"))
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT INTO records(collection, record_id, payload) VALUES(?, ?, ?) ON CONFLICT(collection, record_id) DO UPDATE SET payload=excluded.payload",
                    (collection, str(record_id), payload),
                )
        except (sqlite3.Error, TypeError) as exc:
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
                return (
                    self._connection.execute(
                        "DELETE FROM records WHERE collection=? AND record_id=?",
                        (collection, str(record_id)),
                    ).rowcount
                    > 0
                )
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

    def close(self) -> None:
        with self._lock:
            self._connection.close()


# Kept so existing imports and configuration wiring remain valid.
SQLiteStorage = SQLiteAdapter
