"""PostgreSQL JSONB storage adapter with bounded connection pooling.

This adapter implements the generic Storage contract. SQLite-specific evidence
and entity-intelligence projections are intentionally not advertised as supported.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from uuid import UUID

from argusprowl.exceptions.exceptions import StorageError
from argusprowl.interfaces.storage import Storage


class PostgreSQLAdapter(Storage):
    """Thread-safe PostgreSQL JSONB storage with versioned schema migrations."""

    _MIGRATIONS: tuple[tuple[int, str], ...] = (
        (1, """
            CREATE TABLE IF NOT EXISTS argusprowl_records (
                collection TEXT NOT NULL,
                record_id TEXT NOT NULL,
                payload JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (collection, record_id)
            );
            CREATE INDEX IF NOT EXISTS idx_argusprowl_records_collection_created
                ON argusprowl_records (collection, created_at DESC, record_id);
        """),
    )

    def __init__(
        self,
        connection_string: str,
        *,
        min_size: int = 1,
        max_size: int = 10,
        timeout: float = 10.0,
        open_timeout: float = 10.0,
    ) -> None:
        if not connection_string.strip():
            raise ValueError("PostgreSQL connection string must not be empty.")
        if min_size < 1 or max_size < min_size:
            raise ValueError("Pool sizes must satisfy 1 <= min_size <= max_size.")
        if timeout <= 0 or open_timeout <= 0:
            raise ValueError("Pool timeouts must be positive.")
        try:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError as exc:
            raise StorageError(
                "PostgreSQL support requires the optional dependency: pip install argusprowl[postgresql]"
            ) from exc
        from psycopg.types.json import Jsonb

        self._jsonb = Jsonb
        self._pool = ConnectionPool(
            conninfo=connection_string,
            min_size=min_size,
            max_size=max_size,
            timeout=timeout,
            open=False,
            kwargs={"row_factory": dict_row},
        )
        try:
            self._pool.open(wait=True, timeout=open_timeout)
            self._run_migrations()
        except Exception as exc:
            self._pool.close()
            raise StorageError(f"Unable to initialize PostgreSQL storage: {exc}") from exc

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        try:
            with self._pool.connection() as connection:
                yield connection
        except Exception as exc:
            if isinstance(exc, StorageError):
                raise
            raise StorageError(f"PostgreSQL storage operation failed: {exc}") from exc

    def _run_migrations(self) -> None:
        with self._connection() as connection, connection.transaction():
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                ("argusprowl-schema",),
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS argusprowl_schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )"""
            )
            for version, statement in self._MIGRATIONS:
                applied = connection.execute(
                    "SELECT 1 FROM argusprowl_schema_migrations WHERE version = %s",
                    (version,),
                ).fetchone()
                if applied is None:
                    connection.execute(statement)
                    connection.execute(
                        "INSERT INTO argusprowl_schema_migrations(version) VALUES (%s)",
                        (version,),
                    )

    def save(self, collection: str, record_id: UUID, data: dict[str, object]) -> None:
        if not collection.strip():
            raise ValueError("Collection must not be empty.")
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO argusprowl_records(collection, record_id, payload)
                   VALUES (%s, %s, %s)
                   ON CONFLICT(collection, record_id) DO UPDATE
                   SET payload = EXCLUDED.payload, updated_at = CURRENT_TIMESTAMP""",
                (collection, str(record_id), self._jsonb(data)),
            )

    def load(self, collection: str, record_id: UUID) -> dict[str, object] | None:
        with self._connection() as connection:
            row = connection.execute(
                """SELECT payload FROM argusprowl_records
                   WHERE collection = %s AND record_id = %s""",
                (collection, str(record_id)),
            ).fetchone()
        return row["payload"] if row is not None else None

    def delete(self, collection: str, record_id: UUID) -> bool:
        with self._connection() as connection:
            cursor = connection.execute(
                """DELETE FROM argusprowl_records
                   WHERE collection = %s AND record_id = %s""",
                (collection, str(record_id)),
            )
        return cursor.rowcount > 0

    def list_records(self, collection: str, limit: int = 100) -> list[dict[str, object]]:
        if limit < 1:
            raise ValueError("Record limit must be positive.")
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT payload FROM argusprowl_records
                   WHERE collection = %s ORDER BY created_at DESC, record_id LIMIT %s""",
                (collection, limit),
            ).fetchall()
        return [row["payload"] for row in rows]

    def health_check(self) -> bool:
        with self._connection() as connection:
            row = connection.execute("SELECT 1 AS healthy").fetchone()
        return row is not None and row["healthy"] == 1

    def close(self) -> None:
        """Close the pool during application shutdown."""
        self._pool.close()
