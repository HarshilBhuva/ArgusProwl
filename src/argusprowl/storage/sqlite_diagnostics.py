"""Read-only operational diagnostics for SQLite storage."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote


class SQLiteDiagnosticsError(RuntimeError):
    """Raised when SQLite diagnostics cannot inspect the configured database."""


@dataclass(frozen=True, slots=True)
class SQLiteDiagnostics:
    """Point-in-time, read-only SQLite health and capacity information."""

    database_path: str
    database_bytes: int
    wal_bytes: int
    page_count: int
    freelist_count: int
    schema_version: int
    durable_records: int
    durable_evidence: int | None
    integrity_status: str | None


class SQLiteDiagnosticsService:
    """Inspect an existing SQLite database without initializing or mutating it."""

    def inspect(
        self,
        database_path: str | Path,
        *,
        check_integrity: bool = True,
    ) -> SQLiteDiagnostics:
        path = Path(database_path)
        if not path.is_file():
            raise SQLiteDiagnosticsError(f"SQLite database does not exist: {path}")

        # URI quoting prevents special path characters from changing URI semantics.
        database_uri = f"file:{quote(str(path.resolve()), safe='/')}?mode=ro"
        try:
            with sqlite3.connect(database_uri, uri=True) as connection:
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                required = {"records"}
                if not required.issubset(tables):
                    raise SQLiteDiagnosticsError(
                        "Database is missing required ArgusProwl storage tables."
                    )

                durable_records = int(
                    connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
                )
                durable_evidence = None
                if "telemetry_evidence_index" in tables:
                    durable_evidence = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM telemetry_evidence_index"
                        ).fetchone()[0]
                    )

                page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
                freelist_count = int(
                    connection.execute("PRAGMA freelist_count").fetchone()[0]
                )
                schema_version = int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                )
                integrity_status = None
                if check_integrity:
                    rows = connection.execute("PRAGMA quick_check").fetchall()
                    integrity_status = (
                        "ok"
                        if rows and all(str(row[0]).lower() == "ok" for row in rows)
                        else "; ".join(str(row[0]) for row in rows) or "unknown"
                    )
        except SQLiteDiagnosticsError:
            raise
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise SQLiteDiagnosticsError(
                f"Unable to inspect SQLite database: {path}"
            ) from exc

        wal_path = Path(f"{path}-wal")
        return SQLiteDiagnostics(
            database_path=str(path),
            database_bytes=path.stat().st_size,
            wal_bytes=wal_path.stat().st_size if wal_path.exists() else 0,
            page_count=page_count,
            freelist_count=freelist_count,
            schema_version=schema_version,
            durable_records=durable_records,
            durable_evidence=durable_evidence,
            integrity_status=integrity_status,
        )
