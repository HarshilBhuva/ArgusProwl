"""Tests for read-only SQLite operational diagnostics."""

from __future__ import annotations

import sqlite3

import pytest

from argusprowl.storage.sqlite_diagnostics import (
    SQLiteDiagnosticsError,
    SQLiteDiagnosticsService,
)


def _create_storage_database(path):
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE records (collection TEXT, record_id TEXT, payload TEXT)"
        )
        connection.execute(
            "CREATE TABLE telemetry_evidence_index (event_id TEXT PRIMARY KEY)"
        )
        connection.execute(
            "INSERT INTO records VALUES ('alerts', 'alert-1', '{}')"
        )
        connection.execute(
            "INSERT INTO telemetry_evidence_index VALUES ('event-1')"
        )
        connection.execute("PRAGMA user_version=9")


def test_inspect_reports_integrity_and_durable_counts(tmp_path):
    database = tmp_path / "argusprowl.db"
    _create_storage_database(database)

    result = SQLiteDiagnosticsService().inspect(database)

    assert result.integrity_status == "ok"
    assert result.schema_version == 9
    assert result.durable_records == 1
    assert result.durable_evidence == 1
    assert result.database_bytes == database.stat().st_size
    assert result.page_count > 0
    assert result.freelist_count >= 0


def test_stats_mode_skips_integrity_scan(tmp_path):
    database = tmp_path / "argusprowl.db"
    _create_storage_database(database)

    result = SQLiteDiagnosticsService().inspect(database, check_integrity=False)

    assert result.integrity_status is None
    assert result.durable_records == 1


def test_legacy_database_without_evidence_index_is_supported(tmp_path):
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE records (collection TEXT, record_id TEXT, payload TEXT)"
        )

    result = SQLiteDiagnosticsService().inspect(database)

    assert result.durable_evidence is None
    assert result.integrity_status == "ok"


def test_missing_database_fails_closed(tmp_path):
    with pytest.raises(SQLiteDiagnosticsError, match="does not exist"):
        SQLiteDiagnosticsService().inspect(tmp_path / "missing.db")


def test_unrelated_sqlite_database_is_rejected(tmp_path):
    database = tmp_path / "unrelated.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE unrelated (value TEXT)")

    with pytest.raises(SQLiteDiagnosticsError, match="required ArgusProwl"):
        SQLiteDiagnosticsService().inspect(database)


def test_inspection_does_not_change_database_bytes(tmp_path):
    database = tmp_path / "argusprowl.db"
    _create_storage_database(database)
    before = database.read_bytes()

    SQLiteDiagnosticsService().inspect(database)

    assert database.read_bytes() == before
