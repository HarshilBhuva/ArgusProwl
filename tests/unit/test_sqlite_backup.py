"""Tests for consistent SQLite backup, verification, and offline restore."""

import json
import sqlite3

import pytest

from argusprowl.storage.sqlite_backup import SQLiteBackupError, SQLiteBackupManager


def _create_database(path):
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA user_version=7")
        connection.execute("CREATE TABLE evidence (event_id TEXT PRIMARY KEY, payload TEXT)")
        connection.execute(
            "INSERT INTO evidence(event_id, payload) VALUES (?, ?)",
            ("event-1", '{"severity":"high"}'),
        )


def test_backup_includes_committed_wal_data_and_manifest(tmp_path):
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    _create_database(source)

    manager = SQLiteBackupManager()
    manifest = manager.create_backup(
        source, backup, application_version="0.1.0"
    )

    assert manifest.schema_version == 7
    assert manifest.database_size_bytes == backup.stat().st_size
    assert len(manifest.sha256) == 64
    assert manager.verify_backup(backup) == manifest
    with sqlite3.connect(backup) as connection:
        assert connection.execute("SELECT payload FROM evidence").fetchone()[0] == (
            '{"severity":"high"}'
        )


def test_backup_refuses_to_overwrite_existing_backup_or_manifest(tmp_path):
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    _create_database(source)
    manager = SQLiteBackupManager()
    manager.create_backup(source, backup, application_version="0.1.0")

    with pytest.raises(FileExistsError):
        manager.create_backup(source, backup, application_version="0.1.0")


def test_verification_rejects_checksum_mismatch(tmp_path):
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    _create_database(source)
    manager = SQLiteBackupManager()
    manager.create_backup(source, backup, application_version="0.1.0")

    with backup.open("ab") as stream:
        stream.write(b"tampered")

    with pytest.raises(SQLiteBackupError, match="size does not match"):
        manager.verify_backup(backup)


def test_verification_rejects_manifest_tampering(tmp_path):
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    _create_database(source)
    manager = SQLiteBackupManager()
    manager.create_backup(source, backup, application_version="0.1.0")
    manifest_path = tmp_path / "backup.db.manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(SQLiteBackupError, match="checksum mismatch"):
        manager.verify_backup(backup)


def test_restore_stages_and_atomically_replaces_database(tmp_path):
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    restored = tmp_path / "restored.db"
    _create_database(source)
    with sqlite3.connect(restored) as connection:
        connection.execute("CREATE TABLE old_data (value TEXT)")
        connection.execute("INSERT INTO old_data VALUES ('stale')")

    manager = SQLiteBackupManager()
    manager.create_backup(source, backup, application_version="0.1.0")
    manager.restore_backup(backup, restored)

    with sqlite3.connect(restored) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7
        assert connection.execute("SELECT event_id FROM evidence").fetchone()[0] == "event-1"
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='old_data'"
        ).fetchone() is None


@pytest.mark.parametrize("sidecar", ["-wal", "-shm"])
def test_restore_refuses_target_with_sqlite_sidecars(tmp_path, sidecar):
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    restored = tmp_path / "restored.db"
    _create_database(source)
    manager = SQLiteBackupManager()
    manager.create_backup(source, backup, application_version="0.1.0")
    (tmp_path / f"restored.db{sidecar}").write_bytes(b"")

    with pytest.raises(SQLiteBackupError, match="sidecars"):
        manager.restore_backup(backup, restored)


def test_restore_rejects_invalid_backup_without_changing_target(tmp_path):
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    restored = tmp_path / "restored.db"
    _create_database(source)
    restored.write_bytes(b"existing target")
    manager = SQLiteBackupManager()
    manager.create_backup(source, backup, application_version="0.1.0")
    with backup.open("ab") as stream:
        stream.write(b"corruption")

    with pytest.raises(SQLiteBackupError):
        manager.restore_backup(backup, restored)
    assert restored.read_bytes() == b"existing target"


def test_backup_requires_application_version(tmp_path):
    source = tmp_path / "source.db"
    _create_database(source)

    with pytest.raises(ValueError, match="application_version"):
        SQLiteBackupManager().create_backup(source, tmp_path / "backup.db", application_version=" ")
