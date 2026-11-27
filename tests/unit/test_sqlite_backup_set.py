"""Tests for coordinated, verified SQLite backup generations."""
import json
import sqlite3

import pytest

from argusprowl.storage.sqlite_backup_set import SQLiteBackupSetError, SQLiteBackupSetManager


def _database(path, value):
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE records (value TEXT)")
        connection.execute("INSERT INTO records VALUES (?)", (value,))


def test_backup_set_publishes_and_verifies_all_databases(tmp_path):
    sources = {}
    for name in ("evidence", "alerts", "audit"):
        source = tmp_path / f"{name}-source.db"
        _database(source, name)
        sources[name] = source

    destination = tmp_path / "generation-001"
    manager = SQLiteBackupSetManager()
    created = manager.create_backup_set(
        sources, destination, application_version="0.1.0"
    )

    assert [item["name"] for item in created["databases"]] == [
        "alerts", "audit", "evidence"
    ]
    verified = manager.verify_backup_set(destination)
    assert verified == created
    for name in sources:
        with sqlite3.connect(destination / f"{name}.db") as connection:
            assert connection.execute("SELECT value FROM records").fetchone()[0] == name


def test_backup_set_refuses_to_overwrite_generation(tmp_path):
    source = tmp_path / "source.db"
    _database(source, "evidence")
    destination = tmp_path / "generation"
    manager = SQLiteBackupSetManager()
    manager.create_backup_set({"evidence": source}, destination, application_version="0.1.0")

    with pytest.raises(FileExistsError):
        manager.create_backup_set({"evidence": source}, destination, application_version="0.1.0")


def test_backup_set_verification_rejects_missing_member(tmp_path):
    source = tmp_path / "source.db"
    _database(source, "evidence")
    destination = tmp_path / "generation"
    manager = SQLiteBackupSetManager()
    manager.create_backup_set({"evidence": source}, destination, application_version="0.1.0")
    (destination / "evidence.db").unlink()

    with pytest.raises(SQLiteBackupSetError, match="verification failed"):
        manager.verify_backup_set(destination)


def test_backup_set_verification_rejects_path_traversal(tmp_path):
    source = tmp_path / "source.db"
    _database(source, "evidence")
    destination = tmp_path / "generation"
    manager = SQLiteBackupSetManager()
    manager.create_backup_set({"evidence": source}, destination, application_version="0.1.0")
    manifest_path = destination / "backup-set.json"
    document = json.loads(manifest_path.read_text())
    document["databases"][0]["database_file"] = "../outside.db"
    manifest_path.write_text(json.dumps(document))

    with pytest.raises(SQLiteBackupSetError, match="paths are invalid"):
        manager.verify_backup_set(destination)


def test_backup_set_rejects_missing_source_before_publishing(tmp_path):
    destination = tmp_path / "generation"
    manager = SQLiteBackupSetManager()
    with pytest.raises(SQLiteBackupSetError, match="missing"):
        manager.create_backup_set(
            {"evidence": tmp_path / "missing.db"},
            destination,
            application_version="0.1.0",
        )
    assert not destination.exists()
    assert not list(tmp_path.glob(".*.staging"))

def test_backup_set_rejects_duplicate_database_paths(tmp_path):
    source = tmp_path / "source.db"
    _database(source, "shared")
    manager = SQLiteBackupSetManager()

    with pytest.raises(ValueError, match="distinct"):
        manager.create_backup_set(
            {"evidence": source, "alerts": source},
            tmp_path / "generation",
            application_version="0.1.0",
        )
    assert not (tmp_path / "generation").exists()


def test_backup_set_rejects_boolean_format_version(tmp_path):
    source = tmp_path / "source.db"
    _database(source, "evidence")
    destination = tmp_path / "generation"
    manager = SQLiteBackupSetManager()
    manager.create_backup_set({"evidence": source}, destination, application_version="0.1.0")
    manifest_path = destination / "backup-set.json"
    document = json.loads(manifest_path.read_text())
    document["format_version"] = True
    manifest_path.write_text(json.dumps(document))

    with pytest.raises(SQLiteBackupSetError, match="Unsupported"):
        manager.verify_backup_set(destination)
