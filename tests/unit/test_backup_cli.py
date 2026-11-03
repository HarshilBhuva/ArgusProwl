"""Operator-facing SQLite backup CLI tests."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from types import SimpleNamespace

from argusprowl.constants.exit_codes import ExitCode


@dataclass
class _Manifest:
    created_at: str = "2026-11-03T00:00:00+00:00"
    application_version: str = "0.1.0"
    schema_version: int = 1
    database_size_bytes: int = 128
    sha256: str = "a" * 64


class _BackupManager:
    last_instance: _BackupManager | None = None

    def __init__(self) -> None:
        self.created = None
        self.verified = None
        self.restored = None
        type(self).last_instance = self

    def create_backup(self, database_path, backup_path, *, application_version):
        self.created = (database_path, backup_path, application_version)
        return _Manifest()

    def verify_backup(self, backup_path):
        self.verified = backup_path
        return _Manifest()

    def restore_backup(self, backup_path, destination_path):
        self.restored = (backup_path, destination_path)
        return _Manifest()


def _run(monkeypatch, *argv: str) -> int:
    from argusprowl import __main__ as cli

    monkeypatch.setattr(sys, "argv", ["argusprowl", *argv])
    return cli.main()


def test_backup_verify_does_not_load_application_config(monkeypatch, capsys):
    from argusprowl import __main__ as cli

    monkeypatch.setattr(cli, "SQLiteBackupManager", _BackupManager)

    def fail_config_load(*args, **kwargs):
        raise AssertionError("verify must not require application configuration")

    monkeypatch.setattr(cli.ConfigManager, "load", fail_config_load)
    assert _run(monkeypatch, "backup", "verify", "snapshot.db") == ExitCode.SUCCESS
    assert _BackupManager.last_instance.verified == "snapshot.db"
    assert "Backup verification successful" in capsys.readouterr().out


def test_backup_create_uses_configured_database_and_application_version(monkeypatch):
    from argusprowl import __main__ as cli

    monkeypatch.setattr(cli, "SQLiteBackupManager", _BackupManager)
    monkeypatch.setattr(
        cli.ConfigManager,
        "load",
        lambda self, path: SimpleNamespace(
            storage=SimpleNamespace(backend="sqlite", database_path="/var/lib/argusprowl.db")
        ),
    )

    assert _run(monkeypatch, "backup", "create", "--output", "/backups/daily.db") == ExitCode.SUCCESS
    assert _BackupManager.last_instance.created == (
        "/var/lib/argusprowl.db",
        "/backups/daily.db",
        cli.argusprowl.__version__,
    )


def test_backup_create_rejects_non_sqlite_backend(monkeypatch):
    from argusprowl import __main__ as cli

    monkeypatch.setattr(cli, "SQLiteBackupManager", _BackupManager)
    monkeypatch.setattr(
        cli.ConfigManager,
        "load",
        lambda self, path: SimpleNamespace(
            storage=SimpleNamespace(backend="postgresql", database_path="/db/app.db")
        ),
    )

    assert _run(monkeypatch, "backup", "create", "--output", "/backups/daily.db") == (
        ExitCode.CONFIG_ERROR
    )
    assert _BackupManager.last_instance.created is None


def test_backup_restore_requires_explicit_offline_confirmation(monkeypatch, capsys):
    from argusprowl import __main__ as cli

    monkeypatch.setattr(cli, "SQLiteBackupManager", _BackupManager)
    monkeypatch.setattr(
        cli.ConfigManager,
        "load",
        lambda self, path: SimpleNamespace(
            storage=SimpleNamespace(backend="sqlite", database_path="/var/lib/argusprowl.db")
        ),
    )

    assert _run(monkeypatch, "backup", "restore", "snapshot.db") == ExitCode.CONFIG_ERROR
    assert _BackupManager.last_instance.restored is None
    assert "offline-only" in capsys.readouterr().err


def test_backup_restore_targets_configured_database_after_confirmation(monkeypatch):
    from argusprowl import __main__ as cli

    monkeypatch.setattr(cli, "SQLiteBackupManager", _BackupManager)
    monkeypatch.setattr(
        cli.ConfigManager,
        "load",
        lambda self, path: SimpleNamespace(
            storage=SimpleNamespace(backend="sqlite", database_path="/var/lib/argusprowl.db")
        ),
    )

    assert _run(
        monkeypatch, "backup", "restore", "snapshot.db", "--confirm-offline"
    ) == ExitCode.SUCCESS
    assert _BackupManager.last_instance.restored == (
        "snapshot.db",
        "/var/lib/argusprowl.db",
    )


def test_backup_config_option_works_before_or_after_subcommand():
    from argusprowl.__main__ import create_parser

    parser = create_parser()
    before = parser.parse_args(
        ["--config", "custom.yaml", "backup", "create", "--output", "snapshot.db"]
    )
    after = parser.parse_args(
        ["backup", "--config", "custom.yaml", "create", "--output", "snapshot.db"]
    )

    assert before.config == "custom.yaml"
    assert after.config == "custom.yaml"
