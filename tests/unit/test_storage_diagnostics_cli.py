"""Tests for SQLite storage diagnostics CLI commands."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from argusprowl.constants.exit_codes import ExitCode


def _run(monkeypatch, *argv: str) -> int:
    from argusprowl import __main__ as cli

    monkeypatch.setattr(sys, "argv", ["argusprowl", *argv])
    return cli.main()


def test_storage_check_runs_integrity_check(monkeypatch, capsys):
    from argusprowl import __main__ as cli

    calls = []
    monkeypatch.setattr(
        cli.ConfigManager,
        "load",
        lambda self, path: SimpleNamespace(
            storage=SimpleNamespace(backend="sqlite", database_path="/data/app.db")
        ),
    )

    class _Diagnostics:
        def inspect(self, path, *, check_integrity):
            calls.append((path, check_integrity))
            return SimpleNamespace(
                database_path=path,
                database_bytes=1024,
                wal_bytes=128,
                page_count=10,
                freelist_count=2,
                schema_version=3,
                durable_records=20,
                durable_evidence=15,
                integrity_status="ok" if check_integrity else None,
            )

    monkeypatch.setattr(cli, "SQLiteDiagnosticsService", _Diagnostics)
    assert _run(monkeypatch, "storage", "check") == ExitCode.SUCCESS
    assert calls == [("/data/app.db", True)]
    assert "Quick check:      ok" in capsys.readouterr().out


def test_storage_stats_skips_integrity_scan(monkeypatch):
    from argusprowl import __main__ as cli

    calls = []
    monkeypatch.setattr(
        cli.ConfigManager,
        "load",
        lambda self, path: SimpleNamespace(
            storage=SimpleNamespace(backend="sqlite", database_path="/data/app.db")
        ),
    )

    class _Diagnostics:
        def inspect(self, path, *, check_integrity):
            calls.append(check_integrity)
            return SimpleNamespace(
                database_path=path,
                database_bytes=1024,
                wal_bytes=0,
                page_count=10,
                freelist_count=0,
                schema_version=3,
                durable_records=20,
                durable_evidence=None,
                integrity_status=None,
            )

    monkeypatch.setattr(cli, "SQLiteDiagnosticsService", _Diagnostics)
    assert _run(monkeypatch, "storage", "stats") == ExitCode.SUCCESS
    assert calls == [False]


def test_storage_commands_reject_non_sqlite_backend(monkeypatch):
    from argusprowl import __main__ as cli

    monkeypatch.setattr(
        cli.ConfigManager,
        "load",
        lambda self, path: SimpleNamespace(
            storage=SimpleNamespace(backend="postgresql", database_path="/data/app.db")
        ),
    )
    assert _run(monkeypatch, "storage", "check") == ExitCode.CONFIG_ERROR


def test_storage_check_returns_error_for_failed_integrity(monkeypatch):
    from argusprowl import __main__ as cli

    monkeypatch.setattr(
        cli.ConfigManager,
        "load",
        lambda self, path: SimpleNamespace(
            storage=SimpleNamespace(backend="sqlite", database_path="/data/app.db")
        ),
    )

    class _Diagnostics:
        def inspect(self, path, *, check_integrity):
            return SimpleNamespace(
                database_path=path,
                database_bytes=1,
                wal_bytes=0,
                page_count=1,
                freelist_count=0,
                schema_version=0,
                durable_records=0,
                durable_evidence=None,
                integrity_status="database disk image is malformed",
            )

    monkeypatch.setattr(cli, "SQLiteDiagnosticsService", _Diagnostics)
    assert _run(monkeypatch, "storage", "check") == ExitCode.RUNTIME_ERROR
