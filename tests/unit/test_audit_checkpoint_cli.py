"""CLI tests for signed audit checkpoint operations."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from argusprowl.api.audit import AuditLog
from argusprowl.constants.exit_codes import ExitCode


def _run(monkeypatch, *argv: str) -> int:
    from argusprowl import __main__ as cli

    monkeypatch.setattr(sys, "argv", ["argusprowl", *argv])
    return cli.main()


def test_audit_checkpoint_cli_create_and_verify(tmp_path, monkeypatch, capsys):
    from argusprowl import __main__ as cli

    database = tmp_path / "audit.db"
    checkpoint = tmp_path / "audit.checkpoint.json"
    audit = AuditLog(str(database))
    audit.append(
        event_type="REQUEST_COMPLETED",
        actor_id="operator",
        role="admin",
        method="GET",
        path="/api/v1/alerts",
        status_code=200,
        request_id="request-1",
        client_ip="127.0.0.1",
    )
    monkeypatch.setenv(
        "ARGUSPROWL_AUDIT_CHECKPOINT_KEY",
        "cli-test-signing-key-with-more-than-32-bytes",
    )
    monkeypatch.setattr(
        cli.ConfigManager,
        "load",
        lambda self, path: SimpleNamespace(
            api=SimpleNamespace(audit_db_path=str(database))
        ),
    )

    assert _run(
        monkeypatch, "audit-checkpoint", "create", "--output", str(checkpoint)
    ) == ExitCode.SUCCESS
    assert "Signed audit checkpoint created" in capsys.readouterr().out

    assert _run(
        monkeypatch, "audit-checkpoint", "verify", str(checkpoint)
    ) == ExitCode.SUCCESS
    assert "Audit checkpoint verified" in capsys.readouterr().out


def test_audit_checkpoint_cli_requires_signing_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ARGUSPROWL_AUDIT_CHECKPOINT_KEY", raising=False)
    result = _run(
        monkeypatch, "audit-checkpoint", "create", "--output", str(tmp_path / "cp.json")
    )
    assert result == ExitCode.CONFIG_ERROR
    assert "ARGUSPROWL_AUDIT_CHECKPOINT_KEY" in capsys.readouterr().err


def test_audit_checkpoint_cli_parser_accepts_config_before_or_after_action():
    from argusprowl.__main__ import create_parser

    parser = create_parser()
    before = parser.parse_args(
        ["--config", "custom.yaml", "audit-checkpoint", "verify", "checkpoint.json"]
    )
    after = parser.parse_args(
        ["audit-checkpoint", "--config", "custom.yaml", "verify", "checkpoint.json"]
    )

    assert before.config == "custom.yaml"
    assert after.config == "custom.yaml"
