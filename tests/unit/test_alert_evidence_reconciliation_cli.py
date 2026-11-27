"""Tests for the read-only alert/evidence reconciliation command."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

from argusprowl.constants.exit_codes import ExitCode


class _AlertStore:
    last_instance = None

    def __init__(self, *, db_path, max_alerts):
        self.db_path = db_path
        self.max_alerts = max_alerts
        self.closed = False
        type(self).last_instance = self

    def initialize(self):
        return None

    def get_status(self):
        return SimpleNamespace(value="AVAILABLE")

    def get_status_reason(self):
        return None

    def close(self):
        self.closed = True


class _EvidenceStorage:
    last_instance = None

    def __init__(self, path):
        self.path = path
        self.closed = False
        type(self).last_instance = self

    def close(self):
        self.closed = True


class _EvidenceService:
    def __init__(self, *, storage, max_retained_events):
        self.storage = storage
        self.max_retained_events = max_retained_events


class _Report:
    def __init__(self, status):
        self.status = status

    def to_dict(self):
        return {"status": self.status, "alerts_checked": 2}


class _Reconciler:
    status = "COMPLETE"

    def __init__(self, alert_store, evidence_service):
        self.alert_store = alert_store
        self.evidence_service = evidence_service

    def inspect(self):
        return _Report(type(self).status)



class _RecoveryReport:
    attempted = 1
    completed = 1
    failed = 0
    pending = 0

    def to_dict(self):
        return {
            "attempted": self.attempted,
            "completed": self.completed,
            "failed": self.failed,
            "pending": self.pending,
        }


class _Recovery:
    def __init__(self, alert_store, evidence_service):
        self.alert_store = alert_store
        self.evidence_service = evidence_service

    def recover_pending(self):
        return _RecoveryReport()


def _run(monkeypatch, *argv):
    from argusprowl import __main__ as cli

    monkeypatch.setattr(sys, "argv", ["argusprowl", *argv])
    return cli.main()


def _config():
    return SimpleNamespace(
        storage=SimpleNamespace(backend="sqlite", database_path="/data/events.db"),
        alert_persistence=SimpleNamespace(
            enabled=True, db_path="/data/alerts.db", max_alerts=500
        ),
        telemetry_evidence=SimpleNamespace(enabled=True, max_retained_events=1000),
    )


def _patch_dependencies(monkeypatch):
    from argusprowl import __main__ as cli

    monkeypatch.setattr(cli.ConfigManager, "load", lambda self, path: _config())
    monkeypatch.setattr(cli, "AlertPersistence", _AlertStore)
    monkeypatch.setattr(cli, "SQLiteAdapter", _EvidenceStorage)
    monkeypatch.setattr(cli, "TelemetryEvidenceService", _EvidenceService)
    monkeypatch.setattr(cli, "AlertEvidenceReconciliationService", _Reconciler)
    monkeypatch.setattr(cli, "AlertEvidenceRecoveryService", _Recovery)


def test_reconcile_alert_evidence_reports_json_and_closes_stores(monkeypatch, capsys):
    _patch_dependencies(monkeypatch)
    _Reconciler.status = "COMPLETE"

    assert _run(monkeypatch, "reconcile", "alert-evidence") == ExitCode.SUCCESS

    payload = json.loads(capsys.readouterr().out)
    assert payload == {"status": "COMPLETE", "alerts_checked": 2}
    assert _AlertStore.last_instance.closed is True
    assert _EvidenceStorage.last_instance.closed is True



def test_reconcile_alert_evidence_repair_replays_and_reports(monkeypatch, capsys):
    _patch_dependencies(monkeypatch)
    _Reconciler.status = "COMPLETE"

    assert _run(monkeypatch, "reconcile", "alert-evidence", "--repair") == ExitCode.SUCCESS

    payload = json.loads(capsys.readouterr().out)
    assert payload["recovery"] == {
        "attempted": 1,
        "completed": 1,
        "failed": 0,
        "pending": 0,
    }
    assert payload["reconciliation"]["status"] == "COMPLETE"


def test_reconcile_alert_evidence_returns_nonzero_for_incomplete_report(monkeypatch):
    _patch_dependencies(monkeypatch)
    _Reconciler.status = "INCOMPLETE"

    assert _run(monkeypatch, "reconcile", "alert-evidence") == ExitCode.RUNTIME_ERROR


def test_reconcile_alert_evidence_parser_accepts_config_before_and_after_action():
    from argusprowl.__main__ import create_parser

    parser = create_parser()
    before = parser.parse_args(
        ["--config", "custom.yaml", "reconcile", "alert-evidence"]
    )
    after = parser.parse_args(
        ["reconcile", "--config", "custom.yaml", "alert-evidence"]
    )

    assert before.config == "custom.yaml"
    assert after.config == "custom.yaml"
    repair = parser.parse_args(["reconcile", "alert-evidence", "--repair"])
    assert repair.repair is True
