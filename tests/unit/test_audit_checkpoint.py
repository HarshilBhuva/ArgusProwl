"""Tests for independently retained, HMAC-authenticated audit checkpoints."""

from __future__ import annotations

import json
import sqlite3

import pytest

from argusprowl.api.audit import AuditLog
from argusprowl.api.audit_checkpoint import AuditCheckpointError, AuditCheckpointManager

_KEY = "test-checkpoint-signing-key-with-32-bytes-minimum"


def _append(audit: AuditLog, request_id: str) -> int:
    return audit.append(
        event_type="REQUEST_COMPLETED",
        actor_id="operator",
        role="admin",
        method="GET",
        path="/api/v1/alerts",
        status_code=200,
        request_id=request_id,
        client_ip="127.0.0.1",
    )


def test_checkpoint_authenticates_chain_and_allows_later_appends(tmp_path):
    database = tmp_path / "audit.db"
    checkpoint = tmp_path / "audit.checkpoint.json"
    audit = AuditLog(str(database))
    _append(audit, "request-1")
    manager = AuditCheckpointManager(_KEY)

    payload = manager.create_checkpoint(database, checkpoint)
    assert payload["event_count"] == 1
    assert payload["last_event_id"] == 1

    _append(audit, "request-2")
    result = manager.verify_checkpoint(database, checkpoint)
    assert result["valid"] is True
    assert result["checkpoint_event_count"] == 1
    assert result["current_event_count"] == 2


def test_checkpoint_detects_database_rewrite_before_anchor(tmp_path):
    database = tmp_path / "audit.db"
    checkpoint = tmp_path / "audit.checkpoint.json"
    audit = AuditLog(str(database))
    first_id = _append(audit, "request-1")
    _append(audit, "request-2")
    manager = AuditCheckpointManager(_KEY)
    manager.create_checkpoint(database, checkpoint)

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE api_audit_events SET path = ? WHERE id = ?",
            ("/api/v1/forged", first_id),
        )

    with pytest.raises(AuditCheckpointError, match="integrity failure"):
        manager.verify_checkpoint(database, checkpoint)


def test_checkpoint_rejects_modified_payload_or_signature(tmp_path):
    database = tmp_path / "audit.db"
    checkpoint = tmp_path / "audit.checkpoint.json"
    AuditLog(str(database))
    manager = AuditCheckpointManager(_KEY)
    manager.create_checkpoint(database, checkpoint)

    document = json.loads(checkpoint.read_text(encoding="utf-8"))
    document["payload"]["event_count"] = 1
    checkpoint.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AuditCheckpointError, match="authentication failed"):
        manager.verify_checkpoint(database, checkpoint)


def test_checkpoint_refuses_to_overwrite_existing_file(tmp_path):
    database = tmp_path / "audit.db"
    checkpoint = tmp_path / "audit.checkpoint.json"
    AuditLog(str(database))
    manager = AuditCheckpointManager(_KEY)
    manager.create_checkpoint(database, checkpoint)

    with pytest.raises(AuditCheckpointError, match="refusing overwrite"):
        manager.create_checkpoint(database, checkpoint)


def test_checkpoint_requires_strong_signing_key():
    with pytest.raises(AuditCheckpointError, match="at least 32 bytes"):
        AuditCheckpointManager("too-short")


def test_checkpoint_creation_refuses_an_already_corrupt_chain(tmp_path):
    database = tmp_path / "audit.db"
    checkpoint = tmp_path / "audit.checkpoint.json"
    audit = AuditLog(str(database))
    event_id = _append(audit, "request-1")
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE api_audit_events SET path = ? WHERE id = ?",
            ("/tampered", event_id),
        )

    with pytest.raises(AuditCheckpointError, match="integrity failure"):
        AuditCheckpointManager(_KEY).create_checkpoint(database, checkpoint)
    assert not checkpoint.exists()
