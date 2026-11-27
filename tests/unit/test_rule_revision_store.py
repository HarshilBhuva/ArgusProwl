"""Tests for immutable detector rule revision history."""

from pathlib import Path

import pytest

from argusprowl.detection.rule_loader import RuleDefinition
from argusprowl.detection.rule_revision_store import RuleRevisionStore
from argusprowl.exceptions.exceptions import DetectionError
from argusprowl.storage.sqlite_storage import SQLiteAdapter


@pytest.fixture
def storage(tmp_path: Path):
    adapter = SQLiteAdapter(tmp_path / "rule-revisions.db")
    yield adapter
    adapter._connection.close()


def make_rule(tmp_path: Path, *, version: int, enabled: bool = True, threshold: int = 10):
    return RuleDefinition(
        rule_id="port_scan",
        detector="PortScanDetector",
        enabled=enabled,
        parameters={"min_unique_ports": threshold},
        path=tmp_path / "port_scan.yaml",
        confidence=0.7,
        version=version,
        tactic="TA0007",
        technique="T1046",
    )


def test_revision_history_is_append_only_and_survives_restart(tmp_path: Path, storage):
    store = RuleRevisionStore(storage)
    first = store.record_revision(
        make_rule(tmp_path, version=1), actor="admin@example.test", change_reason="Initial import"
    )
    second = store.record_revision(
        make_rule(tmp_path, version=2, threshold=15),
        actor="analyst@example.test",
        change_reason="Reduce scan noise",
    )
    database_path = tmp_path / "rule-revisions.db"
    storage._connection.close()

    reopened = SQLiteAdapter(database_path)
    try:
        history = RuleRevisionStore(reopened).history("port_scan")
        assert second.version == 2
        assert second.content_sha256 != first.content_sha256
        assert [item.version for item in history] == [2, 1]
        assert history[1].parameters == {"min_unique_ports": 10}
    finally:
        reopened._connection.close()


def test_same_revision_write_is_idempotent(tmp_path: Path, storage):
    store = RuleRevisionStore(storage)
    rule = make_rule(tmp_path, version=1)
    first = store.record_revision(rule, actor="admin", change_reason="Import")
    repeated = store.record_revision(rule, actor="admin", change_reason="Retry")

    assert repeated.revision_id == first.revision_id
    assert len(store.history("port_scan")) == 1


def test_existing_version_cannot_be_rewritten(tmp_path: Path, storage):
    store = RuleRevisionStore(storage)
    store.record_revision(
        make_rule(tmp_path, version=1), actor="admin", change_reason="Initial import"
    )

    with pytest.raises(DetectionError, match="immutable"):
        store.record_revision(
            make_rule(tmp_path, version=1, threshold=99),
            actor="admin",
            change_reason="Attempt rewrite",
        )


def test_revision_numbers_must_be_contiguous(tmp_path: Path, storage):
    store = RuleRevisionStore(storage)

    with pytest.raises(DetectionError, match="increase by exactly one"):
        store.record_revision(
            make_rule(tmp_path, version=2), actor="admin", change_reason="Skip version"
        )


def test_actor_and_reason_are_required(tmp_path: Path, storage):
    store = RuleRevisionStore(storage)
    with pytest.raises(ValueError, match="actor"):
        store.record_revision(make_rule(tmp_path, version=1), actor=" ", change_reason="Import")
    with pytest.raises(ValueError, match="change reason"):
        store.record_revision(make_rule(tmp_path, version=1), actor="admin", change_reason=" ")


def test_rollback_candidate_creates_new_version_without_mutating_history(tmp_path: Path, storage):
    store = RuleRevisionStore(storage)
    store.record_revision(
        make_rule(tmp_path, version=1, threshold=10), actor="admin", change_reason="Initial"
    )
    store.record_revision(
        make_rule(tmp_path, version=2, threshold=20), actor="admin", change_reason="Tune"
    )

    candidate = store.rollback_candidate("port_scan", 1)

    assert candidate["version"] == 3
    assert candidate["parameters"] == {"min_unique_ports": 10}
    assert candidate["rollback_from_version"] == 1
    assert [item.version for item in store.history("port_scan")] == [2, 1]


def test_non_finite_rule_values_are_rejected(tmp_path: Path, storage):
    rule = make_rule(tmp_path, version=1)
    rule.parameters["threshold"] = float("nan")

    with pytest.raises(DetectionError, match="non-JSON or non-finite"):
        RuleRevisionStore(storage).record_revision(rule, actor="admin", change_reason="Invalid")


def test_sqlite_insert_if_absent_never_replaces_existing_payload(storage):
    from uuid import uuid4

    record_id = uuid4()
    assert storage.save_if_absent("immutable_test", record_id, {"value": "original"}) is True
    assert storage.save_if_absent("immutable_test", record_id, {"value": "replacement"}) is False
    assert storage.load("immutable_test", record_id) == {"value": "original"}
