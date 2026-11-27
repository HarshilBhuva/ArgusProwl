"""Tests for durable alert/evidence recovery replay."""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from argusprowl.constants.severity import Severity
from argusprowl.models.alert import Alert
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.alert_evidence_recovery_service import (
    AlertEvidenceRecoveryService,
)
from argusprowl.services.telemetry_evidence_service import (
    PROVENANCE_CONTRIBUTING_EVENT,
    PROVENANCE_DETECTION_SOURCE,
    PROVENANCE_OBSERVED_CONTEXT,
)


class _AlertStore:
    def __init__(self, payload):
        self.pending = [{
            "alert_id": str(uuid4()),
            "payload": payload,
            "attempts": 0,
            "last_error": None,
        }]
        self.failures = []
        self.completed = []

    def list_pending_evidence_recovery(self, limit=100):
        return tuple(self.pending[:limit])

    def complete_evidence_recovery(self, alert_id):
        self.completed.append(alert_id)
        self.pending = [item for item in self.pending if item["alert_id"] != str(alert_id)]
        return True

    def record_evidence_recovery_failure(self, alert_id, reason):
        self.failures.append((alert_id, reason))
        return True

    def get_evidence_recovery_stats(self):
        return {"pending": len(self.pending)}


class _EvidenceStore:
    def __init__(self):
        self.events = {}
        self.records = {}

    def record_event(self, event, provenance=PROVENANCE_OBSERVED_CONTEXT):
        existing = self.events.get(event.event_id)
        if existing is not None:
            assert existing.to_dict() == event.to_dict()
        self.events[event.event_id] = event
        self.records.setdefault(
            event.event_id,
            SimpleNamespace(provenance=provenance),
        )

    def record_provenance(
        self,
        event_id,
        provenance,
        detection_result_id=None,
        contributing_event_ids=(),
    ):
        current = self.records.get(event_id)
        if provenance == PROVENANCE_DETECTION_SOURCE or (
            current is None or current.provenance == PROVENANCE_OBSERVED_CONTEXT
        ):
            self.records[event_id] = SimpleNamespace(provenance=provenance)

    def get_detail(self, event_id):
        event = self.events.get(event_id)
        record = self.records.get(event_id)
        if event is None:
            return None
        return SimpleNamespace(
            event=event,
            record=record,
            status="AVAILABLE",
        )


def _event(event_id=None):
    return NormalizedEvent(
        source_type="test",
        event_type="network_connection",
        timestamp=datetime.now(UTC),
        event_id=event_id or uuid4(),
    )


def test_build_payload_snapshots_source_and_contributing_events():
    source = _event()
    contributor = _event()
    evidence = _EvidenceStore()
    evidence.record_event(contributor)
    alert = Alert(
        title="Detection",
        description="Matched rule",
        severity=Severity.HIGH,
        source="test",
        detection_source_event_id=source.event_id,
        contributing_event_ids=(contributor.event_id,),
    )
    result = DetectionResult(
        rule_id="test.rule",
        event_id=source.event_id,
        matched=True,
        contributing_event_ids=(contributor.event_id,),
    )

    payload = AlertEvidenceRecoveryService.build_payload(
        alert, source, result, evidence
    )

    assert payload is not None
    assert len(payload["expected"]) == 2
    assert len(payload["events"]) == 2
    assert {
        item["provenance"] for item in payload["expected"]
    } == {PROVENANCE_DETECTION_SOURCE, PROVENANCE_CONTRIBUTING_EVENT}


def test_replay_restores_source_and_contributor_then_completes_outbox():
    source = _event()
    contributor = _event()
    evidence = _EvidenceStore()
    evidence.record_event(contributor)
    alert = Alert(
        title="Detection",
        description="Matched rule",
        severity=Severity.HIGH,
        source="test",
        detection_source_event_id=source.event_id,
        contributing_event_ids=(contributor.event_id,),
    )
    result = DetectionResult(
        rule_id="test.rule",
        event_id=source.event_id,
        matched=True,
        contributing_event_ids=(contributor.event_id,),
    )
    payload = AlertEvidenceRecoveryService.build_payload(
        alert, source, result, evidence
    )
    store = _AlertStore(payload)
    service = AlertEvidenceRecoveryService(store, evidence)

    report = service.recover_pending()

    assert report.to_dict() == {
        "attempted": 1,
        "completed": 1,
        "failed": 0,
        "pending": 0,
    }
    assert evidence.get_detail(source.event_id).record.provenance == PROVENANCE_DETECTION_SOURCE
    assert evidence.get_detail(contributor.event_id).record.provenance == PROVENANCE_CONTRIBUTING_EVENT
    assert len(store.completed) == 1


def test_replay_keeps_outbox_when_expected_event_is_unavailable():
    source = _event()
    missing = uuid4()
    result = DetectionResult(
        rule_id="test.rule",
        event_id=source.event_id,
        matched=True,
    )
    payload = {
        "schema_version": 1,
        "detection_result_id": str(result.result_id),
        "contributing_event_ids": [],
        "expected": [
            {"event_id": str(source.event_id), "provenance": PROVENANCE_DETECTION_SOURCE},
            {"event_id": str(missing), "provenance": PROVENANCE_CONTRIBUTING_EVENT},
        ],
        "events": [{"event": source.to_dict()}],
    }
    store = _AlertStore(payload)
    evidence = _EvidenceStore()
    service = AlertEvidenceRecoveryService(store, evidence)

    report = service.recover_pending()

    assert report.failed == 1
    assert report.pending == 1
    assert store.completed == []
    assert len(store.failures) == 1
