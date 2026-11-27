"""Tests for read-only alert/evidence reconciliation diagnostics."""

from types import SimpleNamespace
from uuid import uuid4

from argusprowl.services.alert_evidence_reconciliation import (
    AlertEvidenceReconciliationService,
)
from argusprowl.services.telemetry_evidence_service import (
    PROVENANCE_CONTRIBUTING_EVENT,
    PROVENANCE_DETECTION_SOURCE,
)


class _AlertStore:
    def __init__(self, alerts, status="AVAILABLE", reason=None):
        self.result = SimpleNamespace(alerts=tuple(alerts), status=status, reason=reason)

    def list_all(self):
        return self.result


class _EvidenceStore:
    def __init__(self, details):
        self.details = details

    def get_detail(self, event_id):
        value = self.details.get(event_id)
        if isinstance(value, Exception):
            raise value
        return value


def _alert(source=None, contributors=()):
    return SimpleNamespace(
        alert_id=uuid4(),
        detection_source_event_id=source,
        contributing_event_ids=tuple(contributors),
    )


def _detail(event_id, provenance, status="AVAILABLE", *, event=True, record=True):
    return SimpleNamespace(
        event_id=event_id,
        status=status,
        event=object() if event else None,
        record=SimpleNamespace(provenance=provenance) if record else None,
    )


def test_reconciliation_reports_complete_source_and_contributing_events():
    source, contributor = uuid4(), uuid4()
    alert = _alert(source, (contributor,))
    service = AlertEvidenceReconciliationService(
        _AlertStore([alert]),
        _EvidenceStore(
            {
                source: _detail(source, PROVENANCE_DETECTION_SOURCE),
                contributor: _detail(contributor, PROVENANCE_CONTRIBUTING_EVENT),
            }
        ),
    )

    report = service.inspect()

    assert report.status == "COMPLETE"
    assert report.alerts_checked == 1
    assert report.complete == 1
    assert report.findings[0].referenced_events == 2


def test_reconciliation_identifies_missing_evidence_reference():
    source = uuid4()
    alert = _alert(source)
    service = AlertEvidenceReconciliationService(_AlertStore([alert]), _EvidenceStore({}))

    report = service.inspect()

    assert report.status == "INCOMPLETE"
    assert report.incomplete == 1
    assert report.findings[0].missing_event_ids == (source,)


def test_reconciliation_identifies_provenance_mismatch():
    source = uuid4()
    alert = _alert(source)
    service = AlertEvidenceReconciliationService(
        _AlertStore([alert]),
        _EvidenceStore({source: _detail(source, PROVENANCE_CONTRIBUTING_EVENT)}),
    )

    report = service.inspect()

    assert report.status == "INCOMPLETE"
    assert report.findings[0].provenance_mismatch_event_ids == (source,)


def test_reconciliation_surfaces_unavailable_evidence_store():
    source = uuid4()
    alert = _alert(source)
    service = AlertEvidenceReconciliationService(
        _AlertStore([alert]),
        _EvidenceStore(
            {
                source: _detail(
                    source,
                    PROVENANCE_DETECTION_SOURCE,
                    "UNAVAILABLE",
                    event=False,
                    record=False,
                )
            }
        ),
    )

    report = service.inspect()

    assert report.status == "UNAVAILABLE"
    assert report.findings[0].unavailable_event_ids == (source,)


def test_reconciliation_counts_alerts_without_evidence_references():
    alert = _alert()
    service = AlertEvidenceReconciliationService(_AlertStore([alert]), _EvidenceStore({}))

    report = service.inspect()

    assert report.status == "COMPLETE"
    assert report.no_evidence_references == 1
    assert report.findings[0].status == "NO_EVIDENCE_REFERENCES"


def test_reconciliation_fails_closed_when_alert_store_is_unavailable():
    service = AlertEvidenceReconciliationService(
        _AlertStore([], status="UNAVAILABLE", reason="database unavailable"),
        _EvidenceStore({}),
    )

    report = service.inspect()

    assert report.status == "UNAVAILABLE"
    assert report.alerts_checked == 0
    assert report.reason == "database unavailable"
