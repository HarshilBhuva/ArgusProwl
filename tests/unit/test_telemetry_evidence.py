"""Tests for TelemetryEvidenceService (Phase 7.8)."""

import uuid
from datetime import UTC, datetime

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.services.telemetry_evidence_service import (
    PROVENANCE_CONTRIBUTING_EVENT,
    PROVENANCE_DETECTION_SOURCE,
    PROVENANCE_OBSERVED_CONTEXT,
    TelemetryEvidenceService,
)


@pytest.fixture
def service() -> TelemetryEvidenceService:
    return TelemetryEvidenceService(max_retained_events=5)


def _make_event(
    event_id: uuid.UUID | None = None,
    timestamp: datetime | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    hostname: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id or uuid.uuid4(),
        timestamp=timestamp or datetime.now(UTC),
        source_type="test-source",
        event_type="test-event",
        src_ip=src_ip,
        dst_ip=dst_ip,
        hostname=hostname,
    )


class TestTelemetryEvidenceService:
    def test_record_event_inserts(self, service: TelemetryEvidenceService) -> None:
        ev = _make_event()
        rec = service.record_event(ev, PROVENANCE_OBSERVED_CONTEXT)
        assert rec.event_id == ev.event_id
        assert rec.provenance == PROVENANCE_OBSERVED_CONTEXT

        # Check retrieval
        pair = service.get_event(ev.event_id)
        assert pair is not None
        fetched_ev, fetched_rec = pair
        assert fetched_ev == ev
        assert fetched_rec == rec

    def test_record_event_overrides_provenance(self, service: TelemetryEvidenceService) -> None:
        ev = _make_event()
        service.record_event(ev, PROVENANCE_OBSERVED_CONTEXT)
        # Upgrade to DIFFERENT provenance by re-recording event
        rec2 = service.record_event(ev, PROVENANCE_DETECTION_SOURCE)
        assert rec2.provenance == PROVENANCE_DETECTION_SOURCE

        # Cannot downgrade from DETECTION_SOURCE
        rec3 = service.record_event(ev, PROVENANCE_OBSERVED_CONTEXT)
        assert rec3.provenance == PROVENANCE_DETECTION_SOURCE

    def test_record_provenance_updates(self, service: TelemetryEvidenceService) -> None:
        ev = _make_event()
        service.record_event(ev, PROVENANCE_OBSERVED_CONTEXT)

        # Update via record_provenance
        det_id = uuid.uuid4()
        rec = service.record_provenance(
            ev.event_id,
            PROVENANCE_CONTRIBUTING_EVENT,
            detection_result_id=det_id,
        )
        assert rec.provenance == PROVENANCE_CONTRIBUTING_EVENT
        assert rec.detection_result_id == det_id

        # Upgrade again to DETECTION_SOURCE
        rec2 = service.record_provenance(ev.event_id, PROVENANCE_DETECTION_SOURCE)
        assert rec2.provenance == PROVENANCE_DETECTION_SOURCE

    def test_eviction(self, service: TelemetryEvidenceService) -> None:
        # Max is 5
        events = [_make_event() for _ in range(6)]
        for ev in events:
            service.record_event(ev)

        assert service.get_event(events[0].event_id) is None  # old evicted
        assert service.get_event(events[1].event_id) is not None
        assert service.get_event(events[-1].event_id) is not None

        stats = service.get_stats()
        assert stats["eviction_count"] == 1
        assert stats["retained_events"] == 5

    def test_search_filters(self, service: TelemetryEvidenceService) -> None:
        ev1 = _make_event(src_ip="1.2.3.4", dst_ip="8.8.8.8", hostname="alpha")
        ev2 = _make_event(src_ip="5.6.7.8", dst_ip="1.2.3.4", hostname="beta")
        service.record_event(ev1)
        service.record_event(ev2)

        # Search by src_ip
        res = service.search(src_ip="1.2.3.4")
        assert res.total_count == 1
        assert res.records[0].event_id == ev1.event_id

        # Search by entity (IP matches src or dst)
        res = service.search(entity_type="ip", entity_id="1.2.3.4")
        assert res.total_count == 2

        # Search by exact event_id
        res = service.search(event_id=ev2.event_id)
        assert res.total_count == 1
        assert res.records[0].event_id == ev2.event_id

        # Search domain "alpha"
        res = service.search(domain="alpha")
        assert res.total_count == 1
        assert res.records[0].event_id == ev1.event_id

    def test_search_limits(self, service: TelemetryEvidenceService) -> None:
        for _ in range(4):
            service.record_event(_make_event())

        res = service.search(limit=2)
        assert res.total_count == 4
        assert res.returned_count == 2
        assert res.truncated is True
        assert len(res.records) == 2

    def test_contributing_event_provenance(self, service: TelemetryEvidenceService) -> None:
        """Retained contributing event is marked CONTRIBUTING_EVENT."""
        primary = _make_event(event_id=uuid.uuid4())
        contrib = _make_event(event_id=uuid.uuid4())
        service.record_event(primary, PROVENANCE_DETECTION_SOURCE)
        service.record_event(contrib, PROVENANCE_OBSERVED_CONTEXT)

        det_id = uuid.uuid4()
        rec = service.record_provenance(
            contrib.event_id,
            PROVENANCE_CONTRIBUTING_EVENT,
            detection_result_id=det_id,
        )
        assert rec.provenance == PROVENANCE_CONTRIBUTING_EVENT
        assert rec.detection_result_id == det_id

    def test_unknown_event_provenance_is_not_treated_as_evicted(
        self, service: TelemetryEvidenceService
    ) -> None:
        """An event never retained remains unknown rather than evicted."""
        with pytest.raises(ValueError, match="not found in evidence store"):
            service.record_provenance(
                uuid.uuid4(),
                PROVENANCE_CONTRIBUTING_EVENT,
            )

    def test_evicted_contributing_event_has_explicit_detail_state(
        self, service: TelemetryEvidenceService
    ) -> None:
        """Evicted contributing telemetry preserves its ID and provenance only."""
        contributing = _make_event(event_id=uuid.uuid4())
        service.record_event(contributing)
        service.record_provenance(
            contributing.event_id,
            PROVENANCE_CONTRIBUTING_EVENT,
            detection_result_id=uuid.uuid4(),
        )

        for _ in range(5):
            service.record_event(_make_event())

        detail = service.get_detail(contributing.event_id)
        assert detail is not None
        assert detail.event_id == contributing.event_id
        assert detail.status == "EVICTED"
        assert detail.event is None
        assert detail.record is not None
        assert detail.record.provenance == PROVENANCE_CONTRIBUTING_EVENT
        assert service.get_event(contributing.event_id) is None

    def test_unknown_event_has_no_detail_state(self, service: TelemetryEvidenceService) -> None:
        assert service.get_detail(uuid.uuid4()) is None

    def test_multiple_contributing_events(self, service: TelemetryEvidenceService) -> None:
        """Multiple contributing events are all marked CONTRIBUTING_EVENT."""
        primary = _make_event(event_id=uuid.uuid4())
        contrib1 = _make_event(event_id=uuid.uuid4())
        contrib2 = _make_event(event_id=uuid.uuid4())
        service.record_event(primary, PROVENANCE_DETECTION_SOURCE)
        service.record_event(contrib1, PROVENANCE_OBSERVED_CONTEXT)
        service.record_event(contrib2, PROVENANCE_OBSERVED_CONTEXT)

        det_id = uuid.uuid4()
        service.record_provenance(
            contrib1.event_id,
            PROVENANCE_CONTRIBUTING_EVENT,
            detection_result_id=det_id,
        )
        service.record_provenance(
            contrib2.event_id,
            PROVENANCE_CONTRIBUTING_EVENT,
            detection_result_id=det_id,
        )

        res = service.search()
        provenances = {r.event_id: r.provenance for r in res.records}
        assert provenances[primary.event_id] == PROVENANCE_DETECTION_SOURCE
        assert provenances[contrib1.event_id] == PROVENANCE_CONTRIBUTING_EVENT
        assert provenances[contrib2.event_id] == PROVENANCE_CONTRIBUTING_EVENT

    def test_provenance_upgrade(self, service: TelemetryEvidenceService) -> None:
        """Provenance can be upgraded: OBSERVED_CONTEXT -> CONTRIBUTING_EVENT -> DETECTION_SOURCE."""
        ev = _make_event()
        service.record_event(ev, PROVENANCE_OBSERVED_CONTEXT)

        rec1 = service.record_provenance(ev.event_id, PROVENANCE_CONTRIBUTING_EVENT)
        assert rec1.provenance == PROVENANCE_CONTRIBUTING_EVENT

        rec2 = service.record_provenance(ev.event_id, PROVENANCE_DETECTION_SOURCE)
        assert rec2.provenance == PROVENANCE_DETECTION_SOURCE

    def test_provenance_downgrade_blocked(self, service: TelemetryEvidenceService) -> None:
        """Provenance cannot be downgraded from DETECTION_SOURCE."""
        ev = _make_event()
        service.record_event(ev, PROVENANCE_DETECTION_SOURCE)

        rec = service.record_provenance(ev.event_id, PROVENANCE_CONTRIBUTING_EVENT)
        assert rec.provenance == PROVENANCE_DETECTION_SOURCE

        rec2 = service.record_provenance(ev.event_id, PROVENANCE_OBSERVED_CONTEXT)
        assert rec2.provenance == PROVENANCE_DETECTION_SOURCE

    def test_exact_primary_event_provenance(self, service: TelemetryEvidenceService) -> None:
        """Primary event is exactly DETECTION_SOURCE."""
        ev = _make_event()
        service.record_event(ev, PROVENANCE_DETECTION_SOURCE)

        rec = service.get_event(ev.event_id)
        assert rec is not None
        _, record = rec
        assert record.provenance == PROVENANCE_DETECTION_SOURCE

    def test_resolve_referenced_status_retained_event(
        self, service: TelemetryEvidenceService
    ) -> None:
        """Retained contributing event resolves to AVAILABLE."""
        event = _make_event(event_id=uuid.uuid4())
        service.record_event(event, PROVENANCE_OBSERVED_CONTEXT)
        service.record_provenance(event.event_id, PROVENANCE_CONTRIBUTING_EVENT)

        status = service.resolve_referenced_status((event.event_id,))
        assert status[event.event_id] == "AVAILABLE"

    def test_resolve_referenced_status_evicted_event(
        self, service: TelemetryEvidenceService
    ) -> None:
        """Evicted contributing event resolves to EVICTED."""
        event = _make_event(event_id=uuid.uuid4())
        service.record_event(event, PROVENANCE_OBSERVED_CONTEXT)
        service.record_provenance(event.event_id, PROVENANCE_CONTRIBUTING_EVENT)

        # Evict the event
        for _ in range(5):
            service.record_event(_make_event())

        status = service.resolve_referenced_status((event.event_id,))
        assert status[event.event_id] == "EVICTED"

    def test_resolve_referenced_status_preserves_original_id(
        self, service: TelemetryEvidenceService
    ) -> None:
        """Original event ID remains preserved in status mapping."""
        event = _make_event(event_id=uuid.uuid4())
        service.record_event(event, PROVENANCE_OBSERVED_CONTEXT)
        service.record_provenance(event.event_id, PROVENANCE_CONTRIBUTING_EVENT)

        # Evict
        for _ in range(5):
            service.record_event(_make_event())

        status = service.resolve_referenced_status((event.event_id,))
        assert event.event_id in status
        assert status[event.event_id] == "EVICTED"

    def test_resolve_referenced_status_multiple_events(
        self, service: TelemetryEvidenceService
    ) -> None:
        """Multiple events: retained is AVAILABLE, evicted is EVICTED."""
        evicted = _make_event(event_id=uuid.uuid4())
        retained = _make_event(event_id=uuid.uuid4())
        service.record_event(evicted, PROVENANCE_OBSERVED_CONTEXT)
        service.record_event(retained, PROVENANCE_OBSERVED_CONTEXT)
        service.record_provenance(evicted.event_id, PROVENANCE_CONTRIBUTING_EVENT)
        service.record_provenance(retained.event_id, PROVENANCE_CONTRIBUTING_EVENT)

        # Evict the first event while retaining the second.
        for _ in range(4):
            service.record_event(_make_event())

        status = service.resolve_referenced_status((retained.event_id, evicted.event_id))
        assert status[retained.event_id] == "AVAILABLE"
        assert status[evicted.event_id] == "EVICTED"

    def test_resolve_referenced_status_empty_tuple(self, service: TelemetryEvidenceService) -> None:
        """Empty tuple returns empty dict."""
        status = service.resolve_referenced_status(())
        assert status == {}

    def test_evicted_detection_source_event(self, service: TelemetryEvidenceService) -> None:
        """Detection source events are also tracked as evicted."""
        event = _make_event(event_id=uuid.uuid4())
        service.record_event(event, PROVENANCE_DETECTION_SOURCE)

        # Evict
        for _ in range(5):
            service.record_event(_make_event())

        detail = service.get_detail(event.event_id)
        assert detail is not None
        assert detail.status == "EVICTED"
        assert detail.record is not None
        assert detail.record.provenance == PROVENANCE_DETECTION_SOURCE

    def test_evidence_eviction_does_not_change_alert_synthesis(
        self, service: TelemetryEvidenceService
    ) -> None:
        """Evidence availability remains observational and decision-neutral."""
        contributing_event_id = uuid.uuid4()
        contributing_event = _make_event(event_id=contributing_event_id)
        service.record_event(contributing_event, PROVENANCE_OBSERVED_CONTEXT)
        service.record_provenance(contributing_event_id, PROVENANCE_CONTRIBUTING_EVENT)
        for _ in range(5):
            service.record_event(_make_event())

        result = DetectionResult(
            rule_id="phase78-test",
            event_id=uuid.uuid4(),
            matched=True,
            severity=Severity.HIGH,
            confidence=0.8,
            description="Detection behavior must remain unchanged.",
            contributing_event_ids=(contributing_event_id,),
        )
        alert = DecisionEngine().process_detection_result(result)

        assert alert is not None
        assert alert.severity == Severity.HIGH
        assert alert.contributing_event_ids == (contributing_event_id,)
        assert service.resolve_referenced_status((contributing_event_id,)) == {
            contributing_event_id: "EVICTED"
        }
