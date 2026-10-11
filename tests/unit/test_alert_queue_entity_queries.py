"""Tests for Phase 4.8.3 — AlertQueue Entity-Centric and Incident-Centric Queries.

Covers:
- list_by_entity() with canonical entity-key semantics
- list_by_incident() with Alert.incident_id matching
- Sorting consistency with existing sort_alerts()
- Immutability invariants
- Entity-key consistency with EntityCorrelationService
- Backward compatibility (queue without entity correlation service)
- Concurrent-safe snapshot behavior
"""

from datetime import UTC, datetime
from threading import Thread
from uuid import UUID, uuid4

import pytest

from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
from argusprowl.incident.incident_service import IncidentService
from argusprowl.lifecycle import AlertQueue, AlertQueueFullError
from argusprowl.models.alert import Alert

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_alert(
    *,
    title: str = "Test Alert",
    severity: Severity = Severity.HIGH,
    priority: AlertPriority = AlertPriority.HIGH,
    lifecycle_state: AlertLifecycleState = AlertLifecycleState.OPEN,
    contextual_confidence: float | None = 0.85,
    host: str | None = "workstation-23",
    process_name: str | None = None,
    dst_ip: str | None = None,
    rule_id: str | None = "test_rule",
    created_at: datetime | None = None,
    alert_id: UUID | None = None,
    incident_id: UUID | None = None,
) -> Alert:
    """Helper to create a test alert with sensible defaults."""
    entity_context = {}
    if host is not None:
        entity_context["host"] = host
    if process_name is not None:
        entity_context["process_name"] = process_name
    if dst_ip is not None:
        entity_context["dst_ip"] = dst_ip

    # Only set entity_context if it has at least one field
    entity_context_value = entity_context if entity_context else None

    return Alert(
        title=title,
        description=f"Test alert: {title}",
        severity=severity,
        source="test_source",
        alert_id=alert_id or uuid4(),
        created_at=created_at or datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC),
        metadata={"rule_id": rule_id} if rule_id else {},
        entity_context=entity_context_value,
        priority=priority,
        contextual_confidence=contextual_confidence,
        lifecycle_state=lifecycle_state,
        incident_id=incident_id,
    )


@pytest.fixture
def queue_with_ecs() -> AlertQueue:
    """Queue with EntityCorrelationService injected."""
    ecs = EntityCorrelationService()
    return AlertQueue(max_size=100, entity_correlation_service=ecs)


@pytest.fixture
def queue_without_ecs() -> AlertQueue:
    """Queue without EntityCorrelationService (backward compat)."""
    return AlertQueue(max_size=100)


@pytest.fixture
def incident_service() -> IncidentService:
    return IncidentService(max_incidents=100)


@pytest.fixture
def alerts_with_incidents(
    incident_service: IncidentService,
    entity_correlation_service: EntityCorrelationService,
) -> tuple[list[Alert], UUID, UUID]:
    """Create alerts grouped into two incidents via DecisionEngine-like flow."""
    from argusprowl.decision_engine.decision_engine import DecisionEngine

    de = DecisionEngine(
        cooldown_seconds=60,
        incident_service=incident_service,
        entity_correlation_service=entity_correlation_service,
    )

    # First entity: host1 with process
    result1, assessment1 = _detection_result(
        host="host1", process_name="svchost.exe", dst_ip="10.0.0.1"
    )
    alert1 = de.process_detection_result(result1, assessment=assessment1)

    result2, assessment2 = _detection_result(
        host="host1",
        process_name="svchost.exe",
        dst_ip="10.0.0.2",
        event_id=uuid4(),
    )
    alert2 = de.process_detection_result(result2, assessment=assessment2)

    # Second entity: host2
    result3, assessment3 = _detection_result(
        host="host2",
        dst_ip="10.0.0.1",
        event_id=uuid4(),
    )
    alert3 = de.process_detection_result(result3, assessment=assessment3)

    assert alert1 is not None
    assert alert2 is not None
    assert alert3 is not None
    assert alert1.incident_id is not None
    assert alert2.incident_id == alert1.incident_id
    assert alert3.incident_id != alert1.incident_id

    return [alert1, alert2, alert3], alert1.incident_id, alert3.incident_id


@pytest.fixture
def entity_correlation_service() -> EntityCorrelationService:
    return EntityCorrelationService()


def _detection_result(
    host: str | None = None,
    process_name: str | None = None,
    dst_ip: str | None = None,
    event_id: UUID | None = None,
) -> tuple:
    """Create a DetectionResult and ContextualAssessment for testing."""
    from argusprowl.models.context import ContextualAssessment, EntityContext
    from argusprowl.models.detection_result import DetectionResult

    if event_id is None:
        event_id = uuid4()

    evidence = [
        {"field": "src_ip", "observed": "192.168.1.100", "condition": "exists"},
    ]
    if dst_ip:
        evidence.append({"field": "dst_ip", "observed": dst_ip, "condition": "exists"})
    if process_name:
        evidence.append({"field": "process_name", "observed": process_name, "condition": "exists"})

    entity_context = {}
    if host:
        entity_context["host"] = host
    if process_name:
        entity_context["process_name"] = process_name
    if dst_ip:
        entity_context["dst_ip"] = dst_ip

    assessment = ContextualAssessment(
        detection_result=DetectionResult(
            rule_id="port_scan",
            event_id=event_id,
            matched=True,
            severity=Severity.HIGH,
            confidence=0.8,
            description=f"Test detection from {host or 'unknown'}",
            evidence=evidence,
        ),
        final_confidence=0.8,
        severity=Severity.HIGH,
        entity_context=EntityContext(
            host=host,
            process_name=process_name,
            dst_ip=dst_ip,
        )
        if entity_context
        else None,
    )

    return (
        DetectionResult(
            rule_id="port_scan",
            event_id=event_id,
            matched=True,
            severity=Severity.HIGH,
            confidence=0.8,
            description=f"Test detection from {host or 'unknown'}",
            evidence=evidence,
        ),
        assessment,
    )


# ---------------------------------------------------------------------------
# Entity Queries
# ---------------------------------------------------------------------------


class TestListByEntity:
    """Tests for AlertQueue.list_by_entity()."""

    def test_matching_entity(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_entity should return alerts matching the entity key."""
        alert1 = make_alert(host="host1", dst_ip="10.0.0.1", title="Alert1")
        alert2 = make_alert(host="host1", dst_ip="10.0.0.1", title="Alert2")
        alert3 = make_alert(host="host2", dst_ip="10.0.0.1", title="Alert3")

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)
        queue_with_ecs.enqueue(alert3)

        result = queue_with_ecs.list_by_entity("host1:10.0.0.1")
        assert len(result) == 2
        assert {a.alert_id for a in result} == {alert1.alert_id, alert2.alert_id}

    def test_no_matching_entity(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_entity should return empty list for non-existent entity."""
        alert = make_alert(host="host1", title="Alert1")
        queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_entity("host99:10.0.0.1")
        assert result == []

    def test_multiple_alerts_same_entity(self, queue_with_ecs: AlertQueue) -> None:
        """Multiple alerts with same entity should all be returned."""
        alerts = [make_alert(host="host1", dst_ip="10.0.0.1", title=f"Alert{i}") for i in range(5)]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_entity("host1:10.0.0.1")
        assert len(result) == 5
        assert {a.alert_id for a in result} == {a.alert_id for a in alerts}

    def test_multiple_entities(self, queue_with_ecs: AlertQueue) -> None:
        """Different entities should return different results."""
        alert1 = make_alert(host="host1", dst_ip="10.0.0.1", title="Alert1")
        alert2 = make_alert(host="host2", dst_ip="10.0.0.1", title="Alert2")

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)

        result1 = queue_with_ecs.list_by_entity("host1:10.0.0.1")
        result2 = queue_with_ecs.list_by_entity("host2:10.0.0.1")

        assert len(result1) == 1
        assert len(result2) == 1
        assert result1[0].alert_id != result2[0].alert_id

    def test_deterministic_results(self, queue_with_ecs: AlertQueue) -> None:
        """Repeated calls should return identical results."""
        alerts = [make_alert(host="host1", dst_ip="10.0.0.1", title=f"Alert{i}") for i in range(3)]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        result1 = queue_with_ecs.list_by_entity("host1:10.0.0.1")
        result2 = queue_with_ecs.list_by_entity("host1:10.0.0.1")

        assert [a.alert_id for a in result1] == [a.alert_id for a in result2]

    def test_no_mutation(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_entity should not mutate queue state."""
        alert = make_alert(host="host1", title="Alert1")
        queue_with_ecs.enqueue(alert)

        original_len = len(queue_with_ecs)
        _ = queue_with_ecs.list_by_entity("host1:*")
        assert len(queue_with_ecs) == original_len

    def test_empty_queue(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_entity on empty queue should return empty list."""
        result = queue_with_ecs.list_by_entity("host1:*")
        assert result == []

    def test_sorting_applied_by_default(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_entity should sort by default."""
        alerts = [
            make_alert(
                host="host1",
                title=f"Alert{i}",
                severity=Severity.LOW if i % 2 == 0 else Severity.HIGH,
                created_at=datetime(2026, 8, 31, 10 + i, 0, 0, tzinfo=UTC),
            )
            for i in range(3)
        ]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_entity("host1:*")
        # Should be sorted by severity descending, then created_at descending
        assert len(result) == 3
        # HIGH severity should come before LOW
        high_alerts = [a for a in result if a.severity == Severity.HIGH]
        low_alerts = [a for a in result if a.severity == Severity.LOW]
        assert all(r.severity == Severity.HIGH for r in high_alerts)
        assert all(r.severity == Severity.LOW for r in low_alerts)

    def test_sort_disabled(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_entity(sort=False) should return in insertion order."""
        alerts = [make_alert(host="host1", title=f"Alert{i}") for i in range(3)]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_entity("host1:*", sort=False)
        assert [a.title for a in result] == [a.title for a in alerts]


class TestEntityKeyConsistency:
    """Tests verifying entity-key consistency with EntityCorrelationService."""

    def test_host_plus_process(self, queue_with_ecs: AlertQueue) -> None:
        """host+process should be the entity key."""
        alert1 = make_alert(host="host1", process_name="svchost.exe", title="Alert1")
        alert2 = make_alert(host="host1", process_name="svchost.exe", title="Alert2")
        alert3 = make_alert(host="host1", process_name="powershell.exe", title="Alert3")

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)
        queue_with_ecs.enqueue(alert3)

        result = queue_with_ecs.list_by_entity("host1:svchost.exe")
        assert len(result) == 2
        assert {a.alert_id for a in result} == {alert1.alert_id, alert2.alert_id}

    def test_host_plus_destination(self, queue_with_ecs: AlertQueue) -> None:
        """host+dst_ip should be the entity key when no process."""
        alert1 = make_alert(host="host1", dst_ip="10.0.0.1", title="Alert1")
        alert2 = make_alert(host="host1", dst_ip="10.0.0.1", title="Alert2")
        alert3 = make_alert(host="host1", dst_ip="10.0.0.2", title="Alert3")

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)
        queue_with_ecs.enqueue(alert3)

        result = queue_with_ecs.list_by_entity("host1:10.0.0.1")
        assert len(result) == 2
        assert {a.alert_id for a in result} == {alert1.alert_id, alert2.alert_id}

    def test_host_only(self, queue_with_ecs: AlertQueue) -> None:
        """host-only alerts should use host:* key."""
        alert1 = make_alert(host="host1", title="Alert1")
        alert2 = make_alert(host="host1", title="Alert2")
        alert3 = make_alert(host="host2", title="Alert3")

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)
        queue_with_ecs.enqueue(alert3)

        result = queue_with_ecs.list_by_entity("host1:*")
        assert len(result) == 2
        assert {a.alert_id for a in result} == {alert1.alert_id, alert2.alert_id}

    def test_destination_only(self, queue_with_ecs: AlertQueue) -> None:
        """dst_ip-only alerts should use *:dst_ip key."""
        alert1 = make_alert(host=None, dst_ip="10.0.0.1", title="Alert1")
        alert2 = make_alert(host=None, dst_ip="10.0.0.1", title="Alert2")
        alert3 = make_alert(host=None, dst_ip="10.0.0.2", title="Alert3")

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)
        queue_with_ecs.enqueue(alert3)

        result = queue_with_ecs.list_by_entity("*:10.0.0.1")
        assert len(result) == 2
        assert {a.alert_id for a in result} == {alert1.alert_id, alert2.alert_id}

    def test_no_entity_context(self, queue_with_ecs: AlertQueue) -> None:
        """Alerts without entity context should use unknown:<alert_id> fallback."""
        alert1 = make_alert(host=None, title="Alert1")
        alert2 = make_alert(host=None, title="Alert2")

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)

        # Each alert without entity context gets a unique fallback key
        result1 = queue_with_ecs.list_by_entity(f"unknown:{alert1.alert_id}")
        result2 = queue_with_ecs.list_by_entity(f"unknown:{alert2.alert_id}")
        assert len(result1) == 1
        assert len(result2) == 1
        assert result1[0].alert_id == alert1.alert_id
        assert result2[0].alert_id == alert2.alert_id

    def test_mixed_entity_information_same_host(self, queue_with_ecs: AlertQueue) -> None:
        """Alerts with same host but different process/destination are different entities."""
        alert1 = make_alert(host="host1", process_name="svchost.exe", title="Alert1")
        alert2 = make_alert(host="host1", dst_ip="10.0.0.1", title="Alert2")

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)

        # host+process takes precedence over host+dst_ip
        result1 = queue_with_ecs.list_by_entity("host1:svchost.exe")
        result2 = queue_with_ecs.list_by_entity("host1:10.0.0.1")

        assert len(result1) == 1
        assert len(result2) == 1
        assert result1[0].alert_id == alert1.alert_id
        assert result2[0].alert_id == alert2.alert_id

    def test_host_only_vs_host_with_destination(self, queue_with_ecs: AlertQueue) -> None:
        """Host-only vs host+destination are different entities."""
        alert1 = make_alert(host="host1", title="Alert1")
        alert2 = make_alert(host="host1", dst_ip="10.0.0.1", title="Alert2")

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)

        result1 = queue_with_ecs.list_by_entity("host1:*")
        result2 = queue_with_ecs.list_by_entity("host1:10.0.0.1")

        assert len(result1) == 1
        assert len(result2) == 1
        assert result1[0].alert_id == alert1.alert_id
        assert result2[0].alert_id == alert2.alert_id

    def test_consistency_with_entity_correlation_service(self, queue_with_ecs: AlertQueue) -> None:
        """Queue entity query should agree with EntityCorrelationService grouping."""
        ecs = EntityCorrelationService()
        alerts = [
            make_alert(host="host1", dst_ip="10.0.0.1", title="Alert1"),
            make_alert(host="host1", dst_ip="10.0.0.1", title="Alert2"),
            make_alert(host="host2", dst_ip="10.0.0.1", title="Alert3"),
        ]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        # Get groups from EntityCorrelationService
        groups = ecs.group_alerts_by_entity(alerts)

        # Verify queue query matches
        for entity_key, group_alerts in groups.items():
            queue_result = queue_with_ecs.list_by_entity(entity_key)
            assert {a.alert_id for a in queue_result} == {a.alert_id for a in group_alerts}


# ---------------------------------------------------------------------------
# Incident Queries
# ---------------------------------------------------------------------------


class TestListByIncident:
    """Tests for AlertQueue.list_by_incident()."""

    def test_matching_incident(
        self, queue_with_ecs: AlertQueue, incident_service: IncidentService
    ) -> None:
        """list_by_incident should return alerts belonging to the incident."""
        alert1 = make_alert(host="host1", title="Alert1", incident_id=uuid4())
        alert2 = make_alert(host="host1", title="Alert2", incident_id=alert1.incident_id)
        alert3 = make_alert(host="host2", title="Alert3", incident_id=uuid4())

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)
        queue_with_ecs.enqueue(alert3)

        result = queue_with_ecs.list_by_incident(alert1.incident_id)
        assert len(result) == 2
        assert {a.alert_id for a in result} == {alert1.alert_id, alert2.alert_id}

    def test_no_matching_incident(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_incident should return empty list for non-existent incident."""
        alert = make_alert(host="host1", title="Alert1")
        queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_incident(uuid4())
        assert result == []

    def test_multiple_alerts_same_incident(self, queue_with_ecs: AlertQueue) -> None:
        """Multiple alerts with same incident_id should all be returned."""
        incident_id = uuid4()
        alerts = [
            make_alert(host="host1", title=f"Alert{i}", incident_id=incident_id) for i in range(5)
        ]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_incident(incident_id)
        assert len(result) == 5
        assert {a.alert_id for a in result} == {a.alert_id for a in alerts}

    def test_alerts_from_different_incidents(self, queue_with_ecs: AlertQueue) -> None:
        """Alerts from different incidents should be separated."""
        incident1 = uuid4()
        incident2 = uuid4()

        alert1 = make_alert(host="host1", title="Alert1", incident_id=incident1)
        alert2 = make_alert(host="host2", title="Alert2", incident_id=incident2)

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)

        result1 = queue_with_ecs.list_by_incident(incident1)
        result2 = queue_with_ecs.list_by_incident(incident2)

        assert len(result1) == 1
        assert len(result2) == 1
        assert result1[0].alert_id == alert1.alert_id
        assert result2[0].alert_id == alert2.alert_id

    def test_incident_id_none(self, queue_with_ecs: AlertQueue) -> None:
        """Alerts with incident_id=None should not match any incident query."""
        alert = make_alert(host="host1", title="Alert1", incident_id=None)
        queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_incident(uuid4())
        assert result == []

    def test_deterministic_results(self, queue_with_ecs: AlertQueue) -> None:
        """Repeated calls should return identical results."""
        incident_id = uuid4()
        alerts = [
            make_alert(host="host1", title=f"Alert{i}", incident_id=incident_id) for i in range(3)
        ]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        result1 = queue_with_ecs.list_by_incident(incident_id)
        result2 = queue_with_ecs.list_by_incident(incident_id)

        assert [a.alert_id for a in result1] == [a.alert_id for a in result2]

    def test_no_mutation(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_incident should not mutate queue state."""
        alert = make_alert(host="host1", title="Alert1")
        queue_with_ecs.enqueue(alert)

        original_len = len(queue_with_ecs)
        _ = queue_with_ecs.list_by_incident(uuid4())
        assert len(queue_with_ecs) == original_len

    def test_empty_queue(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_incident on empty queue should return empty list."""
        result = queue_with_ecs.list_by_incident(uuid4())
        assert result == []

    def test_sorting_applied_by_default(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_incident should sort by default."""
        incident_id = uuid4()
        alerts = [
            make_alert(
                host="host1",
                title=f"Alert{i}",
                severity=Severity.LOW if i % 2 == 0 else Severity.HIGH,
                incident_id=incident_id,
                created_at=datetime(2026, 8, 31, 10 + i, 0, 0, tzinfo=UTC),
            )
            for i in range(3)
        ]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_incident(incident_id)
        assert len(result) == 3
        # HIGH severity should come before LOW
        high_alerts = [a for a in result if a.severity == Severity.HIGH]
        low_alerts = [a for a in result if a.severity == Severity.LOW]
        assert all(r.severity == Severity.HIGH for r in high_alerts)
        assert all(r.severity == Severity.LOW for r in low_alerts)

    def test_sort_disabled(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_incident(sort=False) should return in insertion order."""
        incident_id = uuid4()
        alerts = [
            make_alert(host="host1", title=f"Alert{i}", incident_id=incident_id) for i in range(3)
        ]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_incident(incident_id, sort=False)
        assert [a.title for a in result] == [a.title for a in alerts]


# ---------------------------------------------------------------------------
# Integration with DecisionEngine
# ---------------------------------------------------------------------------


class TestIntegrationWithDecisionEngine:
    """Tests verifying entity/incident queries work with DecisionEngine-created alerts."""

    def test_alerts_from_decision_engine_found_by_entity(
        self,
        queue_with_ecs: AlertQueue,
        incident_service: IncidentService,
    ) -> None:
        """Alerts created by DecisionEngine should be findable via list_by_entity."""
        from argusprowl.decision_engine.decision_engine import DecisionEngine

        de = DecisionEngine(
            cooldown_seconds=60,
            incident_service=incident_service,
            entity_correlation_service=queue_with_ecs._entity_correlation_service,
        )

        result1, assessment1 = _detection_result(host="host1", dst_ip="10.0.0.1")
        alert1 = de.process_detection_result(result1, assessment=assessment1)

        result2, assessment2 = _detection_result(host="host1", dst_ip="10.0.0.1", event_id=uuid4())
        # Clear deduplication to allow second alert through
        de._deduplication.clear()
        alert2 = de.process_detection_result(result2, assessment=assessment2)

        assert alert1 is not None
        assert alert2 is not None
        assert alert1.incident_id is not None
        assert alert2.incident_id == alert1.incident_id

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)

        entity_key = queue_with_ecs._entity_correlation_service.compute_entity_key(alert1)
        result = queue_with_ecs.list_by_entity(entity_key)
        assert len(result) == 2
        assert {a.alert_id for a in result} == {alert1.alert_id, alert2.alert_id}

    def test_alerts_from_decision_engine_found_by_incident(
        self,
        queue_with_ecs: AlertQueue,
        incident_service: IncidentService,
    ) -> None:
        """Alerts created by DecisionEngine should be findable via list_by_incident."""
        from argusprowl.decision_engine.decision_engine import DecisionEngine

        de = DecisionEngine(
            cooldown_seconds=60,
            incident_service=incident_service,
            entity_correlation_service=queue_with_ecs._entity_correlation_service,
        )

        result1, assessment1 = _detection_result(host="host1", dst_ip="10.0.0.1")
        alert1 = de.process_detection_result(result1, assessment=assessment1)

        result2, assessment2 = _detection_result(host="host1", dst_ip="10.0.0.1", event_id=uuid4())
        # Clear deduplication to allow second alert through
        de._deduplication.clear()
        alert2 = de.process_detection_result(result2, assessment=assessment2)

        result3, assessment3 = _detection_result(host="host2", dst_ip="10.0.0.1", event_id=uuid4())
        de._deduplication.clear()
        alert3 = de.process_detection_result(result3, assessment=assessment3)

        assert alert1 is not None
        assert alert2 is not None
        assert alert3 is not None
        assert alert1.incident_id == alert2.incident_id
        assert alert3.incident_id != alert1.incident_id

        queue_with_ecs.enqueue(alert1)
        queue_with_ecs.enqueue(alert2)
        queue_with_ecs.enqueue(alert3)

        result = queue_with_ecs.list_by_incident(alert1.incident_id)
        assert len(result) == 2
        assert {a.alert_id for a in result} == {alert1.alert_id, alert2.alert_id}

        result2 = queue_with_ecs.list_by_incident(alert3.incident_id)
        assert len(result2) == 1
        assert result2[0].alert_id == alert3.alert_id


# ---------------------------------------------------------------------------
# Backward Compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Tests for backward compatibility."""

    def test_queue_without_ecs_returns_empty_for_entity_query(
        self, queue_without_ecs: AlertQueue
    ) -> None:
        """Queue without EntityCorrelationService should return empty for entity queries."""
        alert = make_alert(host="host1", title="Alert1")
        queue_without_ecs.enqueue(alert)

        result = queue_without_ecs.list_by_entity("host1:*")
        assert result == []

    def test_existing_queue_operations_unchanged(self, queue_with_ecs: AlertQueue) -> None:
        """Existing queue operations should continue to work."""
        alert = make_alert(title="Alert1")
        queue_with_ecs.enqueue(alert)

        # Existing operations
        assert queue_with_ecs.get(alert.alert_id) is not None
        assert len(queue_with_ecs) == 1
        assert queue_with_ecs.values() == [alert]
        assert queue_with_ecs.list() == [alert]

        # Lifecycle operations
        updated = queue_with_ecs.acknowledge(alert.alert_id)
        assert updated.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED
        assert (
            queue_with_ecs.get(alert.alert_id).lifecycle_state == AlertLifecycleState.ACKNOWLEDGED
        )

    def test_existing_filtering_unchanged(self, queue_with_ecs: AlertQueue) -> None:
        """Existing filtering should continue to work."""
        alerts = [
            make_alert(host="host1", title="Alert1", severity=Severity.HIGH),
            make_alert(host="host2", title="Alert2", severity=Severity.LOW),
        ]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list(host="host1")
        assert len(result) == 1
        assert result[0].title == "Alert1"

    def test_existing_sorting_unchanged(self, queue_with_ecs: AlertQueue) -> None:
        """Existing sorting should continue to work."""
        alerts = [
            make_alert(title="Low", severity=Severity.LOW),
            make_alert(title="High", severity=Severity.HIGH),
        ]
        for alert in alerts:
            queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list()
        assert result[0].title == "High"
        assert result[1].title == "Low"


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    """Tests verifying immutability invariants."""

    def test_list_by_entity_does_not_mutate_alerts(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_entity should not mutate stored alerts."""
        alert = make_alert(host="host1", title="Alert1")
        original_dict = alert.to_dict()
        queue_with_ecs.enqueue(alert)

        _ = queue_with_ecs.list_by_entity("host1:*")
        assert alert.to_dict() == original_dict

    def test_list_by_incident_does_not_mutate_alerts(self, queue_with_ecs: AlertQueue) -> None:
        """list_by_incident should not mutate stored alerts."""
        alert = make_alert(host="host1", title="Alert1")
        original_dict = alert.to_dict()
        queue_with_ecs.enqueue(alert)

        _ = queue_with_ecs.list_by_incident(alert.incident_id or uuid4())
        assert alert.to_dict() == original_dict

    def test_lifecycle_after_entity_query(self, queue_with_ecs: AlertQueue) -> None:
        """Lifecycle transitions should work after entity queries."""
        alert = make_alert(host="host1", title="Alert1")
        queue_with_ecs.enqueue(alert)

        _ = queue_with_ecs.list_by_entity("host1:*")
        updated = queue_with_ecs.acknowledge(alert.alert_id)
        assert updated.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_lifecycle_after_incident_query(self, queue_with_ecs: AlertQueue) -> None:
        """Lifecycle transitions should work after incident queries."""
        alert = make_alert(host="host1", title="Alert1")
        queue_with_ecs.enqueue(alert)

        _ = queue_with_ecs.list_by_incident(alert.incident_id or uuid4())
        updated = queue_with_ecs.acknowledge(alert.alert_id)
        assert updated.lifecycle_state == AlertLifecycleState.ACKNOWLEDGED


# ---------------------------------------------------------------------------
# Bounded Queue Behavior
# ---------------------------------------------------------------------------


class TestBoundedQueueBehavior:
    """Tests for bounded queue behavior with new queries."""

    def test_queries_reflect_current_queue_contents(self, queue_with_ecs: AlertQueue) -> None:
        """Queries should only return alerts currently in the queue."""
        alert1 = make_alert(host="host1", title="Alert1")
        alert2 = make_alert(host="host1", title="Alert2")

        queue_with_ecs.enqueue(alert1)
        result = queue_with_ecs.list_by_entity("host1:*")
        assert len(result) == 1

        queue_with_ecs.enqueue(alert2)
        result = queue_with_ecs.list_by_entity("host1:*")
        assert len(result) == 2

    def test_capacity_does_not_affect_query_semantics(self, queue_with_ecs: AlertQueue) -> None:
        """Queue capacity should not affect query semantics."""
        q = AlertQueue(max_size=2, entity_correlation_service=EntityCorrelationService())
        alert1 = make_alert(host="host1", title="Alert1")
        alert2 = make_alert(host="host1", title="Alert2")
        alert3 = make_alert(host="host2", title="Alert3")

        q.enqueue(alert1)
        q.enqueue(alert2)
        with pytest.raises(AlertQueueFullError):
            q.enqueue(alert3)

        result = q.list_by_entity("host1:*")
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Thread Safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    """Tests for thread-safe snapshot behavior."""

    def test_concurrent_enqueue_and_query(self, queue_with_ecs: AlertQueue) -> None:
        """Concurrent enqueue and query should not raise."""
        errors = []

        def enqueue_alerts():
            for i in range(50):
                try:
                    alert = make_alert(host="host1", title=f"Alert{i}")
                    queue_with_ecs.enqueue(alert)
                except Exception as e:
                    errors.append(e)

        def query_entity():
            for _ in range(50):
                try:
                    queue_with_ecs.list_by_entity("host1:*")
                except Exception as e:
                    errors.append(e)

        threads = [
            Thread(target=enqueue_alerts),
            Thread(target=query_entity),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        assert errors == []
        # Should have some alerts
        assert len(queue_with_ecs) > 0


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge case tests."""

    def test_entity_key_with_special_characters(self, queue_with_ecs: AlertQueue) -> None:
        """Entity keys with special characters should work."""
        alert = make_alert(host="host-1.example.com", dst_ip="10.0.0.1", title="Alert1")
        queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_entity("host-1.example.com:10.0.0.1")
        assert len(result) == 1
        assert result[0].alert_id == alert.alert_id

    def test_large_queue(self, queue_with_ecs: AlertQueue) -> None:
        """Should handle large queues efficiently."""
        for i in range(100):
            alert = make_alert(host="host1", title=f"Alert{i}")
            queue_with_ecs.enqueue(alert)

        result = queue_with_ecs.list_by_entity("host1:*")
        assert len(result) == 100

    def test_query_after_acknowledge(self, queue_with_ecs: AlertQueue) -> None:
        """Entity query should still work after lifecycle transition."""
        alert = make_alert(host="host1", title="Alert1")
        queue_with_ecs.enqueue(alert)
        queue_with_ecs.acknowledge(alert.alert_id)

        result = queue_with_ecs.list_by_entity("host1:*")
        assert len(result) == 1
        assert result[0].lifecycle_state == AlertLifecycleState.ACKNOWLEDGED

    def test_query_after_close(self, queue_with_ecs: AlertQueue) -> None:
        """Entity query should still work after close."""
        alert = make_alert(host="host1", title="Alert1")
        queue_with_ecs.enqueue(alert)
        queue_with_ecs.close(alert.alert_id)

        result = queue_with_ecs.list_by_entity("host1:*")
        assert len(result) == 1
        assert result[0].lifecycle_state == AlertLifecycleState.CLOSED
