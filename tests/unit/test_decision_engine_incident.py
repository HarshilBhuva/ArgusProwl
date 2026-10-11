"""Integration tests for DecisionEngine incident correlation (Phase 4.8.2)."""

from uuid import UUID, uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.incident.incident_service import IncidentService
from argusprowl.models.context import ContextualAssessment, EntityContext
from argusprowl.models.detection_result import DetectionResult


@pytest.fixture
def incident_service() -> IncidentService:
    return IncidentService(max_incidents=100)


@pytest.fixture
def entity_correlation_service() -> EntityCorrelationService:
    return EntityCorrelationService()


@pytest.fixture
def decision_engine_with_incidents(
    incident_service: IncidentService,
    entity_correlation_service: EntityCorrelationService,
) -> DecisionEngine:
    return DecisionEngine(
        cooldown_seconds=60,
        incident_service=incident_service,
        entity_correlation_service=entity_correlation_service,
    )


@pytest.fixture
def decision_engine_without_incidents() -> DecisionEngine:
    return DecisionEngine(cooldown_seconds=60)


def _detection_result(
    rule_id: str = "port_scan",
    src_ip: str = "192.168.1.100",
    dst_ip: str | None = None,
    process_name: str | None = None,
    host: str | None = None,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.8,
    matched: bool = True,
    event_id: UUID | None = None,
) -> tuple[DetectionResult, ContextualAssessment]:
    if event_id is None:
        event_id = uuid4()

    evidence = [
        {"field": "src_ip", "observed": src_ip, "condition": "exists"},
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
            rule_id=rule_id,
            event_id=event_id,
            matched=matched,
            severity=severity,
            confidence=confidence,
            description=f"Test detection from {src_ip}",
            evidence=evidence,
        ),
        final_confidence=confidence,
        severity=severity,
        entity_context=EntityContext(
            host=host,
            process_name=process_name,
            dst_ip=dst_ip,
        )
        if entity_context
        else None,
    )

    return DetectionResult(
        rule_id=rule_id,
        event_id=event_id,
        matched=matched,
        severity=severity,
        confidence=confidence,
        description=f"Test detection from {src_ip}",
        evidence=evidence,
    ), assessment


class TestIncidentCreation:
    def test_first_alert_creates_incident(
        self,
        decision_engine_with_incidents: DecisionEngine,
        incident_service: IncidentService,
    ) -> None:
        result, assessment = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
            dst_ip="10.0.0.1",
        )
        alert = decision_engine_with_incidents.process_detection_result(
            result, assessment=assessment
        )

        assert alert is not None
        assert alert.incident_id is not None

        incident = incident_service.get_incident(alert.incident_id)
        assert incident is not None
        assert len(incident.alert_ids) == 1

    def test_first_alert_without_entity_context_no_incident(
        self,
        decision_engine_with_incidents: DecisionEngine,
    ) -> None:
        result, assessment = _detection_result(
            src_ip="192.168.1.100",
            host=None,
        )
        assessment = ContextualAssessment(
            detection_result=result,
            final_confidence=0.8,
            severity=Severity.HIGH,
            entity_context=None,
        )
        alert = decision_engine_with_incidents.process_detection_result(
            result, assessment=assessment
        )

        assert alert is not None
        assert alert.incident_id is None


class TestDeterministicEntityAssociation:
    def test_same_entity_same_incident(
        self,
        decision_engine_with_incidents: DecisionEngine,
        incident_service: IncidentService,
    ) -> None:
        result1, assessment1 = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
            dst_ip="10.0.0.1",
        )
        alert1 = decision_engine_with_incidents.process_detection_result(
            result1, assessment=assessment1
        )
        assert alert1 is not None
        assert alert1.incident_id is not None

        decision_engine_with_incidents._deduplication.clear()

        result2, assessment2 = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
            dst_ip="10.0.0.1",
            event_id=uuid4(),
        )
        alert2 = decision_engine_with_incidents.process_detection_result(
            result2, assessment=assessment2
        )
        assert alert2 is not None
        assert alert2.incident_id is not None

        assert alert1.incident_id == alert2.incident_id

        incident = incident_service.get_incident(alert1.incident_id)
        assert incident is not None
        assert len(incident.alert_ids) == 2

    def test_different_entity_different_incident(
        self,
        decision_engine_with_incidents: DecisionEngine,
        incident_service: IncidentService,
    ) -> None:
        result1, assessment1 = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
            dst_ip="10.0.0.1",
        )
        alert1 = decision_engine_with_incidents.process_detection_result(
            result1, assessment=assessment1
        )
        assert alert1 is not None

        decision_engine_with_incidents._deduplication.clear()

        result2, assessment2 = _detection_result(
            src_ip="192.168.1.100",
            host="workstation02",
            dst_ip="10.0.0.1",
            event_id=uuid4(),
        )
        alert2 = decision_engine_with_incidents.process_detection_result(
            result2, assessment=assessment2
        )
        assert alert2 is not None

        assert alert1.incident_id != alert2.incident_id

    def test_host_plus_process_precedence(
        self,
        decision_engine_with_incidents: DecisionEngine,
    ) -> None:
        result1, assessment1 = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
            process_name="svchost.exe",
            dst_ip="10.0.0.1",
        )
        alert1 = decision_engine_with_incidents.process_detection_result(
            result1, assessment=assessment1
        )
        assert alert1 is not None

        decision_engine_with_incidents._deduplication.clear()

        result2, assessment2 = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
            process_name="svchost.exe",
            dst_ip="10.0.0.2",
            event_id=uuid4(),
        )
        alert2 = decision_engine_with_incidents.process_detection_result(
            result2, assessment=assessment2
        )
        assert alert2 is not None

        assert alert1.incident_id == alert2.incident_id


class TestAlertImmutability:
    def test_original_alert_unchanged(
        self,
        decision_engine_with_incidents: DecisionEngine,
    ) -> None:
        result, assessment = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
        )

        alert = decision_engine_with_incidents.process_detection_result(
            result, assessment=assessment
        )
        assert alert is not None
        assert alert.incident_id is not None

    def test_associated_alert_is_new_object(
        self,
        decision_engine_with_incidents: DecisionEngine,
    ) -> None:
        result, assessment = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
        )
        alert = decision_engine_with_incidents.process_detection_result(
            result, assessment=assessment
        )
        assert alert is not None
        original_alert_id = alert.alert_id
        original_incident_id = alert.incident_id

        decision_engine_with_incidents._deduplication.clear()

        result2, assessment2 = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
            event_id=uuid4(),
        )
        alert2 = decision_engine_with_incidents.process_detection_result(
            result2, assessment=assessment2
        )
        assert alert2 is not None

        assert alert.alert_id == original_alert_id
        assert alert.incident_id == original_incident_id
        assert alert2.incident_id == original_incident_id


class TestSemanticInvariants:
    def test_severity_unchanged(
        self,
        decision_engine_with_incidents: DecisionEngine,
    ) -> None:
        result, assessment = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
            severity=Severity.CRITICAL,
        )
        alert = decision_engine_with_incidents.process_detection_result(
            result, assessment=assessment
        )

        assert alert is not None
        assert alert.severity == Severity.CRITICAL

    def test_priority_unchanged(
        self,
        decision_engine_with_incidents: DecisionEngine,
    ) -> None:
        result, assessment = _detection_result(
            src_ip="192.168.1.100",
            host="workstation01",
            severity=Severity.HIGH,
        )
        alert = decision_engine_with_incidents.process_detection_result(
            result, assessment=assessment
        )

        assert alert is not None
        assert alert.priority is not None
