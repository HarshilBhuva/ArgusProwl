"""Tests for Phase 6.3: Post-Decision ATT&CK Alert Enrichment."""

from argusprowl.attck.enrichment_service import AttckEnrichmentService
from argusprowl.attck.knowledge_service import AttckKnowledgeStatus
from argusprowl.attck.mapping_registry import AttckMapping, MappingType
from argusprowl.attck.models import AttckTechnique
from argusprowl.constants.severity import Severity
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detector_registry import DetectorRegistry
from argusprowl.detection.detectors.event_count_correlation import EventCountCorrelationDetector
from argusprowl.models.alert import Alert


class MockKnowledgeService:
    def __init__(self, enabled=True, status=AttckKnowledgeStatus.AVAILABLE):
        self.is_enabled = enabled
        self._status = status
        self._techniques = {
            "T1046": AttckTechnique(
                technique_id="T1046", name="Network Service Discovery", tactic="discovery"
            ),
            "T1110": AttckTechnique(
                technique_id="T1110", name="Brute Force", tactic="credential-access"
            ),
            "T1498": AttckTechnique(
                technique_id="T1498", name="Network Denial of Service", tactic="impact"
            ),
        }

    def get_status(self):
        return self._status

    def get_technique(self, technique_id):
        return self._techniques.get(technique_id)

    def get_version(self):
        return "14.0"


class MockMappingRegistry:
    def __init__(self):
        self._mappings = {
            "port_scan": [
                AttckMapping(
                    rule_id="port_scan", technique_id="T1046", mapping_type=MappingType.DIRECT
                )
            ],
            "syn_scan": [
                AttckMapping(
                    rule_id="syn_scan", technique_id="T1046", mapping_type=MappingType.SUPPORTED
                ),
                AttckMapping(
                    rule_id="syn_scan", technique_id="T1498", mapping_type=MappingType.SUPPORTED
                ),
            ],
            "event_count_correlation": [
                AttckMapping(
                    rule_id="event_count_correlation",
                    technique_id="T1110",
                    mapping_type=MappingType.SUPPORTED,
                    condition="authentication-context",
                )
            ],
            "unknown_rule": [],
            "none_rule": [
                AttckMapping(
                    rule_id="none_rule", technique_id="T1046", mapping_type=MappingType.NONE
                )
            ],
            "contextual_rule": [
                AttckMapping(
                    rule_id="contextual_rule",
                    technique_id="T1046",
                    mapping_type=MappingType.CONTEXTUAL,
                )
            ],
        }

    def get_for_rule(self, rule_id):
        return tuple(self._mappings.get(rule_id, []))


def test_enrichment_direct_mapping():
    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()
    service = AttckEnrichmentService(knowledge, registry)

    alert = Alert(
        title="Port Scan",
        description="Detected port scan",
        severity=Severity.HIGH,
        source="port_scan",
    )

    enriched = service.enrich(alert)

    assert enriched is not alert
    assert "attck_observations" in enriched.metadata
    obs = enriched.metadata["attck_observations"]
    assert len(obs) == 1
    assert obs[0]["technique_id"] == "T1046"
    assert obs[0]["mapping_type"] == "DIRECT"
    assert obs[0]["technique_name"] == "Network Service Discovery"
    assert obs[0]["tactic"] == "discovery"
    assert obs[0]["version"] == "14.0"

    # Verify immutability and preservation of fields
    assert enriched.severity == alert.severity
    assert enriched.priority == alert.priority
    assert enriched.lifecycle_state == alert.lifecycle_state
    assert enriched.incident_id == alert.incident_id
    assert enriched.alert_id == alert.alert_id
    assert enriched.source == alert.source


def test_enrichment_multiple_supported_mappings():
    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()
    service = AttckEnrichmentService(knowledge, registry)

    alert = Alert(
        title="SYN Scan",
        description="Detected SYN scan",
        severity=Severity.MEDIUM,
        source="syn_scan",
    )

    enriched = service.enrich(alert)

    obs = enriched.metadata["attck_observations"]
    assert len(obs) == 2
    assert obs[0]["technique_id"] == "T1046"
    assert obs[0]["mapping_type"] == "SUPPORTED"
    assert obs[1]["technique_id"] == "T1498"
    assert obs[1]["mapping_type"] == "SUPPORTED"


def test_enrichment_contextual_mapping():
    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()
    service = AttckEnrichmentService(knowledge, registry)

    alert = Alert(
        title="Contextual",
        description="Contextual alert",
        severity=Severity.LOW,
        source="contextual_rule",
    )

    enriched = service.enrich(alert)

    obs = enriched.metadata["attck_observations"]
    assert len(obs) == 1
    assert obs[0]["mapping_type"] == "CONTEXTUAL"


def test_enrichment_none_mapping_excluded():
    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()
    service = AttckEnrichmentService(knowledge, registry)

    alert = Alert(
        title="None",
        description="None alert",
        severity=Severity.LOW,
        source="none_rule",
    )

    enriched = service.enrich(alert)
    assert "attck_observations" not in enriched.metadata


def test_enrichment_unknown_rule():
    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()
    service = AttckEnrichmentService(knowledge, registry)

    alert = Alert(
        title="Unknown",
        description="Unknown alert",
        severity=Severity.LOW,
        source="unknown_rule",
    )

    enriched = service.enrich(alert)
    assert "attck_observations" not in enriched.metadata


def test_enrichment_disabled():
    knowledge = MockKnowledgeService(enabled=False)
    registry = MockMappingRegistry()
    service = AttckEnrichmentService(knowledge, registry)

    alert = Alert(
        title="Port Scan",
        description="Detected port scan",
        severity=Severity.HIGH,
        source="port_scan",
    )

    enriched = service.enrich(alert)
    assert "attck_observations" not in enriched.metadata


def test_enrichment_unavailable():
    knowledge = MockKnowledgeService(status=AttckKnowledgeStatus.UNAVAILABLE)
    registry = MockMappingRegistry()
    service = AttckEnrichmentService(knowledge, registry)

    alert = Alert(
        title="Port Scan",
        description="Detected port scan",
        severity=Severity.HIGH,
        source="port_scan",
    )

    enriched = service.enrich(alert)
    assert "attck_observations" not in enriched.metadata


def test_enrichment_degraded():
    knowledge = MockKnowledgeService(status=AttckKnowledgeStatus.DEGRADED)
    registry = MockMappingRegistry()
    service = AttckEnrichmentService(knowledge, registry)

    alert = Alert(
        title="Port Scan",
        description="Detected port scan",
        severity=Severity.HIGH,
        source="port_scan",
    )

    enriched = service.enrich(alert)
    assert "attck_observations" in enriched.metadata


def test_enrichment_conditional_mapping_satisfied():
    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()

    detector_registry = DetectorRegistry()
    detector = EventCountCorrelationDetector(
        name="event_count_correlation",
        filter_config={"event_type": "authentication_failed"},
        config={"correlation": {"filter": {"event_type": "authentication_failed"}}},
    )
    detector_registry.register(detector)
    detection_manager = DetectionManager(detector_registry)

    service = AttckEnrichmentService(knowledge, registry, detection_manager)

    alert = Alert(
        title="Brute Force",
        description="Detected brute force",
        severity=Severity.HIGH,
        source="event_count_correlation",
    )

    enriched = service.enrich(alert)
    assert "attck_observations" in enriched.metadata
    obs = enriched.metadata["attck_observations"]
    assert len(obs) == 1
    assert obs[0]["technique_id"] == "T1110"
    assert obs[0]["condition"] == "authentication-context"


def test_enrichment_conditional_mapping_not_satisfied():
    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()

    detector_registry = DetectorRegistry()
    detector = EventCountCorrelationDetector(
        name="event_count_correlation",
        filter_config={"event_type": "other_event"},
        config={"correlation": {"filter": {"event_type": "other_event"}}},
    )
    detector_registry.register(detector)
    detection_manager = DetectionManager(detector_registry)

    service = AttckEnrichmentService(knowledge, registry, detection_manager)

    alert = Alert(
        title="Other Count",
        description="Detected other count",
        severity=Severity.HIGH,
        source="event_count_correlation",
    )

    enriched = service.enrich(alert)
    assert "attck_observations" not in enriched.metadata


def test_enrichment_conditional_mapping_similar_but_unapproved():
    """Similar-but-unapproved authentication values must NOT emit T1110."""
    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()

    detector_registry = DetectorRegistry()
    detector = EventCountCorrelationDetector(
        name="event_count_correlation",
        filter_config={"event_type": "auth_failure"},
        config={"correlation": {"filter": {"event_type": "auth_failure"}}},
    )
    detector_registry.register(detector)
    detection_manager = DetectionManager(detector_registry)

    service = AttckEnrichmentService(knowledge, registry, detection_manager)

    alert = Alert(
        title="Auth Failure",
        description="Detected auth failure",
        severity=Severity.HIGH,
        source="event_count_correlation",
    )

    enriched = service.enrich(alert)
    assert "attck_observations" not in enriched.metadata


def test_enrichment_conditional_mapping_missing_condition():
    """Missing condition must NOT emit T1110."""
    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()

    detector_registry = DetectorRegistry()
    detector = EventCountCorrelationDetector(
        name="event_count_correlation", filter_config={}, config={}
    )
    detector_registry.register(detector)
    detection_manager = DetectionManager(detector_registry)

    service = AttckEnrichmentService(knowledge, registry, detection_manager)

    alert = Alert(
        title="No Condition",
        description="No condition",
        severity=Severity.HIGH,
        source="event_count_correlation",
    )

    enriched = service.enrich(alert)
    assert "attck_observations" not in enriched.metadata


def test_enrichment_preserves_security_decision_fields():
    """ATT&CK enrichment must not modify severity, priority, confidence, fingerprint, dedup identity, lifecycle, incident_id, or alert_id."""
    from argusprowl.deduplication.fingerprint import AlertFingerprint, FingerprintConfig

    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()

    detector_registry = DetectorRegistry()
    detector = EventCountCorrelationDetector(
        name="event_count_correlation",
        filter_config={"event_type": "authentication_failed"},
        config={"correlation": {"filter": {"event_type": "authentication_failed"}}},
    )
    detector_registry.register(detector)
    detection_manager = DetectionManager(detector_registry)

    service = AttckEnrichmentService(knowledge, registry, detection_manager)

    original_alert = Alert(
        title="Brute Force",
        description="Detected brute force",
        severity=Severity.CRITICAL,
        source="event_count_correlation",
        metadata={"confidence": 0.95},
    )

    enriched = service.enrich(original_alert)

    # Verify all security decision fields are preserved
    assert enriched.severity == original_alert.severity
    assert enriched.priority == original_alert.priority
    assert enriched.lifecycle_state == original_alert.lifecycle_state
    assert enriched.incident_id == original_alert.incident_id
    assert enriched.alert_id == original_alert.alert_id
    assert enriched.source == original_alert.source

    # Verify fingerprint is unchanged
    fingerprint = AlertFingerprint(FingerprintConfig())
    assert fingerprint.create(enriched) == fingerprint.create(original_alert)

    # Verify only attck_observations was added to metadata
    assert "attck_observations" in enriched.metadata
    assert enriched.metadata.get("confidence") == 0.95


def test_enrichment_preserves_security_decision_fields_no_enrichment():
    """ATT&CK enrichment must not modify fields when no enrichment is applied."""
    from argusprowl.deduplication.fingerprint import AlertFingerprint, FingerprintConfig

    knowledge = MockKnowledgeService()
    registry = MockMappingRegistry()
    service = AttckEnrichmentService(knowledge, registry)

    original_alert = Alert(
        title="Port Scan",
        description="Detected port scan",
        severity=Severity.HIGH,
        source="port_scan",
        metadata={"confidence": 0.8},
    )

    enriched = service.enrich(original_alert)

    # Verify all security decision fields are preserved
    assert enriched.severity == original_alert.severity
    assert enriched.priority == original_alert.priority
    assert enriched.lifecycle_state == original_alert.lifecycle_state
    assert enriched.incident_id == original_alert.incident_id
    assert enriched.alert_id == original_alert.alert_id
    assert enriched.source == original_alert.source

    # Verify fingerprint is unchanged
    fingerprint = AlertFingerprint(FingerprintConfig())
    assert fingerprint.create(enriched) == fingerprint.create(original_alert)
