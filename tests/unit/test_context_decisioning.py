"""Phase 4.7.1 — Context-Aware Decisioning Tests.

Validates the Alert contract extension and DecisionEngine assessment boundary.
Covers legacy behaviour preservation, contextual behaviour, critical scenarios,
and regression guards.
"""

from uuid import uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.models.alert import Alert
from argusprowl.models.context import (
    ContextualAssessment,
    EntityContext,
    EvidenceType,
    FusionEvidence,
)
from argusprowl.models.detection_result import DetectionResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def decision_engine() -> DecisionEngine:
    """Fresh DecisionEngine with short cooldown for test isolation."""
    return DecisionEngine(cooldown_seconds=60)


@pytest.fixture
def high_confidence_result() -> DetectionResult:
    """DetectionResult with high confidence and HIGH severity."""
    return DetectionResult(
        rule_id="beaconing_c2",
        event_id=uuid4(),
        matched=True,
        severity=Severity.HIGH,
        confidence=0.85,
        description="Beaconing detected from 10.0.0.5 to 203.0.113.50:8443",
        evidence=[
            {"field": "src_ip", "observed": "10.0.0.5", "condition": "equals"},
            {"field": "destination", "observed": "203.0.113.50", "condition": "equals"},
            {"field": "destination_port", "observed": 8443, "condition": "equals"},
            {"field": "periodicity_score", "observed": 0.92, "condition": "greater_than_or_equal"},
        ],
    )


@pytest.fixture
def low_confidence_result() -> DetectionResult:
    """DetectionResult with low confidence."""
    return DetectionResult(
        rule_id="port_scan",
        event_id=uuid4(),
        matched=True,
        severity=Severity.HIGH,
        confidence=0.25,
        description="Port scan detected from 10.0.0.1",
        evidence=[
            {"field": "src_ip", "observed": "10.0.0.1", "condition": "exists"},
        ],
    )


def _severity_from_confidence(confidence: float) -> Severity:
    """Map confidence using the fusion-engine thresholds (not the legacy table)."""
    if confidence < 0.30:
        return Severity.INFO
    if confidence < 0.45:
        return Severity.LOW
    if confidence < 0.60:
        return Severity.MEDIUM
    if confidence < 0.85:
        return Severity.HIGH
    return Severity.CRITICAL


def _make_assessment(
    detection_result: DetectionResult,
    *,
    final_confidence: float,
    severity: Severity | None = None,
    explanation: str = "",
    supporting: tuple[FusionEvidence, ...] = (),
    contradictory: tuple[FusionEvidence, ...] = (),
    pivots: tuple[str, ...] = (),
    entity_context: EntityContext | None = None,
) -> ContextualAssessment:
    """Helper to build a ContextualAssessment for a given DetectionResult."""
    return ContextualAssessment(
        detection_result=detection_result,
        final_confidence=final_confidence,
        severity=severity if severity is not None else _severity_from_confidence(final_confidence),
        entity_context=entity_context,
        supporting_evidence=supporting,
        contradictory_evidence=contradictory,
        explanation=explanation,
        investigation_pivots=pivots,
    )


# ===========================================================================
# SECTION 1 — Legacy behaviour (no assessment)
# ===========================================================================


class TestLegacyBehaviour:
    """DecisionEngine must behave identically when no assessment is provided."""

    def test_detection_result_only_creates_alert(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Legacy path: DetectionResult alone still produces an Alert."""
        alert = decision_engine.process_detection_result(high_confidence_result)
        assert alert is not None
        assert isinstance(alert, Alert)

    def test_legacy_severity_preserved(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Without assessment, severity uses DetectionResult.confidence."""
        alert = decision_engine.process_detection_result(high_confidence_result)
        assert alert is not None
        # confidence=0.85, severity=HIGH → no downgrade
        assert alert.severity == Severity.HIGH

    def test_legacy_low_confidence_downgrade(
        self, decision_engine: DecisionEngine, low_confidence_result: DetectionResult
    ) -> None:
        """Without assessment, low confidence still downgrades severity."""
        alert = decision_engine.process_detection_result(low_confidence_result)
        assert alert is not None
        # confidence=0.25 < 0.3 → downgrade to LOW
        assert alert.severity == Severity.LOW

    def test_legacy_alert_has_no_contextual_fields(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Without assessment, contextual fields remain at defaults."""
        alert = decision_engine.process_detection_result(high_confidence_result)
        assert alert is not None
        assert alert.assessment_id is None
        assert alert.detector_confidence is None
        assert alert.contextual_confidence is None
        assert alert.contextual_explanation == ""
        assert alert.supporting_evidence == ()
        assert alert.contradictory_evidence == ()
        assert alert.investigation_pivots == ()
        assert alert.entity_context is None

    def test_legacy_serialization_metadata(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Legacy metadata keys remain present."""
        alert = decision_engine.process_detection_result(high_confidence_result)
        assert alert is not None
        assert "rule_id" in alert.metadata
        assert "event_id" in alert.metadata
        assert "result_id" in alert.metadata
        assert "confidence" in alert.metadata
        assert "evidence" in alert.metadata
        assert alert.metadata["confidence"] == high_confidence_result.confidence

    def test_legacy_deduplication_unchanged(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Deduplication still suppresses duplicate alerts."""
        alert1 = decision_engine.process_detection_result(high_confidence_result)
        assert alert1 is not None
        alert2 = decision_engine.process_detection_result(high_confidence_result)
        assert alert2 is None

    def test_non_matched_returns_none(self, decision_engine: DecisionEngine) -> None:
        """Non-matched DetectionResult returns None regardless of assessment."""
        result = DetectionResult(rule_id="test", event_id=uuid4(), matched=False)
        alert = decision_engine.process_detection_result(result)
        assert alert is None

    def test_non_matched_with_assessment_returns_none(
        self, decision_engine: DecisionEngine
    ) -> None:
        """Non-matched DetectionResult returns None even with assessment."""
        result = DetectionResult(rule_id="test", event_id=uuid4(), matched=False)
        assessment = _make_assessment(result, final_confidence=0.9)
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is None


# ===========================================================================
# SECTION 2 — Contextual behaviour (assessment provided)
# ===========================================================================


class TestContextualBehaviour:
    """DecisionEngine uses ContextualAssessment when provided."""

    def test_contextual_confidence_drives_severity(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Assessment severity is used for alert severity; DecisionEngine does not remap."""
        # Detector confidence=0.85 (HIGH stays HIGH normally)
        # But contextual severity is LOW → alert severity must be LOW
        assessment = _make_assessment(
            high_confidence_result,
            final_confidence=0.20,
            severity=Severity.LOW,
            explanation="Environment-wide NTP traffic",
        )
        alert = decision_engine.process_detection_result(
            high_confidence_result, assessment=assessment
        )
        assert alert is not None
        assert alert.severity == Severity.LOW

    def test_detector_confidence_preserved(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Original detector confidence is preserved on the Alert."""
        assessment = _make_assessment(
            high_confidence_result,
            final_confidence=0.40,
        )
        alert = decision_engine.process_detection_result(
            high_confidence_result, assessment=assessment
        )
        assert alert is not None
        assert alert.detector_confidence == 0.85
        assert alert.contextual_confidence == 0.40
        # Also preserved in legacy metadata
        assert alert.metadata["confidence"] == 0.85

    def test_supporting_evidence_reaches_alert(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Supporting evidence from assessment is surfaced on Alert."""
        supporting = (
            FusionEvidence(
                evidence_type=EvidenceType.SUPPORTING,
                category="rare_destination",
                description="Destination 203.0.113.50 seen by 1 host",
                weight=0.15,
            ),
        )
        assessment = _make_assessment(
            high_confidence_result,
            final_confidence=0.90,
            supporting=supporting,
        )
        alert = decision_engine.process_detection_result(
            high_confidence_result, assessment=assessment
        )
        assert alert is not None
        assert len(alert.supporting_evidence) == 1
        assert alert.supporting_evidence[0]["category"] == "rare_destination"

    def test_contradictory_evidence_reaches_alert(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Contradictory evidence from assessment is surfaced on Alert."""
        contradictory = (
            FusionEvidence(
                evidence_type=EvidenceType.CONTRADICTORY,
                category="environment_wide",
                description="Destination seen across 80% of hosts",
                weight=-0.40,
            ),
        )
        assessment = _make_assessment(
            high_confidence_result,
            final_confidence=0.30,
            contradictory=contradictory,
        )
        alert = decision_engine.process_detection_result(
            high_confidence_result, assessment=assessment
        )
        assert alert is not None
        assert len(alert.contradictory_evidence) == 1
        assert alert.contradictory_evidence[0]["category"] == "environment_wide"

    def test_explanation_reaches_alert(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Contextual explanation is surfaced on Alert."""
        assessment = _make_assessment(
            high_confidence_result,
            final_confidence=0.70,
            explanation="Rare destination with suspicious TI reputation",
        )
        alert = decision_engine.process_detection_result(
            high_confidence_result, assessment=assessment
        )
        assert alert is not None
        assert alert.contextual_explanation == "Rare destination with suspicious TI reputation"

    def test_investigation_pivots_reach_alert(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Investigation pivots from assessment are surfaced on Alert."""
        assessment = _make_assessment(
            high_confidence_result,
            final_confidence=0.80,
            pivots=(
                "Check DNS logs for 203.0.113.50",
                "Review process tree for svchost.exe PID 1234",
            ),
        )
        alert = decision_engine.process_detection_result(
            high_confidence_result, assessment=assessment
        )
        assert alert is not None
        assert len(alert.investigation_pivots) == 2
        assert "DNS logs" in alert.investigation_pivots[0]

    def test_entity_context_preserved(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Entity context from assessment is preserved on Alert."""
        entity = EntityContext(
            host="workstation01",
            process_name="svchost.exe",
            pid=1234,
            src_ip="10.0.0.5",
            dst_ip="203.0.113.50",
            dst_port=8443,
        )
        assessment = _make_assessment(
            high_confidence_result,
            final_confidence=0.80,
            entity_context=entity,
        )
        alert = decision_engine.process_detection_result(
            high_confidence_result, assessment=assessment
        )
        assert alert is not None
        assert alert.entity_context is not None
        assert alert.entity_context["host"] == "workstation01"
        assert alert.entity_context["process_name"] == "svchost.exe"
        assert alert.entity_context["dst_ip"] == "203.0.113.50"

    def test_assessment_id_preserved(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """Assessment ID is preserved on Alert for audit trail."""
        assessment = _make_assessment(
            high_confidence_result,
            final_confidence=0.80,
        )
        alert = decision_engine.process_detection_result(
            high_confidence_result, assessment=assessment
        )
        assert alert is not None
        assert alert.assessment_id == assessment.assessment_id

    def test_no_second_confidence_calculation(
        self, decision_engine: DecisionEngine, high_confidence_result: DetectionResult
    ) -> None:
        """DecisionEngine does NOT recalculate contextual confidence.

        The contextual_confidence on the Alert must exactly equal
        assessment.final_confidence — no additional scoring occurs.
        """
        assessment = _make_assessment(
            high_confidence_result,
            final_confidence=0.4237,
        )
        alert = decision_engine.process_detection_result(
            high_confidence_result, assessment=assessment
        )
        assert alert is not None
        assert alert.contextual_confidence == 0.4237


# ===========================================================================
# SECTION 3 — Critical scenarios
# ===========================================================================


class TestCriticalScenarios:
    """Scenarios that validate the core architectural invariants."""

    def test_high_detector_benign_context_lowers_severity(
        self, decision_engine: DecisionEngine
    ) -> None:
        """High detector confidence + benign/environment-wide context → lower severity."""
        result = DetectionResult(
            rule_id="beaconing_c2",
            event_id=uuid4(),
            matched=True,
            severity=Severity.HIGH,
            confidence=0.85,
            description="Beaconing from 10.0.0.5",
            evidence=[
                {"field": "src_ip", "observed": "10.0.0.5", "condition": "equals"},
                {
                    "field": "periodicity_score",
                    "observed": 0.92,
                    "condition": "greater_than_or_equal",
                },
            ],
        )
        contradictory = (
            FusionEvidence(
                evidence_type=EvidenceType.CONTRADICTORY,
                category="environment_wide",
                description="Destination seen across 85% of hosts",
                weight=-0.40,
            ),
            FusionEvidence(
                evidence_type=EvidenceType.CONTRADICTORY,
                category="benign_infrastructure",
                description="Known CDN endpoint",
                weight=-0.35,
            ),
        )
        assessment = _make_assessment(
            result,
            final_confidence=0.15,
            explanation="Environment-wide CDN traffic, benign infrastructure",
            contradictory=contradictory,
        )
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        # fusion mapping: 0.15 < 0.30 → INFO. DecisionEngine must not remap this.
        assert alert.severity == Severity.INFO
        assert alert.detector_confidence == 0.85
        assert alert.contextual_confidence == 0.15

    def test_high_detector_rare_dest_malicious_ti_maintains_high(
        self, decision_engine: DecisionEngine
    ) -> None:
        """High detector confidence + rare destination + malicious TI → high priority."""
        result = DetectionResult(
            rule_id="beaconing_c2",
            event_id=uuid4(),
            matched=True,
            severity=Severity.HIGH,
            confidence=0.85,
            description="Beaconing from 10.0.0.5 to 198.51.100.99",
            evidence=[
                {"field": "src_ip", "observed": "10.0.0.5", "condition": "equals"},
                {"field": "destination", "observed": "198.51.100.99", "condition": "equals"},
            ],
        )
        supporting = (
            FusionEvidence(
                evidence_type=EvidenceType.SUPPORTING,
                category="rare_destination",
                description="Destination seen by 1 host only",
                weight=0.15,
            ),
            FusionEvidence(
                evidence_type=EvidenceType.SUPPORTING,
                category="malicious_ti",
                description="IP flagged as C2 infrastructure",
                weight=0.25,
            ),
        )
        assessment = _make_assessment(
            result,
            final_confidence=0.95,
            explanation="Rare destination with malicious TI reputation",
            supporting=supporting,
        )
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        # fusion mapping: 0.95 >= 0.85 → CRITICAL. DecisionEngine must not keep detector HIGH.
        assert alert.severity == Severity.CRITICAL
        assert alert.contextual_confidence == 0.95

    def test_unknown_ti_no_artificial_adjustment(self, decision_engine: DecisionEngine) -> None:
        """UNKNOWN TI → no artificial confidence adjustment."""
        result = DetectionResult(
            rule_id="beaconing_c2",
            event_id=uuid4(),
            matched=True,
            severity=Severity.HIGH,
            confidence=0.75,
            description="Beaconing from 10.0.0.5",
            evidence=[
                {"field": "src_ip", "observed": "10.0.0.5", "condition": "equals"},
            ],
        )
        # Assessment with same confidence as detector (no TI adjustment)
        assessment = _make_assessment(
            result,
            final_confidence=0.75,
            explanation="No threat intelligence available for destination",
        )
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert alert.severity == Severity.HIGH
        assert alert.contextual_confidence == 0.75
        assert alert.detector_confidence == 0.75

    def test_same_detection_different_assessments_different_severity(
        self, decision_engine: DecisionEngine
    ) -> None:
        """Same DetectionResult with different assessments → different severity."""
        result1 = DetectionResult(
            rule_id="beaconing_c2",
            event_id=uuid4(),
            matched=True,
            severity=Severity.HIGH,
            confidence=0.85,
            description="Beaconing from 10.0.0.5",
            evidence=[
                {"field": "src_ip", "observed": "10.0.0.5", "condition": "equals"},
            ],
        )
        # High contextual confidence → CRITICAL (fusion mapping, not detector HIGH)
        assessment_high = _make_assessment(result1, final_confidence=0.90)
        alert_high = decision_engine.process_detection_result(result1, assessment=assessment_high)
        assert alert_high is not None
        assert alert_high.severity == Severity.CRITICAL

        # Different result (different event_id) with low contextual confidence
        result2 = DetectionResult(
            rule_id="horizontal_scan",
            event_id=uuid4(),
            matched=True,
            severity=Severity.HIGH,
            confidence=0.85,
            description="Horizontal scan from 10.0.0.99",
            evidence=[
                {"field": "src_ip", "observed": "10.0.0.99", "condition": "equals"},
            ],
        )
        assessment_low = _make_assessment(result2, final_confidence=0.20)
        alert_low = decision_engine.process_detection_result(result2, assessment=assessment_low)
        assert alert_low is not None
        assert alert_low.severity == Severity.INFO

    def test_medium_confidence_assessment_downgrades_high_severity(
        self, decision_engine: DecisionEngine
    ) -> None:
        """Contextual confidence 0.45 maps to MEDIUM; DecisionEngine must not keep HIGH."""
        result = DetectionResult(
            rule_id="beaconing_c2",
            event_id=uuid4(),
            matched=True,
            severity=Severity.HIGH,
            confidence=0.85,
            description="Beaconing from 10.0.0.5",
            evidence=[
                {"field": "src_ip", "observed": "10.0.0.5", "condition": "equals"},
            ],
        )
        assessment = _make_assessment(result, final_confidence=0.45)
        alert = decision_engine.process_detection_result(result, assessment=assessment)
        assert alert is not None
        assert alert.severity == Severity.MEDIUM

    def test_severity_boundaries(self, decision_engine: DecisionEngine) -> None:
        """Test exact fusion thresholds around 0.30, 0.45, 0.60, 0.85.

        Each case uses a distinct source IP so cooldown does not suppress
        later boundary samples. Alert.severity must equal assessment.severity.
        """
        cases = (
            (0.29, Severity.INFO),
            (0.30, Severity.LOW),
            (0.45, Severity.MEDIUM),
            (0.59, Severity.MEDIUM),
            (0.60, Severity.HIGH),
            (0.85, Severity.CRITICAL),
        )
        for index, (confidence, expected) in enumerate(cases, start=1):
            result = DetectionResult(
                rule_id="beaconing_c2",
                event_id=uuid4(),
                matched=True,
                severity=Severity.HIGH,
                confidence=0.85,
                description=f"Beaconing from 10.0.0.{index}",
                evidence=[
                    {"field": "src_ip", "observed": f"10.0.0.{index}", "condition": "equals"},
                ],
            )
            assessment = _make_assessment(result, final_confidence=confidence)
            alert = decision_engine.process_detection_result(result, assessment=assessment)
            assert alert is not None, f"alert suppressed at confidence={confidence}"
            assert alert.severity == expected
            assert alert.contextual_confidence == confidence


# ===========================================================================
# SECTION 4 — Alert contract validation
# ===========================================================================


class TestAlertContract:
    """Validate the extended Alert model."""

    def test_alert_schema_version_default(self) -> None:
        """New alerts default to schema_version 2."""
        alert = Alert(
            title="Test",
            description="Test alert",
            severity=Severity.LOW,
            source="test",
        )
        assert alert.schema_version == 2

    def test_alert_backward_compatible_schema_v1(self) -> None:
        """Alerts can still be created with schema_version=1."""
        alert = Alert(
            title="Test",
            description="Test alert",
            severity=Severity.LOW,
            source="test",
            schema_version=1,
        )
        assert alert.schema_version == 1

    def test_alert_contextual_fields_default_empty(self) -> None:
        """Contextual fields default to empty/None when not provided."""
        alert = Alert(
            title="Test",
            description="Test alert",
            severity=Severity.LOW,
            source="test",
        )
        assert alert.assessment_id is None
        assert alert.detector_confidence is None
        assert alert.contextual_confidence is None
        assert alert.contextual_explanation == ""
        assert alert.supporting_evidence == ()
        assert alert.contradictory_evidence == ()
        assert alert.investigation_pivots == ()
        assert alert.entity_context is None

    def test_alert_validates_detector_confidence_range(self) -> None:
        """detector_confidence must be in [0.0, 1.0]."""
        with pytest.raises(ValueError, match="detector_confidence"):
            Alert(
                title="Test",
                description="Test",
                severity=Severity.LOW,
                source="test",
                detector_confidence=1.5,
            )

    def test_alert_validates_contextual_confidence_range(self) -> None:
        """contextual_confidence must be in [0.0, 1.0]."""
        with pytest.raises(ValueError, match="contextual_confidence"):
            Alert(
                title="Test",
                description="Test",
                severity=Severity.LOW,
                source="test",
                contextual_confidence=-0.1,
            )

    def test_alert_with_full_contextual_fields(self) -> None:
        """Alert can be constructed with all contextual fields populated."""
        alert = Alert(
            title="Beaconing C2",
            description="Beaconing detected",
            severity=Severity.HIGH,
            source="beaconing_c2",
            assessment_id=uuid4(),
            detector_confidence=0.85,
            contextual_confidence=0.95,
            contextual_explanation="Rare destination with malicious TI",
            supporting_evidence=(
                {
                    "evidence_type": "SUPPORTING",
                    "category": "rare_destination",
                    "description": "Rare dest",
                    "weight": 0.15,
                },
            ),
            contradictory_evidence=(),
            investigation_pivots=("Check DNS logs",),
            entity_context={"host": "ws01", "process_name": "svchost.exe"},
        )
        assert alert.detector_confidence == 0.85
        assert alert.contextual_confidence == 0.95
        assert len(alert.supporting_evidence) == 1
        assert len(alert.investigation_pivots) == 1

    def test_alert_immutability(self) -> None:
        """Alert remains frozen/immutable with new fields."""
        alert = Alert(
            title="Test",
            description="Test",
            severity=Severity.LOW,
            source="test",
            contextual_confidence=0.5,
        )
        with pytest.raises(AttributeError):
            alert.contextual_confidence = 0.9  # type: ignore[misc]

    def test_alert_serialization_roundtrip(self) -> None:
        """Alert can be serialized to dict and deserialized back without data loss."""
        original = Alert(
            title="Beaconing C2",
            description="Beaconing detected",
            severity=Severity.HIGH,
            source="beaconing_c2",
            assessment_id=uuid4(),
            detector_confidence=0.85,
            contextual_confidence=0.95,
            contextual_explanation="Rare destination with malicious TI",
            supporting_evidence=(
                {
                    "evidence_type": "SUPPORTING",
                    "category": "rare_destination",
                    "description": "Rare dest",
                    "weight": 0.15,
                },
            ),
            contradictory_evidence=(),
            investigation_pivots=("Check DNS logs",),
            entity_context={"host": "ws01", "process_name": "svchost.exe"},
        )

        serialized = original.to_dict()
        restored = Alert.from_dict(serialized)

        assert restored.alert_id == original.alert_id
        assert restored.title == original.title
        assert restored.severity == original.severity
        assert restored.assessment_id == original.assessment_id
        assert restored.detector_confidence == original.detector_confidence
        assert restored.contextual_confidence == original.contextual_confidence
        assert restored.contextual_explanation == original.contextual_explanation
        assert restored.supporting_evidence == original.supporting_evidence
        assert restored.contradictory_evidence == original.contradictory_evidence
        assert restored.investigation_pivots == original.investigation_pivots
        assert restored.entity_context == original.entity_context


# ===========================================================================
# SECTION 5 — Batch processing with assessment
# ===========================================================================


class TestBatchProcessing:
    """Verify process_batch still works (legacy, no assessment)."""

    def test_batch_processing_legacy(self, decision_engine: DecisionEngine) -> None:
        """process_batch still works without assessments."""
        results = [
            DetectionResult(
                rule_id="rule_a",
                event_id=uuid4(),
                matched=True,
                severity=Severity.MEDIUM,
                confidence=0.7,
                evidence=[{"field": "src_ip", "observed": "10.0.0.1", "condition": "equals"}],
            ),
            DetectionResult(
                rule_id="rule_b",
                event_id=uuid4(),
                matched=True,
                severity=Severity.LOW,
                confidence=0.5,
                evidence=[{"field": "src_ip", "observed": "10.0.0.2", "condition": "equals"}],
            ),
        ]
        alerts = decision_engine.process_batch(results)
        assert len(alerts) == 2
