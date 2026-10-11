"""Tests for decision engine module."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.models.alert import Alert
from argusprowl.models.detection_result import DetectionResult


@pytest.fixture
def decision_engine() -> DecisionEngine:
    """Create a DecisionEngine instance for testing."""
    return DecisionEngine(cooldown_seconds=60, max_correlated_alerts=10)


@pytest.fixture
def sample_detection_result() -> DetectionResult:
    """Create a sample DetectionResult for testing."""
    return DetectionResult(
        rule_id="port_scan",
        event_id=uuid4(),
        matched=True,
        severity=Severity.HIGH,
        confidence=0.8,
        description="Port scan detected from 192.168.1.100: 15 unique ports, 2.5 conn/sec",
        evidence=[
            {"field": "src_ip", "observed": "192.168.1.100", "condition": "exists"},
            {"field": "unique_ports", "observed": 15, "condition": ">= 10"},
            {"field": "connection_rate", "observed": 2.5, "condition": ">= 1.0"},
        ],
    )


@pytest.fixture
def low_confidence_result() -> DetectionResult:
    """Create a low confidence detection result."""
    return DetectionResult(
        rule_id="port_scan",
        event_id=uuid4(),
        matched=True,
        severity=Severity.HIGH,
        confidence=0.2,
        description="Port scan detected from 192.168.1.100",
        evidence=[
            {"field": "src_ip", "observed": "192.168.1.100", "condition": "exists"},
        ],
    )


class TestDecisionEngine:
    """Tests for DecisionEngine class."""

    def test_process_detection_result_creates_alert(
        self, decision_engine: DecisionEngine, sample_detection_result: DetectionResult
    ) -> None:
        """Test that processing a detection result creates an alert."""
        alert = decision_engine.process_detection_result(sample_detection_result)

        assert alert is not None
        assert isinstance(alert, Alert)
        assert alert.title is not None
        assert alert.description == sample_detection_result.description
        assert "port_scan" in alert.tags

    def test_process_non_matched_returns_none(self, decision_engine: DecisionEngine) -> None:
        """Test that non-matched results return None."""
        result = DetectionResult(
            rule_id="test",
            event_id=uuid4(),
            matched=False,
        )
        alert = decision_engine.process_detection_result(result)
        assert alert is None

    def test_cooldown_suppresses_duplicates(
        self, decision_engine: DecisionEngine, sample_detection_result: DetectionResult
    ) -> None:
        """Test that cooldown suppresses duplicate alerts."""
        # First alert should be created
        alert1 = decision_engine.process_detection_result(sample_detection_result)
        assert alert1 is not None

        # Second alert with same src_ip should be suppressed
        alert2 = decision_engine.process_detection_result(sample_detection_result)
        assert alert2 is None

    def test_cooldown_expires(
        self, decision_engine: DecisionEngine, sample_detection_result: DetectionResult
    ) -> None:
        """Test that alerts are created after cooldown expires."""
        # Mock time by manipulating the decision engine's internal state
        alert1 = decision_engine.process_detection_result(sample_detection_result)
        assert alert1 is not None

        # Manually set the last alert time to be outside cooldown
        alert_key = decision_engine._generate_alert_key(sample_detection_result)
        decision_engine._alert_history[alert_key] = datetime.now(UTC) - timedelta(seconds=120)

        # Now a new alert should be created
        alert2 = decision_engine.process_detection_result(sample_detection_result)
        assert alert2 is not None

    def test_severity_normalization_high_confidence(
        self, decision_engine: DecisionEngine, sample_detection_result: DetectionResult
    ) -> None:
        """Test severity normalization with high confidence."""
        alert = decision_engine.process_detection_result(sample_detection_result)
        assert alert is not None
        assert alert.severity == Severity.HIGH

    def test_severity_normalization_low_confidence(
        self, decision_engine: DecisionEngine, low_confidence_result: DetectionResult
    ) -> None:
        """Test severity normalization with low confidence."""
        alert = decision_engine.process_detection_result(low_confidence_result)
        assert alert is not None
        # Should be downgraded from HIGH to LOW
        assert alert.severity == Severity.LOW

    def test_evidence_enrichment(
        self, decision_engine: DecisionEngine, sample_detection_result: DetectionResult
    ) -> None:
        """Test that evidence is enriched with metadata."""
        alert = decision_engine.process_detection_result(sample_detection_result)
        assert alert is not None

        evidence = alert.metadata.get("evidence")
        assert evidence is not None
        # Evidence is a list of structured evidence entries; the last entry is
        # the decision engine metadata enrichment.
        assert isinstance(evidence, list)
        assert any(
            isinstance(item, dict) and "decision_engine_version" in item for item in evidence
        )
        assert any(isinstance(item, dict) and "processed_at" in item for item in evidence)

    def test_correlation_groups(
        self, decision_engine: DecisionEngine, sample_detection_result: DetectionResult
    ) -> None:
        """Test alert correlation grouping."""
        alert1 = decision_engine.process_detection_result(sample_detection_result)
        assert alert1 is not None

        # Create another result for same src_ip
        result2 = DetectionResult(
            rule_id="horizontal_scan",
            event_id=uuid4(),
            matched=True,
            severity=Severity.MEDIUM,
            confidence=0.7,
            description="Horizontal scan detected from 192.168.1.100",
            evidence=[
                {"field": "src_ip", "observed": "192.168.1.100", "condition": "exists"},
            ],
        )

        alert2 = decision_engine.process_detection_result(result2)
        assert alert2 is not None

        # Both alerts should be correlated
        correlated = decision_engine.get_correlated_alerts("192.168.1.100")
        assert len(correlated) == 2

    def test_statistics(
        self, decision_engine: DecisionEngine, sample_detection_result: DetectionResult
    ) -> None:
        """Test decision engine statistics."""
        decision_engine.process_detection_result(sample_detection_result)
        stats = decision_engine.get_statistics()

        assert stats["total_alerts_created"] == 1
        assert stats["correlation_groups"] >= 1

    def test_clear_cooldowns(
        self, decision_engine: DecisionEngine, sample_detection_result: DetectionResult
    ) -> None:
        """Test clearing cooldowns."""
        decision_engine.process_detection_result(sample_detection_result)
        assert len(decision_engine._alert_history) > 0

        decision_engine.clear_cooldowns()
        assert len(decision_engine._alert_history) == 0

    def test_clear_correlations(
        self, decision_engine: DecisionEngine, sample_detection_result: DetectionResult
    ) -> None:
        """Test clearing correlations."""
        decision_engine.process_detection_result(sample_detection_result)
        assert len(decision_engine._correlation_groups) > 0

        decision_engine.clear_correlations()
        assert len(decision_engine._correlation_groups) == 0

    def test_process_batch(
        self, decision_engine: DecisionEngine, sample_detection_result: DetectionResult
    ) -> None:
        """Test batch processing of detection results."""
        results = [
            sample_detection_result,
            DetectionResult(
                rule_id="test2",
                event_id=uuid4(),
                matched=True,
                evidence=[
                    {"field": "src_ip", "observed": "10.0.0.1", "condition": "exists"},
                ],
            ),
        ]

        alerts = decision_engine.process_batch(results)
        assert len(alerts) == 2
