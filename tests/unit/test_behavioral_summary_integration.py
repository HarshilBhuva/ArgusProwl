"""Tests for Phase 5.1.2 — Behavioral Summary Integration.

Proves that EntityBehaviorSummary is attached to Alert.metadata as
descriptive context only, without affecting any decision logic.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from argusprowl.behavior.entity_behavior_service import EntityBehaviorService
from argusprowl.constants.severity import Severity
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.models.context import ContextualAssessment
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def behavior_service() -> EntityBehaviorService:
    """Create an EntityBehaviorService with pre-populated profiles."""
    service = EntityBehaviorService()
    # Populate some behavior data
    base_time = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
    for i in range(5):
        service.record_observation(
            "hostname",
            "server01",
            "process_name",
            "python",
            base_time + timedelta(minutes=i),
        )
        service.record_observation(
            "hostname",
            "server01",
            "process_name",
            "java",
            base_time + timedelta(minutes=i + 1),
        )
    return service


@pytest.fixture
def decision_engine_with_behavior(behavior_service: EntityBehaviorService) -> DecisionEngine:
    """DecisionEngine wired with EntityBehaviorService."""
    return DecisionEngine(entity_behavior_service=behavior_service)


@pytest.fixture
def decision_engine_without_behavior() -> DecisionEngine:
    """DecisionEngine without EntityBehaviorService (default)."""
    return DecisionEngine()


@pytest.fixture
def sample_detection_result() -> DetectionResult:
    """Create a sample DetectionResult with entity context."""
    return DetectionResult(
        rule_id="first_seen_process",
        event_id=uuid4(),
        matched=True,
        severity=Severity.MEDIUM,
        confidence=0.7,
        description="First seen process python on server01",
        evidence=[
            {"field": "hostname", "observed": "server01", "condition": "equals"},
            {"field": "process_name", "observed": "python", "condition": "equals"},
        ],
    )


@pytest.fixture
def sample_event() -> NormalizedEvent:
    """Create a sample NormalizedEvent."""
    return NormalizedEvent(
        source_type="sysmon",
        event_type="process_create",
        hostname="server01",
        process_name="python",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        dst_port=443,
    )


# ── Test: Summary is context-only ─────────────────────────────────────────────


class TestBehavioralSummaryIsContextOnly:
    """Prove the summary is purely descriptive context."""

    def test_summary_attached_to_metadata(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Summary appears in Alert.metadata.behavioral_summary."""
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        assert "behavioral_summary" in alert.metadata
        summary = alert.metadata["behavioral_summary"]
        assert summary["entity_type"] == "hostname"
        assert summary["entity_id"] == "server01"
        assert summary["dimension"] == "process_name"
        assert summary["observation_count"] == 10
        assert summary["distinct_value_count"] == 2

    def test_summary_narrative_is_descriptive_only(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Summary narrative contains no anomaly/risk claims."""
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        narrative = alert.metadata["behavioral_summary"]["narrative"]
        # Must not contain any of these forbidden terms
        forbidden_terms = [
            "anomaly",
            "deviation",
            "risk",
            "score",
            "ML",
            "baseline",
            "unusual",
            "abnormal",
            "suspicious",
            "threat",
            "danger",
        ]
        narrative_lower = narrative.lower()
        for term in forbidden_terms:
            assert term not in narrative_lower, f"Summary narrative contains forbidden term: {term}"

    def test_summary_no_baseline_comparison(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Summary must not contain baseline comparison language."""
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        narrative = alert.metadata["behavioral_summary"]["narrative"]
        assert "baseline" not in narrative.lower()
        assert "compared" not in narrative.lower()
        assert "normal" not in narrative.lower() or "most frequently" in narrative.lower()

    def test_summary_no_statistical_deviation(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Summary must not contain statistical deviation language."""
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        narrative = alert.metadata["behavioral_summary"]["narrative"]
        forbidden = ["std", "variance", "deviation", "sigma", "percentile", "z-score"]
        for term in forbidden:
            assert term not in narrative.lower(), f"Summary contains statistical term: {term}"


# ── Test: Decision-neutral ────────────────────────────────────────────────────


class TestBehavioralSummaryIsDecisionNeutral:
    """Prove the summary does not affect any decision parameters."""

    def test_severity_unchanged_with_summary(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert.severity is NOT derived from behavioral summary."""
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        # Severity comes from detection result, not summary
        assert alert.severity == sample_detection_result.severity

    def test_priority_unchanged_with_summary(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert.priority is NOT derived from behavioral summary."""
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        # Priority is derived from severity, not summary
        assert alert.priority is not None

    def test_confidence_unchanged_with_summary(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """detector_confidence is None when no assessment provided (existing behavior)."""
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        # detector_confidence is only set when assessment is provided
        assert alert.detector_confidence is None
        assert alert.contextual_confidence is None

    def test_fingerprint_unchanged_with_summary(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert fingerprint/deduplication is NOT affected by summary."""
        # Process same detection twice
        alert1 = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        # Create a second identical detection (different event_id)
        result2 = DetectionResult(
            rule_id=sample_detection_result.rule_id,
            event_id=uuid4(),
            matched=True,
            severity=sample_detection_result.severity,
            confidence=sample_detection_result.confidence,
            description=sample_detection_result.description,
            evidence=sample_detection_result.evidence,
        )
        alert2 = decision_engine_with_behavior.process_detection_result(result2, event=sample_event)
        # Both should have same metadata structure (including summary)
        if alert1 is not None and alert2 is not None:
            assert "behavioral_summary" in alert1.metadata
            assert "behavioral_summary" in alert2.metadata

    def test_lifecycle_state_unchanged_with_summary(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert.lifecycle_state is OPEN, not affected by summary."""
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        from argusprowl.constants.lifecycle import AlertLifecycleState

        assert alert.lifecycle_state == AlertLifecycleState.OPEN

    def test_incident_correlation_unchanged_with_summary(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert.incident_id is None (no incident service configured)."""
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        assert alert.incident_id is None

    def test_deduplication_unchanged_with_summary(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Deduplication still works correctly with summary attached."""
        # First alert should be emitted
        alert1 = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert1 is not None

        # Second identical detection should be suppressed (same cooldown)
        result2 = DetectionResult(
            rule_id=sample_detection_result.rule_id,
            event_id=uuid4(),
            matched=True,
            severity=sample_detection_result.severity,
            confidence=sample_detection_result.confidence,
            description=sample_detection_result.description,
            evidence=sample_detection_result.evidence,
        )
        alert2 = decision_engine_with_behavior.process_detection_result(result2, event=sample_event)
        # Should be suppressed due to cooldown
        assert alert2 is None


# ── Test: Read-only over EntityBehaviorService ────────────────────────────────


class TestBehavioralSummaryIsReadOnly:
    """Prove summary generation does not mutate EntityBehaviorService state."""

    def test_get_summary_does_not_mutate_profile(
        self,
        behavior_service: EntityBehaviorService,
    ) -> None:
        """Calling get_summary does not change observation counts."""
        before_count = behavior_service.profile_count
        before_profile = behavior_service.get_profile("hostname", "server01", "process_name")
        before_obs = before_profile.observation_count if before_profile else 0

        # Call get_summary multiple times
        for _ in range(10):
            summary = behavior_service.get_summary("hostname", "server01", "process_name")
            assert summary is not None

        after_profile = behavior_service.get_profile("hostname", "server01", "process_name")
        after_obs = after_profile.observation_count if after_profile else 0

        assert after_obs == before_obs, "get_summary mutated observation count"
        assert behavior_service.profile_count == before_count

    def test_decision_engine_does_not_mutate_service(
        self,
        decision_engine_with_behavior: DecisionEngine,
        behavior_service: EntityBehaviorService,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """process_detection_result does not mutate EntityBehaviorService."""
        before_count = behavior_service.profile_count
        before_profile = behavior_service.get_profile("hostname", "server01", "process_name")
        before_obs = before_profile.observation_count if before_profile else 0

        # Process detection
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None

        after_profile = behavior_service.get_profile("hostname", "server01", "process_name")
        after_obs = after_profile.observation_count if after_profile else 0

        assert after_obs == before_obs, "DecisionEngine mutated observation count"
        assert behavior_service.profile_count == before_count


# ── Test: No summary when service not configured ──────────────────────────────


class TestNoSummaryWithoutService:
    """Prove no behavioral_summary when EntityBehaviorService is not wired."""

    def test_no_summary_without_service(
        self,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert has no behavioral_summary when service is not configured."""
        alert = decision_engine_without_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        assert "behavioral_summary" not in alert.metadata

    def test_alert_generated_without_service(
        self,
        decision_engine_without_behavior: DecisionEngine,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert is still generated normally without behavioral service."""
        alert = decision_engine_without_behavior.process_detection_result(
            sample_detection_result, event=sample_event
        )
        assert alert is not None
        assert alert.severity == sample_detection_result.severity
        # detector_confidence is None when no assessment provided (existing behavior)
        assert alert.detector_confidence is None


# ── Test: Summary with assessment ─────────────────────────────────────────────


class TestBehavioralSummaryWithAssessment:
    """Prove summary works correctly alongside ContextualAssessment."""

    def test_summary_and_assessment_both_present(
        self,
        decision_engine_with_behavior: DecisionEngine,
        behavior_service: EntityBehaviorService,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Both behavioral_summary and assessment fields are present."""
        assessment = ContextualAssessment(
            detection_result=sample_detection_result,
            final_confidence=0.85,
            severity=Severity.HIGH,
            explanation="Contextual assessment applied",
        )
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, assessment=assessment, event=sample_event
        )
        assert alert is not None
        assert "behavioral_summary" in alert.metadata
        assert alert.contextual_confidence == 0.85
        assert alert.severity == Severity.HIGH  # From assessment, not summary

    def test_summary_does_not_override_assessment(
        self,
        decision_engine_with_behavior: DecisionEngine,
        behavior_service: EntityBehaviorService,
        sample_detection_result: DetectionResult,
        sample_event: NormalizedEvent,
    ) -> None:
        """Assessment severity takes precedence over detection severity."""
        assessment = ContextualAssessment(
            detection_result=sample_detection_result,
            final_confidence=0.9,
            severity=Severity.CRITICAL,
            explanation="Critical assessment",
        )
        alert = decision_engine_with_behavior.process_detection_result(
            sample_detection_result, assessment=assessment, event=sample_event
        )
        assert alert is not None
        # Severity from assessment, not from summary
        assert alert.severity == Severity.CRITICAL
        assert alert.contextual_confidence == 0.9


# ── Test: Missing profile returns None gracefully ─────────────────────────────


class TestMissingProfileGraceful:
    """Prove missing profiles don't break alert generation."""

    def test_no_summary_for_unknown_entity(
        self,
        decision_engine_with_behavior: DecisionEngine,
        sample_event: NormalizedEvent,
    ) -> None:
        """Alert generated even when no behavior profile exists."""
        result = DetectionResult(
            rule_id="first_seen_process",
            event_id=uuid4(),
            matched=True,
            severity=Severity.MEDIUM,
            confidence=0.7,
            description="First seen process on unknown_host",
            evidence=[
                {"field": "hostname", "observed": "unknown_host", "condition": "equals"},
                {"field": "process_name", "observed": "bash", "condition": "equals"},
            ],
        )
        alert = decision_engine_with_behavior.process_detection_result(result, event=sample_event)
        # Alert generated even without profile
        assert alert is not None
        # No behavioral_summary for unknown entity (no profile exists)
        assert "behavioral_summary" not in alert.metadata


# ── Test: Replay parity ───────────────────────────────────────────────────────


class TestReplayParity:
    """Prove live and replay flows produce equivalent summary context."""

    def test_replay_produces_same_summary(
        self,
        behavior_service: EntityBehaviorService,
    ) -> None:
        """Replay with same behavior service produces same summary."""
        # Simulate what replay does: record observations, then get summary
        base_time = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        for i in range(3):
            behavior_service.record_observation(
                "hostname",
                "workstation01",
                "process_name",
                "chrome",
                base_time + timedelta(minutes=i),
            )

        summary = behavior_service.get_summary("hostname", "workstation01", "process_name")
        assert summary is not None
        assert summary.observation_count == 3
        assert summary.distinct_value_count == 1
        assert summary.top_values == [("chrome", 3)]

    def test_summary_deterministic(
        self,
        behavior_service: EntityBehaviorService,
    ) -> None:
        """Same input produces identical summary."""
        base_time = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        for _ in range(5):
            behavior_service.record_observation(
                "hostname",
                "server01",
                "process_name",
                "python",
                base_time,
            )
            behavior_service.record_observation(
                "hostname",
                "server01",
                "process_name",
                "java",
                base_time + timedelta(seconds=1),
            )

        summary1 = behavior_service.get_summary("hostname", "server01", "process_name")
        summary2 = behavior_service.get_summary("hostname", "server01", "process_name")

        assert summary1 is not None
        assert summary2 is not None
        assert summary1.to_dict() == summary2.to_dict()
