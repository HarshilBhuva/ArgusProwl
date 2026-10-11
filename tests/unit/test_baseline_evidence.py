"""Tests for baseline evidence (Phase 5.1.6).

Comprehensive tests for bounded baseline evidence with reason codes:
- All evidence factory methods
- Immutability and serialization
- Bounded comparison values
- Oversized value handling
- Deterministic output
- Replay/live parity
- Backward-compatible serialization
"""

from datetime import UTC, datetime, timedelta

import pytest

from argusprowl.behavior.baseline import (
    BaselineClassification,
)
from argusprowl.behavior.baseline_evidence import (
    BaselineEvidence,
    BaselineReasonCode,
)
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService


class TestBaselineEvidenceModels:
    """Tests for baseline evidence models."""

    def test_reason_code_enum_values(self) -> None:
        """Verify all expected reason code enum values exist."""
        assert BaselineReasonCode.NO_PROFILE.value == "no_profile"
        assert BaselineReasonCode.PROFILE_WARMING.value == "profile_warming"
        assert BaselineReasonCode.PROFILE_STALE.value == "profile_stale"
        assert BaselineReasonCode.VALUE_NEW.value == "value_new"
        assert BaselineReasonCode.VALUE_ESTABLISHED.value == "value_established"
        assert BaselineReasonCode.VALUE_COUNT_AT_THRESHOLD.value == "value_count_at_threshold"
        assert BaselineReasonCode.VALUE_COUNT_BELOW_THRESHOLD.value == "value_count_below_threshold"
        assert (
            BaselineReasonCode.MATURITY_INSUFFICIENT_OBSERVATIONS.value
            == "maturity_insufficient_observations"
        )
        assert BaselineReasonCode.MATURITY_INSUFFICIENT_AGE.value == "maturity_insufficient_age"

    def test_evidence_immutability(self) -> None:
        """Verify BaselineEvidence is immutable (frozen)."""
        evidence = BaselineEvidence(
            reason_code=BaselineReasonCode.VALUE_ESTABLISHED,
            classification="baseline_established",
            profile_maturity="mature",
            value_count=10,
            rare_threshold=5,
            observation_count=20,
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
            first_seen=datetime(2026, 9, 1, tzinfo=UTC),
            last_seen=datetime(2026, 9, 4, tzinfo=UTC),
            top_comparison_values=[],
            explanation="Test explanation",
        )

        # Attempting to modify should raise FrozenInstanceError
        with pytest.raises(AttributeError):
            evidence.reason_code = BaselineReasonCode.VALUE_NEW

        with pytest.raises(AttributeError):
            evidence.value_count = 100

    def test_evidence_to_dict(self) -> None:
        """Verify serialization of evidence."""
        first_seen = datetime(2026, 9, 1, tzinfo=UTC)
        last_seen = datetime(2026, 9, 4, tzinfo=UTC)
        evidence = BaselineEvidence(
            reason_code=BaselineReasonCode.VALUE_ESTABLISHED,
            classification="baseline_established",
            profile_maturity="mature",
            value_count=10,
            rare_threshold=5,
            observation_count=20,
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
            first_seen=first_seen,
            last_seen=last_seen,
            top_comparison_values=[("notepad.exe", 15), ("calc.exe", 8)],
            explanation="Test explanation",
        )

        d = evidence.to_dict()
        assert d["reason_code"] == "value_established"
        assert d["classification"] == "baseline_established"
        assert d["profile_maturity"] == "mature"
        assert d["value_count"] == 10
        assert d["rare_threshold"] == 5
        assert d["observation_count"] == 20
        assert d["maturity_min_observations"] == 20
        assert d["maturity_window_seconds"] == 3600.0
        assert d["first_seen"] == first_seen.isoformat()
        assert d["last_seen"] == last_seen.isoformat()
        assert d["top_comparison_values"] == [("notepad.exe", 15), ("calc.exe", 8)]
        assert d["explanation"] == "Test explanation"

    def test_evidence_top_comparison_values_is_tuple(self) -> None:
        """Verify top_comparison_values is a tuple (immutable)."""
        evidence = BaselineEvidence(
            reason_code=BaselineReasonCode.VALUE_ESTABLISHED,
            classification="baseline_established",
            profile_maturity="mature",
            value_count=10,
            rare_threshold=5,
            observation_count=20,
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
            first_seen=datetime(2026, 9, 1, tzinfo=UTC),
            last_seen=datetime(2026, 9, 4, tzinfo=UTC),
            top_comparison_values=[("notepad.exe", 15), ("calc.exe", 8)],
            explanation="Test explanation",
        )

        # Should be a tuple, not a list
        assert isinstance(evidence.top_comparison_values, tuple)
        assert evidence.top_comparison_values == (("notepad.exe", 15), ("calc.exe", 8))

        # Should be immutable - cannot modify
        with pytest.raises(AttributeError):
            evidence.top_comparison_values = (("something", 1),)

        # Nested tuples should also be immutable
        with pytest.raises(TypeError):
            evidence.top_comparison_values[0] = ("new", 1)


class TestEvidenceFactoryMethods:
    """Tests for evidence factory methods."""

    def test_for_unavailable(self) -> None:
        """Verify unavailable evidence creation."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        evidence = BaselineEvidence.for_unavailable(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            observation_count=1,
            first_seen=ts,
            last_seen=ts,
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
        )

        assert evidence.reason_code == BaselineReasonCode.NO_PROFILE
        assert evidence.classification == "baseline_unavailable"
        assert evidence.profile_maturity == "warming"
        assert evidence.value_count == 0
        assert evidence.rare_threshold == 0
        assert evidence.observation_count == 1
        assert "No baseline profile exists" in evidence.explanation
        assert "host1" in evidence.explanation

    def test_for_warming(self) -> None:
        """Verify warming evidence creation."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        evidence = BaselineEvidence.for_warming(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            value_count=3,
            observation_count=10,
            first_seen=ts,
            last_seen=ts + timedelta(seconds=5),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
        )

        assert evidence.reason_code == BaselineReasonCode.PROFILE_WARMING
        assert evidence.classification == "baseline_warming"
        assert evidence.profile_maturity == "warming"
        assert evidence.value_count == 3
        assert evidence.observation_count == 10
        assert "warming" in evidence.explanation.lower()

    def test_for_warming_stale(self) -> None:
        """Verify stale warming evidence creation."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        evidence = BaselineEvidence.for_warming(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            value_count=3,
            observation_count=10,
            first_seen=ts,
            last_seen=ts + timedelta(seconds=5),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
            is_stale=True,
        )

        assert evidence.reason_code == BaselineReasonCode.PROFILE_STALE
        assert "stale and re-warming" in evidence.explanation

    def test_for_new_value(self) -> None:
        """Verify new value evidence creation."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        evidence = BaselineEvidence.for_new_value(
            entity_id="host1",
            field="process_name",
            value="malware.exe",
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
            top_comparison_values=[("notepad.exe", 15), ("calc.exe", 10)],
        )

        assert evidence.reason_code == BaselineReasonCode.VALUE_NEW
        assert evidence.classification == "baseline_new_value"
        assert evidence.value_count == 0
        assert "never been observed" in evidence.explanation
        assert "malware.exe" in evidence.explanation

    def test_for_rare_value(self) -> None:
        """Verify rare value evidence creation."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        evidence = BaselineEvidence.for_rare_value(
            entity_id="host1",
            field="process_name",
            value="suspicious.exe",
            value_count=3,
            rare_threshold=5,
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
        )

        assert evidence.reason_code == BaselineReasonCode.VALUE_COUNT_BELOW_THRESHOLD
        assert evidence.classification == "baseline_rare_value"
        assert evidence.value_count == 3
        assert evidence.rare_threshold == 5
        assert "rare" in evidence.explanation.lower()
        assert "3" in evidence.explanation

    def test_for_rare_value_at_threshold(self) -> None:
        """Verify rare value evidence when count equals threshold."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        evidence = BaselineEvidence.for_rare_value(
            entity_id="host1",
            field="process_name",
            value="borderline.exe",
            value_count=5,
            rare_threshold=5,
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
        )

        assert evidence.reason_code == BaselineReasonCode.VALUE_COUNT_AT_THRESHOLD
        assert "exactly at threshold" in evidence.explanation

    def test_for_established(self) -> None:
        """Verify established value evidence creation."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        evidence = BaselineEvidence.for_established(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            value_count=10,
            rare_threshold=5,
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
        )

        assert evidence.reason_code == BaselineReasonCode.VALUE_ESTABLISHED
        assert evidence.classification == "baseline_established"
        assert evidence.value_count == 10
        assert evidence.rare_threshold == 5
        assert "established" in evidence.explanation.lower()
        assert "10" in evidence.explanation


class TestEvidenceBoundedValues:
    """Tests for evidence value bounding."""

    def test_top_comparison_values_bounded(self) -> None:
        """Verify top comparison values are bounded to max."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        many_values = [(f"app_{i}.exe", i) for i in range(10)]
        evidence = BaselineEvidence.for_established(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            value_count=10,
            rare_threshold=5,
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
            top_comparison_values=many_values,
        )

        # Should be truncated to 5
        assert len(evidence.top_comparison_values) == 5

    def test_oversized_values_hashed(self) -> None:
        """Verify oversized values are hashed in comparison values."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        long_value = "a" * 200  # Exceeds 128 char limit
        evidence = BaselineEvidence.for_established(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            value_count=10,
            rare_threshold=5,
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
            top_comparison_values=[(long_value, 5)],
        )

        # Long value should be hashed
        assert len(evidence.top_comparison_values[0][0]) == 64  # SHA-256 hex length
        assert evidence.top_comparison_values[0][1] == 5

    def test_value_count_at_threshold_reason(self) -> None:
        """Verify correct reason code when count equals threshold."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        evidence = BaselineEvidence.for_rare_value(
            entity_id="host1",
            field="process_name",
            value="test.exe",
            value_count=5,
            rare_threshold=5,
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
        )

        assert evidence.reason_code == BaselineReasonCode.VALUE_COUNT_AT_THRESHOLD

    def test_value_count_below_threshold_reason(self) -> None:
        """Verify correct reason code when count is below threshold."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        evidence = BaselineEvidence.for_rare_value(
            entity_id="host1",
            field="process_name",
            value="test.exe",
            value_count=3,
            rare_threshold=5,
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
        )

        assert evidence.reason_code == BaselineReasonCode.VALUE_COUNT_BELOW_THRESHOLD


class TestEvidenceDeterministic:
    """Tests for deterministic evidence output."""

    def test_deterministic_explanation(self) -> None:
        """Verify evidence explanation is deterministic."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        evidence1 = BaselineEvidence.for_established(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            value_count=10,
            rare_threshold=5,
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
        )

        evidence2 = BaselineEvidence.for_established(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            value_count=10,
            rare_threshold=5,
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
        )

        assert evidence1.explanation == evidence2.explanation
        assert evidence1.to_dict() == evidence2.to_dict()

    def test_deterministic_serialization(self) -> None:
        """Verify evidence serialization is deterministic."""
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        evidence = BaselineEvidence.for_established(
            entity_id="host1",
            field="process_name",
            value="notepad.exe",
            value_count=10,
            rare_threshold=5,
            observation_count=25,
            first_seen=ts,
            last_seen=ts + timedelta(hours=2),
            maturity_min_observations=20,
            maturity_window_seconds=3600.0,
            top_comparison_values=[("calc.exe", 8), ("svchost.exe", 7)],
        )

        d1 = evidence.to_dict()
        d2 = evidence.to_dict()

        assert d1 == d2
        assert isinstance(d1, dict)
        assert "reason_code" in d1
        assert "explanation" in d1


class TestEvidenceIntegration:
    """Tests for evidence integration with EntityBehaviorService."""

    def test_evidence_for_unavailable(self) -> None:
        """Verify evidence for first observation (unavailable)."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        result, _profile = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts,
            processing_time=ts,
        )

        assert result.classification == BaselineClassification.BASELINE_UNAVAILABLE

        # Generate evidence
        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.reason_code == BaselineReasonCode.NO_PROFILE
        assert evidence.classification == "baseline_unavailable"
        assert evidence.value_count == 0

    def test_evidence_for_warming(self) -> None:
        """Verify evidence for warming profile."""
        service = EntityBehaviorService(
            maturity_min_observations=100,  # High threshold - never reached
            maturity_window_seconds=3600.0,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build profile with few observations
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_WARMING

        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.reason_code in (
            BaselineReasonCode.PROFILE_WARMING,
            BaselineReasonCode.PROFILE_STALE,
        )
        assert evidence.classification == "baseline_warming"

    def test_evidence_for_new_value(self) -> None:
        """Verify evidence for new value in mature profile."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Add new value
        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="malware.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_NEW_VALUE

        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.reason_code == BaselineReasonCode.VALUE_NEW
        assert evidence.classification == "baseline_new_value"
        assert evidence.value_count == 0

    def test_evidence_for_rare_value(self) -> None:
        """Verify evidence for rare value."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Add rare value (seen once)
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare.exe",
            timestamp=ts + timedelta(seconds=50),
            processing_time=ts + timedelta(seconds=50),
        )

        # Observe rare.exe again - should be RARE (count=1 before recording)
        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_RARE_VALUE

        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.reason_code in (
            BaselineReasonCode.VALUE_COUNT_BELOW_THRESHOLD,
            BaselineReasonCode.VALUE_COUNT_AT_THRESHOLD,
        )
        assert evidence.classification == "baseline_rare_value"
        # value_count reflects the PRE-observation count (1 before recording)
        assert evidence.value_count == 1

    def test_evidence_for_established_value(self) -> None:
        """Verify evidence for established value."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile with many observations
        for i in range(10):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        assert result.classification == BaselineClassification.BASELINE_ESTABLISHED

        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.reason_code == BaselineReasonCode.VALUE_ESTABLISHED
        assert evidence.classification == "baseline_established"
        # value_count reflects the PRE-observation count (10 before recording)
        assert evidence.value_count == 10

    def test_threshold_semantics(self) -> None:
        """Verify evidence correctly reflects pre-observation threshold semantics.

        With threshold=2:
        - count 0 + event → NEW (pre_count=0)
        - count 1 + event → RARE (pre_count=1 <= threshold)
        - count 2 + event → RARE (pre_count=2 == threshold)
        - count 3 + event → ESTABLISHED (pre_count=3 > threshold)
        """
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile with notepad.exe
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Test 1: count=0 → NEW_VALUE
        result1, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="new_app.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )
        assert result1.classification == BaselineClassification.BASELINE_NEW_VALUE
        assert result1.pre_observation_value_count == 0
        evidence1 = service.generate_evidence(result1)
        assert evidence1 is not None
        assert evidence1.value_count == 0
        assert evidence1.reason_code == BaselineReasonCode.VALUE_NEW

        # Test 2: count=1 → RARE_VALUE (1 <= 2)
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare_app.exe",
            timestamp=ts + timedelta(seconds=101),
            processing_time=ts + timedelta(seconds=101),
        )
        result2, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="rare_app.exe",
            timestamp=ts + timedelta(seconds=102),
            processing_time=ts + timedelta(seconds=102),
        )
        assert result2.classification == BaselineClassification.BASELINE_RARE_VALUE
        assert result2.pre_observation_value_count == 1
        evidence2 = service.generate_evidence(result2)
        assert evidence2 is not None
        assert evidence2.value_count == 1
        assert evidence2.reason_code == BaselineReasonCode.VALUE_COUNT_BELOW_THRESHOLD

        # Test 3: count=2 → RARE_VALUE (2 == threshold)
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="borderline.exe",
            timestamp=ts + timedelta(seconds=103),
            processing_time=ts + timedelta(seconds=103),
        )
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="borderline.exe",
            timestamp=ts + timedelta(seconds=104),
            processing_time=ts + timedelta(seconds=104),
        )
        result3, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="borderline.exe",
            timestamp=ts + timedelta(seconds=105),
            processing_time=ts + timedelta(seconds=105),
        )
        assert result3.classification == BaselineClassification.BASELINE_RARE_VALUE
        assert result3.pre_observation_value_count == 2
        evidence3 = service.generate_evidence(result3)
        assert evidence3 is not None
        assert evidence3.value_count == 2
        assert evidence3.reason_code == BaselineReasonCode.VALUE_COUNT_AT_THRESHOLD

        # Test 4: count=3 → ESTABLISHED (3 > 2)
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="established.exe",
            timestamp=ts + timedelta(seconds=106),
            processing_time=ts + timedelta(seconds=106),
        )
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="established.exe",
            timestamp=ts + timedelta(seconds=107),
            processing_time=ts + timedelta(seconds=107),
        )
        service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="established.exe",
            timestamp=ts + timedelta(seconds=108),
            processing_time=ts + timedelta(seconds=108),
        )
        result4, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="established.exe",
            timestamp=ts + timedelta(seconds=109),
            processing_time=ts + timedelta(seconds=109),
        )
        assert result4.classification == BaselineClassification.BASELINE_ESTABLISHED
        assert result4.pre_observation_value_count == 3
        evidence4 = service.generate_evidence(result4)
        assert evidence4 is not None
        assert evidence4.value_count == 3
        assert evidence4.reason_code == BaselineReasonCode.VALUE_ESTABLISHED

    def test_pre_observation_count_preserved(self) -> None:
        """Verify pre_observation_value_count is preserved in result."""
        service = EntityBehaviorService(
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Observe notepad.exe again (count=5 before recording)
        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        # Pre-observation count should be 5
        assert result.pre_observation_value_count == 5
        # Post-observation count should be 6
        assert result.observation_count == 6

        # Evidence should use pre-observation count
        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.value_count == 5  # pre-observation
        assert evidence.observation_count == 6  # post-observation

    def test_evidence_for_missing_profile(self) -> None:
        """Verify evidence generation for missing profile returns None."""
        service = EntityBehaviorService()

        # Query classification for non-existent profile
        classification = service.get_baseline_classification(
            entity_type="hostname",
            entity_id="nonexistent",
            dimension="process_name",
            dimension_value="notepad.exe",
        )

        # Should return None
        assert classification is None

        # Evidence generation should handle None gracefully
        evidence = service.generate_evidence_for_classification(
            entity_type="hostname",
            entity_id="nonexistent",
            dimension="process_name",
            dimension_value="notepad.exe",
        )
        assert evidence is None


class TestEvidenceOversizedValues:
    """Tests for oversized value handling in evidence."""

    def test_oversized_value_in_explanation(self) -> None:
        """Verify oversized values are handled in evidence."""
        service = EntityBehaviorService(
            max_value_length=128,
            maturity_min_observations=5,
            maturity_window_seconds=0.1,
            baseline_rare_threshold=2,
            baseline_stale_after_seconds=3600.0,
        )
        ts = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)

        # Build mature profile
        for i in range(5):
            service.classify_and_record(
                entity_type="hostname",
                entity_id="host1",
                dimension="process_name",
                dimension_value="notepad.exe",
                timestamp=ts + timedelta(seconds=i),
                processing_time=ts + timedelta(seconds=i),
            )

        # Add oversized value
        long_value = "a" * 200
        result, _ = service.classify_and_record(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value=long_value,
            timestamp=ts + timedelta(seconds=100),
            processing_time=ts + timedelta(seconds=100),
        )

        # Should not raise
        evidence = service.generate_evidence(result)
        assert evidence is not None
        assert evidence.classification == "baseline_new_value"

        # Verify serialization doesn't raise
        d = evidence.to_dict()
        assert "explanation" in d


class TestEvidenceEmptyProfile:
    """Tests for evidence with empty/missing profiles."""

    def test_evidence_for_missing_profile(self) -> None:
        """Verify evidence generation for missing profile returns None."""
        service = EntityBehaviorService()

        # Query classification for non-existent profile
        classification = service.get_baseline_classification(
            entity_type="hostname",
            entity_id="nonexistent",
            dimension="process_name",
            dimension_value="notepad.exe",
        )

        # Should return None
        assert classification is None

        # Evidence generation should handle None gracefully
        evidence = service.generate_evidence_for_classification(
            entity_type="hostname",
            entity_id="nonexistent",
            dimension="process_name",
            dimension_value="notepad.exe",
        )
        assert evidence is None
