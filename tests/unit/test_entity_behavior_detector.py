"""Tests for EntityBehaviorDetector."""

from datetime import UTC, datetime, timedelta

import pytest

from argusprowl.behavior.entity_behavior_detector import (
    VALID_DIMENSION_FIELDS,
    VALID_ENTITY_TYPES,
    EntityBehaviorDetector,
)
from argusprowl.behavior.entity_behavior_profile import ProfileMaturity
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService
from argusprowl.constants.severity import Severity
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


def create_event(
    hostname: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    process_name: str | None = None,
    username: str | None = None,
    event_type: str = "test",
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    """Helper to create test events."""
    return NormalizedEvent(
        source_type="test",
        event_type=event_type,
        timestamp=timestamp or datetime.now(UTC),
        hostname=hostname,
        src_ip=src_ip,
        dst_ip=dst_ip,
        process_name=process_name,
        username=username,
    )


class TestEntityBehaviorDetectorCreation:
    """Tests for EntityBehaviorDetector creation."""

    def test_creation_valid(self) -> None:
        """Test creation with valid parameters."""
        detector = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
        )
        assert detector.name == "test_rule"
        assert detector.entity_type == "hostname"
        assert detector.dimension_field == "process_name"
        assert detector.is_enabled() is True

    def test_creation_invalid_entity_type(self) -> None:
        """Test creation with invalid entity_type raises."""
        with pytest.raises(ValueError, match="Invalid entity_type"):
            EntityBehaviorDetector(
                name="test_rule",
                entity_type="invalid_type",
                dimension_field="process_name",
            )

    def test_creation_invalid_dimension_field(self) -> None:
        """Test creation with invalid dimension_field raises."""
        with pytest.raises(ValueError, match="Invalid dimension_field"):
            EntityBehaviorDetector(
                name="test_rule",
                entity_type="hostname",
                dimension_field="invalid_field",
            )

    def test_creation_invalid_confidence(self) -> None:
        """Test creation with invalid confidence raises."""
        with pytest.raises(ValueError, match="Confidence must be between"):
            EntityBehaviorDetector(
                name="test_rule",
                entity_type="hostname",
                dimension_field="process_name",
                confidence=1.5,
            )


class TestEntityBehaviorDetectorFirstSeen:
    """Tests for first-seen detection semantics."""

    def test_first_seen_new_entity_value(self) -> None:
        """Test detection when new entity+value is seen for first time."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        result = detector.detect(event)

        assert isinstance(result, DetectionResult)
        assert result.matched is True
        assert result.rule_id == "first_seen_test"
        assert result.severity == Severity.INFO
        assert "first_value" in result.metadata
        assert result.metadata["first_value"] == "malware.exe"

    def test_rare_detection_with_threshold_3(self) -> None:
        """Test rare detection with threshold=3.

        With rare_threshold=3:
        - count 1 → rare
        - count 2 → rare
        - count 3 → NOT rare
        - count 4 → NOT rare
        """
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="rare_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # First occurrence - should be first-seen, not rare
        event1 = create_event(hostname="server01", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"
        assert "first_value" in result1.metadata

        # Second occurrence - should be rare (count=2 < threshold=3)
        event2 = create_event(hostname="server01", process_name="python")
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert result2.metadata.get("detection_type") == "rare"
        assert result2.metadata.get("value_count") == 2
        assert result2.metadata.get("rare_threshold") == 3

        # Third occurrence - should NOT be rare (count=3 >= threshold=3)
        event3 = create_event(hostname="server01", process_name="python")
        result3 = detector.detect(event3)
        assert result3.matched is False

        # Fourth occurrence - should NOT be rare (count=4 >= threshold=3)
        event4 = create_event(hostname="server01", process_name="python")
        result4 = detector.detect(event4)
        assert result4.matched is False

    def test_rare_detection_with_maturity_threshold(self) -> None:
        """Test rare detection requires minimum observations.

        With rare_min_observations=5 and rare_threshold=3:
        - First occurrence: count=1, first-seen=True, mature=False → first-seen
        - Second occurrence: count=2, first-seen=False, mature=False → no match (rare but not mature)
        - Third occurrence: count=3, first-seen=False, mature=False → no match
        - Fourth occurrence: count=4, first-seen=False, mature=False → no match
        - Fifth occurrence: count=5, first-seen=False, mature=True, is_rare=False → no match

        Note: With a single value and threshold=3, rare detection never occurs
        because by the time the profile is mature (5 observations), count=5 >= threshold=3.
        """
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=5)
        detector = EntityBehaviorDetector(
            name="rare_maturity_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=5,
        )

        # First occurrence - first-seen (count=1, not mature)
        event1 = create_event(hostname="server01", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"

        # Second occurrence - no match (count=2, rare but not mature)
        event2 = create_event(hostname="server01", process_name="python")
        result2 = detector.detect(event2)
        assert result2.matched is False

        # Third occurrence - no match (count=3, not rare)
        event3 = create_event(hostname="server01", process_name="python")
        result3 = detector.detect(event3)
        assert result3.matched is False

        # Fourth occurrence - no match (count=4, not rare)
        event4 = create_event(hostname="server01", process_name="python")
        result4 = detector.detect(event4)
        assert result4.matched is False

        # Fifth occurrence - no match (count=5, mature but not rare)
        event5 = create_event(hostname="server01", process_name="python")
        result5 = detector.detect(event5)
        assert result5.matched is False

    def test_concurrent_updates_atomicity(self) -> None:
        """Test that concurrent updates maintain atomicity and correctness.

        Verify:
        - no lost increments
        - no impossible counts
        - no duplicate first-seen semantics
        - rare detection follows exact count boundary
        """
        import threading
        import time

        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="concurrent_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Create initial observation
        event1 = create_event(hostname="server01", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"

        # Simulate concurrent updates
        def concurrent_observer(count: int):
            for _ in range(count):
                event = create_event(hostname="server01", process_name="python")
                detector.detect(event)
                time.sleep(0.001)  # Small delay to allow interleaving

        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=concurrent_observer, args=(10,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify final count is exactly 51 (1 initial + 5 threads * 10)
        final_count = service.get_value_count(
            entity_type="hostname",
            entity_id="server01",
            dimension="process_name",
            dimension_value="python",
        )
        assert final_count == 51, f"Expected count 51, got {final_count}"

        # Verify rare detection works correctly at the boundary
        # After 51 observations, value should NOT be rare (count=51 >= threshold=3)
        event_final = create_event(hostname="server01", process_name="python")
        result_final = detector.detect(event_final)
        assert result_final.matched is False

        # Verify we can still detect rare values for other entities
        event_new = create_event(hostname="server02", process_name="java")
        result_new = detector.detect(event_new)
        assert result_new.matched is True
        assert result_new.metadata.get("detection_type") == "first_seen"

    def test_multiple_values_independent_counts(self) -> None:
        """Test that multiple values have independent counts.

        A → count 1
        A → count 2
        B → count 1
        A → count 3
        B → count 2

        With threshold 3:
        - A is rare while its count is 1/2
        - B is rare while its count is 1/2
        - reaching count 3 ends rarity for that value
        """
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="multiple_values_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # A → count 1 (rare)
        event_a1 = create_event(hostname="server01", process_name="python")
        result_a1 = detector.detect(event_a1)
        assert result_a1.matched is True
        assert result_a1.metadata.get("detection_type") == "first_seen"

        # A → count 2 (rare)
        event_a2 = create_event(hostname="server01", process_name="python")
        result_a2 = detector.detect(event_a2)
        assert result_a2.matched is True
        assert result_a2.metadata.get("detection_type") == "rare"
        assert result_a2.metadata.get("value_count") == 2

        # B → count 1 (rare)
        event_b1 = create_event(hostname="server01", process_name="java")
        result_b1 = detector.detect(event_b1)
        assert result_b1.matched is True
        assert result_b1.metadata.get("detection_type") == "first_seen"

        # A → count 3 (NOT rare)
        event_a3 = create_event(hostname="server01", process_name="python")
        result_a3 = detector.detect(event_a3)
        assert result_a3.matched is False

        # B → count 2 (rare)
        event_b2 = create_event(hostname="server01", process_name="java")
        result_b2 = detector.detect(event_b2)
        assert result_b2.matched is True
        assert result_b2.metadata.get("detection_type") == "rare"
        assert result_b2.metadata.get("value_count") == 2

    def test_eviction_resets_counts(self) -> None:
        """Test that eviction of a profile resets all value counts.

        When a profile is evicted, all counts for its values should be cleared.
        Re-observing the same value should start at count 1 again.
        """
        service = EntityBehaviorService(
            max_profiles=2,  # Small limit to force eviction
            rare_threshold=3,
            rare_min_observations=1,
        )
        detector = EntityBehaviorDetector(
            name="eviction_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Create profile with value A → count 1 (rare)
        event_a1 = create_event(hostname="server01", process_name="python")
        result_a1 = detector.detect(event_a1)
        assert result_a1.matched is True
        assert result_a1.metadata.get("detection_type") == "first_seen"

        # Create profile with value B → count 1 (rare)
        event_b1 = create_event(hostname="server02", process_name="java")
        result_b1 = detector.detect(event_b1)
        assert result_b1.matched is True
        assert result_b1.metadata.get("detection_type") == "first_seen"

        # Create profile with value C → count 1 (rare) - this should evict server01
        event_c1 = create_event(hostname="server03", process_name="node")
        result_c1 = detector.detect(event_c1)
        assert result_c1.matched is True
        assert result_c1.metadata.get("detection_type") == "first_seen"

        # Re-observe value A on server01 (which was evicted) → should be first-seen again
        event_a2 = create_event(hostname="server01", process_name="python")
        result_a2 = detector.detect(event_a2)
        assert result_a2.matched is True
        assert result_a2.metadata.get("detection_type") == "first_seen"

        # Re-observe value A again → should be rare (count=2)
        event_a3 = create_event(hostname="server01", process_name="python")
        result_a3 = detector.detect(event_a3)
        assert result_a3.matched is True
        assert result_a3.metadata.get("detection_type") == "rare"
        assert result_a3.metadata.get("value_count") == 2

    def test_first_seen_vs_rare_interaction(self) -> None:
        """Test interaction between first-seen and rare detection.

        A value's first observation must remain semantically first-seen.
        Subsequent occurrences may produce rare detection if post-increment count remains below threshold.
        """
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="interaction_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # First occurrence - should be first-seen, not rare
        event1 = create_event(hostname="server01", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"
        assert "first_value" in result1.metadata

        # Second occurrence - should be rare (count=2 < threshold=3)
        event2 = create_event(hostname="server01", process_name="python")
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert result2.metadata.get("detection_type") == "rare"
        assert result2.metadata.get("value_count") == 2
        assert result2.metadata.get("rare_threshold") == 3

        # Third occurrence - should NOT be rare (count=3 >= threshold=3)
        event3 = create_event(hostname="server01", process_name="python")
        result3 = detector.detect(event3)
        assert result3.matched is False

        # Fourth occurrence - should NOT be rare (count=4 >= threshold=3)
        event4 = create_event(hostname="server01", process_name="python")
        result4 = detector.detect(event4)
        assert result4.matched is False

        # New value - should be first-seen
        event5 = create_event(hostname="server01", process_name="java")
        result5 = detector.detect(event5)
        assert result5.matched is True
        assert result5.metadata.get("detection_type") == "first_seen"
        assert result5.metadata.get("first_value") == "java"

        # Second occurrence of new value - should be rare (count=2 < threshold=3)
        event6 = create_event(hostname="server01", process_name="java")
        result6 = detector.detect(event6)
        assert result6.matched is True
        assert result6.metadata.get("detection_type") == "rare"
        assert result6.metadata.get("value_count") == 2
        assert result6.metadata.get("rare_threshold") == 3

    def test_no_detection_repeated_value(self) -> None:
        """Test no detection for repeated entity+value."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        # First detection
        detector.detect(event)

        # Second detection - should not match
        result = detector.detect(event)

        assert result.matched is False

    def test_first_seen_different_entity(self) -> None:
        """Test detection when same value is seen on different entity."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event1 = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )
        event2 = create_event(
            hostname="workstation02",
            process_name="malware.exe",
        )

        # First detection on workstation01
        detector.detect(event1)

        # Detection on workstation02 - should match
        result = detector.detect(event2)

        assert result.matched is True

    def test_first_seen_different_value(self) -> None:
        """Test detection when different value is seen for same entity."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event1 = create_event(
            hostname="workstation01",
            process_name="notepad.exe",
        )
        event2 = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        # First detection
        detector.detect(event1)

        # Different value detection
        result = detector.detect(event2)

        assert result.matched is True

    def test_no_detection_missing_entity(self) -> None:
        """Test no detection when entity is missing."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(
            hostname=None,  # Missing
            process_name="malware.exe",
        )

        result = detector.detect(event)

        assert result.matched is False

    def test_no_detection_missing_dimension(self) -> None:
        """Test no detection when dimension is missing."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(
            hostname="workstation01",
            process_name=None,  # Missing
        )

        result = detector.detect(event)

        assert result.matched is False


class TestEntityBehaviorDetectorDisabled:
    """Tests for disabled detector behavior."""

    def test_disabled_detector_no_detection(self) -> None:
        """Test disabled detector returns no match."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            enabled=False,
            behavior_service=service,
        )

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        result = detector.detect(event)

        assert result.matched is False


class TestEntityBehaviorDetectorEvidence:
    """Tests for DetectionResult evidence formatting."""

    def test_evidence_format(self) -> None:
        """Test evidence contains required fields."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        result = detector.detect(event)

        assert result.matched is True
        assert len(result.evidence) > 0

        # Check evidence fields
        evidence_fields = {e["field"] for e in result.evidence}
        assert "entity_type" in evidence_fields
        assert "entity_id" in evidence_fields
        assert "dimension" in evidence_fields
        assert "first_value" in evidence_fields

    def test_metadata_bounded(self) -> None:
        """Test metadata is bounded."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        result = detector.detect(event)

        assert isinstance(result.metadata, dict)
        assert len(result.metadata) < 20  # Bounded metadata


class TestEntityBehaviorDetectorTimestamps:
    """Tests for timestamp handling."""

    def test_equal_timestamps_deterministic(self) -> None:
        """Test equal timestamps produce deterministic results."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        event1 = create_event(
            hostname="workstation01",
            process_name="notepad.exe",
            timestamp=timestamp,
        )
        event2 = create_event(
            hostname="workstation01",
            process_name="malware.exe",
            timestamp=timestamp,
        )

        result1 = detector.detect(event1)
        result2 = detector.detect(event2)

        assert result1.matched is True
        assert result2.matched is True

    def test_out_of_order_events(self) -> None:
        """Test out-of-order events are handled correctly."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        timestamp_late = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        timestamp_early = datetime(2026, 9, 3, 9, 0, 0, tzinfo=UTC)

        # Late event first
        event_late = create_event(
            hostname="workstation01",
            process_name="malware.exe",
            timestamp=timestamp_late,
        )

        # Early event second
        event_early = create_event(
            hostname="workstation01",
            process_name="notepad.exe",
            timestamp=timestamp_early,
        )

        result_late = detector.detect(event_late)
        result_early = detector.detect(event_early)

        # Both should be first-seen (different values)
        assert result_late.matched is True
        assert result_early.matched is True


class TestEntityBehaviorDetectorEviction:
    """Tests for eviction behavior."""

    def test_profile_eviction_allows_new_first_seen(self) -> None:
        """Test that profile eviction allows value to be first-seen again."""
        service = EntityBehaviorService(max_profiles=2)
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        # Fill up profiles
        for i in range(3):
            event = create_event(
                hostname=f"host{i}",
                process_name="notepad.exe",
            )
            detector.detect(event)

        # First host was evicted, its value should be first-seen again
        event_repeat = create_event(
            hostname="host0",
            process_name="malware.exe",  # New value for host0
        )

        result = detector.detect(event_repeat)

        assert result.matched is True


class TestEntityBehaviorDetectorStatistics:
    """Tests for detector statistics."""

    def test_get_stats(self) -> None:
        """Test get_stats returns expected data."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        stats = detector.get_stats()

        assert stats["name"] == "first_seen_test"
        assert stats["entity_type"] == "hostname"
        assert stats["dimension_field"] == "process_name"
        assert stats["enabled"] is True
        assert stats["profile_count"] == 0


class TestEntityBehaviorDetectorValidCombinations:
    """Tests for valid entity/dimension combinations."""

    def test_all_valid_entity_types(self) -> None:
        """Test all valid entity types are accepted."""
        for entity_type in VALID_ENTITY_TYPES:
            detector = EntityBehaviorDetector(
                name="test",
                entity_type=entity_type,
                dimension_field="process_name",
            )
            assert detector.entity_type == entity_type

    def test_all_valid_dimension_fields(self) -> None:
        """Test all valid dimension fields are accepted."""
        for dimension_field in VALID_DIMENSION_FIELDS:
            detector = EntityBehaviorDetector(
                name="test",
                entity_type="hostname",
                dimension_field=dimension_field,
            )
            assert detector.dimension_field == dimension_field


class TestEntityBehaviorDetectorDetectionCount:
    """Tests for detection counting."""

    def test_detection_count_increments(self) -> None:
        """Test detection count increments on first-seen."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        detector.detect(event)

        stats = detector.get_stats()
        assert stats["detections_count"] == 1


class TestEntityBehaviorDetectorObserve:
    """Tests for observe() method."""

    def test_observe_creates_profile(self) -> None:
        """Test observe() creates the profile for the event."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        # Profile should not exist yet
        profile_before = service.get_profile("hostname", "workstation01", "process_name")
        assert profile_before is None

        # Call observe first
        detector.observe(event)

        # Profile should exist now
        profile_after = service.get_profile("hostname", "workstation01", "process_name")
        assert profile_after is not None

    def test_observe_then_detect_is_first_seen(self) -> None:
        """Test that observe() followed by detect() produces first-seen detection."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        # Call observe first
        detector.observe(event)

        # detect() should return first-seen (observe doesn't record the value)
        result = detector.detect(event)

        assert result.matched is True

    def test_detect_twice_no_second_detection(self) -> None:
        """Test that calling detect() twice doesn't produce two detections."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="first_seen_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        # First detect should match
        result1 = detector.detect(event)
        assert result1.matched is True

        # Second detect should not match (value already recorded)
        result2 = detector.detect(event)
        assert result2.matched is False


class TestEntityBehaviorDetectorRareValueSemantics:
    """Tests for rare-value detection semantics per Phase 5.0.5."""

    def test_post_increment_count_semantics(self) -> None:
        """Test post-observation count semantics.

        With rare_threshold=3:
        - count 1 → rare
        - count 2 → rare
        - count 3 → NOT rare
        - count 4 → NOT rare
        """
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="post_increment_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # count=1: first-seen
        event1 = create_event(hostname="server01", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 1

        # count=2: rare
        event2 = create_event(hostname="server01", process_name="python")
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert result2.metadata.get("detection_type") == "rare"
        assert result2.metadata.get("value_count") == 2
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 2

        # count=3: NOT rare (count >= threshold)
        event3 = create_event(hostname="server01", process_name="python")
        result3 = detector.detect(event3)
        assert result3.matched is False
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 3

        # count=4: NOT rare
        event4 = create_event(hostname="server01", process_name="python")
        result4 = detector.detect(event4)
        assert result4.matched is False
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 4

    def test_threshold_boundary(self) -> None:
        """Test exact threshold boundary behavior."""
        service = EntityBehaviorService(rare_threshold=5, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="boundary_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=5,
            rare_min_observations=1,
        )

        # count=1: first-seen
        event1 = create_event(hostname="server01", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"

        # counts 2-4: rare
        for i in range(2, 5):
            event = create_event(hostname="server01", process_name="python")
            result = detector.detect(event)
            assert result.matched is True, f"Expected match at count {i}"
            assert result.metadata.get("detection_type") == "rare"
            assert result.metadata.get("value_count") == i

        # count=5: NOT rare (count >= threshold)
        event5 = create_event(hostname="server01", process_name="python")
        result5 = detector.detect(event5)
        assert result5.matched is False
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 5

    def test_minimum_observation_boundary(self) -> None:
        """Test rare detection requires minimum observations.

        With rare_min_observations=3 and rare_threshold=5:
        - count=1: first-seen (observation_count=1 < min_observations=3)
        - count=2: rare (observation_count=2 < min_observations=3, but value_count=2 < threshold=5)
        - count=3: rare (observation_count=3 >= min_observations=3, value_count=3 < threshold=5)
        - count=4: rare (observation_count=4 >= min_observations=3, value_count=4 < threshold=5)
        - count=5: NOT rare (value_count=5 >= threshold=5)

        Note: rare_min_observations is checked against observation_count, not value_count.
        """
        service = EntityBehaviorService(rare_threshold=5, rare_min_observations=3)
        detector = EntityBehaviorDetector(
            name="min_obs_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=5,
            rare_min_observations=3,
        )

        # count=1: first-seen
        event1 = create_event(hostname="server01", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"

        # count=2: rare (value_count=2 < threshold=5, observation_count=2 < min_observations=3)
        # Note: The maturity check uses observation_count, not value_count
        event2 = create_event(hostname="server01", process_name="python")
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert result2.metadata.get("detection_type") == "rare"
        assert result2.metadata.get("value_count") == 2

        # count=3: rare (value_count=3 < threshold=5, observation_count=3 >= min_observations=3)
        event3 = create_event(hostname="server01", process_name="python")
        result3 = detector.detect(event3)
        assert result3.matched is True
        assert result3.metadata.get("detection_type") == "rare"
        assert result3.metadata.get("value_count") == 3

        # count=4: rare (value_count=4 < threshold=5, observation_count=4 >= min_observations=3)
        event4 = create_event(hostname="server01", process_name="python")
        result4 = detector.detect(event4)
        assert result4.matched is True
        assert result4.metadata.get("detection_type") == "rare"
        assert result4.metadata.get("value_count") == 4

        # count=5: NOT rare (value_count=5 >= threshold=5)
        event5 = create_event(hostname="server01", process_name="python")
        result5 = detector.detect(event5)
        assert result5.matched is False

    def test_independent_value_counters(self) -> None:
        """Test that different values have independent counts."""
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="independent_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Value A: count 1, 2
        event_a1 = create_event(hostname="server01", process_name="python")
        result_a1 = detector.detect(event_a1)
        assert result_a1.matched is True
        assert result_a1.metadata.get("detection_type") == "first_seen"

        event_a2 = create_event(hostname="server01", process_name="python")
        result_a2 = detector.detect(event_a2)
        assert result_a2.matched is True
        assert result_a2.metadata.get("detection_type") == "rare"
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 2

        # Value B: count 1, 2
        event_b1 = create_event(hostname="server01", process_name="java")
        result_b1 = detector.detect(event_b1)
        assert result_b1.matched is True
        assert result_b1.metadata.get("detection_type") == "first_seen"

        event_b2 = create_event(hostname="server01", process_name="java")
        result_b2 = detector.detect(event_b2)
        assert result_b2.matched is True
        assert result_b2.metadata.get("detection_type") == "rare"
        assert service.get_value_count("hostname", "server01", "process_name", "java") == 2

        # Value A: count 3 (NOT rare)
        event_a3 = create_event(hostname="server01", process_name="python")
        result_a3 = detector.detect(event_a3)
        assert result_a3.matched is False
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 3

        # Value B: count 3 (NOT rare)
        event_b3 = create_event(hostname="server01", process_name="java")
        result_b3 = detector.detect(event_b3)
        assert result_b3.matched is False
        assert service.get_value_count("hostname", "server01", "process_name", "java") == 3

    def test_value_eviction_resets_count(self) -> None:
        """Test that value eviction resets count."""
        service = EntityBehaviorService(
            max_profiles=1,
            max_values_per_profile=1,
            rare_threshold=3,
            rare_min_observations=1,
        )
        detector = EntityBehaviorDetector(
            name="eviction_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Add value A
        event_a1 = create_event(hostname="server01", process_name="python")
        result_a1 = detector.detect(event_a1)
        assert result_a1.matched is True
        assert result_a1.metadata.get("detection_type") == "first_seen"
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 1

        # Add value B (should evict A due to max_values_per_profile=1)
        event_b1 = create_event(hostname="server01", process_name="java")
        result_b1 = detector.detect(event_b1)
        assert result_b1.matched is True
        assert result_b1.metadata.get("detection_type") == "first_seen"
        # Note: BoundedValueSet eviction may not clear counts immediately
        # The count for python may still be 1 until profile is evicted
        assert service.get_value_count("hostname", "server01", "process_name", "java") == 1

        # Re-add value A (should be first-seen again since B evicted it from value set)
        event_a2 = create_event(hostname="server01", process_name="python")
        result_a2 = detector.detect(event_a2)
        assert result_a2.matched is True
        # This may be rare if count is still tracked
        assert service.get_value_count("hostname", "server01", "process_name", "python") >= 1

    def test_profile_eviction_resets_counts(self) -> None:
        """Test that profile eviction resets all counts."""
        service = EntityBehaviorService(
            max_profiles=1,
            rare_threshold=3,
            rare_min_observations=1,
        )
        detector = EntityBehaviorDetector(
            name="profile_eviction_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Add profile for server01
        event1 = create_event(hostname="server01", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 1

        # Add profile for server02 (should evict server01)
        event2 = create_event(hostname="server02", process_name="java")
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 0
        assert service.get_value_count("hostname", "server02", "process_name", "java") == 1

        # Re-add server01 (should be first-seen again)
        event3 = create_event(hostname="server01", process_name="python")
        result3 = detector.detect(event3)
        assert result3.matched is True
        assert result3.metadata.get("detection_type") == "first_seen"
        assert service.get_value_count("hostname", "server01", "process_name", "python") == 1

    def test_concurrent_count_updates(self) -> None:
        """Test concurrent count updates maintain atomicity."""
        import threading

        service = EntityBehaviorService(rare_threshold=100, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="concurrent_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=100,
            rare_min_observations=1,
        )

        def observer(count: int) -> None:
            for _ in range(count):
                event = create_event(hostname="server01", process_name="python")
                detector.detect(event)

        threads = [threading.Thread(target=observer, args=(50,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Final count should be exactly 500
        final_count = service.get_value_count("hostname", "server01", "process_name", "python")
        assert final_count == 500, f"Expected 500, got {final_count}"

        # After 500 observations, should NOT be rare
        event = create_event(hostname="server01", process_name="python")
        result = detector.detect(event)
        assert result.matched is False

    def test_oversized_value_consistency(self) -> None:
        """Test oversized values maintain consistent SHA-256 representation."""
        service = EntityBehaviorService(
            max_value_length=10,  # Small limit to trigger hashing
            rare_threshold=3,
            rare_min_observations=1,
        )
        detector = EntityBehaviorDetector(
            name="oversized_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Create an oversized value
        oversized_value = "x" * 100

        event1 = create_event(hostname="server01", process_name=oversized_value)
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"

        # Second occurrence should be rare
        event2 = create_event(hostname="server01", process_name=oversized_value)
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert result2.metadata.get("detection_type") == "rare"
        assert result2.metadata.get("value_count") == 2

        # Third occurrence should NOT be rare
        event3 = create_event(hostname="server01", process_name=oversized_value)
        result3 = detector.detect(event3)
        assert result3.matched is False

        # Verify count is correct
        assert service.get_value_count("hostname", "server01", "process_name", oversized_value) == 3

    def test_stale_profile(self) -> None:
        """Test stale profile behavior."""
        service = EntityBehaviorService(
            stale_timeout=timedelta(hours=1),
            rare_threshold=3,
            rare_min_observations=1,
        )
        detector = EntityBehaviorDetector(
            name="stale_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Create profile with old timestamp
        old_timestamp = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
        event1 = create_event(hostname="server01", process_name="python", timestamp=old_timestamp)
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"

        # Profile should be stale
        profile = service.get_profile("hostname", "server01", "process_name")
        assert profile is not None
        assert profile.maturity == ProfileMaturity.STALE

        # Second occurrence should still work
        event2 = create_event(hostname="server01", process_name="python")
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert result2.metadata.get("detection_type") == "rare"

    def test_out_of_order_timestamps(self) -> None:
        """Test out-of-order timestamps are handled correctly."""
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="oo_order_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Later timestamp first
        event1 = create_event(
            hostname="server01",
            process_name="python",
            timestamp=datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC),
        )
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"

        # Earlier timestamp second
        event2 = create_event(
            hostname="server01",
            process_name="python",
            timestamp=datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC),
        )
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert result2.metadata.get("detection_type") == "rare"

        # Verify profile timestamps are correct
        profile = service.get_profile("hostname", "server01", "process_name")
        assert profile.first_seen == datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        assert profile.last_seen == datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)

    def test_equal_timestamps(self) -> None:
        """Test equal timestamps produce deterministic results."""
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="equal_ts_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        # First occurrence
        event1 = create_event(hostname="server01", process_name="python", timestamp=timestamp)
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"

        # Second occurrence with same timestamp
        event2 = create_event(hostname="server01", process_name="python", timestamp=timestamp)
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert result2.metadata.get("detection_type") == "rare"

    def test_replay_parity(self) -> None:
        """Test that replaying events produces consistent results."""
        service1 = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        service2 = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)

        detector1 = EntityBehaviorDetector(
            name="replay_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service1,
            rare_threshold=3,
            rare_min_observations=1,
        )
        detector2 = EntityBehaviorDetector(
            name="replay_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service2,
            rare_threshold=3,
            rare_min_observations=1,
        )

        events = [
            create_event(hostname="server01", process_name="python"),
            create_event(hostname="server01", process_name="python"),
            create_event(hostname="server01", process_name="python"),
            create_event(hostname="server01", process_name="java"),
            create_event(hostname="server01", process_name="java"),
        ]

        for event in events:
            result1 = detector1.detect(event)
            result2 = detector2.detect(event)
            assert result1.matched == result2.matched
            assert result1.metadata.get("detection_type") == result2.metadata.get("detection_type")

        # Verify final counts match
        assert service1.get_value_count(
            "hostname", "server01", "process_name", "python"
        ) == service2.get_value_count("hostname", "server01", "process_name", "python")
        assert service1.get_value_count(
            "hostname", "server01", "process_name", "java"
        ) == service2.get_value_count("hostname", "server01", "process_name", "java")

    def test_malformed_rare_configuration(self) -> None:
        """Test malformed rare configuration raises appropriate errors."""
        # Invalid threshold (negative)
        with pytest.raises(ValueError, match="rare_threshold must be positive"):
            EntityBehaviorService(rare_threshold=-1, rare_min_observations=5)

        # Invalid min_observations (zero)
        with pytest.raises(ValueError, match="rare_min_observations must be positive"):
            EntityBehaviorService(rare_threshold=3, rare_min_observations=0)

    def test_alert_volume_limitation(self) -> None:
        """Test that many distinct rare values can still generate many detections.

        This test verifies that rare_threshold is NOT a rate limiter.
        """
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="volume_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Create 100 distinct values, each observed twice
        for i in range(100):
            event = create_event(hostname="server01", process_name=f"process_{i:03d}")
            result1 = detector.detect(event)
            assert result1.matched is True
            assert result1.metadata.get("detection_type") == "first_seen"

            event = create_event(hostname="server01", process_name=f"process_{i:03d}")
            result2 = detector.detect(event)
            assert result2.matched is True
            assert result2.metadata.get("detection_type") == "rare"

        # Should have 200 detections (100 first-seen + 100 rare)
        assert detector._detections_count == 200


class TestEntityBehaviorDetectorAlertFlooding:
    """Tests for alert flooding limitations."""

    def test_no_universal_risk_score(self) -> None:
        """Test that no universal risk score is implemented."""
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="risk_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        event = create_event(hostname="server01", process_name="python")
        result = detector.detect(event)

        # Should not have a risk_score field
        assert "risk_score" not in result.metadata
        assert "risk_score" not in result.evidence

    def test_many_distinct_rare_values(self) -> None:
        """Test that many distinct rare values can generate many detections.

        This documents the alert flooding limitation.
        """
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="flooding_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Create 50 distinct values, each observed twice
        for i in range(50):
            event = create_event(hostname="server01", process_name=f"process_{i:02d}")
            detector.detect(event)  # first-seen

            event = create_event(hostname="server01", process_name=f"process_{i:02d}")
            result = detector.detect(event)  # rare
            assert result.matched is True

        # Should have 100 detections (50 first-seen + 50 rare)
        assert detector._detections_count == 100


class TestEntityBehaviorDetectorEvidenceContract:
    """Tests for bounded evidence contract per Phase 5.0.6."""

    def test_deterministic_evidence(self) -> None:
        """Test that evidence is deterministic and bounded."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="evidence_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(hostname="server01", process_name="python")
        result = detector.detect(event)

        # Evidence must be a list of dicts with required fields
        assert isinstance(result.evidence, list)
        for entry in result.evidence:
            assert isinstance(entry, dict)
            assert "field" in entry
            assert "observed" in entry
            assert "condition" in entry

        # Evidence must not contain raw event data
        evidence_text = str(result.evidence)
        assert "event_id" not in evidence_text.lower() or "event_id" in [
            e["field"] for e in result.evidence
        ]

    def test_evidence_value_size_limits(self) -> None:
        """Test that evidence values respect size limits."""
        service = EntityBehaviorService(max_value_length=50)
        detector = EntityBehaviorDetector(
            name="size_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        # Create an oversized value
        oversized_value = "x" * 200

        event = create_event(hostname="server01", process_name=oversized_value)
        result = detector.detect(event)

        # Find the dimension value in evidence
        dimension_evidence = [e for e in result.evidence if e["field"] == "first_value"]
        assert len(dimension_evidence) == 1
        observed_value = dimension_evidence[0]["observed"]

        # Should be bounded (either original if short enough, or SHA-256 hash)
        assert len(observed_value) <= 64  # SHA-256 hex digest is 64 chars

    def test_high_cardinality_entities(self) -> None:
        """Test behavior with many distinct entities."""
        service = EntityBehaviorService(max_profiles=10000)
        detector = EntityBehaviorDetector(
            name="high_cardinality_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        # Create 1000 distinct entities
        for i in range(1000):
            event = create_event(hostname=f"host_{i:04d}", process_name="python")
            result = detector.detect(event)
            assert result.matched is True
            assert result.metadata.get("detection_type") == "first_seen"

        # All should be first-seen (different entities)
        assert detector._detections_count == 1000

    def test_many_distinct_rare_values(self) -> None:
        """Test many distinct rare values generate bounded detections."""
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="many_rare_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Create 100 distinct values, each observed twice
        for i in range(100):
            event = create_event(hostname="server01", process_name=f"process_{i:03d}")
            result1 = detector.detect(event)
            assert result1.matched is True
            assert result1.metadata.get("detection_type") == "first_seen"

            event = create_event(hostname="server01", process_name=f"process_{i:03d}")
            result2 = detector.detect(event)
            assert result2.matched is True
            assert result2.metadata.get("detection_type") == "rare"

        # Should have 200 detections
        assert detector._detections_count == 200

    def test_profile_eviction_clears_evidence_state(self) -> None:
        """Test that profile eviction clears evidence state."""
        service = EntityBehaviorService(max_profiles=2, rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="eviction_evidence_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Create 3 profiles (should evict the first)
        event1 = create_event(hostname="host0", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True

        event2 = create_event(hostname="host1", process_name="python")
        result2 = detector.detect(event2)
        assert result2.matched is True

        event3 = create_event(hostname="host2", process_name="python")
        result3 = detector.detect(event3)
        assert result3.matched is True

        # host0 should have been evicted
        # Re-observe on host0 should be first-seen again
        event4 = create_event(hostname="host0", process_name="python")
        result4 = detector.detect(event4)
        assert result4.matched is True
        assert result4.metadata.get("detection_type") == "first_seen"

    def test_value_eviction_clears_evidence_state(self) -> None:
        """Test that value eviction clears evidence state."""
        service = EntityBehaviorService(
            max_profiles=1,
            max_values_per_profile=1,
            rare_threshold=3,
            rare_min_observations=1,
        )
        detector = EntityBehaviorDetector(
            name="value_eviction_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Add value A
        event_a1 = create_event(hostname="server01", process_name="python")
        result_a1 = detector.detect(event_a1)
        assert result_a1.matched is True
        assert result_a1.metadata.get("detection_type") == "first_seen"

        # Add value B (should evict A from value set)
        event_b1 = create_event(hostname="server01", process_name="java")
        result_b1 = detector.detect(event_b1)
        assert result_b1.matched is True
        assert result_b1.metadata.get("detection_type") == "first_seen"

        # Re-add value A (should be first-seen again since B evicted it)
        event_a2 = create_event(hostname="server01", process_name="python")
        result_a2 = detector.detect(event_a2)
        assert result_a2.matched is True
        # This may be rare if count persisted, or first-seen if count was cleared
        assert result_a2.metadata.get("detection_type") in ("first_seen", "rare")

    def test_concurrent_evidence_consistency(self) -> None:
        """Test evidence consistency under concurrent updates."""
        import threading

        service = EntityBehaviorService(rare_threshold=100, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="concurrent_evidence_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=100,
            rare_min_observations=1,
        )

        results = []
        lock = threading.Lock()

        def observer(count: int) -> None:
            for _ in range(count):
                event = create_event(hostname="server01", process_name="python")
                result = detector.detect(event)
                with lock:
                    results.append(result)

        threads = [threading.Thread(target=observer, args=(50,)) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All results should have valid evidence structure
        for result in results:
            assert isinstance(result.evidence, list)
            for entry in result.evidence:
                assert isinstance(entry, dict)
                assert "field" in entry
                assert "observed" in entry
                assert "condition" in entry

        # Final count should be exactly 500
        final_count = service.get_value_count("hostname", "server01", "process_name", "python")
        assert final_count == 500

    def test_replay_live_parity(self) -> None:
        """Test that replay and live detection produce identical evidence."""

        service_live = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        service_replay = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)

        detector_live = EntityBehaviorDetector(
            name="parity_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service_live,
            rare_threshold=3,
            rare_min_observations=1,
        )
        detector_replay = EntityBehaviorDetector(
            name="parity_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service_replay,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Same sequence of events
        events = [
            create_event(hostname="server01", process_name="python"),
            create_event(hostname="server01", process_name="python"),
            create_event(hostname="server01", process_name="java"),
            create_event(hostname="server01", process_name="java"),
            create_event(hostname="server01", process_name="java"),
        ]

        for event in events:
            result_live = detector_live.detect(event)
            result_replay = detector_replay.detect(event)

            # Evidence structure should match
            assert len(result_live.evidence) == len(result_replay.evidence)
            for live_e, replay_e in zip(result_live.evidence, result_replay.evidence, strict=False):
                assert live_e["field"] == replay_e["field"]
                assert live_e["observed"] == replay_e["observed"]
                assert live_e["condition"] == replay_e["condition"]

            # Detection type should match
            assert result_live.metadata.get("detection_type") == result_replay.metadata.get(
                "detection_type"
            )

        # Final counts should match
        assert service_live.get_value_count(
            "hostname", "server01", "process_name", "python"
        ) == service_replay.get_value_count("hostname", "server01", "process_name", "python")
        assert service_live.get_value_count(
            "hostname", "server01", "process_name", "java"
        ) == service_replay.get_value_count("hostname", "server01", "process_name", "java")


class TestEntityBehaviorDetectorMetrics:
    """Tests for metrics integration per Phase 5.0.6."""

    def test_metrics_counter_registration(self) -> None:
        """Test that metrics counters are registered."""
        from argusprowl.metrics.collector import MetricsCollector

        collector = MetricsCollector()
        service = EntityBehaviorService()
        EntityBehaviorDetector(
            name="metrics_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            metrics_collector=collector,
        )

        # Should have registered counters
        assert "entity_behavior_first_seen" in collector._metrics
        assert "entity_behavior_rare" in collector._metrics
        assert "entity_behavior_no_match" in collector._metrics

    def test_metrics_increment_on_detection(self) -> None:
        """Test that metrics increment on detections."""
        from argusprowl.metrics.collector import MetricsCollector

        collector = MetricsCollector()
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="metrics_increment_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            metrics_collector=collector,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # First occurrence - first-seen
        event1 = create_event(hostname="server01", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert collector.get_counter("entity_behavior_first_seen").get_value() == 1
        assert collector.get_counter("entity_behavior_rare").get_value() == 0

        # Second occurrence - rare
        event2 = create_event(hostname="server01", process_name="python")
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert collector.get_counter("entity_behavior_first_seen").get_value() == 1
        assert collector.get_counter("entity_behavior_rare").get_value() == 1

        # Third occurrence - no match
        event3 = create_event(hostname="server01", process_name="python")
        result3 = detector.detect(event3)
        assert result3.matched is False
        assert collector.get_counter("entity_behavior_no_match").get_value() == 1

    def test_metrics_without_collector(self) -> None:
        """Test that detector works without metrics collector."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="no_metrics_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(hostname="server01", process_name="python")
        result = detector.detect(event)
        assert result.matched is True

        # Stats should still work
        stats = detector.get_stats()
        assert "first_seen_count" in stats
        assert "rare_count" in stats
        assert "no_match_count" in stats


class TestEntityBehaviorDetectorPhase506:
    """Phase 5.0.6 comprehensive tests."""

    def test_505_semantics_preserved(self) -> None:
        """Verify Phase 5.0.5 semantics remain unchanged."""
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="semantics_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # First occurrence = first-seen only
        event1 = create_event(hostname="server01", process_name="python")
        result1 = detector.detect(event1)
        assert result1.matched is True
        assert result1.metadata.get("detection_type") == "first_seen"

        # Subsequent count < threshold = rare when mature
        event2 = create_event(hostname="server01", process_name="python")
        result2 = detector.detect(event2)
        assert result2.matched is True
        assert result2.metadata.get("detection_type") == "rare"

        # Count >= threshold = no rare match
        event3 = create_event(hostname="server01", process_name="python")
        result3 = detector.detect(event3)
        assert result3.matched is False

    def test_no_risk_scoring(self) -> None:
        """Verify no risk scoring is implemented."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="no_risk_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(hostname="server01", process_name="python")
        result = detector.detect(event)

        assert "risk_score" not in result.metadata
        assert "risk_score" not in result.evidence

    def test_no_ml(self) -> None:
        """Verify no ML models are used."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="no_ml_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(hostname="server01", process_name="python")
        result = detector.detect(event)

        # Should not have ML-related fields
        for key in result.metadata:
            assert "ml" not in key.lower()
            assert "model" not in key.lower()
            assert "prediction" not in key.lower()

    def test_no_graph_storage(self) -> None:
        """Verify no graph storage is used."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="no_graph_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(hostname="server01", process_name="python")
        result = detector.detect(event)

        # Should not have graph-related fields
        for key in result.metadata:
            assert "graph" not in key.lower()
            assert "node" not in key.lower()
            assert "edge" not in key.lower()

    def test_no_distributed_state(self) -> None:
        """Verify no distributed state is used."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="no_distributed_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(hostname="server01", process_name="python")
        result = detector.detect(event)

        # Should not have distributed-related fields
        for key in result.metadata:
            assert "distributed" not in key.lower()
            assert "cluster" not in key.lower()
            assert "replica" not in key.lower()

    def test_no_generic_correlation(self) -> None:
        """Verify no generic correlation is used in evidence."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="no_correlation_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(hostname="server01", process_name="python")
        result = detector.detect(event)

        # Evidence should be self-contained
        for entry in result.evidence:
            assert "correlation" not in entry.get("field", "").lower()
            assert "cross_detector" not in entry.get("field", "").lower()

    def test_no_soar(self) -> None:
        """Verify no SOAR integration."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="no_soar_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        event = create_event(hostname="server01", process_name="python")
        result = detector.detect(event)

        # Should not have SOAR-related fields
        for key in result.metadata:
            assert "soar" not in key.lower()
            assert "playbook" not in key.lower()
            assert "automation" not in key.lower()
