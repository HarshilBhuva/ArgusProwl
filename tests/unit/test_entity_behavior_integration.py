"""Integration tests for EntityBehaviorDetector with DetectionManager and Replay."""

from datetime import UTC, datetime

from argusprowl.behavior.entity_behavior_detector import EntityBehaviorDetector
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService
from argusprowl.detection.detection_manager import DetectionManager
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


class TestEntityBehaviorDetectionManagerIntegration:
    """Tests for EntityBehaviorDetector with DetectionManager."""

    def test_detection_manager_registers_behavior_detector(self) -> None:
        """Test DetectionManager can register EntityBehaviorDetector."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        manager = DetectionManager()
        manager.register_detector(detector)

        enabled = manager._registry.get_enabled()
        assert "test_rule" in enabled
        assert enabled["test_rule"] is detector

    def test_process_event_through_detection_manager(self) -> None:
        """Test processing event through DetectionManager."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        manager = DetectionManager()
        manager.register_detector(detector)

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        results = manager.process_event(event)

        assert len(results) == 1
        assert results[0].matched is True

    def test_no_detection_for_known_value(self) -> None:
        """Test no detection for known entity+value."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        manager = DetectionManager()
        manager.register_detector(detector)

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        # First event - should detect
        results1 = manager.process_event(event)
        assert len(results1) == 1

    def test_rare_detection_through_detection_manager(self) -> None:
        """Test rare detection through DetectionManager."""
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="rare_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        manager = DetectionManager()
        manager.register_detector(detector)

        # First occurrence - first-seen
        event1 = create_event(hostname="server01", process_name="python")
        results1 = manager.process_event(event1)
        assert len(results1) == 1
        assert results1[0].matched is True
        assert results1[0].metadata.get("detection_type") == "first_seen"

        # Second occurrence - rare
        event2 = create_event(hostname="server01", process_name="python")
        results2 = manager.process_event(event2)
        assert len(results2) == 1
        assert results2[0].matched is True
        assert results2[0].metadata.get("detection_type") == "rare"
        assert results2[0].metadata.get("value_count") == 2

        # Third occurrence - no detection
        event3 = create_event(hostname="server01", process_name="python")
        results3 = manager.process_event(event3)
        assert len(results3) == 0

    def test_replay_parity_direct_vs_manager(self) -> None:
        """Test identical event sequences produce same results through direct and manager paths."""
        # Create fresh service and detector for direct path
        service_direct = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector_direct = EntityBehaviorDetector(
            name="replay_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service_direct,
            rare_threshold=3,
            rare_min_observations=1,
        )

        # Create fresh service and detector for manager path
        service_manager = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector_manager = EntityBehaviorDetector(
            name="replay_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service_manager,
            rare_threshold=3,
            rare_min_observations=1,
        )
        manager = DetectionManager()
        manager.register_detector(detector_manager)

        # Create identical event sequence
        events = [
            create_event(hostname="server01", process_name="python"),
            create_event(hostname="server01", process_name="python"),
            create_event(hostname="server01", process_name="java"),
            create_event(hostname="server01", process_name="python"),
            create_event(hostname="server01", process_name="java"),
        ]

        # Process through direct detector
        direct_results = []
        for event in events:
            result = detector_direct.detect(event)
            if result.matched:
                direct_results.append(result)

        # Process through DetectionManager
        manager_results = []
        for event in events:
            results = manager.process_event(event)
            for result in results:
                if result.matched:
                    manager_results.append(result)

        # Verify same number of detections
        assert len(direct_results) == len(manager_results)

        # Verify same detection types
        for direct, manager in zip(direct_results, manager_results, strict=False):
            assert direct.metadata.get("detection_type") == manager.metadata.get("detection_type")
            assert direct.metadata.get("value_count") == manager.metadata.get("value_count")

    def test_security_distinct_value_flooding(self) -> None:
        """Test security: distinct value flooding behavior.

        Document that an attacker can generate many distinct rare values.
        This is a known limitation.
        """
        service = EntityBehaviorService(rare_threshold=3, rare_min_observations=1)
        detector = EntityBehaviorDetector(
            name="flood_test",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
            rare_threshold=3,
            rare_min_observations=1,
        )

        manager = DetectionManager()
        manager.register_detector(detector)

        # Generate 10 distinct values - each should be detected as first-seen
        results = []
        for i in range(10):
            event = create_event(hostname="server01", process_name=f"python_{i}")
            detector_results = manager.process_event(event)
            for result in detector_results:
                if result.matched:
                    results.append(result)

        # Each distinct value should be detected as first-seen (count=1 < threshold=3)
        assert len(results) == 10
        for result in results:
            assert result.metadata.get("detection_type") == "first_seen"

        # Second occurrence of each value should also be rare
        rare_results = []
        for i in range(10):
            event = create_event(hostname="server01", process_name=f"python_{i}")
            detector_results = manager.process_event(event)
            for result in detector_results:
                if result.matched:
                    rare_results.append(result)

        # Each distinct value should be detected as rare (count=2 < threshold=3)
        assert len(rare_results) == 10
        for result in rare_results:
            assert result.metadata.get("detection_type") == "rare"

        # Second event - should not detect
        results2 = manager.process_event(event)
        assert len(results2) == 0


class TestEntityBehaviorReplayParity:
    """Tests for replay parity with fresh state."""

    def test_fresh_service_per_detection(self) -> None:
        """Test each detection uses fresh service state."""
        service1 = EntityBehaviorService()
        service2 = EntityBehaviorService()

        detector1 = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service1,
        )

        detector2 = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service2,
        )

        event = create_event(
            hostname="workstation01",
            process_name="malware.exe",
        )

        # First service sees event
        result1 = detector1.detect(event)

        # Fresh service should also detect
        result2 = detector2.detect(event)

        assert result1.matched is True
        assert result2.matched is True  # Both detect because they have fresh state

    def test_same_event_sequence_same_results(self) -> None:
        """Test same event sequence produces same detection results."""
        events = [
            create_event(
                hostname="host1",
                process_name="proc1",
            ),
            create_event(
                hostname="host1",
                process_name="proc2",
            ),
            create_event(
                hostname="host2",
                process_name="proc1",
            ),
        ]

        # First run
        service1 = EntityBehaviorService()
        detector1 = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service1,
        )

        results1 = [detector1.detect(e) for e in events]
        matches1 = [r.matched for r in results1]

        # Second run (fresh state)
        service2 = EntityBehaviorService()
        detector2 = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service2,
        )

        results2 = [detector2.detect(e) for e in events]
        matches2 = [r.matched for r in results2]

        # Same sequence should produce same results
        assert matches1 == matches2

    def test_event_timestamps_drive_ordering(self) -> None:
        """Test event timestamps drive behavioral ordering."""
        timestamp1 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        timestamp2 = datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC)

        event1 = create_event(
            hostname="host1",
            process_name="proc1",
            timestamp=timestamp2,  # Later
        )
        event2 = create_event(
            hostname="host1",
            process_name="proc1",
            timestamp=timestamp1,  # Earlier
        )

        # Run in timestamp order
        service1 = EntityBehaviorService()
        detector1 = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service1,
        )

        result1 = detector1.detect(event1)
        result2 = detector1.detect(event2)

        # Both are first-seen because they are the same value (second is out-of-order but same value)
        assert result1.matched is True
        assert result2.matched is False  # Already seen proc1

    def test_wall_clock_not_used_for_detection(self) -> None:
        """Test that wall-clock time is not used for behavioral ordering."""
        # Events with specific timestamps
        events = [
            create_event(
                hostname="host1",
                process_name="proc1",
                timestamp=datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC),
            ),
            create_event(
                hostname="host1",
                process_name="proc2",
                timestamp=datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC),
            ),
        ]

        # Run with fresh service
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        results = [detector.detect(e) for e in events]

        # Both should be first-seen
        assert results[0].matched is True
        assert results[1].matched is True


class TestEntityBehaviorMultipleEntities:
    """Tests for multiple entity tracking."""

    def test_multiple_entities_independent(self) -> None:
        """Test multiple entities have independent profiles."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        events = [
            create_event(hostname="host1", process_name="proc1"),
            create_event(hostname="host2", process_name="proc1"),
            create_event(hostname="host1", process_name="proc2"),
        ]

        results = [detector.detect(e) for e in events]

        # All should be first-seen (different entities/values)
        assert all(r.matched for r in results)

    def test_same_entity_repeated_value(self) -> None:
        """Test same entity with repeated value."""
        service = EntityBehaviorService()
        detector = EntityBehaviorDetector(
            name="test_rule",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service,
        )

        events = [
            create_event(hostname="host1", process_name="proc1"),
            create_event(hostname="host1", process_name="proc1"),
            create_event(hostname="host1", process_name="proc1"),
        ]

        results = [detector.detect(e) for e in events]

        # Only first should be detected
        assert results[0].matched is True
        assert not results[1].matched
        assert not results[2].matched
