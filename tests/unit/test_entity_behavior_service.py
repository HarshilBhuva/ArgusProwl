"""Tests for EntityBehaviorService."""

from datetime import UTC, datetime, timedelta

import pytest

from argusprowl.behavior.entity_behavior_profile import ProfileMaturity
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService


class TestEntityBehaviorServiceCreation:
    """Tests for EntityBehaviorService creation."""

    def test_creation_default(self) -> None:
        """Test creation with defaults."""
        service = EntityBehaviorService()
        assert service.max_profiles == 100000
        assert service.profile_count == 0

    def test_creation_custom(self) -> None:
        """Test creation with custom values."""
        service = EntityBehaviorService(
            max_profiles=1000,
            max_values_per_profile=500,
            max_value_length=128,
            stale_timeout=timedelta(hours=12),
        )
        assert service.max_profiles == 1000
        assert service.max_values_per_profile == 500
        assert service.max_value_length == 128
        assert service.stale_timeout == timedelta(hours=12)

    def test_creation_invalid_max_profiles(self) -> None:
        """Test creation with invalid max_profiles raises."""
        with pytest.raises(ValueError, match="max_profiles must be positive"):
            EntityBehaviorService(max_profiles=0)

    def test_creation_invalid_max_values(self) -> None:
        """Test creation with invalid max_values_per_profile raises."""
        with pytest.raises(ValueError, match="max_values_per_profile must be positive"):
            EntityBehaviorService(max_values_per_profile=0)


class TestEntityBehaviorServiceProfiles:
    """Tests for profile management."""

    def test_get_or_create_profile_new(self) -> None:
        """Test creating a new profile."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        profile = service.get_or_create_profile(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp,
        )

        assert profile.entity_type == "hostname"
        assert profile.entity_id == "workstation01"
        assert profile.dimension == "process_name"
        assert profile.first_seen == timestamp
        assert profile.observation_count == 1

    def test_get_or_create_profile_existing(self) -> None:
        """Test getting an existing profile."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        profile1 = service.get_or_create_profile(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp,
        )

        profile2 = service.get_or_create_profile(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp,
        )

        assert profile1.profile_key == profile2.profile_key
        assert service.profile_count == 1

    def test_get_profile(self) -> None:
        """Test getting a profile."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.get_or_create_profile(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp,
        )

        profile = service.get_profile(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
        )

        assert profile is not None
        assert profile.entity_id == "workstation01"

    def test_get_profile_not_found(self) -> None:
        """Test getting a non-existent profile returns None."""
        service = EntityBehaviorService()
        profile = service.get_profile(
            entity_type="hostname",
            entity_id="nonexistent",
            dimension="process_name",
        )
        assert profile is None


class TestEntityBehaviorServiceObservations:
    """Tests for observation recording."""

    def test_record_observation_new(self) -> None:
        """Test recording a new observation."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        profile, is_first_seen = service.record_observation(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=timestamp,
        )

        assert is_first_seen is True
        assert profile.observation_count == 1
        assert profile.maturity == ProfileMaturity.WARMING

    def test_record_observation_repeated(self) -> None:
        """Test recording a repeated observation."""
        service = EntityBehaviorService()
        timestamp1 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        timestamp2 = datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC)

        service.record_observation(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=timestamp1,
        )

        profile, is_first_seen = service.record_observation(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=timestamp2,
        )

        assert is_first_seen is False
        assert profile.observation_count == 2

    def test_record_observation_different_value(self) -> None:
        """Test recording a different value for same entity."""
        service = EntityBehaviorService()
        timestamp1 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        timestamp2 = datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC)

        service.record_observation(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=timestamp1,
        )

        profile, is_first_seen = service.record_observation(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            dimension_value="explorer.exe",
            timestamp=timestamp2,
        )

        assert is_first_seen is True  # New value
        assert profile.observation_count == 2

    def test_record_observation_different_entity_same_value(self) -> None:
        """Test same value for different entity is first-seen."""
        service = EntityBehaviorService()
        timestamp1 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        timestamp2 = datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC)

        service.record_observation(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=timestamp1,
        )

        profile, is_first_seen = service.record_observation(
            entity_type="hostname",
            entity_id="workstation02",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=timestamp2,
        )

        assert is_first_seen is True  # Different entity
        assert profile.entity_id == "workstation02"


class TestEntityBehaviorServiceHasValue:
    """Tests for has_value()."""

    def test_has_value_true(self) -> None:
        """Test has_value returns True for existing value."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.record_observation(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=timestamp,
        )

        assert (
            service.has_value(
                entity_type="hostname",
                entity_id="workstation01",
                dimension="process_name",
                dimension_value="notepad.exe",
            )
            is True
        )

    def test_has_value_false(self) -> None:
        """Test has_value returns False for non-existing value."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.record_observation(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            dimension_value="notepad.exe",
            timestamp=timestamp,
        )

        assert (
            service.has_value(
                entity_type="hostname",
                entity_id="workstation01",
                dimension="process_name",
                dimension_value="malware.exe",
            )
            is False
        )

    def test_has_value_no_profile(self) -> None:
        """Test has_value returns False when no profile exists."""
        service = EntityBehaviorService()

        assert (
            service.has_value(
                entity_type="hostname",
                entity_id="nonexistent",
                dimension="process_name",
                dimension_value="notepad.exe",
            )
            is False
        )


class TestEntityBehaviorServiceEviction:
    """Tests for LRU eviction."""

    def test_lru_eviction(self) -> None:
        """Test LRU eviction when at capacity."""
        service = EntityBehaviorService(max_profiles=3)
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.record_observation(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="proc1",
            timestamp=timestamp,
        )

        # Access host2 and host3 to make them more recently used than host1
        service.get_profile("hostname", "host2", "process_name")
        service.get_profile("hostname", "host3", "process_name")

        service.record_observation(
            entity_type="hostname",
            entity_id="host2",
            dimension="process_name",
            dimension_value="proc2",
            timestamp=timestamp,
        )
        service.record_observation(
            entity_type="hostname",
            entity_id="host3",
            dimension="process_name",
            dimension_value="proc3",
            timestamp=timestamp,
        )

        assert service.profile_count == 3

        # Adding host4 should evict host1 (LRU - least recently accessed)
        service.record_observation(
            entity_type="hostname",
            entity_id="host4",
            dimension="process_name",
            dimension_value="proc4",
            timestamp=timestamp,
        )

        assert service.profile_count == 3
        # host1 should be evicted (LRU)
        assert service.get_profile("hostname", "host1", "process_name") is None
        # host2, host3, host4 should still exist
        assert service.get_profile("hostname", "host2", "process_name") is not None
        assert service.get_profile("hostname", "host3", "process_name") is not None
        assert service.get_profile("hostname", "host4", "process_name") is not None

    def test_value_set_lru_eviction(self) -> None:
        """Test value set LRU eviction within a profile."""
        service = EntityBehaviorService(max_values_per_profile=3)
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        # Add values
        service.record_observation(
            entity_type="hostname",
            entity_id="host1",
            dimension="dst_ip",
            dimension_value="10.0.0.1",
            timestamp=timestamp,
        )
        service.record_observation(
            entity_type="hostname",
            entity_id="host1",
            dimension="dst_ip",
            dimension_value="10.0.0.2",
            timestamp=timestamp,
        )
        service.record_observation(
            entity_type="hostname",
            entity_id="host1",
            dimension="dst_ip",
            dimension_value="10.0.0.3",
            timestamp=timestamp,
        )

        # Access value2 to make it most recently used
        service.has_value(
            entity_type="hostname",
            entity_id="host1",
            dimension="dst_ip",
            dimension_value="10.0.0.2",
        )

        # Add new value - should evict value1 (LRU - accessed first)
        service.record_observation(
            entity_type="hostname",
            entity_id="host1",
            dimension="dst_ip",
            dimension_value="10.0.0.4",
            timestamp=timestamp,
        )

        # Check values - value1 should be evicted (LRU)
        assert (
            service.has_value(
                entity_type="hostname",
                entity_id="host1",
                dimension="dst_ip",
                dimension_value="10.0.0.1",
            )
            is False
        )  # Evicted
        assert (
            service.has_value(
                entity_type="hostname",
                entity_id="host1",
                dimension="dst_ip",
                dimension_value="10.0.0.2",
            )
            is True
        )  # Most recently accessed
        assert (
            service.has_value(
                entity_type="hostname",
                entity_id="host1",
                dimension="dst_ip",
                dimension_value="10.0.0.3",
            )
            is True
        )
        assert (
            service.has_value(
                entity_type="hostname",
                entity_id="host1",
                dimension="dst_ip",
                dimension_value="10.0.0.4",
            )
            is True
        )


class TestEntityBehaviorServiceMaturity:
    """Tests for profile maturity."""

    def test_maturity_empty(self) -> None:
        """Test maturity for non-existent profile."""
        service = EntityBehaviorService()

        maturity = service.get_profile_maturity(
            entity_type="hostname",
            entity_id="nonexistent",
            dimension="process_name",
        )

        assert maturity == ProfileMaturity.EMPTY

    def test_maturity_warming(self) -> None:
        """Test maturity for warming profile."""
        service = EntityBehaviorService()
        # Use a recent timestamp to avoid staleness detection
        timestamp = datetime.now(UTC)

        service.record_observation(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="proc1",
            timestamp=timestamp,
        )

        maturity = service.get_profile_maturity(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
        )

        assert maturity == ProfileMaturity.WARMING


class TestEntityBehaviorServiceClear:
    """Tests for service clear."""

    def test_clear(self) -> None:
        """Test clear removes all profiles."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.record_observation(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="proc1",
            timestamp=timestamp,
        )

        assert service.profile_count == 1
        service.clear()
        assert service.profile_count == 0


class TestEntityBehaviorServiceConcurrency:
    """Tests for thread safety."""

    def test_concurrent_record_observation(self) -> None:
        """Test concurrent observation recording."""
        import threading

        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        errors: list[Exception] = []

        def record_values(start: int, count: int) -> None:
            try:
                for i in range(start, start + count):
                    service.record_observation(
                        entity_type="hostname",
                        entity_id=f"host{i % 10}",  # 10 different hosts
                        dimension="process_name",
                        dimension_value=f"proc{i}",
                        timestamp=timestamp,
                    )
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=record_values, args=(0, 100)),
            threading.Thread(target=record_values, args=(100, 100)),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert service.profile_count > 0


class TestEntityBehaviorServiceGetProfileValues:
    """Tests for get_profile_values()."""

    def test_get_profile_values(self) -> None:
        """Test getting all values for a profile."""
        service = EntityBehaviorService()
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        service.record_observation(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="proc1",
            timestamp=timestamp,
        )
        service.record_observation(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
            dimension_value="proc2",
            timestamp=timestamp,
        )

        values = service.get_profile_values(
            entity_type="hostname",
            entity_id="host1",
            dimension="process_name",
        )

        assert len(values) == 2
        assert "proc1" in values
        assert "proc2" in values

    def test_get_profile_values_no_profile(self) -> None:
        """Test getting values for non-existent profile."""
        service = EntityBehaviorService()
        values = service.get_profile_values(
            entity_type="hostname",
            entity_id="nonexistent",
            dimension="process_name",
        )
        assert values == []
