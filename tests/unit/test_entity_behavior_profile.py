"""Tests for EntityBehaviorProfile."""

from datetime import UTC, datetime

import pytest

from argusprowl.behavior.entity_behavior_profile import EntityBehaviorProfile, ProfileMaturity


class TestProfileMaturity:
    """Tests for ProfileMaturity enum."""

    def test_maturity_values(self) -> None:
        """Test all maturity states exist."""
        assert ProfileMaturity.EMPTY.value == "empty"
        assert ProfileMaturity.WARMING.value == "warming"
        assert ProfileMaturity.MATURE.value == "mature"
        assert ProfileMaturity.STALE.value == "stale"

    def test_maturity_is_enum(self) -> None:
        """Test maturity is an Enum."""
        assert isinstance(ProfileMaturity.EMPTY, ProfileMaturity)


class TestEntityBehaviorProfileCreation:
    """Tests for EntityBehaviorProfile creation."""

    def test_create_profile(self) -> None:
        """Test profile creation via factory method."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        profile = EntityBehaviorProfile.create(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp,
        )

        assert profile.entity_type == "hostname"
        assert profile.entity_id == "workstation01"
        assert profile.dimension == "process_name"
        assert profile.first_seen == timestamp
        assert profile.last_seen == timestamp
        assert profile.observation_count == 1
        assert profile.maturity == ProfileMaturity.WARMING
        assert profile.profile_version == 1
        assert "hostname:workstation01" in profile.profile_key
        assert "dimension:process_name" in profile.profile_key

    def test_create_profile_invalid_entity_type(self) -> None:
        """Test profile creation with empty entity_type raises."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        with pytest.raises(ValueError, match="entity_type must not be empty"):
            EntityBehaviorProfile.create(
                entity_type="",
                entity_id="workstation01",
                dimension="process_name",
                timestamp=timestamp,
            )

    def test_create_profile_invalid_entity_id(self) -> None:
        """Test profile creation with empty entity_id raises."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        with pytest.raises(ValueError, match="entity_id must not be empty"):
            EntityBehaviorProfile.create(
                entity_type="hostname",
                entity_id="",
                dimension="process_name",
                timestamp=timestamp,
            )

    def test_create_profile_invalid_dimension(self) -> None:
        """Test profile creation with empty dimension raises."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        with pytest.raises(ValueError, match="dimension must not be empty"):
            EntityBehaviorProfile.create(
                entity_type="hostname",
                entity_id="workstation01",
                dimension="",
                timestamp=timestamp,
            )

    def test_create_profile_negative_count(self) -> None:
        """Test profile with negative observation_count raises."""
        with pytest.raises(ValueError, match="observation_count must be non-negative"):
            EntityBehaviorProfile(
                profile_key="test",
                entity_type="hostname",
                entity_id="host1",
                dimension="process",
                observation_count=-1,
            )

    def test_create_profile_invalid_version(self) -> None:
        """Test profile with invalid version raises."""
        with pytest.raises(ValueError, match="profile_version must be positive"):
            EntityBehaviorProfile(
                profile_key="test",
                entity_type="hostname",
                entity_id="host1",
                dimension="process",
                profile_version=0,
            )


class TestEntityBehaviorProfileImmutability:
    """Tests for EntityBehaviorProfile immutability."""

    def test_profile_is_frozen(self) -> None:
        """Test profile is a frozen dataclass."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        profile = EntityBehaviorProfile.create(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp,
        )

        with pytest.raises(AttributeError):
            profile.entity_type = "other"

    def test_slots_enabled(self) -> None:
        """Test profile uses __slots__."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        profile = EntityBehaviorProfile.create(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp,
        )

        with pytest.raises(AttributeError):
            _ = profile.__dict__


class TestEntityBehaviorProfileObservation:
    """Tests for profile observation tracking."""

    def test_with_observation_updates_timestamps(self) -> None:
        """Test with_observation updates first_seen and last_seen."""
        timestamp1 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        timestamp2 = datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC)

        profile = EntityBehaviorProfile.create(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp1,
        )

        updated = profile.with_observation(timestamp2)
        assert updated.first_seen == timestamp1  # Unchanged
        assert updated.last_seen == timestamp2  # Updated
        assert updated.observation_count == 2

    def test_with_observation_early_timestamp(self) -> None:
        """Test with_observation handles earlier timestamp."""
        timestamp1 = datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC)
        timestamp2 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        profile = EntityBehaviorProfile.create(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp1,
        )

        updated = profile.with_observation(timestamp2)
        assert updated.first_seen == timestamp2  # Updated
        assert updated.last_seen == timestamp1  # Unchanged

    def test_with_observation_preserves_identity(self) -> None:
        """Test with_observation preserves profile identity fields."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        profile = EntityBehaviorProfile.create(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp,
        )

        updated = profile.with_observation(timestamp)
        assert updated.profile_key == profile.profile_key
        assert updated.entity_type == profile.entity_type
        assert updated.entity_id == profile.entity_id
        assert updated.dimension == profile.dimension


class TestEntityBehaviorProfileMaturity:
    """Tests for profile maturity transitions."""

    def test_with_maturity(self) -> None:
        """Test maturity transition."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        profile = EntityBehaviorProfile.create(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp,
        )

        assert profile.maturity == ProfileMaturity.WARMING

        mature = profile.with_maturity(ProfileMaturity.MATURE)
        assert mature.maturity == ProfileMaturity.MATURE

    def test_maturity_transitions(self) -> None:
        """Test typical maturity transitions."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)

        # Empty -> Warming
        empty = EntityBehaviorProfile(
            profile_key="test",
            entity_type="hostname",
            entity_id="host1",
            dimension="process",
        )
        assert empty.maturity == ProfileMaturity.EMPTY

        # Warmed up
        warming = empty.with_observation(timestamp)
        assert warming.maturity == ProfileMaturity.EMPTY  # Still EMPTY until created via create()

        # Use create for initial state
        created = EntityBehaviorProfile.create(
            entity_type="hostname",
            entity_id="host1",
            dimension="process",
            timestamp=timestamp,
        )
        assert created.maturity == ProfileMaturity.WARMING


class TestEntityBehaviorProfileSerialization:
    """Tests for profile serialization."""

    def test_to_dict(self) -> None:
        """Test serialization to dict."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        profile = EntityBehaviorProfile.create(
            entity_type="hostname",
            entity_id="workstation01",
            dimension="process_name",
            timestamp=timestamp,
        )

        data = profile.to_dict()
        assert data["entity_type"] == "hostname"
        assert data["entity_id"] == "workstation01"
        assert data["dimension"] == "process_name"
        assert data["first_seen"] == timestamp.isoformat()
        assert data["maturity"] == "warming"
        assert data["observation_count"] == 1

    def test_from_dict(self) -> None:
        """Test deserialization from dict."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        data = {
            "profile_key": "hostname:host1|dimension:process",
            "entity_type": "hostname",
            "entity_id": "host1",
            "dimension": "process",
            "first_seen": timestamp.isoformat(),
            "last_seen": timestamp.isoformat(),
            "observation_count": 5,
            "maturity": "mature",
            "profile_version": 2,
            "last_update": timestamp.isoformat(),
        }

        profile = EntityBehaviorProfile.from_dict(data)
        assert profile.entity_type == "hostname"
        assert profile.entity_id == "host1"
        assert profile.observation_count == 5
        assert profile.maturity == ProfileMaturity.MATURE

    def test_roundtrip(self) -> None:
        """Test serialization roundtrip."""
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        original = EntityBehaviorProfile.create(
            entity_type="src_ip",
            entity_id="192.168.1.100",
            dimension="dst_ip",
            timestamp=timestamp,
        )

        data = original.to_dict()
        restored = EntityBehaviorProfile.from_dict(data)

        assert restored.profile_key == original.profile_key
        assert restored.entity_type == original.entity_type
        assert restored.entity_id == original.entity_id
        assert restored.dimension == original.dimension
        assert restored.observation_count == original.observation_count
        assert restored.maturity == original.maturity
