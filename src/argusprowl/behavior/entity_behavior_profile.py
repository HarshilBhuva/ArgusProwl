"""Entity behavior profile data model.

Represents a bounded behavioral profile for a single entity + dimension combination.
Stores first-seen tracking and observation metadata.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class ProfileMaturity(Enum):
    """Maturity state of an entity behavior profile.

    Attributes:
        EMPTY: Profile exists but has no observations yet.
        WARMING: Profile has at least one observation but hasn't reached
            the minimum observation threshold for maturity.
        MATURE: Profile has reached the minimum observation threshold.
        STALE: Profile has not received updates within the configured
            stale timeout. It can still participate in detection but may
            need refreshing.
    """

    EMPTY = "empty"
    WARMING = "warming"
    MATURE = "mature"
    STALE = "stale"


@dataclass(frozen=True, slots=True)
class EntityBehaviorProfile:
    """Immutable behavioral profile for one entity + dimension combination.

    Tracks the first occurrence of dimension values observed for a specific
    entity, enabling first-seen behavioral detection.

    Attributes:
        profile_key: Unique key identifying this profile (entity_type:entity_id|dimension:dimension_value).
        entity_type: Type of entity (e.g., 'hostname', 'src_ip', 'username').
        entity_id: Unique identifier of the entity.
        dimension: Behavioral dimension field being tracked (e.g., 'process_name', 'dst_ip').
        first_seen: UTC timestamp of the first observation for this profile.
        last_seen: UTC timestamp of the most recent observation.
        observation_count: Total number of events observed for this entity+dimension.
        maturity: Current maturity state of the profile.
        profile_version: Version counter for significant profile changes.
        last_update: UTC timestamp of the last profile update (internal bookkeeping).
    """

    profile_key: str
    entity_type: str
    entity_id: str
    dimension: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    observation_count: int = 0
    distinct_value_count: int = 0
    maturity: ProfileMaturity = ProfileMaturity.EMPTY
    profile_version: int = 1
    last_update: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Validate profile constraints."""
        if not self.profile_key:
            raise ValueError("EntityBehaviorProfile profile_key must not be empty.")
        if not self.entity_type:
            raise ValueError("EntityBehaviorProfile entity_type must not be empty.")
        if not self.entity_id:
            raise ValueError("EntityBehaviorProfile entity_id must not be empty.")
        if not self.dimension:
            raise ValueError("EntityBehaviorProfile dimension must not be empty.")
        if self.observation_count < 0:
            raise ValueError(
                f"EntityBehaviorProfile observation_count must be non-negative, got {self.observation_count}."
            )
        if self.profile_version < 1:
            raise ValueError(
                f"EntityBehaviorProfile profile_version must be positive, got {self.profile_version}."
            )
        if self.first_seen is not None and self.first_seen.tzinfo is None:
            raise ValueError("EntityBehaviorProfile first_seen must be timezone-aware UTC.")
        if self.last_seen is not None and self.last_seen.tzinfo is None:
            raise ValueError("EntityBehaviorProfile last_seen must be timezone-aware UTC.")
        if self.last_update.tzinfo is None:
            raise ValueError("EntityBehaviorProfile last_update must be timezone-aware UTC.")

    @classmethod
    def create(
        cls,
        entity_type: str,
        entity_id: str,
        dimension: str,
        timestamp: datetime,
    ) -> "EntityBehaviorProfile":
        """Factory method to create a new profile with initial observation.

        Args:
            entity_type: Type of entity (e.g., 'hostname', 'src_ip').
            entity_id: Unique identifier of the entity.
            dimension: Behavioral dimension field being tracked.
            timestamp: UTC timestamp of the first observation.

        Returns:
            A new EntityBehaviorProfile in WARMING state.
        """
        profile_key = f"{entity_type}:{entity_id}|dimension:{dimension}"
        return cls(
            profile_key=profile_key,
            entity_type=entity_type,
            entity_id=entity_id,
            dimension=dimension,
            first_seen=timestamp,
            last_seen=timestamp,
            observation_count=1,
            distinct_value_count=1,
            maturity=ProfileMaturity.WARMING,
            profile_version=1,
            last_update=datetime.now(UTC),
        )

    def with_observation(
        self,
        timestamp: datetime,
        new_observation: bool = False,
    ) -> "EntityBehaviorProfile":
        """Create an updated profile with a new observation.

        Args:
            timestamp: UTC timestamp of the new observation.
            new_observation: Whether this is a new distinct value (first-seen).

        Returns:
            A new EntityBehaviorProfile with updated timestamps and counters.
        """
        new_first_seen = self.first_seen
        if self.first_seen is None or timestamp < self.first_seen:
            new_first_seen = timestamp

        new_last_seen = self.last_seen
        if self.last_seen is None or timestamp > self.last_seen:
            new_last_seen = timestamp

        return EntityBehaviorProfile(
            profile_key=self.profile_key,
            entity_type=self.entity_type,
            entity_id=self.entity_id,
            dimension=self.dimension,
            first_seen=new_first_seen,
            last_seen=new_last_seen,
            observation_count=self.observation_count + 1,
            distinct_value_count=self.distinct_value_count + (1 if new_observation else 0),
            maturity=self.maturity,
            profile_version=self.profile_version,
            last_update=datetime.now(UTC),
        )

    def with_maturity(self, maturity: ProfileMaturity) -> "EntityBehaviorProfile":
        """Create a profile with updated maturity state.

        Args:
            maturity: New maturity state.

        Returns:
            A new EntityBehaviorProfile with updated maturity.
        """
        return EntityBehaviorProfile(
            profile_key=self.profile_key,
            entity_type=self.entity_type,
            entity_id=self.entity_id,
            dimension=self.dimension,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            observation_count=self.observation_count,
            distinct_value_count=self.distinct_value_count,
            maturity=maturity,
            profile_version=self.profile_version,
            last_update=datetime.now(UTC),
        )

    @property
    def total_observations(self) -> int:
        """Return total observation count (alias for observation_count)."""
        return self.observation_count

    def to_dict(self) -> dict[str, Any]:
        """Serialize the profile to a dictionary.

        Returns:
            Dictionary representation of the profile.
        """
        return {
            "profile_key": self.profile_key,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "dimension": self.dimension,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "observation_count": self.observation_count,
            "distinct_value_count": self.distinct_value_count,
            "maturity": self.maturity.value,
            "profile_version": self.profile_version,
            "last_update": self.last_update.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EntityBehaviorProfile":
        """Deserialize a profile from a dictionary.

        Args:
            data: Dictionary representation of a profile.

        Returns:
            EntityBehaviorProfile instance.
        """
        first_seen = None
        if data.get("first_seen"):
            first_seen = datetime.fromisoformat(data["first_seen"])
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=UTC)

        last_seen = None
        if data.get("last_seen"):
            last_seen = datetime.fromisoformat(data["last_seen"])
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=UTC)

        last_update = datetime.fromisoformat(data["last_update"])
        if last_update.tzinfo is None:
            last_update = last_update.replace(tzinfo=UTC)

        return cls(
            profile_key=data["profile_key"],
            entity_type=data["entity_type"],
            entity_id=data["entity_id"],
            dimension=data["dimension"],
            first_seen=first_seen,
            last_seen=last_seen,
            observation_count=data.get("observation_count", 0),
            distinct_value_count=data.get("distinct_value_count", 0),
            maturity=ProfileMaturity(data.get("maturity", ProfileMaturity.EMPTY.value)),
            profile_version=data.get("profile_version", 1),
            last_update=last_update,
        )
