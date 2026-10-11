"""Entity behavior summary data model.

Provides a read-only, descriptive summary of an entity's behavior.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from argusprowl.behavior.entity_behavior_profile import ProfileMaturity


@dataclass(frozen=True, slots=True)
class EntityBehaviorSummary:
    """Immutable descriptive summary of entity behavior.

    Attributes:
        entity_type: Type of entity.
        entity_id: Unique identifier of the entity.
        dimension: Behavioral dimension field.
        observation_count: Total number of events observed.
        distinct_value_count: Total number of distinct values observed.
        first_seen: UTC timestamp of the first observation.
        last_seen: UTC timestamp of the most recent observation.
        maturity: Current maturity state of the profile.
        top_values: List of (value, count) tuples for the most frequent values,
            ordered by count (descending) and then value (lexicographically).
    """

    entity_type: str
    entity_id: str
    dimension: str
    observation_count: int
    distinct_value_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    maturity: ProfileMaturity
    top_values: list[tuple[str, int]]

    @property
    def narrative(self) -> str:
        """Generate a strictly descriptive, deterministic narrative.

        Returns:
            A string describing the observation count, distinct values, and top values.
        """
        if self.observation_count == 0:
            return "No observations recorded."

        obs_plural = "s" if self.observation_count != 1 else ""
        val_plural = "s" if self.distinct_value_count != 1 else ""

        base = f"Observed {self.observation_count} time{obs_plural} across {self.distinct_value_count} distinct value{val_plural}."

        if not self.top_values:
            return base

        top_items = [v for v, _ in self.top_values]
        return f"{base} Most frequently observed values: {', '.join(top_items)}."

    def to_dict(self) -> dict[str, Any]:
        """Serialize the summary to a dictionary."""
        return {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "dimension": self.dimension,
            "observation_count": self.observation_count,
            "distinct_value_count": self.distinct_value_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "maturity": self.maturity.value,
            "top_values": self.top_values,
            "narrative": self.narrative,
        }
