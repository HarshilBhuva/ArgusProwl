"""Baseline classification models.

Provides baseline classification types and result contracts for behavioral
baseline state management.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class BaselineClassification(Enum):
    """Classification states for baseline behavioral analysis.

    These classifications describe how an observed value relates to the
    established baseline for an entity-field combination. Classification
    never implies threat — it is a behavioral characterization only.

    Attributes:
        BASELINE_UNAVAILABLE: No profile exists for this entity-field.
        BASELINE_WARMING: Profile exists but is not yet mature.
        BASELINE_NEW_VALUE: Value has never been seen in this profile.
        BASELINE_RARE_VALUE: Value exists but historical count ≤ rare_threshold.
        BASELINE_ESTABLISHED: Value exists, historical count > rare_threshold,
            and profile is MATURE.
    """

    BASELINE_UNAVAILABLE = "baseline_unavailable"
    BASELINE_WARMING = "baseline_warming"
    BASELINE_NEW_VALUE = "baseline_new_value"
    BASELINE_RARE_VALUE = "baseline_rare_value"
    BASELINE_ESTABLISHED = "baseline_established"


@dataclass(frozen=True, slots=True)
class BaselineClassificationResult:
    """Immutable result of a baseline classification query.

    This object is produced by the baseline service after classifying an
    observation against the current profile state. It is read-only and
    carries the classification along with the profile state at the time
    of classification (before the current event is recorded).

    Attributes:
        entity_id: The entity identifier this result pertains to.
        field: The behavioral field/dimension being classified.
        value: The value that was classified.
        classification: The baseline classification state.
        profile_maturity: The profile maturity state at classification time
            (WARMING, MATURE, or STALE).
        pre_observation_value_count: Count of this value BEFORE the current
            observation was recorded. Used for evidence generation.
        observation_count: Cumulative observation count after this event
            would be recorded.
        first_seen: Earliest timestamp observed for this entity-field.
        last_seen: Most recent timestamp observed for this entity-field.
    """

    entity_id: str
    field: str
    value: str
    classification: BaselineClassification
    profile_maturity: "BaselineMaturityState"
    pre_observation_value_count: int
    observation_count: int
    first_seen: datetime | None
    last_seen: datetime | None

    def __post_init__(self) -> None:
        """Validate result constraints."""
        if not self.entity_id:
            raise ValueError("entity_id must not be empty.")
        if not self.field:
            raise ValueError("field must not be empty.")
        if self.pre_observation_value_count < 0:
            raise ValueError("pre_observation_value_count must be non-negative.")
        if self.first_seen is not None and self.first_seen.tzinfo is None:
            raise ValueError("first_seen must be timezone-aware UTC.")
        if self.last_seen is not None and self.last_seen.tzinfo is None:
            raise ValueError("last_seen must be timezone-aware UTC.")

    def to_dict(self) -> dict:
        """Serialize the result to a dictionary.

        Returns:
            Dictionary representation of the classification result.
        """
        return {
            "entity_id": self.entity_id,
            "field": self.field,
            "value": self.value,
            "classification": self.classification.value,
            "profile_maturity": self.profile_maturity.value,
            "pre_observation_value_count": self.pre_observation_value_count,
            "observation_count": self.observation_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class BaselineMaturityState(Enum):
    """Maturity states for baseline profiles.

    Attributes:
        EMPTY: No profile exists yet.
        WARMING: Profile has observations but hasn't reached maturity.
        MATURE: Profile has met both maturity criteria.
        STALE: Profile has not received updates within the stale timeout.
    """

    EMPTY = "empty"
    WARMING = "warming"
    MATURE = "mature"
    STALE = "stale"
