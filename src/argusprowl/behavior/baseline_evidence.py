"""Baseline evidence models.

Provides bounded, deterministic evidence and reason codes for baseline
classification results. Makes baseline decisions explainable to analysts
without adding ML, risk scores, or unbounded state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import Any

# Maximum number of comparison values to include in evidence
_MAX_COMPARISON_VALUES: int = 5
# Maximum length for value strings in evidence
_MAX_VALUE_LENGTH: int = 128


class BaselineReasonCode(Enum):
    """Explicit reason codes for baseline classification decisions.

    These codes are stable, deterministic, and analyst-readable. They explain
    WHY a particular classification was assigned without free-form prose.

    Precedence rules (applied in order):
    1. NO_PROFILE: No baseline profile exists
    2. PROFILE_WARMING / PROFILE_STALE: Profile not yet mature
    3. VALUE_NEW: Value has never been observed (pre_count == 0)
    4. VALUE_COUNT_AT_THRESHOLD: Value count exactly equals threshold
    5. VALUE_COUNT_BELOW_THRESHOLD: Value count below threshold
    6. VALUE_ESTABLISHED: Value count above threshold in mature profile

    Attributes:
        NO_PROFILE: No baseline profile exists for this entity-field.
        PROFILE_WARMING: Profile exists but has not reached maturity.
        PROFILE_STALE: Profile is stale (no recent events) and re-warming.
        VALUE_NEW: Value has never been observed in this profile.
        VALUE_COUNT_AT_THRESHOLD: Value count exactly equals the rare threshold.
        VALUE_COUNT_BELOW_THRESHOLD: Value count is below the rare threshold.
        VALUE_ESTABLISHED: Value exists with count above threshold in mature profile.
        MATURITY_INSUFFICIENT_OBSERVATIONS: Profile lacks enough observations for maturity.
        MATURITY_INSUFFICIENT_AGE: Profile lacks sufficient age for maturity.
    """

    NO_PROFILE = "no_profile"
    PROFILE_WARMING = "profile_warming"
    PROFILE_STALE = "profile_stale"
    VALUE_NEW = "value_new"
    VALUE_COUNT_AT_THRESHOLD = "value_count_at_threshold"
    VALUE_COUNT_BELOW_THRESHOLD = "value_count_below_threshold"
    VALUE_ESTABLISHED = "value_established"
    MATURITY_INSUFFICIENT_OBSERVATIONS = "maturity_insufficient_observations"
    MATURITY_INSUFFICIENT_AGE = "maturity_insufficient_age"


@dataclass(frozen=True, slots=True)
class BaselineEvidence:
    """Bounded evidence explaining a baseline classification decision.

    This is a deterministic, auditable explanation of WHY a classification
    occurred. It is derived entirely from structured profile state and
    configuration — no free-form text generation.

    Attributes:
        reason_code: Stable enum code explaining the classification.
        classification: The baseline classification that was assigned.
        profile_maturity: The maturity state of the profile.
        value_count: Historical count of this value (before current observation).
        rare_threshold: The configured rare threshold for comparison.
        observation_count: Total profile observation count.
        maturity_min_observations: Configured minimum for maturity.
        maturity_window_seconds: Configured maturity time window.
        first_seen: Earliest observed timestamp.
        last_seen: Most recent observed timestamp.
        top_comparison_values: Bounded list of other observed values with counts.
        explanation: Deterministic narrative derived from structured fields.
    """

    reason_code: BaselineReasonCode
    classification: str
    profile_maturity: str
    value_count: int
    rare_threshold: int
    observation_count: int
    maturity_min_observations: int
    maturity_window_seconds: float
    first_seen: datetime | None
    last_seen: datetime | None
    top_comparison_values: tuple[tuple[str, int], ...]
    explanation: str

    # Maximum number of comparison values to include
    _MAX_COMPARISON_VALUES: int = _MAX_COMPARISON_VALUES
    # Maximum length for value strings in evidence
    _MAX_VALUE_LENGTH: int = _MAX_VALUE_LENGTH

    def __post_init__(self) -> None:
        """Validate evidence constraints."""
        # Normalize to tuple for immutability
        if not isinstance(self.top_comparison_values, tuple):
            normalized = tuple(self.top_comparison_values)
            object.__setattr__(self, "top_comparison_values", normalized)
        if len(self.top_comparison_values) > _MAX_COMPARISON_VALUES:
            object.__setattr__(
                self,
                "top_comparison_values",
                self.top_comparison_values[:_MAX_COMPARISON_VALUES],
            )
        # Bound value strings in comparison values
        bounded: list[tuple[str, int]] = []
        for value, count in self.top_comparison_values:
            bounded_value = self._bound_value(value)
            bounded.append((bounded_value, count))
        object.__setattr__(self, "top_comparison_values", tuple(bounded))

    @staticmethod
    def _bound_value(value: str) -> str:
        """Return a bounded representation of a value string.

        If the value exceeds the maximum length, return its SHA-256 hash.
        Otherwise, return the value as-is.

        Args:
            value: The string to bound.

        Returns:
            A bounded string representation.
        """
        if len(value) > _MAX_VALUE_LENGTH:
            return sha256(value.encode("utf-8")).hexdigest()
        return value

    @classmethod
    def for_unavailable(
        cls,
        entity_id: str,
        field: str,
        value: str,
        observation_count: int,
        first_seen: datetime | None,
        last_seen: datetime | None,
        maturity_min_observations: int,
        maturity_window_seconds: float,
    ) -> BaselineEvidence:
        """Create evidence for BASELINE_UNAVAILABLE classification.

        Args:
            entity_id: The entity identifier.
            field: The behavioral field/dimension.
            value: The observed value.
            observation_count: Total profile observation count after recording.
            first_seen: Earliest observed timestamp.
            last_seen: Most recent observed timestamp.
            maturity_min_observations: Configured minimum for maturity.
            maturity_window_seconds: Configured maturity time window.

        Returns:
            BaselineEvidence for unavailable classification.
        """
        explanation = (
            f"No baseline profile exists for {field} on entity '{entity_id}'. "
            f"This is the first observation. "
            f"Profile will begin warming with {observation_count} observation(s)."
        )
        return cls(
            reason_code=BaselineReasonCode.NO_PROFILE,
            classification="baseline_unavailable",
            profile_maturity="warming",
            value_count=0,
            rare_threshold=0,
            observation_count=observation_count,
            maturity_min_observations=maturity_min_observations,
            maturity_window_seconds=maturity_window_seconds,
            first_seen=first_seen,
            last_seen=last_seen,
            top_comparison_values=[],
            explanation=explanation,
        )

    @classmethod
    def for_warming(
        cls,
        entity_id: str,
        field: str,
        value: str,
        value_count: int,
        observation_count: int,
        first_seen: datetime | None,
        last_seen: datetime | None,
        maturity_min_observations: int,
        maturity_window_seconds: float,
        top_comparison_values: tuple[tuple[str, int], ...] | list[tuple[str, int]] | None = None,
        is_stale: bool = False,
    ) -> BaselineEvidence:
        """Create evidence for BASELINE_WARMING classification.

        Args:
            entity_id: The entity identifier.
            field: The behavioral field/dimension.
            value: The observed value.
            value_count: Historical count of this value before recording.
            observation_count: Total profile observation count after recording.
            first_seen: Earliest observed timestamp.
            last_seen: Most recent observed timestamp.
            maturity_min_observations: Configured minimum for maturity.
            maturity_window_seconds: Configured maturity time window.
            top_comparison_values: Bounded list of other observed values.
            is_stale: Whether the profile was stale before this observation.

        Returns:
            BaselineEvidence for warming classification.
        """
        reason = (
            BaselineReasonCode.PROFILE_STALE if is_stale else BaselineReasonCode.PROFILE_WARMING
        )
        status = "stale and re-warming" if is_stale else "warming"

        # Determine maturity reason
        age_reasons: list[str] = []
        if first_seen is not None and last_seen is not None:
            age = (last_seen - first_seen).total_seconds()
            if observation_count < maturity_min_observations:
                age_reasons.append(
                    f"only {observation_count} observations (need {maturity_min_observations})"
                )
            if age < maturity_window_seconds:
                age_reasons.append(f"only {age:.0f}s age (need {maturity_window_seconds:.0f}s)")
        elif observation_count < maturity_min_observations:
            age_reasons.append(
                f"only {observation_count} observations (need {maturity_min_observations})"
            )

        if age_reasons:
            maturity_detail = f"Profile not yet mature: {'; '.join(age_reasons)}."
        else:
            maturity_detail = "Profile is warming."

        explanation = (
            f"Baseline profile for {field} on entity '{entity_id}' is {status}. "
            f"Value '{value}' seen {value_count} time(s) previously. "
            f"{maturity_detail}"
        )

        return cls(
            reason_code=reason,
            classification="baseline_warming",
            profile_maturity="warming",
            value_count=value_count,
            rare_threshold=0,
            observation_count=observation_count,
            maturity_min_observations=maturity_min_observations,
            maturity_window_seconds=maturity_window_seconds,
            first_seen=first_seen,
            last_seen=last_seen,
            top_comparison_values=tuple(top_comparison_values) if top_comparison_values else (),
            explanation=explanation,
        )

    @classmethod
    def for_new_value(
        cls,
        entity_id: str,
        field: str,
        value: str,
        observation_count: int,
        first_seen: datetime | None,
        last_seen: datetime | None,
        maturity_min_observations: int,
        maturity_window_seconds: float,
        top_comparison_values: tuple[tuple[str, int], ...] | list[tuple[str, int]] | None = None,
    ) -> BaselineEvidence:
        """Create evidence for BASELINE_NEW_VALUE classification.

        Args:
            entity_id: The entity identifier.
            field: The behavioral field/dimension.
            value: The newly observed value.
            observation_count: Total profile observation count after recording.
            first_seen: Earliest observed timestamp.
            last_seen: Most recent observed timestamp.
            maturity_min_observations: Configured minimum for maturity.
            maturity_window_seconds: Configured maturity time window.
            top_comparison_values: Bounded list of other observed values.

        Returns:
            BaselineEvidence for new value classification.
        """
        explanation = (
            f"Value '{value}' has never been observed for {field} on entity '{entity_id}'. "
            f"Profile has {observation_count} total observation(s) across "
            f"{len(top_comparison_values) if top_comparison_values else 0} distinct value(s). "
            f"Profile maturity: {'mature' if observation_count >= maturity_min_observations else 'warming'}."
        )
        return cls(
            reason_code=BaselineReasonCode.VALUE_NEW,
            classification="baseline_new_value",
            profile_maturity="mature",
            value_count=0,
            rare_threshold=0,
            observation_count=observation_count,
            maturity_min_observations=maturity_min_observations,
            maturity_window_seconds=maturity_window_seconds,
            first_seen=first_seen,
            last_seen=last_seen,
            top_comparison_values=tuple(top_comparison_values) if top_comparison_values else (),
            explanation=explanation,
        )

    @classmethod
    def for_rare_value(
        cls,
        entity_id: str,
        field: str,
        value: str,
        value_count: int,
        rare_threshold: int,
        observation_count: int,
        first_seen: datetime | None,
        last_seen: datetime | None,
        maturity_min_observations: int,
        maturity_window_seconds: float,
        top_comparison_values: tuple[tuple[str, int], ...] | list[tuple[str, int]] | None = None,
    ) -> BaselineEvidence:
        """Create evidence for BASELINE_RARE_VALUE classification.

        Args:
            entity_id: The entity identifier.
            field: The behavioral field/dimension.
            value: The observed value.
            value_count: Historical count of this value before recording.
            rare_threshold: The configured rare threshold.
            observation_count: Total profile observation count after recording.
            first_seen: Earliest observed timestamp.
            last_seen: Most recent observed timestamp.
            maturity_min_observations: Configured minimum for maturity.
            maturity_window_seconds: Configured maturity time window.
            top_comparison_values: Bounded list of other observed values.

        Returns:
            BaselineEvidence for rare value classification.
        """
        if value_count == rare_threshold:
            reason = BaselineReasonCode.VALUE_COUNT_AT_THRESHOLD
            count_desc = f"exactly at threshold ({value_count} == {rare_threshold})"
        else:
            reason = BaselineReasonCode.VALUE_COUNT_BELOW_THRESHOLD
            count_desc = f"below threshold ({value_count} <= {rare_threshold})"

        explanation = (
            f"Value '{value}' for {field} on entity '{entity_id}' is rare. "
            f"Historical count: {value_count} ({count_desc}). "
            f"Profile has {observation_count} total observation(s). "
            f"Established threshold: count > {rare_threshold}."
        )
        return cls(
            reason_code=reason,
            classification="baseline_rare_value",
            profile_maturity="mature",
            value_count=value_count,
            rare_threshold=rare_threshold,
            observation_count=observation_count,
            maturity_min_observations=maturity_min_observations,
            maturity_window_seconds=maturity_window_seconds,
            first_seen=first_seen,
            last_seen=last_seen,
            top_comparison_values=tuple(top_comparison_values) if top_comparison_values else (),
            explanation=explanation,
        )

    @classmethod
    def for_established(
        cls,
        entity_id: str,
        field: str,
        value: str,
        value_count: int,
        rare_threshold: int,
        observation_count: int,
        first_seen: datetime | None,
        last_seen: datetime | None,
        maturity_min_observations: int,
        maturity_window_seconds: float,
        top_comparison_values: tuple[tuple[str, int], ...] | list[tuple[str, int]] | None = None,
    ) -> BaselineEvidence:
        """Create evidence for BASELINE_ESTABLISHED classification.

        Args:
            entity_id: The entity identifier.
            field: The behavioral field/dimension.
            value: The observed value.
            value_count: Historical count of this value before recording.
            rare_threshold: The configured rare threshold.
            observation_count: Total profile observation count after recording.
            first_seen: Earliest observed timestamp.
            last_seen: Most recent observed timestamp.
            maturity_min_observations: Configured minimum for maturity.
            maturity_window_seconds: Configured maturity time window.
            top_comparison_values: Bounded list of other observed values.

        Returns:
            BaselineEvidence for established value classification.
        """
        explanation = (
            f"Value '{value}' for {field} on entity '{entity_id}' is established. "
            f"Historical count: {value_count} (threshold: >{rare_threshold}). "
            f"Profile has {observation_count} total observation(s) "
            f"over {((last_seen - first_seen).total_seconds() if first_seen and last_seen else 0):.0f}s window."
        )
        return cls(
            reason_code=BaselineReasonCode.VALUE_ESTABLISHED,
            classification="baseline_established",
            profile_maturity="mature",
            value_count=value_count,
            rare_threshold=rare_threshold,
            observation_count=observation_count,
            maturity_min_observations=maturity_min_observations,
            maturity_window_seconds=maturity_window_seconds,
            first_seen=first_seen,
            last_seen=last_seen,
            top_comparison_values=tuple(top_comparison_values) if top_comparison_values else (),
            explanation=explanation,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the evidence to a dictionary.

        Returns:
            Dictionary representation of the evidence.
        """
        return {
            "reason_code": self.reason_code.value,
            "classification": self.classification,
            "profile_maturity": self.profile_maturity,
            "value_count": self.value_count,
            "rare_threshold": self.rare_threshold,
            "observation_count": self.observation_count,
            "maturity_min_observations": self.maturity_min_observations,
            "maturity_window_seconds": self.maturity_window_seconds,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "top_comparison_values": list(self.top_comparison_values),
            "explanation": self.explanation,
        }
