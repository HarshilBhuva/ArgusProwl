"""Entity behavior detector implementation.

Detects first-seen values for configured entity+dimension combinations.
"""

from __future__ import annotations

import hashlib
from typing import Any

from argusprowl.behavior.entity_behavior_service import EntityBehaviorService
from argusprowl.constants.severity import Severity
from argusprowl.interfaces.detector import Detector
from argusprowl.metrics.collector import MetricsCollector
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent

# Valid entity types that can be extracted from NormalizedEvent
VALID_ENTITY_TYPES: set[str] = {
    "hostname",
    "src_ip",
    "dst_ip",
    "username",
    "process_name",
    "pid",
}

# Valid dimension fields that can be extracted from NormalizedEvent
VALID_DIMENSION_FIELDS: set[str] = {
    "process_name",
    "dst_ip",
    "dst_port",
    "protocol",
    "username",
    "event_type",
    "source_type",
    "command_line",
    "hostname",
    "src_ip",
}


class EntityBehaviorDetector(Detector):
    """Detects first-seen values for entity+dimension combinations.

    Monitors events for a specific entity type and dimension field, tracking
    which dimension values have been observed. When a new value is seen for
    an entity, emits a DetectionResult with severity INFO.

    Thread-safe via the EntityBehaviorService.

    Attributes:
        name: Unique rule identifier.
        entity_type: Type of entity to track (e.g., 'hostname', 'src_ip').
        dimension_field: Field to track for first-seen (e.g., 'process_name', 'dst_ip').
        confidence: Confidence score for detections.
        version: Rule version.
    """

    def __init__(
        self,
        name: str,
        entity_type: str,
        dimension_field: str,
        enabled: bool = True,
        confidence: float = 1.0,
        version: int = 1,
        config: dict[str, Any] | None = None,
        behavior_service: EntityBehaviorService | None = None,
        rare_threshold: int = 3,
        rare_min_observations: int = 5,
        metrics_collector: MetricsCollector | None = None,
    ) -> None:
        """Initialize entity behavior detector.

        Args:
            name: Unique rule identifier.
            entity_type: Type of entity to track (e.g., 'hostname', 'src_ip').
            dimension_field: Field to track for first-seen (e.g., 'process_name', 'dst_ip').
            enabled: Whether the detector is active.
            confidence: Confidence score for detections.
            version: Rule version.
            config: Optional configuration dictionary.
            behavior_service: Optional EntityBehaviorService instance.
            rare_threshold: Threshold for rare value detection.
            rare_min_observations: Minimum observations before rare detection.
            metrics_collector: Optional MetricsCollector for telemetry.
        """
        if entity_type not in VALID_ENTITY_TYPES:
            raise ValueError(
                f"Invalid entity_type: {entity_type}. Valid types: {sorted(VALID_ENTITY_TYPES)}"
            )
        if dimension_field not in VALID_DIMENSION_FIELDS:
            raise ValueError(
                f"Invalid dimension_field: {dimension_field}. "
                f"Valid fields: {sorted(VALID_DIMENSION_FIELDS)}"
            )
        if not 0.0 <= confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {confidence}")

        self._name = name
        self._entity_type = entity_type
        self._dimension_field = dimension_field
        self._enabled = enabled
        self._confidence = confidence
        self._version = version
        self._config = config or {}
        self._behavior_service = behavior_service or EntityBehaviorService()
        self._detections_count = 0
        self._rare_threshold = rare_threshold
        self._rare_min_observations = rare_min_observations
        self._metrics_collector = metrics_collector

        # Register metrics through existing collector if provided
        self._first_seen_count = self._register_counter("entity_behavior_first_seen")
        self._rare_count = self._register_counter("entity_behavior_rare")
        self._no_match_count = self._register_counter("entity_behavior_no_match")

    @property
    def name(self) -> str:
        """Return the detector name."""
        return self._name

    @property
    def confidence(self) -> float:
        """Return the confidence score for detections."""
        return self._confidence

    @property
    def description(self) -> str:
        """Return the detector description."""
        return "Detects first-seen values for entity+dimension combinations"

    @property
    def version(self) -> int:
        """Return the detector version."""
        return self._version

    @property
    def entity_type(self) -> str:
        """Return the entity type being tracked."""
        return self._entity_type

    @property
    def dimension_field(self) -> str:
        """Return the dimension field being tracked."""
        return self._dimension_field

    def is_enabled(self) -> bool:
        """Return whether the detector is enabled."""
        return self._enabled

    def enable(self) -> None:
        """Enable this detector."""
        self._enabled = True

    def disable(self) -> None:
        """Disable this detector."""
        self._enabled = False

    def configure(self, config: dict[str, Any]) -> None:
        """Update detector configuration."""
        self._config.update(config)

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self._config.get(key, default)

    def _extract_entity_value(self, event: NormalizedEvent) -> str | None:
        """Extract the entity value from an event.

        Args:
            event: The normalized event.

        Returns:
            The entity value or None if not present.
        """
        value = getattr(event, self._entity_type, None)
        if value is not None:
            return str(value)
        return None

    def _extract_dimension_value(self, event: NormalizedEvent) -> str | None:
        """Extract the dimension value from an event.

        Args:
            event: The normalized event.

        Returns:
            The dimension value or None if not present.
        """
        value = getattr(event, self._dimension_field, None)
        if value is not None:
            return str(value)
        return None

    def _get_bounded_representation(self, value: str) -> str:
        """Return a bounded representation of a string for evidence and metadata.

        If the value exceeds the maximum length, return its SHA-256 hash.
        Otherwise, return the value as-is.

        Args:
            value: The string to bound.

        Returns:
            A string representation bounded by the service's max_value_length.
        """
        max_value_length = self._behavior_service.max_value_length
        if len(value) > max_value_length:
            return hashlib.sha256(value.encode("utf-8")).hexdigest()
        return value

    def _register_counter(self, name: str) -> Any:
        """Register or retrieve a counter metric.

        Args:
            name: Metric name.

        Returns:
            Counter instance.
        """
        if self._metrics_collector is None:
            from argusprowl.metrics.metrics import Counter

            return Counter(name)
        try:
            return self._metrics_collector.get_counter(name)
        except KeyError:
            return self._metrics_collector.register_counter(name)

    def _increment_detections(self) -> None:
        """Increment the detection counter (called by DetectionManager)."""
        self._detections_count += 1

    def observe(self, event: NormalizedEvent) -> None:
        """Pre-process an event before detection.

        Records the event observation in the behavior service for state tracking.
        This is called by DetectionManager before detect().

        Note: For first-seen detection, observe() does NOT record the value to the
        value set. It only creates the profile if needed. The actual first-seen
        check and value recording is done in detect() to ensure atomicity.

        Args:
            event: The normalized event to observe.
        """
        if not self._enabled:
            return

        entity_value = self._extract_entity_value(event)
        dimension_value = self._extract_dimension_value(event)

        if entity_value is None or dimension_value is None:
            return

        # Only create the profile if it doesn't exist (don't record the value yet)
        self._behavior_service.get_or_create_profile(
            entity_type=self._entity_type,
            entity_id=entity_value,
            dimension=self._dimension_field,
            timestamp=event.timestamp,
        )

    def detect(self, event: NormalizedEvent) -> DetectionResult:
        """Evaluate an event for first-seen and rare behavior.

        Checks if the dimension value is new for the entity and emits a detection
        result if it is. Also checks for rare values based on the configured threshold.
        Uses atomic check-and-record to ensure consistency.

        Args:
            event: The normalized event to evaluate.

        Returns:
            DetectionResult indicating first-seen or rare detection.
        """
        if not self._enabled:
            return self._no_match_result(event)

        # Extract entity and dimension values
        entity_value = self._extract_entity_value(event)
        dimension_value = self._extract_dimension_value(event)

        # Missing entity or dimension: no detection
        if entity_value is None:
            return self._no_match_result(event, "missing_entity")
        if dimension_value is None:
            return self._no_match_result(event, "missing_dimension")

        # Check and record atomically - this is the first-seen check
        profile, is_first_seen = self._behavior_service.check_and_record_first_seen(
            entity_type=self._entity_type,
            entity_id=entity_value,
            dimension=self._dimension_field,
            dimension_value=dimension_value,
            timestamp=event.timestamp,
        )

        # Check for rare detection
        if profile is not None:
            value_count = self._behavior_service.get_value_count(
                entity_type=self._entity_type,
                entity_id=entity_value,
                dimension=self._dimension_field,
                dimension_value=dimension_value,
            )
            is_rare = value_count < self._rare_threshold
            is_mature = profile.observation_count >= self._rare_min_observations

            if is_rare and is_mature and not is_first_seen:
                self._detections_count += 1
                self._rare_count.increment()
                return self._build_rare_result(
                    event, entity_value, dimension_value, profile, value_count
                )

        if is_first_seen:
            self._detections_count += 1
            self._first_seen_count.increment()
            return self._build_first_seen_result(event, entity_value, dimension_value, profile)
        else:
            self._no_match_count.increment()
            return self._no_match_result(event)

    def _no_match_result(
        self,
        event: NormalizedEvent,
        reason: str = "no_match",
    ) -> DetectionResult:
        """Build a no-match DetectionResult.

        Args:
            event: The event being evaluated.
            reason: Reason code for no match.

        Returns:
            DetectionResult with matched=False.
        """
        return DetectionResult(
            rule_id=self._name,
            event_id=event.event_id,
            matched=False,
            severity=Severity.INFO,
            confidence=self._confidence,
            description="",
            explanation="",
            evidence=[],
            metadata={"reason": reason},
        )

    def _build_first_seen_result(
        self,
        event: NormalizedEvent,
        entity_value: str,
        dimension_value: str,
        profile,
    ) -> DetectionResult:
        """Build a first-seen DetectionResult.

        Args:
            event: The event that triggered the detection.
            entity_value: The entity identifier.
            dimension_value: The newly observed dimension value.
            profile: The entity behavior profile.

        Returns:
            DetectionResult with matched=True.
        """
        # Build evidence
        evidence = [
            {"field": "entity_type", "observed": self._entity_type, "condition": "equals"},
            {
                "field": "entity_id",
                "observed": self._get_bounded_representation(entity_value),
                "condition": "equals",
            },
            {"field": "dimension", "observed": self._dimension_field, "condition": "equals"},
            {
                "field": "first_value",
                "observed": self._get_bounded_representation(dimension_value),
                "condition": "equals",
            },
            {
                "field": "first_seen_timestamp",
                "observed": event.timestamp.isoformat(),
                "condition": "equals",
            },
            {
                "field": "profile_maturity",
                "observed": profile.maturity.value,
                "condition": "equals",
            },
            {
                "field": "observation_count",
                "observed": profile.observation_count,
                "condition": "equals",
            },
        ]

        # Build metadata
        metadata = {
            "entity_type": self._entity_type,
            "entity_id": self._get_bounded_representation(entity_value),
            "dimension": self._dimension_field,
            "first_value": self._get_bounded_representation(dimension_value),
            "profile_maturity": profile.maturity.value,
            "observation_count": profile.observation_count,
            "detection_type": "first_seen",
        }

        # Build description
        description = (
            f"First seen: {dimension_value} for {self._entity_type} {entity_value} "
            f"at {event.timestamp.isoformat()}"
        )

        # Build explanation
        explanation = (
            f"New {self._dimension_field} value '{dimension_value}' observed "
            f"for {self._entity_type} '{entity_value}'. "
            f"This is the first occurrence in this behavioral profile "
            f"(observation count: {profile.observation_count}, "
            f"maturity: {profile.maturity.value})."
        )

        return DetectionResult(
            rule_id=self._name,
            event_id=event.event_id,
            matched=True,
            severity=Severity.INFO,
            confidence=self._confidence,
            description=description,
            explanation=explanation,
            evidence=evidence,
            contributing_event_ids=(event.event_id,),
            metadata=metadata,
        )

    def _build_rare_result(
        self,
        event: NormalizedEvent,
        entity_value: str,
        dimension_value: str,
        profile,
        value_count: int,
    ) -> DetectionResult:
        """Build a rare DetectionResult.

        Args:
            event: The event that triggered the detection.
            entity_value: The entity identifier.
            dimension_value: The observed dimension value.
            profile: The entity behavior profile.
            value_count: The count of the observed value.

        Returns:
            DetectionResult with matched=True.
        """
        # Build evidence
        evidence = [
            {"field": "entity_type", "observed": self._entity_type, "condition": "equals"},
            {
                "field": "entity_id",
                "observed": self._get_bounded_representation(entity_value),
                "condition": "equals",
            },
            {"field": "dimension", "observed": self._dimension_field, "condition": "equals"},
            {
                "field": "rare_value",
                "observed": self._get_bounded_representation(dimension_value),
                "condition": "equals",
            },
            {"field": "value_count", "observed": value_count, "condition": "equals"},
            {"field": "rare_threshold", "observed": self._rare_threshold, "condition": "equals"},
            {
                "field": "total_observations",
                "observed": profile.observation_count,
                "condition": "equals",
            },
            {
                "field": "rare_min_observations",
                "observed": self._rare_min_observations,
                "condition": "equals",
            },
            {
                "field": "profile_maturity",
                "observed": profile.maturity.value,
                "condition": "equals",
            },
        ]

        # Build metadata
        metadata = {
            "entity_type": self._entity_type,
            "entity_id": self._get_bounded_representation(entity_value),
            "dimension": self._dimension_field,
            "rare_value": self._get_bounded_representation(dimension_value),
            "value_count": value_count,
            "rare_threshold": self._rare_threshold,
            "total_observations": profile.observation_count,
            "rare_min_observations": self._rare_min_observations,
            "profile_maturity": profile.maturity.value,
            "detection_type": "rare",
        }

        # Build description
        description = (
            f"Rare {self._dimension_field} value: {dimension_value} for "
            f"{self._entity_type} {entity_value}"
        )

        # Build explanation
        explanation = (
            f"The {self._dimension_field} value '{dimension_value}' was observed "
            f"{value_count} times, which is below the rare threshold of {self._rare_threshold}. "
            f"The profile has {profile.observation_count} total observations, "
            f"satisfying the minimum requirement of {self._rare_min_observations}."
        )

        return DetectionResult(
            rule_id=self._name,
            event_id=event.event_id,
            matched=True,
            severity=Severity.INFO,
            confidence=self._confidence,
            description=description,
            explanation=explanation,
            evidence=evidence,
            contributing_event_ids=(event.event_id,),
            metadata=metadata,
        )

    def get_stats(self) -> dict[str, Any]:
        """Get detector statistics.

        Returns:
            Dictionary of statistics.
        """
        return {
            "name": self._name,
            "entity_type": self._entity_type,
            "dimension_field": self._dimension_field,
            "enabled": self._enabled,
            "detections_count": self._detections_count,
            "profile_count": self._behavior_service.profile_count,
            "first_seen_count": self._first_seen_count.get_value(),
            "rare_count": self._rare_count.get_value(),
            "no_match_count": self._no_match_count.get_value(),
        }
