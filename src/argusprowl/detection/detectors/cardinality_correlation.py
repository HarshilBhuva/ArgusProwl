"""Cardinality correlation detector.

Detects when a configured number of unique values for a specific field
occur within a time window, grouped by specified fields. Used for
horizontal scanning, vertical scanning, and other cardinality-based
correlation patterns.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import timedelta
from pathlib import Path
from threading import Lock
from typing import Any, ClassVar

from argusprowl.constants.severity import Severity
from argusprowl.detection.detectors.cardinality_state import CardinalityState
from argusprowl.exceptions.exceptions import DetectionError
from argusprowl.interfaces.detector import Detector
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


class CardinalityCorrelationDetector(Detector):
    """Detects unique value count thresholds within sliding time windows.

    Groups events by configured fields, counts unique values of a target field
    within a sliding window, and produces DetectionResult when thresholds are met.

    This detector maintains bounded state to prevent resource exhaustion:
    - Maximum number of group keys (LRU eviction)
    - Maximum observations per key (FIFO eviction)
    - Configurable time window

    Thread-safe for concurrent access.
    """

    # Valid grouping fields that can be extracted from NormalizedEvent
    VALID_GROUP_BY_FIELDS: ClassVar[set[str]] = {
        "src_ip",
        "dst_ip",
        "hostname",
        "username",
        "event_type",
    }

    # Valid filter fields
    VALID_FILTER_FIELDS: ClassVar[set[str]] = {
        "event_type",
        "source_type",
        "src_ip",
        "dst_ip",
        "hostname",
        "username",
        "process_name",
    }

    # Timespan pattern: number followed by unit (s/m/h/d)
    _TIMESPAN_PATTERN = re.compile(r"^(\d+)([smhd])$")

    @staticmethod
    def parse_timespan(timespan_str: str, rule_path: Path | None = None) -> timedelta:
        """Parse a timespan string into a timedelta.

        Args:
            timespan_str: String in format '<number><unit>' where unit is s/m/h/d.
            rule_path: Optional path for error messages.

        Returns:
            Parsed timedelta.

        Raises:
            DetectionError: If the timespan format is invalid.
        """
        match = CardinalityCorrelationDetector._TIMESPAN_PATTERN.match(str(timespan_str))
        if not match:
            raise DetectionError(
                f"Invalid timespan format: {timespan_str}. Expected format: <number><unit> (s/m/h/d)",
                details={"path": str(rule_path) if rule_path else None, "timespan": timespan_str},
            )
        value = int(match.group(1))
        unit = match.group(2)
        if value <= 0:
            raise DetectionError(
                f"Timespan value must be positive, got {value}",
                details={"path": str(rule_path) if rule_path else None, "timespan": timespan_str},
            )
        if unit == "s":
            return timedelta(seconds=value)
        elif unit == "m":
            return timedelta(minutes=value)
        elif unit == "h":
            return timedelta(hours=value)
        elif unit == "d":
            return timedelta(days=value)
        raise DetectionError(
            f"Unsupported timespan unit: {unit}",
            details={"path": str(rule_path) if rule_path else None, "timespan": timespan_str},
        )

    def __init__(
        self,
        cardinality_field: str,
        threshold: int = 15,
        timespan: timedelta = timedelta(minutes=5),
        group_by: list[str] | None = None,
        filter_config: dict[str, Any] | None = None,
        max_keys: int = 10000,
        max_observations_per_key: int = 1000,
        confidence: float = 0.7,
        version: int = 1,
        enabled: bool = True,
        config: dict[str, Any] | None = None,
        name: str = "cardinality_correlation",
    ) -> None:
        """Initialize cardinality correlation detector.

        Args:
            cardinality_field: The field to count unique values for.
            threshold: Minimum unique count to trigger detection.
            timespan: Sliding window duration for event counting.
            group_by: Fields to group events by. Defaults to ["src_ip"].
            filter_config: Optional event filtering criteria.
            max_keys: Maximum number of group keys to track.
            max_observations_per_key: Maximum observations per group key.
            confidence: Confidence score for matched detections.
            version: Rule version.
            enabled: Whether detector is active.
            config: Optional configuration dictionary.
            name: Detector name/rule ID.
        """
        self._cardinality_field = cardinality_field
        self._threshold = threshold
        self._timespan = timespan
        self._group_by = group_by or ["src_ip"]
        self._filter_config = filter_config or {}
        self._max_keys = max_keys
        self._max_observations_per_key = max_observations_per_key
        self._confidence = confidence
        self._version = version
        self._enabled = enabled
        self._config = config or {}
        self._name = name
        self._detections_count = 0

        # Bounded state storage
        self._state: OrderedDict[tuple[str, ...], CardinalityState] = OrderedDict()
        self._lock = Lock()

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "Detects unique value count thresholds within sliding time windows"

    @property
    def version(self) -> int:
        return self._version

    def is_enabled(self) -> bool:
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

    def _build_group_key(self, event: NormalizedEvent) -> tuple[str, ...]:
        """Build a group key from the event's configured fields.

        Args:
            event: The normalized event.

        Returns:
            Tuple of string values for the configured group fields.
        """
        key_parts = []
        for field in self._group_by:
            value = getattr(event, field, None)
            key_parts.append(str(value) if value is not None else "")
        return tuple(key_parts)

    def _matches_filter(self, event: NormalizedEvent) -> bool:
        """Check if event matches the configured filter criteria.

        Args:
            event: The normalized event to check.

        Returns:
            True if event matches all filter criteria, False otherwise.
        """
        if not self._filter_config:
            return True

        for field, expected_value in self._filter_config.items():
            actual_value = getattr(event, field, None)
            if actual_value != expected_value:
                return False

        return True

    def observe(self, event: NormalizedEvent) -> None:
        """Observe an event and update state.

        Args:
            event: The normalized event to observe.
        """
        if not self._enabled:
            return

        if not self._matches_filter(event):
            return

        cardinality_value = getattr(event, self._cardinality_field, None)
        if cardinality_value is None or cardinality_value == "":
            return

        group_key = self._build_group_key(event)

        with self._lock:
            state = self._state.get(group_key)
            if state is None:
                if len(self._state) >= self._max_keys:
                    self._state.popitem(last=False)
                state = CardinalityState(
                    group_key=group_key,
                    window_duration=self._timespan,
                    max_observations=self._max_observations_per_key,
                )
                self._state[group_key] = state
            else:
                self._state.move_to_end(group_key)

        state.add(event, cardinality_value)

    def detect(self, event: NormalizedEvent) -> DetectionResult:
        """Evaluate the event against the cardinality threshold.

        Args:
            event: The normalized event to evaluate.

        Returns:
            DetectionResult indicating whether the threshold was crossed.
        """
        if not self._enabled:
            return DetectionResult(
                rule_id=self._name,
                event_id=event.event_id,
                matched=False,
                version=self._version,
            )

        if not self._matches_filter(event):
            return DetectionResult(
                rule_id=self._name,
                event_id=event.event_id,
                matched=False,
                version=self._version,
            )

        cardinality_value = getattr(event, self._cardinality_field, None)
        if cardinality_value is None or cardinality_value == "":
            return DetectionResult(
                rule_id=self._name,
                event_id=event.event_id,
                matched=False,
                version=self._version,
            )

        group_key = self._build_group_key(event)

        with self._lock:
            state = self._state.get(group_key)

        if state is None:
            return DetectionResult(
                rule_id=self._name,
                event_id=event.event_id,
                matched=False,
                version=self._version,
            )

        triggered, unique_count, trigger_event_id = state.check_threshold(self._threshold, event)

        if not triggered or trigger_event_id != event.event_id:
            return DetectionResult(
                rule_id=self._name,
                event_id=event.event_id,
                matched=False,
                version=self._version,
            )

        self._detections_count += 1

        # Build evidence
        evidence = [
            {
                "field": self._cardinality_field,
                "observed": unique_count,
                "condition": f">= {self._threshold}",
            }
        ]

        # Add group fields to evidence
        for field_name, field_value in zip(self._group_by, group_key, strict=False):
            evidence.append(
                {
                    "field": field_name,
                    "observed": field_value,
                    "condition": "==",
                }
            )

        metadata = {
            "timespan_seconds": state.get_timespan(),
            "sample_values": state.get_sample_values(limit=5),
        }

        return DetectionResult(
            rule_id=self._name,
            event_id=event.event_id,
            matched=True,
            severity=Severity.HIGH,
            confidence=self._confidence,
            description=f"Observed {unique_count} unique {self._cardinality_field} values within {self._timespan.total_seconds()}s",
            explanation=f"Threshold of {self._threshold} unique values exceeded.",
            evidence=evidence,
            version=self._version,
            contributing_event_ids=state.get_contributing_event_ids(limit=50),
            metadata=metadata,
        )
