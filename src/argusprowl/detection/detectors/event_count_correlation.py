"""Event-count correlation detector.

Detects when a configured number of events occur within a time window,
grouped by specified fields. Used for brute force detection, scanning,
and other threshold-based correlation patterns.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import timedelta
from pathlib import Path
from threading import Lock
from typing import Any, ClassVar

from argusprowl.constants.severity import Severity
from argusprowl.detection.detectors.event_count_state import EventCountState
from argusprowl.exceptions.exceptions import DetectionError
from argusprowl.interfaces.detector import Detector
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


class EventCountCorrelationDetector(Detector):
    """Detects event count thresholds within sliding time windows.

    Groups events by configured fields, counts occurrences within a
    sliding window, and produces DetectionResult when thresholds are met.

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
        match = EventCountCorrelationDetector._TIMESPAN_PATTERN.match(str(timespan_str))
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
        # Should not reach here due to regex, but be safe
        raise DetectionError(
            f"Unsupported timespan unit: {unit}",
            details={"path": str(rule_path) if rule_path else None, "timespan": timespan_str},
        )

    def __init__(
        self,
        count: int = 5,
        timespan: timedelta = timedelta(minutes=5),
        group_by: list[str] | None = None,
        filter_config: dict[str, Any] | None = None,
        max_keys: int = 10000,
        max_observations_per_key: int = 1000,
        confidence: float = 0.7,
        version: int = 1,
        enabled: bool = True,
        config: dict[str, Any] | None = None,
        name: str = "event_count_correlation",
    ) -> None:
        """Initialize event-count correlation detector.

        Args:
            count: Minimum event count to trigger detection.
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
        self._count = count
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
        self._state: OrderedDict[tuple[str, ...], EventCountState] = OrderedDict()
        self._lock = Lock()

    @property
    def confidence(self) -> float:
        return self._confidence

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "Detects event count thresholds within sliding time windows"

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
            True if event matches all filter criteria.
        """
        if not self._filter_config:
            return True

        for field, expected_value in self._filter_config.items():
            actual_value = getattr(event, field, None)
            if actual_value != expected_value:
                return False

        return True

    def observe(self, event: NormalizedEvent) -> None:
        """Observe an event and update correlation state.

        This method is called by the application pipeline to feed events
        into the correlator. It does not produce DetectionResult directly;
        use detect() to check for threshold crossings.

        Args:
            event: The normalized event to observe.
        """
        if not self._matches_filter(event):
            return

        group_key = self._build_group_key(event)

        with self._lock:
            if group_key in self._state:
                state = self._state[group_key]
                state.add(event)
                # Move to end for LRU
                self._state.move_to_end(group_key)
            else:
                if len(self._state) >= self._max_keys:
                    # Evict least recently used
                    self._state.popitem(last=False)
                state = EventCountState(
                    group_key=group_key,
                    window_duration=self._timespan,
                    max_observations=self._max_observations_per_key,
                )
                state.add(event)
                self._state[group_key] = state

    def detect(self, event: NormalizedEvent) -> DetectionResult:
        """Evaluate an event for event-count correlation.

        Checks if the event causes a threshold crossing in any group.

        Args:
            event: The normalized event to evaluate.

        Returns:
            DetectionResult with correlation evidence if triggered.
        """
        if not self._matches_filter(event):
            return self._no_match(event)

        group_key = self._build_group_key(event)

        with self._lock:
            state = self._state.get(group_key)
            if state is None:
                return self._no_match(event)

            triggered, count, trigger_event_id = state.check_threshold(self._count, event)

        if triggered:
            self._detections_count += 1
            return self._create_detection_result(
                event=event,
                group_key=group_key,
                count=count,
                trigger_event_id=trigger_event_id,
            )

        return self._no_match(event)

    def _create_detection_result(
        self,
        event: NormalizedEvent,
        group_key: tuple[str, ...],
        count: int,
        trigger_event_id: Any,
    ) -> DetectionResult:
        """Create a DetectionResult for a threshold crossing.

        Args:
            event: The triggering event.
            group_key: The group key that triggered.
            count: The event count at threshold crossing.
            trigger_event_id: The event that caused the threshold crossing.

        Returns:
            DetectionResult with correlation evidence.
        """
        # Get contributing events from state
        with self._lock:
            state = self._state.get(group_key)
            if state is None:
                contributing_ids = (trigger_event_id,)
                timespan = 0.0
            else:
                contributing_ids = state.get_contributing_event_ids()
                timespan = state.get_timespan()

        # Build group key description
        group_desc = ", ".join(
            f"{field}={value}" for field, value in zip(self._group_by, group_key, strict=False)
        )

        description = (
            f"Event count threshold reached: {count} events from {group_desc} "
            f"within {self._timespan.total_seconds():.0f}s"
        )

        explanation = (
            f"Detected {count} events matching the correlation criteria within "
            f"the configured time window. Group: {group_desc}. "
            f"Timespan: {timespan:.1f}s. Threshold: {self._count}."
        )

        evidence = [
            {
                "field": "event_count",
                "observed": count,
                "condition": f">= {self._count}",
            },
            {
                "field": "group_key",
                "observed": group_desc,
                "condition": "equals",
            },
            {
                "field": "timespan_seconds",
                "observed": round(timespan, 2),
                "condition": "<=",
            },
            {
                "field": "window_duration_seconds",
                "observed": self._timespan.total_seconds(),
                "condition": "equals",
            },
        ]

        metadata = {
            "correlation_type": "event_count",
            "group_by": self._group_by,
            "count": count,
            "threshold": self._count,
            "window_duration_seconds": self._timespan.total_seconds(),
            "timespan_seconds": round(timespan, 2),
            "rule_version": self._version,
        }

        return DetectionResult(
            rule_id=self.name,
            event_id=trigger_event_id,
            matched=True,
            severity=Severity.HIGH,
            confidence=self._confidence,
            description=description,
            explanation=explanation,
            evidence=evidence,
            version=self._version,
            contributing_event_ids=contributing_ids,
            metadata=metadata,
        )

    def _no_match(self, event: NormalizedEvent) -> DetectionResult:
        """Return non-matching detection result."""
        return DetectionResult(
            rule_id=self.name,
            event_id=event.event_id,
            matched=False,
        )

    def _increment_detections(self) -> None:
        """Increment detection counter (used by DetectionManager)."""
        self._detections_count += 1

    @property
    def detections_count(self) -> int:
        return self._detections_count

    def get_state_keys(self) -> int:
        """Return the number of active group keys."""
        with self._lock:
            return len(self._state)

    def get_all_counts(self) -> dict[tuple[str, ...], int]:
        """Return current counts for all group keys."""
        with self._lock:
            return {key: state.count for key, state in self._state.items()}
