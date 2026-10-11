"""Ordered sequence correlation detector.

Detects when a configured ordered sequence of events occurs within a time window,
grouped by specified fields. Used for multi-step attack detection.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import timedelta
from pathlib import Path
from threading import Lock
from typing import Any, ClassVar

from argusprowl.constants.severity import Severity
from argusprowl.detection.detectors.ordered_sequence_state import OrderedSequenceState
from argusprowl.exceptions.exceptions import DetectionError
from argusprowl.interfaces.detector import Detector
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


class OrderedSequenceDetector(Detector):
    """Detects ordered event sequences within sliding time windows.

    Groups events by configured fields, tracks progress toward a configured
    sequence of event types, and produces DetectionResult when sequences complete.

    This detector maintains bounded state to prevent resource exhaustion:
    - Maximum number of group keys (LRU eviction)
    - Maximum sequences per group (bounded deque)
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

    # Valid filter fields for step conditions
    VALID_FILTER_FIELDS: ClassVar[set[str]] = {
        "event_type",
        "source_type",
        "src_ip",
        "dst_ip",
        "hostname",
        "username",
        "process_name",
    }

    # Maximum allowed sequence duration (e.g., 30 days) to prevent unbounded state
    MAX_ALLOWED_TIMESPAN = timedelta(days=30)

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
        match = OrderedSequenceDetector._TIMESPAN_PATTERN.match(str(timespan_str))
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
        steps: list[dict[str, Any]],
        timespan: timedelta = timedelta(minutes=5),
        group_by: list[str] | None = None,
        max_keys: int = 10000,
        max_sequences_per_key: int = 100,
        confidence: float = 0.7,
        version: int = 1,
        enabled: bool = True,
        config: dict[str, Any] | None = None,
        name: str = "ordered_sequence_correlation",
    ) -> None:
        """Initialize ordered sequence correlation detector.

        Args:
            steps: List of step conditions, each step is a dict of field->value filters.
            timespan: Maximum time window for sequence completion.
            group_by: Fields to group events by. Defaults to ["src_ip"].
            max_keys: Maximum number of group keys to track.
            max_sequences_per_key: Maximum in-progress sequences per group key.
            confidence: Confidence score for matched detections.
            version: Rule version.
            enabled: Whether detector is active.
            config: Optional configuration dictionary.
            name: Detector name/rule ID.
        """
        if len(steps) < 2:
            raise ValueError("OrderedSequenceDetector requires at least 2 steps")

        if timespan > OrderedSequenceDetector.MAX_ALLOWED_TIMESPAN:
            raise ValueError(
                f"Timespan exceeds maximum allowed duration of {OrderedSequenceDetector.MAX_ALLOWED_TIMESPAN}"
            )

        self._steps = steps
        self._timespan = timespan
        self._group_by = group_by or ["src_ip"]
        self._max_keys = max_keys
        self._max_sequences_per_key = max_sequences_per_key
        self._confidence = confidence
        self._version = version
        self._enabled = enabled
        self._config = config or {}
        self._name = name
        self._detections_count = 0

        # Bounded state storage: group_key -> OrderedSequenceState
        self._state: OrderedDict[tuple[str, ...], OrderedSequenceState] = OrderedDict()
        self._lock = Lock()

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "Detects ordered event sequences within sliding time windows"

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

    def _validate_step_condition(
        self, condition: dict[str, Any], rule_path: Path | None = None
    ) -> None:
        """Validate a step condition.

        Args:
            condition: The step condition to validate.
            rule_path: Optional path for error messages.

        Raises:
            DetectionError: If the condition is invalid.
        """
        if not isinstance(condition, dict):
            raise DetectionError(
                "Step condition must be a mapping.",
                details={"path": str(rule_path) if rule_path else None},
            )
        for field in condition:
            if field not in self.VALID_FILTER_FIELDS:
                raise DetectionError(
                    f"Invalid step field: {field}. Valid fields: {sorted(self.VALID_FILTER_FIELDS)}",
                    details={"path": str(rule_path) if rule_path else None},
                )

    def observe(self, event: NormalizedEvent) -> None:
        """Observe an event and update sequence state.

        Args:
            event: The normalized event to observe.
        """
        if not self._enabled:
            return

        group_key = self._build_group_key(event)

        with self._lock:
            state = self._state.get(group_key)
            if state is None:
                if len(self._state) >= self._max_keys:
                    self._state.popitem(last=False)
                state = OrderedSequenceState(
                    group_key=group_key,
                    window_duration=self._timespan,
                    max_steps=self._max_sequences_per_key,
                    total_steps=len(self._steps),
                )
                self._state[group_key] = state
            else:
                self._state.move_to_end(group_key)

        state.try_advance(event, self._steps)

    def detect(self, event: NormalizedEvent) -> DetectionResult:
        """Evaluate the event for sequence completion.

        Args:
            event: The normalized event to evaluate.

        Returns:
            DetectionResult indicating whether a sequence completed.
        """
        if not self._enabled:
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

        was_triggered, completed = state.check_and_clear_trigger(event)

        if not was_triggered:
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
                "field": "sequence_steps",
                "observed": len(self._steps),
                "condition": "completed",
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

        # Add step types to evidence (bounded)
        step_types = [s.get("event_type", "unknown") for s in self._steps[:5]]
        evidence.append(
            {
                "field": "step_types",
                "observed": step_types,
                "condition": "ordered",
            }
        )

        metadata = {
            "timespan_seconds": completed.get_sequence_timespan() if completed else 0.0,
            "step_count": len(self._steps),
            "group_by": self._group_by,
        }

        # Build step descriptions
        step_descriptions = []
        for i, step in enumerate(self._steps):
            desc = ", ".join(f"{k}={v}" for k, v in step.items())
            step_descriptions.append(f"Step {i + 1}: {desc}")

        description = (
            f"Ordered sequence completed: {len(self._steps)} steps "
            f"for group {' + '.join(str(v) for v in group_key)} "
            f"within {self._timespan.total_seconds():.0f}s"
        )

        explanation = (
            f"Detected a sequence of {len(self._steps)} ordered events matching "
            f"the correlation criteria. Steps: {' -> '.join(step_types)}."
        )

        contributing_ids = completed.get_contributing_event_ids(limit=50) if completed else ()

        return DetectionResult(
            rule_id=self._name,
            event_id=event.event_id,
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
