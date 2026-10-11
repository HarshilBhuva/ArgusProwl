"""Cross-detector correlation correlator.

Provides bounded in-memory correlation between DetectionResults from
different detectors. Tracks recent detections grouped by configurable
fields and produces new DetectionResults when configured sequences
complete.

This is a minimal primitive that correlates detections across detectors
without modifying existing DetectionResult schema or detector semantics.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import timedelta
from pathlib import Path
from threading import Lock
from typing import Any, ClassVar
from uuid import UUID

from argusprowl.constants.severity import Severity
from argusprowl.exceptions.exceptions import DetectionError
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


class CrossDetectorCorrelator:
    """Correlates DetectionResults from different detectors.

    Maintains bounded in-memory state of recent DetectionResults grouped
    by configurable fields. When a configured sequence of rule_ids
    completes within the timespan, produces a new DetectionResult.

    Thread-safe for concurrent access.
    """

    # Valid grouping fields that can be extracted from NormalizedEvent
    VALID_GROUP_BY_FIELDS: ClassVar[set[str]] = {
        "src_ip",
        "dst_ip",
        "hostname",
        "username",
    }

    # Maximum allowed correlation timespan (e.g., 30 days)
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
        match = CrossDetectorCorrelator._TIMESPAN_PATTERN.match(str(timespan_str))
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
        sequence: list[str],
        timespan: timedelta = timedelta(minutes=5),
        group_by: list[str] | None = None,
        max_entries: int = 10000,
        confidence: float = 0.8,
        version: int = 1,
        enabled: bool = True,
        config: dict[str, Any] | None = None,
        name: str = "cross_detector_correlation",
    ) -> None:
        """Initialize cross-detector correlator.

        Args:
            sequence: List of rule_ids that form the correlation sequence.
            timespan: Maximum time window for sequence completion.
            group_by: Fields to group events by. Defaults to ["src_ip"].
            max_entries: Maximum entries to track per group.
            confidence: Confidence score for matched correlations.
            version: Rule version.
            enabled: Whether correlator is active.
            config: Optional configuration dictionary.
            name: Correlator name/rule ID.
        """
        if len(sequence) < 2:
            raise ValueError("CrossDetectorCorrelator requires at least 2 rule_ids in sequence")

        if timespan > CrossDetectorCorrelator.MAX_ALLOWED_TIMESPAN:
            raise ValueError(
                f"Timespan exceeds maximum allowed duration of {CrossDetectorCorrelator.MAX_ALLOWED_TIMESPAN}"
            )

        self._sequence = sequence
        self._timespan = timespan
        self._group_by = group_by or ["src_ip"]
        self._max_entries = max_entries
        self._confidence = confidence
        self._version = version
        self._enabled = enabled
        self._config = config or {}
        self._name = name
        self._detections_count = 0

        # Bounded state storage: group_key -> list of (timestamp, rule_id, result_id)
        self._state: OrderedDict[tuple[str, ...], list[tuple[Any, str, UUID]]] = OrderedDict()
        self._lock = Lock()

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return "Correlates DetectionResults from different detectors"

    @property
    def version(self) -> int:
        return self._version

    def is_enabled(self) -> bool:
        return self._enabled

    def enable(self) -> None:
        """Enable this correlator."""
        self._enabled = True

    def disable(self) -> None:
        """Disable this correlator."""
        self._enabled = False

    def configure(self, config: dict[str, Any]) -> None:
        """Update correlator configuration."""
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

    def process(
        self,
        event: NormalizedEvent,
        detection_results: list[DetectionResult],
    ) -> list[DetectionResult]:
        """Process DetectionResults and check for correlations.

        Records matched DetectionResults and checks if any configured
        sequence has completed. Returns new DetectionResults for
        completed correlations.

        Args:
            event: The current normalized event.
            detection_results: DetectionResults from other detectors.

        Returns:
            List of new DetectionResults from completed correlations.
        """
        if not self._enabled:
            return []

        new_results: list[DetectionResult] = []

        with self._lock:
            # Record matched DetectionResults
            for result in detection_results:
                if result.matched:
                    self._record(result, event)

            # Check for completed correlations
            correlation_result = self._check(event, detection_results)
            if correlation_result is not None:
                new_results.append(correlation_result)
                self._detections_count += 1

        return new_results

    def _record(self, result: DetectionResult, event: NormalizedEvent) -> None:
        """Record a DetectionResult in the sliding window.

        Args:
            result: The DetectionResult to record.
            event: The associated normalized event.
        """
        group_key = self._build_group_key(event)

        # Evict expired entries
        self._expire_old_entries(group_key, event.timestamp)

        # Add new entry
        if group_key not in self._state:
            if len(self._state) >= self._max_entries:
                self._state.popitem(last=False)
            self._state[group_key] = []

        self._state[group_key].append(
            (
                event.timestamp,
                result.rule_id,
                result.result_id,
            )
        )
        self._state.move_to_end(group_key)

    def _expire_old_entries(self, group_key: tuple[str, ...], reference_time: Any) -> None:
        """Remove entries that have expired from the window.

        Args:
            group_key: The group key to expire entries for.
            reference_time: The reference timestamp for expiration.
        """
        if group_key not in self._state:
            return

        cutoff = reference_time - self._timespan
        entries = self._state[group_key]

        # Remove expired entries from the front
        while entries and entries[0][0] < cutoff:
            entries.pop(0)

        # Remove empty groups
        if not entries:
            del self._state[group_key]

    def _remove_sequence_entries(
        self,
        group_key: tuple[str, ...],
        sequence_entries: list[tuple[Any, str, UUID]],
    ) -> None:
        """Remove completed sequence entries from state after emitting correlation.

        This enables re-arm: new correlations can form using the remaining entries
        or new arrivals. Only removes entries that were part of the completed sequence.

        Args:
            group_key: The group key to remove entries from.
            sequence_entries: The entries that formed the completed sequence.
        """
        if group_key not in self._state:
            return

        # Convert sequence_entries to set of result_ids for efficient lookup
        completed_ids = {entry[2] for entry in sequence_entries}

        # Remove matching entries from the state's entry list
        entries = self._state[group_key]
        len(entries)
        remaining = [e for e in entries if e[2] not in completed_ids]

        if remaining:
            self._state[group_key] = remaining
        else:
            del self._state[group_key]

    def _check(
        self,
        event: NormalizedEvent,
        detection_results: list[DetectionResult],
    ) -> DetectionResult | None:
        """Check if any correlation sequence is complete.

        Args:
            event: The current normalized event.
            detection_results: DetectionResults from other detectors.

        Returns:
            DetectionResult if a correlation completed, None otherwise.
        """
        group_key = self._build_group_key(event)
        self._state.get(group_key, [])

        # Find the most recent DetectionResult that matches the last step
        last_rule_id = self._sequence[-1]
        matching_result = None
        for result in reversed(detection_results):
            if result.rule_id == last_rule_id and result.matched:
                matching_result = result
                break

        if matching_result is None:
            return None

        # Get the current state which includes the newly recorded entry
        current_entries = self._state.get(group_key, [])

        # Check if the window contains a complete sequence
        sequence_entries = self._is_sequence_complete(current_entries, matching_result.result_id)
        if sequence_entries is not None:
            result = self._create_detection_result(sequence_entries, matching_result, event)
            # Re-arm: remove the completed sequence entries so new correlations can form
            self._remove_sequence_entries(group_key, sequence_entries)
            return result

        return None

    def _is_sequence_complete(
        self,
        entries: list[tuple[Any, str, UUID]],
        last_result_id: UUID,
    ) -> list[tuple[Any, str, UUID]] | None:
        """Check if the entries contain a complete sequence.

        Searches backwards from last_result_id to find the FIRST valid sequence.
        This implements "first valid sequence" semantics: when a completion step
        arrives, it completes the earliest sequence that can form with it, then
        re-arms to allow subsequent sequences.

        Args:
            entries: List of (timestamp, rule_id, result_id) tuples.
            last_result_id: The result_id of the matching DetectionResult.

        Returns:
            The sequence_entries tuple if a complete sequence is found, None otherwise.
        """
        if len(entries) < len(self._sequence):
            return None

        # Find the index of last_result_id in entries
        last_index = None
        for i, (_, _, result_id) in enumerate(entries):
            if result_id == last_result_id:
                last_index = i
                break

        if last_index is None or last_index < len(self._sequence) - 1:
            return None

        # Find the FIRST valid sequence using non-contiguous matching.
        # For overlapping sequences: B1 completes with earliest A, B2 with next A.
        #
        # Algorithm: For a sequence [S1, S2, ..., Sn], find the earliest
        # occurrence of each step such that:
        # 1. Each step occurs after the previous step
        # 2. The timespan between consecutive steps is within bounds
        #
        # For sequence [A, B] and entries [A1, A2, B1]:
        # - B1 is at index 2 (confirmed as last step via last_result_id)
        # - For A: find the earliest occurrence before index 2 that's valid with B1
        # - If A1@0 is within timespan of B1@2, use A1
        # - Result: [A1, B1]

        seq_len = len(self._sequence)

        # Find indices of all occurrences of each step
        step_indices: dict[int, list[int]] = {i: [] for i in range(seq_len)}
        for i, (_, rule_id, _result_id) in enumerate(entries):
            for step_idx, expected_rule_id in enumerate(self._sequence):
                if rule_id == expected_rule_id:
                    step_indices[step_idx].append(i)

        # The last step must include last_result_id
        last_result_indices = [
            i for i in step_indices[seq_len - 1] if entries[i][2] == last_result_id
        ]
        if not last_result_indices:
            return None

        # For each possible last step index, try to form a valid sequence
        # using the earliest occurrences of preceding steps
        for last_idx in last_result_indices:
            candidate_indices = [last_idx]
            valid = True

            # Work backwards: for each preceding step, find the earliest valid occurrence
            for step_idx in range(seq_len - 2, -1, -1):
                expected_rule = self._sequence[step_idx]
                prev_idx = candidate_indices[-1]  # Index of the next step in sequence

                # Find the EARLIEST occurrence of this step that's valid
                # Collect all valid candidates, then pick the smallest index
                curr_ts = entries[prev_idx][0]
                valid_candidates = []
                for i in range(prev_idx - 1, -1, -1):
                    if entries[i][1] == expected_rule:
                        prev_ts = entries[i][0]
                        if curr_ts - prev_ts <= self._timespan:
                            valid_candidates.append(i)

                if valid_candidates:
                    # Pick the EARLIEST (smallest index)
                    candidate_indices.append(min(valid_candidates))
                else:
                    valid = False
                    break

            if valid:
                # Reverse to get chronological order
                candidate_indices.reverse()
                return [entries[i] for i in candidate_indices]

        return None

    def _create_detection_result(
        self,
        entries: list[tuple[Any, str, UUID]],
        last_result: DetectionResult,
        event: NormalizedEvent,
    ) -> DetectionResult:
        """Create a DetectionResult for a completed correlation.

        Args:
            entries: The entries that form the correlation.
            last_result: The DetectionResult that completed the sequence.
            event: The current normalized event.

        Returns:
            New DetectionResult for the correlation.
        """
        # Extract contributing event IDs from entries
        contributing_ids = tuple(result_id for _, _, result_id in entries)

        # Build evidence
        evidence = [
            {
                "field": "correlation_sequence",
                "observed": self._sequence,
                "condition": "completed",
            }
        ]

        # Add group fields to evidence
        group_key = self._build_group_key(event)
        for field_name, field_value in zip(self._group_by, group_key, strict=False):
            evidence.append(
                {
                    "field": field_name,
                    "observed": field_value,
                    "condition": "==",
                }
            )

        # Add timespan to evidence
        if len(entries) >= 2:
            timespan_seconds = (entries[-1][0] - entries[0][0]).total_seconds()
            evidence.append(
                {
                    "field": "timespan_seconds",
                    "observed": timespan_seconds,
                    "condition": "<=",
                }
            )

        metadata = {
            "timespan_seconds": (entries[-1][0] - entries[0][0]).total_seconds()
            if len(entries) >= 2
            else 0.0,
            "step_count": len(self._sequence),
            "group_by": self._group_by,
            "sequence": self._sequence,
        }

        description = (
            f"Cross-detector correlation completed: {' -> '.join(self._sequence)} "
            f"for group {' + '.join(str(v) for v in group_key)} "
            f"within {self._timespan.total_seconds():.0f}s"
        )

        explanation = (
            f"Detected a correlation between {len(self._sequence)} detectors: "
            f"{' -> '.join(self._sequence)}. "
            f"Group: {' + '.join(str(v) for v in group_key)}."
        )

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

    def get_state_entries(self) -> int:
        """Return the total number of state entries across all groups."""
        with self._lock:
            return sum(len(entries) for entries in self._state.values())

    def get_state_keys(self) -> int:
        """Return the number of active group keys."""
        with self._lock:
            return len(self._state)
