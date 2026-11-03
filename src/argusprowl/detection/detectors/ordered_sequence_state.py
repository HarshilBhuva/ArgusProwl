"""Ordered sequence state tracking.

Provides bounded in-memory state for ordered event sequence detection,
grouped by configurable fields. Used by OrderedSequenceDetector.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Any
from uuid import UUID

from argusprowl.models.normalized_event import NormalizedEvent


@dataclass
class SequenceStep:
    """A single step in an ordered sequence."""

    step_index: int  # 0-based index in the sequence
    event: NormalizedEvent
    timestamp: Any


@dataclass
class SequenceProgress:
    """Tracks progress of an in-progress sequence."""

    steps: list[SequenceStep] = field(default_factory=list)
    started_at: Any = None
    last_event_time: Any = None

    def to_dict(self) -> dict[str, object]:
        """Serialize sequence progress and its event evidence."""
        return {
            "started_at": self.started_at.isoformat() if self.started_at is not None else None,
            "last_event_time": (
                self.last_event_time.isoformat()
                if self.last_event_time is not None
                else None
            ),
            "steps": [
                {
                    "step_index": step.step_index,
                    "event": step.event.to_dict(),
                    "timestamp": step.timestamp.isoformat(),
                }
                for step in self.steps
            ],
        }

    @classmethod
    def from_dict(cls, snapshot: dict[str, object]) -> SequenceProgress:
        """Restore validated progress while preserving event-time ordering."""
        if not isinstance(snapshot, dict):
            raise ValueError("Sequence progress snapshot must be a mapping.")
        raw_steps = snapshot.get("steps")
        if not isinstance(raw_steps, list) or not raw_steps:
            raise ValueError("Sequence progress snapshot steps are invalid.")

        steps: list[SequenceStep] = []
        for expected_index, raw_step in enumerate(raw_steps):
            if not isinstance(raw_step, dict):
                raise ValueError("Sequence progress snapshot contains an invalid step.")
            if raw_step.get("step_index") != expected_index:
                raise ValueError("Sequence progress snapshot step indexes are invalid.")
            raw_event = raw_step.get("event")
            raw_timestamp = raw_step.get("timestamp")
            if not isinstance(raw_event, dict) or not isinstance(raw_timestamp, str):
                raise ValueError("Sequence progress snapshot step data is invalid.")
            event = NormalizedEvent.from_dict(raw_event)
            timestamp = datetime.fromisoformat(raw_timestamp)
            if timestamp.tzinfo is None or timestamp != event.timestamp:
                raise ValueError("Sequence progress snapshot timestamp is inconsistent.")
            if steps and timestamp < steps[-1].timestamp:
                raise ValueError("Sequence progress snapshot is not time ordered.")
            steps.append(
                SequenceStep(
                    step_index=expected_index,
                    event=event,
                    timestamp=timestamp,
                )
            )

        raw_started_at = snapshot.get("started_at")
        raw_last_event_time = snapshot.get("last_event_time")
        if not isinstance(raw_started_at, str) or not isinstance(raw_last_event_time, str):
            raise ValueError("Sequence progress snapshot time bounds are invalid.")
        started_at = datetime.fromisoformat(raw_started_at)
        last_event_time = datetime.fromisoformat(raw_last_event_time)
        if (
            started_at.tzinfo is None
            or last_event_time.tzinfo is None
            or started_at != steps[0].timestamp
            or last_event_time != steps[-1].timestamp
        ):
            raise ValueError("Sequence progress snapshot time bounds are inconsistent.")

        return cls(
            steps=steps,
            started_at=started_at,
            last_event_time=last_event_time,
        )

    def current_step_index(self) -> int:
        """Return the next expected step index."""
        return len(self.steps)

    def add_step(self, event: NormalizedEvent, timestamp: Any) -> None:
        """Add a completed step to the sequence."""
        self.steps.append(
            SequenceStep(
                step_index=len(self.steps),
                event=event,
                timestamp=timestamp,
            )
        )
        self.last_event_time = timestamp

    def get_contributing_event_ids(self, limit: int = 50) -> tuple[Any, ...]:
        """Return event IDs from the sequence.

        Args:
            limit: Maximum number of event IDs to return.

        Returns:
            Tuple of event IDs in order.
        """
        return tuple(step.event.event_id for step in self.steps[:limit])

    def get_sequence_timespan(self) -> float:
        """Return the timespan of the sequence in seconds."""
        if len(self.steps) < 2:
            return 0.0
        first = self.steps[0].timestamp
        last = self.steps[-1].timestamp
        return (last - first).total_seconds()


class OrderedSequenceState:
    """Bounded state for ordered sequence correlation.

    Tracks events grouped by a key tuple, maintaining progress toward
    a configured sequence. Enforces capacity limits via FIFO eviction.

    Attributes:
        group_key: The grouping key tuple (e.g., src_ip).
        window_duration: Maximum age before the sequence expires.
        max_steps: Maximum number of steps to retain per sequence.
        total_steps: Total steps required to complete the sequence.
    """

    def __init__(
        self,
        group_key: tuple[str, ...],
        window_duration: timedelta,
        max_steps: int = 100,
        total_steps: int = 2,
    ) -> None:
        """Initialize ordered sequence state.

        Args:
            group_key: Tuple of field values identifying this group.
            window_duration: Maximum time from sequence start to completion.
            max_steps: Maximum steps to retain (bounded per sequence).
            total_steps: Number of steps required to complete sequence.
        """
        if total_steps < 2:
            raise ValueError("OrderedSequenceState requires at least 2 steps")

        self._group_key = group_key
        self._window_duration = window_duration
        self._max_steps = max_steps
        self._total_steps = total_steps

        # List of SequenceProgress objects (partial or complete sequences)
        # Bounded via max_sequences per group
        self._sequences: deque[SequenceProgress] = deque(maxlen=max_steps)

        self._triggered = False
        self._trigger_event_id: Any = None
        self._completed_sequence: SequenceProgress | None = None
        self._max_event_time: Any = None
        self._late_event_count = 0
        self._lock = Lock()

    def to_dict(self) -> dict[str, object]:
        """Return a versioned snapshot suitable for durable correlation storage."""
        with self._lock:
            return {
                "schema_version": 1,
                "group_key": list(self._group_key),
                "window_duration_seconds": self._window_duration.total_seconds(),
                "max_sequences": self._max_steps,
                "total_steps": self._total_steps,
                "max_event_time": (
                    self._max_event_time.isoformat()
                    if self._max_event_time is not None
                    else None
                ),
                "late_event_count": self._late_event_count,
                "sequences": [sequence.to_dict() for sequence in self._sequences],
                "triggered": self._triggered,
                "trigger_event_id": (
                    str(self._trigger_event_id)
                    if self._trigger_event_id is not None
                    else None
                ),
                "completed_sequence": (
                    self._completed_sequence.to_dict()
                    if self._completed_sequence is not None
                    else None
                ),
            }

    @classmethod
    def from_dict(cls, snapshot: dict[str, object]) -> OrderedSequenceState:
        """Restore a validated ordered-sequence snapshot."""
        if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1:
            raise ValueError("Unsupported ordered-sequence state snapshot schema.")

        group_key = snapshot.get("group_key")
        duration = snapshot.get("window_duration_seconds")
        max_sequences = snapshot.get("max_sequences")
        total_steps = snapshot.get("total_steps")
        raw_sequences = snapshot.get("sequences")
        if (
            not isinstance(group_key, list)
            or not group_key
            or any(not isinstance(part, str) for part in group_key)
        ):
            raise ValueError("Ordered-sequence snapshot group_key is invalid.")
        if (
            not isinstance(duration, (int, float))
            or isinstance(duration, bool)
            or duration <= 0
            or duration > 31_536_000
            or not math.isfinite(float(duration))
        ):
            raise ValueError("Ordered-sequence snapshot window duration is invalid.")
        if (
            not isinstance(max_sequences, int)
            or isinstance(max_sequences, bool)
            or not 1 <= max_sequences <= 100_000
        ):
            raise ValueError("Ordered-sequence snapshot capacity is invalid.")
        if (
            not isinstance(total_steps, int)
            or isinstance(total_steps, bool)
            or not 2 <= total_steps <= 100
        ):
            raise ValueError("Ordered-sequence snapshot step count is invalid.")
        if not isinstance(raw_sequences, list) or len(raw_sequences) > max_sequences:
            raise ValueError("Ordered-sequence snapshot sequences are invalid.")

        sequences = [
            SequenceProgress.from_dict(item)
            for item in raw_sequences
            if isinstance(item, dict)
        ]
        if len(sequences) != len(raw_sequences) or any(
            len(sequence.steps) > total_steps for sequence in sequences
        ):
            raise ValueError("Ordered-sequence snapshot contains invalid progress.")

        raw_watermark = snapshot.get("max_event_time")
        if raw_watermark is not None and not isinstance(raw_watermark, str):
            raise ValueError("Ordered-sequence snapshot watermark is invalid.")
        watermark = datetime.fromisoformat(raw_watermark) if raw_watermark is not None else None
        if watermark is not None and watermark.tzinfo is None:
            raise ValueError("Ordered-sequence snapshot watermark must be timezone-aware.")
        if watermark is not None and any(
            sequence.last_event_time > watermark for sequence in sequences
        ):
            raise ValueError("Ordered-sequence snapshot progress exceeds its watermark.")

        late_count = snapshot.get("late_event_count")
        triggered = snapshot.get("triggered")
        raw_trigger_id = snapshot.get("trigger_event_id")
        raw_completed = snapshot.get("completed_sequence")
        if (
            not isinstance(late_count, int)
            or isinstance(late_count, bool)
            or late_count < 0
        ):
            raise ValueError("Ordered-sequence snapshot late-event count is invalid.")
        if not isinstance(triggered, bool):
            raise ValueError("Ordered-sequence snapshot trigger flag is invalid.")
        if raw_trigger_id is not None and not isinstance(raw_trigger_id, str):
            raise ValueError("Ordered-sequence snapshot trigger identity is invalid.")
        if raw_completed is not None and not isinstance(raw_completed, dict):
            raise ValueError("Ordered-sequence snapshot completion is invalid.")
        completed = (
            SequenceProgress.from_dict(raw_completed)
            if raw_completed is not None
            else None
        )
        if completed is not None and len(completed.steps) != total_steps:
            raise ValueError("Ordered-sequence snapshot completion is incomplete.")
        if triggered and (raw_trigger_id is None or completed is None):
            raise ValueError("Triggered ordered-sequence state requires completion evidence.")
        if not triggered and (raw_trigger_id is not None or completed is not None):
            raise ValueError("Untriggered ordered-sequence state cannot retain trigger evidence.")
        trigger_id = UUID(raw_trigger_id) if raw_trigger_id is not None else None
        if completed is not None:
            if trigger_id != completed.steps[-1].event.event_id:
                raise ValueError("Ordered-sequence trigger identity does not match completion.")
            if watermark is None or completed.last_event_time > watermark:
                raise ValueError("Ordered-sequence completion exceeds its watermark.")
            if not any(
                [step.event.event_id for step in sequence.steps]
                == [step.event.event_id for step in completed.steps]
                for sequence in sequences
            ):
                raise ValueError("Ordered-sequence completion is absent from retained state.")

        state = cls(
            group_key=tuple(group_key),
            window_duration=timedelta(seconds=float(duration)),
            max_steps=max_sequences,
            total_steps=total_steps,
        )
        state._sequences = deque(sequences, maxlen=max_sequences)
        state._max_event_time = watermark
        state._late_event_count = late_count
        state._triggered = triggered
        state._trigger_event_id = trigger_id
        state._completed_sequence = completed
        return state

    @property
    def group_key(self) -> tuple[str, ...]:
        """Return the grouping key."""
        return self._group_key

    @property
    def late_event_count(self) -> int:
        """Return the number of out-of-order events rejected by this state."""
        with self._lock:
            return self._late_event_count

    @property
    def triggered(self) -> bool:
        """Return whether sequence has completed."""
        with self._lock:
            return self._triggered

    @property
    def trigger_event_id(self) -> Any:
        """Return the triggering event ID."""
        with self._lock:
            return self._trigger_event_id

    @property
    def completed_sequence(self) -> SequenceProgress | None:
        """Return the completed sequence if triggered."""
        with self._lock:
            return self._completed_sequence

    def _expire_old_sequences(self, reference_time: Any) -> None:
        """Remove sequences that have expired from the window.

        A sequence expires if:
        1. Its start time is older than the window duration from reference_time
        2. It has been completed and the completion event has expired

        Must be called with lock held.
        """
        if reference_time is None:
            return

        cutoff = reference_time - self._window_duration

        # Expire sequences whose start time is before the cutoff
        while self._sequences and self._sequences[0].started_at is not None:
            seq = self._sequences[0]
            if seq.started_at < cutoff:
                self._sequences.popleft()
            else:
                break

    def try_advance(
        self, event: NormalizedEvent, step_conditions: list[dict[str, Any]]
    ) -> tuple[bool, SequenceProgress | None]:
        """Try to advance this group's sequence with a new event.

        Args:
            event: The event to add.
            step_conditions: List of filter conditions, one per step.

        Returns:
            Tuple of (advanced, completed_sequence_or_none).
            advanced=True means the event was consumed (matched or completed).
            If completed_sequence is not None, the sequence just completed.
        """
        with self._lock:
            # Sequence progress is evaluated in event-time order. Without a
            # reorder buffer, accepting an event behind the watermark could
            # create an impossible sequence or make replay delivery-order
            # dependent. Reject it explicitly and keep expiration monotonic.
            if self._max_event_time is not None and event.timestamp < self._max_event_time:
                self._late_event_count += 1
                return False, None

            if self._max_event_time is None or event.timestamp > self._max_event_time:
                self._max_event_time = event.timestamp
            self._expire_old_sequences(self._max_event_time)

            advanced_any = False
            completed_seq = None

            # Advance all incomplete sequences that can accept this event
            for seq in self._sequences:
                if len(seq.steps) >= self._total_steps:
                    continue  # Already complete

                expected_step = len(seq.steps)
                if expected_step >= len(step_conditions):
                    continue  # No more steps defined

                condition = step_conditions[expected_step]
                if self._matches_condition(event, condition):
                    # This event advances this sequence
                    seq.add_step(event, event.timestamp)
                    advanced_any = True

                    if len(seq.steps) >= self._total_steps:
                        # Sequence completed!
                        if completed_seq is None:
                            completed_seq = seq
                            self._completed_sequence = seq

                        self._triggered = True
                        self._trigger_event_id = event.event_id

            # Always check if we should start a new sequence
            started_new = False
            if len(step_conditions) > 0:
                condition = step_conditions[0]
                if self._matches_condition(event, condition):
                    new_seq = SequenceProgress(
                        started_at=event.timestamp,
                        last_event_time=event.timestamp,
                    )
                    new_seq.add_step(event, event.timestamp)

                    self._sequences.append(new_seq)
                    started_new = True

            return advanced_any or started_new, completed_seq

    def _matches_condition(self, event: NormalizedEvent, condition: dict[str, Any]) -> bool:
        """Check if an event matches a step condition.

        Args:
            event: The event to check.
            condition: Dictionary of field -> expected value.

        Returns:
            True if event matches all conditions.
        """
        if not condition:
            return True

        for field_name, expected_value in condition.items():
            actual_value = getattr(event, field_name, None)
            if actual_value != expected_value:
                return False

        return True

    def check_and_clear_trigger(
        self, event: NormalizedEvent
    ) -> tuple[bool, SequenceProgress | None]:
        """Check if this event completed a sequence and clear the triggered state.

        Args:
            event: The event being evaluated.

        Returns:
            Tuple of (was_triggered, completed_sequence).
        """
        with self._lock:
            if self._triggered and self._trigger_event_id == event.event_id:
                triggered = True
                completed = self._completed_sequence
                # Clear triggered state for re-arm
                self._triggered = False
                self._trigger_event_id = None
                self._completed_sequence = None
                return triggered, completed
            return False, None

    def get_contributing_event_ids(self, limit: int = 50) -> tuple[Any, ...]:
        """Return event IDs from the completed sequence.

        Args:
            limit: Maximum number of event IDs to return.

        Returns:
            Tuple of event IDs in order.
        """
        with self._lock:
            if self._completed_sequence is None:
                return ()
            return tuple(step.event.event_id for step in self._completed_sequence.steps[:limit])

    def get_sequence_timespan(self) -> float:
        """Return the timespan of the completed sequence in seconds."""
        with self._lock:
            if self._completed_sequence is None or len(self._completed_sequence.steps) < 2:
                return 0.0
            first = self._completed_sequence.steps[0].timestamp
            last = self._completed_sequence.steps[-1].timestamp
            return (last - first).total_seconds()
