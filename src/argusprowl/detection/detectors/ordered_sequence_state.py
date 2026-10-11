"""Ordered sequence state tracking.

Provides bounded in-memory state for ordered event sequence detection,
grouped by configurable fields. Used by OrderedSequenceDetector.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import timedelta
from threading import Lock
from typing import Any

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
        self._lock = Lock()

    @property
    def group_key(self) -> tuple[str, ...]:
        """Return the grouping key."""
        return self._group_key

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
            self._expire_old_sequences(event.timestamp)

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
