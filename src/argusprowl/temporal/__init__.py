"""Temporal detection package.

Provides bounded in-memory state tracking and periodicity analysis
for detecting suspicious beaconing behavior.
"""

from argusprowl.temporal.engine import TemporalEngine
from argusprowl.temporal.periodicity import (
    calculate_coefficient_of_variation,
    calculate_periodicity_score,
    classify_periodicity,
)
from argusprowl.temporal.temporal_state import TemporalBucket, TemporalObservation

__all__ = [
    "TemporalBucket",
    "TemporalEngine",
    "TemporalObservation",
    "calculate_coefficient_of_variation",
    "calculate_periodicity_score",
    "classify_periodicity",
]
