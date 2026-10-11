"""Periodicity calculation utilities.

Provides statistical measures for determining if network behavior
exhibits periodic patterns characteristic of beaconing.
"""

from __future__ import annotations

import math
from collections.abc import Sequence


def calculate_mean(values: Sequence[float]) -> float:
    """Calculate arithmetic mean.

    Args:
        values: Sequence of numeric values.

    Returns:
        Arithmetic mean, or 0.0 if empty.
    """
    if not values:
        return 0.0
    return sum(values) / len(values)


def calculate_std_dev(values: Sequence[float], mean: float | None = None) -> float:
    """Calculate population standard deviation.

    Args:
        values: Sequence of numeric values.
        mean: Pre-calculated mean (optional).

    Returns:
        Population standard deviation, or 0.0 if fewer than 2 values.
    """
    if len(values) < 2:
        return 0.0

    if mean is None:
        mean = calculate_mean(values)

    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def calculate_coefficient_of_variation(std_dev: float, mean: float) -> float:
    """Calculate coefficient of variation (CV).

    CV = std_dev / mean. Lower CV indicates more regular periodicity.

    Args:
        std_dev: Standard deviation.
        mean: Mean value.

    Returns:
        Coefficient of variation, or 0.0 if mean is zero.
    """
    if mean == 0:
        return 0.0
    return std_dev / abs(mean)


def calculate_periodicity_score(intervals: Sequence[float]) -> float:
    """Calculate periodicity score in [0.0, 1.0].

    A score of 1.0 indicates perfectly periodic behavior.
    A score of 0.0 indicates no periodicity.

    Uses coefficient of variation of intervals:
    - CV < 0.1: Very high periodicity (score ~0.9-1.0)
    - CV < 0.3: High periodicity (score ~0.7-0.9)
    - CV < 0.5: Moderate periodicity (score ~0.5-0.7)
    - CV >= 0.5: Low periodicity (score < 0.5)

    Args:
        intervals: Sequence of time intervals between observations.

    Returns:
        Periodicity score in [0.0, 1.0].
    """
    if len(intervals) < 2:
        return 0.0

    mean = calculate_mean(intervals)
    if mean == 0:
        return 0.0

    std_dev = calculate_std_dev(intervals, mean)
    cv = calculate_coefficient_of_variation(std_dev, mean)

    # Inverse relationship: lower CV = higher periodicity
    # Use exponential decay for smooth scoring
    score = math.exp(-3.0 * cv)
    return max(0.0, min(1.0, score))


def classify_periodicity(score: float) -> str:
    """Classify periodicity score into human-readable category.

    Args:
        score: Periodicity score in [0.0, 1.0].

    Returns:
        Classification string: 'none', 'low', 'moderate', 'high', 'very_high'.
    """
    if score < 0.3:
        return "none"
    elif score < 0.5:
        return "low"
    elif score < 0.7:
        return "moderate"
    elif score < 0.9:
        return "high"
    else:
        return "very_high"
