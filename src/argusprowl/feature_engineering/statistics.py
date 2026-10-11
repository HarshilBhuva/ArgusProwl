"""Statistical calculation utilities.

Provides common statistical functions for feature engineering.
"""

import math
from collections.abc import Sequence


def calculate_mean(values: Sequence[float]) -> float:
    """Calculate arithmetic mean of a sequence of values.

    Args:
        values: Sequence of numeric values.

    Returns:
        Arithmetic mean, or 0.0 if sequence is empty.
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


def calculate_min_max(values: Sequence[float]) -> tuple[float, float]:
    """Calculate minimum and maximum values.

    Args:
        values: Sequence of numeric values.

    Returns:
        Tuple of (min, max). Returns (0.0, 0.0) if sequence is empty.
    """
    if not values:
        return 0.0, 0.0
    return min(values), max(values)


def calculate_percentile(values: Sequence[float], percentile: float) -> float:
    """Calculate the given percentile of a sequence of values.

    Args:
        values: Sequence of numeric values (will be sorted).
        percentile: Percentile to calculate (0-100).

    Returns:
        Percentile value, or 0.0 if sequence is empty.
    """
    if not values:
        return 0.0

    sorted_values = sorted(values)
    index = (percentile / 100.0) * (len(sorted_values) - 1)
    lower_index = math.floor(index)
    upper_index = math.ceil(index)

    if lower_index == upper_index:
        return sorted_values[lower_index]

    # Linear interpolation
    lower_value = sorted_values[lower_index]
    upper_value = sorted_values[upper_index]
    fraction = index - lower_index
    return lower_value + fraction * (upper_value - lower_value)


def calculate_entropy(values: Sequence[int]) -> float:
    """Calculate Shannon entropy of a distribution.

    Args:
        values: Sequence of integer counts.

    Returns:
        Entropy in bits, or 0.0 if sequence is empty or sum is 0.
    """
    total = sum(values)
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in values:
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)

    return entropy


def calculate_concentration(counts: dict[str, int]) -> float:
    """Calculate concentration ratio (top item / total).

    Args:
        counts: Dictionary mapping items to their counts.

    Returns:
        Concentration ratio in [0.0, 1.0], or 0.0 if empty.
    """
    if not counts:
        return 0.0

    total = sum(counts.values())
    if total == 0:
        return 0.0

    max_count = max(counts.values())
    return max_count / total


def calculate_rate(count: int, time_window_seconds: float) -> float:
    """Calculate rate (events per second).

    Args:
        count: Number of events.
        time_window_seconds: Duration of time window in seconds.

    Returns:
        Events per second, or 0.0 if window is 0 or negative.
    """
    if time_window_seconds <= 0:
        return 0.0
    return count / time_window_seconds
