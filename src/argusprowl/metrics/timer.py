"""Timer context manager for metrics.

Provides a context manager for timing code execution and recording
metrics automatically.
"""

import time
from typing import Any

from argusprowl.metrics.metrics import Histogram


class Timer:
    """Context manager for timing execution.

    Automatically records execution time to a histogram metric.

    Attributes:
        histogram: Histogram metric to record times to.
        start_time: Start time of the timed section.
    """

    def __init__(self, histogram: Histogram) -> None:
        """Initialize timer.

        Args:
            histogram: Histogram metric to record execution times.
        """
        self._histogram = histogram
        self._start_time: float = 0.0

    def __enter__(self) -> "Timer":
        """Start timing.

        Returns:
            Self for context manager protocol.
        """
        self._start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Stop timing and record to histogram.

        Args:
            exc_type: Exception type if raised.
            exc_val: Exception value if raised.
            exc_tb: Exception traceback if raised.
        """
        end_time = time.perf_counter()
        elapsed = end_time - self._start_time
        self._histogram.observe(elapsed)

    @property
    def elapsed(self) -> float:
        """Get elapsed time since timer started.

        Returns:
            Elapsed time in seconds.
        """
        if self._start_time == 0.0:
            return 0.0
        return time.perf_counter() - self._start_time

    def __repr__(self) -> str:
        """String representation."""
        return f"Timer(histogram={self._histogram.name!r})"
