"""Metrics collector implementation.

Provides centralized collection and reporting of application metrics.
"""

import threading
import time
from collections.abc import Callable
from typing import Any

from argusprowl.metrics.metrics import Counter, Gauge, Histogram, Metric
from argusprowl.models.metrics_snapshot import MetricsSnapshot


class MetricsCollector:
    """Centralized metrics collection and reporting.

    Manages registration, collection, and reporting of application metrics.

    Attributes:
        metrics: Dictionary of registered metrics.
    """

    def __init__(self) -> None:
        """Initialize metrics collector."""
        self._metrics: dict[str, Metric] = {}
        self._start_time = time.time()
        self._lock = threading.RLock()
        self._resource_hooks: dict[str, Callable[[], float]] = {}

    def register_resource_hook(self, name: str, sampler: Callable[[], float]) -> None:
        """Register a lightweight pull sampler (CPU, memory, queue depth, etc.).

        Platform-specific monitoring libraries remain outside the foundation;
        exporters can invoke these hooks at their own cadence.
        """
        with self._lock:
            if name in self._resource_hooks:
                raise ValueError(f"Resource hook '{name}' already registered.")
            self._resource_hooks[name] = sampler

    def collect_resource_metrics(self) -> dict[str, float]:
        """Execute registered resource samplers with per-hook fault isolation."""
        with self._lock:
            hooks = dict(self._resource_hooks)
        values: dict[str, float] = {}
        for name, sampler in hooks.items():
            try:
                values[name] = float(sampler())
            except Exception:
                # Monitoring must not impact the data path.
                continue
        return values

    def register_counter(self, name: str, description: str = "") -> Counter:
        """Register a counter metric.

        Args:
            name: Metric name.
            description: Metric description.

        Returns:
            Counter instance.
        """
        with self._lock:
            if name in self._metrics:
                raise ValueError(f"Metric '{name}' already registered.")
            counter = Counter(name, description)
            self._metrics[name] = counter
            return counter

    def register_gauge(self, name: str, description: str = "") -> Gauge:
        """Register a gauge metric.

        Args:
            name: Metric name.
            description: Metric description.

        Returns:
            Gauge instance.
        """
        with self._lock:
            if name in self._metrics:
                raise ValueError(f"Metric '{name}' already registered.")
            gauge = Gauge(name, description)
            self._metrics[name] = gauge
            return gauge

    def register_histogram(
        self, name: str, description: str = "", buckets: list[float] | None = None
    ) -> Histogram:
        """Register a histogram metric.

        Args:
            name: Metric name.
            description: Metric description.
            buckets: List of bucket boundaries.

        Returns:
            Histogram instance.
        """
        with self._lock:
            if name in self._metrics:
                raise ValueError(f"Metric '{name}' already registered.")
            histogram = Histogram(name, description, buckets)
            self._metrics[name] = histogram
            return histogram

    def get_counter(self, name: str) -> Counter:
        """Get a counter metric by name.

        Args:
            name: Metric name.

        Returns:
            Counter instance.

        Raises:
            KeyError: If metric not found.
        """
        metric = self._metrics.get(name)
        if not isinstance(metric, Counter):
            raise KeyError(f"Counter metric '{name}' not found.")
        return metric

    def get_gauge(self, name: str) -> Gauge:
        """Get a gauge metric by name.

        Args:
            name: Metric name.

        Returns:
            Gauge instance.

        Raises:
            KeyError: If metric not found.
        """
        metric = self._metrics.get(name)
        if not isinstance(metric, Gauge):
            raise KeyError(f"Gauge metric '{name}' not found.")
        return metric

    def get_histogram(self, name: str) -> Histogram:
        """Get a histogram metric by name.

        Args:
            name: Metric name.

        Returns:
            Histogram instance.

        Raises:
            KeyError: If metric not found.
        """
        metric = self._metrics.get(name)
        if not isinstance(metric, Histogram):
            raise KeyError(f"Histogram metric '{name}' not found.")
        return metric

    def get_metric(self, name: str) -> Metric:
        """Get any metric by name.

        Args:
            name: Metric name.

        Returns:
            Metric instance.

        Raises:
            KeyError: If metric not found.
        """
        if name not in self._metrics:
            raise KeyError(f"Metric '{name}' not found.")
        return self._metrics[name]

    def increment_counter(self, name: str, amount: int = 1) -> None:
        """Increment a counter metric.

        Args:
            name: Metric name.
            amount: Amount to increment by.
        """
        counter = self.get_counter(name)
        counter.increment(amount)

    def set_gauge(self, name: str, value: float) -> None:
        """Set a gauge metric value.

        Args:
            name: Metric name.
            value: Value to set.
        """
        gauge = self.get_gauge(name)
        gauge.set(value)

    def observe_histogram(self, name: str, value: float) -> None:
        """Observe a value in a histogram metric.

        Args:
            name: Metric name.
            value: Value to observe.
        """
        histogram = self.get_histogram(name)
        histogram.observe(value)

    def get_all_metrics(self) -> dict[str, dict[str, Any]]:
        """Get all metrics with their current values.

        Returns:
            Dictionary mapping metric names to their values.
        """
        result = {}
        for name, metric in self._metrics.items():
            result[name] = {
                "type": type(metric).__name__,
                "value": metric.get_value(),
            }
        return result

    def get_snapshot(self) -> dict[str, Any]:
        """Get a snapshot of all metrics.

        Returns:
            Dictionary containing all metrics and uptime.
        """
        return {
            "uptime_seconds": time.time() - self._start_time,
            "metrics": self.get_all_metrics(),
        }

    def snapshot(self) -> MetricsSnapshot:
        """Return a typed snapshot suitable for API/export adapters."""
        return MetricsSnapshot(
            uptime_seconds=time.time() - self._start_time, metrics=self.get_all_metrics()
        )

    def reset_all(self) -> None:
        """Reset all metrics to initial state."""
        for metric in self._metrics.values():
            metric.reset()

    def clear(self) -> None:
        """Remove all registered metrics."""
        with self._lock:
            self._metrics.clear()
            self._resource_hooks.clear()

    @property
    def metric_count(self) -> int:
        """Number of registered metrics."""
        return len(self._metrics)

    def __repr__(self) -> str:
        """String representation."""
        return f"MetricsCollector(metrics={self.metric_count})"
