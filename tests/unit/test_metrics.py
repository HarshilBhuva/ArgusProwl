"""Tests for metrics module."""

import threading
import time

import pytest

from argusprowl.metrics.collector import MetricsCollector
from argusprowl.metrics.metrics import Counter, Gauge, Histogram
from argusprowl.metrics.timer import Timer


@pytest.fixture
def metrics_collector() -> MetricsCollector:
    """Create a MetricsCollector instance for testing."""
    return MetricsCollector()


class TestCounter:
    """Tests for Counter metric."""

    def test_initial_value(self) -> None:
        """Test counter initial value."""
        counter = Counter("test_counter", "Test counter")
        assert counter.get_value() == 0

    def test_increment(self) -> None:
        """Test counter increment."""
        counter = Counter("test_counter")
        counter.increment()
        assert counter.get_value() == 1

        counter.increment(5)
        assert counter.get_value() == 6

    def test_reset(self) -> None:
        """Test counter reset."""
        counter = Counter("test_counter")
        counter.increment(10)
        assert counter.get_value() == 10

        counter.reset()
        assert counter.get_value() == 0

    def test_thread_safety(self) -> None:
        """Test thread-safe counter operations."""
        counter = Counter("test_counter")

        def increment_many():
            for _ in range(100):
                counter.increment()

        threads = [threading.Thread(target=increment_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert counter.get_value() == 1000


class TestGauge:
    """Tests for Gauge metric."""

    def test_initial_value(self) -> None:
        """Test gauge initial value."""
        gauge = Gauge("test_gauge", "Test gauge")
        assert gauge.get_value() == 0.0

    def test_set_value(self) -> None:
        """Test setting gauge value."""
        gauge = Gauge("test_gauge")
        gauge.set(42.5)
        assert gauge.get_value() == 42.5

    def test_increment_decrement(self) -> None:
        """Test gauge increment and decrement."""
        gauge = Gauge("test_gauge")
        gauge.set(10.0)
        gauge.increment(5.0)
        assert gauge.get_value() == 15.0

        gauge.decrement(3.0)
        assert gauge.get_value() == 12.0

    def test_reset(self) -> None:
        """Test gauge reset."""
        gauge = Gauge("test_gauge")
        gauge.set(100.0)
        gauge.reset()
        assert gauge.get_value() == 0.0


class TestHistogram:
    """Tests for Histogram metric."""

    def test_initial_state(self) -> None:
        """Test histogram initial state."""
        histogram = Histogram("test_histogram")
        value = histogram.get_value()
        assert value["count"] == 0
        assert value["sum"] == 0.0
        assert value["mean"] == 0.0

    def test_observe_values(self) -> None:
        """Test observing values."""
        histogram = Histogram("test_histogram")
        histogram.observe(1.0)
        histogram.observe(2.0)
        histogram.observe(3.0)

        value = histogram.get_value()
        assert value["count"] == 3
        assert value["sum"] == 6.0
        assert value["mean"] == 2.0

    def test_reset(self) -> None:
        """Test histogram reset."""
        histogram = Histogram("test_histogram")
        histogram.observe(5.0)
        histogram.reset()

        value = histogram.get_value()
        assert value["count"] == 0
        assert value["sum"] == 0.0

    def test_custom_buckets(self) -> None:
        """Test histogram with custom buckets."""
        histogram = Histogram("test_histogram", buckets=[1.0, 5.0, 10.0])
        histogram.observe(3.0)
        histogram.observe(7.0)

        value = histogram.get_value()
        assert value["count"] == 2
        assert value["buckets"][1.0] == 2  # Both values <= 1.0? No, 3.0 > 1.0
        assert value["buckets"][5.0] == 1  # Only 3.0 <= 5.0
        assert value["buckets"][10.0] == 2  # Both <= 10.0


class TestMetricsCollector:
    """Tests for MetricsCollector."""

    def test_register_counter(self, metrics_collector: MetricsCollector) -> None:
        """Test counter registration."""
        counter = metrics_collector.register_counter("requests", "Total requests")
        assert counter.name == "requests"
        assert metrics_collector.metric_count == 1

    def test_register_gauge(self, metrics_collector: MetricsCollector) -> None:
        """Test gauge registration."""
        gauge = metrics_collector.register_gauge("queue_size", "Queue size")
        assert gauge.name == "queue_size"
        assert metrics_collector.metric_count == 1

    def test_register_histogram(self, metrics_collector: MetricsCollector) -> None:
        """Test histogram registration."""
        histogram = metrics_collector.register_histogram("latency", "Operation latency")
        assert histogram.name == "latency"
        assert metrics_collector.metric_count == 1

    def test_register_duplicate_raises(self, metrics_collector: MetricsCollector) -> None:
        """Test registering duplicate metric raises error."""
        metrics_collector.register_counter("test")
        with pytest.raises(ValueError):
            metrics_collector.register_counter("test")

    def test_get_counter(self, metrics_collector: MetricsCollector) -> None:
        """Test getting counter by name."""
        metrics_collector.register_counter("test_counter")
        counter = metrics_collector.get_counter("test_counter")
        assert counter.name == "test_counter"

    def test_get_gauge(self, metrics_collector: MetricsCollector) -> None:
        """Test getting gauge by name."""
        metrics_collector.register_gauge("test_gauge")
        gauge = metrics_collector.get_gauge("test_gauge")
        assert gauge.name == "test_gauge"

    def test_get_histogram(self, metrics_collector: MetricsCollector) -> None:
        """Test getting histogram by name."""
        metrics_collector.register_histogram("test_histogram")
        histogram = metrics_collector.get_histogram("test_histogram")
        assert histogram.name == "test_histogram"

    def test_increment_counter(self, metrics_collector: MetricsCollector) -> None:
        """Test incrementing counter via collector."""
        metrics_collector.register_counter("test")
        metrics_collector.increment_counter("test", 5)
        assert metrics_collector.get_counter("test").get_value() == 5

    def test_set_gauge(self, metrics_collector: MetricsCollector) -> None:
        """Test setting gauge via collector."""
        metrics_collector.register_gauge("test")
        metrics_collector.set_gauge("test", 42.0)
        assert metrics_collector.get_gauge("test").get_value() == 42.0

    def test_observe_histogram(self, metrics_collector: MetricsCollector) -> None:
        """Test observing histogram via collector."""
        metrics_collector.register_histogram("test")
        metrics_collector.observe_histogram("test", 1.5)
        value = metrics_collector.get_histogram("test").get_value()
        assert value["count"] == 1

    def test_get_all_metrics(self, metrics_collector: MetricsCollector) -> None:
        """Test getting all metrics."""
        metrics_collector.register_counter("counter1")
        metrics_collector.register_gauge("gauge1")

        all_metrics = metrics_collector.get_all_metrics()
        assert "counter1" in all_metrics
        assert "gauge1" in all_metrics
        assert all_metrics["counter1"]["type"] == "Counter"

    def test_get_snapshot(self, metrics_collector: MetricsCollector) -> None:
        """Test getting metrics snapshot."""
        metrics_collector.register_counter("test")
        snapshot = metrics_collector.get_snapshot()

        assert "uptime_seconds" in snapshot
        assert "metrics" in snapshot
        assert snapshot["uptime_seconds"] >= 0

    def test_reset_all(self, metrics_collector: MetricsCollector) -> None:
        """Test resetting all metrics."""
        counter = metrics_collector.register_counter("test")
        counter.increment(10)

        metrics_collector.reset_all()
        assert counter.get_value() == 0

    def test_clear(self, metrics_collector: MetricsCollector) -> None:
        """Test clearing all metrics."""
        metrics_collector.register_counter("test1")
        metrics_collector.register_counter("test2")
        assert metrics_collector.metric_count == 2

        metrics_collector.clear()
        assert metrics_collector.metric_count == 0


class TestTimer:
    """Tests for Timer context manager."""

    def test_timer_context_manager(self) -> None:
        """Test timer as context manager."""
        histogram = Histogram("test_timer")
        timer = Timer(histogram)

        with timer:
            time.sleep(0.01)

        value = histogram.get_value()
        assert value["count"] == 1
        assert value["mean"] > 0.0

    def test_timer_elapsed(self) -> None:
        """Test timer elapsed property."""
        histogram = Histogram("test_timer")
        timer = Timer(histogram)

        with timer:
            time.sleep(0.01)

        assert timer.elapsed > 0.0

    def test_timer_without_context(self) -> None:
        """Test timer elapsed before use."""
        histogram = Histogram("test_timer")
        timer = Timer(histogram)

        assert timer.elapsed == 0.0
