"""Collector manager.

Orchestrates all registered collectors: starts, stops, pauses, resumes, and
queries them en-masse.  Failure isolation is the key guarantee: one collector
raising during a bulk operation never prevents the others from proceeding.
"""

import queue
import threading
from typing import Any

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.collectors.registry import CollectorRegistry
from argusprowl.collectors.state import CollectorState
from argusprowl.constants.log_names import LogName
from argusprowl.logging.logger_factory import LoggerFactory
from argusprowl.metrics.collector import MetricsCollector
from argusprowl.models.collector_health import CollectorHealth
from argusprowl.models.normalized_event import NormalizedEvent


class CollectorManager:
    """Orchestrates the lifecycle of all registered collectors.

    Guarantees that one collector failing during a bulk operation
    (``start_all``, ``stop_all``, etc.) will *never* abort the operation for
    other collectors.  Each operation returns a per-collector result map so
    callers can inspect individual failures without catching broad exceptions.

    Args:
        registry: Shared :class:`~app.collectors.registry.CollectorRegistry`.
        event_queue: Optional :class:`queue.Queue` for routing NormalizedEvents.
        metrics_collector: Optional :class:`~app.metrics.collector.MetricsCollector`
            for aggregated manager metrics.
    """

    def __init__(
        self,
        registry: CollectorRegistry | None = None,
        event_queue: queue.Queue[NormalizedEvent] | None = None,
        metrics_collector: MetricsCollector | None = None,
    ) -> None:
        self._registry = registry or CollectorRegistry()
        self._event_queue = event_queue
        self._metrics_collector = metrics_collector
        self._lock = threading.RLock()
        self._logger = LoggerFactory.get_logger(LogName.COLLECTOR_MANAGER)
        self._setup_manager_metrics()

    # ------------------------------------------------------------------ collector registration

    def add_collector(self, collector: BaseCollector) -> None:
        """Register a collector with the manager.

        Args:
            collector: Initialized :class:`BaseCollector` to add.

        Raises:
            CollectorError: If a collector with the same name is already registered.
        """
        self._registry.register(collector)
        self._logger.info("Collector '%s' registered with manager.", collector.name)

    def remove_collector(self, name: str) -> None:
        """Unregister a collector from the manager.

        The collector is stopped first if it is not already stopped or
        uninitialized.  Removal proceeds even if stop fails.

        Args:
            name: Collector name to remove.

        Raises:
            KeyError: If no collector with *name* is registered.
        """
        collector = self._registry.get(name)
        if collector.state not in (CollectorState.STOPPED, CollectorState.UNINITIALIZED):
            try:
                collector.stop()
            except Exception as exc:
                self._logger.warning("Error stopping collector '%s' during removal: %s", name, exc)
        self._registry.unregister(name)
        self._logger.info("Collector '%s' removed from manager.", name)

    # ------------------------------------------------------------------ bulk lifecycle

    def start_all(self) -> dict[str, Exception | None]:
        """Start every STOPPED collector.

        Collectors that are already RUNNING are skipped.  Failures are
        captured per-collector and do not abort the batch.

        Returns:
            Dict mapping collector names to ``None`` (success) or the
            :class:`Exception` that was raised.
        """
        return self._apply_to_all(self._safe_start, states={CollectorState.STOPPED}, label="start")

    def stop_all(self) -> dict[str, Exception | None]:
        """Stop every active collector.

        Returns:
            Dict mapping collector names to ``None`` (success) or exception.
        """
        stoppable = {
            CollectorState.RUNNING,
            CollectorState.PAUSED,
            CollectorState.PAUSING,
            CollectorState.STARTING,
            CollectorState.RESUMING,
            CollectorState.FAILED,
        }
        return self._apply_to_all(self._safe_stop, states=stoppable, label="stop")

    def pause_all(self) -> dict[str, Exception | None]:
        """Pause every RUNNING collector.

        Returns:
            Dict mapping collector names to ``None`` (success) or exception.
        """
        return self._apply_to_all(self._safe_pause, states={CollectorState.RUNNING}, label="pause")

    def resume_all(self) -> dict[str, Exception | None]:
        """Resume every PAUSED collector.

        Returns:
            Dict mapping collector names to ``None`` (success) or exception.
        """
        return self._apply_to_all(self._safe_resume, states={CollectorState.PAUSED}, label="resume")

    # ------------------------------------------------------------------ individual lifecycle

    def start_collector(self, name: str) -> None:
        """Start a single named collector.

        Args:
            name: Collector name.

        Raises:
            KeyError: If *name* is not registered.
            CollectorError: If start fails.
        """
        collector = self._registry.get(name)
        collector.start()

    def stop_collector(self, name: str) -> None:
        """Stop a single named collector.

        Args:
            name: Collector name.

        Raises:
            KeyError: If *name* is not registered.
            CollectorError: If stop fails.
        """
        collector = self._registry.get(name)
        collector.stop()

    def pause_collector(self, name: str) -> None:
        """Pause a single named collector.

        Args:
            name: Collector name.

        Raises:
            KeyError: If *name* is not registered.
            CollectorError: If pause fails.
        """
        collector = self._registry.get(name)
        collector.pause()

    def resume_collector(self, name: str) -> None:
        """Resume a single named collector.

        Args:
            name: Collector name.

        Raises:
            KeyError: If *name* is not registered.
            CollectorError: If resume fails.
        """
        collector = self._registry.get(name)
        collector.resume()

    # ------------------------------------------------------------------ observability

    def health_all(self) -> dict[str, CollectorHealth]:
        """Return health snapshots for all registered collectors.

        Returns:
            Dict mapping collector names to :class:`~app.models.collector_health.CollectorHealth`.
        """
        return {name: collector.health() for name, collector in self._registry.get_all().items()}

    def status_all(self) -> dict[str, dict[str, Any]]:
        """Return serializable status dicts for all registered collectors.

        Returns:
            Dict mapping collector names to plain status dicts.
        """
        return {name: collector.status() for name, collector in self._registry.get_all().items()}

    def get_collector(self, name: str) -> BaseCollector:
        """Return a collector by name.

        Args:
            name: Collector name.

        Returns:
            :class:`BaseCollector` instance.

        Raises:
            KeyError: If *name* is not registered.
        """
        return self._registry.get(name)

    # ------------------------------------------------------------------ properties

    @property
    def collector_count(self) -> int:
        """Total number of registered collectors."""
        return len(self._registry)

    @property
    def running_count(self) -> int:
        """Number of collectors currently in RUNNING state."""
        return len(self._registry.get_by_state(CollectorState.RUNNING))

    @property
    def failed_count(self) -> int:
        """Number of collectors currently in FAILED state."""
        return len(self._registry.get_by_state(CollectorState.FAILED))

    @property
    def registry(self) -> CollectorRegistry:
        """The backing :class:`~app.collectors.registry.CollectorRegistry`."""
        return self._registry

    # ------------------------------------------------------------------ private helpers

    def _apply_to_all(
        self,
        operation: Any,
        states: set[CollectorState],
        label: str,
    ) -> dict[str, Exception | None]:
        """Apply *operation* to every collector whose state is in *states*.

        Failures are isolated: exceptions are caught, logged, and returned in
        the result dict without interrupting other collectors.

        Args:
            operation: Callable ``(BaseCollector) -> None``.
            states: Set of states for which the operation is applicable.
            label: Human-readable operation name for log messages.

        Returns:
            Dict mapping collector names to ``None`` (success) or exception.
        """
        results: dict[str, Exception | None] = {}
        collectors = self._registry.get_all()

        for name, collector in collectors.items():
            if collector.state not in states:
                continue
            try:
                operation(collector)
                results[name] = None
            except Exception as exc:
                results[name] = exc
                self._logger.error("Collector '%s' failed during '%s': %s", name, label, exc)

        if self._metrics_collector is not None:
            self._update_aggregate_metrics()

        return results

    @staticmethod
    def _safe_start(collector: BaseCollector) -> None:
        collector.start()

    @staticmethod
    def _safe_stop(collector: BaseCollector) -> None:
        collector.stop()

    @staticmethod
    def _safe_pause(collector: BaseCollector) -> None:
        collector.pause()

    @staticmethod
    def _safe_resume(collector: BaseCollector) -> None:
        collector.resume()

    def _setup_manager_metrics(self) -> None:
        """Register manager-level aggregate metrics if a MetricsCollector is present."""
        if self._metrics_collector is None:
            return
        try:
            self._metrics_collector.register_gauge(
                "collector_manager.running_count",
                "Number of collectors currently in RUNNING state.",
            )
            self._metrics_collector.register_gauge(
                "collector_manager.failed_count",
                "Number of collectors currently in FAILED state.",
            )
            self._metrics_collector.register_gauge(
                "collector_manager.total_count",
                "Total number of registered collectors.",
            )
        except ValueError:
            # Metrics already registered (e.g. manager re-created in tests).
            pass

    def _update_aggregate_metrics(self) -> None:
        """Push current collector counts into the manager-level gauges."""
        if self._metrics_collector is None:
            return
        try:
            self._metrics_collector.set_gauge(
                "collector_manager.running_count", float(self.running_count)
            )
            self._metrics_collector.set_gauge(
                "collector_manager.failed_count", float(self.failed_count)
            )
            self._metrics_collector.set_gauge(
                "collector_manager.total_count", float(self.collector_count)
            )
        except KeyError:
            pass

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"CollectorManager("
            f"total={self.collector_count}, "
            f"running={self.running_count}, "
            f"failed={self.failed_count})"
        )
