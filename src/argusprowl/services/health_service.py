"""System health monitoring service.

Performs health checks across configuration, logging, processing queue,
and storage subsystem components.
"""

import shutil
from datetime import UTC, datetime
from pathlib import Path

import argusprowl
from argusprowl.config.config_manager import ConfigManager
from argusprowl.interfaces.storage import Storage
from argusprowl.logging.logger_factory import LoggerFactory
from argusprowl.metrics.collector import MetricsCollector
from argusprowl.models.system_status import ComponentHealth, HealthStatus, SystemStatus


class HealthService:
    """Service to evaluate and aggregate platform component health."""

    def __init__(
        self,
        start_time: datetime | None = None,
        config_manager: ConfigManager | None = None,
        storage: Storage | None = None,
        collector_manager: object | None = None,
        event_queue: object | None = None,
        metrics_collector: MetricsCollector | None = None,
    ) -> None:
        self._start_time = start_time or datetime.now(UTC)
        self._config_manager = config_manager
        self._storage = storage
        self._collector_manager = collector_manager  # CollectorManager | None (optional)
        self._event_queue = event_queue
        self._metrics_collector = metrics_collector

    def check_health(self) -> SystemStatus:
        """Run all subsystem health checks and return aggregated SystemStatus.

        Returns:
            Aggregated SystemStatus.
        """
        components: list[ComponentHealth] = []

        components.append(self._check_config())
        components.append(self._check_logging())
        components.append(self._check_processing_queue())
        components.append(self._check_storage())
        components.append(self._check_detection_pipeline())
        components.append(self._check_disk())

        # Collector health is optional - silently skipped when no manager is wired.
        collector_components = self._check_collectors()
        components.extend(collector_components)

        # Determine overall system health
        statuses = {c.status for c in components}
        if HealthStatus.UNHEALTHY in statuses:
            overall = HealthStatus.UNHEALTHY
        elif HealthStatus.DEGRADED in statuses:
            overall = HealthStatus.DEGRADED
        else:
            overall = HealthStatus.HEALTHY

        now = datetime.now(UTC)
        uptime = (now - self._start_time).total_seconds()

        return SystemStatus(
            status=overall,
            version=argusprowl.__version__,
            uptime_seconds=uptime,
            checked_at=now,
            components=tuple(components),
        )

    def _check_config(self) -> ComponentHealth:
        cm = self._config_manager or ConfigManager.get_instance()
        if cm.is_loaded:
            return ComponentHealth(
                name="config",
                status=HealthStatus.HEALTHY,
                message="Configuration loaded successfully.",
            )
        return ComponentHealth(
            name="config",
            status=HealthStatus.UNHEALTHY,
            message="Configuration has not been loaded.",
        )

    def _check_logging(self) -> ComponentHealth:
        if LoggerFactory.is_initialized():
            return ComponentHealth(
                name="logging",
                status=HealthStatus.HEALTHY,
                message="Logging subsystem initialized.",
            )
        return ComponentHealth(
            name="logging",
            status=HealthStatus.DEGRADED,
            message="Logging subsystem operating on defaults (not explicitly setup).",
        )

    def _check_processing_queue(self) -> ComponentHealth:
        """Report queue pressure and cumulative ingestion/processing loss."""
        if self._event_queue is None:
            return ComponentHealth(
                name="processing_queue",
                status=HealthStatus.DEGRADED,
                message="Ingestion queue not wired into health checks.",
            )

        try:
            depth = len(self._event_queue)
            capacity = int(getattr(self._event_queue, "max_size", 0))
            dropped = int(self._event_queue.events_dropped.get_value())
            failed = int(self._event_queue.events_processing_failed.get_value())
            received = int(self._event_queue.events_received.get_value())
            processed = int(self._event_queue.events_processed.get_value())
            rejected = int(self._event_queue.rejected_count.get_value())
            closed = bool(getattr(self._event_queue, "closed", False))
            pressure = depth / capacity if capacity > 0 else 0.0
            if closed:
                status = HealthStatus.UNHEALTHY
            elif dropped or failed or pressure >= 0.8:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.HEALTHY
            message = (
                f"depth={depth}/{capacity or 'unknown'}; received={received}; "
                f"processed={processed}; dropped={dropped}; rejected={rejected}; "
                f"processing_failed={failed}"
            )
            if closed:
                message = f"Ingestion queue is closed; {message}"
            elif dropped or failed:
                message = f"Loss or processing failures detected; {message}"
            elif pressure >= 0.8:
                message = f"Ingestion queue near capacity; {message}"
            else:
                message = f"Ingestion queue active; {message}"
            return ComponentHealth(name="processing_queue", status=status, message=message)
        except Exception as exc:
            return ComponentHealth(
                name="processing_queue",
                status=HealthStatus.DEGRADED,
                message=f"Unable to inspect ingestion queue metrics: {exc}",
            )

    def _check_storage(self) -> ComponentHealth:
        """Perform a read-only storage probe without creating or mutating records."""
        if self._storage is None:
            return ComponentHealth(
                name="storage",
                status=HealthStatus.DEGRADED,
                message="Storage adapter not wired into health checks.",
            )
        try:
            self._storage.list_records("__argusprowl_health_probe__", limit=1)
            return ComponentHealth(
                name="storage",
                status=HealthStatus.HEALTHY,
                message="Storage read probe succeeded.",
            )
        except Exception as exc:
            return ComponentHealth(
                name="storage",
                status=HealthStatus.UNHEALTHY,
                message=f"Storage read probe failed: {exc}",
            )


    def _check_detection_pipeline(self) -> ComponentHealth:
        """Surface detector and evidence-persistence failures that do not stop ingestion."""
        if self._metrics_collector is None:
            return ComponentHealth(
                name="detection_pipeline",
                status=HealthStatus.DEGRADED,
                message="Detection pipeline error metrics are not wired into health checks.",
            )
        metric_names = (
            "beaconing_detector_errors",
            "correlation_detector_errors",
            "evidence_persistence_errors",
        )
        try:
            counts = {}
            for name in metric_names:
                try:
                    counts[name] = int(self._metrics_collector.get_counter(name).get_value())
                except KeyError:
                    counts[name] = 0
        except KeyError:
            counts = {name: 0 for name in metric_names}
        except Exception as exc:
            return ComponentHealth(
                name="detection_pipeline",
                status=HealthStatus.DEGRADED,
                message=f"Unable to inspect detection pipeline metrics: {exc}",
            )
        total = sum(counts.values())
        status = HealthStatus.DEGRADED if total else HealthStatus.HEALTHY
        message = (
            "Detector/evidence errors detected; "
            if total
            else "No detector/evidence errors recorded; "
        ) + "; ".join(f"{name}={count}" for name, count in counts.items())
        return ComponentHealth(name="detection_pipeline", status=status, message=message)

    def _check_disk(self) -> ComponentHealth:
        try:
            _, _, free = shutil.disk_usage(Path.cwd())
            free_mb = free / (1024 * 1024)
            if free_mb < 100:  # Less than 100 MB free space
                return ComponentHealth(
                    name="disk_space",
                    status=HealthStatus.DEGRADED,
                    message=f"Low disk space available: {free_mb:.1f} MB.",
                )
            return ComponentHealth(
                name="disk_space",
                status=HealthStatus.HEALTHY,
                message=f"Disk space sufficient: {free_mb:.1f} MB free.",
            )
        except Exception as exc:
            return ComponentHealth(
                name="disk_space",
                status=HealthStatus.DEGRADED,
                message=f"Disk check error: {exc}",
            )

    def _check_collectors(self) -> list[ComponentHealth]:
        """Aggregate per-collector health into ComponentHealth entries.

        Returns an empty list when no :class:`CollectorManager` is wired,
        preserving backward compatibility with Phase 1 deployments.

        Returns:
            Zero or more :class:`ComponentHealth` instances, one per collector.
        """
        if self._collector_manager is None:
            return []

        try:
            from argusprowl.collectors.state import (
                CollectorState,  # lazy import avoids circular issues
            )

            health_map = self._collector_manager.health_all()  # type: ignore[union-attr]
            result: list[ComponentHealth] = []
            for name, ch in health_map.items():
                if ch.state == CollectorState.FAILED:
                    status = HealthStatus.UNHEALTHY
                elif ch.state == CollectorState.PAUSED:
                    status = HealthStatus.DEGRADED
                elif ch.state == CollectorState.RUNNING:
                    status = HealthStatus.HEALTHY
                else:
                    status = HealthStatus.DEGRADED

                result.append(
                    ComponentHealth(
                        name=f"collector.{name}",
                        status=status,
                        message=ch.error_message or f"State: {ch.state}",
                    )
                )
            return result
        except Exception as exc:
            return [
                ComponentHealth(
                    name="collectors",
                    status=HealthStatus.DEGRADED,
                    message=f"Collector health check error: {exc}",
                )
            ]
