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
    ) -> None:
        self._start_time = start_time or datetime.now(UTC)
        self._config_manager = config_manager
        self._storage = storage
        self._collector_manager = collector_manager  # CollectorManager | None (optional)
        self._event_queue = event_queue

    def check_health(self) -> SystemStatus:
        """Run all subsystem health checks and return aggregated SystemStatus.

        Returns:
            Aggregated SystemStatus.
        """
        components: list[ComponentHealth] = []

        components.append(self._check_config())
        components.append(self._check_logging())
        components.append(self._check_processing_queue())
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
        if self._event_queue is not None:
            return ComponentHealth(
                name="processing_queue",
                status=HealthStatus.HEALTHY,
                message="Ingestion queue active.",
            )
        return ComponentHealth(
            name="processing_queue",
            status=HealthStatus.DEGRADED,
            message="Ingestion queue not wired into health checks.",
        )

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
