"""Configuration manager.

Centralized thread-safe access point for application configuration.
"""

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from argusprowl.config.config_loader import ConfigLoader
from argusprowl.config.config_validator import ConfigValidator
from argusprowl.models.configuration import (
    AlertPersistenceConfig,
    AlertQueueConfig,
    ApiConfig,
    AppConfiguration,
    AttckConfig,
    BufferConfig,
    DeduplicationConfig,
    EndpointCorrelationConfig,
    EventsConfig,
    IngestionConfig,
    LinuxAuditConfig,
    LoggingConfig,
    ReliabilityConfig,
    RetryConfig,
    StorageConfig,
    SysmonConfig,
    TemporalConfig,
    WindowsEventLogConfig,
)


class ConfigManager:
    """Manager class for loading, validating, and accessing configuration."""

    _instance: "ConfigManager | None" = None
    _lock: threading.Lock = threading.Lock()

    def __init__(
        self,
        loader: ConfigLoader | None = None,
        validator: ConfigValidator | None = None,
    ) -> None:
        """Initialize ConfigManager.

        Args:
            loader: Loader instance (defaults to ConfigLoader).
            validator: Validator instance (defaults to ConfigValidator).
        """
        self._loader = loader or ConfigLoader()
        self._validator = validator or ConfigValidator()
        self._config: AppConfiguration | None = None
        self._raw_config: dict[str, Any] = {}
        self._source_path: Path | None = None
        self._source_mtime_ns: int | None = None
        self._reload_listeners: list[Callable[[AppConfiguration], None]] = []

    @classmethod
    def get_instance(cls) -> "ConfigManager":
        """Get or create singleton instance of ConfigManager.

        Returns:
            The singleton ConfigManager instance.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (primarily for testing)."""
        with cls._lock:
            cls._instance = None

    def load(self, yaml_path: str | Path | None = None) -> AppConfiguration:
        """Load, validate, and construct typed AppConfiguration.

        Args:
            yaml_path: Optional path to YAML config file.

        Returns:
            Populated :class:`AppConfiguration` dataclass.
        """
        raw = self._loader.load_config(yaml_path)
        self._validator.validate(raw)
        self._raw_config = raw

        logging_data = raw.get("logging", {})
        storage_data = raw.get("storage", {})
        events_data = raw.get("events", {})

        logging_cfg = LoggingConfig(
            level=logging_data.get("level", "INFO"),
            console_enabled=logging_data.get("console_enabled", True),
            file_enabled=logging_data.get("file_enabled", True),
            json_enabled=logging_data.get("json_enabled", False),
            log_file=logging_data.get("log_file", "logs/argusprowl.log"),
            json_log_file=logging_data.get("json_log_file", "logs/argusprowl.json"),
            max_bytes=logging_data.get("max_bytes", 10485760),
            backup_count=logging_data.get("backup_count", 5),
            colored_console=logging_data.get("colored_console", True),
        )

        storage_cfg = StorageConfig(
            backend=storage_data.get("backend", "sqlite"),
            base_path=storage_data.get("base_path", "data"),
            database_path=storage_data.get("database_path", "data/argusprowl.db"),
        )

        events_cfg = EventsConfig(
            queue_size=events_data.get("queue_size", 1000),
            async_dispatch=events_data.get("async_dispatch", False),
            worker_count=events_data.get("worker_count", 1),
            shutdown_timeout_seconds=float(events_data.get("shutdown_timeout_seconds", 5.0)),
        )

        ingestion_data = raw.get("ingestion", {})
        ingestion_cfg = IngestionConfig(
            zeek_log_path=ingestion_data.get("zeek_log_path", "data/conn.log"),
            poll_interval=float(ingestion_data.get("poll_interval", 0.5)),
            batch_size=int(ingestion_data.get("batch_size", 100)),
        )
        reliability_data = raw.get("reliability", {})
        buffer_data = reliability_data.get("buffer", {})
        retry_data = reliability_data.get("retry", {})
        deduplication_data = reliability_data.get("deduplication", {})
        alert_queue_data = reliability_data.get("alert_queue", {})
        reliability_cfg = ReliabilityConfig(
            buffer=BufferConfig(
                max_size=buffer_data.get("max_size", 1000),
                overflow_policy=buffer_data.get("overflow_policy", "drop_newest"),
            ),
            retry=RetryConfig(
                max_attempts=retry_data.get("max_attempts", 3),
                initial_delay=retry_data.get("initial_delay", 0.1),
                max_delay=retry_data.get("max_delay", 5.0),
                jitter=retry_data.get("jitter", False),
            ),
            deduplication=DeduplicationConfig(
                enabled=deduplication_data.get("enabled", True),
                default_cooldown=deduplication_data.get("default_cooldown", 300.0),
                max_fingerprints=deduplication_data.get("max_fingerprints", 10000),
            ),
            alert_queue=AlertQueueConfig(
                max_size=alert_queue_data.get("max_size", 10_000),
            ),
        )
        temporal_data = raw.get("temporal", {})
        temporal_cfg = TemporalConfig(
            enabled=temporal_data.get("enabled", True),
            max_keys=int(temporal_data.get("max_keys", 10000)),
            max_observations_per_key=int(temporal_data.get("max_observations_per_key", 1000)),
            window_duration_seconds=float(temporal_data.get("window_duration_seconds", 3600.0)),
            min_observations=int(temporal_data.get("min_observations", 10)),
            min_duration_seconds=float(temporal_data.get("min_duration_seconds", 300.0)),
            periodicity_threshold=float(temporal_data.get("periodicity_threshold", 0.7)),
        )
        endpoint_corr_data = raw.get("endpoint_correlation", {})
        endpoint_corr_cfg = EndpointCorrelationConfig(
            enabled=endpoint_corr_data.get("enabled", True),
            correlation_window_seconds=float(
                endpoint_corr_data.get("correlation_window_seconds", 30.0)
            ),
            max_processes=int(endpoint_corr_data.get("max_processes", 10000)),
            max_observations=int(endpoint_corr_data.get("max_observations", 1000)),
        )
        sysmon_data = raw.get("sysmon", {})
        sysmon_cfg = SysmonConfig(
            enabled=sysmon_data.get("enabled", False),
            channel=sysmon_data.get("channel", "Microsoft-Windows-Sysmon/Operational"),
            bookmark_path=sysmon_data.get("bookmark_path", "data/sysmon-bookmark.json"),
            batch_size=sysmon_data.get("batch_size", 100),
            polling_interval=sysmon_data.get("polling_interval", 1.0),
            supported_event_ids=tuple(
                sysmon_data.get("supported_event_ids", (1, 3, 7, 8, 10, 11, 12, 13, 14, 22))
            ),
        )
        windows_data = raw.get("windows_event_log", {})
        windows_cfg = WindowsEventLogConfig(
            enabled=windows_data.get("enabled", False),
            channels=tuple(windows_data.get("channels", ("Security",))),
            bookmark_path=windows_data.get("bookmark_path", "data/windows-event-bookmarks.json"),
            batch_size=windows_data.get("batch_size", 100),
            polling_interval=windows_data.get("polling_interval", 1.0),
            event_ids=tuple(
                windows_data.get(
                    "event_ids", (4624, 4625, 4648, 4672, 4688, 4697, 4720, 4728, 4732, 4756, 1102)
                )
            ),
        )
        audit_data = raw.get("linux_audit", {})
        audit_cfg = LinuxAuditConfig(
            enabled=audit_data.get("enabled", False),
            path=audit_data.get("path", "/var/log/audit/audit.log"),
            bookmark_path=audit_data.get("bookmark_path", "data/linux-audit-bookmark.json"),
            batch_size=audit_data.get("batch_size", 100),
            polling_interval=audit_data.get("polling_interval", 1.0),
            grouping_timeout=audit_data.get("grouping_timeout", 1.0),
            max_pending_groups=audit_data.get("max_pending_groups", 1000),
            supported_record_types=tuple(
                audit_data.get("supported_record_types", LinuxAuditConfig().supported_record_types)
            ),
        )

        # Baseline configuration (Phase 5.1.5)
        from argusprowl.models.configuration import BaselineConfig

        baseline_data = raw.get("baseline", {})
        baseline_cfg = BaselineConfig(
            enabled=baseline_data.get("enabled", True),
            maturity_min_observations=baseline_data.get("maturity_min_observations", 20),
            maturity_window_seconds=float(baseline_data.get("maturity_window_seconds", 3600.0)),
            rare_threshold=baseline_data.get("rare_threshold", 5),
            future_skew_threshold_seconds=float(
                baseline_data.get("future_skew_threshold_seconds", 60.0)
            ),
            max_distinct_values=baseline_data.get("max_distinct_values", 1000),
            max_observations_retained=baseline_data.get("max_observations_retained", 10000),
            stale_after_seconds=float(baseline_data.get("stale_after_seconds", 86400.0)),
        )

        # Behavior persistence configuration (Phase 5.1.8)
        from argusprowl.models.configuration import BehaviorPersistenceConfig

        persistence_data = raw.get("behavior_persistence", {})
        persistence_cfg = BehaviorPersistenceConfig(
            enabled=persistence_data.get("enabled", False),
            db_path=persistence_data.get("db_path", "data/behavior_state.db"),
            save_interval_seconds=float(persistence_data.get("save_interval_seconds", 60.0)),
            max_profiles=int(persistence_data.get("max_profiles", 100000)),
        )

        # Analyst annotation configuration (Phase 5.2)
        from argusprowl.models.configuration import AnalystAnnotationConfig

        annotation_data = raw.get("analyst_annotations", {})
        annotation_cfg = AnalystAnnotationConfig(
            enabled=annotation_data.get("enabled", False),
            db_path=annotation_data.get("db_path", "data/analyst_annotations.db"),
            max_annotations_per_target=annotation_data.get("max_annotations_per_target", 50),
            max_total_annotations=annotation_data.get("max_total_annotations", 10000),
        )

        # Alert persistence configuration (Phase 5.4.1)
        alert_persistence_data = raw.get("alert_persistence", {})
        alert_persistence_cfg = AlertPersistenceConfig(
            enabled=alert_persistence_data.get("enabled", False),
            db_path=alert_persistence_data.get("db_path", "data/alerts.db"),
            max_alerts=int(alert_persistence_data.get("max_alerts", 10_000)),
        )

        # ATT&CK knowledge configuration (Phase 6.1)
        attck_data = raw.get("attck", {})
        attck_cfg = AttckConfig(
            enabled=attck_data.get("enabled", False),
            snapshot_path=attck_data.get("snapshot_path", "data/attck_snapshot.json"),
            previous_snapshot_path=attck_data.get("previous_snapshot_path", ""),
        )

        # API configuration (Phase 7.0)
        api_data = raw.get("api", {})
        api_cfg = ApiConfig(
            enabled=api_data.get("enabled", True),
            host=api_data.get("host", "127.0.0.1"),
            port=int(api_data.get("port", 8080)),
            cors_origins=api_data.get("cors_origins", []),
            max_alert_limit=int(api_data.get("max_alert_limit", 100)),
        )

        self._config = AppConfiguration(
            app_name=raw.get("app_name", "argusprowl"),
            debug=raw.get("debug", False),
            environment=raw.get("environment", "production"),
            logging=logging_cfg,
            storage=storage_cfg,
            events=events_cfg,
            attck=attck_cfg,
            ingestion=ingestion_cfg,
            reliability=reliability_cfg,
            temporal=temporal_cfg,
            endpoint_correlation=endpoint_corr_cfg,
            baseline=baseline_cfg,
            behavior_persistence=persistence_cfg,
            analyst_annotations=annotation_cfg,
            alert_persistence=alert_persistence_cfg,
            sysmon=sysmon_cfg,
            windows_event_log=windows_cfg,
            linux_audit=audit_cfg,
            api=api_cfg,
        )

        if yaml_path is not None:
            self._source_path = Path(yaml_path)
            self._source_mtime_ns = self._source_path.stat().st_mtime_ns

        return self._config

    def add_reload_listener(self, listener: Callable[[AppConfiguration], None]) -> None:
        """Register a callback for a future file-watcher or SIGHUP adapter.

        Callbacks run only after parsing and validation succeed, so consumers
        never observe a partial configuration.
        """
        self._reload_listeners.append(listener)

    def reload_if_changed(self) -> bool:
        """Reload the configured YAML file when its modification time changes.

        This is deliberately polling-only: deployment-specific watchers are an
        outer adapter and do not belong in the configuration domain service.
        """
        if self._source_path is None or not self._source_path.exists():
            return False
        current_mtime = self._source_path.stat().st_mtime_ns
        if current_mtime == self._source_mtime_ns:
            return False
        config = self.load(self._source_path)
        for listener in tuple(self._reload_listeners):
            listener(config)
        return True

    @property
    def config(self) -> AppConfiguration:
        """Get loaded configuration.

        Returns:
            The loaded :class:`AppConfiguration`.

        Raises:
            RuntimeError: If configuration has not been loaded yet.
        """
        if self._config is None:
            raise RuntimeError("Configuration has not been loaded. Call load() first.")
        return self._config

    @property
    def is_loaded(self) -> bool:
        """Return True if configuration is loaded."""
        return self._config is not None

    def get_raw(self) -> dict[str, Any]:
        """Return raw loaded configuration dictionary."""
        return self._raw_config.copy()
