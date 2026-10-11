"""Configuration validator.

Validates configuration dictionaries against constraints and type rules.
"""

import math
import re
from typing import Any, ClassVar

from argusprowl.exceptions.exceptions import ValidationError
from argusprowl.utils.validation_helpers import is_non_empty_string


class ConfigValidator:
    """Validates raw configuration dictionaries before instantiation of models."""

    VALID_LOG_LEVELS: ClassVar[set[str]] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    VALID_STORAGE_BACKENDS: ClassVar[set[str]] = {
        "sqlite",
        "memory",
        "postgresql",
        "redis",
        "clickhouse",
        "filesystem",
    }

    def validate(self, config: dict[str, Any]) -> None:
        """Validate a configuration dictionary.

        Args:
            config: Configuration dictionary to check.

        Raises:
            ValidationError: If any validation check fails.
        """
        if not isinstance(config, dict):
            raise ValidationError("Configuration must be a dictionary.")

        self._validate_app_section(config)
        self._validate_logging_section(config.get("logging"))
        self._validate_storage_section(config.get("storage"))
        self._validate_events_section(config.get("events"))
        self._validate_reliability_section(
            config.get("reliability", {}), config.get("reliability", {}).get("alert_queue", {})
        )
        self._validate_temporal_section(config.get("temporal", {}))
        self._validate_endpoint_correlation_section(config.get("endpoint_correlation", {}))
        self._validate_event_count_correlation_section(config.get("event_count_correlation", {}))
        self._validate_sysmon_section(config.get("sysmon", {}))
        self._validate_windows_event_log_section(config.get("windows_event_log", {}))
        self._validate_linux_audit_section(config.get("linux_audit", {}))
        self._validate_behavior_persistence_section(config.get("behavior_persistence", {}))
        self._validate_analyst_annotations_section(config.get("analyst_annotations", {}))
        self._validate_alert_persistence_section(config.get("alert_persistence", {}))
        self._validate_attck_section(config.get("attck", {}))
        self._validate_api_section(config.get("api", {}))

    def _validate_app_section(self, config: dict[str, Any]) -> None:
        app_name = config.get("app_name")
        if not is_non_empty_string(app_name):
            raise ValidationError(
                "app_name must be a non-empty string.",
                details={"app_name": app_name},
            )

        if not isinstance(config.get("debug", False), bool):
            raise ValidationError(
                "debug must be a boolean.",
                details={"debug": config.get("debug")},
            )

        env = config.get("environment")
        if not is_non_empty_string(env):
            raise ValidationError(
                "environment must be a non-empty string.",
                details={"environment": env},
            )

    def _validate_logging_section(self, logging_cfg: Any) -> None:
        if not isinstance(logging_cfg, dict):
            raise ValidationError("logging section must be a dictionary.")

        level = logging_cfg.get("level")
        if not isinstance(level, str) or level.upper() not in self.VALID_LOG_LEVELS:
            raise ValidationError(
                f"Invalid log level '{level}'. Valid levels: {sorted(self.VALID_LOG_LEVELS)}",
                details={"level": level},
            )

        for bool_key in ("console_enabled", "file_enabled", "json_enabled", "colored_console"):
            val = logging_cfg.get(bool_key)
            if not isinstance(val, bool):
                raise ValidationError(
                    f"logging.{bool_key} must be a boolean.",
                    details={bool_key: val},
                )

        max_bytes = logging_cfg.get("max_bytes")
        if not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValidationError(
                "logging.max_bytes must be a positive integer.",
                details={"max_bytes": max_bytes},
            )

        backup_count = logging_cfg.get("backup_count")
        if not isinstance(backup_count, int) or backup_count < 0:
            raise ValidationError(
                "logging.backup_count must be a non-negative integer.",
                details={"backup_count": backup_count},
            )

    def _validate_storage_section(self, storage_cfg: Any) -> None:
        if not isinstance(storage_cfg, dict):
            raise ValidationError("storage section must be a dictionary.")

        backend = storage_cfg.get("backend")
        if not isinstance(backend, str) or backend.lower() not in self.VALID_STORAGE_BACKENDS:
            raise ValidationError(
                f"Invalid storage backend '{backend}'. Valid backends: {sorted(self.VALID_STORAGE_BACKENDS)}",
                details={"backend": backend},
            )

        base_path = storage_cfg.get("base_path")
        if not is_non_empty_string(base_path):
            raise ValidationError(
                "storage.base_path must be a non-empty string.",
                details={"base_path": base_path},
            )
        if backend.lower() == "sqlite" and not is_non_empty_string(
            storage_cfg.get("database_path")
        ):
            raise ValidationError("storage.database_path must be a non-empty string for sqlite.")

    def _validate_events_section(self, events_cfg: Any) -> None:
        if not isinstance(events_cfg, dict):
            raise ValidationError("events section must be a dictionary.")

        queue_size = events_cfg.get("queue_size")
        if not isinstance(queue_size, int) or queue_size <= 0:
            raise ValidationError(
                "events.queue_size must be a positive integer.",
                details={"queue_size": queue_size},
            )

        async_dispatch = events_cfg.get("async_dispatch")
        if not isinstance(async_dispatch, bool):
            raise ValidationError(
                "events.async_dispatch must be a boolean.",
                details={"async_dispatch": async_dispatch},
            )
        if (
            not isinstance(events_cfg.get("worker_count", 1), int)
            or events_cfg.get("worker_count", 1) <= 0
        ):
            raise ValidationError("events.worker_count must be a positive integer.")

    def _validate_reliability_section(self, reliability: Any, alert_queue: Any) -> None:
        if not isinstance(reliability, dict):
            raise ValidationError("reliability section must be a dictionary.")
        buffer = reliability.get("buffer", {})
        retry = reliability.get("retry", {})
        deduplication = reliability.get("deduplication", {})

        # Alert queue validation
        if not isinstance(alert_queue, dict):
            raise ValidationError("reliability.alert_queue must be a dictionary.")
        max_size = alert_queue.get("max_size", 10_000)
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValidationError(
                "reliability.alert_queue.max_size must be a positive integer.",
                details={"max_size": max_size},
            )
        if (
            not isinstance(buffer, dict)
            or not isinstance(buffer.get("max_size", 1000), int)
            or buffer.get("max_size", 1000) <= 0
        ):
            raise ValidationError("reliability.buffer.max_size must be a positive integer.")
        if buffer.get("overflow_policy", "drop_newest") not in {
            "block",
            "drop_newest",
            "drop_oldest",
        }:
            raise ValidationError("reliability.buffer.overflow_policy is invalid.")
        if (
            not isinstance(retry, dict)
            or not isinstance(retry.get("max_attempts", 3), int)
            or retry.get("max_attempts", 3) < 1
        ):
            raise ValidationError("reliability.retry.max_attempts must be a positive integer.")
        if not all(
            isinstance(retry.get(key, default), (int, float)) and retry.get(key, default) >= 0
            for key, default in (("initial_delay", 0.1), ("max_delay", 5.0))
        ):
            raise ValidationError("reliability retry delays must be non-negative numbers.")
        if retry.get("max_delay", 5.0) < retry.get("initial_delay", 0.1) or not isinstance(
            retry.get("jitter", False), bool
        ):
            raise ValidationError("reliability retry configuration is invalid.")
        if (
            not isinstance(deduplication, dict)
            or not isinstance(deduplication.get("enabled", True), bool)
            or not isinstance(deduplication.get("max_fingerprints", 10000), int)
            or deduplication.get("max_fingerprints", 10000) <= 0
            or not isinstance(deduplication.get("default_cooldown", 300.0), (int, float))
            or deduplication.get("default_cooldown", 300.0) < 0
        ):
            raise ValidationError("reliability.deduplication configuration is invalid.")

    def _validate_temporal_section(self, temporal: Any) -> None:
        if not isinstance(temporal, dict):
            raise ValidationError("temporal section must be a dictionary.")
        if not isinstance(temporal.get("enabled", True), bool):
            raise ValidationError("temporal.enabled must be a boolean.")
        max_keys = temporal.get("max_keys", 10000)
        if not isinstance(max_keys, int) or max_keys <= 0:
            raise ValidationError("temporal.max_keys must be a positive integer.")
        max_obs = temporal.get("max_observations_per_key", 1000)
        if not isinstance(max_obs, int) or max_obs <= 0:
            raise ValidationError("temporal.max_observations_per_key must be a positive integer.")
        window = temporal.get("window_duration_seconds", 3600.0)
        if not isinstance(window, (int, float)) or window <= 0:
            raise ValidationError("temporal.window_duration_seconds must be positive.")
        min_obs = temporal.get("min_observations", 10)
        if not isinstance(min_obs, int) or min_obs < 1:
            raise ValidationError("temporal.min_observations must be a positive integer.")
        min_dur = temporal.get("min_duration_seconds", 300.0)
        if not isinstance(min_dur, (int, float)) or min_dur < 0:
            raise ValidationError("temporal.min_duration_seconds must be non-negative.")
        periodicity = temporal.get("periodicity_threshold", 0.7)
        if not isinstance(periodicity, (int, float)) or not 0.0 <= periodicity <= 1.0:
            raise ValidationError("temporal.periodicity_threshold must be between 0.0 and 1.0.")

    def _validate_endpoint_correlation_section(self, endpoint_corr: Any) -> None:
        if not isinstance(endpoint_corr, dict):
            raise ValidationError("endpoint_correlation section must be a dictionary.")
        if not isinstance(endpoint_corr.get("enabled", True), bool):
            raise ValidationError("endpoint_correlation.enabled must be a boolean.")
        window = endpoint_corr.get("correlation_window_seconds", 30.0)
        if not isinstance(window, (int, float)) or window <= 0:
            raise ValidationError(
                "endpoint_correlation.correlation_window_seconds must be positive."
            )
        max_procs = endpoint_corr.get("max_processes", 10000)
        if not isinstance(max_procs, int) or max_procs <= 0:
            raise ValidationError("endpoint_correlation.max_processes must be a positive integer.")
        max_obs = endpoint_corr.get("max_observations", 1000)
        if not isinstance(max_obs, int) or max_obs <= 0:
            raise ValidationError(
                "endpoint_correlation.max_observations must be a positive integer."
            )

    def _validate_sysmon_section(self, sysmon: Any) -> None:
        allowed = {1, 3, 7, 8, 10, 11, 12, 13, 14, 22}
        if not isinstance(sysmon, dict) or not isinstance(sysmon.get("enabled", False), bool):
            raise ValidationError("sysmon.enabled must be a boolean.")
        if not is_non_empty_string(sysmon.get("channel", "")) or not is_non_empty_string(
            sysmon.get("bookmark_path", "")
        ):
            raise ValidationError("sysmon channel and bookmark_path must be non-empty strings.")
        if not isinstance(sysmon.get("batch_size", 100), int) or sysmon.get("batch_size", 100) <= 0:
            raise ValidationError("sysmon.batch_size must be a positive integer.")
        if (
            not isinstance(sysmon.get("polling_interval", 1.0), (int, float))
            or sysmon.get("polling_interval", 1.0) <= 0
        ):
            raise ValidationError("sysmon.polling_interval must be positive.")
        ids = sysmon.get("supported_event_ids", [])
        if (
            not isinstance(ids, list)
            or not ids
            or any(not isinstance(event_id, int) or event_id not in allowed for event_id in ids)
        ):
            raise ValidationError("sysmon.supported_event_ids contains unsupported IDs.")

    def _validate_windows_event_log_section(self, windows: Any) -> None:
        allowed = {4624, 4625, 4648, 4672, 4688, 4697, 4720, 4728, 4732, 4756, 1102}
        if not isinstance(windows, dict) or not isinstance(windows.get("enabled", False), bool):
            raise ValidationError("windows_event_log.enabled must be a boolean.")
        channels = windows.get("channels", [])
        channel_pattern = re.compile(r"^[A-Za-z0-9_./ -]+$")
        if (
            not isinstance(channels, list)
            or not channels
            or len(channels) != len(set(channels))
            or any(
                not is_non_empty_string(channel) or not channel_pattern.fullmatch(channel)
                for channel in channels
            )
        ):
            raise ValidationError("windows_event_log.channels must be unique non-empty strings.")
        if not is_non_empty_string(windows.get("bookmark_path", "")):
            raise ValidationError("windows_event_log.bookmark_path must be a non-empty string.")
        if (
            not isinstance(windows.get("batch_size", 100), int)
            or isinstance(windows.get("batch_size", 100), bool)
            or windows.get("batch_size", 100) <= 0
        ):
            raise ValidationError("windows_event_log.batch_size must be a positive integer.")
        interval = windows.get("polling_interval", 1.0)
        if (
            not isinstance(interval, (int, float))
            or isinstance(interval, bool)
            or not math.isfinite(interval)
            or interval <= 0
        ):
            raise ValidationError("windows_event_log.polling_interval must be positive.")
        ids = windows.get("event_ids", [])
        if (
            not isinstance(ids, list)
            or not ids
            or any(not isinstance(event_id, int) or event_id not in allowed for event_id in ids)
        ):
            raise ValidationError("windows_event_log.event_ids contains unsupported IDs.")

    def _validate_linux_audit_section(self, audit: Any) -> None:
        allowed = {
            "SYSCALL",
            "EXECVE",
            "USER_LOGIN",
            "USER_START",
            "USER_ACCT",
            "USER_CMD",
            "USER_ROLE_CHANGE",
            "USER_CHAUTHTOK",
            "CRED_ACQ",
            "CRED_REFR",
            "CRED_DISP",
            "USER_END",
        }
        if not isinstance(audit, dict) or not isinstance(audit.get("enabled", False), bool):
            raise ValidationError("linux_audit.enabled must be a boolean.")
        if not is_non_empty_string(audit.get("path", "")) or not is_non_empty_string(
            audit.get("bookmark_path", "")
        ):
            raise ValidationError("linux_audit path and bookmark_path must be non-empty strings.")
        if any(
            not isinstance(audit.get(key, default), int)
            or isinstance(audit.get(key, default), bool)
            or audit.get(key, default) <= 0
            for key, default in (("batch_size", 100), ("max_pending_groups", 1000))
        ):
            raise ValidationError(
                "linux_audit batch_size and max_pending_groups must be positive integers."
            )
        if any(
            not isinstance(audit.get(key, default), (int, float))
            or isinstance(audit.get(key, default), bool)
            or not math.isfinite(audit.get(key, default))
            or audit.get(key, default) <= 0
            for key, default in (("polling_interval", 1.0), ("grouping_timeout", 1.0))
        ):
            raise ValidationError("linux_audit intervals must be positive finite numbers.")
        types = audit.get("supported_record_types", [])
        if (
            not isinstance(types, list)
            or not types
            or any(not isinstance(value, str) or value not in allowed for value in types)
        ):
            raise ValidationError("linux_audit.supported_record_types contains unsupported values.")

    def _validate_behavior_persistence_section(self, persistence: Any) -> None:
        if not isinstance(persistence, dict):
            raise ValidationError("behavior_persistence section must be a dictionary.")
        # Skip validation if persistence is disabled
        if not persistence.get("enabled", False):
            return
        db_path = persistence.get("db_path")
        if not is_non_empty_string(db_path):
            raise ValidationError("behavior_persistence.db_path must be a non-empty string.")
        save_interval = persistence.get("save_interval_seconds", 60.0)
        if not isinstance(save_interval, (int, float)) or save_interval < 0:
            raise ValidationError(
                "behavior_persistence.save_interval_seconds must be non-negative."
            )
        max_profiles = persistence.get("max_profiles", 100000)
        if not isinstance(max_profiles, int) or max_profiles <= 0:
            raise ValidationError("behavior_persistence.max_profiles must be a positive integer.")

    def _validate_analyst_annotations_section(self, annotations: Any) -> None:
        if not isinstance(annotations, dict):
            raise ValidationError("analyst_annotations section must be a dictionary.")
        # Skip validation if annotations are disabled
        if not annotations.get("enabled", False):
            return
        db_path = annotations.get("db_path")
        if not is_non_empty_string(db_path):
            raise ValidationError("analyst_annotations.db_path must be a non-empty string.")
        max_per_target = annotations.get("max_annotations_per_target", 50)
        if not isinstance(max_per_target, int) or max_per_target <= 0:
            raise ValidationError(
                "analyst_annotations.max_annotations_per_target must be a positive integer."
            )
        max_total = annotations.get("max_total_annotations", 10000)
        if not isinstance(max_total, int) or max_total <= 0:
            raise ValidationError(
                "analyst_annotations.max_total_annotations must be a positive integer."
            )

    def _validate_alert_persistence_section(self, persistence: Any) -> None:
        if not isinstance(persistence, dict):
            raise ValidationError("alert_persistence section must be a dictionary.")
        # Skip validation if persistence is disabled
        if not persistence.get("enabled", False):
            return
        db_path = persistence.get("db_path")
        if not is_non_empty_string(db_path):
            raise ValidationError("alert_persistence.db_path must be a non-empty string.")
        max_alerts = persistence.get("max_alerts", 10_000)
        if not isinstance(max_alerts, int) or max_alerts <= 0:
            raise ValidationError("alert_persistence.max_alerts must be a positive integer.")

    def _validate_attck_section(self, attck: Any) -> None:
        if not isinstance(attck, dict):
            raise ValidationError("attck section must be a dictionary.")
        if not isinstance(attck.get("enabled", False), bool):
            raise ValidationError("attck.enabled must be a boolean.")
        snapshot_path = attck.get("snapshot_path", "data/attck_snapshot.json")
        if not is_non_empty_string(snapshot_path):
            raise ValidationError("attck.snapshot_path must be a non-empty string.")
        previous_path = attck.get("previous_snapshot_path", "")
        if previous_path is not None and not isinstance(previous_path, str):
            raise ValidationError("attck.previous_snapshot_path must be a string.")

    def _validate_api_section(self, api: Any) -> None:
        if not isinstance(api, dict):
            raise ValidationError("api section must be a dictionary.")
        if not isinstance(api.get("enabled", False), bool):
            raise ValidationError("api.enabled must be a boolean.")
        host = api.get("host", "127.0.0.1")
        if not isinstance(host, str) or not host:
            raise ValidationError("api.host must be a non-empty string.")
        port = api.get("port", 8080)
        if not isinstance(port, int) or isinstance(port, bool) or port <= 0 or port > 65535:
            raise ValidationError("api.port must be a positive integer in range 1-65535.")
        max_limit = api.get("max_alert_limit", 100)
        if not isinstance(max_limit, int) or isinstance(max_limit, bool) or max_limit <= 0:
            raise ValidationError("api.max_alert_limit must be a positive integer.")
        cors = api.get("cors_origins", [])
        if not isinstance(cors, list):
            raise ValidationError("api.cors_origins must be a list.")
        for origin in cors:
            if not isinstance(origin, str) or not origin:
                raise ValidationError("api.cors_origins must contain non-empty strings.")

    def _validate_event_count_correlation_section(self, event_count_corr: Any) -> None:
        if not isinstance(event_count_corr, dict):
            raise ValidationError("event_count_correlation section must be a dictionary.")
        if not isinstance(event_count_corr.get("enabled", True), bool):
            raise ValidationError("event_count_correlation.enabled must be a boolean.")
        max_keys = event_count_corr.get("max_keys", 10000)
        if not isinstance(max_keys, int) or max_keys <= 0:
            raise ValidationError("event_count_correlation.max_keys must be a positive integer.")
        max_obs = event_count_corr.get("max_observations_per_key", 1000)
        if not isinstance(max_obs, int) or max_obs <= 0:
            raise ValidationError(
                "event_count_correlation.max_observations_per_key must be a positive integer."
            )
        count = event_count_corr.get("default_count", 5)
        if not isinstance(count, int) or count <= 0:
            raise ValidationError(
                "event_count_correlation.default_count must be a positive integer."
            )
        timespan = event_count_corr.get("default_timespan_seconds", 300.0)
        if not isinstance(timespan, (int, float)) or timespan <= 0:
            raise ValidationError(
                "event_count_correlation.default_timespan_seconds must be positive."
            )
        confidence = event_count_corr.get("default_confidence", 0.7)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            raise ValidationError(
                "event_count_correlation.default_confidence must be between 0.0 and 1.0."
            )
        group_by = event_count_corr.get("default_group_by", ["src_ip"])
        if not isinstance(group_by, list) or not group_by:
            raise ValidationError(
                "event_count_correlation.default_group_by must be a non-empty list."
            )
        valid_fields = {"src_ip", "dst_ip", "hostname", "username", "event_type"}
        for field in group_by:
            if field not in valid_fields:
                raise ValidationError(
                    f"event_count_correlation.default_group_by contains invalid field: {field}"
                )
