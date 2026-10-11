"""Configuration loader.

Loads configuration from YAML files, overlays environment variable overrides,
and merges with default values.
"""

import os
from pathlib import Path
from typing import Any

import yaml

from argusprowl.constants.defaults import (
    DEFAULT_APP_NAME,
    DEFAULT_LOG_BACKUP_COUNT,
    DEFAULT_LOG_LEVEL,
    DEFAULT_LOG_MAX_BYTES,
)
from argusprowl.constants.paths import ProjectPath
from argusprowl.exceptions.exceptions import ConfigurationError


class ConfigLoader:
    """Loads and merges configuration from multiple sources.

    Precedence order (highest to lowest):
    1. Environment variables (prefixed with TH_)
    2. Explicitly loaded YAML configuration file
    3. Default configuration dictionary
    """

    ENV_PREFIX: str = "TH_"

    def get_default_config(self) -> dict[str, Any]:
        """Return the default configuration dictionary.

        Returns:
            A dictionary containing baseline configuration settings.
        """
        return {
            "app_name": DEFAULT_APP_NAME,
            "debug": False,
            "environment": "production",
            "logging": {
                "level": DEFAULT_LOG_LEVEL,
                "console_enabled": True,
                "file_enabled": True,
                "json_enabled": False,
                "log_file": str(ProjectPath.DEFAULT_LOG_FILE),
                "json_log_file": str(ProjectPath.DEFAULT_JSON_LOG_FILE),
                "max_bytes": DEFAULT_LOG_MAX_BYTES,
                "backup_count": DEFAULT_LOG_BACKUP_COUNT,
                "colored_console": True,
            },
            "storage": {
                "backend": "sqlite",
                "base_path": str(ProjectPath.DATA_DIR),
                "database_path": str(ProjectPath.DATA_DIR / "argusprowl.db"),
            },
            "events": {
                "queue_size": 1000,
                "async_dispatch": False,
                "worker_count": 1,
                "shutdown_timeout_seconds": 5.0,
            },
            "ingestion": {
                "zeek_log_path": "data/conn.log",
                "poll_interval": 0.5,
                "batch_size": 100,
            },
            "reliability": {
                "buffer": {"max_size": 1000, "overflow_policy": "drop_newest"},
                "retry": {
                    "max_attempts": 3,
                    "initial_delay": 0.1,
                    "max_delay": 5.0,
                    "jitter": False,
                },
                "deduplication": {
                    "enabled": True,
                    "default_cooldown": 300.0,
                    "max_fingerprints": 10000,
                },
            },
            "sysmon": {
                "enabled": False,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "bookmark_path": "data/sysmon-bookmark.json",
                "batch_size": 100,
                "polling_interval": 1.0,
                "supported_event_ids": [1, 3, 7, 8, 10, 11, 12, 13, 14, 22],
            },
            "windows_event_log": {
                "enabled": False,
                "channels": ["Security"],
                "bookmark_path": "data/windows-event-bookmarks.json",
                "batch_size": 100,
                "polling_interval": 1.0,
                "event_ids": [4624, 4625, 4648, 4672, 4688, 4697, 4720, 4728, 4732, 4756, 1102],
            },
            "linux_audit": {
                "enabled": False,
                "path": "/var/log/audit/audit.log",
                "bookmark_path": "data/linux-audit-bookmark.json",
                "batch_size": 100,
                "polling_interval": 1.0,
                "grouping_timeout": 1.0,
                "max_pending_groups": 1000,
                "supported_record_types": [
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
                ],
            },
            "attck": {
                "enabled": False,
                "snapshot_path": "data/attck_snapshot.json",
                "previous_snapshot_path": "",
            },
            "api": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 8080,
                "cors_origins": [],
                "max_alert_limit": 100,
            },
        }

    def load_from_yaml(self, path: str | Path) -> dict[str, Any]:
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML file.

        Returns:
            The parsed configuration dictionary.

        Raises:
            ConfigurationError: If the file is missing, unreadable, or invalid YAML.
        """
        file_path = Path(path)
        if not file_path.exists():
            raise ConfigurationError(
                f"Configuration file not found: {file_path}",
                details={"path": str(file_path)},
            )

        try:
            with open(file_path, encoding="utf-8") as f:
                content = yaml.safe_load(f)
                if content is None:
                    return {}
                if not isinstance(content, dict):
                    raise ConfigurationError(
                        "YAML configuration root must be a mapping/dict.",
                        details={"path": str(file_path)},
                    )
                return content
        except yaml.YAMLError as exc:
            raise ConfigurationError(
                f"Failed to parse YAML configuration: {exc}",
                details={"path": str(file_path)},
            ) from exc
        except OSError as exc:
            raise ConfigurationError(
                f"Error reading configuration file: {exc}",
                details={"path": str(file_path)},
            ) from exc

    def load_env_overrides(self) -> dict[str, Any]:
        """Extract environment variables starting with ``TH_``.

        Supported mapping patterns:
        - ``TH_APP_NAME`` -> ``app_name``
        - ``TH_DEBUG`` -> ``debug`` (parsed as bool)
        - ``TH_ENVIRONMENT`` -> ``environment``
        - ``TH_LOGGING__LEVEL`` -> ``logging.level``
        - ``TH_LOGGING__CONSOLE_ENABLED`` -> ``logging.console_enabled`` (parsed as bool)

        Double underscores (``__``) denote nested dictionary keys.

        Returns:
            Dictionary of configuration overrides.
        """
        overrides: dict[str, Any] = {}
        prefix_len = len(self.ENV_PREFIX)

        for key, value in os.environ.items():
            if not key.startswith(self.ENV_PREFIX):
                continue

            raw_key = key[prefix_len:].lower()
            parts = raw_key.split("__")
            parsed_value = self._parse_env_value(value)

            curr = overrides
            for part in parts[:-1]:
                curr = curr.setdefault(part, {})
            curr[parts[-1]] = parsed_value

        return overrides

    def load_config(self, yaml_path: str | Path | None = None) -> dict[str, Any]:
        """Load and merge complete configuration dictionary.

        Args:
            yaml_path: Optional path to a YAML configuration file.

        Returns:
            Merged configuration dictionary.
        """
        config = self.get_default_config()

        if yaml_path is not None:
            file_config = self.load_from_yaml(yaml_path)
            config = self._deep_merge(config, file_config)

        env_config = self.load_env_overrides()
        config = self._deep_merge(config, env_config)

        return config

    def _parse_env_value(self, val: str) -> Any:
        """Helper to cast string environment variables to typed Python primitives."""
        val_lower = val.lower().strip()
        if val_lower == "true":
            return True
        if val_lower == "false":
            return False
        try:
            return int(val)
        except ValueError:
            pass
        try:
            return float(val)
        except ValueError:
            pass
        return val

    def _deep_merge(self, base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        """Recursively merge *override* dictionary into *base* dictionary."""
        result = base.copy()
        for key, val in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(val, dict):
                result[key] = self._deep_merge(result[key], val)
            else:
                result[key] = val
        return result
