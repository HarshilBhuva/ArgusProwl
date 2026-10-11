"""Default configuration values.

These serve as fallback values when no configuration file or
environment variable override is provided.
"""

DEFAULT_APP_NAME: str = "argusprowl"
DEFAULT_CONFIG_FILENAME: str = "default.yaml"

# Logging defaults
DEFAULT_LOG_LEVEL: str = "INFO"
DEFAULT_LOG_FORMAT: str = "%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s"
DEFAULT_LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10 MB
DEFAULT_LOG_BACKUP_COUNT: int = 5

# Event system defaults
DEFAULT_EVENT_QUEUE_SIZE: int = 1000
