"""Central logger factory.

Manages setup and retrieval of application loggers.
"""

import logging
from typing import ClassVar

from argusprowl.constants.log_names import LogName
from argusprowl.logging.handlers import create_console_handler, create_file_handler
from argusprowl.models.configuration import LoggingConfig


class LoggerFactory:
    """Central factory for configuring and creating application loggers."""

    _initialized: ClassVar[bool] = False

    @classmethod
    def setup_logging(cls, config: LoggingConfig) -> None:
        """Configure the root 'argusprowl' logger based on LoggingConfig.

        Args:
            config: LoggingConfig settings dataclass.
        """
        root_logger = logging.getLogger(LogName.ROOT)
        root_logger.setLevel(getattr(logging, config.level.upper(), logging.INFO))

        # Clear existing handlers to allow re-configuration cleanly
        root_logger.handlers.clear()

        if config.console_enabled:
            console_handler = create_console_handler(
                level=config.level,
                use_colors=config.colored_console,
            )
            root_logger.addHandler(console_handler)

        if config.file_enabled:
            file_handler = create_file_handler(
                filepath=config.log_file,
                level=config.level,
                max_bytes=config.max_bytes,
                backup_count=config.backup_count,
                is_json=False,
            )
            root_logger.addHandler(file_handler)

        if config.json_enabled:
            json_handler = create_file_handler(
                filepath=config.json_log_file,
                level=config.level,
                max_bytes=config.max_bytes,
                backup_count=config.backup_count,
                is_json=True,
            )
            root_logger.addHandler(json_handler)

        cls._initialized = True

    @classmethod
    def get_logger(cls, name: str = LogName.ROOT) -> logging.Logger:
        """Get a named logger instance under the argusprowl hierarchy.

        Args:
            name: Logger name. If not prefixed with 'argusprowl',
                  it will be converted to a sub-logger.

        Returns:
            logging.Logger instance.
        """
        if not name.startswith(LogName.ROOT):
            name = f"{LogName.ROOT}.{name}"
        return logging.getLogger(name)

    @classmethod
    def is_initialized(cls) -> bool:
        """Return True if setup_logging has been called."""
        return cls._initialized

    @classmethod
    def reset(cls) -> None:
        """Reset root logger handlers and state (useful for tests)."""
        root_logger = logging.getLogger(LogName.ROOT)
        root_logger.handlers.clear()
        cls._initialized = False
