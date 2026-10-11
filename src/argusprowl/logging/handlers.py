"""Log handler factories.

Creates console and rotating file logging handlers with specified formatters.
"""

import logging
from logging import StreamHandler
from logging.handlers import RotatingFileHandler
from pathlib import Path

from argusprowl.constants.defaults import DEFAULT_LOG_FORMAT
from argusprowl.logging.formatters import ColoredConsoleFormatter, JsonFormatter
from argusprowl.utils.path_helpers import ensure_directory


def create_console_handler(
    level: str = "INFO",
    use_colors: bool = True,
    fmt: str = DEFAULT_LOG_FORMAT,
) -> StreamHandler:
    """Create a stream handler for stdout.

    Args:
        level: Minimum log level string.
        use_colors: Whether to apply ANSI color codes.
        fmt: Log line format string.

    Returns:
        Configured StreamHandler.
    """
    handler = StreamHandler()
    handler.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = ColoredConsoleFormatter(fmt=fmt) if use_colors else logging.Formatter(fmt=fmt)
    handler.setFormatter(formatter)
    return handler


def create_file_handler(
    filepath: str | Path,
    level: str = "INFO",
    max_bytes: int = 10485760,
    backup_count: int = 5,
    is_json: bool = False,
    fmt: str = DEFAULT_LOG_FORMAT,
) -> RotatingFileHandler:
    """Create a rotating file handler.

    Args:
        filepath: Target log file path.
        level: Minimum log level.
        max_bytes: Max file size before rotation.
        backup_count: Number of rotated backups to keep.
        is_json: Whether to use JsonFormatter.
        fmt: Standard text format string (ignored if is_json is True).

    Returns:
        Configured RotatingFileHandler.
    """
    path = Path(filepath)
    ensure_directory(path.parent)

    handler = RotatingFileHandler(
        filename=path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setLevel(getattr(logging, level.upper(), logging.INFO))

    if is_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(fmt=fmt))

    return handler
