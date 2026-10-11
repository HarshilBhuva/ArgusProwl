"""Custom log formatters.

Includes:
- ColoredConsoleFormatter: Terminal output with ANSI level highlighting.
- JsonFormatter: Structured JSON log records for SIEM/centralized log analysis.
"""

import json
import logging
from datetime import UTC, datetime
from typing import Any, ClassVar

from argusprowl.utils.json_helpers import make_serializable


class ColoredConsoleFormatter(logging.Formatter):
    """Console formatter adding ANSI color codes based on log level."""

    RESET: str = "\033[0m"
    COLORS: ClassVar[dict[int, str]] = {
        logging.DEBUG: "\033[36m",  # Cyan
        logging.INFO: "\033[32m",  # Green
        logging.WARNING: "\033[33m",  # Yellow
        logging.ERROR: "\033[31m",  # Red
        logging.CRITICAL: "\033[35;1m",  # Magenta Bold
    }

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with level colors.

        Args:
            record: The LogRecord instance to format.

        Returns:
            Colored log string.
        """
        color = self.COLORS.get(record.levelno, self.RESET)
        record_copy = logging.makeLogRecord(record.__dict__)
        record_copy.levelname = f"{color}{record_copy.levelname:<8}{self.RESET}"
        return super().format(record_copy)


class JsonFormatter(logging.Formatter):
    """Structured JSON formatter outputting single-line JSON records."""

    def format(self, record: logging.LogRecord) -> str:
        """Format record into a JSON string.

        Args:
            record: The LogRecord instance.

        Returns:
            Single line JSON string.
        """
        created_dt = datetime.fromtimestamp(record.created, tz=UTC)

        log_obj: dict[str, Any] = {
            "timestamp": created_dt.isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "process": record.process,
            "thread": record.threadName,
        }

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        # Include extra attributes attached to the LogRecord
        standard_attrs = set(logging.makeLogRecord({}).__dict__.keys())
        standard_attrs.add("message")
        standard_attrs.add("asctime")

        extra: dict[str, Any] = {}
        for key, val in record.__dict__.items():
            if key not in standard_attrs:
                extra[key] = make_serializable(val)

        if extra:
            log_obj["extra"] = extra

        return json.dumps(log_obj, ensure_ascii=False)
