"""Replay reader for log files.

Reads Zeek log files for replay through the detection pipeline.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from argusprowl.collectors.zeek.parser import ZeekConnLogParser
from argusprowl.constants.log_names import LogName
from argusprowl.logging.logger_factory import LoggerFactory
from argusprowl.models.normalized_event import NormalizedEvent


class ReplayReader:
    """Reads Zeek log files for replay.

    Parses log files and yields NormalizedEvents for processing
    through the detection pipeline.

    Attributes:
        log_path: Path to the log file.
        parser: Log parser instance.
    """

    def __init__(self, log_path: str | Path) -> None:
        """Initialize replay reader.

        Args:
            log_path: Path to Zeek log file.

        Raises:
            FileNotFoundError: If log file doesn't exist.
        """
        self._log_path = Path(log_path)
        if not self._log_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")

        self._parser = ZeekConnLogParser()
        self._logger = LoggerFactory.get_logger(LogName.INGESTION)
        self._lines_processed = 0
        self._parse_errors = 0
        self._events_yielded = 0

    def read_events(self) -> Iterator[NormalizedEvent]:
        """Read and parse events from log file.

        Yields:
            NormalizedEvent instances parsed from log file.
        """
        self._lines_processed = 0
        self._parse_errors = 0
        self._events_yielded = 0

        with open(self._log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                self._lines_processed += 1
                try:
                    event = self._parser.parse(line)
                    if isinstance(event, NormalizedEvent):
                        self._events_yielded += 1
                        yield event
                except Exception as exc:
                    self._parse_errors += 1
                    self._logger.debug(f"Failed to parse line {self._lines_processed}: {exc}")

        self._logger.info(
            f"Replay complete: {self._lines_processed} lines processed, {self._parse_errors} errors"
        )

    def get_statistics(self) -> dict[str, Any]:
        """Get replay reader statistics.

        Returns:
            Dictionary with reader statistics.
        """
        return {
            "log_path": str(self._log_path),
            "file_exists": self._log_path.exists(),
            "file_size_bytes": self._log_path.stat().st_size if self._log_path.exists() else 0,
            "lines_processed": self._lines_processed,
            "parse_errors": self._parse_errors,
            "events_yielded": self._events_yielded,
        }

    def __repr__(self) -> str:
        """String representation."""
        return f"ReplayReader(log_path={self._log_path})"
