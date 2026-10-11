"""Zeek Collector Configuration."""

import math
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ZeekCollectorConfig:
    """Configuration for Zeek Collector."""

    log_path: Path
    offset_file: Path
    poll_interval_sec: float = 0.1
    batch_size: int = 1000

    def validate(self) -> None:
        """Validate configuration values."""
        if not isinstance(self.log_path, Path) or not str(self.log_path):
            raise ValueError("log_path must be provided.")
        if not isinstance(self.offset_file, Path) or not str(self.offset_file):
            raise ValueError("offset_file must be provided.")
        if (
            not isinstance(self.poll_interval_sec, (int, float))
            or isinstance(self.poll_interval_sec, bool)
            or not math.isfinite(self.poll_interval_sec)
            or self.poll_interval_sec <= 0
        ):
            raise ValueError("poll_interval_sec must be greater than 0.")
        if (
            not isinstance(self.batch_size, int)
            or isinstance(self.batch_size, bool)
            or self.batch_size <= 0
        ):
            raise ValueError("batch_size must be greater than 0.")
