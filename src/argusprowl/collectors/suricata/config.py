"""Validated settings for Suricata EVE JSON collection."""

import math
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_EVENT_TYPES = frozenset(
    {
        "alert",
        "flow",
        "dns",
        "http",
        "tls",
        "ssh",
        "fileinfo",
    }
)


@dataclass(frozen=True, slots=True)
class SuricataCollectorConfig:
    eve_path: Path = Path("/var/log/suricata/eve.json")
    bookmark_path: Path = Path("data/suricata-bookmark.json")
    batch_size: int = 100
    polling_interval: float = 1.0
    max_record_size: int = 10 * 1024 * 1024  # 10 MB default limit
    supported_event_types: tuple[str, ...] = tuple(sorted(SUPPORTED_EVENT_TYPES))

    def validate(self) -> None:
        if (
            not isinstance(self.eve_path, Path)
            or not str(self.eve_path)
            or not isinstance(self.bookmark_path, Path)
            or not str(self.bookmark_path)
        ):
            raise ValueError("eve_path and bookmark_path must be non-empty Path objects")
        if (
            not isinstance(self.batch_size, int)
            or isinstance(self.batch_size, bool)
            or self.batch_size <= 0
        ):
            raise ValueError("batch_size must be a positive integer")
        if (
            not isinstance(self.polling_interval, (int, float))
            or isinstance(self.polling_interval, bool)
            or not math.isfinite(self.polling_interval)
            or self.polling_interval <= 0
        ):
            raise ValueError("polling_interval must be positive")
        if (
            not isinstance(self.max_record_size, int)
            or isinstance(self.max_record_size, bool)
            or self.max_record_size <= 0
        ):
            raise ValueError("max_record_size must be a positive integer")
        if not self.supported_event_types or any(
            value not in SUPPORTED_EVENT_TYPES for value in self.supported_event_types
        ):
            raise ValueError("supported_event_types contains unsupported event types")
