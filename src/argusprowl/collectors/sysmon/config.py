"""Validated configuration for the Sysmon collector."""

import math
import re
from dataclasses import dataclass
from pathlib import Path

from argusprowl.collectors.sysmon.parser import SUPPORTED_EVENT_IDS

_CHANNEL = re.compile(r"^[A-Za-z0-9_./ -]+$")


@dataclass(frozen=True, slots=True)
class SysmonCollectorConfig:
    channel: str = "Microsoft-Windows-Sysmon/Operational"
    bookmark_path: Path = Path("data/sysmon-bookmark.json")
    batch_size: int = 100
    polling_interval: float = 1.0
    supported_event_ids: tuple[int, ...] = tuple(sorted(SUPPORTED_EVENT_IDS))

    def validate(self) -> None:
        if (
            not isinstance(self.channel, str)
            or not self.channel.strip()
            or not _CHANNEL.fullmatch(self.channel)
        ):
            raise ValueError("channel contains unsupported characters")
        if not isinstance(self.bookmark_path, Path) or not str(self.bookmark_path):
            raise ValueError("bookmark_path must be provided")
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
        if not self.supported_event_ids or any(
            event_id not in SUPPORTED_EVENT_IDS for event_id in self.supported_event_ids
        ):
            raise ValueError("supported_event_ids must be supported positive Sysmon IDs")
