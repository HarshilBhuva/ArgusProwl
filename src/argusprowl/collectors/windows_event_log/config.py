"""Validated multi-channel Windows Event Log collector configuration."""

import math
import re
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_EVENT_IDS = frozenset({4624, 4625, 4648, 4672, 4688, 4697, 4720, 4728, 4732, 4756, 1102})
_CHANNEL = re.compile(r"^[A-Za-z0-9_./ -]+$")


@dataclass(frozen=True, slots=True)
class WindowsEventCollectorConfig:
    channels: tuple[str, ...] = ("Security",)
    bookmark_path: Path = Path("data/windows-event-bookmarks.json")
    batch_size: int = 100
    polling_interval: float = 1.0
    event_ids: tuple[int, ...] = tuple(sorted(SUPPORTED_EVENT_IDS))

    def validate(self) -> None:
        if (
            not self.channels
            or len(set(self.channels)) != len(self.channels)
            or any(
                not isinstance(channel, str)
                or not channel.strip()
                or not _CHANNEL.fullmatch(channel)
                for channel in self.channels
            )
        ):
            raise ValueError("channels must contain unique validated Windows channel names")
        if not isinstance(self.bookmark_path, Path) or not str(self.bookmark_path):
            raise ValueError("bookmark_path must be provided")
        if (
            not isinstance(self.batch_size, int)
            or isinstance(self.batch_size, bool)
            or self.batch_size <= 0
        ):
            raise ValueError("batch_size must be positive")
        if (
            not isinstance(self.polling_interval, (int, float))
            or isinstance(self.polling_interval, bool)
            or not math.isfinite(self.polling_interval)
            or self.polling_interval <= 0
        ):
            raise ValueError("polling_interval must be positive")
        if not self.event_ids or any(
            event_id not in SUPPORTED_EVENT_IDS for event_id in self.event_ids
        ):
            raise ValueError("event_ids contains unsupported values")
