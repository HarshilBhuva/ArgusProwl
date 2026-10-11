"""One lifecycle-managed collector for configurable standard Windows channels."""

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.collectors.windows_event_log.bookmark import WindowsEventBookmarkStore
from argusprowl.collectors.windows_event_log.config import (
    SUPPORTED_EVENT_IDS,
    WindowsEventCollectorConfig,
)
from argusprowl.collectors.windows_event_log.events import (
    StaleWindowsBookmarkError,
    WindowsEventSource,
    WindowsEventSourceError,
)
from argusprowl.collectors.windows_event_log.parser import WindowsEventParser
from argusprowl.collectors.windows_event_log.source import WindowsNativeEventSource
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.metrics.metrics import Counter, Gauge


class WindowsEventCollector(BaseCollector):
    """Incrementally collects Security/System/Application events when configured."""

    def __init__(self, event_queue=None, *, source: WindowsEventSource | None = None) -> None:
        super().__init__(event_queue)
        self._source = source

    @property
    def name(self) -> str:
        return "windows_event_log_collector"

    def _do_initialize(self, config: dict[str, Any]) -> None:
        ids = config.get("event_ids") or tuple(sorted(SUPPORTED_EVENT_IDS))
        self._windows_config = WindowsEventCollectorConfig(
            channels=tuple(config.get("channels") or ("Security",)),
            bookmark_path=Path(config.get("bookmark_path", "data/windows-event-bookmarks.json")),
            batch_size=config.get("batch_size", 100),
            polling_interval=config.get("polling_interval", 1.0),
            event_ids=tuple(ids),
        )
        self._windows_config.validate()
        self._parser, self._bookmarks = (
            WindowsEventParser(),
            WindowsEventBookmarkStore(self._windows_config.bookmark_path),
        )
        self._source = self._source or WindowsNativeEventSource()
        self.windows_events_received = Counter("windows_events_received")
        self.windows_events_parsed = Counter("windows_events_parsed")
        self.windows_parse_errors = Counter("windows_parse_errors")
        self.windows_unknown_events = Counter("windows_unknown_events")
        self.windows_retries = Counter("windows_retries")
        self.windows_reconnects = Counter("windows_reconnects")
        self.windows_events_processed = Counter("windows_events_processed")
        self.windows_lag = Gauge("windows_lag_seconds")
        self._paused, self._collecting = False, False
        self._last_event_time, self._last_successful_read = None, None

    def _do_start(self) -> None:
        assert self._source is not None
        self._source.open()
        self._collecting = True

    def _do_stop(self) -> None:
        self._collecting = False
        if self._source is not None:
            self._source.close()

    def _do_pause(self) -> None:
        self._paused = True

    def _do_resume(self) -> None:
        self._paused = False

    def _do_collect(self) -> Iterator[Any]:
        assert self._source is not None
        while self._collecting:
            if self._paused:
                time.sleep(self._windows_config.polling_interval)
                continue
            emitted = False
            for channel in self._windows_config.channels:
                try:
                    records = self._source.read(
                        channel, self._bookmarks.load(channel), self._windows_config.batch_size
                    )
                    self._last_successful_read = time.time()
                except StaleWindowsBookmarkError:
                    self._logger.warning(
                        "Windows Event Log bookmark stale for channel=%s; recovering", channel
                    )
                    self._bookmarks.clear(channel)
                    self.windows_reconnects.increment()
                    continue
                except WindowsEventSourceError as exc:
                    self.windows_retries.increment()
                    self._logger.warning(
                        "Windows Event Log source unavailable for channel=%s: %s", channel, exc
                    )
                    continue
                for record in records:
                    emitted = True
                    self.windows_events_received.increment()
                    try:
                        event = self._parser.parse(record)
                        if (
                            event.attributes["windows_event_id"]
                            not in self._windows_config.event_ids
                        ):
                            self.windows_unknown_events.increment()
                        self.windows_events_parsed.increment()
                        self.windows_events_processed.increment()
                        self._metrics.record_event_collected()
                        self._last_event_time = event.timestamp
                        self.windows_lag.set(max(0.0, time.time() - event.timestamp.timestamp()))
                        if self._event_queue is not None:
                            self._event_queue.put(event)
                        if record.record_id is not None:
                            self._bookmarks.save(channel, record.record_id)
                        yield event
                    except ParserError as exc:
                        self.windows_parse_errors.increment()
                        self._logger.warning("Malformed Windows Event record: %s", exc)
                        if record.record_id is not None:
                            self._bookmarks.save(channel, record.record_id)
                        self._metrics.record_error()
            if not emitted:
                time.sleep(self._windows_config.polling_interval)

    def bookmark(self, channel: str) -> int | None:
        return self._bookmarks.load(channel)

    def status(self) -> dict[str, object]:
        status = super().status()
        status["windows_event_log"] = {
            "channels": self._windows_config.channels,
            "bookmarks": {
                channel: self.bookmark(channel) for channel in self._windows_config.channels
            },
            "last_event_time": self._last_event_time.isoformat() if self._last_event_time else None,
            "last_successful_read": self._last_successful_read,
        }
        return status
