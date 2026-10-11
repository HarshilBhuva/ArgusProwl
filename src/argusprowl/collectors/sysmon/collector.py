"""Lifecycle-managed Sysmon collector using shared parsing and dead letters."""

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.collectors.sysmon.bookmark import SysmonBookmarkStore
from argusprowl.collectors.sysmon.config import SysmonCollectorConfig
from argusprowl.collectors.sysmon.events import (
    StaleBookmarkError,
    SysmonEventSource,
    SysmonSourceError,
)
from argusprowl.collectors.sysmon.parser import SysmonParser
from argusprowl.collectors.sysmon.source import WindowsEventLogSource
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.metrics.metrics import Counter, Gauge


class SysmonCollector(BaseCollector):
    """Collects Windows Sysmon telemetry, or explicit replay records in tests."""

    def __init__(self, event_queue=None, *, source: SysmonEventSource | None = None) -> None:
        super().__init__(event_queue)
        self._source = source

    @property
    def name(self) -> str:
        return "sysmon_collector"

    def _do_initialize(self, config: dict[str, Any]) -> None:
        self._sysmon_config = SysmonCollectorConfig(
            channel=config.get("channel", "Microsoft-Windows-Sysmon/Operational"),
            bookmark_path=Path(config.get("bookmark_path", "data/sysmon-bookmark.json")),
            batch_size=config.get("batch_size", 100),
            polling_interval=config.get("polling_interval", 1.0),
            supported_event_ids=tuple(config.get("supported_event_ids", tuple(range(1)))),
        )
        # Avoid coupling defaults to a mutable config mapping.
        if not config.get("supported_event_ids"):
            self._sysmon_config = SysmonCollectorConfig(
                self._sysmon_config.channel,
                self._sysmon_config.bookmark_path,
                self._sysmon_config.batch_size,
                self._sysmon_config.polling_interval,
            )
        self._sysmon_config.validate()
        self._parser = SysmonParser()
        self._bookmarks = SysmonBookmarkStore(self._sysmon_config.bookmark_path)
        self._source = self._source or WindowsEventLogSource(self._sysmon_config.channel)
        self.sysmon_events_received = Counter("sysmon_events_received")
        self.sysmon_events_parsed = Counter("sysmon_events_parsed")
        self.sysmon_parse_errors = Counter("sysmon_parse_errors")
        self.sysmon_retries = Counter("sysmon_retries")
        self.sysmon_reconnects = Counter("sysmon_reconnects")
        self.sysmon_events_processed = Counter("sysmon_events_processed")
        self.sysmon_unknown_event_ids = Counter("sysmon_unknown_event_ids")
        self.sysmon_lag = Gauge("sysmon_lag_seconds")
        self._paused = False
        self._collecting = False
        self._last_event_time = None
        self._last_successful_read = None

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
                time.sleep(self._sysmon_config.polling_interval)
                continue
            bookmark = self._bookmarks.load()
            try:
                records = self._source.read(bookmark, self._sysmon_config.batch_size)
                self._last_successful_read = time.time()
            except StaleBookmarkError:
                self._logger.warning("Sysmon bookmark stale; restarting from current retained log")
                self._bookmarks.clear()
                self.sysmon_reconnects.increment()
                continue
            except SysmonSourceError as exc:
                self.sysmon_retries.increment()
                self._logger.warning("Sysmon source temporarily unavailable: %s", exc)
                time.sleep(self._sysmon_config.polling_interval)
                continue
            emitted = False
            for record in records:
                emitted = True
                self.sysmon_events_received.increment()
                try:
                    event = self._parser.parse(record)
                    event_id = event.attributes["sysmon_event_id"]
                    if event_id not in self._sysmon_config.supported_event_ids:
                        self.sysmon_unknown_event_ids.increment()
                    self.sysmon_events_parsed.increment()
                    self.sysmon_events_processed.increment()
                    self._metrics.record_event_collected()
                    self._last_event_time = event.timestamp
                    self.sysmon_lag.set(max(0.0, time.time() - event.timestamp.timestamp()))
                    if self._event_queue is not None:
                        self._event_queue.put(event)
                    if record.record_id is not None:
                        self._bookmarks.save(record.record_id)
                    yield event
                except ParserError as exc:
                    self.sysmon_parse_errors.increment()
                    self._logger.warning("Malformed Sysmon record: %s", exc)
                    # Advancing the checkpoint prevents a single poison event from being
                    # re-read forever after restart.
                    if record.record_id is not None:
                        self._bookmarks.save(record.record_id)
                    self._metrics.record_error()
            if not emitted:
                time.sleep(self._sysmon_config.polling_interval)

    @property
    def bookmark(self) -> int | None:
        return self._bookmarks.load()

    def status(self) -> dict[str, object]:
        status = super().status()
        status["sysmon"] = {
            "bookmark": self.bookmark,
            "last_event_time": self._last_event_time.isoformat() if self._last_event_time else None,
            "last_successful_read": self._last_successful_read,
        }
        return status
