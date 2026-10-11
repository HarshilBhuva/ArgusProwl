"""Lifecycle-managed Suricata EVE JSON collector."""

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.collectors.suricata.bookmark import SuricataBookmarkStore
from argusprowl.collectors.suricata.config import (
    SUPPORTED_EVENT_TYPES,
    SuricataCollectorConfig,
)
from argusprowl.collectors.suricata.events import (
    SuricataEventSource,
    SuricataSourceError,
)
from argusprowl.collectors.suricata.parser import SuricataParser
from argusprowl.collectors.suricata.source import EveFileSource
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.metrics.metrics import Counter, Gauge


class SuricataCollector(BaseCollector):
    """Collects Suricata EVE JSON records from file tailing or replay sources."""

    def __init__(self, event_queue=None, *, source: SuricataEventSource | None = None) -> None:
        super().__init__(event_queue)
        self._source = source

    @property
    def name(self) -> str:
        return "suricata_collector"

    def _do_initialize(self, config: dict[str, Any]) -> None:
        types = config.get("supported_event_types") or tuple(sorted(SUPPORTED_EVENT_TYPES))
        self._suricata_config = SuricataCollectorConfig(
            eve_path=Path(
                config.get("eve_path") or config.get("path") or "/var/log/suricata/eve.json"
            ),
            bookmark_path=Path(config.get("bookmark_path", "data/suricata-bookmark.json")),
            batch_size=config.get("batch_size", 100),
            polling_interval=config.get("polling_interval", 1.0),
            max_record_size=config.get("max_record_size", 10 * 1024 * 1024),
            supported_event_types=tuple(types),
        )
        self._suricata_config.validate()
        self._parser = SuricataParser()
        self._bookmarks = SuricataBookmarkStore(self._suricata_config.bookmark_path)

        self._source = self._source or EveFileSource(
            self._suricata_config.eve_path, self._suricata_config.max_record_size
        )

        # Standard metrics
        for name in (
            "events_received",
            "events_parsed",
            "parse_errors",
            "unknown_events",
            "retries",
            "reconnects",
            "rotations",
            "events_processed",
            "events_dropped",
        ):
            setattr(self, f"suricata_{name}", Counter(f"suricata_{name}"))

        # Event type specific metrics
        for event_type in ("alert", "flow", "dns", "http", "tls", "ssh", "fileinfo"):
            setattr(self, f"suricata_{event_type}_events", Counter(f"suricata_{event_type}_events"))

        self.suricata_lag = Gauge("suricata_lag_seconds")

        self._collecting = True
        self._paused = False
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
                time.sleep(self._suricata_config.polling_interval)
                continue

            try:
                records = self._source.read(
                    self._bookmarks.load(), self._suricata_config.batch_size
                )
                self._last_successful_read = time.time()
            except SuricataSourceError as exc:
                self.suricata_retries.increment()
                self._logger.warning("Suricata source unavailable: %s", exc)
                time.sleep(self._suricata_config.polling_interval)
                continue

            emitted = False
            for record in records:
                emitted = True
                self.suricata_events_received.increment()
                try:
                    event = self._parser.parse(record)
                    raw_type = event.attributes.get("suricata_event_type")

                    if raw_type not in self._suricata_config.supported_event_types:
                        self.suricata_unknown_events.increment()

                    # Increment event type specific counter if present
                    type_counter = getattr(self, f"suricata_{raw_type}_events", None)
                    if type_counter:
                        type_counter.increment()

                    self.suricata_events_parsed.increment()
                    self.suricata_events_processed.increment()
                    self._metrics.record_event_collected()

                    self._last_event_time = event.timestamp
                    self.suricata_lag.set(max(0.0, time.time() - event.timestamp.timestamp()))

                    if self._event_queue is not None:
                        self._event_queue.put(event)

                    if record.inode is not None and record.offset is not None:
                        self._bookmarks.save(record.inode, record.offset)

                    yield event
                except ParserError as exc:
                    self.suricata_parse_errors.increment()
                    self._logger.warning("Malformed Suricata record: %s", exc)
                    if record.inode is not None and record.offset is not None:
                        self._bookmarks.save(record.inode, record.offset)
                    self._metrics.record_error()

            rotations = getattr(self._source, "rotations", 0)
            while self.suricata_rotations.get_value() < rotations:
                self.suricata_rotations.increment()

            if not emitted:
                time.sleep(self._suricata_config.polling_interval)

    @property
    def bookmark(self) -> dict[str, int] | None:
        return self._bookmarks.load()

    def status(self) -> dict[str, object]:
        status = super().status()
        status["suricata"] = {
            "eve_path": str(self._suricata_config.eve_path),
            "bookmark": self.bookmark,
            "last_event_time": self._last_event_time.isoformat() if self._last_event_time else None,
            "last_successful_read": self._last_successful_read,
        }
        return status
