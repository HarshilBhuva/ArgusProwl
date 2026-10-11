"""Lifecycle-managed Linux audit/auditd collector."""

import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.collectors.linux_audit.bookmark import LinuxAuditBookmarkStore
from argusprowl.collectors.linux_audit.config import (
    SUPPORTED_RECORD_TYPES,
    LinuxAuditCollectorConfig,
)
from argusprowl.collectors.linux_audit.events import (
    AuditRecordAssembler,
    LinuxAuditSource,
    LinuxAuditSourceError,
)
from argusprowl.collectors.linux_audit.parser import LinuxAuditParser
from argusprowl.collectors.linux_audit.source import AuditLogFileSource
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.metrics.metrics import Counter, Gauge


class LinuxAuditCollector(BaseCollector):
    def __init__(self, event_queue=None, *, source: LinuxAuditSource | None = None) -> None:
        super().__init__(event_queue)
        self._source = source

    @property
    def name(self) -> str:
        return "linux_audit_collector"

    def _do_initialize(self, config: dict[str, Any]) -> None:
        types = config.get("supported_record_types") or tuple(sorted(SUPPORTED_RECORD_TYPES))
        self._audit_config = LinuxAuditCollectorConfig(
            Path(config.get("path", "/var/log/audit/audit.log")),
            Path(config.get("bookmark_path", "data/linux-audit-bookmark.json")),
            config.get("batch_size", 100),
            config.get("polling_interval", 1.0),
            config.get("grouping_timeout", 1.0),
            config.get("max_pending_groups", 1000),
            tuple(types),
        )
        self._audit_config.validate()
        self._parser = LinuxAuditParser()
        self._bookmarks = LinuxAuditBookmarkStore(self._audit_config.bookmark_path)
        self._assembler = AuditRecordAssembler(
            self._audit_config.grouping_timeout, self._audit_config.max_pending_groups
        )
        config.get("reliability", {})

        self._source = self._source or AuditLogFileSource(self._audit_config.path)
        for name in (
            "events_received",
            "events_parsed",
            "parse_errors",
            "unknown_events",
            "retries",
            "reconnects",
            "rotations",
            "events_processed",
            "group_timeouts",
        ):
            setattr(self, f"linux_audit_{name}", Counter(f"linux_audit_{name}"))
        self.linux_audit_pending_groups = Gauge("linux_audit_pending_groups")
        self.linux_audit_lag = Gauge("linux_audit_lag_seconds")
        self._collecting = True
        self._paused = False
        self._last_event_time = self._last_successful_read = None

    def _do_start(self) -> None:
        self._source.open()
        self._collecting = True

    def _do_stop(self) -> None:
        self._collecting = False
        self._source.close()

    def _do_pause(self) -> None:
        self._paused = True

    def _do_resume(self) -> None:
        self._paused = False

    def _emit(self, group: tuple, timed_out: bool = False):
        try:
            event = self._parser.parse_group(group)
            if (
                event.attributes["audit_record_type"]
                not in self._audit_config.supported_record_types
            ):
                self.linux_audit_unknown_events.increment()
            self.linux_audit_events_parsed.increment()
            self.linux_audit_events_processed.increment()
            self._metrics.record_event_collected()
            self._last_event_time = event.timestamp
            self.linux_audit_lag.set(max(0.0, time.time() - event.timestamp.timestamp()))
            if self._event_queue is not None:
                self._event_queue.put(event)
            if timed_out:
                self.linux_audit_group_timeouts.increment()
            return event
        except ParserError as exc:
            self.linux_audit_parse_errors.increment()
            self._logger.warning("Malformed audit record: %s", exc)
            return None

    def _do_collect(self) -> Iterator[Any]:
        while self._collecting:
            if self._paused:
                time.sleep(self._audit_config.polling_interval)
                continue
            try:
                records = self._source.read(self._bookmarks.load(), self._audit_config.batch_size)
                self._last_successful_read = time.time()
            except LinuxAuditSourceError as exc:
                self.linux_audit_retries.increment()
                self._logger.warning("Linux audit source unavailable: %s", exc)
                time.sleep(self._audit_config.polling_interval)
                continue
            emitted = False
            for record in records:
                emitted = True
                self.linux_audit_events_received.increment()
                try:
                    record_type, serial = self._parser.inspect(record)
                except ParserError:
                    record_type, serial = None, None
                for group in self._assembler.add(serial, record_type, record, time.monotonic()):
                    event = self._emit(group)
                    if event is not None:
                        yield event
                if record.inode is not None and record.offset is not None:
                    self._bookmarks.save(record.inode, record.offset)
            for group in self._assembler.expire(time.monotonic()):
                event = self._emit(group, timed_out=True)
                if event is not None:
                    yield event
            self.linux_audit_pending_groups.set(self._assembler.pending_count)
            rotations = getattr(self._source, "rotations", 0)
            while self.linux_audit_rotations.get_value() < rotations:
                self.linux_audit_rotations.increment()
            if not emitted:
                time.sleep(self._audit_config.polling_interval)

    @property
    def bookmark(self) -> dict[str, int] | None:
        return self._bookmarks.load()

    def status(self) -> dict[str, object]:
        status = super().status()
        status["linux_audit"] = {
            "path": str(self._audit_config.path),
            "bookmark": self.bookmark,
            "pending_groups": self._assembler.pending_count,
            "last_event_time": self._last_event_time.isoformat() if self._last_event_time else None,
            "last_successful_read": self._last_successful_read,
        }
        return status
