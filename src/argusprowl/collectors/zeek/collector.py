"""Zeek Collector Implementation."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.collectors.zeek.config import ZeekCollectorConfig
from argusprowl.collectors.zeek.offset import ZeekOffsetStore
from argusprowl.collectors.zeek.parser import ZeekConnLogParser
from argusprowl.collectors.zeek.tailer import ZeekTailReader
from argusprowl.exceptions.exceptions import ParserError


class ZeekCollector(BaseCollector):
    """Collector for Zeek connection logs."""

    @property
    def name(self) -> str:
        return "zeek_conn_collector"

    def _do_initialize(self, config_dict: dict[str, Any]) -> None:
        """Initialize collector components."""
        self._zeek_config = ZeekCollectorConfig(
            log_path=Path(config_dict["log_path"]),
            offset_file=Path(config_dict["offset_file"]),
            poll_interval_sec=config_dict.get("poll_interval_sec", 0.1),
            batch_size=config_dict.get("batch_size", 1000),
        )
        self._zeek_config.validate()

        self._parser = ZeekConnLogParser()
        self._offset_store = ZeekOffsetStore(self._zeek_config.offset_file)
        self._tailer = ZeekTailReader(
            log_path=self._zeek_config.log_path,
            offset_store=self._offset_store,
            poll_interval=self._zeek_config.poll_interval_sec,
        )

    def _do_start(self) -> None:
        """Start the tailer."""
        self._tailer.start()

    def _do_stop(self) -> None:
        """Stop tailing."""
        if hasattr(self, "_tailer"):
            self._tailer.stop()

    def _do_pause(self) -> None:
        """Pause collection."""
        self._tailer.pause()

    def _do_resume(self) -> None:
        """Resume collection."""
        self._tailer.resume()

    def _do_collect(self) -> Iterator[Any]:
        """Yield events parsed from the Zeek log."""
        for line in self._tailer.tail():
            if not line:
                continue

            try:
                event = self._parser.parse(line)
                if event:
                    self._metrics.record_event_collected()
                    if self._event_queue is not None:
                        self._event_queue.put(event)
                    yield event
            except ParserError as exc:
                # Zeek headers are expected and the parser may use #fields to
                # update its schema; they are not operational parse failures.
                if line.lstrip().startswith("#"):
                    continue
                self._logger.warning("Malformed Zeek record: %s", exc)
                self._metrics.record_error()
            except Exception as exc:
                self._logger.error(f"Unexpected error processing log line: {exc}")
                self._metrics.record_error()
