"""Windows-native standard Event Log acquisition through ``wevtutil``."""

import os
import re
import subprocess
from collections.abc import Iterable

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from argusprowl.collectors.windows_event_log.events import (
    StaleWindowsBookmarkError,
    WindowsEventRawRecord,
    WindowsEventSource,
    WindowsEventSourceError,
)

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_CHANNEL = re.compile(r"^[A-Za-z0-9_./ -]+$")


class WindowsNativeEventSource(WindowsEventSource):
    """Real Windows adapter, unavailable by design on non-Windows platforms."""

    def __init__(self) -> None:
        self._open = False

    def open(self) -> None:
        if os.name != "nt":
            raise WindowsEventSourceError("Windows Event Log acquisition requires Windows")
        self._open = True

    def close(self) -> None:
        self._open = False

    def read(
        self, channel: str, after_record_id: int | None, limit: int
    ) -> Iterable[WindowsEventRawRecord]:
        if not self._open:
            raise WindowsEventSourceError("Windows Event Log source is not open")
        if not isinstance(channel, str) or not channel.strip() or not _CHANNEL.fullmatch(channel):
            raise WindowsEventSourceError("Windows Event Log channel is invalid")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise WindowsEventSourceError("Windows Event Log limit is invalid")
        if after_record_id is not None and (
            not isinstance(after_record_id, int)
            or isinstance(after_record_id, bool)
            or after_record_id < 0
        ):
            raise WindowsEventSourceError("Windows Event Log bookmark is invalid")
        if not isinstance(channel, str) or not channel.strip() or not _CHANNEL.fullmatch(channel):
            raise WindowsEventSourceError("Windows Event Log channel is invalid")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise WindowsEventSourceError("Windows Event Log limit is invalid")
        if after_record_id is not None and (
            not isinstance(after_record_id, int)
            or isinstance(after_record_id, bool)
            or after_record_id < 0
        ):
            raise WindowsEventSourceError("Windows Event Log bookmark is invalid")
        query = (
            "*" if after_record_id is None else f"*[System[(EventRecordID > {after_record_id})]]"
        )
        try:
            completed = subprocess.run(
                ["wevtutil", "qe", channel, f"/q:{query}", "/f:xml", "/rd:false", f"/c:{limit}"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WindowsEventSourceError("Windows Event Log query failed") from exc
        if completed.returncode:
            if after_record_id is not None:
                raise StaleWindowsBookmarkError(
                    "Windows Event Log bookmark is stale or unavailable"
                )
            raise WindowsEventSourceError(
                "Windows Event Log channel is unavailable or access is denied"
            )
        try:
            root = ElementTree.fromstring(completed.stdout)
        except (ElementTree.ParseError, DefusedXmlException) as exc:
            raise WindowsEventSourceError("Windows Event Log returned malformed XML") from exc
        output = []
        for event in root.findall(f"{_NS}Event"):
            text = event.findtext(f"{_NS}System/{_NS}EventRecordID")
            output.append(
                WindowsEventRawRecord(
                    ElementTree.tostring(event, encoding="unicode"),
                    channel,
                    int(text) if text and text.isdigit() else None,
                )
            )
        return tuple(output)
