"""Windows-only Sysmon Event Log acquisition via the native wevtutil tool."""

import os
import subprocess
from collections.abc import Iterable

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from argusprowl.collectors.sysmon.events import (
    StaleBookmarkError,
    SysmonEventSource,
    SysmonRawRecord,
    SysmonSourceError,
)

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class WindowsEventLogSource(SysmonEventSource):
    """Reads real Windows Event Log XML; unavailable platforms fail explicitly.

    ``wevtutil`` is a Windows-supplied native adapter. Arguments are passed as
    a list (never through a shell) and the validated channel is supplied by
    ``SysmonCollectorConfig``.
    """

    def __init__(self, channel: str) -> None:
        self._channel = channel
        self._open = False

    def open(self) -> None:
        if os.name != "nt":
            raise SysmonSourceError("Windows Event Log acquisition requires Windows")
        self._open = True

    def close(self) -> None:
        self._open = False

    def read(self, after_record_id: int | None, limit: int) -> Iterable[SysmonRawRecord]:
        if not self._open:
            raise SysmonSourceError("Windows Event Log source is not open")
        query = (
            "*" if after_record_id is None else f"*[System[(EventRecordID > {after_record_id})]]"
        )
        try:
            completed = subprocess.run(
                [
                    "wevtutil",
                    "qe",
                    self._channel,
                    f"/q:{query}",
                    "/f:xml",
                    "/rd:false",
                    f"/c:{limit}",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SysmonSourceError("Windows Event Log query failed") from exc
        if completed.returncode:
            if after_record_id is not None:
                raise StaleBookmarkError("Windows Event Log bookmark is stale or unavailable")
            raise SysmonSourceError("Windows Event Log query failed")
        try:
            root = ElementTree.fromstring(completed.stdout)
        except (ElementTree.ParseError, DefusedXmlException) as exc:
            raise SysmonSourceError("Windows Event Log returned malformed XML") from exc
        records = []
        for event in root.findall(f"{_NS}Event"):
            record_text = event.findtext(f"{_NS}System/{_NS}EventRecordID")
            record_id = int(record_text) if record_text and record_text.isdigit() else None
            records.append(
                SysmonRawRecord(
                    xml=ElementTree.tostring(event, encoding="unicode"), record_id=record_id
                )
            )
        return tuple(records)
