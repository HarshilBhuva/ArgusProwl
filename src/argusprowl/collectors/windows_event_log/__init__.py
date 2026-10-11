"""Standard Windows Event Log collection with native and replay sources."""

from argusprowl.collectors.windows_event_log.bookmark import WindowsEventBookmarkStore
from argusprowl.collectors.windows_event_log.collector import WindowsEventCollector
from argusprowl.collectors.windows_event_log.config import WindowsEventCollectorConfig
from argusprowl.collectors.windows_event_log.events import (
    ReplayWindowsEventSource,
    WindowsEventRawRecord,
    WindowsEventSource,
)
from argusprowl.collectors.windows_event_log.parser import WindowsEventParser
from argusprowl.collectors.windows_event_log.source import WindowsNativeEventSource

__all__ = [
    "ReplayWindowsEventSource",
    "WindowsEventBookmarkStore",
    "WindowsEventCollector",
    "WindowsEventCollectorConfig",
    "WindowsEventParser",
    "WindowsEventRawRecord",
    "WindowsEventSource",
    "WindowsNativeEventSource",
]
