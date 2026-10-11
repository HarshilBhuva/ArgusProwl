"""Zeek Collector Package."""

from argusprowl.collectors.zeek.collector import ZeekCollector
from argusprowl.collectors.zeek.config import ZeekCollectorConfig
from argusprowl.collectors.zeek.offset import ZeekOffsetStore
from argusprowl.collectors.zeek.tailer import ZeekFileWatcher, ZeekTailReader

__all__ = [
    "ZeekCollector",
    "ZeekCollectorConfig",
    "ZeekFileWatcher",
    "ZeekOffsetStore",
    "ZeekTailReader",
]
