"""Collector framework public API.

Import from this package to access all collector framework types without
reaching into sub-modules directly.

Example::

    from argusprowl.collectors import (
        BaseCollector,
        CollectorFactory,
        CollectorManager,
        CollectorMetrics,
        CollectorMetricsSnapshot,
        CollectorRegistry,
        CollectorState,
    )
"""

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.collectors.factory import CollectorFactory
from argusprowl.collectors.linux_audit import LinuxAuditCollector
from argusprowl.collectors.manager import CollectorManager
from argusprowl.collectors.metrics import CollectorMetrics, CollectorMetricsSnapshot
from argusprowl.collectors.registry import CollectorRegistry
from argusprowl.collectors.state import CollectorState
from argusprowl.collectors.suricata import SuricataCollector
from argusprowl.collectors.sysmon import SysmonCollector
from argusprowl.collectors.windows_event_log import WindowsEventCollector

__all__ = [
    "BaseCollector",
    "CollectorFactory",
    "CollectorManager",
    "CollectorMetrics",
    "CollectorMetricsSnapshot",
    "CollectorRegistry",
    "CollectorState",
    "LinuxAuditCollector",
    "SuricataCollector",
    "SysmonCollector",
    "WindowsEventCollector",
]
