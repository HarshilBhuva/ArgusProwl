"""Factory for building and registering configured collectors.

Bridges the gap between :class:`~argusprowl.models.configuration.AppConfiguration`
and the concrete collector implementations.  Each source type (zeek, suricata,
sysmon, windows_event_log, linux_audit) maps to a specific collector class
and a config-dict builder that extracts the right keys from the corresponding
configuration dataclass section.
"""

import logging
import queue
from dataclasses import asdict, fields, is_dataclass
from typing import Any

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.collectors.linux_audit.collector import LinuxAuditCollector
from argusprowl.collectors.registry import CollectorRegistry
from argusprowl.collectors.suricata.collector import SuricataCollector
from argusprowl.collectors.sysmon.collector import SysmonCollector
from argusprowl.collectors.windows_event_log.collector import WindowsEventCollector
from argusprowl.collectors.zeek.collector import ZeekCollector
from argusprowl.models.configuration import AppConfiguration

logger = logging.getLogger(__name__)

# Sentinel used to detect "section absent" vs "field explicitly False" when
# loading config from YAML (where only explicitly-present keys are in the dict).
_ABSENT: Any = object()


def _section_dict(config: AppConfiguration, section: str) -> dict[str, Any]:
    """Return the raw attribute dict for a config section.

    Falls back to dataclass-field defaults for fields not explicitly present
    (which happens when the section is loaded from a partial YAML dict).
    """
    section_obj = getattr(config, section, None)
    if section_obj is None:
        return {}
    if is_dataclass(section_obj):
        return asdict(section_obj)
    # Already a plain dict (loaded from YAML).
    result: dict[str, Any] = dict(section_obj)
    # Backfill missing keys with the dataclass defaults so collector-side
    # defaults are always consistent.
    cls = type(section_obj)
    default_section = _default_section(cls, section)
    for name, default in default_section.items():
        result.setdefault(name, default)
    return result


def _default_section(cls: type, section: str) -> dict[str, Any]:
    """Build a defaults dict for *section* by instantiating the dataclass."""
    if is_dataclass(cls):
        return asdict(cls())
    # Fallback: derive from the first matching AppConfiguration field.
    app_default = AppConfiguration()
    obj = getattr(app_default, section, None)
    return asdict(obj) if is_dataclass(obj) else {}


def _get(section: dict[str, Any], key: str, default: Any = _ABSENT) -> Any:
    """Get a value from a section dict, returning *default* if absent.

    If *default* is the sentinel ``_ABSENT`` the call will raise
    ``KeyError`` when the key is missing — mirroring ``dict.get``'s
    ``default=None`` behaviour but making absence explicit.
    """
    if key in section:
        return section[key]
    if default is _ABSENT:
        raise KeyError(key)
    return default


def _section_present(config: AppConfiguration, section: str) -> bool:
    """Return True if *section* is explicitly present in the config.

    Handles both dataclass (always present) and partial-YAML-dict cases.
    For dataclass sections we check the *enabled* flag instead.
    """
    section_obj = getattr(config, section, None)
    if section_obj is None:
        return False
    if is_dataclass(section_obj):
        # Dataclass sections are always "present"; the enabled flag decides.
        return _section_dict(config, section).get("enabled", False)
    # Plain dict loaded from YAML — present iff the key was in the raw config.
    return bool(section_obj)


def build_zeek_config_dict(config: AppConfiguration) -> dict[str, Any]:
    """Build the ZeekCollector config dict from AppConfiguration.

    The Zeek collector expects keys: ``log_path``, ``offset_file``,
    ``poll_interval_sec``, ``batch_size``.
    """
    section = _section_dict(config, "zeek")
    return {
        "log_path": section.get("log_path", config.ingestion.zeek_log_path),
        "offset_file": section.get("offset_file", "data/zeek-offsets.json"),
        "poll_interval_sec": section.get("poll_interval_sec", config.ingestion.poll_interval),
        "batch_size": section.get("batch_size", config.ingestion.batch_size),
    }


def build_suricata_config_dict(config: AppConfiguration) -> dict[str, Any]:
    """Build the SuricataCollector config dict from AppConfiguration."""
    section = _section_dict(config, "suricata")
    return {
        "eve_path": section.get("eve_path", "/var/log/suricata/eve.json"),
        "bookmark_path": section.get("bookmark_path", "data/suricata-bookmark.json"),
        "batch_size": section.get("batch_size", 100),
        "polling_interval": section.get("polling_interval", 1.0),
    }


def build_sysmon_config_dict(config: AppConfiguration) -> dict[str, Any]:
    """Build the SysmonCollector config dict from AppConfiguration."""
    section = _section_dict(config, "sysmon")
    supported_event_ids = section.get("supported_event_ids")
    return {
        "channel": section.get("channel", "Microsoft-Windows-Sysmon/Operational"),
        "bookmark_path": section.get("bookmark_path", "data/sysmon-bookmark.json"),
        "batch_size": section.get("batch_size", 100),
        "polling_interval": section.get("polling_interval", 1.0),
        "supported_event_ids": tuple(supported_event_ids) if supported_event_ids else None,
    }


def build_windows_event_log_config_dict(config: AppConfiguration) -> dict[str, Any]:
    """Build the WindowsEventCollector config dict from AppConfiguration."""
    section = _section_dict(config, "windows_event_log")
    return {
        "channels": tuple(section.get("channels", ("Security",))),
        "bookmark_path": section.get("bookmark_path", "data/windows-event-bookmarks.json"),
        "batch_size": section.get("batch_size", 100),
        "polling_interval": section.get("polling_interval", 1.0),
        "event_ids": tuple(section.get("event_ids", ())),
    }


def build_linux_audit_config_dict(config: AppConfiguration) -> dict[str, Any]:
    """Build the LinuxAuditCollector config dict from AppConfiguration."""
    section = _section_dict(config, "linux_audit")
    supported_record_types = section.get("supported_record_types")
    return {
        "path": section.get("path", "/var/log/audit/audit.log"),
        "bookmark_path": section.get("bookmark_path", "data/linux-audit-bookmark.json"),
        "batch_size": section.get("batch_size", 100),
        "polling_interval": section.get("polling_interval", 1.0),
        "grouping_timeout": section.get("grouping_timeout", 1.0),
        "max_pending_groups": section.get("max_pending_groups", 1000),
        "supported_record_types": tuple(supported_record_types) if supported_record_types else None,
    }


# Mapping of source-type name -> (builder function, collector class,
#                                      enabled-flag-section-name).
_COLLECTOR_SOURCES: dict[str, tuple] = {
    "zeek": (build_zeek_config_dict, ZeekCollector, "zeek"),
    "suricata": (build_suricata_config_dict, SuricataCollector, "suricata"),
    "sysmon": (build_sysmon_config_dict, SysmonCollector, "sysmon"),
    "windows_event_log": (
        build_windows_event_log_config_dict,
        WindowsEventCollector,
        "windows_event_log",
    ),
    "linux_audit": (
        build_linux_audit_config_dict,
        LinuxAuditCollector,
        "linux_audit",
    ),
}


def is_source_enabled(config: AppConfiguration, source: str) -> bool:
    """Return True if *source* is enabled in *config*.

    For sections that are dataclasses the ``enabled`` attribute is authoritative.
    For sections loaded as plain dicts (partial YAML) presence of the key
    implies enabled=True (matching YAML semantics where the user explicitly
    listed the section).
    """
    builder, _cls, flag_section = _COLLECTOR_SOURCES[source]
    section_obj = getattr(config, flag_section, None)
    if section_obj is None:
        return False
    if is_dataclass(section_obj):
        return bool(getattr(section_obj, "enabled", False))
    # Plain dict: presence of "enabled" key wins; otherwise key presence implies enabled.
    if "enabled" in section_obj:
        return bool(section_obj["enabled"])
    return True


def build_collectors(
    config: AppConfiguration,
    event_queue: queue.Queue | None,
    registry: CollectorRegistry,
) -> list[tuple[str, BaseCollector]]:
    """Instantiate and register configured collectors.

    For each of the 5 source types (zeek, suricata, sysmon, windows_event_log,
    linux_audit) that are enabled in *config*, build the collector-specific
    config dict, instantiate the collector, initialize it, and register it in
    *registry*.

    A failure in one collector's initialization is logged and does not prevent
    the remaining collectors from being created.  Collectors that fail
    initialization are **not** registered (they are not usable).

    Args:
        config: The loaded application configuration.
        event_queue: The shared event queue that collectors will publish to.
        registry: The collector registry that successfully initialized
            collectors will be registered into.

    Returns:
        A list of ``(source_name, collector)`` tuples for every collector
        that was successfully created and registered.
    """
    created: list[tuple[str, BaseCollector]] = []

    for source_name, (builder, collector_cls, flag_section) in _COLLECTOR_SOURCES.items():
        if not is_source_enabled(config, source_name):
            logger.debug("Collector source '%s' is disabled; skipping", source_name)
            continue

        config_dict = builder(config)
        collector = collector_cls(event_queue=event_queue)

        try:
            collector.initialize(config_dict)
        except Exception as exc:
            logger.error(
                "Failed to initialize collector '%s' (source=%s): %s",
                collector.name,
                source_name,
                exc,
                exc_info=True,
            )
            continue

        try:
            registry.register(collector)
        except Exception as exc:
            logger.error(
                "Failed to register collector '%s' in registry: %s",
                collector.name,
                exc,
                exc_info=True,
            )
            continue

        logger.info("Collector '%s' (source=%s) registered successfully", source_name, source_name)
        created.append((source_name, collector))

    return created
