"""Deterministic parser for exported Sysmon Windows Event XML."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from xml.etree.ElementTree import Element

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from argusprowl.collectors.sysmon.events import SysmonRawRecord
from argusprowl.constants.event_type import EventType
from argusprowl.constants.source_type import SourceType
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.interfaces.parser import Parser
from argusprowl.models.normalized_event import NormalizedEvent

EVENT_TYPES = {
    1: EventType.PROCESS_CREATE,
    3: EventType.NETWORK_CONNECTION,
    7: EventType.IMAGE_LOAD,
    8: EventType.REMOTE_THREAD,
    10: EventType.PROCESS_ACCESS,
    11: EventType.FILE_CREATE,
    12: EventType.REGISTRY_CREATE,
    13: EventType.REGISTRY_SET,
    14: EventType.REGISTRY_RENAME,
    22: EventType.DNS_QUERY,
}
SUPPORTED_EVENT_IDS = frozenset(EVENT_TYPES)
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class SysmonParser(Parser):
    """Maps Sysmon's System/EventData XML to source-neutral NormalizedEvent."""

    def can_parse(self, raw_data: str) -> bool:
        return isinstance(raw_data, str) and raw_data.lstrip().startswith("<Event")

    def parse(self, raw_data: str | SysmonRawRecord) -> NormalizedEvent:
        record = raw_data if isinstance(raw_data, SysmonRawRecord) else SysmonRawRecord(raw_data)
        try:
            root = ElementTree.fromstring(record.xml)
        except (ElementTree.ParseError, DefusedXmlException) as exc:
            raise ParserError("Malformed Sysmon XML") from exc
        system = root.find(f"{_NS}System")
        if system is None:
            raise ParserError("Sysmon XML has no System element")
        event_id_text = self._text(system.find(f"{_NS}EventID"))
        try:
            event_id = int(event_id_text)
        except (TypeError, ValueError) as exc:
            raise ParserError("Sysmon XML has invalid EventID") from exc
        raw_fields = {
            element.get("Name", ""): self._text(element) or ""
            for element in root.findall(f"{_NS}EventData/{_NS}Data")
        }
        hostname = self._text(system.find(f"{_NS}Computer"))
        timestamp = self._timestamp(system.find(f"{_NS}TimeCreated"))
        native_record_id = self._integer(self._text(system.find(f"{_NS}EventRecordID")))
        source_record_id = (
            str(native_record_id)
            if native_record_id is not None
            else (str(record.record_id) if record.record_id is not None else None)
        )
        attributes: dict[str, Any] = {**raw_fields, "sysmon_event_id": event_id}
        if native_record_id is not None or record.record_id is not None:
            attributes["event_record_id"] = (
                native_record_id if native_record_id is not None else record.record_id
            )
        if event_id == 1:
            attributes.pop("Image", None)
            attributes.pop("CommandLine", None)
            attributes.pop("User", None)
        elif event_id in {3, 22}:
            for key in ("SourceIp", "SourcePort", "DestinationIp", "DestinationPort", "Protocol"):
                attributes.pop(key, None)
        elif event_id in {7, 8, 10, 11, 12, 13, 14}:
            for key in (
                "Image",
                "User",
                "ProcessId",
                "ProcessGuid",
                "ParentImage",
                "ParentCommandLine",
            ):
                attributes.pop(key, None)
        try:
            return NormalizedEvent(
                source_type=SourceType.SYSMON,
                event_type=EVENT_TYPES.get(event_id, "sysmon_unknown"),
                timestamp=timestamp,
                hostname=self._empty(hostname),
                username=self._empty(raw_fields.get("User")),
                process_name=self._empty(raw_fields.get("Image")),
                command_line=self._empty(raw_fields.get("CommandLine")),
                src_ip=self._ip(raw_fields.get("SourceIp")),
                src_port=self._port(raw_fields.get("SourcePort")),
                dst_ip=self._ip(raw_fields.get("DestinationIp")),
                dst_port=self._port(raw_fields.get("DestinationPort")),
                protocol=self._empty(raw_fields.get("Protocol")),
                raw_event=record.xml,
                metadata={"collector": record.collector, "bookmark": record.bookmark},
                attributes=attributes,
                source_record_id=source_record_id,
            )
        except ValueError as exc:
            raise ParserError("Invalid Sysmon event field", {"event_id": event_id}) from exc

    @staticmethod
    def _text(element: Element | None) -> str | None:
        return element.text.strip() if element is not None and element.text else None

    @staticmethod
    def _empty(value: str | None) -> str | None:
        return value if value and value not in {"-", "<unknown>"} else None

    @classmethod
    def _ip(cls, value: str | None) -> str | None:
        value = cls._empty(value)
        # "0.0.0.0" is an event-field sentinel here, not a bind address.
        return None if value in {None, "::", "0.0.0.0", "-"} else value  # nosec B104

    @staticmethod
    def _port(value: str | None) -> int | None:
        if not value or value in {"-", "0"}:
            return None
        return int(value)

    @staticmethod
    def _integer(value: str | None) -> int | None:
        return int(value) if value and value.isdigit() else None

    @staticmethod
    def _timestamp(element: Element | None) -> datetime:
        value = element.get("SystemTime") if element is not None else None
        if not value:
            return datetime.now(UTC)
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
        except ValueError as exc:
            raise ParserError("Sysmon XML has invalid timestamp") from exc
