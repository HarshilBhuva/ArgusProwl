"""Safe, side-effect-free parser for standard Windows Event Log XML."""

from datetime import UTC, datetime
from xml.etree.ElementTree import Element

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from argusprowl.collectors.windows_event_log.events import WindowsEventRawRecord
from argusprowl.constants.event_type import EventType
from argusprowl.constants.source_type import SourceType
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.interfaces.parser import Parser
from argusprowl.models.normalized_event import NormalizedEvent

EVENT_TYPES = {
    4624: EventType.AUTHENTICATION_SUCCESS,
    4625: EventType.AUTHENTICATION_FAILURE,
    4648: EventType.EXPLICIT_CREDENTIAL_LOGON,
    4672: EventType.PRIVILEGE_ASSIGNMENT,
    4688: EventType.PROCESS_CREATE,
    4697: EventType.SERVICE_INSTALL,
    4720: EventType.ACCOUNT_CREATE,
    4728: EventType.GROUP_MEMBERSHIP_CHANGE,
    4732: EventType.GROUP_MEMBERSHIP_CHANGE,
    4756: EventType.GROUP_MEMBERSHIP_CHANGE,
    1102: EventType.AUDIT_LOG_CLEARED,
}
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class WindowsEventParser(Parser):
    """Maps namespaced Event/System/EventData XML to NormalizedEvent."""

    def can_parse(self, raw_data: str) -> bool:
        return isinstance(raw_data, str) and raw_data.lstrip().startswith("<Event")

    def parse(self, raw_data: str | WindowsEventRawRecord) -> NormalizedEvent:
        record = (
            raw_data
            if isinstance(raw_data, WindowsEventRawRecord)
            else WindowsEventRawRecord(raw_data, "Security")
        )
        try:
            root = ElementTree.fromstring(record.xml)
        except (ElementTree.ParseError, DefusedXmlException) as exc:
            raise ParserError("Malformed Windows Event Log XML") from exc
        system = root.find(f"{_NS}System")
        if system is None:
            raise ParserError("Windows Event XML has no System element")
        event_id = self._integer(self._text(system.find(f"{_NS}EventID")))
        if event_id is None:
            raise ParserError("Windows Event XML has invalid EventID")
        fields = {
            node.get("Name", ""): self._text(node) or ""
            for node in root.findall(f"{_NS}EventData/{_NS}Data")
        }
        channel = self._text(system.find(f"{_NS}Channel")) or record.channel
        provider = (
            system.find(f"{_NS}Provider").get("Name")
            if system.find(f"{_NS}Provider") is not None
            else None
        )
        record_id = (
            self._integer(self._text(system.find(f"{_NS}EventRecordID"))) or record.record_id
        )
        source_record_id = str(record_id) if record_id is not None else None
        try:
            return NormalizedEvent(
                source_type=SourceType.WINDOWS_EVENT_LOG,
                event_type=EVENT_TYPES.get(event_id, "windows_unknown"),
                timestamp=self._timestamp(system.find(f"{_NS}TimeCreated")),
                hostname=self._empty(self._text(system.find(f"{_NS}Computer"))),
                username=self._extract_username(event_id, fields),
                process_name=self._empty(
                    fields.get("NewProcessName") or fields.get("ProcessName") or fields.get("Image")
                ),
                command_line=self._empty(fields.get("CommandLine")),
                src_ip=self._ip(fields.get("IpAddress") or fields.get("SourceAddress")),
                src_port=self._port(fields.get("IpPort") or fields.get("SourcePort")),
                dst_ip=self._ip(fields.get("DestinationAddress") or fields.get("DestAddress")),
                dst_port=self._port(fields.get("DestinationPort") or fields.get("DestPort")),
                raw_event=record.xml,
                metadata={
                    **record.metadata,
                    "channel": channel,
                    "provider": provider,
                    "collector": record.collector,
                },
                attributes={**fields, "windows_event_id": event_id, "event_record_id": record_id},
                source_record_id=source_record_id,
            )
        except ValueError as exc:
            raise ParserError("Invalid Windows Event Log field", {"event_id": event_id}) from exc

    @classmethod
    def _extract_username(cls, event_id: int, fields: dict[str, str]) -> str | None:
        if event_id in {4624, 4625, 4648, 4720, 4728, 4732, 4756}:
            return cls._empty(
                fields.get("TargetUserName") or fields.get("SubjectUserName") or fields.get("User")
            )
        return cls._empty(
            fields.get("SubjectUserName") or fields.get("TargetUserName") or fields.get("User")
        )

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
        return None if value in {None, "-", "::", "0.0.0.0"} else value  # nosec B104

    @staticmethod
    def _port(value: str | None) -> int | None:
        return int(value) if value and value not in {"-", "0"} else None

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
            raise ParserError("Windows Event XML has invalid timestamp") from exc
