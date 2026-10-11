"""Side-effect-free parser and normalizer for auditd text records."""

import re
import shlex
from datetime import UTC, datetime

from argusprowl.collectors.linux_audit.events import LinuxAuditRawRecord
from argusprowl.constants.event_type import EventType
from argusprowl.constants.source_type import SourceType
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.interfaces.parser import Parser
from argusprowl.models.normalized_event import NormalizedEvent

EVENT_TYPES = {
    "SYSCALL": EventType.PROCESS_EXECUTION,
    "EXECVE": EventType.PROCESS_EXECUTION,
    "USER_LOGIN": EventType.AUTHENTICATION,
    "USER_START": EventType.SESSION_START,
    "USER_END": EventType.SESSION_END,
    "USER_ACCT": EventType.ACCOUNT_ACTIVITY,
    "USER_CMD": EventType.COMMAND_ACTIVITY,
    "USER_ROLE_CHANGE": EventType.ROLE_CHANGE,
    "USER_CHAUTHTOK": EventType.CREDENTIAL_CHANGE,
    "CRED_ACQ": EventType.CREDENTIAL_ACQUISITION,
    "CRED_REFR": EventType.CREDENTIAL_REFRESH,
    "CRED_DISP": EventType.CREDENTIAL_DISPOSAL,
}
_MESSAGE = re.compile(r"msg=audit\((?P<seconds>\d+(?:\.\d+)?):(?P<serial>\d+)\):")


class LinuxAuditParser(Parser):
    def can_parse(self, raw_data: str) -> bool:
        return isinstance(raw_data, str) and raw_data.lstrip().startswith("type=")

    def inspect(self, record: LinuxAuditRawRecord) -> tuple[str | None, str | None]:
        fields = self._fields(record.line)
        return fields.get("type"), self._serial(record.line)

    def parse(self, raw_data: str | LinuxAuditRawRecord) -> NormalizedEvent:
        record = (
            raw_data if isinstance(raw_data, LinuxAuditRawRecord) else LinuxAuditRawRecord(raw_data)
        )
        return self.parse_group((record,))

    def parse_group(self, records: tuple[LinuxAuditRawRecord, ...]) -> NormalizedEvent:
        if not records:
            raise ParserError("Linux audit record group is empty")
        parsed = [self._fields(record.line) for record in records]
        if not parsed[0].get("type"):
            raise ParserError("Linux audit record has no type")
        fields: dict[str, str] = {}
        arguments: dict[int, str] = {}
        types: list[str] = []
        serial = None
        for record, item in zip(records, parsed, strict=True):
            record_type = item.pop("type", None)
            if record_type:
                types.append(record_type)
            serial = serial or self._serial(record.line)
            for key, value in item.items():
                if key.startswith("a") and key[1:].isdigit() and record_type == "EXECVE":
                    arguments[int(key[1:])] = value
                elif key not in fields or not fields[key]:
                    fields[key] = value
        primary = next((value for value in types if value in EVENT_TYPES), types[0])
        command_line = " ".join(arguments[index] for index in sorted(arguments)) or fields.get(
            "cmd"
        )
        source_record_id = str(serial) if serial is not None else None
        event_type = self._resolve_event_type(primary, types, fields)
        raw_payload = records[0].line if len(records) == 1 else [r.line for r in records]

        try:
            return NormalizedEvent(
                source_type=SourceType.LINUX_AUDIT,
                event_type=event_type,
                timestamp=self._timestamp(records[0].line, records[0].collected_at),
                hostname=self._empty(fields.get("hostname") or fields.get("node")),
                username=self._extract_username(fields),
                process_name=self._empty(fields.get("exe") or fields.get("comm")),
                command_line=self._empty(command_line),
                src_ip=self._ip(fields.get("addr") or fields.get("saddr")),
                src_port=self._port(fields.get("port") or fields.get("sport")),
                dst_ip=self._ip(fields.get("dst") or fields.get("daddr")),
                dst_port=self._port(fields.get("dport")),
                raw_event=raw_payload,
                metadata={
                    "collector": records[0].source,
                    "audit_serial": serial,
                    **records[0].metadata,
                },
                attributes={
                    **fields,
                    "audit_record_type": primary,
                    "audit_record_types": tuple(types),
                    "audit_serial": serial,
                    "execve_arguments": {str(key): value for key, value in arguments.items()},
                    "audit_key": fields.get("key"),
                },
                source_record_id=source_record_id,
            )
        except ValueError as exc:
            raise ParserError("Invalid Linux audit field", {"record_type": primary}) from exc

    _EXEC_SYSCALLS = frozenset({"execve", "execveat", "59", "322", "11"})

    @classmethod
    def _resolve_event_type(cls, primary: str, types: list[str], fields: dict[str, str]) -> str:
        if primary == "USER_LOGIN":
            res = (fields.get("res") or fields.get("result") or "").lower()
            if res in {"success", "1"}:
                return EventType.AUTHENTICATION_SUCCESS
            if res in {"failed", "failure", "0"}:
                return EventType.AUTHENTICATION_FAILURE
            return EventType.AUTHENTICATION
        if "EXECVE" in types:
            return EventType.PROCESS_EXECUTION
        if primary == "SYSCALL":
            syscall_val = (fields.get("syscall") or "").lower().strip()
            if syscall_val in cls._EXEC_SYSCALLS:
                return EventType.PROCESS_EXECUTION
            return "linux_audit_unknown"
        return EVENT_TYPES.get(primary, "linux_audit_unknown")

    @classmethod
    def _extract_username(cls, fields: dict[str, str]) -> str | None:
        return cls._empty(fields.get("acct") or fields.get("user"))

    @staticmethod
    def _fields(line: str) -> dict[str, str]:
        if not isinstance(line, str) or not line.strip():
            raise ParserError("Linux audit record is empty")
        try:
            tokens = shlex.split(line, posix=True)
        except ValueError as exc:
            raise ParserError("Malformed Linux audit record") from exc
        fields: dict[str, str] = {}
        for token in tokens:
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value
        return fields

    @staticmethod
    def _serial(line: str) -> str | None:
        match = _MESSAGE.search(line)
        return match.group("serial") if match else None

    @staticmethod
    def _timestamp(line: str, fallback: datetime) -> datetime:
        match = _MESSAGE.search(line)
        if not match:
            return fallback.astimezone(UTC)
        return datetime.fromtimestamp(float(match.group("seconds")), tz=UTC)

    @staticmethod
    def _empty(value: str | None) -> str | None:
        return value if value and value not in {"-", "?", "(null)"} else None

    @classmethod
    def _ip(cls, value: str | None) -> str | None:
        value = cls._empty(value)
        return None if value in {None, "localhost", "none"} else value

    @staticmethod
    def _port(value: str | None) -> int | None:
        if not value or value in {"-", "?", "0"}:
            return None
        try:
            val = int(value)
            return val if 0 <= val <= 65535 else None
        except ValueError:
            return None
