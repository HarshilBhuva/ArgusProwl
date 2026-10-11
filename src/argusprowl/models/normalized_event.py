"""Canonical, source-neutral telemetry model for future collectors."""

import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from uuid import UUID, uuid4

from argusprowl.constants.severity import Severity


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """A stable envelope for telemetry independent of a vendor log schema.

    Source-specific data belongs in ``attributes``; ``metadata`` is reserved for
    platform processing context. The envelope is immutable, while callers must
    treat the supplied mapping values as immutable after construction.
    """

    source_type: str
    event_type: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    hostname: str | None = None
    sensor: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    username: str | None = None
    process_name: str | None = None
    pid: int | None = None
    command_line: str | None = None
    severity: Severity = Severity.INFO
    raw_event: str | list[str] | dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)
    event_id: UUID = field(default_factory=uuid4)
    schema_version: int = 1
    source_record_id: str | None = None

    def __post_init__(self) -> None:
        if not self.source_type.strip() or not self.event_type.strip():
            raise ValueError("NormalizedEvent source_type and event_type must not be empty.")
        if self.schema_version < 1:
            raise ValueError("NormalizedEvent schema_version must be positive.")
        if not isinstance(self.event_id, UUID):
            raise ValueError("NormalizedEvent event_id must be a UUID.")
        if self.source_record_id is not None and not isinstance(self.source_record_id, str):
            raise ValueError("NormalizedEvent source_record_id must be a string if provided.")
        if self.timestamp.tzinfo is None:
            raise ValueError("NormalizedEvent timestamp must be timezone-aware.")
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(UTC))
        for value, label in ((self.src_ip, "src_ip"), (self.dst_ip, "dst_ip")):
            if value is not None:
                try:
                    ip_address(value)
                except ValueError as exc:
                    raise ValueError(
                        f"NormalizedEvent {label} must be a valid IP address."
                    ) from exc
        for value, label in ((self.src_port, "src_port"), (self.dst_port, "dst_port")):
            if value is not None and (not isinstance(value, int) or not 0 <= value <= 65535):
                raise ValueError(f"NormalizedEvent {label} must be between 0 and 65535.")

    def to_dict(self) -> dict[str, Any]:
        """Serialize explicitly so adapters do not need dataclass knowledge."""
        return {
            "schema_version": self.schema_version,
            "event_id": str(self.event_id),
            "source_type": self.source_type,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "hostname": self.hostname,
            "sensor": self.sensor,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "username": self.username,
            "process_name": self.process_name,
            "pid": self.pid,
            "command_line": self.command_line,
            "severity": self.severity.value,
            "raw_event": copy.deepcopy(self.raw_event),
            "metadata": copy.deepcopy(self.metadata),
            "tags": list(self.tags),
            "attributes": copy.deepcopy(self.attributes),
            "source_record_id": self.source_record_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NormalizedEvent":
        """Deserialize a persisted envelope, rejecting malformed identities."""
        value = dict(data)
        value["event_id"] = UUID(str(value["event_id"]))
        value["timestamp"] = datetime.fromisoformat(str(value["timestamp"]))
        value["severity"] = Severity(value.get("severity", Severity.INFO))
        value["tags"] = tuple(value.get("tags", ()))
        # source_record_id defaults to None if missing, which is handled by dataclass default or dict.get
        if "source_record_id" not in value:
            value["source_record_id"] = None
        return cls(**value)
