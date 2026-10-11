"""Adapter for converting Zeek SSL telemetry into normalized events."""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address
from math import isfinite
from typing import Any

from argusprowl.constants.event_type import EventType
from argusprowl.constants.severity import Severity
from argusprowl.constants.source_type import SourceType
from argusprowl.models.normalized_event import NormalizedEvent


class ZeekTelemetryAdapter:
    """Convert raw Zeek ``ssl.log`` JSON records into normalized events."""

    @staticmethod
    def from_raw_ssl_record(record: dict[str, Any]) -> NormalizedEvent:
        """Normalize a Zeek SSL record while retaining TLS evidence provenance."""
        record = record if isinstance(record, dict) else {}
        event_ts = ZeekTelemetryAdapter._coerce_timestamp(record.get("ts"))

        zeek_uid = ZeekTelemetryAdapter._coerce_text(record.get("uid"))
        sensor_id = ZeekTelemetryAdapter._coerce_text(
            record.get("_sensor_id"), default="unknown-sensor"
        )
        ingest_timestamp = ZeekTelemetryAdapter._coerce_text(
            record.get("_ingest_timestamp"), default=datetime.now(UTC).isoformat()
        )
        metadata = {
            "zeek_uid": zeek_uid,
            "sensor_id": sensor_id,
            "ingest_timestamp": ingest_timestamp,
            "raw_source": "zeek.ssl",
            "provenance_chain": [
                f"sensor:{sensor_id}",
                "source:zeek.ssl",
                f"zeek_uid:{zeek_uid}",
            ],
        }
        additional_data = {
            "service": "TLS",
            "tls": {
                "version": record.get("version"),
                "cipher": record.get("cipher"),
                "server_name": record.get("server_name"),
                "established": ZeekTelemetryAdapter._coerce_bool(record.get("established")),
                "resumed": ZeekTelemetryAdapter._coerce_bool(record.get("resumed")),
                "cert_chain_fuids": ZeekTelemetryAdapter._coerce_list(
                    record.get("cert_chain_fuids")
                ),
                "subject": record.get("subject"),
                "issuer": record.get("issuer"),
            },
            "flow_stats": {
                "duration": ZeekTelemetryAdapter._coerce_float(record.get("duration")),
                "orig_bytes": ZeekTelemetryAdapter._coerce_int(record.get("orig_bytes")),
                "resp_bytes": ZeekTelemetryAdapter._coerce_int(record.get("resp_bytes")),
                "orig_pkts": ZeekTelemetryAdapter._coerce_int(record.get("orig_pkts")),
                "resp_pkts": ZeekTelemetryAdapter._coerce_int(record.get("resp_pkts")),
            },
        }

        return NormalizedEvent(
            source_type=SourceType.ZEEK,
            event_type=EventType.NETWORK_FLOW,
            severity=Severity.INFO,
            timestamp=event_ts,
            src_ip=ZeekTelemetryAdapter._coerce_ip(record.get("id_orig_h")),
            src_port=ZeekTelemetryAdapter._coerce_port(record.get("id_orig_p")),
            dst_ip=ZeekTelemetryAdapter._coerce_ip(record.get("id_resp_h")),
            dst_port=ZeekTelemetryAdapter._coerce_port(record.get("id_resp_p")),
            protocol="TCP",
            raw_event=record,
            metadata=metadata,
            attributes=additional_data,
            source_record_id=zeek_uid or None,
        )

    @staticmethod
    def _coerce_timestamp(value: Any) -> datetime:
        """Return a UTC timestamp, falling back to the current UTC time."""
        try:
            if isinstance(value, bool) or value is None:
                raise ValueError
            if isinstance(value, (int, float)):
                if not isfinite(value):
                    raise ValueError
                return datetime.fromtimestamp(value, tz=UTC)
            if isinstance(value, str):
                normalized = value.strip()
                if not normalized:
                    raise ValueError
                try:
                    return datetime.fromtimestamp(float(normalized), tz=UTC)
                except ValueError:
                    parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=UTC)
                    return parsed.astimezone(UTC)
        except (OSError, OverflowError, TypeError, ValueError):
            pass
        return datetime.now(UTC)

    @staticmethod
    def _coerce_ip(value: Any) -> str:
        """Return a valid IP address or the unspecified IPv4 address."""
        try:
            return str(ip_address(str(value).strip()))
        except (TypeError, ValueError):
            # Sentinel output for an invalid event field, not a socket bind.
            return "0.0.0.0"  # nosec B104

    @staticmethod
    def _coerce_port(value: Any) -> int:
        """Return a valid transport port, otherwise zero."""
        port = ZeekTelemetryAdapter._coerce_int(value)
        return port if 0 <= port <= 65535 else 0

    @staticmethod
    def _coerce_int(value: Any) -> int:
        """Coerce a value to an integer, using zero when conversion fails."""
        try:
            if isinstance(value, bool) or value is None:
                return 0
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return 0

    @staticmethod
    def _coerce_float(value: Any) -> float:
        """Coerce a value to a finite float, using zero when conversion fails."""
        try:
            if isinstance(value, bool) or value is None:
                return 0.0
            result = float(value)
            return result if isfinite(result) else 0.0
        except (TypeError, ValueError, OverflowError):
            return 0.0

    @staticmethod
    def _coerce_text(value: Any, default: str = "") -> str:
        """Coerce a non-empty scalar value to text, otherwise use a default."""
        if value is None:
            return default
        result = str(value).strip()
        return result or default

    @staticmethod
    def _coerce_bool(value: Any) -> bool | None:
        """Coerce common Zeek boolean representations while preserving unknowns."""
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"t", "true", "1", "yes"}:
                return True
            if normalized in {"f", "false", "0", "no"}:
                return False
        return None

    @staticmethod
    def _coerce_list(value: Any) -> list[Any]:
        """Return a list representation without treating strings as iterables."""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        return [value]
