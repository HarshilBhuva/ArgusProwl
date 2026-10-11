"""Zeek conn.log parser implementation (canonical)."""

from datetime import UTC, datetime

from argusprowl.constants.event_type import EventType
from argusprowl.constants.source_type import SourceType
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.interfaces.parser import Parser
from argusprowl.models.normalized_event import NormalizedEvent

DEFAULT_ZEEK_CONN_FIELDS: list[str] = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
]


class ZeekConnLogParser(Parser):
    """Parser implementation for Zeek connection logs (conn.log).

    Converts tab-separated values into populated :class:`NormalizedEvent` objects.
    """

    def __init__(self, fields: list[str] | None = None) -> None:
        """Initialize ZeekConnLogParser.

        Args:
            fields: Custom list of column field names in order.
                Defaults to standard Zeek conn.log specification.
        """
        self._fields = fields or list(DEFAULT_ZEEK_CONN_FIELDS)

    def set_fields(self, fields: list[str]) -> None:
        """Update active column fields schema."""
        self._fields = fields

    def can_parse(self, raw_data: str) -> bool:
        """Check whether the given raw line appears to be a valid tab-separated Zeek record.

        Args:
            raw_data: Unparsed log line.

        Returns:
            True if line is non-empty, not a comment, and contains tabs.
        """
        line = raw_data.strip()
        if not line or line.startswith("#"):
            return False
        parts = line.split("\t")
        return len(parts) >= 5

    def parse(self, raw_data: str) -> NormalizedEvent:
        """Parse a raw Zeek conn.log TSV line into a NormalizedEvent object.

        Args:
            raw_data: Unparsed TSV log line.

        Returns:
            Populated :class:`NormalizedEvent`.

        Raises:
            ParserError: If parsing fails due to invalid format or unparseable fields.
        """
        line = raw_data.strip()
        if not line:
            raise ParserError("Cannot parse empty log line.")

        if line.startswith("#fields"):
            parts = line.split("\t")
            self._fields = parts[1:]
            raise ParserError("Line is a schema header (#fields). Updated parser schema.")

        if line.startswith("#"):
            raise ParserError(f"Line is a comment header: '{line[:20]}...'")

        parts = line.split("\t")
        if len(parts) < 6:
            raise ParserError(
                f"Insufficient columns in log record. Expected at least 6, got {len(parts)}.",
                details={"raw_data": raw_data},
            )

        # Map fields by column name
        record: dict[str, str] = {}
        for idx, field_name in enumerate(self._fields):
            if idx < len(parts):
                record[field_name] = parts[idx]

        try:
            # Timestamp
            ts_str = record.get("ts", "0")
            ts_val = self._parse_float(ts_str, default=0.0)
            event_ts = datetime.fromtimestamp(ts_val, tz=UTC) if ts_val > 0 else datetime.now(UTC)

            uid = record.get("uid", "-")
            src_ip = record.get("id.orig_h", "")
            src_port = self._parse_int(record.get("id.orig_p", "0"))
            dst_ip = record.get("id.resp_h", "")
            dst_port = self._parse_int(record.get("id.resp_p", "0"))

            proto = record.get("proto", "")
            service = record.get("service", "-")
            duration = self._parse_float(record.get("duration", "0"))
            orig_bytes = self._parse_int(record.get("orig_bytes", "0"))
            resp_bytes = self._parse_int(record.get("resp_bytes", "0"))
            conn_state = record.get("conn_state", "")
            history = record.get("history", "")
            orig_pkts = self._parse_int(record.get("orig_pkts", "0"))
            resp_pkgs = self._parse_int(record.get("resp_pkts", "0"))
            # Populate source_record_id from Zeek UID when present
            source_record_id = uid if uid and uid != "-" else None

            return NormalizedEvent(
                source_type=SourceType.ZEEK,
                event_type=EventType.NETWORK_CONNECTION,
                raw_event=line,
                timestamp=event_ts,
                src_ip=src_ip if src_ip and src_ip != "-" else None,
                src_port=src_port if src_port > 0 else None,
                dst_ip=dst_ip if dst_ip and dst_ip != "-" else None,
                dst_port=dst_port if dst_port > 0 else None,
                protocol=proto if proto and proto != "-" else None,
                source_record_id=source_record_id,
                attributes={
                    "uid": uid,
                    "service": service,
                    "duration": duration,
                    "orig_bytes": orig_bytes,
                    "resp_bytes": resp_bytes,
                    "conn_state": conn_state,
                    "history": history,
                    "orig_pkts": orig_pkts,
                    "resp_pkts": resp_pkgs,
                },
            )
        except (ValueError, TypeError) as exc:
            raise ParserError(
                f"Failed to parse Zeek record fields: {exc}",
                details={"raw_data": raw_data},
            ) from exc

    @staticmethod
    def _parse_int(val: str, default: int = 0) -> int:
        """Parse an integer, treating '-' as missing (returns default)."""
        if not val or val == "-":
            return default
        try:
            return int(val)
        except ValueError:
            return default

    @staticmethod
    def _parse_float(val: str, default: float = 0.0) -> float:
        """Parse a float, treating '-' as missing (returns default)."""
        if not val or val == "-":
            return default
        try:
            return float(val)
        except ValueError:
            return default
