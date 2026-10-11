"""Side-effect-free parser and normalizer for Suricata EVE JSON records."""

import json
from datetime import UTC, datetime
from typing import Any

from argusprowl.collectors.suricata.events import SuricataRawRecord
from argusprowl.constants.event_type import EventType
from argusprowl.constants.source_type import SourceType
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.interfaces.parser import Parser
from argusprowl.models.normalized_event import NormalizedEvent

# Map raw Suricata EVE event_type to canonical EventType constants.
EVENT_TYPES = {
    "alert": EventType.IDS_ALERT,
    "flow": EventType.NETWORK_FLOW,
    "dns": EventType.DNS_QUERY,
    "http": EventType.HTTP_TRANSACTION,
    "tls": EventType.TLS_CONNECTION,
    "ssh": EventType.SSH_ACTIVITY,
    "fileinfo": EventType.FILE_OBSERVATION,
}


class SuricataParser(Parser):
    """Parses Suricata EVE JSON records into canonical NormalizedEvent envelopes."""

    def __init__(self) -> None:
        self._handlers = {
            "alert": self._parse_alert,
            "flow": self._parse_flow,
            "dns": self._parse_dns,
            "http": self._parse_http,
            "tls": self._parse_tls,
            "ssh": self._parse_ssh,
            "fileinfo": self._parse_fileinfo,
        }

    def can_parse(self, raw_data: str) -> bool:
        """Check if raw_data appears to be valid EVE JSON with a timestamp or event_type."""
        if not isinstance(raw_data, str):
            return False
        cleaned = raw_data.strip()
        if not (cleaned.startswith("{") and cleaned.endswith("}")):
            return False
        try:
            data = json.loads(cleaned)
            return isinstance(data, dict) and ("event_type" in data or "timestamp" in data)
        except Exception:
            return False

    def parse(self, raw_data: str | SuricataRawRecord) -> NormalizedEvent:
        """Parse a raw JSON line or SuricataRawRecord into a NormalizedEvent."""
        if isinstance(raw_data, SuricataRawRecord):
            record = raw_data
            line = record.line
            fallback_ts = record.collected_at
            if record.metadata.get("oversized"):
                raise ParserError("Suricata EVE record exceeds maximum allowed size limit")
        else:
            record = None
            line = str(raw_data)
            fallback_ts = datetime.now(UTC)

        if not isinstance(line, str) or not line.strip():
            raise ParserError("Suricata EVE JSON record is empty")

        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ParserError(f"Malformed Suricata EVE JSON record: {exc}") from exc

        if not isinstance(data, dict):
            raise ParserError("Suricata EVE JSON payload must be a JSON object")

        raw_event_type = data.get("event_type")
        if not raw_event_type or not isinstance(raw_event_type, str):
            raw_event_type = "unknown"

        semantic_event_type = EVENT_TYPES.get(raw_event_type, "suricata_unknown")

        timestamp = self._parse_timestamp(data.get("timestamp"), fallback_ts)

        # Network fields
        src_ip = self._sanitize_ip(data.get("src_ip"))
        src_port = self._sanitize_port(data.get("src_port"))
        dst_ip = self._sanitize_ip(data.get("dest_ip") or data.get("dst_ip"))
        dst_port = self._sanitize_port(data.get("dest_port") or data.get("dst_port"))
        protocol = data.get("proto")
        if protocol and not isinstance(protocol, str):
            protocol = str(protocol)

        hostname = self._extract_hostname(data)

        # Common attributes
        attributes: dict[str, Any] = {
            "suricata_event_type": raw_event_type,
        }
        if "flow_id" in data:
            attributes["flow_id"] = data["flow_id"]
        if "community_id" in data:
            attributes["community_id"] = data["community_id"]
        elif isinstance(data.get("flow"), dict) and "community_id" in data["flow"]:
            attributes["community_id"] = data["flow"]["community_id"]
        if "in_iface" in data:
            attributes["in_iface"] = data["in_iface"]
        if "tx_id" in data:
            attributes["tx_id"] = data["tx_id"]

        # Dispatch to event-specific handler
        handler = self._handlers.get(raw_event_type, self._parse_unknown)
        handler(data, attributes)

        metadata: dict[str, Any] = {
            "collector": record.source if record else "suricata",
        }
        if record and record.metadata:
            metadata.update(record.metadata)

        # Determine source_record_id where semantics are appropriate.
        # - flow: use flow_id (the flow event IS the flow observation)
        # - http/dns/tls/ssh/fileinfo: prefer tx_id (transaction-level identity),
        #   else flow_id (flow-level fallback when transaction ID is absent)
        # - alert: None (Suricata alerts have no native record-level identifier;
        #   flow_id identifies the flow, not the specific alert observation)
        # - unknown: None (no reliable native identity)
        source_record_id: str | None = None
        if raw_event_type == "flow":
            flow_id = data.get("flow_id")
            if flow_id is not None:
                source_record_id = str(flow_id)
        elif raw_event_type in ("http", "dns", "tls", "ssh", "fileinfo"):
            tx_id = data.get("tx_id")
            flow_id = data.get("flow_id")
            if tx_id is not None:
                source_record_id = str(tx_id)
            elif flow_id is not None:
                source_record_id = str(flow_id)
        elif raw_event_type == "alert":
            # Suricata alerts lack a native record-level identifier.
            # flow_id identifies the flow, not the specific alert.
            # signature_id/gid identify the rule, not the observation.
            # Leave source_record_id as None to avoid collision semantics.
            pass

        try:
            return NormalizedEvent(
                source_type=SourceType.SURICATA,
                event_type=semantic_event_type,
                timestamp=timestamp,
                hostname=hostname,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                raw_event=line,
                metadata=metadata,
                attributes=attributes,
                source_record_id=source_record_id,
            )
        except ValueError as exc:
            raise ParserError(
                f"NormalizedEvent validation failed for Suricata event: {exc}"
            ) from exc

    def _parse_alert(self, data: dict[str, Any], attributes: dict[str, Any]) -> None:
        alert_data = data.get("alert")
        if isinstance(alert_data, dict):
            attributes["alert"] = {
                "action": alert_data.get("action"),
                "gid": alert_data.get("gid"),
                "signature_id": alert_data.get("signature_id"),
                "rev": alert_data.get("rev") or alert_data.get("signature_revision"),
                "signature": alert_data.get("signature"),
                "category": alert_data.get("category"),
                "severity": alert_data.get("severity"),
                "metadata": alert_data.get("metadata"),
                "references": alert_data.get("references"),
            }
            # Top-level convenient access
            attributes["signature"] = alert_data.get("signature")
            attributes["signature_id"] = alert_data.get("signature_id")
            attributes["category"] = alert_data.get("category")
            attributes["severity"] = alert_data.get("severity")
            attributes["action"] = alert_data.get("action")
            attributes["gid"] = alert_data.get("gid")
        if "app_proto" in data:
            attributes["app_proto"] = data["app_proto"]
        if "direction" in data:
            attributes["direction"] = data["direction"]

    def _parse_flow(self, data: dict[str, Any], attributes: dict[str, Any]) -> None:
        flow_data = data.get("flow")
        if isinstance(flow_data, dict):
            attributes["flow"] = {
                "pkts_toserver": flow_data.get("pkts_toserver"),
                "pkts_toclient": flow_data.get("pkts_toclient"),
                "bytes_toserver": flow_data.get("bytes_toserver"),
                "bytes_toclient": flow_data.get("bytes_toclient"),
                "start": flow_data.get("start"),
                "end": flow_data.get("end"),
                "age": flow_data.get("age"),
                "state": flow_data.get("state"),
                "reason": flow_data.get("reason"),
                "alerted": flow_data.get("alerted"),
            }

    def _parse_dns(self, data: dict[str, Any], attributes: dict[str, Any]) -> None:
        dns_data = data.get("dns")
        if isinstance(dns_data, dict):
            attributes["dns"] = {
                "type": dns_data.get("type"),
                "id": dns_data.get("id"),
                "rrname": dns_data.get("rrname") or dns_data.get("query"),
                "rrtype": dns_data.get("rrtype"),
                "rcode": dns_data.get("rcode"),
                "answers": dns_data.get("answers"),
                "grouped": dns_data.get("grouped") or dns_data.get("group"),
                "flags": dns_data.get("flags"),
                "version": dns_data.get("version"),
            }

    def _parse_http(self, data: dict[str, Any], attributes: dict[str, Any]) -> None:
        http_data = data.get("http")
        if isinstance(http_data, dict):
            attributes["http"] = {
                "hostname": http_data.get("hostname"),
                "url": http_data.get("url"),
                "http_method": http_data.get("http_method"),
                "protocol": http_data.get("protocol"),
                "status": http_data.get("status"),
                "length": http_data.get("length"),
                "user_agent": http_data.get("user_agent"),
                "http_content_type": http_data.get("http_content_type"),
                "referer": http_data.get("referer"),
            }
            if "request_headers" in http_data:
                attributes["http"]["request_headers"] = http_data["request_headers"]
            if "response_headers" in http_data:
                attributes["http"]["response_headers"] = http_data["response_headers"]

    def _parse_tls(self, data: dict[str, Any], attributes: dict[str, Any]) -> None:
        tls_data = data.get("tls")
        if isinstance(tls_data, dict):
            attributes["tls"] = {
                "subject": tls_data.get("subject"),
                "issuer": tls_data.get("issuer"),
                "serial": tls_data.get("serial"),
                "fingerprint": tls_data.get("fingerprint"),
                "sni": tls_data.get("sni"),
                "version": tls_data.get("version"),
                "ja3": tls_data.get("ja3"),
                "ja3s": tls_data.get("ja3s"),
                "notbefore": tls_data.get("notbefore"),
                "notafter": tls_data.get("notafter"),
            }

    def _parse_ssh(self, data: dict[str, Any], attributes: dict[str, Any]) -> None:
        ssh_data = data.get("ssh")
        if isinstance(ssh_data, dict):
            attributes["ssh"] = {
                "client": ssh_data.get("client"),
                "server": ssh_data.get("server"),
                "software": ssh_data.get("software"),
                "version": ssh_data.get("version"),
                "hassh": ssh_data.get("hassh"),
                "hasshServer": ssh_data.get("hasshServer"),
                "client_version": ssh_data.get("client_version"),
                "server_version": ssh_data.get("server_version"),
                "kex": ssh_data.get("kex"),
                "auth_attempt": ssh_data.get("auth_attempt"),
                "auth_success": ssh_data.get("auth_success"),
                "auth_method": ssh_data.get("auth_method"),
            }

    def _parse_fileinfo(self, data: dict[str, Any], attributes: dict[str, Any]) -> None:
        file_data = data.get("fileinfo")
        if isinstance(file_data, dict):
            attributes["fileinfo"] = {
                "filename": file_data.get("filename"),
                "size": file_data.get("size"),
                "state": file_data.get("state"),
                "stored": file_data.get("stored"),
                "md5": file_data.get("md5"),
                "sha1": file_data.get("sha1"),
                "sha256": file_data.get("sha256"),
                "magic": file_data.get("magic"),
                "gtype": file_data.get("gtype"),
                "tx_id": file_data.get("tx_id"),
            }

    def _parse_unknown(self, data: dict[str, Any], attributes: dict[str, Any]) -> None:
        # Preserve payload key-values under attributes if missing
        pass

    @staticmethod
    def _parse_timestamp(val: Any, fallback: datetime) -> datetime:
        if val is None:
            return fallback.astimezone(UTC)
        if isinstance(val, (int, float)):
            try:
                return datetime.fromtimestamp(float(val), tz=UTC)
            except (OverflowError, ValueError) as exc:
                raise ParserError(f"Invalid timestamp epoch value: {val}") from exc
        if isinstance(val, str):
            ts_str = val.strip()
            if not ts_str:
                return fallback.astimezone(UTC)
            try:
                # Standardize ISO-8601 string timezone formatting if needed (+0000 -> +00:00)
                if (
                    len(ts_str) >= 5
                    and (ts_str[-5] in ("+", "-"))
                    and ts_str[-3:] != ":00"
                    and ts_str[-2:].isdigit()
                    and ts_str[-4:-2].isdigit()
                ):
                    ts_str = ts_str[:-2] + ":" + ts_str[-2:]
                dt = datetime.fromisoformat(ts_str)
                return dt.astimezone(UTC)
            except ValueError as exc:
                raise ParserError(f"Malformed Suricata timestamp string: {val!r}") from exc
        raise ParserError(f"Unsupported timestamp type: {type(val).__name__}")

    @staticmethod
    def _sanitize_ip(val: Any) -> str | None:
        if isinstance(val, str) and val.strip() and val.strip() not in ("-", "none", "null"):
            return val.strip()
        return None

    @staticmethod
    def _sanitize_port(val: Any) -> int | None:
        if val is None or val == "":
            return None
        if isinstance(val, bool):
            return None
        try:
            port = int(val)
            return port if 0 <= port <= 65535 else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _extract_hostname(data: dict[str, Any]) -> str | None:
        if "host" in data and isinstance(data["host"], str) and data["host"].strip():
            return data["host"].strip()
        if "hostname" in data and isinstance(data["hostname"], str) and data["hostname"].strip():
            return data["hostname"].strip()
        if isinstance(data.get("http"), dict) and isinstance(data["http"].get("hostname"), str):
            return data["http"]["hostname"].strip() or None
        return None
