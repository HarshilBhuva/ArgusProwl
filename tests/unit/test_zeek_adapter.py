"""Unit tests for Zeek SSL telemetry normalization."""

from datetime import UTC, datetime, timedelta

from argusprowl.collectors.zeek.adapter import ZeekTelemetryAdapter
from argusprowl.constants.event_type import EventType
from argusprowl.constants.severity import Severity
from argusprowl.constants.source_type import SourceType
from argusprowl.models.normalized_event import NormalizedEvent


def test_from_raw_ssl_record_normalizes_valid_zeek_json() -> None:
    """Convert a complete Zeek SSL JSON record and retain its evidence context."""
    record = {
        "ts": 1_726_765_296.125,
        "uid": "CzeekSsl123",
        "_sensor_id": "sensor-east-1",
        "_ingest_timestamp": "2026-09-22T12:00:00Z",
        "id_orig_h": "10.10.20.15",
        "id_orig_p": "51234",
        "id_resp_h": "203.0.113.20",
        "id_resp_p": 443,
        "version": "TLSv13",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "server_name": "api.example.test",
        "established": "T",
        "resumed": False,
        "cert_chain_fuids": ["FcertOne", "FcertTwo"],
        "subject": "CN=api.example.test",
        "issuer": "CN=Example Test CA",
        "duration": "3.25",
        "orig_bytes": "1024",
        "resp_bytes": 4096,
        "orig_pkts": "8",
        "resp_pkts": 12,
    }

    event = ZeekTelemetryAdapter.from_raw_ssl_record(record)

    assert isinstance(event, NormalizedEvent)
    assert event.source_type == SourceType.ZEEK
    assert event.event_type == EventType.NETWORK_FLOW
    assert event.severity is Severity.INFO
    assert event.timestamp == datetime.fromtimestamp(record["ts"], tz=UTC)
    assert event.src_ip == "10.10.20.15"
    assert event.src_port == 51234
    assert event.dst_ip == "203.0.113.20"
    assert event.dst_port == 443
    assert event.protocol == "TCP"
    assert event.source_record_id == "CzeekSsl123"
    assert event.raw_event == record
    assert event.metadata == {
        "zeek_uid": "CzeekSsl123",
        "sensor_id": "sensor-east-1",
        "ingest_timestamp": "2026-09-22T12:00:00Z",
        "raw_source": "zeek.ssl",
        "provenance_chain": [
            "sensor:sensor-east-1",
            "source:zeek.ssl",
            "zeek_uid:CzeekSsl123",
        ],
    }
    assert event.attributes["service"] == "TLS"
    assert event.attributes["tls"] == {
        "version": "TLSv13",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "server_name": "api.example.test",
        "established": True,
        "resumed": False,
        "cert_chain_fuids": ["FcertOne", "FcertTwo"],
        "subject": "CN=api.example.test",
        "issuer": "CN=Example Test CA",
    }
    assert event.attributes["flow_stats"] == {
        "duration": 3.25,
        "orig_bytes": 1024,
        "resp_bytes": 4096,
        "orig_pkts": 8,
        "resp_pkts": 12,
    }


def test_from_raw_ssl_record_preserves_empty_ech_server_name() -> None:
    """Preserve absent SNI for TLS 1.3 records protected by ECH."""
    event = ZeekTelemetryAdapter.from_raw_ssl_record(
        {
            "ts": "2026-09-22T12:30:00Z",
            "uid": "CechTls13",
            "id_orig_h": "2001:db8::10",
            "id_orig_p": 61000,
            "id_resp_h": "2001:db8::20",
            "id_resp_p": 443,
            "version": "TLSv13",
            "server_name": None,
            "established": "T",
            "resumed": "F",
        }
    )

    assert event.timestamp == datetime(2026, 9, 22, 12, 30, tzinfo=UTC)
    assert event.src_ip == "2001:db8::10"
    assert event.dst_ip == "2001:db8::20"
    assert event.attributes["tls"]["version"] == "TLSv13"
    assert event.attributes["tls"]["server_name"] is None
    assert event.attributes["tls"]["cert_chain_fuids"] == []
    assert event.attributes["tls"]["established"] is True
    assert event.attributes["tls"]["resumed"] is False


def test_from_raw_ssl_record_uses_safe_defaults_for_malformed_values() -> None:
    """Use safe defaults for absent fields, malformed timestamps, and invalid types."""
    before = datetime.now(UTC)
    event = ZeekTelemetryAdapter.from_raw_ssl_record(
        {
            "ts": "not-a-timestamp",
            "id_orig_h": "not-an-ip",
            "id_orig_p": "not-a-port",
            "id_resp_h": None,
            "id_resp_p": 70000,
            "duration": "NaN",
            "orig_bytes": "not-a-number",
            "resp_bytes": None,
            "orig_pkts": True,
            "resp_pkts": [],
            "established": "unknown",
            "cert_chain_fuids": "FcertOnly",
        }
    )
    after = datetime.now(UTC)

    assert before <= event.timestamp <= after + timedelta(seconds=1)
    assert event.src_ip == "0.0.0.0"
    assert event.src_port == 0
    assert event.dst_ip == "0.0.0.0"
    assert event.dst_port == 0
    assert event.source_record_id is None
    assert event.metadata["zeek_uid"] == ""
    assert event.metadata["sensor_id"] == "unknown-sensor"
    assert event.metadata["raw_source"] == "zeek.ssl"
    assert event.attributes["tls"]["established"] is None
    assert event.attributes["tls"]["cert_chain_fuids"] == ["FcertOnly"]
    assert event.attributes["flow_stats"] == {
        "duration": 0.0,
        "orig_bytes": 0,
        "resp_bytes": 0,
        "orig_pkts": 0,
        "resp_pkts": 0,
    }
