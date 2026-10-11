"""Comprehensive tests for the Suricata collector, parser, source, bookmarking, and reliability integration."""

import json
from pathlib import Path

import pytest

from argusprowl.collectors.suricata import (
    EveFileSource,
    ReplaySuricataEventSource,
    SuricataBookmarkStore,
    SuricataCollector,
    SuricataParser,
    SuricataRawRecord,
)
from argusprowl.exceptions.exceptions import ParserError
from argusprowl.models.normalized_event import NormalizedEvent

# Sample EVE JSON Fixtures
ALERT_EVE = json.dumps(
    {
        "timestamp": "2026-03-15T12:34:56.789012+0000",
        "flow_id": 123456789,
        "in_iface": "eth0",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "community_id": "1:9/Wp4M1F...",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2000001,
            "rev": 5,
            "signature": "ET MALWARE Suspicious User-Agent",
            "category": "A Network Trojan was detected",
            "severity": 1,
            "metadata": {"affected_product": ["Web_Browsers"]},
            "references": ["url,example.com/cve"],
        },
    }
)

FLOW_EVE = json.dumps(
    {
        "timestamp": "2026-03-15T12:34:57.000Z",
        "flow_id": 987654321,
        "event_type": "flow",
        "src_ip": "192.168.1.50",
        "src_port": 44444,
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "community_id": "1:abc...",
        "flow": {
            "pkts_toserver": 2,
            "pkts_toclient": 2,
            "bytes_toserver": 120,
            "bytes_toclient": 240,
            "start": "2026-03-15T12:34:50.000Z",
            "end": "2026-03-15T12:34:57.000Z",
            "age": 7,
            "state": "closed",
            "reason": "idle",
            "alerted": False,
        },
    }
)

DNS_EVE = json.dumps(
    {
        "timestamp": "2026-03-15T12:35:00.123+02:00",
        "event_type": "dns",
        "src_ip": "192.168.1.100",
        "src_port": 53535,
        "dest_ip": "1.1.1.1",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "id": 1234,
            "rrname": "malicious.example.com",
            "rrtype": "A",
            "rcode": "NOERROR",
            "answers": [
                {"rrname": "malicious.example.com", "rrtype": "A", "rdata": "93.184.216.34"}
            ],
            "grouped": {"A": ["93.184.216.34"]},
            "flags": "8180",
        },
    }
)

HTTP_EVE = json.dumps(
    {
        "timestamp": "2026-03-15T12:35:05.000000Z",
        "event_type": "http",
        "src_ip": "10.1.1.5",
        "src_port": 12345,
        "dest_ip": "93.184.216.34",
        "dest_port": 80,
        "proto": "TCP",
        "http": {
            "hostname": "example.com",
            "url": "/login.php",
            "http_method": "POST",
            "protocol": "HTTP/1.1",
            "status": 200,
            "length": 450,
            "user_agent": "Mozilla/5.0",
            "http_content_type": "text/html",
            "referer": "http://example.com/",
        },
    }
)

TLS_EVE = json.dumps(
    {
        "timestamp": "2026-03-15T12:35:10.000Z",
        "event_type": "tls",
        "src_ip": "10.1.1.5",
        "src_port": 54322,
        "dest_ip": "104.16.132.229",
        "dest_port": 443,
        "proto": "TCP",
        "tls": {
            "subject": "CN=example.com",
            "issuer": "CN=Let's Encrypt Authority X3",
            "serial": "03:A1:...",
            "fingerprint": "a1b2c3d4...",
            "sni": "example.com",
            "version": "TLS 1.3",
            "ja3": "771,4865-4866-4867...",
            "ja3s": "771,4865...",
            "notbefore": "2026-01-01T00:00:00Z",
            "notafter": "2026-04-01T00:00:00Z",
        },
    }
)

SSH_EVE = json.dumps(
    {
        "timestamp": "2026-03-15T12:35:15.000Z",
        "event_type": "ssh",
        "src_ip": "192.168.1.200",
        "src_port": 45000,
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "proto": "TCP",
        "ssh": {
            "client": {"proto_version": "2.0", "software_version": "OpenSSH_8.9p1"},
            "server": {"proto_version": "2.0", "software_version": "OpenSSH_8.2p1"},
            "hassh": "bf116662...",
            "hasshServer": "10712398...",
            "auth_attempt": True,
            "auth_success": True,
            "auth_method": "publickey",
        },
    }
)

FILEINFO_EVE = json.dumps(
    {
        "timestamp": "2026-03-15T12:35:20.000Z",
        "event_type": "fileinfo",
        "src_ip": "10.0.0.50",
        "src_port": 80,
        "dest_ip": "192.168.1.100",
        "dest_port": 50000,
        "proto": "TCP",
        "fileinfo": {
            "filename": "payload.exe",
            "size": 1048576,
            "state": "CLOSED",
            "stored": True,
            "md5": "e10adc3949ba59abbe56e057f20f883e",
            "sha1": "7c4a8d09ca3762af61e59520943dc26494f8941b",
            "sha256": "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
            "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
            "gtype": "executable",
            "tx_id": 1,
        },
    }
)

UNKNOWN_EVE = json.dumps(
    {
        "timestamp": "2026-03-15T12:35:25.000Z",
        "event_type": "future_suricata_type",
        "src_ip": "1.2.3.4",
        "dest_ip": "5.6.7.8",
    }
)


# 35.1 ALERT TESTS
def test_parse_alert_event() -> None:
    parser = SuricataParser()
    event = parser.parse(ALERT_EVE)

    assert isinstance(event, NormalizedEvent)
    assert event.source_type == "suricata"
    assert event.event_type == "ids_alert"
    assert event.src_ip == "192.168.1.100"
    assert event.src_port == 54321
    assert event.dst_ip == "10.0.0.1"
    assert event.dst_port == 80
    assert event.protocol == "TCP"
    assert event.attributes["flow_id"] == 123456789
    assert event.attributes["community_id"] == "1:9/Wp4M1F..."
    assert event.attributes["signature_id"] == 2000001
    assert event.attributes["signature"] == "ET MALWARE Suspicious User-Agent"
    assert event.attributes["category"] == "A Network Trojan was detected"
    assert event.attributes["severity"] == 1
    assert event.attributes["action"] == "allowed"
    assert event.attributes["gid"] == 1

    # CRITICAL AUDIT CHECK: A Suricata alert MUST remain a NormalizedEvent, NOT a platform Alert
    assert type(event).__name__ == "NormalizedEvent"
    assert not hasattr(event, "alert_id")  # Platform Alert model has alert_id


# 35.2 FLOW TESTS
def test_parse_flow_event() -> None:
    parser = SuricataParser()
    event = parser.parse(FLOW_EVE)

    assert event.source_type == "suricata"
    assert event.event_type == "network_flow"
    assert event.src_ip == "192.168.1.50"
    assert event.dst_ip == "8.8.8.8"
    assert event.attributes["flow_id"] == 987654321
    assert event.attributes["flow"]["pkts_toserver"] == 2
    assert event.attributes["flow"]["bytes_toclient"] == 240
    assert event.attributes["flow"]["state"] == "closed"


# 35.3 DNS TESTS
def test_parse_dns_event() -> None:
    parser = SuricataParser()
    event = parser.parse(DNS_EVE)

    assert event.source_type == "suricata"
    assert event.event_type == "dns_query"
    assert event.src_ip == "192.168.1.100"
    assert event.dst_ip == "1.1.1.1"
    assert event.attributes["dns"]["rrname"] == "malicious.example.com"
    assert event.attributes["dns"]["rcode"] == "NOERROR"


# 35.4 HTTP TESTS
def test_parse_http_event() -> None:
    parser = SuricataParser()
    event = parser.parse(HTTP_EVE)

    assert event.source_type == "suricata"
    assert event.event_type == "http_transaction"
    assert event.hostname == "example.com"
    assert event.attributes["http"]["url"] == "/login.php"
    assert event.attributes["http"]["http_method"] == "POST"
    assert event.attributes["http"]["status"] == 200


# 35.5 TLS TESTS
def test_parse_tls_event() -> None:
    parser = SuricataParser()
    event = parser.parse(TLS_EVE)

    assert event.source_type == "suricata"
    assert event.event_type == "tls_connection"
    assert event.attributes["tls"]["sni"] == "example.com"
    assert event.attributes["tls"]["version"] == "TLS 1.3"
    assert event.attributes["tls"]["ja3"] == "771,4865-4866-4867..."


# 35.6 SSH TESTS
def test_parse_ssh_event() -> None:
    parser = SuricataParser()
    event = parser.parse(SSH_EVE)

    assert event.source_type == "suricata"
    assert event.event_type == "ssh_activity"
    assert event.attributes["ssh"]["hassh"] == "bf116662..."
    assert event.attributes["ssh"]["auth_success"] is True


# 35.7 FILEINFO TESTS
def test_parse_fileinfo_event() -> None:
    parser = SuricataParser()
    event = parser.parse(FILEINFO_EVE)

    assert event.source_type == "suricata"
    assert event.event_type == "file_observation"
    assert event.attributes["fileinfo"]["filename"] == "payload.exe"
    assert event.attributes["fileinfo"]["md5"] == "e10adc3949ba59abbe56e057f20f883e"
    assert event.attributes["fileinfo"]["size"] == 1048576


# 35.8 UNKNOWN EVENT TEST
def test_parse_unknown_event() -> None:
    parser = SuricataParser()
    event = parser.parse(UNKNOWN_EVE)

    assert event.source_type == "suricata"
    assert event.event_type == "suricata_unknown"
    assert event.attributes["suricata_event_type"] == "future_suricata_type"


# 35.9 MALFORMED JSON
def test_parse_malformed_json() -> None:
    parser = SuricataParser()

    with pytest.raises(ParserError):
        parser.parse("invalid json string {")

    with pytest.raises(ParserError):
        parser.parse("")

    with pytest.raises(ParserError):
        parser.parse("   ")

    with pytest.raises(ParserError):
        parser.parse("[1, 2, 3]")  # JSON array instead of object


# 35.10 TIMESTAMP TESTS
def test_timestamp_parsing() -> None:
    parser = SuricataParser()

    # ISO with offset
    e1 = parser.parse(json.dumps({"timestamp": "2026-03-15T12:00:00+0200", "event_type": "flow"}))
    assert e1.timestamp.hour == 10  # 12:00 +02:00 -> 10:00 UTC

    # ISO with Z
    e2 = parser.parse(json.dumps({"timestamp": "2026-03-15T12:00:00Z", "event_type": "flow"}))
    assert e2.timestamp.hour == 12

    # Unix epoch float
    e3 = parser.parse(json.dumps({"timestamp": 1700000000.5, "event_type": "flow"}))
    assert e3.timestamp.timestamp() == 1700000000.5

    # Malformed timestamp
    with pytest.raises(ParserError):
        parser.parse(json.dumps({"timestamp": "not-a-timestamp", "event_type": "flow"}))


# 35.11 FILE TAILING & OVERSIZED LINES
def test_file_tailing_and_oversized_line(tmp_path: Path) -> None:
    eve_file = tmp_path / "eve.json"
    eve_file.write_text(ALERT_EVE + "\n", encoding="utf-8")

    source = EveFileSource(eve_file, max_record_size=100)  # Low limit for testing
    source.open()

    records = tuple(source.read(checkpoint=None, limit=10))
    assert len(records) == 1
    assert records[0].metadata["oversized"] is True

    source.close()


# 35.12 ROTATION & BOOKMARK
def test_bookmark_store_and_rotation(tmp_path: Path) -> None:
    bm_path = tmp_path / "bookmark.json"
    store = SuricataBookmarkStore(bm_path)

    assert store.load() is None
    store.save(inode=100, offset=500)
    assert store.load() == {"inode": 100, "offset": 500}

    store.clear()
    assert store.load() is None


# 35.14 REPLAY
def test_suricata_replay_source() -> None:
    records = [
        SuricataRawRecord(line=ALERT_EVE, offset=100, inode=1),
        SuricataRawRecord(line=FLOW_EVE, offset=200, inode=1),
    ]
    replay = ReplaySuricataEventSource(records)
    replay.open()

    read_records = tuple(replay.read(checkpoint=None, limit=10))
    assert len(read_records) == 2

    parser = SuricataParser()
    events = [parser.parse(r) for r in read_records]
    assert len(events) == 2
    assert events[0].event_type == "ids_alert"
    assert events[1].event_type == "network_flow"

    replay.close()


# 35.13 SOURCE RECORD IDENTITY TESTS
def test_source_record_id_alert_is_none() -> None:
    """Suricata alerts have no native record-level identifier."""
    parser = SuricataParser()
    event = parser.parse(ALERT_EVE)
    assert event.source_record_id is None
    # Original identifiers remain in attributes
    assert event.attributes["flow_id"] == 123456789
    assert event.attributes["community_id"] == "1:9/Wp4M1F..."


def test_source_record_id_flow_uses_flow_id() -> None:
    """Flow events use flow_id as source_record_id."""
    parser = SuricataParser()
    event = parser.parse(FLOW_EVE)
    assert event.source_record_id == "987654321"


def test_source_record_id_dns_prefers_tx_id() -> None:
    """DNS events prefer tx_id over flow_id."""
    parser = SuricataParser()
    event = parser.parse(DNS_EVE)
    # DNS_EVE fixture has no tx_id or flow_id, so source_record_id should be None
    assert event.source_record_id is None


def test_source_record_id_http_prefers_tx_id() -> None:
    """HTTP events prefer tx_id over flow_id."""
    parser = SuricataParser()
    event = parser.parse(HTTP_EVE)
    # HTTP_EVE fixture has no tx_id or flow_id, so source_record_id should be None
    assert event.source_record_id is None


def test_source_record_id_tls_prefers_tx_id() -> None:
    """TLS events prefer tx_id over flow_id."""
    parser = SuricataParser()
    event = parser.parse(TLS_EVE)
    # TLS_EVE fixture has no tx_id or flow_id, so source_record_id should be None
    assert event.source_record_id is None


def test_source_record_id_ssh_prefers_tx_id() -> None:
    """SSH events prefer tx_id over flow_id."""
    parser = SuricataParser()
    event = parser.parse(SSH_EVE)
    # SSH_EVE fixture has no tx_id or flow_id, so source_record_id should be None
    assert event.source_record_id is None


def test_source_record_id_fileinfo_prefers_tx_id() -> None:
    """Fileinfo events prefer tx_id over flow_id."""
    parser = SuricataParser()
    event = parser.parse(FILEINFO_EVE)
    # FILEINFO_EVE has tx_id=1 in nested fileinfo, but top-level tx_id is absent
    # The parser reads top-level tx_id, so source_record_id should be None
    assert event.source_record_id is None
    # The nested tx_id remains in attributes
    assert event.attributes["fileinfo"]["tx_id"] == 1


def test_source_record_id_unknown_is_none() -> None:
    """Unknown event types have no source_record_id."""
    parser = SuricataParser()
    event = parser.parse(UNKNOWN_EVE)
    assert event.source_record_id is None


def test_source_record_id_is_string_and_survives_serialization() -> None:
    """source_record_id must be a string and survive to_dict/from_dict round-trip."""
    parser = SuricataParser()
    event = parser.parse(FLOW_EVE)
    assert isinstance(event.source_record_id, str)
    restored = NormalizedEvent.from_dict(event.to_dict())
    assert restored.source_record_id == event.source_record_id


def test_source_record_id_distinct_events_same_flow() -> None:
    """Events on the same flow with different tx_ids get distinct source_record_ids."""
    dns_with_tx = json.dumps(
        {
            "timestamp": "2026-03-15T12:35:00.123+02:00",
            "event_type": "dns",
            "src_ip": "192.168.1.100",
            "src_port": 53535,
            "dest_ip": "1.1.1.1",
            "dest_port": 53,
            "proto": "UDP",
            "flow_id": 999,
            "tx_id": 10,
            "dns": {"type": "query", "rrname": "a.example.com"},
        }
    )
    http_with_tx = json.dumps(
        {
            "timestamp": "2026-03-15T12:35:01.000Z",
            "event_type": "http",
            "src_ip": "192.168.1.100",
            "src_port": 12345,
            "dest_ip": "93.184.216.34",
            "dest_port": 80,
            "proto": "TCP",
            "flow_id": 999,
            "tx_id": 20,
            "http": {"url": "/"},
        }
    )
    parser = SuricataParser()
    dns_event = parser.parse(dns_with_tx)
    http_event = parser.parse(http_with_tx)
    assert dns_event.source_record_id == "10"
    assert http_event.source_record_id == "20"
    assert dns_event.source_record_id != http_event.source_record_id


def test_source_record_id_falls_back_to_flow_id_when_tx_id_missing() -> None:
    """When tx_id is absent, flow_id is used as fallback for transaction events."""
    dns_no_tx = json.dumps(
        {
            "timestamp": "2026-03-15T12:35:00.123+02:00",
            "event_type": "dns",
            "src_ip": "192.168.1.100",
            "src_port": 53535,
            "dest_ip": "1.1.1.1",
            "dest_port": 53,
            "proto": "UDP",
            "flow_id": 777,
            "dns": {"type": "query", "rrname": "a.example.com"},
        }
    )
    parser = SuricataParser()
    event = parser.parse(dns_no_tx)
    assert event.source_record_id == "777"


# 35.15 RELIABILITY & COLLECTOR LIFECYCLE
def test_collector_lifecycle_and_dead_letter(tmp_path: Path) -> None:
    records = [
        SuricataRawRecord(line=ALERT_EVE, offset=100, inode=1),
        SuricataRawRecord(line="BAD JSON {{{", offset=200, inode=1),
        SuricataRawRecord(line=FLOW_EVE, offset=300, inode=1),
    ]
    source = ReplaySuricataEventSource(records)
    collector = SuricataCollector(source=source)

    config = {
        "eve_path": str(tmp_path / "eve.json"),
        "bookmark_path": str(tmp_path / "bookmark.json"),
        "batch_size": 10,
        "polling_interval": 0.01,
    }

    collector.initialize(config)
    collector.start()

    collected_events = []
    # Generator collect
    gen = collector.collect()
    for _ in range(2):
        collected_events.append(next(gen))

    collector.stop()

    assert len(collected_events) == 2
    assert collected_events[0].event_type == "ids_alert"
    assert collected_events[1].event_type == "network_flow"

    # Health & status
    health = collector.health()
    assert health.name == "suricata_collector"
    assert collector.suricata_events_received.get_value() == 3
    assert collector.suricata_events_parsed.get_value() == 2
    assert collector.suricata_parse_errors.get_value() == 1
    assert collector.suricata_alert_events.get_value() == 1
    assert collector.suricata_flow_events.get_value() == 1
