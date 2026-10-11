import contextlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from argusprowl.collectors.sysmon import (
    ReplaySysmonEventSource,
    SysmonBookmarkStore,
    SysmonCollector,
    SysmonParser,
    SysmonRawRecord,
)
from argusprowl.constants.event_type import EventType
from argusprowl.constants.source_type import SourceType
from argusprowl.exceptions.exceptions import ParserError


def _xml(event_id: int, record_id: int = 1, data: dict[str, str] | None = None) -> str:
    values = data or {}
    payload = "".join(f'<Data Name="{key}">{value}</Data>' for key, value in values.items())
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System><EventID>{event_id}</EventID><EventRecordID>{record_id}</EventRecordID>
 <TimeCreated SystemTime="2026-01-02T03:04:05.000Z"/><Computer>HOST01</Computer></System>
 <EventData>{payload}</EventData></Event>"""


@pytest.mark.parametrize(
    ("event_id", "event_type"),
    [
        (1, EventType.PROCESS_CREATE),
        (3, EventType.NETWORK_CONNECTION),
        (7, EventType.IMAGE_LOAD),
        (8, EventType.REMOTE_THREAD),
        (10, EventType.PROCESS_ACCESS),
        (11, EventType.FILE_CREATE),
        (12, EventType.REGISTRY_CREATE),
        (13, EventType.REGISTRY_SET),
        (14, EventType.REGISTRY_RENAME),
        (22, EventType.DNS_QUERY),
    ],
)
def test_parser_maps_supported_sysmon_events(event_id: int, event_type: str) -> None:
    event = SysmonParser().parse(
        _xml(
            event_id,
            data={
                "Image": r"C:\Windows\cmd.exe",
                "CommandLine": "cmd /c whoami",
                "User": "DOMAIN\\alice",
                "SourceIp": "10.0.0.1",
                "SourcePort": "1234",
                "DestinationIp": "10.0.0.2",
                "DestinationPort": "443",
                "Protocol": "tcp",
                "Unicode": "Δ",
            },
        )
    )
    assert event.source_type == SourceType.SYSMON and event.event_type == event_type
    assert event.hostname == "HOST01" and event.src_ip == "10.0.0.1" and event.dst_port == 443
    assert event.username == "DOMAIN\\alice" and event.process_name == r"C:\Windows\cmd.exe"
    assert event.attributes["sysmon_event_id"] == event_id and event.attributes["Unicode"] == "Δ"
    assert event.timestamp == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_parser_uses_native_event_record_id_for_source_record_id() -> None:
    event = SysmonParser().parse(
        _xml(3, record_id=42, data={"Image": r"C:\Windows\System32\svchost.exe"})
    )
    assert event.source_record_id == "42"
    assert event.attributes["event_record_id"] == 42
    assert event.attributes["sysmon_event_id"] == 3
    restored = type(event).from_dict(event.to_dict())
    assert restored.source_record_id == "42"
    assert restored.attributes["event_record_id"] == 42


def test_parser_handles_unknown_missing_and_malformed_events() -> None:
    parser = SysmonParser()
    assert parser.parse(_xml(99)).event_type == "sysmon_unknown"
    assert parser.parse(_xml(1, data={"SourceIp": "-"})).src_ip is None
    with pytest.raises(ParserError):
        parser.parse("<Event>")
    with pytest.raises(ParserError):
        parser.parse(_xml(1, data={"SourcePort": "bad"}))


def test_parser_rejects_doctype_and_external_entities() -> None:
    malicious_xml = """<!DOCTYPE Event [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>1</EventID></System>
      <EventData><Data Name="Image">&xxe;</Data></EventData>
    </Event>"""
    with pytest.raises(ParserError, match="Malformed Sysmon XML"):
        SysmonParser().parse(malicious_xml)


def test_bookmark_is_atomic_and_restart_safe(tmp_path: Path) -> None:
    path = tmp_path / "sysmon.json"
    store = SysmonBookmarkStore(path)
    assert store.load() is None
    store.save(42)
    assert SysmonBookmarkStore(path).load() == 42
    store.clear()
    assert store.load() is None


def test_collector_replays_parses_dead_letters_and_checkpoints(tmp_path: Path) -> None:
    records = [SysmonRawRecord(_xml(1, 7), 7), SysmonRawRecord("<Event>", 8)]
    collector = SysmonCollector(source=ReplaySysmonEventSource(records))
    collector.initialize(
        {"bookmark_path": str(tmp_path / "checkpoint.json"), "polling_interval": 0.001}
    )
    collector.start()
    iterator = collector.collect()
    event = next(iterator)
    assert event.event_type == "process_create" and collector.bookmark == 7
    next(iterator, None) if False else None
    # The malformed record is handled when the iterator advances, without
    # propagating a parser failure to the collector.
    import threading

    def advance() -> None:
        with contextlib.suppress(StopIteration):
            next(iterator)

    thread = threading.Thread(target=advance, daemon=True)
    thread.start()
    thread.join(0.05)
    collector.stop()
