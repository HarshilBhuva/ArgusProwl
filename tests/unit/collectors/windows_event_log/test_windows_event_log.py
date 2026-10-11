"""Linux-safe coverage for standard Windows Event Log collection."""

from datetime import UTC, datetime
from pathlib import Path
from threading import Thread

import pytest

from argusprowl.collectors.state import CollectorState
from argusprowl.collectors.windows_event_log import (
    ReplayWindowsEventSource,
    WindowsEventBookmarkStore,
    WindowsEventCollector,
    WindowsEventParser,
    WindowsEventRawRecord,
)
from argusprowl.collectors.windows_event_log.config import WindowsEventCollectorConfig
from argusprowl.collectors.windows_event_log.events import (
    StaleWindowsBookmarkError,
    WindowsEventSource,
)
from argusprowl.constants.event_type import EventType
from argusprowl.constants.source_type import SourceType
from argusprowl.exceptions.exceptions import ParserError


def _xml(
    event_id: int, record_id: int = 1, data: dict[str, str] | None = None, *, version: int = 0
) -> str:
    payload = "".join(f'<Data Name="{key}">{value}</Data>' for key, value in (data or {}).items())
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID Version="{version}">{event_id}</EventID>
 <EventRecordID>{record_id}</EventRecordID><TimeCreated SystemTime="2026-01-02T03:04:05.000Z"/>
 <Channel>Security</Channel><Computer>HOST01</Computer></System><EventData>{payload}</EventData></Event>'''


@pytest.mark.parametrize(
    ("event_id", "event_type"),
    [
        (4624, EventType.AUTHENTICATION_SUCCESS),
        (4625, EventType.AUTHENTICATION_FAILURE),
        (4648, EventType.EXPLICIT_CREDENTIAL_LOGON),
        (4672, EventType.PRIVILEGE_ASSIGNMENT),
        (4688, EventType.PROCESS_CREATE),
        (4697, EventType.SERVICE_INSTALL),
        (4720, EventType.ACCOUNT_CREATE),
        (4728, EventType.GROUP_MEMBERSHIP_CHANGE),
        (4732, EventType.GROUP_MEMBERSHIP_CHANGE),
        (4756, EventType.GROUP_MEMBERSHIP_CHANGE),
        (1102, EventType.AUDIT_LOG_CLEARED),
    ],
)
def test_parser_maps_supported_event_ids(event_id: int, event_type: str) -> None:
    event = WindowsEventParser().parse(
        WindowsEventRawRecord(
            _xml(event_id, record_id=20, data={"SubjectUserName": "alice", "Unicode": "Δ"}),
            "Security",
            20,
            metadata={"source": "fixture"},
        )
    )
    assert event.source_type == SourceType.WINDOWS_EVENT_LOG and event.event_type == event_type
    assert event.timestamp == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert event.hostname == "HOST01" and event.username == "alice"
    assert event.attributes["windows_event_id"] == event_id and event.attributes["Unicode"] == "Δ"
    assert event.source_record_id == "20"
    assert (
        event.metadata["source"] == "fixture"
        and event.metadata["provider"] == "Microsoft-Windows-Security-Auditing"
    )


def test_parser_uses_native_event_record_id_for_source_record_id() -> None:
    xml_without_record_id = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>
 <TimeCreated SystemTime="2026-01-02T03:04:05.000Z"/>
 <Channel>Security</Channel><Computer>HOST01</Computer></System><EventData></EventData></Event>"""
    parser = WindowsEventParser()
    event_with_id = parser.parse(_xml(4624, record_id=100))
    assert event_with_id.source_record_id == "100"
    assert event_with_id.attributes["event_record_id"] == 100
    assert event_with_id.attributes["windows_event_id"] == 4624
    assert event_with_id.metadata["channel"] == "Security"

    restored = type(event_with_id).from_dict(event_with_id.to_dict())
    assert restored.source_record_id == "100"
    assert restored.attributes["event_record_id"] == 100

    event_without_id = parser.parse(WindowsEventRawRecord(xml_without_record_id, "Security", None))
    assert event_without_id.source_record_id is None
    assert event_without_id.attributes.get("event_record_id") is None


def test_parser_normalizes_authentication_and_process_fields() -> None:
    parser = WindowsEventParser()
    authentication = parser.parse(
        _xml(
            4624,
            data={
                "SubjectUserName": "SYSTEM",
                "TargetUserName": "alice",
                "LogonType": "3",
                "AuthenticationPackageName": "Negotiate",
                "WorkstationName": "WORKSTATION",
                "IpAddress": "10.2.3.4",
                "IpPort": "51515",
                "ProcessName": "lsass.exe",
            },
        )
    )
    assert (
        authentication.username == "alice"
        and authentication.src_ip == "10.2.3.4"
        and authentication.src_port == 51515
    )
    assert (
        authentication.process_name == "lsass.exe"
        and authentication.attributes["SubjectUserName"] == "SYSTEM"
        and authentication.attributes["TargetUserName"] == "alice"
    )
    process = parser.parse(
        _xml(
            4688,
            data={
                "SubjectUserName": "alice",
                "NewProcessName": r"C:\\Windows\\cmd.exe",
                "CreatorProcessName": r"C:\\Windows\\explorer.exe",
                "CommandLine": "cmd /c whoami",
            },
        )
    )
    assert process.username == "alice" and process.process_name == r"C:\\Windows\\cmd.exe"
    assert (
        process.command_line == "cmd /c whoami"
        and process.attributes["CreatorProcessName"] == r"C:\\Windows\\explorer.exe"
    )


def test_username_semantics_for_actor_and_target() -> None:
    parser = WindowsEventParser()
    # 4624 Logon: TargetUserName (authenticated user) prioritized over SubjectUserName (requester)
    auth_event = parser.parse(
        _xml(4624, data={"SubjectUserName": "SYSTEM", "TargetUserName": "target_user"})
    )
    assert auth_event.username == "target_user"
    assert auth_event.attributes["SubjectUserName"] == "SYSTEM"
    assert auth_event.attributes["TargetUserName"] == "target_user"

    # 4688 Process Create: SubjectUserName (actor) prioritized
    process_event = parser.parse(
        _xml(4688, data={"SubjectUserName": "actor_user", "TargetUserName": "other_user"})
    )
    assert process_event.username == "actor_user"
    assert process_event.attributes["SubjectUserName"] == "actor_user"

    # Missing username fields: username is None
    no_user_event = parser.parse(_xml(4624, data={}))
    assert no_user_event.username is None


def test_parser_handles_unknown_optional_and_invalid_records() -> None:
    parser = WindowsEventParser()
    event = parser.parse(_xml(9999, data={"IpAddress": "-", "IpPort": "0", "Extra": ""}, version=2))
    assert event.event_type == "windows_unknown" and event.src_ip is None and event.src_port is None
    assert event.attributes["Extra"] == ""
    with pytest.raises(ParserError):
        parser.parse("<Event>")
    with pytest.raises(ParserError):
        parser.parse('<Event xmlns="urn:invalid"><System/></Event>')
    with pytest.raises(ParserError):
        parser.parse(_xml(4624, data={"IpPort": "invalid"}))


def test_parser_rejects_doctype_and_external_entities() -> None:
    malicious_xml = """<!DOCTYPE Event [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>4624</EventID></System>
      <EventData><Data Name="SubjectUserName">&xxe;</Data></EventData>
    </Event>"""
    with pytest.raises(ParserError, match="Malformed Windows Event Log XML"):
        WindowsEventParser().parse(malicious_xml)


def test_bookmarks_are_atomic_and_per_channel(tmp_path: Path) -> None:
    path = tmp_path / "windows-bookmarks.json"
    store = WindowsEventBookmarkStore(path)
    assert store.load("Security") is None
    store.save("Security", 42)
    store.save("System", 9)
    restarted = WindowsEventBookmarkStore(path)
    assert restarted.load("Security") == 42 and restarted.load("System") == 9
    restarted.clear("Security")
    assert restarted.load("Security") is None and restarted.load("System") == 9


def test_config_rejects_unsafe_channels_and_invalid_values() -> None:
    with pytest.raises(ValueError):
        WindowsEventCollectorConfig(channels=("Security;whoami",)).validate()
    with pytest.raises(ValueError):
        WindowsEventCollectorConfig(channels=(" ",)).validate()
    with pytest.raises(ValueError):
        WindowsEventCollectorConfig(batch_size=True).validate()


def test_collector_lifecycle_replay_checkpoint_and_dead_letters(tmp_path: Path) -> None:
    records = [
        WindowsEventRawRecord(_xml(4625, 7), "Security", 7),
        WindowsEventRawRecord("<Event>", "Security", 8),
        WindowsEventRawRecord(_xml(9999, 9), "Security", 9),
    ]
    collector = WindowsEventCollector(source=ReplayWindowsEventSource(records))
    collector.initialize(
        {"bookmark_path": str(tmp_path / "checkpoint.json"), "polling_interval": 0.001}
    )
    collector.start()
    iterator = collector.collect()
    assert next(iterator).event_type == "authentication_failure"
    assert next(iterator).event_type == "windows_unknown"
    assert collector.bookmark("Security") == 9 and collector.windows_unknown_events.get_value() == 1
    status = collector.status()["windows_event_log"]
    assert status["bookmarks"] == {"Security": 9} and status["last_event_time"] is not None
    collector.pause()
    assert collector.state == CollectorState.PAUSED
    collector.resume()
    collector.stop()
    assert collector.state == CollectorState.STOPPED


class _StaleThenReplaySource(WindowsEventSource):
    def __init__(self, record: WindowsEventRawRecord) -> None:
        self.record, self.stale = record, True

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def read(self, channel: str, after_record_id: int | None, limit: int):
        if self.stale:
            self.stale = False
            raise StaleWindowsBookmarkError("retention")
        return (self.record,)


def test_collector_recovers_from_a_stale_bookmark(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    WindowsEventBookmarkStore(path).save("Security", 3)
    collector = WindowsEventCollector(
        source=_StaleThenReplaySource(WindowsEventRawRecord(_xml(4624, 4), "Security", 4))
    )
    collector.initialize({"bookmark_path": str(path), "polling_interval": 0.001})
    collector.start()
    iterator = collector.collect()
    result: list[object] = []
    thread = Thread(target=lambda: result.append(next(iterator)), daemon=True)
    thread.start()
    thread.join(0.2)
    collector.stop()
    assert (
        result
        and collector.windows_reconnects.get_value() == 1
        and collector.bookmark("Security") == 4
    )
