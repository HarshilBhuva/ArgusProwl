from pathlib import Path

import pytest

from argusprowl.collectors.linux_audit import (
    LinuxAuditBookmarkStore,
    LinuxAuditParser,
    LinuxAuditRawRecord,
)
from argusprowl.collectors.linux_audit.events import AuditRecordAssembler
from argusprowl.constants.event_type import EventType
from argusprowl.constants.source_type import SourceType
from argusprowl.exceptions.exceptions import ParserError


def _record(record_type: str, serial: int = 10, fields: str = "") -> LinuxAuditRawRecord:
    return LinuxAuditRawRecord(f"type={record_type} msg=audit(1710000000.123:{serial}): {fields}")


@pytest.mark.parametrize(
    "record_type",
    [
        "SYSCALL",
        "EXECVE",
        "USER_LOGIN",
        "USER_START",
        "USER_ACCT",
        "USER_CMD",
        "USER_ROLE_CHANGE",
        "USER_CHAUTHTOK",
        "CRED_ACQ",
        "CRED_REFR",
        "CRED_DISP",
        "USER_END",
    ],
)
def test_parser_maps_supported_audit_types(record_type: str) -> None:
    event = LinuxAuditParser().parse(
        _record(record_type, serial=15, fields='acct="alice" exe="/usr/bin/id" addr=10.1.2.3')
    )
    assert (
        event.source_type == SourceType.LINUX_AUDIT
        and event.attributes["audit_record_type"] == record_type
    )
    assert event.source_record_id == "15"
    assert event.username == "alice" and event.process_name == "/usr/bin/id"
    assert event.src_ip == "10.1.2.3"


def test_user_login_res_type_resolution() -> None:
    parser = LinuxAuditParser()
    success_event = parser.parse(_record("USER_LOGIN", fields='acct="alice" res=success'))
    assert success_event.event_type == EventType.AUTHENTICATION_SUCCESS

    failure_event = parser.parse(_record("USER_LOGIN", fields='acct="bob" res=failed'))
    assert failure_event.event_type == EventType.AUTHENTICATION_FAILURE

    unknown_res_event = parser.parse(_record("USER_LOGIN", fields='acct="charlie"'))
    assert unknown_res_event.event_type == EventType.AUTHENTICATION


def test_parser_source_record_id_and_serialization() -> None:
    parser = LinuxAuditParser()
    event = parser.parse(_record("SYSCALL", serial=42, fields='exe="/bin/ls"'))
    assert event.source_record_id == "42"
    assert event.metadata["audit_serial"] == "42"
    restored = type(event).from_dict(event.to_dict())
    assert restored.source_record_id == "42"

    no_serial_record = LinuxAuditRawRecord('type=SYSCALL exe="/bin/ls"')
    no_serial_event = parser.parse(no_serial_record)
    assert no_serial_event.source_record_id is None


def test_grouping_reconstructs_execve_and_is_bounded() -> None:
    parser = LinuxAuditParser()
    assembler = AuditRecordAssembler(1.0, 1)
    syscall = _record("SYSCALL", serial=10, fields='exe="/usr/bin/python" pid=12 success=yes')
    execve = _record("EXECVE", serial=10, fields='argc=2 a1="--version" a0="python"')
    assert not assembler.add("10", "SYSCALL", syscall, 0)
    assert not assembler.add("10", "EXECVE", execve, 0)
    event = parser.parse_group(assembler.flush()[0])
    assert (
        event.event_type == EventType.PROCESS_EXECUTION and event.command_line == "python --version"
    )
    assert event.source_record_id == "10"
    assert event.attributes["execve_arguments"] == {"0": "python", "1": "--version"}
    assert assembler.add("11", "SYSCALL", syscall, 0) == []
    assert len(assembler.add("12", "SYSCALL", syscall, 0)) == 1


def test_syscall_event_type_semantics() -> None:
    parser = LinuxAuditParser()
    # Test A: SYSCALL with non-exec syscall must NOT become process_execution
    non_exec = parser.parse(_record("SYSCALL", fields='syscall=chmod exe="/usr/bin/chmod"'))
    assert non_exec.event_type != EventType.PROCESS_EXECUTION
    assert non_exec.event_type == "linux_audit_unknown"

    # Test B: SYSCALL with execve / execveat -> process_execution
    exec_syscall = parser.parse(_record("SYSCALL", fields='syscall=execve exe="/bin/ls"'))
    assert exec_syscall.event_type == EventType.PROCESS_EXECUTION

    execat_syscall = parser.parse(_record("SYSCALL", fields='syscall=execveat exe="/bin/ls"'))
    assert execat_syscall.event_type == EventType.PROCESS_EXECUTION

    # Test C: EXECVE -> process_execution
    execve_event = parser.parse(_record("EXECVE", fields='a0="ls" a1="-l"'))
    assert execve_event.event_type == EventType.PROCESS_EXECUTION


def test_username_vs_uid_semantics() -> None:
    parser = LinuxAuditParser()
    # Test D: Record with acct="alice", auid=1000, uid=0 -> username == "alice"
    event_with_acct = parser.parse(
        _record(
            "USER_LOGIN",
            fields='acct="alice" auid=1000 uid=0 euid=0 suid=0 fsuid=0 gid=100 egid=100 ses=5',
        )
    )
    assert event_with_acct.username == "alice"

    # Test E: Record with auid=1000, uid=0 but no textual username -> username is None
    event_numeric_only = parser.parse(
        _record(
            "SYSCALL",
            fields="syscall=execve auid=1000 uid=0 euid=0 suid=0 fsuid=0 gid=100 egid=100 ses=5",
        )
    )
    assert event_numeric_only.username is None

    # Test F: auid/uid/euid/etc remain preserved in attributes
    attrs = event_numeric_only.attributes
    assert attrs["auid"] == "1000"
    assert attrs["uid"] == "0"
    assert attrs["euid"] == "0"
    assert attrs["suid"] == "0"
    assert attrs["fsuid"] == "0"
    assert attrs["gid"] == "100"
    assert attrs["egid"] == "100"
    assert attrs["ses"] == "5"


def test_parser_and_bookmark_handle_invalid_and_restart(tmp_path: Path) -> None:
    with pytest.raises(ParserError):
        LinuxAuditParser().parse("not audit")
    path = tmp_path / "bookmark.json"
    store = LinuxAuditBookmarkStore(path)
    assert store.load() is None
    store.save(4, 99)
    assert LinuxAuditBookmarkStore(path).load() == {"inode": 4, "offset": 99}
