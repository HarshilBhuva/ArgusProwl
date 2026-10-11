"""Tests for the Phase 3.1 normalization contract registries."""

import pytest

from argusprowl.constants.event_type import EventType
from argusprowl.constants.source_type import SourceType


def test_source_type_registry_contains_all_current_sources():
    """Verify all five current source types exist and are stable."""
    assert SourceType.ZEEK == "zeek"
    assert SourceType.SURICATA == "suricata"
    assert SourceType.SYSMON == "sysmon"
    assert SourceType.WINDOWS_EVENT_LOG == "windows_event_log"
    assert SourceType.LINUX_AUDIT == "linux_audit"

    all_sources = SourceType.all()
    assert len(all_sources) >= 5
    assert "zeek" in all_sources
    assert "suricata" in all_sources
    assert "sysmon" in all_sources
    assert "windows_event_log" in all_sources
    assert "linux_audit" in all_sources


def test_source_type_validation():
    """Verify source type validation logic."""
    assert SourceType.is_valid("zeek") is True
    assert SourceType.is_valid("unknown_source") is False

    assert SourceType.require("suricata") == "suricata"
    with pytest.raises(ValueError, match="Unknown source_type"):
        SourceType.require("invalid_source")


def test_event_type_registry_contains_approved_types():
    """Verify all approved initial event types exist and are stable."""
    # Network
    assert EventType.NETWORK_CONNECTION == "network_connection"
    assert EventType.NETWORK_FLOW == "network_flow"
    assert EventType.DNS_QUERY == "dns_query"
    assert EventType.HTTP_TRANSACTION == "http_transaction"
    assert EventType.TLS_CONNECTION == "tls_connection"
    assert EventType.SSH_ACTIVITY == "ssh_activity"

    # File
    assert EventType.FILE_OBSERVATION == "file_observation"
    assert EventType.FILE_CREATE == "file_create"

    # Process
    assert EventType.PROCESS_CREATE == "process_create"
    assert EventType.PROCESS_ACCESS == "process_access"
    assert EventType.IMAGE_LOAD == "image_loaded"
    assert EventType.REMOTE_THREAD == "remote_thread"

    # Authentication / Identity
    assert EventType.AUTHENTICATION_SUCCESS == "authentication_success"
    assert EventType.AUTHENTICATION_FAILURE == "authentication_failure"
    assert EventType.ACCOUNT_CHANGE == "account_change"
    assert EventType.CREDENTIAL_CHANGE == "credential_change"
    assert EventType.PRIVILEGE_CHANGE == "privilege_change"

    # System
    assert EventType.SERVICE_INSTALL == "service_install"
    assert EventType.REGISTRY_CREATE == "registry_create"
    assert EventType.REGISTRY_MODIFY == "registry_modify"
    assert EventType.AUDIT_LOG_CLEARED == "audit_log_cleared"

    # Security Telemetry
    assert EventType.IDS_ALERT == "ids_alert"


def test_event_type_validation():
    """Verify event type validation logic."""
    assert EventType.is_valid("network_connection") is True
    assert EventType.is_valid("unknown_event") is False

    all_events = EventType.all()
    assert len(all_events) >= 20
    assert "network_connection" in all_events
    assert "process_create" in all_events


def test_registries_are_independent():
    """Verify source_type and event_type are independent concepts."""
    # A source type should not be valid as an event type
    assert not EventType.is_valid(SourceType.ZEEK)
    # An event type should not be valid as a source type
    assert not SourceType.is_valid(EventType.NETWORK_CONNECTION)


def test_no_accidental_duplicates_in_event_types():
    """Verify that all event type values are unique."""
    values = [
        value
        for name, value in vars(EventType).items()
        if not name.startswith("_")
        and not callable(value)
        and not isinstance(value, (classmethod, staticmethod))
        and isinstance(value, str)
    ]
    assert len(values) == len(set(values)), "Duplicate event type values found"
