"""Canonical event-type taxonomy registry.

Defines the canonical spelling of every semantic event type supported by
argusprowl.  Collectors and parsers should reference these constants
instead of inventing ad-hoc string literals.

Semantics
---------

``event_type`` answers the question:

    "What kind of security-relevant observation is this?"

It does **not** mean:

- who produced the telemetry (that is ``source_type``)
- attack category
- detection category
- severity

A semantic event type is independent of source type.  For example::

    source_type = SourceType.ZEEK
    event_type  = EventType.NETWORK_CONNECTION

Another source may produce the same semantic event type::

    source_type = SourceType.SURICATA
    event_type  = EventType.NETWORK_CONNECTION

This is desirable — the detection engine can eventually reason about
``event_type == network_connection`` without knowing whether the source
was Zeek or Suricata.

Extensibility
-------------

New event types are added by appending a class attribute here.  Do **not**
rename existing values — they are part of the persisted schema contract.
Do **not** force an existing event into a taxonomy category unless the
mapping is semantically defensible.

Unknown Events
--------------

The contract explicitly supports unknown/unrecognized source events.
Do not discard unknown telemetry merely because it does not fit the current
taxonomy.  Existing collectors may continue using source-specific forms
such as ``suricata_unknown`` or ``linux_audit_unknown``.
"""

from __future__ import annotations

from typing import Final


class EventType:
    """Canonical semantic event-type identifiers.

    All values are lowercase strings.  Multi-word types use underscores.
    """

    # ------------------------------------------------------------------ NETWORK

    NETWORK_CONNECTION: Final[str] = "network_connection"
    """A telemetry observation representing a network connection between a source and destination endpoint."""

    NETWORK_FLOW: Final[str] = "network_flow"
    """A telemetry observation representing aggregated network flow statistics."""

    DNS_QUERY: Final[str] = "dns_query"
    """A telemetry observation representing a DNS query and its response."""

    HTTP_TRANSACTION: Final[str] = "http_transaction"
    """A telemetry observation representing an HTTP request and response."""

    TLS_CONNECTION: Final[str] = "tls_connection"
    """A telemetry observation representing a TLS handshake and connection."""

    SSH_ACTIVITY: Final[str] = "ssh_activity"
    """A telemetry observation representing SSH protocol activity."""

    # ------------------------------------------------------------------ FILE

    FILE_OBSERVATION: Final[str] = "file_observation"
    """A telemetry observation representing metadata about a file seen in transit or at rest."""

    FILE_CREATE: Final[str] = "file_create"
    """A telemetry observation indicating creation of a file on a host."""

    # ------------------------------------------------------------------ PROCESS

    PROCESS_CREATE: Final[str] = "process_create"
    """A telemetry observation indicating creation/start of a process."""

    PROCESS_ACCESS: Final[str] = "process_access"
    """A telemetry observation indicating one process accessing another."""

    IMAGE_LOAD: Final[str] = "image_loaded"
    """A telemetry observation indicating a module/library was loaded into a process."""

    REMOTE_THREAD: Final[str] = "remote_thread"
    """A telemetry observation indicating a thread was created in another process."""

    PROCESS_EXECUTION: Final[str] = "process_execution"
    """A telemetry observation indicating process execution (e.g., Linux execve)."""

    # ------------------------------------------------------------------ AUTHENTICATION / IDENTITY

    AUTHENTICATION_SUCCESS: Final[str] = "authentication_success"
    """A telemetry observation indicating a successful authentication attempt."""

    AUTHENTICATION_FAILURE: Final[str] = "authentication_failure"
    """A telemetry observation indicating a failed authentication attempt."""

    AUTHENTICATION: Final[str] = "authentication"
    """A telemetry observation indicating an authentication event (success or failure)."""

    ACCOUNT_CHANGE: Final[str] = "account_change"
    """A telemetry observation indicating an account was created, modified, or deleted."""

    CREDENTIAL_CHANGE: Final[str] = "credential_change"
    """A telemetry observation indicating a credential was modified."""

    PRIVILEGE_CHANGE: Final[str] = "privilege_change"
    """A telemetry observation indicating a privilege assignment or escalation."""

    SESSION_START: Final[str] = "session_start"
    """A telemetry observation indicating the start of a user session."""

    SESSION_END: Final[str] = "session_end"
    """A telemetry observation indicating the end of a user session."""

    ACCOUNT_ACTIVITY: Final[str] = "account_activity"
    """A telemetry observation indicating general account activity."""

    COMMAND_ACTIVITY: Final[str] = "command_activity"
    """A telemetry observation indicating command execution by a user."""

    ROLE_CHANGE: Final[str] = "role_change"
    """A telemetry observation indicating a user role change."""

    CREDENTIAL_ACTIVITY: Final[str] = "credential_activity"
    """A telemetry observation indicating general credential activity."""

    CREDENTIAL_ACQUISITION: Final[str] = "credential_acquisition"
    """A telemetry observation indicating credential acquisition."""

    CREDENTIAL_REFRESH: Final[str] = "credential_refresh"
    """A telemetry observation indicating credential refresh."""

    CREDENTIAL_DISPOSAL: Final[str] = "credential_disposal"
    """A telemetry observation indicating credential disposal."""

    EXPLICIT_CREDENTIAL_LOGON: Final[str] = "explicit_credential_logon"
    """A telemetry observation indicating a logon using explicit credentials."""

    PRIVILEGE_ASSIGNMENT: Final[str] = "privilege_assignment"
    """A telemetry observation indicating privilege assignment."""

    ACCOUNT_CREATE: Final[str] = "account_create"
    """A telemetry observation indicating account creation."""

    GROUP_MEMBERSHIP_CHANGE: Final[str] = "group_membership_change"
    """A telemetry observation indicating a change in group membership."""

    # ------------------------------------------------------------------ SYSTEM

    SERVICE_INSTALL: Final[str] = "service_install"
    """A telemetry observation indicating a system service was installed."""

    REGISTRY_CREATE: Final[str] = "registry_create"
    """A telemetry observation indicating a registry key was created."""

    REGISTRY_MODIFY: Final[str] = "registry_modify"
    """A telemetry observation indicating a registry key or value was modified."""

    REGISTRY_SET: Final[str] = "registry_set"
    """A telemetry observation indicating a registry value was set."""

    REGISTRY_RENAME: Final[str] = "registry_rename"
    """A telemetry observation indicating a registry key or value was renamed."""

    AUDIT_LOG_CLEARED: Final[str] = "audit_log_cleared"
    """A telemetry observation indicating a system audit log was cleared."""

    # ------------------------------------------------------------------ SECURITY TELEMETRY

    IDS_ALERT: Final[str] = "ids_alert"
    """A telemetry observation representing an alert from an Intrusion Detection System."""

    @classmethod
    def all(cls) -> frozenset[str]:
        """Return all registered event-type values.

        Returns:
            Frozen set of canonical event-type strings.
        """
        return frozenset(
            value
            for name, value in vars(cls).items()
            if not name.startswith("_")
            and not callable(value)
            and not isinstance(value, (classmethod, staticmethod))
            and isinstance(value, str)
        )

    @classmethod
    def is_valid(cls, event_type: str) -> bool:
        """Check whether *event_type* is a registered value.

        Args:
            event_type: The event-type string to validate.

        Returns:
            ``True`` if the value is registered, ``False`` otherwise.
        """
        return event_type in cls.all()
