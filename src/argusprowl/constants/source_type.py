"""Canonical source-type registry for telemetry sources.

Defines the canonical spelling of every telemetry source type supported by
argusprowl.  Collectors and parsers should reference these constants
instead of inventing ad-hoc string literals.

Semantics
---------

``source_type`` answers the question:

    "Which telemetry source produced the original observation?"

It does **not** mean:

- attack category
- detection category
- severity
- event semantic type

A source type is independent of event type.  For example::

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

New source types are added by appending a class attribute here.  Do **not**
rename existing values — they are part of the persisted schema contract.
"""

from __future__ import annotations

from typing import Final


class SourceType:
    """Canonical telemetry source-type identifiers.

    All values are lowercase strings.  Multi-word sources use underscores.
    """

    ZEEK: Final[str] = "zeek"
    SURICATA: Final[str] = "suricata"
    SYSMON: Final[str] = "sysmon"
    WINDOWS_EVENT_LOG: Final[str] = "windows_event_log"
    LINUX_AUDIT: Final[str] = "linux_audit"

    @classmethod
    def all(cls) -> frozenset[str]:
        """Return all registered source-type values.

        Returns:
            Frozen set of canonical source-type strings.
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
    def is_valid(cls, source_type: str) -> bool:
        """Check whether *source_type* is a registered value.

        Args:
            source_type: The source-type string to validate.

        Returns:
            ``True`` if the value is registered, ``False`` otherwise.
        """
        return source_type in cls.all()

    @classmethod
    def require(cls, source_type: str) -> str:
        """Validate *source_type* and return it, or raise.

        Args:
            source_type: The source-type string to validate.

        Returns:
            The validated source-type string.

        Raises:
            ValueError: If *source_type* is not registered.
        """
        if not cls.is_valid(source_type):
            valid = ", ".join(sorted(cls.all()))
            raise ValueError(f"Unknown source_type '{source_type}'. Valid values: {valid}")
        return source_type
