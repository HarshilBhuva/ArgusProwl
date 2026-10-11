"""Timestamp and duration helper functions.

All timestamps are UTC-aware :class:`datetime.datetime` objects.
"""

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime.

    Returns:
        A :class:`datetime` set to the current UTC instant.
    """
    return datetime.now(UTC)


def iso_format(dt: datetime) -> str:
    """Format a datetime as an ISO-8601 string with ``Z`` suffix for UTC.

    Args:
        dt: The datetime to format.

    Returns:
        An ISO-8601 formatted string (e.g. ``"2025-06-15T12:30:00Z"``).
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 datetime string into a UTC-aware datetime.

    Handles both ``Z`` and ``+00:00`` timezone suffixes.

    Args:
        value: The ISO-8601 string to parse.

    Returns:
        A timezone-aware :class:`datetime`.

    Raises:
        ValueError: If *value* cannot be parsed.
    """
    normalised = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalised)


def elapsed_seconds(start: datetime, end: datetime | None = None) -> float:
    """Calculate elapsed seconds between two datetimes.

    Args:
        start: The start time.
        end: The end time (defaults to ``utc_now()``).

    Returns:
        Elapsed time in seconds as a float.
    """
    if end is None:
        end = utc_now()
    return (end - start).total_seconds()
