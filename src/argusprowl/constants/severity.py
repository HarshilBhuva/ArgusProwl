"""Severity level enumeration.

Maps threat and log severity to integer weights for comparison and filtering.
"""

from enum import IntEnum


class Severity(IntEnum):
    """Severity levels for alerts, events, and detections.

    Ordered from lowest to highest so that comparisons like
    ``if severity >= Severity.HIGH`` work intuitively.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse a severity from its case-insensitive name.

        Args:
            value: The severity name (e.g. ``"high"``).

        Returns:
            The corresponding ``Severity`` member.

        Raises:
            ValueError: If *value* does not match any member.
        """
        try:
            return cls[value.upper()]
        except KeyError:
            valid = ", ".join(m.name for m in cls)
            raise ValueError(f"Unknown severity '{value}'. Valid values: {valid}") from None
