"""Alert lifecycle state enumeration.

Represents the workflow state of an alert from creation through triage.
Lifecycle is independent of severity, priority, and confidence.
"""

from enum import StrEnum


class AlertLifecycleState(StrEnum):
    """Lifecycle states for security alerts.

    Ordered to reflect the natural workflow progression:
    OPEN -> ACKNOWLEDGED -> CLOSED
    """

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    CLOSED = "CLOSED"

    @classmethod
    def from_string(cls, value: str) -> "AlertLifecycleState":
        """Parse a lifecycle state from its case-insensitive name.

        Args:
            value: The lifecycle state name (e.g. ``"open"``).

        Returns:
            The corresponding ``AlertLifecycleState`` member.

        Raises:
            ValueError: If value does not match any member.
        """
        try:
            return cls[value.upper()]
        except KeyError:
            valid = ", ".join(m.value for m in cls)
            raise ValueError(
                f"Unknown alert lifecycle state '{value}'. Valid values: {valid}"
            ) from None
