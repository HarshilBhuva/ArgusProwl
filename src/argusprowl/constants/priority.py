"""Alert priority enumeration.

Operational ordering signal derived from alert severity.
Priority is downstream of severity/contextual assessment and is NOT
another confidence or risk score.
"""

from enum import StrEnum


class AlertPriority(StrEnum):
    """Operational alert priority for analyst triage ordering.

    Ordered from lowest to highest so that comparisons like
    ``if priority > AlertPriority.LOW`` work intuitively.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_string(cls, value: str) -> "AlertPriority":
        """Parse a priority from its case-insensitive name.

        Args:
            value: The priority name (e.g. ``"high"``).

        Returns:
            The corresponding ``AlertPriority`` member.

        Raises:
            ValueError: If value does not match any member.
        """
        try:
            return cls[value.upper()]
        except KeyError:
            valid = ", ".join(m.value for m in cls)
            raise ValueError(f"Unknown alert priority '{value}'. Valid values: {valid}") from None

    @property
    def order(self) -> int:
        """Return a deterministic integer ordering for this priority."""
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]
