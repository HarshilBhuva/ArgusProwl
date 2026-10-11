"""Metadata data model.

General-purpose metadata container attached to various domain objects.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(slots=True)
class Metadata:
    """General-purpose metadata record.

    Attributes:
        created_at: UTC creation timestamp.
        updated_at: UTC last-modification timestamp.
        created_by: Identifier of the creator (user, service, plugin).
        version: Schema or record version string.
        labels: Arbitrary string key-value labels.
    """

    created_by: str = ""
    version: str = "1.0.0"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    labels: dict[str, str] = field(default_factory=dict)

    def touch(self) -> None:
        """Update the ``updated_at`` timestamp to *now*."""
        self.updated_at = datetime.now(UTC)
