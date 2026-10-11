"""Storage interface.

Defines the contract for components that persist and retrieve
domain objects (events, alerts, detection results).
"""

from abc import ABC, abstractmethod
from uuid import UUID


class Storage(ABC):
    """Abstract persistence backend.

    Implementations may target the local filesystem, SQLite,
    PostgreSQL, Elasticsearch, etc.
    """

    @abstractmethod
    def save(self, collection: str, record_id: UUID, data: dict[str, object]) -> None:
        """Persist a record.

        Args:
            collection: Logical grouping (e.g. ``"events"``, ``"alerts"``).
            record_id: Unique identifier for the record.
            data: Serialised record payload.

        Raises:
            StorageError: If the write fails.
        """

    @abstractmethod
    def load(self, collection: str, record_id: UUID) -> dict[str, object] | None:
        """Retrieve a record by its identifier.

        Args:
            collection: The logical grouping to search.
            record_id: The record's unique ID.

        Returns:
            The record payload, or ``None`` if not found.
        """

    @abstractmethod
    def delete(self, collection: str, record_id: UUID) -> bool:
        """Remove a record.

        Args:
            collection: The logical grouping.
            record_id: The record's unique ID.

        Returns:
            ``True`` if a record was deleted.
        """

    @abstractmethod
    def list_records(self, collection: str, limit: int = 100) -> list[dict[str, object]]:
        """List records from a collection.

        Args:
            collection: The logical grouping.
            limit: Maximum number of records to return.

        Returns:
            A list of record payloads.
        """
