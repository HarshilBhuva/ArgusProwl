"""Log source interface.

Defines the contract for components that produce raw log data
for ingestion into the platform.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterator


class LogSource(ABC):
    """Abstract log data source.

    Implementations might read from files, syslog, Windows Event Log,
    network sockets, or cloud APIs.
    """

    @abstractmethod
    def connect(self) -> None:
        """Establish a connection to the underlying data source.

        Raises:
            StorageError: If the connection cannot be established.
        """

    @abstractmethod
    def disconnect(self) -> None:
        """Cleanly release the data source connection."""

    @abstractmethod
    def read_events(self) -> Iterator[str]:
        """Yield raw event payloads from the source.

        Yields:
            Raw string payloads, one per event.
        """

    @abstractmethod
    def is_connected(self) -> bool:
        """Return whether the source connection is active."""
