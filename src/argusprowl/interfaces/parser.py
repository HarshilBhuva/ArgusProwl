"""Parser interface.

Defines the contract for components that transform raw log strings
into structured :class:`~app.models.event.Event` objects.
"""

from abc import ABC, abstractmethod

from argusprowl.models.event import Event


class Parser(ABC):
    """Abstract log parser.

    Implementations handle specific log formats (syslog, JSON, CSV, etc.).
    """

    @abstractmethod
    def parse(self, raw_data: str) -> Event:
        """Parse a raw log string into a structured event.

        Args:
            raw_data: The unparsed log line or payload.

        Returns:
            A populated :class:`Event` instance.

        Raises:
            ParserError: If the data cannot be parsed.
        """

    @abstractmethod
    def can_parse(self, raw_data: str) -> bool:
        """Check whether this parser can handle the given payload.

        Args:
            raw_data: The raw log string to inspect.

        Returns:
            ``True`` if this parser recognises the format.
        """
