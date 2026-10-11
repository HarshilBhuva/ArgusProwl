"""Source collector extension point."""

from abc import ABC, abstractmethod
from collections.abc import Iterator

from argusprowl.models.event import Event


class Collector(ABC):
    """Produces raw source events without exposing source mechanics to the pipeline."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def collect(self) -> Iterator[Event]: ...

    @abstractmethod
    def close(self) -> None: ...
