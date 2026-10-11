"""Cache abstraction for local and future distributed deduplication state."""

from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import Iterable

from argusprowl.deduplication.models import DeduplicationState


class DeduplicationCache(ABC):
    @abstractmethod
    def get(self, fingerprint: str) -> DeduplicationState | None: ...

    @abstractmethod
    def put(self, state: DeduplicationState) -> None: ...

    @abstractmethod
    def remove(self, fingerprint: str) -> None: ...

    @abstractmethod
    def items(self) -> Iterable[DeduplicationState]: ...

    @abstractmethod
    def __len__(self) -> int: ...


class InMemoryDeduplicationCache(DeduplicationCache):
    """Bounded LRU state cache. The engine serializes all cache operations."""

    def __init__(self, max_fingerprints: int = 10_000) -> None:
        if not isinstance(max_fingerprints, int) or max_fingerprints <= 0:
            raise ValueError("max_fingerprints must be a positive integer")
        self.max_fingerprints = max_fingerprints
        self._items: OrderedDict[str, DeduplicationState] = OrderedDict()

    def get(self, fingerprint: str) -> DeduplicationState | None:
        state = self._items.get(fingerprint)
        if state is not None:
            self._items.move_to_end(fingerprint)
        return state

    def put(self, state: DeduplicationState) -> None:
        self._items[state.fingerprint] = state
        self._items.move_to_end(state.fingerprint)
        while len(self._items) > self.max_fingerprints:
            self._items.popitem(last=False)

    def remove(self, fingerprint: str) -> None:
        self._items.pop(fingerprint, None)

    def items(self) -> Iterable[DeduplicationState]:
        return tuple(self._items.values())

    def __len__(self) -> int:
        return len(self._items)
