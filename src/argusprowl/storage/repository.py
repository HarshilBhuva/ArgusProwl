"""Repository boundary keeping persistence details out of use cases."""

from dataclasses import asdict, is_dataclass
from typing import TypeVar
from uuid import UUID

from argusprowl.interfaces.storage import Storage

T = TypeVar("T")


class Repository[T]:
    def __init__(self, storage: Storage, collection: str) -> None:
        self._storage, self._collection = storage, collection

    def save(self, entity: T, entity_id: UUID) -> None:
        payload = asdict(entity) if is_dataclass(entity) else dict(entity)  # type: ignore[arg-type]
        self._storage.save(self._collection, entity_id, payload)

    def get(self, entity_id: UUID) -> dict[str, object] | None:
        return self._storage.load(self._collection, entity_id)

    def list(self, limit: int = 100) -> list[dict[str, object]]:
        return self._storage.list_records(self._collection, limit)
