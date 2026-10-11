"""Redis adapter placeholder for short-lived cache and streaming workloads."""

from uuid import UUID

from argusprowl.interfaces.storage import Storage


class RedisAdapter(Storage):
    """Future low-latency adapter; intentionally unavailable in Phase 1."""

    def _unavailable(self) -> None:
        raise NotImplementedError("RedisAdapter is a Phase 1 architecture skeleton.")

    def save(self, collection: str, record_id: UUID, data: dict[str, object]) -> None:
        self._unavailable()

    def load(self, collection: str, record_id: UUID) -> dict[str, object] | None:
        self._unavailable()

    def delete(self, collection: str, record_id: UUID) -> bool:
        self._unavailable()

    def list_records(self, collection: str, limit: int = 100) -> list[dict[str, object]]:
        self._unavailable()
