"""ClickHouse adapter placeholder for high-volume analytical telemetry."""

from uuid import UUID

from argusprowl.interfaces.storage import Storage


class ClickHouseAdapter(Storage):
    """Future append-oriented analytics adapter; no Phase 1 implementation."""

    def _unavailable(self) -> None:
        raise NotImplementedError("ClickHouseAdapter is a Phase 1 architecture skeleton.")

    def save(self, collection: str, record_id: UUID, data: dict[str, object]) -> None:
        self._unavailable()

    def load(self, collection: str, record_id: UUID) -> dict[str, object] | None:
        self._unavailable()

    def delete(self, collection: str, record_id: UUID) -> bool:
        self._unavailable()

    def list_records(self, collection: str, limit: int = 100) -> list[dict[str, object]]:
        self._unavailable()
