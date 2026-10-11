"""PostgreSQL adapter placeholder for transactional multi-node deployments.

It intentionally has no driver dependency in Phase 1. A later adapter will
add pooling, migrations, and query-specific repositories behind ``Storage``.
"""

from uuid import UUID

from argusprowl.interfaces.storage import Storage


class PostgreSQLAdapter(Storage):
    """Future relational adapter; unavailable until the PostgreSQL phase."""

    def _unavailable(self) -> None:
        raise NotImplementedError("PostgreSQLAdapter is a Phase 1 architecture skeleton.")

    def save(self, collection: str, record_id: UUID, data: dict[str, object]) -> None:
        self._unavailable()

    def load(self, collection: str, record_id: UUID) -> dict[str, object] | None:
        self._unavailable()

    def delete(self, collection: str, record_id: UUID) -> bool:
        self._unavailable()

    def list_records(self, collection: str, limit: int = 100) -> list[dict[str, object]]:
        self._unavailable()
