"""Repository contract for evidence-backed entity intelligence."""

from __future__ import annotations

from typing import Protocol


class EntityIntelligenceRepository(Protocol):
    """Indexed persistence contract used by entity-intelligence use cases."""

    def list_entity_intelligence_entities(
        self, *, entity_type: str | None = None, limit: int = 100
    ) -> list[dict[str, object]]: ...

    def get_entity_intelligence_entity(
        self, entity_type: str, entity_value: str
    ) -> dict[str, object] | None: ...

    def list_entity_intelligence_relationships(
        self, entity_type: str, entity_value: str, *, direction: str = "both", limit: int = 100
    ) -> list[dict[str, object]]: ...

    def list_entity_intelligence_evidence(
        self, entity_type: str, entity_value: str, *, limit: int = 100
    ) -> list[dict[str, object]]: ...

    def add_inferred_entity_relationship(
        self,
        source_entity_type: str,
        source_entity_value: str,
        target_entity_type: str,
        target_entity_value: str,
        relationship_type: str,
        *,
        confidence: float,
        provenance: str,
        evidence_event_ids: tuple[str, ...],
    ) -> None: ...
