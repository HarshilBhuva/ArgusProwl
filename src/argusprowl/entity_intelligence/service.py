"""Use cases for indexed, evidence-backed entity intelligence."""

from __future__ import annotations

from uuid import UUID

from argusprowl.entity_intelligence.extractor import normalize_entity_type, normalize_entity_value
from argusprowl.entity_intelligence.models import (
    EntityEvidenceReference,
    EntityIdentity,
    EntityRelationship,
    EvidenceKind,
)
from argusprowl.interfaces.entity_intelligence import EntityIntelligenceRepository


class EntityIntelligenceService:
    """Read and maintain the relational entity intelligence view.

    Event-derived observations are indexed transactionally by the SQLite
    evidence adapter. This service owns query validation and domain projection.
    """

    def __init__(self, repository: EntityIntelligenceRepository) -> None:
        self._repository = repository

    @staticmethod
    def _limit(limit: int) -> int:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValueError("Entity intelligence limit must be between 1 and 500.")
        return limit

    @staticmethod
    def _entity_type(entity_type: str | None) -> str | None:
        return normalize_entity_type(entity_type) if entity_type is not None else None

    @staticmethod
    def _entity_value(entity_type: str, entity_id: str) -> str:
        return normalize_entity_value(entity_type, entity_id)

    @staticmethod
    def _identity(row: dict[str, object]) -> EntityIdentity:
        return EntityIdentity(
            entity_type=str(row["entity_type"]),
            entity_id=str(row["entity_id"]),
            display_value=str(row["display_value"]),
            first_seen=str(row["first_seen"]),
            last_seen=str(row["last_seen"]),
            observation_count=int(row["observation_count"]),
        )

    @staticmethod
    def _evidence(row: dict[str, object]) -> EntityEvidenceReference:
        return EntityEvidenceReference(
            event_id=str(row["event_id"]),
            observed_at=str(row["observed_at"]),
            provenance=str(row["provenance"]),
            available=bool(row["available"]),
        )

    @classmethod
    def _relationship(cls, row: dict[str, object]) -> EntityRelationship:
        refs = row.get("evidence_refs", [])
        evidence_refs = tuple(
            cls._evidence(ref)
            for ref in refs
            if isinstance(ref, dict)
        ) if isinstance(refs, list) else ()
        return EntityRelationship(
            relationship_id=str(row["relationship_id"]),
            source_entity_type=str(row["source_entity_type"]),
            source_entity_id=str(row["source_entity_id"]),
            target_entity_type=str(row["target_entity_type"]),
            target_entity_id=str(row["target_entity_id"]),
            relationship_type=str(row["relationship_type"]),
            evidence_kind=EvidenceKind(str(row["evidence_kind"])),
            confidence=float(row["confidence"]),
            provenance=str(row["provenance"]),
            first_seen=str(row["first_seen"]),
            last_seen=str(row["last_seen"]),
            observation_count=int(row["observation_count"]),
            evidence_refs=evidence_refs,
        )

    def list_entities(
        self, *, entity_type: str | None = None, limit: int = 100
    ) -> tuple[EntityIdentity, ...]:
        """List the most recently observed entities, optionally by type."""
        bounded_limit = self._limit(limit)
        canonical_type = self._entity_type(entity_type)
        rows = self._repository.list_entity_intelligence_entities(
            entity_type=canonical_type,
            limit=bounded_limit,
        )
        return tuple(self._identity(row) for row in rows)

    def get_entity(self, entity_type: str, entity_id: str) -> EntityIdentity | None:
        """Resolve one entity by its canonical type and normalized value."""
        canonical_type = normalize_entity_type(entity_type)
        normalized_value = self._entity_value(canonical_type, entity_id)
        row = self._repository.get_entity_intelligence_entity(
            canonical_type,
            normalized_value,
        )
        return self._identity(row) if row is not None else None

    def get_relationships(
        self,
        entity_type: str,
        entity_id: str,
        *,
        direction: str = "both",
        limit: int = 100,
    ) -> tuple[EntityRelationship, ...]:
        """Return bounded inbound, outbound, or bidirectional pivots."""
        if direction not in {"both", "inbound", "outbound"}:
            raise ValueError("direction must be 'both', 'inbound', or 'outbound'.")
        bounded_limit = self._limit(limit)
        canonical_type = normalize_entity_type(entity_type)
        normalized_value = self._entity_value(canonical_type, entity_id)
        rows = self._repository.list_entity_intelligence_relationships(
            canonical_type,
            normalized_value,
            direction=direction,
            limit=bounded_limit,
        )
        return tuple(self._relationship(row) for row in rows)

    def get_evidence(
        self,
        entity_type: str,
        entity_id: str,
        *,
        limit: int = 100,
    ) -> tuple[EntityEvidenceReference, ...]:
        """Return evidence references and explicitly report retention availability."""
        bounded_limit = self._limit(limit)
        canonical_type = normalize_entity_type(entity_type)
        normalized_value = self._entity_value(canonical_type, entity_id)
        rows = self._repository.list_entity_intelligence_evidence(
            canonical_type,
            normalized_value,
            limit=bounded_limit,
        )
        return tuple(self._evidence(row) for row in rows)

    def record_inferred_relationship(
        self,
        source_entity_type: str,
        source_entity_id: str,
        target_entity_type: str,
        target_entity_id: str,
        relationship_type: str,
        *,
        confidence: float,
        provenance: str,
        evidence_event_ids: tuple[str, ...],
    ) -> None:
        """Persist an explicitly inferred edge with durable supporting references."""
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("confidence must be a number between 0 and 1.")
        if not 0.0 <= float(confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1.")
        if not isinstance(provenance, str) or not provenance.strip() or len(provenance) > 256:
            raise ValueError("provenance must contain between 1 and 256 characters.")
        if not evidence_event_ids or len(evidence_event_ids) > 100:
            raise ValueError("An inferred relationship requires between 1 and 100 evidence events.")
        normalized_ids: list[str] = []
        for event_id in evidence_event_ids:
            try:
                normalized_ids.append(str(UUID(str(event_id))))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError("evidence_event_ids must contain UUID values.") from exc
        source_type = normalize_entity_type(source_entity_type)
        source_value = self._entity_value(source_type, source_entity_id)
        target_type = normalize_entity_type(target_entity_type)
        target_value = self._entity_value(target_type, target_entity_id)
        normalized_relationship = relationship_type.strip().upper()
        if not normalized_relationship or len(normalized_relationship) > 64:
            raise ValueError("relationship_type must contain between 1 and 64 characters.")
        self._repository.add_inferred_entity_relationship(
            source_type,
            source_value,
            target_type,
            target_value,
            normalized_relationship,
            confidence=float(confidence),
            provenance=provenance.strip(),
            evidence_event_ids=tuple(sorted(set(normalized_ids))),
        )


__all__ = ["EntityIntelligenceService"]
