"""Immutable domain models for entity intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class EvidenceKind(StrEnum):
    """Whether a relationship is directly observed or analytically inferred."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"


@dataclass(frozen=True, slots=True)
class EntityIdentity:
    """A stable entity identity aggregated from normalized telemetry."""

    entity_type: str
    entity_id: str
    display_value: str
    first_seen: str
    last_seen: str
    observation_count: int


@dataclass(frozen=True, slots=True)
class EntityEvidenceReference:
    """Reference to the event that supports an entity or relationship."""

    event_id: str
    observed_at: str
    provenance: str
    available: bool


@dataclass(frozen=True, slots=True)
class EntityRelationship:
    """Evidence-backed directed relationship between two entity identities."""

    relationship_id: str
    source_entity_type: str
    source_entity_id: str
    target_entity_type: str
    target_entity_id: str
    relationship_type: str
    evidence_kind: EvidenceKind
    confidence: float
    provenance: str
    first_seen: str
    last_seen: str
    observation_count: int
    evidence_refs: tuple[EntityEvidenceReference, ...] = field(default_factory=tuple)


__all__ = [
    "EntityEvidenceReference",
    "EntityIdentity",
    "EntityRelationship",
    "EvidenceKind",
]
