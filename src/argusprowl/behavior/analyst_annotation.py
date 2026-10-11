"""Analyst annotation data model.

Represents an immutable, append-only annotation created by an analyst.
Annotations are untrusted human-provided context and must never alter
detection behavior, baseline state, or alert semantics.

Phase 5.2 — Analyst Context Hardening:
    - Annotations are contextual human commentary only
    - No labels, categories, or decision-affecting semantics
    - Append-only with explicit tombstone/retraction support
    - Immutable identity with bounded fields
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class AnalystAnnotation:
    """Immutable analyst annotation.

    Represents a piece of contextual human commentary about an entity or
    behavior. Annotations are untrusted and must never influence detection
    or decision logic.

    Attributes:
        annotation_id: Unique identifier for this annotation.
        target_key: Canonical target key (e.g., 'entity:user:admin').
        author: Analyst identifier who created this annotation.
        created_at: UTC timestamp when the annotation was created.
        comment: Human-readable commentary text.
        tombstoned: Whether this annotation has been retracted.
            False = active, True = retracted (still visible for audit).
    """

    annotation_id: UUID
    target_key: str
    author: str
    created_at: datetime
    comment: str
    tombstoned: bool = False

    @classmethod
    def create(
        cls,
        target_key: str,
        author: str,
        comment: str,
        created_at: datetime | None = None,
    ) -> AnalystAnnotation:
        """Factory method to create a new annotation.

        Args:
            target_key: Canonical target key.
            author: Analyst identifier.
            comment: Human-readable commentary.
            created_at: UTC timestamp (defaults to now if None).

        Returns:
            New AnalystAnnotation instance.
        """
        if created_at is None:
            created_at = datetime.now(UTC)
        elif created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware UTC.")

        return cls(
            annotation_id=uuid4(),
            target_key=target_key,
            author=author,
            created_at=created_at,
            comment=comment,
            tombstoned=False,
        )

    def with_tombstone(self) -> AnalystAnnotation:
        """Return a new annotation with tombstoned=True.

        Returns:
            New AnalystAnnotation with tombstoned set to True.
        """
        return AnalystAnnotation(
            annotation_id=self.annotation_id,
            target_key=self.target_key,
            author=self.author,
            created_at=self.created_at,
            comment=self.comment,
            tombstoned=True,
        )
