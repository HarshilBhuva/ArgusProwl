"""Analyst annotation service.

Provides a bounded, append-only annotation service for analyst-provided
contextual metadata. Annotations are untrusted human-provided context
and must never alter detection behavior, baseline state, or alert semantics.

Phase 5.2 — Analyst Context Hardening:
    - Annotations are contextual human commentary only
    - No labels, categories, or decision-affecting semantics
    - Append-only with explicit tombstone/retraction support
    - Immutable identity with bounded fields
    - Decision-neutral: no effect on detection, confidence, severity, or priority
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from argusprowl.behavior.analyst_annotation import AnalystAnnotation
from argusprowl.behavior.analyst_annotation_persistence import (
    _MAX_ANNOTATIONS_PER_TARGET,
    _MAX_TOTAL_ANNOTATIONS,
    AnalystAnnotationPersistence,
)

logger = logging.getLogger(__name__)

# Input validation bounds
_MAX_TARGET_KEY_LENGTH: int = 256
_MAX_AUTHOR_LENGTH: int = 128
_MAX_COMMENT_LENGTH: int = 512
_MAX_ANNOTATIONS_PER_TARGET_QUERY: int = 50
_MAX_TOTAL_ANNOTATIONS_QUERY: int = 100


class AnalystAnnotationService:
    """Append-only annotation service for analyst context.

    This service provides a bounded, validated interface for analysts to
    add contextual commentary about entities and behaviors. Annotations
    are untrusted and must never influence detection or decision logic.

    Security Properties:
        - All inputs are validated and bounded
        - Annotations are append-only (no edits, only tombstones)
        - No executable or interpreted content
        - Persistence failures are logged but don't disrupt detection
        - Decision-neutral: annotations never affect detection results

    Target Semantics:
        - entity:{entity_type}:{entity_id} — e.g., entity:user:admin
        - behavior:{entity_type}:{entity_id}|dimension:{dimension}|value:{value}
          — e.g., behavior:host:server01|dimension:process_name|value:powershell.exe

    Lifecycle:
        - Create: Add a new annotation
        - Tombstone: Retract an annotation (still visible for audit)
        - Query: Read annotations by target or globally
    """

    # Target key patterns (strict validation)
    _TARGET_ENTITY_PATTERN: re.Pattern[str] = re.compile(r"^entity:[a-zA-Z0-9_]+:[a-zA-Z0-9_.\-]+$")
    _TARGET_BEHAVIOR_PATTERN: re.Pattern[str] = re.compile(
        r"^behavior:[a-zA-Z0-9_]+:[a-zA-Z0-9_.\-]+\|dimension:[a-zA-Z0-9_]+\|value:[a-zA-Z0-9_.\-]+$"
    )

    def __init__(
        self,
        persistence: AnalystAnnotationPersistence | None = None,
        max_annotations_per_target: int = _MAX_ANNOTATIONS_PER_TARGET,
        max_total_annotations: int = _MAX_TOTAL_ANNOTATIONS,
    ) -> None:
        """Initialize annotation service.

        Args:
            persistence: Optional persistence layer. If None, in-memory only.
            max_annotations_per_target: Maximum annotations per target key.
            max_total_annotations: Maximum total annotations in storage.
        """
        self._persistence = persistence
        self._max_annotations_per_target = min(
            max_annotations_per_target, _MAX_ANNOTATIONS_PER_TARGET
        )
        self._max_total_annotations = min(max_total_annotations, _MAX_TOTAL_ANNOTATIONS)

        # In-memory store for when persistence is unavailable
        # target_key -> list of AnalystAnnotation (ordered by created_at desc)
        self._annotations: dict[str, list[AnalystAnnotation]] = {}
        self._all_annotations: list[AnalystAnnotation] = []
        self._active_annotation_count = 0
        self._lock = __import__("threading").RLock()

        # Load persisted state if available
        if persistence is not None:
            persistence.initialize()
            self._load_persisted_state()

    def _load_persisted_state(self) -> None:
        """Load persisted annotations into memory."""
        if self._persistence is None:
            return
        try:
            annotations = self._persistence.load_all_annotations(
                limit=self._max_total_annotations,
                include_tombstoned=False,
            )
            with self._lock:
                self._annotations.clear()
                self._all_annotations.clear()
                self._active_annotation_count = len(annotations)
                for annotation in annotations:
                    target = annotation.target_key
                    if target not in self._annotations:
                        self._annotations[target] = []
                    self._annotations[target].append(annotation)
                    self._all_annotations.append(annotation)
                # Sort by created_at descending
                self._all_annotations.sort(key=lambda a: a.created_at, reverse=True)
                for target in self._annotations:
                    self._annotations[target].sort(key=lambda a: a.created_at, reverse=True)
            logger.info("Loaded %d annotations from persistence", len(annotations))
        except Exception as exc:
            logger.warning("Failed to load persisted annotations: %s", exc)

    def _validate_target_key(self, target_key: str) -> str:
        """Validate a target key.

        Args:
            target_key: The target key to validate.

        Returns:
            The validated target key.

        Raises:
            ValueError: If validation fails.
        """
        if not isinstance(target_key, str):
            raise ValueError("target_key must be a string.")
        if not target_key:
            raise ValueError("target_key must not be empty.")
        if len(target_key) > _MAX_TARGET_KEY_LENGTH:
            raise ValueError(f"target_key exceeds maximum length of {_MAX_TARGET_KEY_LENGTH}.")

        # Validate against known patterns
        if not self._TARGET_ENTITY_PATTERN.match(
            target_key
        ) and not self._TARGET_BEHAVIOR_PATTERN.match(target_key):
            raise ValueError(
                "target_key must match 'entity:type:id' or "
                "'behavior:type:id|dimension:dim|value:val' pattern."
            )

        return target_key

    def _validate_author(self, author: str) -> str:
        """Validate an author identifier.

        Args:
            author: The author to validate.

        Returns:
            The validated author.

        Raises:
            ValueError: If validation fails.
        """
        if not isinstance(author, str):
            raise ValueError("author must be a string.")
        if not author:
            raise ValueError("author must not be empty.")
        if len(author) > _MAX_AUTHOR_LENGTH:
            raise ValueError(f"author exceeds maximum length of {_MAX_AUTHOR_LENGTH}.")
        # Allow alphanumeric, underscores, dots, hyphens
        if not re.match(r"^[a-zA-Z0-9_.\-]+$", author):
            raise ValueError(
                "author must contain only alphanumeric characters, underscores, dots, and hyphens."
            )
        return author

    def _validate_comment(self, comment: str) -> str:
        """Validate a comment.

        Args:
            comment: The comment to validate.

        Returns:
            The validated comment.

        Raises:
            ValueError: If validation fails.
        """
        if not isinstance(comment, str):
            raise ValueError("comment must be a string.")
        if not comment.strip():
            raise ValueError("comment must not be empty.")
        if len(comment) > _MAX_COMMENT_LENGTH:
            raise ValueError(f"comment exceeds maximum length of {_MAX_COMMENT_LENGTH}.")
        # Strip control characters except newline and tab
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", comment)
        return cleaned

    def create_annotation(
        self,
        target_key: str,
        author: str,
        comment: str,
        created_at: datetime | None = None,
    ) -> AnalystAnnotation:
        """Create a new annotation.

        This is an append-only operation. Annotations cannot be edited,
        only tombstoned (retracted).

        Args:
            target_key: Canonical target key (e.g., 'entity:user:admin').
            author: Analyst identifier.
            comment: Human-readable commentary.
            created_at: Optional timestamp (defaults to now if None).

        Returns:
            The created annotation.

        Raises:
            ValueError: If any input is invalid.
            RuntimeError: If annotation limit would be exceeded.
        """
        # Validate inputs
        target_key = self._validate_target_key(target_key)
        author = self._validate_author(author)
        comment = self._validate_comment(comment)

        # Check bounds (tombstoned annotations don't count toward limits)
        with self._lock:
            # Check per-target limit (count non-tombstoned only)
            target_annotations = self._annotations.get(target_key, [])
            target_count = sum(1 for a in target_annotations if not a.tombstoned)
            if target_count >= self._max_annotations_per_target:
                raise RuntimeError(
                    f"Maximum annotations per target ({self._max_annotations_per_target}) reached."
                )

            # Check total limit in O(1); keep the count synchronized under this lock.
            if self._active_annotation_count >= self._max_total_annotations:
                raise RuntimeError(
                    f"Maximum total annotations ({self._max_total_annotations}) reached."
                )

            # Create annotation
            annotation = AnalystAnnotation.create(
                target_key=target_key,
                author=author,
                comment=comment,
                created_at=created_at,
            )

            # Add to in-memory store
            if target_key not in self._annotations:
                self._annotations[target_key] = []
            self._annotations[target_key].append(annotation)
            self._all_annotations.append(annotation)
            self._active_annotation_count += 1

            # Avoid sorting the complete history on every insertion. Public list/query
            # methods sort their bounded result when ordering is actually required.

        # Persist if available
        if self._persistence is not None:
            self._persistence.save_annotation(annotation)

        logger.debug(
            "Created annotation %s for target %s by %s",
            annotation.annotation_id,
            target_key,
            author,
        )
        return annotation

    def get_annotation(self, annotation_id: Any) -> AnalystAnnotation | None:
        """Get an annotation by ID.

        Args:
            annotation_id: The annotation ID to look up.

        Returns:
            The annotation if found, None otherwise.
        """
        from uuid import UUID

        if annotation_id is None:
            return None
        if isinstance(annotation_id, UUID):
            pass
        elif isinstance(annotation_id, str):
            try:
                annotation_id = UUID(annotation_id)
            except (ValueError, TypeError):
                return None
        else:
            return None

        with self._lock:
            # Search in-memory first
            for annotation in self._all_annotations:
                if annotation.annotation_id == annotation_id:
                    return annotation

        # Fall back to persistence
        if self._persistence is not None:
            return self._persistence.load_annotation(annotation_id)

        return None

    def get_annotations_by_target(
        self,
        target_key: str,
        include_tombstoned: bool = False,
        limit: int = _MAX_ANNOTATIONS_PER_TARGET_QUERY,
    ) -> list[dict[str, Any]]:
        """Get annotations for a target.

        Args:
            target_key: The target key to query.
            include_tombstoned: Whether to include tombstoned annotations.
            limit: Maximum annotations to return.

        Returns:
            List of annotation dicts, ordered by created_at descending.
        """
        target_key = self._validate_target_key(target_key)
        bounded_limit = min(limit, _MAX_ANNOTATIONS_PER_TARGET_QUERY)

        with self._lock:
            annotations = list(self._annotations.get(target_key, []))

        # Filter by tombstone status
        if not include_tombstoned:
            annotations = [a for a in annotations if not a.tombstoned]

        # Preserve the public newest-first ordering without sorting on every write.
        annotations.sort(key=lambda a: a.created_at, reverse=True)

        # Apply limit
        annotations = annotations[:bounded_limit]

        # Serialize
        return [
            {
                "annotation_id": str(a.annotation_id),
                "target_key": a.target_key,
                "author": a.author,
                "created_at": a.created_at.isoformat(),
                "comment": a.comment,
                "tombstoned": a.tombstoned,
            }
            for a in annotations
        ]

    def list_annotations(
        self,
        include_tombstoned: bool = False,
        limit: int = _MAX_TOTAL_ANNOTATIONS_QUERY,
    ) -> list[dict[str, Any]]:
        """List all annotations.

        Args:
            include_tombstoned: Whether to include tombstoned annotations.
            limit: Maximum annotations to return.

        Returns:
            List of annotation dicts, ordered by created_at descending.
        """
        bounded_limit = min(limit, _MAX_TOTAL_ANNOTATIONS_QUERY)

        with self._lock:
            annotations = list(self._all_annotations)

        # Filter by tombstone status
        if not include_tombstoned:
            annotations = [a for a in annotations if not a.tombstoned]

        # Preserve newest-first ordering while keeping writes inexpensive.
        annotations.sort(key=lambda a: a.created_at, reverse=True)

        # Apply limit
        annotations = annotations[:bounded_limit]

        # Serialize
        return [
            {
                "annotation_id": str(a.annotation_id),
                "target_key": a.target_key,
                "author": a.author,
                "created_at": a.created_at.isoformat(),
                "comment": a.comment,
                "tombstoned": a.tombstoned,
            }
            for a in annotations
        ]

    def tombstone_annotation(self, annotation_id: Any) -> bool:
        """Tombstone (retract) an annotation.

        This does not delete the annotation; it marks it as retracted.
        Tombstoned annotations remain visible for audit purposes.

        Args:
           annotation_id is None:
            return False
        if isinstance(annotation_id, UUID):
            pass
        elif isinstance(annotation_id, str):
            try:
                annotation_id = UUID(annotation_id)
            except (ValueError, TypeError):
                return False
        else:
        """
        from uuid import UUID

        if not isinstance(annotation_id, UUID):
            try:
                annotation_id = UUID(annotation_id)
            except (ValueError, TypeError):
                return False

        with self._lock:
            # Find the annotation
            annotation = None
            for a in self._all_annotations:
                if a.annotation_id == annotation_id:
                    annotation = a
                    break

            if annotation is None or annotation.tombstoned:
                return False

            # Create tombstoned version
            tombstoned = annotation.with_tombstone()

            # Update in-memory store
            self._active_annotation_count -= 1
            for i, a in enumerate(self._all_annotations):
                if a.annotation_id == annotation_id:
                    self._all_annotations[i] = tombstoned
                    break

            # Update target-specific list
            target_key = tombstoned.target_key
            for i, a in enumerate(self._annotations.get(target_key, [])):
                if a.annotation_id == annotation_id:
                    self._annotations[target_key][i] = tombstoned
                    break

        # Persist tombstone
        if self._persistence is not None:
            self._persistence.tombstone_annotation(annotation_id)

        logger.debug(
            "Tombstoned annotation %s",
            annotation_id,
        )
        return True

    def count_annotations(self, target_key: str | None = None) -> int:
        """Count annotations.

        Args:
            target_key: Optional target key to count for.

        Returns:
            Number of non-tombstoned annotations.
        """
        with self._lock:
            if target_key is not None:
                return sum(
                    1
                    for annotation in self._annotations.get(target_key, [])
                    if not annotation.tombstoned
                )
            return self._active_annotation_count

    def get_annotation_count(self) -> int:
        """Get total annotation count (non-tombstoned).

        Returns:
            Total number of non-tombstoned annotations.
        """
        return self.count_annotations()

    def get_target_annotation_count(self, target_key: str) -> int:
        """Get annotation count for a target.

        Args:
            target_key: The target key to count.

        Returns:
            Number of non-tombstoned annotations for this target.
        """
        return self.count_annotations(target_key)

    def clear(self) -> None:
        """Clear all in-memory annotations (for testing)."""
        with self._lock:
            self._annotations.clear()
            self._all_annotations.clear()
            self._active_annotation_count = 0
