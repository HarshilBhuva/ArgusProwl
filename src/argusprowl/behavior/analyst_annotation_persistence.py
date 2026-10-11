"""Persistence layer for analyst annotations.

Provides SQLite-backed storage for AnalystAnnotationService annotations.
Annotations are append-only with explicit tombstone support.

Phase 5.2 — Analyst Context Hardening:
    - Bounded storage (max_total_annotations)
    - Parameterized SQL (no injection risk)
    - Failure-tolerant (persistence failures don't disrupt detection)
    - Schema versioning for future migrations
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from uuid import UUID

from argusprowl.behavior.analyst_annotation import AnalystAnnotation

logger = logging.getLogger(__name__)

# Schema version for migration tracking
_SCHEMA_VERSION = 1

# Maximum annotations per target key
_MAX_ANNOTATIONS_PER_TARGET: int = 50

# Maximum total annotations
_MAX_TOTAL_ANNOTATIONS: int = 10_000


class AnalystAnnotationPersistence:
    """SQLite-backed persistence for analyst annotations.

    Thread-safe for concurrent reads and writes. Persistence failures are
    logged but do not disrupt the annotation service or detection pipeline.

    Attributes:
        db_path: Path to the SQLite database file.
        max_total_annotations: Maximum total annotations to store.
    """

    def __init__(
        self,
        db_path: str | Path,
        max_total_annotations: int = _MAX_TOTAL_ANNOTATIONS,
    ) -> None:
        """Initialize persistence layer.

        Args:
            db_path: Path to SQLite database file.
            max_total_annotations: Maximum total annotations to persist.
        """
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._max_total_annotations = max_total_annotations
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._initialized = False

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create database connection.

        Returns:
            SQLite connection.
        """
        if self._connection is None:
            self._connection = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
            )
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
        return self._connection

    def initialize(self) -> None:
        """Create tables if they don't exist."""
        with self._lock:
            try:
                conn = self._get_connection()
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS analyst_annotations (
                        annotation_id TEXT PRIMARY KEY,
                        target_key TEXT NOT NULL,
                        author TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        comment TEXT NOT NULL,
                        tombstoned INTEGER NOT NULL DEFAULT 0,
                        created_at_sort INTEGER NOT NULL DEFAULT 0
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_annotations_target
                    ON analyst_annotations(target_key, created_at_sort DESC)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_annotations_created_at
                    ON analyst_annotations(created_at DESC)
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                """)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO metadata (key, value)
                    VALUES ('schema_version', ?)
                """,
                    (str(_SCHEMA_VERSION),),
                )
                conn.commit()
                self._initialized = True
                logger.info("Analyst annotation persistence initialized at %s", self._db_path)
            except sqlite3.DatabaseError as exc:
                logger.warning("Failed to initialize annotation persistence: %s", exc)
                self._initialized = False

    def save_annotation(self, annotation: AnalystAnnotation) -> bool:
        """Save an annotation to storage.

        Args:
            annotation: The annotation to save.

        Returns:
            True if saved successfully, False otherwise.
        """
        if not self._initialized:
            return False

        try:
            with self._lock:
                conn = self._get_connection()
                conn.execute(
                    """
                    INSERT OR REPLACE INTO analyst_annotations
                    (annotation_id, target_key, author, created_at, comment, tombstoned, created_at_sort)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(annotation.annotation_id),
                        annotation.target_key,
                        annotation.author,
                        annotation.created_at.isoformat(),
                        annotation.comment,
                        1 if annotation.tombstoned else 0,
                        int(annotation.created_at.timestamp()),
                    ),
                )
                conn.commit()
                return True
        except (sqlite3.Error, TypeError) as exc:
            logger.warning("Failed to save annotation: %s", exc)
            return False

    def load_annotation(self, annotation_id: UUID) -> AnalystAnnotation | None:
        """Load a single annotation by ID.

        Args:
            annotation_id: The annotation ID to load.

        Returns:
            The annotation if found, None otherwise.
        """
        if not self._initialized:
            return None

        try:
            with self._lock:
                conn = self._get_connection()
                row = conn.execute(
                    "SELECT * FROM analyst_annotations WHERE annotation_id=?",
                    (str(annotation_id),),
                ).fetchone()

            if row is None:
                return None

            return AnalystAnnotation(
                annotation_id=UUID(row[0]),
                target_key=row[1],
                author=row[2],
                created_at=datetime.fromisoformat(row[3]),
                comment=row[4],
                tombstoned=bool(row[5]),
            )
        except (sqlite3.Error, ValueError) as exc:
            logger.warning("Failed to load annotation: %s", exc)
            return None

    def load_annotations_by_target(
        self,
        target_key: str,
        limit: int = _MAX_ANNOTATIONS_PER_TARGET,
        include_tombstoned: bool = False,
    ) -> list[AnalystAnnotation]:
        """Load annotations for a specific target.

        Args:
            target_key: The target key to query.
            limit: Maximum annotations to return.
            include_tombstoned: Whether to include tombstoned annotations.

        Returns:
            List of annotations ordered by created_at descending.
        """
        if not self._initialized:
            return []

        try:
            with self._lock:
                conn = self._get_connection()
                if include_tombstoned:
                    rows = conn.execute(
                        """
                        SELECT * FROM analyst_annotations
                        WHERE target_key=?
                        ORDER BY created_at_sort DESC
                        LIMIT ?
                        """,
                        (target_key, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT * FROM analyst_annotations
                        WHERE target_key=? AND tombstoned=0
                        ORDER BY created_at_sort DESC
                        LIMIT ?
                        """,
                        (target_key, limit),
                    ).fetchall()

            return [
                AnalystAnnotation(
                    annotation_id=UUID(row[0]),
                    target_key=row[1],
                    author=row[2],
                    created_at=datetime.fromisoformat(row[3]),
                    comment=row[4],
                    tombstoned=bool(row[5]),
                )
                for row in rows
            ]
        except (sqlite3.Error, ValueError) as exc:
            logger.warning("Failed to load annotations by target: %s", exc)
            return []

    def load_all_annotations(
        self,
        limit: int = _MAX_TOTAL_ANNOTATIONS,
        include_tombstoned: bool = False,
    ) -> list[AnalystAnnotation]:
        """Load all annotations with optional tombstone inclusion.

        Args:
            limit: Maximum annotations to return.
            include_tombstoned: Whether to include tombstoned annotations.

        Returns:
            List of annotations ordered by created_at descending.
        """
        if not self._initialized:
            return []

        try:
            with self._lock:
                conn = self._get_connection()
                if include_tombstoned:
                    rows = conn.execute(
                        """
                        SELECT * FROM analyst_annotations
                        ORDER BY created_at_sort DESC
                        LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT * FROM analyst_annotations
                        WHERE tombstoned=0
                        ORDER BY created_at_sort DESC
                        LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()

            return [
                AnalystAnnotation(
                    annotation_id=UUID(row[0]),
                    target_key=row[1],
                    author=row[2],
                    created_at=datetime.fromisoformat(row[3]),
                    comment=row[4],
                    tombstoned=bool(row[5]),
                )
                for row in rows
            ]
        except (sqlite3.Error, ValueError) as exc:
            logger.warning("Failed to load all annotations: %s", exc)
            return []

    def count_annotations_by_target(self, target_key: str) -> int:
        """Count annotations for a target.

        Args:
            target_key: The target key to count.

        Returns:
            Number of non-tombstoned annotations for this target.
        """
        if not self._initialized:
            return 0

        try:
            with self._lock:
                conn = self._get_connection()
                row = conn.execute(
                    """
                    SELECT COUNT(*) FROM analyst_annotations
                    WHERE target_key=? AND tombstoned=0
                    """,
                    (target_key,),
                ).fetchone()
            return row[0] if row else 0
        except sqlite3.Error as exc:
            logger.warning("Failed to count annotations: %s", exc)
            return 0

    def count_total_annotations(self) -> int:
        """Count total non-tombstoned annotations.

        Returns:
            Total number of non-tombstoned annotations.
        """
        if not self._initialized:
            return 0

        try:
            with self._lock:
                conn = self._get_connection()
                row = conn.execute(
                    "SELECT COUNT(*) FROM analyst_annotations WHERE tombstoned=0"
                ).fetchone()
            return row[0] if row else 0
        except sqlite3.Error as exc:
            logger.warning("Failed to count total annotations: %s", exc)
            return 0

    def tombstone_annotation(self, annotation_id: UUID) -> bool:
        """Tombstone (retract) an annotation.

        Args:
            annotation_id: The annotation to tombstone.

        Returns:
            True if successfully tombstoned, False otherwise.
        """
        if not self._initialized:
            return False

        try:
            with self._lock:
                conn = self._get_connection()
                cursor = conn.execute(
                    """
                    UPDATE analyst_annotations
                    SET tombstoned=1
                    WHERE annotation_id=? AND tombstoned=0
                    """,
                    (str(annotation_id),),
                )
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as exc:
            logger.warning("Failed to tombstone annotation: %s", exc)
            return False

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
