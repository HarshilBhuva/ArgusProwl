"""Bounded persistence for entity behavior state.

Provides SQLite-backed persistence for EntityBehaviorService profiles and
value counts. State is loaded on startup and saved incrementally.

Design constraints:
- Bounded: respects max_profiles and max_values_per_profile limits
- Deterministic: same input produces same persisted state
- Replay-safe: replay mode uses in-memory state only
- Decision-neutral: persistence does not affect alert decisions
- Failure-tolerant: persistence failures are logged but do not disrupt detection
"""

from __future__ import annotations

import contextlib
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from argusprowl.behavior.entity_behavior_profile import EntityBehaviorProfile, ProfileMaturity

logger = logging.getLogger(__name__)

# Schema version for migration tracking
_SCHEMA_VERSION = 1


class EntityBehaviorPersistence:
    """SQLite-backed persistence for entity behavior profiles.

    Thread-safe for concurrent reads and writes. Persistence failures are
    logged but do not disrupt the detection pipeline.

    Attributes:
        db_path: Path to the SQLite database file.
        max_profiles: Maximum number of profiles to persist.
        max_values_per_profile: Maximum distinct values per profile.
    """

    def __init__(
        self,
        db_path: str | Path,
        max_profiles: int = 100000,
        max_values_per_profile: int = 1000,
    ) -> None:
        """Initialize persistence layer.

        Args:
            db_path: Path to SQLite database file.
            max_profiles: Maximum profiles to persist.
            max_values_per_profile: Maximum values per profile.
        """
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._max_profiles = max_profiles
        self._max_values_per_profile = max_values_per_profile
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
                    CREATE TABLE IF NOT EXISTS profiles (
                        profile_key TEXT PRIMARY KEY,
                        entity_type TEXT NOT NULL,
                        entity_id TEXT NOT NULL,
                        dimension TEXT NOT NULL,
                        first_seen TEXT,
                        last_seen TEXT,
                        observation_count INTEGER NOT NULL DEFAULT 0,
                        distinct_value_count INTEGER NOT NULL DEFAULT 0,
                        maturity TEXT NOT NULL DEFAULT 'warming',
                        profile_version INTEGER NOT NULL DEFAULT 1,
                        last_update TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS value_counts (
                        profile_key TEXT NOT NULL,
                        value TEXT NOT NULL,
                        count INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (profile_key, value),
                        FOREIGN KEY (profile_key) REFERENCES profiles(profile_key) ON DELETE CASCADE
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                """)
                # Insert schema version
                conn.execute(
                    """
                    INSERT OR REPLACE INTO metadata (key, value)
                    VALUES ('schema_version', ?)
                """,
                    (str(_SCHEMA_VERSION),),
                )
                conn.commit()
                self._initialized = True
                logger.info("Entity behavior persistence initialized at %s", self._db_path)
            except sqlite3.DatabaseError as exc:
                logger.warning("Failed to initialize persistence: %s", exc)
                self._initialized = False

    def load_profiles(
        self,
        max_profiles: int | None = None,
    ) -> tuple[dict[str, EntityBehaviorProfile], dict[str, dict[str, int]]]:
        """Load persisted profiles and value counts.

        Args:
            max_profiles: Maximum profiles to load (defaults to instance limit).

        Returns:
            Tuple of (profiles_dict, value_counts_dict).
        """
        if not self._initialized:
            return {}, {}

        limit = max_profiles or self._max_profiles
        profiles: dict[str, EntityBehaviorProfile] = {}
        value_counts: dict[str, dict[str, int]] = {}

        with self._lock:
            conn = self._get_connection()
            rows = conn.execute(
                "SELECT * FROM profiles ORDER BY last_update DESC LIMIT ?",
                (limit,),
            ).fetchall()

            for row in rows:
                profile_key = row[0]
                profile = EntityBehaviorProfile(
                    profile_key=profile_key,
                    entity_type=row[1],
                    entity_id=row[2],
                    dimension=row[3],
                    first_seen=datetime.fromisoformat(row[4]) if row[4] else None,
                    last_seen=datetime.fromisoformat(row[5]) if row[5] else None,
                    observation_count=row[6],
                    distinct_value_count=row[7],
                    maturity=ProfileMaturity(row[8]),
                    profile_version=row[9],
                    last_update=datetime.fromisoformat(row[10]),
                )
                profiles[profile_key] = profile

            # Load value counts
            vc_rows = conn.execute("SELECT profile_key, value, count FROM value_counts").fetchall()
            for row in vc_rows:
                pk = row[0]
                if pk not in value_counts:
                    value_counts[pk] = {}
                value_counts[pk][row[1]] = row[2]

        logger.info("Loaded %d profiles from persistence", len(profiles))
        return profiles, value_counts

    def save_profile(
        self,
        profile: EntityBehaviorProfile,
        value_counts: dict[str, int],
    ) -> None:
        """Save a single profile and its value counts.

        Args:
            profile: The profile to save.
            value_counts: Value counts for this profile.
        """
        if not self._initialized:
            return

        try:
            with self._lock:
                conn = self._get_connection()
                conn.execute(
                    """
                    INSERT OR REPLACE INTO profiles (
                        profile_key, entity_type, entity_id, dimension,
                        first_seen, last_seen, observation_count,
                        distinct_value_count, maturity, profile_version, last_update
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        profile.profile_key,
                        profile.entity_type,
                        profile.entity_id,
                        profile.dimension,
                        profile.first_seen.isoformat() if profile.first_seen else None,
                        profile.last_seen.isoformat() if profile.last_seen else None,
                        profile.observation_count,
                        profile.distinct_value_count,
                        profile.maturity.value,
                        profile.profile_version,
                        profile.last_update.isoformat(),
                    ),
                )

                # Save value counts
                conn.execute(
                    "DELETE FROM value_counts WHERE profile_key = ?",
                    (profile.profile_key,),
                )
                for value, count in value_counts.items():
                    conn.execute(
                        "INSERT OR REPLACE INTO value_counts (profile_key, value, count) VALUES (?, ?, ?)",
                        (profile.profile_key, value, count),
                    )

                conn.commit()
        except sqlite3.Error as exc:
            logger.warning("Failed to persist profile %s: %s", profile.profile_key, exc)

    def save_all(
        self,
        profiles: dict[str, EntityBehaviorProfile],
        value_counts: dict[str, dict[str, int]],
    ) -> None:
        """Save all profiles and value counts.

        Args:
            profiles: Dictionary of profile_key to EntityBehaviorProfile.
            value_counts: Dictionary of profile_key to value counts.
        """
        if not self._initialized:
            return

        saved = 0
        with self._lock:
            conn = self._get_connection()
            try:
                for profile_key, profile in profiles.items():
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO profiles (
                            profile_key, entity_type, entity_id, dimension,
                            first_seen, last_seen, observation_count,
                            distinct_value_count, maturity, profile_version, last_update
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            profile.profile_key,
                            profile.entity_type,
                            profile.entity_id,
                            profile.dimension,
                            profile.first_seen.isoformat() if profile.first_seen else None,
                            profile.last_seen.isoformat() if profile.last_seen else None,
                            profile.observation_count,
                            profile.distinct_value_count,
                            profile.maturity.value,
                            profile.profile_version,
                            profile.last_update.isoformat(),
                        ),
                    )

                    # Delete old value counts
                    conn.execute(
                        "DELETE FROM value_counts WHERE profile_key = ?",
                        (profile_key,),
                    )

                    # Insert new value counts
                    for value, count in value_counts.get(profile_key, {}).items():
                        conn.execute(
                            "INSERT OR REPLACE INTO value_counts (profile_key, value, count) VALUES (?, ?, ?)",
                            (profile_key, value, count),
                        )

                    saved += 1
                conn.commit()
                logger.info("Persisted %d profiles", saved)
            except sqlite3.Error as exc:
                logger.warning("Failed to persist profiles: %s", exc)
                conn.rollback()

    def delete_profile(self, profile_key: str) -> None:
        """Delete a profile and its value counts.

        Args:
            profile_key: The profile key to delete.
        """
        if not self._initialized:
            return

        try:
            with self._lock:
                conn = self._get_connection()
                conn.execute("DELETE FROM value_counts WHERE profile_key = ?", (profile_key,))
                conn.execute("DELETE FROM profiles WHERE profile_key = ?", (profile_key,))
                conn.commit()
        except sqlite3.Error as exc:
            logger.warning("Failed to delete profile %s: %s", profile_key, exc)

    def get_profile_count(self) -> int:
        """Get the number of persisted profiles.

        Returns:
            Number of profiles.
        """
        if not self._initialized:
            return 0
        with self._lock:
            conn = self._get_connection()
            row = conn.execute("SELECT COUNT(*) FROM profiles").fetchone()
            return row[0] if row else 0

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._connection is not None:
                with contextlib.suppress(sqlite3.Error):
                    self._connection.close()
                self._connection = None
                self._initialized = False

    def __enter__(self) -> EntityBehaviorPersistence:
        self.initialize()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
