"""Persistent alert storage foundation.

Provides SQLite-backed persistence for Alert objects with bounded retention,
deterministic eviction, and explicit failure semantics.

Phase 5.4.1 — Persistent Alert Storage Foundation:
    - Bounded storage (max_alerts)
    - Parameterized SQL (no injection risk)
    - Failure-tolerant (persistence failures don't disrupt detection)
    - Explicit status reporting (AVAILABLE/EMPTY/UNAVAILABLE/DEGRADED)
    - Lifecycle state persistence
    - Canonical entity key storage
    - Replay-safe (replay mode uses in-memory only)
    - Duplicate semantics (idempotent for same alert_id, reject for integrity conflict)
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import threading
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from uuid import UUID

from argusprowl.models.alert import Alert

logger = logging.getLogger(__name__)

# Schema version for migration tracking
_SCHEMA_VERSION = 1

# Maximum query limit to prevent abuse
_MAX_QUERY_LIMIT: int = 1000

# Maximum entity key length
_MAX_ENTITY_KEY_LENGTH: int = 256


class AlertPersistenceStatus(StrEnum):
    """Status of the alert persistence layer.

    Semantics:
        AVAILABLE: Persistence is operational; queries return data (possibly empty).
        EMPTY: Persistence is operational but contains no alerts.
        UNAVAILABLE: Persistence could not be initialized (database unavailable,
                     corruption, permission denied, etc.).
        DEGRADED: Persistence is partially operational; some alerts could not be
                  reconstructed due to malformed/corrupted rows.
    """

    AVAILABLE = "AVAILABLE"
    EMPTY = "EMPTY"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True, slots=True)
class AlertQueryResult:
    """Result of an alert persistence query.

    Attributes:
        alerts: Tuple of reconstructed Alert objects (may be empty).
        status: Current persistence status for this query.
        reason: Optional explanation for DEGRADED/UNAVAILABLE status.
    """

    alerts: tuple[Alert, ...]
    status: AlertPersistenceStatus
    reason: str | None = None


class AlertPersistence:
    """SQLite-backed persistence for Alert objects.

    Thread-safe. Persistence failures are logged but do not disrupt
    the detection pipeline.

    Attributes:
        db_path: Path to the SQLite database file.
        max_alerts: Maximum number of alerts to retain.
    """

    def __init__(
        self,
        db_path: str | Path,
        max_alerts: int = 10_000,
    ) -> None:
        """Initialize persistence layer.

        Args:
            db_path: Path to SQLite database file.
            max_alerts: Maximum number of alerts to persist.
        """
        self._db_path = Path(db_path)
        # Directory creation may fail if parent doesn't exist or is not writable.
        # initialize() will catch the resulting sqlite3 error and set UNAVAILABLE.
        with contextlib.suppress(OSError):
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._max_alerts = max_alerts
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._initialized = False
        self._status = AlertPersistenceStatus.UNAVAILABLE
        self._status_reason: str | None = None

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
        """Create tables if they don't exist.

        On first startup with no DB file: creates tables, status = EMPTY.
        On existing DB: checks for corruption, status = AVAILABLE or EMPTY.
        On corruption/unreadable DB: status = UNAVAILABLE.
        """
        with self._lock:
            try:
                conn = self._get_connection()
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        alert_id TEXT PRIMARY KEY,
                        payload TEXT NOT NULL,
                        lifecycle_state TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        entity_key TEXT,
                        incident_id TEXT
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                    ON alerts(created_at DESC, alert_id DESC)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_alerts_entity
                    ON alerts(entity_key, created_at DESC, alert_id DESC)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_alerts_incident
                    ON alerts(incident_id, created_at DESC, alert_id DESC)
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

                # Check if database has any alerts
                count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                self._initialized = True
                self._status = (
                    AlertPersistenceStatus.EMPTY if count == 0 else AlertPersistenceStatus.AVAILABLE
                )
                self._status_reason = None
                logger.info("Alert persistence initialized at %s", self._db_path)
            except sqlite3.DatabaseError as exc:
                logger.warning("Failed to initialize alert persistence: %s", exc)
                self._initialized = False
                self._status = AlertPersistenceStatus.UNAVAILABLE
                self._status_reason = str(exc)

    def save_alert(self, alert: Alert) -> bool:
        """Persist an alert to SQLite.

        Returns True only when the alert is durably persisted.
        Returns False when durability is not achieved.

        Duplicate semantics:
            - Same alert_id + identical payload: idempotent success
            - Same alert_id + different payload: reject with integrity conflict

        Args:
            alert: The immutable alert to persist.

        Returns:
            True if successfully persisted, False otherwise.
        """
        if not self._initialized:
            return False

        try:
            with self._lock:
                conn = self._get_connection()
                payload = json.dumps(alert.to_dict(), sort_keys=True)
                entity_key = self._compute_entity_key(alert)
                incident_id = str(alert.incident_id) if alert.incident_id else None

                # Check for integrity conflict: same alert_id but different payload
                existing = conn.execute(
                    "SELECT payload FROM alerts WHERE alert_id = ?",
                    (str(alert.alert_id),),
                ).fetchone()

                if existing is not None:
                    existing_payload = existing[0]
                    if existing_payload != payload:
                        logger.warning(
                            "Integrity conflict for alert %s: payload mismatch. "
                            "Rejecting write to preserve existing alert.",
                            alert.alert_id,
                        )
                        self._status = AlertPersistenceStatus.DEGRADED
                        self._status_reason = "integrity_conflict"
                        return False

                # Evict oldest if at capacity
                if self._get_count(conn) >= self._max_alerts:
                    self._evict_oldest(conn)

                conn.execute(
                    """
                    INSERT OR REPLACE INTO alerts
                    (alert_id, payload, lifecycle_state, created_at, entity_key, incident_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(alert.alert_id),
                        payload,
                        alert.lifecycle_state.value,
                        alert.created_at.isoformat(),
                        entity_key,
                        incident_id,
                    ),
                )
                conn.commit()

                # Update status
                if self._status == AlertPersistenceStatus.EMPTY:
                    self._status = AlertPersistenceStatus.AVAILABLE
                    self._status_reason = None

                return True
        except sqlite3.Error as exc:
            logger.warning("Failed to save alert %s: %s", alert.alert_id, exc)
            self._mark_degraded("write_failure")
            return False

    def load_alert(self, alert_id: UUID) -> Alert | None:
        """Load a single alert by ID.

        Args:
            alert_id: The alert ID to load.

        Returns:
            The reconstructed Alert, or None if not found.
        """
        if not self._initialized:
            return None

        try:
            with self._lock:
                conn = self._get_connection()
                row = conn.execute(
                    "SELECT payload, lifecycle_state FROM alerts WHERE alert_id = ?",
                    (str(alert_id),),
                ).fetchone()

                if row is None:
                    return None

                alert = self._deserialize(row[0])
                # Override lifecycle_state with persisted value
                if row[1] is not None:
                    from dataclasses import replace

                    from argusprowl.constants.lifecycle import AlertLifecycleState

                    try:
                        persisted_state = AlertLifecycleState(row[1])
                        alert = replace(alert, lifecycle_state=persisted_state)
                    except ValueError:
                        pass
                return alert
        except sqlite3.Error as exc:
            logger.warning("Failed to load alert %s: %s", alert_id, exc)
            self._mark_unavailable("read_failure")
            return None
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("Malformed alert record for %s: %s", alert_id, exc)
            self._mark_degraded("malformed_record")
            return None

    def list_all(self, limit: int | None = None) -> AlertQueryResult:
        """Return all persisted alerts, bounded by max_alerts.

        Unlike list_recent(), this does not cap at _MAX_QUERY_LIMIT.
        The bound is the configured max_alerts, which is the actual
        retention limit of the store.

        Args:
            limit: Maximum number of alerts to return. If None, returns
                up to max_alerts. Explicit values are clamped to max_alerts.

        Returns:
            AlertQueryResult with alerts and status.
        """
        if not self._initialized:
            return AlertQueryResult((), AlertPersistenceStatus.UNAVAILABLE, "unavailable")

        bounded_limit = min(
            max(1, int(limit) if limit is not None else self._max_alerts), self._max_alerts
        )

        try:
            with self._lock:
                conn = self._get_connection()
                rows = conn.execute(
                    """
                    SELECT payload, lifecycle_state FROM alerts
                    ORDER BY created_at DESC, alert_id DESC
                    LIMIT ?
                    """,
                    (bounded_limit,),
                ).fetchall()

            alerts = []
            degraded = False
            for row in rows:
                try:
                    alert = self._deserialize(row[0])
                    # Override lifecycle_state with persisted value
                    if row[1] is not None:
                        from dataclasses import replace

                        from argusprowl.constants.lifecycle import AlertLifecycleState

                        try:
                            persisted_state = AlertLifecycleState(row[1])
                            alert = replace(alert, lifecycle_state=persisted_state)
                        except ValueError:
                            pass
                    alerts.append(alert)
                except (json.JSONDecodeError, ValueError) as exc:
                    logger.warning("Malformed alert record skipped: %s", exc)
                    degraded = True

            if degraded:
                return AlertQueryResult(
                    tuple(alerts),
                    AlertPersistenceStatus.DEGRADED,
                    "malformed_record",
                )

            status = (
                AlertPersistenceStatus.EMPTY if not alerts else AlertPersistenceStatus.AVAILABLE
            )
            return AlertQueryResult(tuple(alerts), status)
        except sqlite3.Error as exc:
            logger.warning("Failed to list all alerts: %s", exc)
            self._mark_unavailable("query_failed")
            return AlertQueryResult((), AlertPersistenceStatus.UNAVAILABLE, "query_failed")

    def list_recent(self, limit: int = 100) -> AlertQueryResult:
        """Return most-recent alerts.

        Args:
            limit: Maximum number of alerts to return (bounded to 1000).

        Returns:
            AlertQueryResult with alerts and status.
        """
        if not self._initialized:
            return AlertQueryResult((), AlertPersistenceStatus.UNAVAILABLE, "unavailable")

        bounded_limit = min(max(1, int(limit)), _MAX_QUERY_LIMIT)

        try:
            with self._lock:
                conn = self._get_connection()
                rows = conn.execute(
                    """
                    SELECT payload FROM alerts
                    ORDER BY created_at DESC, alert_id DESC
                    LIMIT ?
                    """,
                    (bounded_limit,),
                ).fetchall()

            alerts = []
            degraded = False
            for row in rows:
                try:
                    alerts.append(self._deserialize(row[0]))
                except (json.JSONDecodeError, ValueError) as exc:
                    logger.warning("Malformed alert record skipped: %s", exc)
                    degraded = True

            if degraded:
                return AlertQueryResult(
                    tuple(alerts),
                    AlertPersistenceStatus.DEGRADED,
                    "malformed_record",
                )

            status = (
                AlertPersistenceStatus.EMPTY if not alerts else AlertPersistenceStatus.AVAILABLE
            )
            return AlertQueryResult(tuple(alerts), status)
        except sqlite3.Error as exc:
            logger.warning("Failed to list recent alerts: %s", exc)
            self._mark_unavailable("query_failed")
            return AlertQueryResult((), AlertPersistenceStatus.UNAVAILABLE, "query_failed")

    def list_by_entity(self, entity_key: str, limit: int = 50) -> AlertQueryResult:
        """Return alerts for a specific entity key.

        Uses the canonical entity key from EntityCorrelationService.

        Args:
            entity_key: The canonical entity key to match.
            limit: Maximum number of alerts to return (bounded to 1000).

        Returns:
            AlertQueryResult with alerts and status.
        """
        if not self._initialized:
            return AlertQueryResult((), AlertPersistenceStatus.UNAVAILABLE, "unavailable")

        # Validate entity key
        if not isinstance(entity_key, str) or not entity_key:
            return AlertQueryResult((), AlertPersistenceStatus.UNAVAILABLE, "invalid_entity_key")
        if len(entity_key) > _MAX_ENTITY_KEY_LENGTH:
            return AlertQueryResult((), AlertPersistenceStatus.UNAVAILABLE, "entity_key_too_long")

        bounded_limit = min(max(1, int(limit)), _MAX_QUERY_LIMIT)

        try:
            with self._lock:
                conn = self._get_connection()
                rows = conn.execute(
                    """
                    SELECT payload FROM alerts
                    WHERE entity_key = ?
                    ORDER BY created_at DESC, alert_id DESC
                    LIMIT ?
                    """,
                    (entity_key, bounded_limit),
                ).fetchall()

            alerts = []
            degraded = False
            for row in rows:
                try:
                    alerts.append(self._deserialize(row[0]))
                except (json.JSONDecodeError, ValueError) as exc:
                    logger.warning("Malformed alert record skipped: %s", exc)
                    degraded = True

            if degraded:
                return AlertQueryResult(
                    tuple(alerts),
                    AlertPersistenceStatus.DEGRADED,
                    "malformed_record",
                )

            status = (
                AlertPersistenceStatus.EMPTY if not alerts else AlertPersistenceStatus.AVAILABLE
            )
            return AlertQueryResult(tuple(alerts), status)
        except sqlite3.Error as exc:
            logger.warning("Failed to list alerts by entity %s: %s", entity_key, exc)
            self._mark_unavailable("query_failed")
            return AlertQueryResult((), AlertPersistenceStatus.UNAVAILABLE, "query_failed")

    def list_by_incident(self, incident_id: UUID, limit: int = 100) -> AlertQueryResult:
        """Return alerts for a specific incident.

        Args:
            incident_id: The incident ID to filter by.
            limit: Maximum number of alerts to return (bounded to 1000).

        Returns:
            AlertQueryResult with alerts and status.
        """
        if not self._initialized:
            return AlertQueryResult((), AlertPersistenceStatus.UNAVAILABLE, "unavailable")

        bounded_limit = min(max(1, int(limit)), _MAX_QUERY_LIMIT)

        try:
            with self._lock:
                conn = self._get_connection()
                rows = conn.execute(
                    """
                    SELECT payload FROM alerts
                    WHERE incident_id = ?
                    ORDER BY created_at DESC, alert_id DESC
                    LIMIT ?
                    """,
                    (str(incident_id), bounded_limit),
                ).fetchall()

            alerts = []
            degraded = False
            for row in rows:
                try:
                    alerts.append(self._deserialize(row[0]))
                except (json.JSONDecodeError, ValueError) as exc:
                    logger.warning("Malformed alert record skipped: %s", exc)
                    degraded = True

            if degraded:
                return AlertQueryResult(
                    tuple(alerts),
                    AlertPersistenceStatus.DEGRADED,
                    "malformed_record",
                )

            status = (
                AlertPersistenceStatus.EMPTY if not alerts else AlertPersistenceStatus.AVAILABLE
            )
            return AlertQueryResult(tuple(alerts), status)
        except sqlite3.Error as exc:
            logger.warning("Failed to list alerts by incident %s: %s", incident_id, exc)
            self._mark_unavailable("query_failed")
            return AlertQueryResult((), AlertPersistenceStatus.UNAVAILABLE, "query_failed")

    def update_lifecycle(self, alert_id: UUID, lifecycle_state: str) -> bool:
        """Update the lifecycle state of a persisted alert.

        Args:
            alert_id: The alert ID to update.
            lifecycle_state: The new lifecycle state (OPEN/ACKNOWLEDGED/CLOSED).

        Returns:
            True if successfully updated, False otherwise.
        """
        if not self._initialized:
            return False

        try:
            with self._lock:
                conn = self._get_connection()
                cursor = conn.execute(
                    """
                    UPDATE alerts
                    SET lifecycle_state = ?
                    WHERE alert_id = ?
                    """,
                    (lifecycle_state, str(alert_id)),
                )
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as exc:
            logger.warning("Failed to update lifecycle for alert %s: %s", alert_id, exc)
            self._mark_degraded("lifecycle_update_failure")
            return False

    def get_status(self) -> AlertPersistenceStatus:
        """Get the current persistence status.

        Returns:
            Current AlertPersistenceStatus.
        """
        return self._status

    def get_status_reason(self) -> str | None:
        """Get the reason for the current status (if any).

        Returns:
            Optional reason string.
        """
        return self._status_reason

    def close(self) -> None:
        """Release database connection."""
        with self._lock:
            if self._connection is not None:
                with contextlib.suppress(sqlite3.Error):
                    self._connection.close()
                self._connection = None
            self._initialized = False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_count(self, conn: sqlite3.Connection) -> int:
        """Get the current alert count."""
        return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def _evict_oldest(self, conn: sqlite3.Connection) -> None:
        """Evict the oldest alert (by created_at, then alert_id)."""
        conn.execute(
            """
            DELETE FROM alerts
            WHERE alert_id = (
                SELECT alert_id FROM alerts
                ORDER BY created_at ASC, alert_id ASC
                LIMIT 1
            )
            """
        )

    def _deserialize(self, payload: str) -> Alert:
        """Deserialize a JSON payload to an Alert.

        Args:
            payload: JSON-serialized alert dictionary.

        Returns:
            Reconstructed Alert object.

        Raises:
            json.JSONDecodeError: If payload is not valid JSON.
            ValueError: If payload cannot be deserialized to Alert.
        """
        data = json.loads(payload)
        return Alert.from_dict(data)

    def _compute_entity_key(self, alert: Alert) -> str:
        """Compute canonical entity key from alert.

        Reuses the same logic as EntityCorrelationService.

        Args:
            alert: The alert to compute the entity key for.

        Returns:
            Canonical entity key string.
        """
        entity_context = alert.entity_context or {}

        host = entity_context.get("host")
        process_name = entity_context.get("process_name")
        dst_ip = entity_context.get("dst_ip")

        # Priority 1: host + process
        if host and process_name:
            return f"{host}:{process_name}"

        # Priority 2: host + destination
        if host and dst_ip:
            return f"{host}:{dst_ip}"

        # Priority 3: host alone
        if host:
            return f"{host}:*"

        # Priority 4: destination alone
        if dst_ip:
            return f"*:{dst_ip}"

        # Priority 5: stable fallback
        return f"unknown:{alert.alert_id}"

    def _mark_degraded(self, reason: str) -> None:
        """Mark persistence as degraded."""
        self._status = AlertPersistenceStatus.DEGRADED
        self._status_reason = reason

    def _mark_unavailable(self, reason: str) -> None:
        """Mark persistence as unavailable."""
        self._status = AlertPersistenceStatus.UNAVAILABLE
        self._status_reason = reason
