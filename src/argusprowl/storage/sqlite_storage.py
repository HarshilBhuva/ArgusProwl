"""SQLite infrastructure adapter with indexed telemetry evidence queries."""

import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from argusprowl.entity_intelligence.extractor import (
    extract_event_observations,
    normalize_entity_type,
    normalize_entity_value,
)
from argusprowl.exceptions.exceptions import StorageError
from argusprowl.interfaces.storage import Storage


class SQLiteAdapter(Storage):
    """Thread-safe JSON document storage with a transactional evidence index.

    The JSON record remains authoritative. The narrow index contains only
    normalized query dimensions and is maintained in the same SQLite transaction.
    """

    _EVIDENCE_COLLECTION = "telemetry_evidence"

    def __init__(self, database_path: str | Path) -> None:
        self._path = Path(database_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self._path, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS records (collection TEXT NOT NULL, record_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(collection, record_id))"
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_records_collection_created ON records(collection, created_at DESC)"
        )
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS telemetry_evidence_index (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                hostname TEXT,
                username TEXT,
                process_name TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                event_type TEXT NOT NULL,
                source_type TEXT NOT NULL
            )"""
        )
        self._connection.execute("CREATE INDEX IF NOT EXISTS idx_evidence_time_id ON telemetry_evidence_index(timestamp, event_id)")
        for column in ("hostname", "username", "process_name", "src_ip", "dst_ip", "event_type", "source_type"):
            self._connection.execute(
                f"CREATE INDEX IF NOT EXISTS idx_evidence_{column}_time ON telemetry_evidence_index({column}, timestamp, event_id)"
            )
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)"
        )

        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS entity_intelligence_entities (
                entity_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                display_value TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 0,
                UNIQUE(entity_type, normalized_value)
            )"""
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_entity_intelligence_type_seen ON entity_intelligence_entities(entity_type, last_seen DESC)"
        )
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS entity_intelligence_relationships (
                relationship_id TEXT PRIMARY KEY,
                source_entity_id TEXT NOT NULL,
                target_entity_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                evidence_kind TEXT NOT NULL CHECK(evidence_kind IN ('OBSERVED', 'INFERRED')),
                confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
                provenance TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 0,
                UNIQUE(source_entity_id, target_entity_id, relationship_type, evidence_kind)
            )"""
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_entity_intelligence_rel_source_seen ON entity_intelligence_relationships(source_entity_id, last_seen DESC)"
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_entity_intelligence_rel_target_seen ON entity_intelligence_relationships(target_entity_id, last_seen DESC)"
        )
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS entity_intelligence_entity_evidence (
                entity_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                provenance TEXT NOT NULL,
                PRIMARY KEY(entity_id, event_id)
            )"""
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_entity_intelligence_entity_evidence_seen ON entity_intelligence_entity_evidence(entity_id, observed_at DESC, event_id)"
        )
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS entity_intelligence_relationship_evidence (
                relationship_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                provenance TEXT NOT NULL,
                PRIMARY KEY(relationship_id, event_id)
            )"""
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_entity_intelligence_relationship_evidence_seen ON entity_intelligence_relationship_evidence(relationship_id, observed_at DESC, event_id)"
        )
        self._connection.commit()
        self._lock = threading.RLock()
        self._migrate_evidence_index()
        self._migrate_entity_intelligence()

    def _migrate_evidence_index(self) -> None:
        """Backfill the derived index once for databases created before this version."""
        with self._lock, self._connection:
            migrated = self._connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version=1"
            ).fetchone()
            if migrated:
                return
            rows = self._connection.execute(
                "SELECT record_id, payload FROM records WHERE collection=?",
                (self._EVIDENCE_COLLECTION,),
            )
            for record_id, raw_payload in rows:
                try:
                    payload = json.loads(raw_payload)
                    self._upsert_evidence_index(record_id, payload)
                except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                    # The evidence service reports malformed source records during
                    # recovery; do not make a partial migration look complete.
                    continue
            self._connection.execute(
                "INSERT INTO schema_migrations(version) VALUES(1)"
            )

    def _upsert_evidence_index(self, record_id: str, payload: dict[str, object]) -> None:
        event = payload.get("event")
        if not isinstance(event, dict):
            raise ValueError("Telemetry evidence payload must contain an event object.")
        event_id = str(event.get("event_id", ""))
        if event_id != record_id:
            raise ValueError("Telemetry evidence record ID does not match event ID.")
        timestamp = event.get("timestamp")
        event_type = event.get("event_type")
        source_type = event.get("source_type")
        if not all(isinstance(value, str) and value for value in (timestamp, event_type, source_type)):
            raise ValueError("Telemetry evidence index fields are incomplete.")
        self._connection.execute(
            """INSERT INTO telemetry_evidence_index
            (event_id, timestamp, hostname, username, process_name, src_ip, dst_ip, event_type, source_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                timestamp=excluded.timestamp, hostname=excluded.hostname,
                username=excluded.username, process_name=excluded.process_name,
                src_ip=excluded.src_ip, dst_ip=excluded.dst_ip,
                event_type=excluded.event_type, source_type=excluded.source_type""",
            (
                event_id, timestamp, event.get("hostname"), event.get("username"),
                event.get("process_name"), event.get("src_ip"), event.get("dst_ip"),
                event_type, source_type,
            ),
        )

        self._upsert_entity_intelligence(record_id, payload)

    def _migrate_entity_intelligence(self) -> None:
        """Backfill relational entity indexes from authoritative evidence records."""
        with self._lock, self._connection:
            migrated = self._connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version=2"
            ).fetchone()
            if migrated:
                return
            rows = self._connection.execute(
                "SELECT record_id, payload FROM records WHERE collection=?",
                (self._EVIDENCE_COLLECTION,),
            )
            for record_id, raw_payload in rows:
                try:
                    payload = json.loads(raw_payload)
                    self._upsert_entity_intelligence(record_id, payload)
                except (TypeError, ValueError, KeyError, UnicodeError, json.JSONDecodeError):
                    # Keep the authoritative evidence record; malformed source rows
                    # remain visible to the evidence recovery diagnostics.
                    continue
            self._connection.execute(
                "INSERT INTO schema_migrations(version) VALUES(2)"
            )

    @staticmethod
    def _relationship_identifier(
        source_entity_id: str,
        target_entity_id: str,
        relationship_type: str,
        evidence_kind: str,
    ) -> str:
        material = "\0".join(
            (source_entity_id, target_entity_id, relationship_type, evidence_kind)
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def _upsert_entity_intelligence(
        self, record_id: str, payload: dict[str, object]
    ) -> None:
        event = payload.get("event")
        if not isinstance(event, dict):
            raise ValueError("Telemetry evidence payload must contain an event object.")
        event_id = str(event.get("event_id", ""))
        if event_id != record_id:
            raise ValueError("Telemetry evidence record ID does not match event ID.")
        timestamp = event.get("timestamp")
        source_type = event.get("source_type")
        event_type = event.get("event_type")
        if not all(isinstance(value, str) and value for value in (timestamp, source_type, event_type)):
            raise ValueError("Entity intelligence requires event timestamp and source identity.")
        entities, relationships = extract_event_observations(event)
        event_provenance = str(payload.get("provenance", "OBSERVED_CONTEXT"))
        provenance = f"{event_provenance}:{source_type}:{event_type}"[:256]

        for fact in entities:
            self._connection.execute(
                """INSERT INTO entity_intelligence_entities
                (entity_id, entity_type, normalized_value, display_value, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity_type, normalized_value) DO UPDATE SET
                    display_value=excluded.display_value,
                    first_seen=MIN(entity_intelligence_entities.first_seen, excluded.first_seen),
                    last_seen=MAX(entity_intelligence_entities.last_seen, excluded.last_seen)""",
                (
                    fact.entity_id,
                    fact.entity_type,
                    fact.normalized_value,
                    fact.display_value,
                    timestamp,
                    timestamp,
                ),
            )
            inserted = self._connection.execute(
                """INSERT OR IGNORE INTO entity_intelligence_entity_evidence
                (entity_id, event_id, observed_at, provenance) VALUES (?, ?, ?, ?)""",
                (fact.entity_id, event_id, timestamp, provenance),
            )
            if inserted.rowcount:
                self._connection.execute(
                    """UPDATE entity_intelligence_entities
                    SET observation_count=observation_count+1
                    WHERE entity_id=?""",
                    (fact.entity_id,),
                )

        for fact in relationships:
            relationship_id = self._relationship_identifier(
                fact.source_entity_id,
                fact.target_entity_id,
                fact.relationship_type,
                fact.evidence_kind,
            )
            self._connection.execute(
                """INSERT OR IGNORE INTO entity_intelligence_relationships
                (relationship_id, source_entity_id, target_entity_id, relationship_type,
                 evidence_kind, confidence, provenance, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    relationship_id,
                    fact.source_entity_id,
                    fact.target_entity_id,
                    fact.relationship_type,
                    fact.evidence_kind,
                    fact.confidence,
                    provenance,
                    timestamp,
                    timestamp,
                ),
            )
            inserted = self._connection.execute(
                """INSERT OR IGNORE INTO entity_intelligence_relationship_evidence
                (relationship_id, event_id, observed_at, provenance)
                VALUES (?, ?, ?, ?)""",
                (relationship_id, event_id, timestamp, provenance),
            )
            if inserted.rowcount:
                self._connection.execute(
                    """UPDATE entity_intelligence_relationships
                    SET first_seen=MIN(first_seen, ?),
                        last_seen=MAX(last_seen, ?),
                        observation_count=observation_count+1
                    WHERE relationship_id=?""",
                    (timestamp, timestamp, relationship_id),
                )

    @staticmethod
    def _validate_entity_limit(limit: int) -> None:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValueError("Entity intelligence limit must be between 1 and 500.")

    def list_entity_intelligence_entities(
        self, *, entity_type: str | None = None, limit: int = 100
    ) -> list[dict[str, object]]:
        self._validate_entity_limit(limit)
        canonical_type = normalize_entity_type(entity_type) if entity_type is not None else None
        try:
            with self._lock:
                if canonical_type is None:
                    rows = self._connection.execute(
                        """SELECT entity_type, normalized_value, display_value,
                                  first_seen, last_seen, observation_count
                           FROM entity_intelligence_entities
                           ORDER BY last_seen DESC, entity_type ASC, normalized_value ASC
                           LIMIT ?""",
                        (limit,),
                    ).fetchall()
                else:
                    rows = self._connection.execute(
                        """SELECT entity_type, normalized_value, display_value,
                                  first_seen, last_seen, observation_count
                           FROM entity_intelligence_entities
                           WHERE entity_type=?
                           ORDER BY last_seen DESC, normalized_value ASC
                           LIMIT ?""",
                        (canonical_type, limit),
                    ).fetchall()
            return [
                {
                    "entity_type": row[0],
                    "entity_id": row[1],
                    "display_value": row[2],
                    "first_seen": row[3],
                    "last_seen": row[4],
                    "observation_count": int(row[5]),
                }
                for row in rows
            ]
        except sqlite3.Error as exc:
            raise StorageError("Unable to list entity intelligence records", {}) from exc

    def get_entity_intelligence_entity(
        self, entity_type: str, entity_value: str
    ) -> dict[str, object] | None:
        canonical_type = normalize_entity_type(entity_type)
        normalized_value = normalize_entity_value(canonical_type, entity_value)
        try:
            with self._lock:
                row = self._connection.execute(
                    """SELECT entity_type, normalized_value, display_value,
                              first_seen, last_seen, observation_count
                       FROM entity_intelligence_entities
                       WHERE entity_type=? AND normalized_value=?""",
                    (canonical_type, normalized_value),
                ).fetchone()
            if row is None:
                return None
            return {
                "entity_type": row[0],
                "entity_id": row[1],
                "display_value": row[2],
                "first_seen": row[3],
                "last_seen": row[4],
                "observation_count": int(row[5]),
            }
        except sqlite3.Error as exc:
            raise StorageError("Unable to retrieve entity intelligence record", {}) from exc

    def list_entity_intelligence_relationships(
        self,
        entity_type: str,
        entity_value: str,
        *,
        direction: str = "both",
        limit: int = 100,
    ) -> list[dict[str, object]]:
        self._validate_entity_limit(limit)
        if direction not in {"both", "inbound", "outbound"}:
            raise ValueError("direction must be 'both', 'inbound', or 'outbound'.")
        canonical_type = normalize_entity_type(entity_type)
        normalized_value = normalize_entity_value(canonical_type, entity_value)
        try:
            with self._lock:
                entity_row = self._connection.execute(
                    """SELECT entity_id FROM entity_intelligence_entities
                       WHERE entity_type=? AND normalized_value=?""",
                    (canonical_type, normalized_value),
                ).fetchone()
                if entity_row is None:
                    return []
                entity_id = str(entity_row[0])
                if direction == "outbound":
                    rows = self._connection.execute(
                        """SELECT r.relationship_id, s.entity_type, s.normalized_value,
                                  t.entity_type, t.normalized_value, r.relationship_type,
                                  r.evidence_kind, r.confidence, r.provenance,
                                  r.first_seen, r.last_seen, r.observation_count
                           FROM entity_intelligence_relationships r
                           JOIN entity_intelligence_entities s ON s.entity_id=r.source_entity_id
                           JOIN entity_intelligence_entities t ON t.entity_id=r.target_entity_id
                           WHERE r.source_entity_id=?
                           ORDER BY r.last_seen DESC, r.relationship_id ASC
                           LIMIT ?""",
                        (entity_id, limit),
                    ).fetchall()
                elif direction == "inbound":
                    rows = self._connection.execute(
                        """SELECT r.relationship_id, s.entity_type, s.normalized_value,
                                  t.entity_type, t.normalized_value, r.relationship_type,
                                  r.evidence_kind, r.confidence, r.provenance,
                                  r.first_seen, r.last_seen, r.observation_count
                           FROM entity_intelligence_relationships r
                           JOIN entity_intelligence_entities s ON s.entity_id=r.source_entity_id
                           JOIN entity_intelligence_entities t ON t.entity_id=r.target_entity_id
                           WHERE r.target_entity_id=?
                           ORDER BY r.last_seen DESC, r.relationship_id ASC
                           LIMIT ?""",
                        (entity_id, limit),
                    ).fetchall()
                else:
                    rows = self._connection.execute(
                        """SELECT r.relationship_id, s.entity_type, s.normalized_value,
                                  t.entity_type, t.normalized_value, r.relationship_type,
                                  r.evidence_kind, r.confidence, r.provenance,
                                  r.first_seen, r.last_seen, r.observation_count
                           FROM entity_intelligence_relationships r
                           JOIN entity_intelligence_entities s ON s.entity_id=r.source_entity_id
                           JOIN entity_intelligence_entities t ON t.entity_id=r.target_entity_id
                           WHERE r.source_entity_id=? OR r.target_entity_id=?
                           ORDER BY r.last_seen DESC, r.relationship_id ASC
                           LIMIT ?""",
                        (entity_id, entity_id, limit),
                    ).fetchall()
                results: list[dict[str, object]] = []
                for row in rows:
                    evidence_rows = self._connection.execute(
                        """SELECT e.event_id, e.observed_at, e.provenance,
                                  CASE WHEN i.event_id IS NULL THEN 0 ELSE 1 END
                           FROM entity_intelligence_relationship_evidence e
                           LEFT JOIN telemetry_evidence_index i ON i.event_id=e.event_id
                           WHERE e.relationship_id=?
                           ORDER BY e.observed_at DESC, e.event_id DESC
                           LIMIT 20""",
                        (row[0],),
                    ).fetchall()
                    results.append(
                        {
                            "relationship_id": row[0],
                            "source_entity_type": row[1],
                            "source_entity_id": row[2],
                            "target_entity_type": row[3],
                            "target_entity_id": row[4],
                            "relationship_type": row[5],
                            "evidence_kind": row[6],
                            "confidence": float(row[7]),
                            "provenance": row[8],
                            "first_seen": row[9],
                            "last_seen": row[10],
                            "observation_count": int(row[11]),
                            "evidence_refs": [
                                {
                                    "event_id": evidence[0],
                                    "observed_at": evidence[1],
                                    "provenance": evidence[2],
                                    "available": bool(evidence[3]),
                                }
                                for evidence in evidence_rows
                            ],
                        }
                    )
                return results
        except sqlite3.Error as exc:
            raise StorageError("Unable to query entity relationships", {}) from exc

    def list_entity_intelligence_evidence(
        self, entity_type: str, entity_value: str, *, limit: int = 100
    ) -> list[dict[str, object]]:
        self._validate_entity_limit(limit)
        canonical_type = normalize_entity_type(entity_type)
        normalized_value = normalize_entity_value(canonical_type, entity_value)
        try:
            with self._lock:
                rows = self._connection.execute(
                    """SELECT e.event_id, e.observed_at, e.provenance,
                              CASE WHEN i.event_id IS NULL THEN 0 ELSE 1 END
                       FROM entity_intelligence_entity_evidence e
                       JOIN entity_intelligence_entities n ON n.entity_id=e.entity_id
                       LEFT JOIN telemetry_evidence_index i ON i.event_id=e.event_id
                       WHERE n.entity_type=? AND n.normalized_value=?
                       ORDER BY e.observed_at DESC, e.event_id DESC
                       LIMIT ?""",
                    (canonical_type, normalized_value, limit),
                ).fetchall()
            return [
                {
                    "event_id": row[0],
                    "observed_at": row[1],
                    "provenance": row[2],
                    "available": bool(row[3]),
                }
                for row in rows
            ]
        except sqlite3.Error as exc:
            raise StorageError("Unable to query entity evidence references", {}) from exc

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
    ) -> None:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1.")
        if not evidence_event_ids:
            raise ValueError("An inferred relationship requires evidence event IDs.")
        source_type = normalize_entity_type(source_entity_type)
        source_value = normalize_entity_value(source_type, source_entity_value)
        target_type = normalize_entity_type(target_entity_type)
        target_value = normalize_entity_value(target_type, target_entity_value)
        relation_type = relationship_type.strip().upper()
        if not relation_type or len(relation_type) > 64:
            raise ValueError("Invalid inferred relationship type.")
        try:
            with self._lock, self._connection:
                source = self._connection.execute(
                    """SELECT entity_id FROM entity_intelligence_entities
                       WHERE entity_type=? AND normalized_value=?""",
                    (source_type, source_value),
                ).fetchone()
                target = self._connection.execute(
                    """SELECT entity_id FROM entity_intelligence_entities
                       WHERE entity_type=? AND normalized_value=?""",
                    (target_type, target_value),
                ).fetchone()
                if source is None or target is None:
                    raise ValueError("Inferred relationships require existing observed entities.")
                evidence = []
                for evidence_event_id in dict.fromkeys(evidence_event_ids):
                    row = self._connection.execute(
                        """SELECT event_id, timestamp FROM telemetry_evidence_index
                           WHERE event_id=?""",
                        (evidence_event_id,),
                    ).fetchone()
                    if row is not None:
                        evidence.append(row)
                if len(evidence) != len(evidence_event_ids):
                    raise ValueError("Every inferred relationship evidence ID must be durable.")
                timestamps = [str(row[1]) for row in evidence]
                relationship_id = self._relationship_identifier(
                    str(source[0]), str(target[0]), relation_type, "INFERRED"
                )
                self._connection.execute(
                    """INSERT OR IGNORE INTO entity_intelligence_relationships
                    (relationship_id, source_entity_id, target_entity_id, relationship_type,
                     evidence_kind, confidence, provenance, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, 'INFERRED', ?, ?, ?, ?)""",
                    (
                        relationship_id,
                        str(source[0]),
                        str(target[0]),
                        relation_type,
                        confidence,
                        provenance,
                        min(timestamps),
                        max(timestamps),
                    ),
                )
                for event_id, observed_at in evidence:
                    inserted = self._connection.execute(
                        """INSERT OR IGNORE INTO entity_intelligence_relationship_evidence
                        (relationship_id, event_id, observed_at, provenance)
                        VALUES (?, ?, ?, ?)""",
                        (relationship_id, str(event_id), str(observed_at), provenance),
                    )
                    if inserted.rowcount:
                        self._connection.execute(
                            """UPDATE entity_intelligence_relationships
                            SET first_seen=MIN(first_seen, ?),
                                last_seen=MAX(last_seen, ?),
                                observation_count=observation_count+1
                            WHERE relationship_id=?""",
                            (str(observed_at), str(observed_at), relationship_id),
                        )
        except sqlite3.Error as exc:
            raise StorageError("Unable to persist inferred entity relationship", {}) from exc

    def save(self, collection: str, record_id: UUID, data: dict[str, object]) -> None:
        try:
            payload = json.dumps(data, default=str, separators=(",", ":"))
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT INTO records(collection, record_id, payload) VALUES(?, ?, ?) ON CONFLICT(collection, record_id) DO UPDATE SET payload=excluded.payload",
                    (collection, str(record_id), payload),
                )
                if collection == self._EVIDENCE_COLLECTION:
                    self._upsert_evidence_index(str(record_id), data)
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise StorageError("Unable to persist record", {"collection": collection}) from exc

    def load(self, collection: str, record_id: UUID) -> dict[str, object] | None:
        try:
            with self._lock:
                row = self._connection.execute(
                    "SELECT payload FROM records WHERE collection=? AND record_id=?",
                    (collection, str(record_id)),
                ).fetchone()
            return json.loads(row[0]) if row else None
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            raise StorageError("Unable to load record", {"collection": collection}) from exc

    def delete(self, collection: str, record_id: UUID) -> bool:
        try:
            with self._lock, self._connection:
                deleted = self._connection.execute(
                    "DELETE FROM records WHERE collection=? AND record_id=?",
                    (collection, str(record_id)),
                ).rowcount > 0
                if collection == self._EVIDENCE_COLLECTION:
                    self._connection.execute(
                        "DELETE FROM telemetry_evidence_index WHERE event_id=?",
                        (str(record_id),),
                    )
                return deleted
        except sqlite3.Error as exc:
            raise StorageError("Unable to delete record", {"collection": collection}) from exc

    def list_records(self, collection: str, limit: int = 100) -> list[dict[str, object]]:
        if limit < 1:
            return []
        try:
            with self._lock:
                rows = self._connection.execute(
                    "SELECT payload FROM records WHERE collection=? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                    (collection, limit),
                ).fetchall()
            return [json.loads(row[0]) for row in rows]
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            raise StorageError("Unable to list records", {"collection": collection}) from exc

    @staticmethod
    def _decode_cursor(cursor: str | None) -> tuple[str, str] | None:
        if cursor is None:
            return None
        try:
            raw = base64.urlsafe_b64decode(cursor.encode("ascii") + b"=" * (-len(cursor) % 4))
            value = json.loads(raw)
            timestamp = value["timestamp"]
            if not isinstance(timestamp, str) or not timestamp:
                raise ValueError
            parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed_timestamp.tzinfo is None:
                raise ValueError
            event_id = str(UUID(value["event_id"]))
            return parsed_timestamp.astimezone(UTC).isoformat(), event_id
        except (ValueError, KeyError, TypeError, UnicodeError, binascii.Error, json.JSONDecodeError) as exc:
            raise ValueError("Invalid evidence pagination cursor.") from exc

    @staticmethod
    def _encode_cursor(timestamp: str, event_id: str) -> str:
        raw = json.dumps({"timestamp": timestamp, "event_id": event_id}, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def search_telemetry_evidence(
        self,
        filters: dict[str, object],
        *,
        limit: int,
        cursor: str | None = None,
    ) -> dict[str, object]:
        """Search the durable evidence index with keyset pagination."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValueError("Evidence result limit must be between 1 and 500.")
        clauses: list[str] = []
        values: list[object] = []

        exact_fields = {
            "event_id": "i.event_id",
            "event_type": "i.event_type",
            "source_type": "i.source_type",
            "src_ip": "i.src_ip",
            "dst_ip": "i.dst_ip",
        }
        for key, column in exact_fields.items():
            value = filters.get(key)
            if value is not None:
                clauses.append(f"{column} = ?")
                values.append(str(value))
        for key, operator in (("start_time", ">="), ("end_time", "<=")):
            value = filters.get(key)
            if value is not None:
                clauses.append(f"i.timestamp {operator} ?")
                values.append(value.astimezone(UTC).isoformat() if isinstance(value, datetime) else str(value))

        entity_type, entity_id = filters.get("entity_type"), filters.get("entity_id")
        if entity_type is not None or entity_id is not None:
            if not entity_type or not entity_id:
                clauses.append("0 = 1")
            else:
                entity_columns = {
                    "hostname": ("i.hostname",),
                    "host": ("i.hostname",),
                    "user": ("i.username",),
                    "process": ("i.process_name",),
                    "src_ip": ("i.src_ip", "i.dst_ip"),
                    "ip": ("i.src_ip", "i.dst_ip"),
                    "network": ("i.src_ip", "i.dst_ip"),
                }
                columns = entity_columns.get(str(entity_type).lower())
                if columns is None:
                    clauses.append("0 = 1")
                elif len(columns) == 1:
                    clauses.append(f"{columns[0]} = ? COLLATE NOCASE")
                    values.append(str(entity_id))
                else:
                    clauses.append(f"({columns[0]} = ? OR {columns[1]} = ?)")
                    values.extend((str(entity_id), str(entity_id)))

        domain = filters.get("domain")
        if domain is not None:
            literal = str(domain).lower().replace("!", "!!").replace("%", "!%").replace("_", "!_")
            clauses.append("(lower(i.hostname) LIKE ? ESCAPE '!' OR lower(i.dst_ip) LIKE ? ESCAPE '!')")
            pattern = f"%{literal}%"
            values.extend((pattern, pattern))

        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        decoded = self._decode_cursor(cursor)
        with self._lock:
            # nosec B608: SQL fragments above are fixed literals/allowlisted column names;
            # every user-supplied value is passed separately through SQLite placeholders.
            total_row = self._connection.execute(
                "SELECT COUNT(*) FROM telemetry_evidence_index i" + where, values  # nosec B608
            ).fetchone()
            total_count = int(total_row[0]) if total_row else 0
            page_clauses = list(clauses)
            page_values = list(values)
            if decoded is not None:
                page_clauses.append("(i.timestamp > ? OR (i.timestamp = ? AND i.event_id > ?))")
                page_values.extend((decoded[0], decoded[0], decoded[1]))
            page_where = " WHERE " + " AND ".join(page_clauses) if page_clauses else ""
            # nosec B608: only fixed SQL predicates and allowlisted identifiers are composed;
            # cursor and filter values remain bound parameters.
            rows = self._connection.execute(
                """SELECT r.payload, i.timestamp, i.event_id
                FROM telemetry_evidence_index i
                JOIN records r ON r.collection=? AND r.record_id=i.event_id"""
                + page_where  # nosec B608
                + " ORDER BY i.timestamp ASC, i.event_id ASC LIMIT ?",
                [self._EVIDENCE_COLLECTION, *page_values, limit + 1],
            ).fetchall()
        has_more = len(rows) > limit
        selected = rows[:limit]
        next_cursor = (
            self._encode_cursor(selected[-1][1], selected[-1][2])
            if has_more and selected else None
        )
        try:
            payloads = [json.loads(row[0]) for row in selected]
        except json.JSONDecodeError as exc:
            raise StorageError(
                "Unable to decode indexed telemetry evidence",
                {"collection": self._EVIDENCE_COLLECTION},
            ) from exc
        return {
            "records": payloads,
            "total_count": total_count,
            "returned_count": len(payloads),
            "truncated": has_more,
            "next_cursor": next_cursor,
        }

    def purge_expired_telemetry_evidence(
        self,
        cutoff: datetime,
        *,
        batch_size: int,
    ) -> list[UUID]:
        """Atomically delete one bounded batch of evidence older than cutoff.

        The authoritative JSON record and derived search-index row are removed
        in the same transaction. The caller schedules subsequent batches.
        """
        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            raise ValueError("Evidence retention cutoff must be timezone-aware.")
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or not 1 <= batch_size <= 10_000:
            raise ValueError("Evidence retention batch_size must be between 1 and 10000.")
        cutoff_value = cutoff.astimezone(UTC).isoformat()
        try:
            with self._lock, self._connection:
                rows = self._connection.execute(
                    """SELECT event_id FROM telemetry_evidence_index
                    WHERE timestamp < ?
                    ORDER BY timestamp ASC, event_id ASC
                    LIMIT ?""",
                    (cutoff_value, batch_size),
                ).fetchall()
                event_ids = [UUID(str(row[0])) for row in rows]
                if event_ids:
                    values = [(self._EVIDENCE_COLLECTION, str(event_id)) for event_id in event_ids]
                    self._connection.executemany(
                        "DELETE FROM records WHERE collection=? AND record_id=?",
                        values,
                    )
                    self._connection.executemany(
                        "DELETE FROM telemetry_evidence_index WHERE event_id=?",
                        [(str(event_id),) for event_id in event_ids],
                    )
            return event_ids
        except (sqlite3.Error, ValueError, TypeError) as exc:
            raise StorageError(
                "Unable to apply telemetry evidence retention batch",
                {"collection": self._EVIDENCE_COLLECTION},
            ) from exc

    def checkpoint_wal(self) -> tuple[int, int, int]:
        """Run a non-blocking passive WAL checkpoint and return SQLite counters."""
        try:
            with self._lock:
                row = self._connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
            return (int(row[0]), int(row[1]), int(row[2])) if row else (0, 0, 0)
        except sqlite3.Error as exc:
            raise StorageError(
                "Unable to checkpoint telemetry evidence WAL",
                {"collection": self._EVIDENCE_COLLECTION},
            ) from exc

    def get_storage_metrics(self) -> dict[str, int]:
        """Return inexpensive SQLite file and durable evidence size metrics."""
        database_bytes = self._path.stat().st_size if self._path.exists() else 0
        wal_path = Path(f"{self._path}-wal")
        wal_bytes = wal_path.stat().st_size if wal_path.exists() else 0
        try:
            with self._lock:
                row = self._connection.execute(
                    "SELECT COUNT(*) FROM telemetry_evidence_index"
                ).fetchone()
            return {
                "database_bytes": database_bytes,
                "wal_bytes": wal_bytes,
                "durable_events": int(row[0]) if row else 0,
            }
        except sqlite3.Error as exc:
            raise StorageError(
                "Unable to read SQLite storage metrics",
                {"collection": self._EVIDENCE_COLLECTION},
            ) from exc

    def check_integrity(self) -> str:
        """Run SQLite quick_check and return its integrity status."""
        try:
            with self._lock:
                row = self._connection.execute("PRAGMA quick_check").fetchone()
            return str(row[0]) if row else "unknown"
        except sqlite3.Error as exc:
            raise StorageError(
                "Unable to check SQLite storage integrity",
                {"collection": self._EVIDENCE_COLLECTION},
            ) from exc

    def count_telemetry_evidence(self) -> int:
        """Return the durable evidence row count, independent of the hot cache."""
        try:
            with self._lock:
                row = self._connection.execute(
                    "SELECT COUNT(*) FROM telemetry_evidence_index"
                ).fetchone()
            return int(row[0]) if row else 0
        except sqlite3.Error as exc:
            raise StorageError(
                "Unable to count durable telemetry evidence",
                {"collection": self._EVIDENCE_COLLECTION},
            ) from exc

    def close(self) -> None:
        with self._lock:
            self._connection.close()


# Kept so existing imports and configuration wiring remain valid.
SQLiteStorage = SQLiteAdapter
