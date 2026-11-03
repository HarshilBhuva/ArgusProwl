"""Durable repository for per-rule temporal correlation state."""

from __future__ import annotations

import json
from uuid import NAMESPACE_URL, UUID, uuid5

from argusprowl.interfaces.storage import Storage


class CorrelationStateRepository:
    """Persist one bounded state snapshot per rule and correlation group.

    Group records use deterministic UUIDs so detectors can restore state lazily
    without scanning the entire storage collection after a restart.
    """

    COLLECTION = "correlation_state"
    SCHEMA_VERSION = 1

    def __init__(
        self, storage: Storage, rule_id: str, state_identity: str = "default"
    ) -> None:
        if not rule_id or not rule_id.strip():
            raise ValueError("Correlation state rule_id must not be empty.")
        if not state_identity or not state_identity.strip():
            raise ValueError("Correlation state identity must not be empty.")
        self._storage = storage
        self._rule_id = rule_id
        self._state_identity = state_identity

    def _record_id(self, group_key: tuple[str, ...]) -> UUID:
        identity = json.dumps(
            [self._rule_id, self._state_identity, list(group_key)],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        return uuid5(NAMESPACE_URL, f"argusprowl:correlation-state:{identity}")

    def load(self, group_key: tuple[str, ...]) -> dict[str, object] | None:
        """Load and validate a snapshot for one rule/group pair."""
        record = self._storage.load(self.COLLECTION, self._record_id(group_key))
        if record is None:
            return None
        if (
            record.get("schema_version") != self.SCHEMA_VERSION
            or record.get("rule_id") != self._rule_id
            or record.get("state_identity") != self._state_identity
            or record.get("group_key") != list(group_key)
            or not isinstance(record.get("state"), dict)
        ):
            raise ValueError("Persisted correlation state identity or schema is invalid.")
        return record["state"]

    def save(self, group_key: tuple[str, ...], state: dict[str, object]) -> None:
        """Atomically replace the snapshot for one rule/group pair."""
        self._storage.save(
            self.COLLECTION,
            self._record_id(group_key),
            {
                "schema_version": self.SCHEMA_VERSION,
                "rule_id": self._rule_id,
                "state_identity": self._state_identity,
                "group_key": list(group_key),
                "state": state,
            },
        )

    def delete(self, group_key: tuple[str, ...]) -> bool:
        """Delete persisted state when the detector evicts a group."""
        return self._storage.delete(self.COLLECTION, self._record_id(group_key))
