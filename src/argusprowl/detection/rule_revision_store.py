"""Append-only persistence for validated detector rule revisions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid5

from argusprowl.detection.rule_loader import RuleDefinition
from argusprowl.exceptions.exceptions import DetectionError
from argusprowl.interfaces.storage import Storage

_RULE_REVISION_NAMESPACE = UUID("af1a4b3d-93b8-4e93-b6f1-24aaf1d57a5e")
_RULE_REVISION_COLLECTION = "detector_rule_revisions"
_MAX_HISTORY_SCAN = 10_000


@dataclass(frozen=True, slots=True)
class RuleRevision:
    """Immutable, content-addressed snapshot of one rule revision."""

    rule_id: str
    version: int
    content_sha256: str
    detector: str
    enabled: bool
    confidence_threshold: float
    parameters: dict[str, Any]
    tactic: str | None
    technique: str | None
    source_path: str
    actor: str
    change_reason: str
    created_at: str
    revision_id: str
    rollback_from_version: int | None = None


class RuleRevisionStore:
    """Persist immutable rule snapshots using the application's Storage contract.

    The caller must supply an authenticated actor and change reason. The store
    never edits the active YAML file or silently activates a historical revision.
    """

    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    @staticmethod
    def _snapshot(rule: RuleDefinition) -> dict[str, object]:
        return {
            "rule_id": rule.rule_id,
            "version": rule.version,
            "detector": rule.detector,
            "enabled": rule.enabled,
            "confidence_threshold": float(rule.confidence),
            "parameters": rule.parameters,
            "tactic": rule.tactic,
            "technique": rule.technique,
            "source_path": rule.path.as_posix(),
        }

    @staticmethod
    def _canonical_json(value: object) -> str:
        try:
            return json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise DetectionError("Rule revision contains non-JSON or non-finite values.") from exc

    @staticmethod
    def _revision_uuid(rule_id: str, version: int) -> UUID:
        return uuid5(_RULE_REVISION_NAMESPACE, f"{rule_id}:{version}")

    def record_revision(
        self,
        rule: RuleDefinition,
        *,
        actor: str,
        change_reason: str,
        rollback_from_version: int | None = None,
    ) -> RuleRevision:
        """Append a revision; repeated identical writes are idempotent."""
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("A non-empty authenticated actor is required.")
        if not isinstance(change_reason, str) or not change_reason.strip():
            raise ValueError("A non-empty change reason is required.")
        if (
            not isinstance(rule.version, int)
            or isinstance(rule.version, bool)
            or rule.version < 1
        ):
            raise DetectionError("Rule revision version must be a positive integer.")

        snapshot = self._snapshot(rule)
        content_hash = hashlib.sha256(self._canonical_json(snapshot).encode("utf-8")).hexdigest()
        revision_id = self._revision_uuid(rule.rule_id, rule.version)
        existing = self._storage.load(_RULE_REVISION_COLLECTION, revision_id)
        if existing is not None:
            if existing.get("content_sha256") != content_hash:
                raise DetectionError(
                    "Rule revision is immutable; this version already has different content.",
                    details={"rule_id": rule.rule_id, "version": rule.version},
                )
            return self._from_record(existing)

        history = self.history(rule.rule_id, limit=_MAX_HISTORY_SCAN)
        latest_version = history[0].version if history else 0
        if rule.version != latest_version + 1:
            raise DetectionError(
                "Rule revisions must increase by exactly one.",
                details={
                    "rule_id": rule.rule_id,
                    "expected_version": latest_version + 1,
                    "received_version": rule.version,
                },
            )

        created_at = datetime.now(UTC).isoformat()
        record: dict[str, object] = {
            **snapshot,
            "content_sha256": content_hash,
            "actor": actor.strip(),
            "change_reason": change_reason.strip(),
            "created_at": created_at,
            "revision_id": str(revision_id),
            "rollback_from_version": rollback_from_version,
        }
        inserted = self._storage.save_if_absent(_RULE_REVISION_COLLECTION, revision_id, record)
        if not inserted:
            # Another writer may have won the same revision key. Re-read and
            # verify the content; never turn a concurrent race into an overwrite.
            existing = self._storage.load(_RULE_REVISION_COLLECTION, revision_id)
            if existing is None or existing.get("content_sha256") != content_hash:
                raise DetectionError(
                    "Rule revision is immutable; this version was concurrently created with different content.",
                    details={"rule_id": rule.rule_id, "version": rule.version},
                )
            return self._from_record(existing)
        return self._from_record(record)

    def history(self, rule_id: str, *, limit: int = 100) -> list[RuleRevision]:
        """Return newest-first revision history for one stable rule identity."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("Rule revision history limit must be between 1 and 1000.")
        records = self._storage.list_records(_RULE_REVISION_COLLECTION, _MAX_HISTORY_SCAN)
        revisions = [
            self._from_record(record)
            for record in records
            if record.get("rule_id") == rule_id
        ]
        revisions.sort(key=lambda item: item.version, reverse=True)
        return revisions[:limit]

    def rollback_candidate(self, rule_id: str, target_version: int) -> dict[str, object]:
        """Build, but do not activate, a new-version snapshot from prior content."""
        if not isinstance(target_version, int) or isinstance(target_version, bool) or target_version < 1:
            raise ValueError("Rollback target version must be a positive integer.")
        target_id = self._revision_uuid(rule_id, target_version)
        target = self._storage.load(_RULE_REVISION_COLLECTION, target_id)
        if target is None:
            raise DetectionError(
                "Requested rule revision does not exist.",
                details={"rule_id": rule_id, "version": target_version},
            )
        latest = self.history(rule_id, limit=1)
        if not latest:
            raise DetectionError("Rule revision history is empty.")
        candidate = {
            "rule_id": rule_id,
            "version": latest[0].version + 1,
            "detector": target["detector"],
            "enabled": target["enabled"],
            "confidence_threshold": target["confidence_threshold"],
            "parameters": target["parameters"],
            "tactic": target.get("tactic"),
            "technique": target.get("technique"),
            "rollback_from_version": target_version,
        }
        return candidate

    @staticmethod
    def _from_record(record: dict[str, object]) -> RuleRevision:
        return RuleRevision(
            rule_id=str(record["rule_id"]),
            version=int(record["version"]),
            content_sha256=str(record["content_sha256"]),
            detector=str(record["detector"]),
            enabled=bool(record["enabled"]),
            confidence_threshold=float(record["confidence_threshold"]),
            parameters=dict(record["parameters"]),
            tactic=str(record["tactic"]) if record.get("tactic") is not None else None,
            technique=str(record["technique"]) if record.get("technique") is not None else None,
            source_path=str(record["source_path"]),
            actor=str(record["actor"]),
            change_reason=str(record["change_reason"]),
            created_at=str(record["created_at"]),
            revision_id=str(record["revision_id"]),
            rollback_from_version=(
                int(record["rollback_from_version"])
                if record.get("rollback_from_version") is not None
                else None
            ),
        )
