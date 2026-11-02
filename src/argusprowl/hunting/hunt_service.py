"""Persistent application service for hypothesis-driven hunts.

Each mutation persists the complete aggregate before publishing the updated
in-memory value. This is a single-node/single-process service built on the
existing Storage abstraction; it does not claim multi-process concurrency.
"""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from threading import RLock
from uuid import UUID, uuid4

from argusprowl.hunting.hunt_service_serialization import deserialize_hunt, serialize_hunt
from argusprowl.interfaces.storage import Storage
from argusprowl.models.hunt import (
    Hunt,
    HuntAuditEntry,
    HuntConclusion,
    HuntEvidenceReference,
    HuntExecution,
    HuntFinding,
    HuntQuery,
    HuntScope,
    HuntStatus,
)


class HuntServiceError(Exception):
    """Base error for hunt service failures."""


class HuntNotFoundError(HuntServiceError):
    """Requested hunt does not exist."""


class HuntConflictError(HuntServiceError):
    """Requested mutation conflicts with the current hunt state."""


class HuntService:
    """Owns persistent hunt lifecycle and append-only domain history."""

    COLLECTION = "hunts"

    def __init__(self, storage: Storage, *, max_hunts: int = 10000) -> None:
        if not isinstance(max_hunts, int) or isinstance(max_hunts, bool) or max_hunts < 1:
            raise ValueError("max_hunts must be a positive integer.")
        self._storage = storage
        self._max_hunts = max_hunts
        self._lock = RLock()
        self._hunts: dict[UUID, Hunt] = {}
        self._recover()

    def _recover(self) -> None:
        try:
            rows = self._storage.list_records(self.COLLECTION, limit=self._max_hunts)
            recovered: dict[UUID, Hunt] = {}
            for payload in reversed(rows):
                hunt = deserialize_hunt(payload)
                recovered[hunt.hunt_id] = hunt
            self._hunts = recovered
        except Exception as exc:
            raise HuntServiceError("Persisted hunt records could not be recovered.") from exc

    def _commit(self, hunt: Hunt) -> Hunt:
        try:
            self._storage.save(self.COLLECTION, hunt.hunt_id, serialize_hunt(hunt))
        except Exception as exc:
            raise HuntServiceError("Hunt mutation could not be persisted.") from exc
        stored = deserialize_hunt(serialize_hunt(hunt))
        self._hunts[hunt.hunt_id] = stored
        # Never expose nested mutable dictionaries owned by the service cache.
        return deserialize_hunt(serialize_hunt(stored))

    @staticmethod
    def _audit(hunt: Hunt, action: str, actor: str, **details: object) -> tuple[HuntAuditEntry, ...]:
        entry = HuntAuditEntry(action=action, actor=actor, details=details)
        return (*hunt.audit_history, entry)

    def create_hunt(self, *, title: str, hypothesis: str, actor: str) -> Hunt:
        now = datetime.now(UTC)
        hunt = Hunt(
            title=title,
            hypothesis=hypothesis,
            created_by=actor,
            created_at=now,
            updated_at=now,
            audit_history=(HuntAuditEntry(action="HUNT_CREATED", actor=actor),),
        )
        with self._lock:
            if len(self._hunts) >= self._max_hunts:
                raise HuntConflictError("Hunt capacity reached; archive or remove records before creating more.")
            return self._commit(hunt)

    def get_hunt(self, hunt_id: UUID) -> Hunt | None:
        with self._lock:
            hunt = self._hunts.get(hunt_id)
            return deserialize_hunt(serialize_hunt(hunt)) if hunt is not None else None

    def list_hunts(
        self,
        *,
        status: HuntStatus | None = None,
        created_by: str | None = None,
        limit: int = 100,
    ) -> tuple[Hunt, ...]:
        """List bounded hunts, optionally restricted to their creator."""
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500.")
        with self._lock:
            hunts = [
                hunt for hunt in self._hunts.values()
                if (status is None or hunt.status == status)
                and (created_by is None or hunt.created_by == created_by)
            ]
            hunts.sort(key=lambda item: (item.updated_at, str(item.hunt_id)), reverse=True)
            return tuple(deserialize_hunt(serialize_hunt(hunt)) for hunt in hunts[:limit])

    def count_hunts(
        self, *, status: HuntStatus | None = None, created_by: str | None = None
    ) -> int:
        """Return the number of hunts matching the optional status and owner."""
        with self._lock:
            return sum(
                1 for hunt in self._hunts.values()
                if (status is None or hunt.status == status)
                and (created_by is None or hunt.created_by == created_by)
            )

    def _require(self, hunt_id: UUID) -> Hunt:
        hunt = self._hunts.get(hunt_id)
        if hunt is None:
            raise HuntNotFoundError(f"Hunt {hunt_id} not found.")
        if hunt.status == HuntStatus.ARCHIVED:
            raise HuntConflictError("Archived hunts are read-only.")
        return hunt

    def _update(
        self,
        hunt: Hunt,
        actor: str,
        action: str,
        *,
        audit_details: dict[str, object] | None = None,
        **changes: object,
    ) -> Hunt:
        now = datetime.now(UTC)
        if len(hunt.audit_history) >= 20000:
            raise HuntConflictError("Hunt audit history capacity reached.")
        updated = replace(
            hunt,
            **changes,
            updated_at=now,
            revision=hunt.revision + 1,
            audit_history=self._audit(
                hunt, action, actor, revision=hunt.revision + 1, **(audit_details or {})
            ),
        )
        return self._commit(updated)

    def update_hypothesis(
        self,
        hunt_id: UUID,
        actor: str,
        *,
        title: str | None = None,
        hypothesis: str | None = None,
    ) -> Hunt:
        """Revise hunt intent while preserving the previous revision in history."""
        if title is None and hypothesis is None:
            raise ValueError("At least one of title or hypothesis must be provided.")
        with self._lock:
            hunt = self._require(hunt_id)
            changes: dict[str, object] = {}
            if title is not None:
                changes["title"] = title
            if hypothesis is not None:
                changes["hypothesis"] = hypothesis
            return self._update(
                hunt,
                actor,
                "HUNT_HYPOTHESIS_UPDATED",
                audit_details={
                    "title_changed": title is not None,
                    "hypothesis_changed": hypothesis is not None,
                },
                **changes,
            )

    def update_scope(self, hunt_id: UUID, scope: HuntScope, actor: str) -> Hunt:
        with self._lock:
            hunt = self._require(hunt_id)
            return self._update(hunt, actor, "HUNT_SCOPE_UPDATED", scope=scope)

    def save_query(self, hunt_id: UUID, *, name: str, definition: dict[str, object], actor: str) -> Hunt:
        serialized_definition = json.dumps(
            definition, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        if len(serialized_definition) > 32768:
            raise ValueError("Query definition must not exceed 32768 serialized characters.")
        normalized_definition = json.loads(serialized_definition)
        with self._lock:
            hunt = self._require(hunt_id)
            existing = next((query for query in hunt.queries if query.name == name), None)
            if existing is None and len({item.name for item in hunt.queries}) >= 100:
                raise HuntConflictError("A hunt may contain at most 100 saved query names.")
            if len(hunt.queries) >= 1000:
                raise HuntConflictError("Hunt query version history capacity reached.")
            query = HuntQuery(
                name=name,
                definition=normalized_definition,
                version=(existing.version + 1) if existing else 1,
                query_id=existing.query_id if existing else uuid4(),
            )
            # Preserve every immutable version so historical executions remain reproducible.
            queries = (*hunt.queries, query)
            return self._update(
                hunt,
                actor,
                "HUNT_QUERY_SAVED",
                queries=queries,
                audit_details={"query_name": name, "query_version": query.version},
            )

    def record_execution(self, hunt_id: UUID, execution: HuntExecution, actor: str) -> Hunt:
        with self._lock:
            hunt = self._require(hunt_id)
            query_exists = any(
                item.query_id == execution.query_id and item.version == execution.query_version
                for item in hunt.queries
            )
            if not query_exists:
                raise HuntConflictError("Execution must reference a saved query ID and version.")
            if len(hunt.executions) >= 10000:
                raise HuntConflictError("Hunt execution history capacity reached.")
            return self._update(
                hunt,
                actor,
                "HUNT_QUERY_EXECUTION_RECORDED",
                executions=(*hunt.executions, execution),
                audit_details={
                    "execution_id": str(execution.execution_id),
                    "result_count": execution.result_count,
                    "query_version": execution.query_version,
                },
            )

    def attach_evidence(self, hunt_id: UUID, reference: HuntEvidenceReference) -> Hunt:
        with self._lock:
            hunt = self._require(hunt_id)
            if any(item.event_id == reference.event_id for item in hunt.evidence_references):
                raise HuntConflictError("Evidence event is already attached to this hunt.")
            if len(hunt.evidence_references) >= 10000:
                raise HuntConflictError("Hunt evidence reference capacity reached.")
            return self._update(
                hunt,
                reference.added_by,
                "HUNT_EVIDENCE_ATTACHED",
                evidence_references=(*hunt.evidence_references, reference),
                audit_details={
                    "event_id": str(reference.event_id),
                    "evidence_role": reference.role.value,
                },
            )

    def add_finding(self, hunt_id: UUID, finding: HuntFinding) -> Hunt:
        with self._lock:
            hunt = self._require(hunt_id)
            known = {item.event_id for item in hunt.evidence_references}
            if len(hunt.findings) >= 2000:
                raise HuntConflictError("Hunt finding capacity reached.")
            if not set(finding.evidence_event_ids).issubset(known):
                raise HuntConflictError("Finding evidence must reference events already attached to the hunt.")
            return self._update(
                hunt,
                finding.author,
                "HUNT_FINDING_RECORDED",
                findings=(*hunt.findings, finding),
                audit_details={
                    "finding_id": str(finding.finding_id),
                    "disposition": finding.disposition.value,
                },
            )

    def set_conclusion(self, hunt_id: UUID, conclusion: HuntConclusion) -> Hunt:
        with self._lock:
            hunt = self._require(hunt_id)
            return self._update(
                hunt,
                conclusion.author,
                "HUNT_CONCLUSION_UPDATED",
                conclusion=conclusion,
                audit_details={
                    "disposition": conclusion.disposition.value,
                    "confidence": conclusion.confidence,
                },
            )

    def transition_status(self, hunt_id: UUID, status: HuntStatus, actor: str) -> Hunt:
        allowed = {
            HuntStatus.DRAFT: {HuntStatus.ACTIVE, HuntStatus.ARCHIVED},
            HuntStatus.ACTIVE: {HuntStatus.COMPLETED, HuntStatus.ARCHIVED},
            HuntStatus.COMPLETED: {HuntStatus.ACTIVE, HuntStatus.ARCHIVED},
            HuntStatus.ARCHIVED: set(),
        }
        with self._lock:
            hunt = self._hunts.get(hunt_id)
            if hunt is None:
                raise HuntNotFoundError(f"Hunt {hunt_id} not found.")
            if status == hunt.status:
                return deserialize_hunt(serialize_hunt(hunt))
            if status not in allowed[hunt.status]:
                raise HuntConflictError(f"Invalid hunt status transition: {hunt.status.value} -> {status.value}.")
            if status == HuntStatus.COMPLETED and hunt.conclusion is None:
                raise HuntConflictError("A hunt conclusion is required before completion.")
            return self._update(
                hunt,
                actor,
                "HUNT_STATUS_CHANGED",
                status=status,
                audit_details={"previous_status": hunt.status.value, "new_status": status.value},
            )
