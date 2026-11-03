"""Execute saved Hunt query versions against the telemetry evidence service."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from argusprowl.hunting.hunt_service import HuntConflictError, HuntNotFoundError, HuntService
from argusprowl.models.hunt import HuntExecution, HuntEvidenceReference, EvidenceRole
from argusprowl.services.telemetry_evidence_service import TelemetryEvidenceService


@dataclass(frozen=True, slots=True)
class HuntQueryExecutionResult:
    hunt: object
    execution: HuntExecution


class HuntQueryExecutionService:
    """Translate a strict structured query to a bounded evidence search."""

    MAX_RESULT_LIMIT = 500
    ALLOWED_FIELDS = frozenset({
        "event_id", "start_time", "end_time", "entity_type", "entity_id",
        "src_ip", "dst_ip", "domain", "event_type", "source_type", "limit",
    })

    def __init__(self, evidence: TelemetryEvidenceService) -> None:
        self._evidence = evidence

    @classmethod
    def _compile(cls, definition: dict[str, object], scope) -> dict[str, object]:
        if not isinstance(definition, dict):
            raise ValueError("Query definition must be an object.")
        unknown = set(definition) - cls.ALLOWED_FIELDS
        if unknown:
            raise ValueError(f"Unsupported query fields: {', '.join(sorted(unknown))}")
        limit = definition.get("limit", cls.MAX_RESULT_LIMIT)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= cls.MAX_RESULT_LIMIT:
            raise ValueError(f"Query limit must be between 1 and {cls.MAX_RESULT_LIMIT}.")
        params = dict(definition)
        params.pop("limit", None)
        for name in ("start_time", "end_time"):
            value = params.get(name)
            if isinstance(value, str):
                try:
                    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError as exc:
                    raise ValueError(f"{name} must be an ISO 8601 timestamp.") from exc
            if value is not None and (not isinstance(value, datetime) or value.utcoffset() is None):
                raise ValueError(f"{name} must include a timezone.")
            if value is not None:
                params[name] = value
        for key, max_len in (("entity_type",64),("entity_id",256),("src_ip",64),("dst_ip",64),("domain",256),("event_type",128),("source_type",128)):
            value=params.get(key)
            if value is not None and (not isinstance(value,str) or not value.strip() or len(value)>max_len):
                raise ValueError(f"{key} must be a non-empty string of at most {max_len} characters.")
        if "event_id" in params:
            try: params["event_id"] = UUID(str(params["event_id"]))
            except ValueError as exc: raise ValueError("event_id must be a UUID.") from exc
        if scope.start_time:
            params["start_time"] = max(params.get("start_time", scope.start_time), scope.start_time)
        if scope.end_time:
            params["end_time"] = min(params.get("end_time", scope.end_time), scope.end_time)
        if params.get("start_time") and params.get("end_time") and params["start_time"] > params["end_time"]:
            raise ValueError("Query time range does not intersect the hunt scope.")
        return {"limit": limit, **params}

    def execute(self, hunts: HuntService, hunt_id: UUID, query_id: UUID, version: int, actor: str) -> HuntQueryExecutionResult:
        hunt = hunts.get_hunt(hunt_id)
        if hunt is None:
            raise HuntNotFoundError(f"Hunt {hunt_id} not found.")
        query = next((item for item in hunt.queries if item.query_id == query_id and item.version == version), None)
        if query is None:
            raise HuntConflictError("Execution must reference an exact saved query ID and version.")
        params = self._compile(query.definition, hunt.scope)
        started = datetime.now(UTC)
        status, error, truncated, ids, sources = "complete", None, False, (), ()
        try:
            found = self._evidence.search(**params)
            ids = tuple(found.events.keys())
            truncated = found.truncated
            sources = tuple(sorted({event.source_type for event in found.events.values()}))
            status = "partial" if truncated else ("degraded" if found.status != "AVAILABLE" else "complete")
            error = found.reason if found.status != "AVAILABLE" else None
            # Verify each match against the durable authoritative detail lookup.
            verified = []
            if found.status == "UNAVAILABLE":
                status, error = "failed", found.reason or "Evidence store unavailable."
            else:
                for event_id in ids:
                    detail = self._evidence.get_detail(event_id)
                    if detail is None or detail.event is None:
                        status = "degraded"
                        error = error or "One or more matched events could not be verified in evidence storage."
                        continue
                    if detail.status == "UNAVAILABLE":
                        status = "failed"
                        error = detail.reason or "Evidence storage unavailable during verification."
                        break
                    if detail.status != "AVAILABLE":
                        status = "degraded"
                        error = error or detail.reason or "Evidence recovery is degraded."
                        continue
                    verified.append(event_id)
                ids = tuple(verified)
        except Exception as exc:
            status, error, ids = "failed", str(exc)[:2000], ()
        finished = datetime.now(UTC)
        execution = HuntExecution(
            query_id=query_id, query_version=version, started_at=started, completed_at=finished,
            result_count=len(ids), data_sources=sources, evidence_event_ids=ids,
            status=status, error=error, truncated=truncated,
        )
        updated = hunts.record_execution(hunt_id, execution, actor)
        if status != "failed":
            for event_id in ids:
                if not any(ref.event_id == event_id for ref in updated.evidence_references):
                    updated = hunts.attach_evidence(hunt_id, HuntEvidenceReference(
                        event_id=event_id, role=EvidenceRole.CONTEXT, added_by=actor,
                        note=f"Matched by query {query.name} v{version} (execution {execution.execution_id}).",
                    ))
        return HuntQueryExecutionResult(updated, execution)
