"""Versioned JSON serialization for persisted hunt aggregates."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from argusprowl.models.hunt import (
    EvidenceRole,
    FindingDisposition,
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

SCHEMA_VERSION = 1


def _dt(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def serialize_hunt(hunt: Hunt) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "hunt_id": str(hunt.hunt_id),
        "title": hunt.title,
        "hypothesis": hunt.hypothesis,
        "created_by": hunt.created_by,
        "status": hunt.status.value,
        "scope": {
            "start_time": _dt(hunt.scope.start_time),
            "end_time": _dt(hunt.scope.end_time),
            "hosts": list(hunt.scope.hosts),
            "users": list(hunt.scope.users),
            "sources": list(hunt.scope.sources),
        },
        "queries": [{
            "query_id": str(q.query_id), "name": q.name, "definition": q.definition,
            "version": q.version, "created_at": _dt(q.created_at),
        } for q in hunt.queries],
        "executions": [{
            "execution_id": str(e.execution_id), "query_id": str(e.query_id),
            "query_version": e.query_version, "started_at": _dt(e.started_at),
            "completed_at": _dt(e.completed_at), "result_count": e.result_count,
            "data_sources": list(e.data_sources),
            "evidence_event_ids": [str(value) for value in e.evidence_event_ids],
        } for e in hunt.executions],
        "evidence_references": [{
            "event_id": str(e.event_id), "role": e.role.value, "added_by": e.added_by,
            "note": e.note, "added_at": _dt(e.added_at),
        } for e in hunt.evidence_references],
        "findings": [{
            "finding_id": str(f.finding_id), "title": f.title,
            "description": f.description, "disposition": f.disposition.value,
            "author": f.author, "evidence_event_ids": [str(value) for value in f.evidence_event_ids],
            "created_at": _dt(f.created_at),
        } for f in hunt.findings],
        "conclusion": None if hunt.conclusion is None else {
            "summary": hunt.conclusion.summary, "disposition": hunt.conclusion.disposition.value,
            "confidence": hunt.conclusion.confidence, "author": hunt.conclusion.author,
            "updated_at": _dt(hunt.conclusion.updated_at),
        },
        "audit_history": [{
            "entry_id": str(a.entry_id), "action": a.action, "actor": a.actor,
            "timestamp": _dt(a.timestamp), "details": a.details,
        } for a in hunt.audit_history],
        "created_at": _dt(hunt.created_at),
        "updated_at": _dt(hunt.updated_at),
        "revision": hunt.revision,
    }


def deserialize_hunt(data: dict[str, object]) -> Hunt:
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported persisted hunt schema version.")
    scope_data = data["scope"]
    assert isinstance(scope_data, dict)
    scope = HuntScope(
        start_time=datetime.fromisoformat(scope_data["start_time"]) if scope_data.get("start_time") else None,
        end_time=datetime.fromisoformat(scope_data["end_time"]) if scope_data.get("end_time") else None,
        hosts=tuple(scope_data.get("hosts", [])),
        users=tuple(scope_data.get("users", [])),
        sources=tuple(scope_data.get("sources", [])),
    )
    queries = tuple(HuntQuery(
        query_id=UUID(q["query_id"]), name=q["name"], definition=q["definition"],
        version=int(q["version"]), created_at=datetime.fromisoformat(q["created_at"]),
    ) for q in data.get("queries", []))
    executions = tuple(HuntExecution(
        execution_id=UUID(e["execution_id"]), query_id=UUID(e["query_id"]),
        query_version=int(e["query_version"]), started_at=datetime.fromisoformat(e["started_at"]),
        completed_at=datetime.fromisoformat(e["completed_at"]), result_count=int(e["result_count"]),
        data_sources=tuple(e.get("data_sources", [])),
        evidence_event_ids=tuple(UUID(v) for v in e.get("evidence_event_ids", [])),
    ) for e in data.get("executions", []))
    evidence = tuple(HuntEvidenceReference(
        event_id=UUID(e["event_id"]), role=EvidenceRole(e["role"]), added_by=e["added_by"],
        note=e.get("note", ""), added_at=datetime.fromisoformat(e["added_at"]),
    ) for e in data.get("evidence_references", []))
    findings = tuple(HuntFinding(
        finding_id=UUID(f["finding_id"]), title=f["title"], description=f["description"],
        disposition=FindingDisposition(f["disposition"]), author=f["author"],
        evidence_event_ids=tuple(UUID(v) for v in f.get("evidence_event_ids", [])),
        created_at=datetime.fromisoformat(f["created_at"]),
    ) for f in data.get("findings", []))
    c = data.get("conclusion")
    conclusion = None if c is None else HuntConclusion(
        summary=c["summary"], disposition=FindingDisposition(c["disposition"]),
        confidence=float(c["confidence"]), author=c["author"],
        updated_at=datetime.fromisoformat(c["updated_at"]),
    )
    audit = tuple(HuntAuditEntry(
        entry_id=UUID(a["entry_id"]), action=a["action"], actor=a["actor"],
        timestamp=datetime.fromisoformat(a["timestamp"]), details=a.get("details", {}),
    ) for a in data.get("audit_history", []))
    return Hunt(
        hunt_id=UUID(data["hunt_id"]), title=data["title"], hypothesis=data["hypothesis"],
        created_by=data["created_by"], status=HuntStatus(data["status"]), scope=scope,
        queries=queries, executions=executions, evidence_references=evidence,
        findings=findings, conclusion=conclusion, audit_history=audit,
        created_at=datetime.fromisoformat(data["created_at"]),
        updated_at=datetime.fromisoformat(data["updated_at"]), revision=int(data["revision"]),
    )
