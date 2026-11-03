"""Persistent hypothesis-driven hunt domain models.

Hunts represent analyst investigation records. They deliberately keep observed
telemetry references, analytical findings, and analyst conclusions separate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4


class HuntStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class EvidenceRole(StrEnum):
    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    CONTEXT = "context"


class FindingDisposition(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class HuntScope:
    """Explicit investigation boundaries."""

    start_time: datetime | None = None
    end_time: datetime | None = None
    hosts: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.start_time and self.start_time.utcoffset() is None:
            raise ValueError("Hunt scope start_time must be timezone-aware.")
        if self.end_time and self.end_time.utcoffset() is None:
            raise ValueError("Hunt scope end_time must be timezone-aware.")
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("Hunt scope start_time must not be after end_time.")
        for values, label in ((self.hosts, "hosts"), (self.users, "users"), (self.sources, "sources")):
            if len(values) > 500 or any(not value.strip() or len(value) > 256 for value in values):
                raise ValueError(f"Hunt scope {label} must contain at most 500 non-empty values of 256 characters or fewer.")


@dataclass(frozen=True, slots=True)
class HuntQuery:
    """Versioned, serializable query definition; execution is handled separately."""

    name: str
    definition: dict[str, object]
    version: int = 1
    query_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not self.name.strip() or len(self.name) > 128:
            raise ValueError("Query name must contain 1-128 characters.")
        if not isinstance(self.definition, dict):
            raise ValueError("Query definition must be an object.")
        if self.version < 1:
            raise ValueError("Query version must be positive.")


@dataclass(frozen=True, slots=True)
class HuntExecution:
    """Immutable execution receipt, not a claim that a query engine ran it."""

    query_id: UUID
    query_version: int
    started_at: datetime
    completed_at: datetime
    result_count: int
    data_sources: tuple[str, ...] = ()
    execution_id: UUID = field(default_factory=uuid4)
    evidence_event_ids: tuple[UUID, ...] = ()
    status: str = "complete"
    error: str | None = None
    truncated: bool = False

    def __post_init__(self) -> None:
        if self.status not in {"complete", "partial", "degraded", "failed"}:
            raise ValueError("Execution status must be complete, partial, degraded, or failed.")
        if self.error is not None and len(self.error) > 2000:
            raise ValueError("Execution error must not exceed 2000 characters.")
        if self.started_at.utcoffset() is None or self.completed_at.utcoffset() is None:
            raise ValueError("Execution timestamps must be timezone-aware.")
        if self.query_version < 1:
            raise ValueError("Execution query_version must be positive.")
        if self.completed_at < self.started_at:
            raise ValueError("Execution completed_at must not precede started_at.")
        if self.result_count < 0:
            raise ValueError("Execution result_count cannot be negative.")
        if len(self.evidence_event_ids) > 10000:
            raise ValueError("An execution may reference at most 10000 evidence events.")


@dataclass(frozen=True, slots=True)
class HuntEvidenceReference:
    """Reference to existing telemetry; telemetry itself remains authoritative elsewhere."""

    event_id: UUID
    role: EvidenceRole
    added_by: str
    note: str = ""
    added_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not self.added_by.strip() or len(self.added_by) > 256:
            raise ValueError("Evidence added_by must contain 1-256 characters.")
        if len(self.note) > 2000:
            raise ValueError("Evidence note must not exceed 2000 characters.")


@dataclass(frozen=True, slots=True)
class HuntFinding:
    """Analyst-authored finding, explicitly distinct from raw observations."""

    title: str
    description: str
    disposition: FindingDisposition
    author: str
    evidence_event_ids: tuple[UUID, ...] = ()
    finding_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not self.title.strip() or len(self.title) > 200:
            raise ValueError("Finding title must contain 1-200 characters.")
        if not self.description.strip() or len(self.description) > 4000:
            raise ValueError("Finding description must contain 1-4000 characters.")
        if not self.author.strip() or len(self.author) > 256:
            raise ValueError("Finding author must contain 1-256 characters.")


@dataclass(frozen=True, slots=True)
class HuntConclusion:
    """Analyst conclusion and confidence, never inferred automatically."""

    summary: str
    disposition: FindingDisposition
    confidence: float
    author: str
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not self.summary.strip() or len(self.summary) > 4000:
            raise ValueError("Conclusion summary must contain 1-4000 characters.")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Conclusion confidence must be between 0 and 1.")
        if not self.author.strip() or len(self.author) > 256:
            raise ValueError("Conclusion author must contain 1-256 characters.")


@dataclass(frozen=True, slots=True)
class HuntAuditEntry:
    """Append-only domain history for material hunt changes."""

    action: str
    actor: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    details: dict[str, object] = field(default_factory=dict)
    entry_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.action.strip() or not self.actor.strip():
            raise ValueError("Hunt audit action and actor must not be empty.")


@dataclass(frozen=True, slots=True)
class Hunt:
    """Persistent investigation aggregate."""

    title: str
    hypothesis: str
    created_by: str
    hunt_id: UUID = field(default_factory=uuid4)
    status: HuntStatus = HuntStatus.DRAFT
    scope: HuntScope = field(default_factory=HuntScope)
    queries: tuple[HuntQuery, ...] = ()
    executions: tuple[HuntExecution, ...] = ()
    evidence_references: tuple[HuntEvidenceReference, ...] = ()
    findings: tuple[HuntFinding, ...] = ()
    conclusion: HuntConclusion | None = None
    audit_history: tuple[HuntAuditEntry, ...] = ()
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    revision: int = 1

    def __post_init__(self) -> None:
        if not self.title.strip() or len(self.title) > 200:
            raise ValueError("Hunt title must contain 1-200 characters.")
        if not self.hypothesis.strip() or len(self.hypothesis) > 4000:
            raise ValueError("Hunt hypothesis must contain 1-4000 characters.")
        if not self.created_by.strip() or len(self.created_by) > 256:
            raise ValueError("Hunt created_by must contain 1-256 characters.")
        if self.revision < 1:
            raise ValueError("Hunt revision must be positive.")
