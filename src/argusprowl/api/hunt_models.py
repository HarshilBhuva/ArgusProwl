"""Validated HTTP schemas for persistent hunts."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from argusprowl.models.hunt import EvidenceRole, FindingDisposition, HuntStatus


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HuntCreateRequest(StrictRequest):
    title: str = Field(min_length=1, max_length=200)
    hypothesis: str = Field(min_length=1, max_length=4000)


class HuntHypothesisRequest(StrictRequest):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    hypothesis: str | None = Field(default=None, min_length=1, max_length=4000)

    @model_validator(mode="after")
    def require_update(self) -> HuntHypothesisRequest:
        if self.title is None and self.hypothesis is None:
            raise ValueError("At least one of title or hypothesis must be provided")
        return self


class HuntScopeRequest(StrictRequest):
    start_time: datetime | None = None
    end_time: datetime | None = None
    hosts: list[str] = Field(default_factory=list, max_length=500)
    users: list[str] = Field(default_factory=list, max_length=500)
    sources: list[str] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def validate_scope(self) -> HuntScopeRequest:
        for value in (self.start_time, self.end_time):
            if value is not None and value.utcoffset() is None:
                raise ValueError("Scope timestamps must include a timezone offset")
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValueError("start_time must not be after end_time")
        for values in (self.hosts, self.users, self.sources):
            if any(not value.strip() or len(value) > 256 for value in values):
                raise ValueError("Scope values must contain 1-256 characters")
        return self


class HuntQueryRequest(StrictRequest):
    name: str = Field(min_length=1, max_length=128)
    definition: dict[str, object]


class HuntExecutionRequest(StrictRequest):
    query_id: UUID
    query_version: int = Field(ge=1)
    started_at: datetime
    completed_at: datetime
    result_count: int = Field(ge=0, le=100_000_000)
    data_sources: list[str] = Field(default_factory=list, max_length=100)
    evidence_event_ids: list[UUID] = Field(default_factory=list, max_length=10000)
    status: str = Field(default="complete", pattern="^(complete|partial|degraded|failed)$")
    error: str | None = Field(default=None, max_length=2000)
    truncated: bool = False

    @model_validator(mode="after")
    def validate_execution(self) -> HuntExecutionRequest:
        if self.started_at.utcoffset() is None or self.completed_at.utcoffset() is None:
            raise ValueError("Execution timestamps must include a timezone offset")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        if any(not value.strip() or len(value) > 128 for value in self.data_sources):
            raise ValueError("Data source names must contain 1-128 characters")
        return self


class HuntEvidenceRequest(StrictRequest):
    event_id: UUID
    role: EvidenceRole
    note: str = Field(default="", max_length=2000)


class HuntFindingRequest(StrictRequest):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    disposition: FindingDisposition
    evidence_event_ids: list[UUID] = Field(default_factory=list, max_length=500)


class HuntConclusionRequest(StrictRequest):
    summary: str = Field(min_length=1, max_length=4000)
    disposition: FindingDisposition
    confidence: float = Field(ge=0.0, le=1.0)


class HuntStatusRequest(StrictRequest):
    status: HuntStatus


class HuntListQuery(StrictRequest):
    status: HuntStatus | None = None
    limit: int = Field(default=100, ge=1, le=500)
