"""Request models for authenticated detector rule lifecycle operations."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RuleUpdateRequest(BaseModel):
    """Optimistic-concurrency guarded rule revision request."""

    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(..., ge=1)
    change_reason: str = Field(..., min_length=3, max_length=500)
    enabled: bool | None = None
    confidence_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    parameters: dict[str, Any] | None = None
    tactic: str | None = Field(default=None, max_length=32)
    technique: str | None = Field(default=None, max_length=32)


class RuleRollbackRequest(BaseModel):
    """Request to create and activate a forward revision from history."""

    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(..., ge=1)
    target_version: int = Field(..., ge=1)
    change_reason: str = Field(..., min_length=3, max_length=500)
