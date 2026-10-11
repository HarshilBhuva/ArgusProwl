"""API request models.

Defines Pydantic request schemas for the HTTP API layer.
All externally supplied values are bounded and validated.
"""

from typing import Annotated

from pydantic import BaseModel, Field, field_validator

from argusprowl.constants.lifecycle import AlertLifecycleState
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity


class AlertSearchParams(BaseModel):
    """Query parameters for alert search.

    All fields are optional. Only non-None values are applied as filters.
    """

    limit: Annotated[int, Field(ge=1, le=100, default=20)] = Field(
        ...,
        description="Maximum number of alerts to return. Bounded to [1, 100].",
    )
    min_priority: AlertPriority | None = Field(
        default=None,
        description="Keep alerts with priority >= this value.",
    )
    min_severity: Severity | None = Field(
        default=None,
        description="Keep alerts with severity >= this value.",
    )
    rule_id: Annotated[str | None, Field(max_length=128)] = Field(
        default=None,
        description="Keep alerts whose metadata contains this rule_id.",
    )
    host: Annotated[str | None, Field(max_length=256)] = Field(
        default=None,
        description="Keep alerts whose entity_context.host matches.",
    )
    lifecycle_state: AlertLifecycleState | None = Field(
        default=None,
        description="Keep alerts with this lifecycle state.",
    )
    entity_key: Annotated[str | None, Field(max_length=256)] = Field(
        default=None,
        description="Keep alerts whose canonical entity key matches.",
    )
    incident_id: Annotated[str | None, Field(max_length=36)] = Field(
        default=None,
        description="Keep alerts whose incident_id matches (as string).",
    )

    @field_validator("limit")
    @classmethod
    def validate_limit(cls, v: int) -> int:
        """Ensure limit is a positive integer."""
        if v < 1:
            raise ValueError("limit must be at least 1")
        return v

    @field_validator("rule_id", "host", "entity_key")
    @classmethod
    def validate_string_fields(cls, v: str | None) -> str | None:
        """Ensure string fields are not empty if provided."""
        if v is not None and not v.strip():
            raise ValueError("String field must not be empty")
        return v
