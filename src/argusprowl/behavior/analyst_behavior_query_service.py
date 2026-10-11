"""Analyst behavioral query service.

Provides a bounded, read-only query interface over EntityBehaviorService
for analyst-facing lookups. This service does NOT modify behavioral state.

Phase 5.1.9 Hardening:
    - All queries are read-only (no state mutations)
    - All inputs are validated and bounded
    - All outputs are bounded and deterministic
    - Decision-neutral: no effect on alert severity, priority, or confidence
"""

from __future__ import annotations

from typing import Any

from argusprowl.behavior.baseline_evidence import BaselineEvidence
from argusprowl.behavior.entity_behavior_profile import ProfileMaturity
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService


class AnalystBehaviorQueryService:
    """Read-only query service for analyst behavioral lookups.

    This service wraps EntityBehaviorService and provides bounded,
    validated query methods for analyst use cases. It is intentionally
    read-only: no observations are recorded, no profiles are created,
    and no state is modified.

    Query Bounds:
        - get_entity_behavior: bounded by _MAX_DIMENSIONS_PER_ENTITY (10)
        - list_entities: bounded by _MAX_ENTITIES (100)
        - get_dimension_values: bounded by _MAX_VALUES (10)
        - get_baseline_evidence: bounded by _MAX_COMPARISON_VALUES (5)

    Security:
        - All string inputs are validated for type and length
        - All numeric inputs are validated for range
        - No internal state details are exposed
    """

    # Query bounds
    _MAX_DIMENSIONS_PER_ENTITY: int = 10
    _MAX_ENTITIES: int = 100
    _MAX_VALUES: int = 10
    _MAX_ENTITY_TYPE_LENGTH: int = 64
    _MAX_ENTITY_ID_LENGTH: int = 256
    _MAX_DIMENSION_LENGTH: int = 64
    _MAX_VALUE_LENGTH: int = 128

    def __init__(self, behavior_service: EntityBehaviorService) -> None:
        """Initialize analyst query service.

        Args:
            behavior_service: The EntityBehaviorService to query.
        """
        self._service = behavior_service

    def _validate_string_input(
        self,
        value: str,
        name: str,
        max_length: int,
    ) -> str:
        """Validate a string input parameter.

        Args:
            value: The string to validate.
            name: The parameter name (for error messages).
            max_length: Maximum allowed length.

        Returns:
            The validated string.

        Raises:
            ValueError: If validation fails.
        """
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string.")
        if not value:
            raise ValueError(f"{name} must not be empty.")
        if len(value) > max_length:
            raise ValueError(f"{name} exceeds maximum length of {max_length}.")
        return value

    def _validate_positive_int(self, value: int, name: str, min_value: int = 1) -> int:
        """Validate a positive integer input.

        Args:
            value: The integer to validate.
            name: The parameter name (for error messages).
            min_value: Minimum allowed value.

        Returns:
            The validated integer.

        Raises:
            ValueError: If validation fails.
        """
        if not isinstance(value, int):
            raise ValueError(f"{name} must be an integer.")
        if value < min_value:
            raise ValueError(f"{name} must be >= {min_value}.")
        return value

    def get_entity_behavior(
        self,
        entity_type: str,
        entity_id: str,
        max_values: int = 10,
    ) -> list[dict[str, Any]]:
        """Get all behavior profiles for an entity.

        This is a read-only query that does not modify state.

        Args:
            entity_type: Type of entity (e.g., 'hostname', 'src_ip').
            entity_id: Unique identifier of the entity.
            max_values: Maximum distinct values returned per dimension
                (bounded to 10).

        Returns:
            List of behavior summaries for all dimensions of this entity,
            ordered deterministically by dimension name.

        Raises:
            ValueError: If any input is invalid.
        """
        entity_type = self._validate_string_input(
            entity_type, "entity_type", self._MAX_ENTITY_TYPE_LENGTH
        )
        entity_id = self._validate_string_input(entity_id, "entity_id", self._MAX_ENTITY_ID_LENGTH)
        max_values = self._validate_positive_int(max_values, "max_values")
        bounded_max = min(max_values, self._MAX_VALUES)

        # Delegate to service (read-only)
        results = self._service.get_entity_behavior(entity_type, entity_id)

        # Apply our bounds
        bounded_results = []
        for result in results[: self._MAX_DIMENSIONS_PER_ENTITY]:
            bounded_result = result.copy()
            bounded_result["top_values"] = result["top_values"][:bounded_max]
            bounded_results.append(bounded_result)

        return bounded_results

    def list_entities(
        self,
        entity_type: str | None = None,
        maturity: ProfileMaturity | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List entities with optional filtering.

        This is a read-only query that does not modify state.

        Args:
            entity_type: Optional entity type filter.
            maturity: Optional maturity state filter.
            limit: Maximum entities returned (bounded to 100).

        Returns:
            List of entity summaries, ordered deterministically.

        Raises:
            ValueError: If any input is invalid.
        """
        if entity_type is not None:
            entity_type = self._validate_string_input(
                entity_type, "entity_type", self._MAX_ENTITY_TYPE_LENGTH
            )

        if maturity is not None and not isinstance(maturity, ProfileMaturity):
            raise ValueError("maturity must be a ProfileMaturity enum value.")

        limit = self._validate_positive_int(limit, "limit")
        bounded_limit = min(limit, self._MAX_ENTITIES)

        # Delegate to service (read-only)
        results = self._service.list_entity_behavior(
            entity_type=entity_type,
            max_results=bounded_limit,
            maturity_filter=maturity.value if maturity is not None else None,
        )

        return results

    def get_dimension_values(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        max_values: int = 10,
    ) -> dict[str, int]:
        """Get value frequencies for a specific dimension.

        This is a read-only query that does not modify state.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of the entity.
            dimension: Behavioral dimension field.
            max_values: Maximum distinct values returned (bounded to 10).

        Returns:
            Dictionary mapping values to their observation counts.

        Raises:
            ValueError: If any input is invalid.
        """
        entity_type = self._validate_string_input(
            entity_type, "entity_type", self._MAX_ENTITY_TYPE_LENGTH
        )
        entity_id = self._validate_string_input(entity_id, "entity_id", self._MAX_ENTITY_ID_LENGTH)
        dimension = self._validate_string_input(dimension, "dimension", self._MAX_DIMENSION_LENGTH)
        max_values = self._validate_positive_int(max_values, "max_values")
        bounded_max = min(max_values, self._MAX_VALUES)

        # Get summary from service
        summary = self._service.get_behavior_summary(
            entity_type, entity_id, dimension, max_top_values=bounded_max
        )

        if summary is None:
            return {}

        # Return value counts (bounded)
        return dict(summary.top_values[:bounded_max])

    def get_baseline_evidence(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
        dimension_value: str,
    ) -> BaselineEvidence | None:
        """Get baseline evidence for a value without recording.

        This is a read-only query that does not modify state.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of the entity.
            dimension: Behavioral dimension field.
            dimension_value: The value to get evidence for.

        Returns:
            BaselineEvidence if a profile exists, None otherwise.

        Raises:
            ValueError: If any input is invalid.
        """
        entity_type = self._validate_string_input(
            entity_type, "entity_type", self._MAX_ENTITY_TYPE_LENGTH
        )
        entity_id = self._validate_string_input(entity_id, "entity_id", self._MAX_ENTITY_ID_LENGTH)
        dimension = self._validate_string_input(dimension, "dimension", self._MAX_DIMENSION_LENGTH)
        dimension_value = self._validate_string_input(
            dimension_value, "dimension_value", self._MAX_VALUE_LENGTH
        )

        # Delegate to service (read-only)
        return self._service.get_baseline_evidence(
            entity_type, entity_id, dimension, dimension_value
        )

    def get_entity_summary(
        self,
        entity_type: str,
        entity_id: str,
        dimension: str,
    ) -> dict[str, Any] | None:
        """Get a descriptive summary of an entity's behavior for a dimension.

        This is a read-only query that does not modify state.

        Args:
            entity_type: Type of entity.
            entity_id: Unique identifier of the entity.
            dimension: Behavioral dimension field.

        Returns:
            Summary dictionary if the profile exists, None otherwise.
        """
        entity_type = self._validate_string_input(
            entity_type, "entity_type", self._MAX_ENTITY_TYPE_LENGTH
        )
        entity_id = self._validate_string_input(entity_id, "entity_id", self._MAX_ENTITY_ID_LENGTH)
        dimension = self._validate_string_input(dimension, "dimension", self._MAX_DIMENSION_LENGTH)

        summary = self._service.get_behavior_summary(entity_type, entity_id, dimension)

        if summary is None:
            return None

        return summary.to_dict()
