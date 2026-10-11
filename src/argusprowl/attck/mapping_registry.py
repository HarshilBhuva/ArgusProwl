"""Approved ATT&CK mapping registry.

The registry is a small, deterministic semantic layer between detection rule
identities and the local ATT&CK knowledge service.  It has exactly one
authoritative source: ``config/attck_mappings.yaml``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from argusprowl.attck.knowledge_service import AttckKnowledgeService
from argusprowl.constants.paths import ProjectPath
from argusprowl.exceptions.exceptions import ValidationError

_MAX_FILE_BYTES = 256 * 1024
_MAX_MAPPINGS = 256
_MAX_RULE_ID_LENGTH = 128
_MAX_TECHNIQUE_ID_LENGTH = 12
_MAX_RATIONALE_LENGTH = 512
_RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_ALLOWED_ROOT_KEYS = {"mappings"}
_ALLOWED_MAPPING_KEYS = {
    "rule_id",
    "technique_id",
    "subtechnique_id",
    "mapping_type",
    "rationale",
    "condition",
}


class MappingType(StrEnum):
    """Approved semantic mapping types."""

    DIRECT = "DIRECT"
    SUPPORTED = "SUPPORTED"
    CONTEXTUAL = "CONTEXTUAL"
    NONE = "NONE"


@dataclass(frozen=True, slots=True)
class AttckMapping:
    """Immutable, bounded authoritative mapping entry."""

    rule_id: str
    technique_id: str
    mapping_type: MappingType
    subtechnique_id: str | None = None
    rationale: str | None = None
    condition: str | None = None


class AttckMappingRegistry:
    """Read-only registry backed by the approved mapping YAML file."""

    def __init__(
        self,
        knowledge_service: AttckKnowledgeService,
        mapping_path: str | Path = ProjectPath.CONFIG_DIR / "attck_mappings.yaml",
    ) -> None:
        self._knowledge_service = knowledge_service
        self._mapping_path = Path(mapping_path).resolve()
        self._mappings: tuple[AttckMapping, ...] = ()
        self._load()

    @property
    def mapping_path(self) -> Path:
        """Return the resolved authoritative mapping source path."""
        return self._mapping_path

    def get_for_rule(self, rule_id: str) -> tuple[AttckMapping, ...]:
        """Return mappings for a rule in deterministic order."""
        if not isinstance(rule_id, str) or not _RULE_ID_PATTERN.fullmatch(rule_id):
            raise ValidationError("Invalid rule_id.", details={"rule_id": rule_id})
        return tuple(mapping for mapping in self._mappings if mapping.rule_id == rule_id)

    def get_all(self) -> tuple[AttckMapping, ...]:
        """Return all authoritative mappings in deterministic order."""
        return self._mappings

    def validate(self) -> None:
        """Re-validate the authoritative source and knowledge references."""
        self._load()

    def _load(self) -> None:
        raw = self._read_bounded()
        data = self._parse_yaml(raw)
        mappings = self._validate_and_build(data)
        self._mappings = tuple(sorted(mappings, key=self._sort_key))

    def _read_bounded(self) -> bytes:
        if not self._mapping_path.is_file():
            raise ValidationError(
                "Authoritative ATT&CK mapping file not found.",
                details={"path": str(self._mapping_path)},
            )
        size = self._mapping_path.stat().st_size
        if size > _MAX_FILE_BYTES:
            raise ValidationError(
                "Authoritative ATT&CK mapping file exceeds size limit.",
                details={"size": size, "max_size": _MAX_FILE_BYTES},
            )
        try:
            return self._mapping_path.read_bytes()
        except OSError as exc:
            raise ValidationError(
                "Unable to read authoritative ATT&CK mapping file.",
                details={"path": str(self._mapping_path), "error": str(exc)},
            ) from exc

    @staticmethod
    def _parse_yaml(raw: bytes) -> Any:
        try:
            # safe_load deliberately excludes Python/object constructors.
            return yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ValidationError("Malformed authoritative ATT&CK mapping YAML.") from exc

    def _validate_and_build(self, data: Any) -> list[AttckMapping]:
        if not isinstance(data, dict):
            raise ValidationError("ATT&CK mapping YAML root must be a mapping.")
        if set(data) - _ALLOWED_ROOT_KEYS:
            raise ValidationError("ATT&CK mapping YAML contains unknown root fields.")

        raw_mappings = data.get("mappings")
        if not isinstance(raw_mappings, list):
            raise ValidationError("ATT&CK mapping YAML must contain a mappings list.")
        if len(raw_mappings) > _MAX_MAPPINGS:
            raise ValidationError(
                "ATT&CK mapping count exceeds the configured bound.",
                details={"count": len(raw_mappings), "max_mappings": _MAX_MAPPINGS},
            )

        result: list[AttckMapping] = []
        seen: set[tuple[str, str, MappingType]] = set()
        for index, raw_mapping in enumerate(raw_mappings):
            result.append(self._build_mapping(raw_mapping, index, seen))
        return result

    def _build_mapping(
        self,
        raw_mapping: Any,
        index: int,
        seen: set[tuple[str, str, MappingType]],
    ) -> AttckMapping:
        if not isinstance(raw_mapping, dict):
            raise ValidationError(
                "ATT&CK mapping entry must be a mapping.", details={"index": index}
            )
        if set(raw_mapping) - _ALLOWED_MAPPING_KEYS:
            raise ValidationError(
                "ATT&CK mapping entry contains unknown fields.", details={"index": index}
            )

        rule_id = raw_mapping.get("rule_id")
        if not isinstance(rule_id, str) or not _RULE_ID_PATTERN.fullmatch(rule_id):
            raise ValidationError("Invalid rule_id in ATT&CK mapping.", details={"index": index})
        if len(rule_id) > _MAX_RULE_ID_LENGTH:
            raise ValidationError("rule_id exceeds maximum length.", details={"index": index})

        technique_id = raw_mapping.get("technique_id")
        self._validate_technique_id(technique_id, "technique_id", index)

        subtechnique_id = raw_mapping.get("subtechnique_id")
        if subtechnique_id is not None:
            self._validate_technique_id(subtechnique_id, "subtechnique_id", index)

        mapping_type_raw = raw_mapping.get("mapping_type")
        if not isinstance(mapping_type_raw, str):
            raise ValidationError("mapping_type must be a string.", details={"index": index})
        try:
            mapping_type = MappingType(mapping_type_raw.upper())
        except ValueError as exc:
            raise ValidationError(
                "Invalid ATT&CK mapping type.",
                details={"index": index, "mapping_type": mapping_type_raw},
            ) from exc

        rationale = raw_mapping.get("rationale")
        if rationale is not None and (
            not isinstance(rationale, str) or len(rationale) > _MAX_RATIONALE_LENGTH
        ):
            raise ValidationError(
                "Invalid or oversized mapping rationale.", details={"index": index}
            )

        condition = raw_mapping.get("condition")
        if condition is not None and (
            not isinstance(condition, str) or len(condition) > _MAX_RATIONALE_LENGTH
        ):
            raise ValidationError(
                "Invalid or oversized mapping condition.", details={"index": index}
            )

        key = (rule_id, technique_id, mapping_type)
        if key in seen:
            raise ValidationError(
                "Duplicate ATT&CK mapping entry.",
                details={
                    "rule_id": rule_id,
                    "technique_id": technique_id,
                    "mapping_type": mapping_type.value,
                },
            )
        seen.add(key)

        self._validate_knowledge_reference(technique_id, "technique_id", index)
        if subtechnique_id is not None:
            self._validate_subtechnique(technique_id, subtechnique_id, index)

        return AttckMapping(
            rule_id=rule_id,
            technique_id=technique_id,
            mapping_type=mapping_type,
            subtechnique_id=subtechnique_id,
            rationale=rationale,
            condition=condition,
        )

    @staticmethod
    def _validate_technique_id(value: Any, field: str, index: int) -> None:
        if (
            not isinstance(value, str)
            or len(value) > _MAX_TECHNIQUE_ID_LENGTH
            or not _TECHNIQUE_ID_PATTERN.fullmatch(value)
        ):
            raise ValidationError(
                f"Invalid {field} in ATT&CK mapping.", details={"index": index, field: value}
            )

    def _validate_knowledge_reference(self, technique_id: str, field: str, index: int) -> None:
        if not self._knowledge_service.is_enabled:
            raise ValidationError("ATT&CK knowledge service is disabled.")
        status = self._knowledge_service.get_status()
        if status.value not in {"AVAILABLE", "DEGRADED"}:
            raise ValidationError(
                "ATT&CK knowledge is unavailable for mapping validation.",
                details={"status": status.value, "index": index},
            )
        if self._knowledge_service.get_technique(technique_id) is None:
            raise ValidationError(
                f"Unknown ATT&CK {field}.", details={"index": index, field: technique_id}
            )

    def _validate_subtechnique(self, parent_id: str, subtechnique_id: str, index: int) -> None:
        self._validate_knowledge_reference(subtechnique_id, "subtechnique_id", index)
        subtechnique = self._knowledge_service.get_technique(subtechnique_id)
        if subtechnique is None or subtechnique.parent_technique_id != parent_id:
            raise ValidationError(
                "ATT&CK sub-technique does not belong to the declared parent technique.",
                details={
                    "index": index,
                    "technique_id": parent_id,
                    "subtechnique_id": subtechnique_id,
                },
            )

    @staticmethod
    def _sort_key(mapping: AttckMapping) -> tuple[str, str, str, str]:
        return (
            mapping.rule_id,
            mapping.technique_id,
            mapping.mapping_type.value,
            mapping.subtechnique_id or "",
        )
