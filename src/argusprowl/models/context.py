"""Data contracts for the Context & Intelligence Layer (Phase 4.6A).

Defines immutable models for entity context, threat intelligence lookups,
prevalence observations, structured evidence fusion, and contextual assessments.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from ipaddress import ip_address
from typing import Any
from uuid import UUID, uuid4

from argusprowl.constants.severity import Severity
from argusprowl.models.detection_result import DetectionResult


class ThreatIntelVerdict(Enum):
    """Verdict classifications for threat intelligence indicators."""

    UNKNOWN = "UNKNOWN"
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"

    @classmethod
    def from_string(cls, value: str) -> "ThreatIntelVerdict":
        """Parse verdict from string case-insensitively.

        Args:
            value: The verdict string.

        Returns:
            Corresponding ThreatIntelVerdict member.

        Raises:
            ValueError: If value is unknown.
        """
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(m.name for m in cls)
            raise ValueError(
                f"Unknown threat intel verdict '{value}'. Valid values: {valid}"
            ) from None


class EvidenceType(Enum):
    """Classification of evidence impact on risk assessment."""

    SUPPORTING = "SUPPORTING"
    CONTRADICTORY = "CONTRADICTORY"

    @classmethod
    def from_string(cls, value: str) -> "EvidenceType":
        """Parse evidence type from string case-insensitively.

        Args:
            value: The evidence type string.

        Returns:
            Corresponding EvidenceType member.

        Raises:
            ValueError: If value is unknown.
        """
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(m.name for m in cls)
            raise ValueError(f"Unknown evidence type '{value}'. Valid values: {valid}") from None


@dataclass(frozen=True, slots=True)
class EntityContext:
    """Immutable representation of entities associated with an assessment."""

    host: str | None = None
    process_name: str | None = None
    pid: int | None = None
    username: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    domain: str | None = None

    def __post_init__(self) -> None:
        """Validate entity context attributes."""
        if self.pid is not None and (not isinstance(self.pid, int) or self.pid < 0):
            raise ValueError(f"EntityContext pid must be a non-negative integer, got {self.pid}")
        for value, label in ((self.src_ip, "src_ip"), (self.dst_ip, "dst_ip")):
            if value is not None:
                try:
                    ip_address(value)
                except ValueError as exc:
                    raise ValueError(f"EntityContext {label} must be a valid IP address.") from exc
        if self.dst_port is not None and (
            not isinstance(self.dst_port, int) or not 0 <= self.dst_port <= 65535
        ):
            raise ValueError(
                f"EntityContext dst_port must be between 0 and 65535, got {self.dst_port}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize EntityContext to a plain dictionary."""
        return {
            "host": self.host,
            "process_name": self.process_name,
            "pid": self.pid,
            "username": self.username,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "domain": self.domain,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EntityContext":
        """Deserialize EntityContext from dictionary."""
        try:
            return cls(
                host=data.get("host"),
                process_name=data.get("process_name"),
                pid=data.get("pid"),
                username=data.get("username"),
                src_ip=data.get("src_ip"),
                dst_ip=data.get("dst_ip"),
                dst_port=data.get("dst_port"),
                domain=data.get("domain"),
            )
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid EntityContext mapping: {exc}") from exc


@dataclass(frozen=True, slots=True)
class ThreatIntelReputation:
    """Immutable representation of a threat intelligence indicator lookup result."""

    indicator: str
    verdict: ThreatIntelVerdict = ThreatIntelVerdict.UNKNOWN
    confidence: float = 0.0
    categories: tuple[str, ...] = ()
    source: str = ""

    def __post_init__(self) -> None:
        """Validate threat intel reputation attributes."""
        if not isinstance(self.indicator, str) or not self.indicator.strip():
            raise ValueError("ThreatIntelReputation indicator must be a non-empty string.")
        if not isinstance(self.verdict, ThreatIntelVerdict):
            raise ValueError(
                f"ThreatIntelReputation verdict must be ThreatIntelVerdict, got {type(self.verdict)}"
            )
        if (
            not isinstance(self.confidence, (int, float))
            or not 0.0 <= float(self.confidence) <= 1.0
        ):
            raise ValueError(
                f"ThreatIntelReputation confidence must be between 0.0 and 1.0, got {self.confidence}"
            )
        if not isinstance(self.categories, tuple):
            raise ValueError("ThreatIntelReputation categories must be a tuple of strings.")
        if any(not isinstance(cat, str) or not cat.strip() for cat in self.categories):
            raise ValueError("ThreatIntelReputation categories must contain non-empty strings.")
        if not isinstance(self.source, str):
            raise ValueError("ThreatIntelReputation source must be a string.")

    def to_dict(self) -> dict[str, Any]:
        """Serialize ThreatIntelReputation to plain dictionary."""
        return {
            "indicator": self.indicator,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "categories": list(self.categories),
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ThreatIntelReputation":
        """Deserialize ThreatIntelReputation from dictionary."""
        try:
            return cls(
                indicator=str(data["indicator"]),
                verdict=ThreatIntelVerdict.from_string(
                    str(data.get("verdict", ThreatIntelVerdict.UNKNOWN.value))
                ),
                confidence=float(data.get("confidence", 0.0)),
                categories=tuple(str(c) for c in data.get("categories", ())),
                source=str(data.get("source", "")),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"Invalid ThreatIntelReputation mapping: {exc}") from exc


@dataclass(frozen=True, slots=True)
class PrevalenceResult:
    """Immutable result contract for environmental destination prevalence observations."""

    dest_host_count: int = 0
    process_dest_count: int = 0
    is_rare_destination: bool = False
    is_environment_wide: bool = False

    def __post_init__(self) -> None:
        """Validate prevalence result metrics."""
        if not isinstance(self.dest_host_count, int) or self.dest_host_count < 0:
            raise ValueError(
                f"dest_host_count must be a non-negative integer, got {self.dest_host_count}"
            )
        if not isinstance(self.process_dest_count, int) or self.process_dest_count < 0:
            raise ValueError(
                f"process_dest_count must be a non-negative integer, got {self.process_dest_count}"
            )
        if not isinstance(self.is_rare_destination, bool):
            raise ValueError("is_rare_destination must be a boolean.")
        if not isinstance(self.is_environment_wide, bool):
            raise ValueError("is_environment_wide must be a boolean.")

    def to_dict(self) -> dict[str, Any]:
        """Serialize PrevalenceResult to plain dictionary."""
        return {
            "dest_host_count": self.dest_host_count,
            "process_dest_count": self.process_dest_count,
            "is_rare_destination": self.is_rare_destination,
            "is_environment_wide": self.is_environment_wide,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PrevalenceResult":
        """Deserialize PrevalenceResult from dictionary."""
        try:
            return cls(
                dest_host_count=int(data.get("dest_host_count", 0)),
                process_dest_count=int(data.get("process_dest_count", 0)),
                is_rare_destination=bool(data.get("is_rare_destination", False)),
                is_environment_wide=bool(data.get("is_environment_wide", False)),
            )
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid PrevalenceResult mapping: {exc}") from exc


@dataclass(frozen=True, slots=True)
class FusionEvidence:
    """Immutable evidence item contributing to evidence fusion decision."""

    evidence_type: EvidenceType
    category: str
    description: str
    weight: float
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate evidence fields and bounded weights."""
        if not isinstance(self.evidence_type, EvidenceType):
            raise ValueError(f"evidence_type must be EvidenceType, got {type(self.evidence_type)}")
        if not isinstance(self.category, str) or not self.category.strip():
            raise ValueError("FusionEvidence category must be a non-empty string.")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("FusionEvidence description must be a non-empty string.")
        if not isinstance(self.weight, (int, float)) or not -1.0 <= float(self.weight) <= 1.0:
            raise ValueError(
                f"FusionEvidence weight must be between -1.0 and 1.0, got {self.weight}"
            )
        if not isinstance(self.metadata, dict):
            raise ValueError("FusionEvidence metadata must be a dictionary.")

    def to_dict(self) -> dict[str, Any]:
        """Serialize FusionEvidence to plain dictionary."""
        return {
            "evidence_type": self.evidence_type.value,
            "category": self.category,
            "description": self.description,
            "weight": self.weight,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FusionEvidence":
        """Deserialize FusionEvidence from dictionary."""
        try:
            return cls(
                evidence_type=EvidenceType.from_string(str(data["evidence_type"])),
                category=str(data["category"]),
                description=str(data["description"]),
                weight=float(data["weight"]),
                metadata=dict(data.get("metadata", {})),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"Invalid FusionEvidence mapping: {exc}") from exc


@dataclass(frozen=True, slots=True)
class ContextualAssessment:
    """Immutable contextual assessment synthesizing detection, evidence, and entity context."""

    detection_result: DetectionResult
    final_confidence: float = 0.0
    severity: Severity = Severity.INFO
    entity_context: EntityContext | None = None
    supporting_evidence: tuple[FusionEvidence, ...] = ()
    contradictory_evidence: tuple[FusionEvidence, ...] = ()
    explanation: str = ""
    investigation_pivots: tuple[str, ...] = ()
    assessment_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Validate assessment attributes."""
        if not isinstance(self.detection_result, DetectionResult):
            raise ValueError(
                "ContextualAssessment detection_result must be a DetectionResult instance."
            )
        if (
            not isinstance(self.final_confidence, (int, float))
            or not 0.0 <= float(self.final_confidence) <= 1.0
        ):
            raise ValueError(
                f"final_confidence must be between 0.0 and 1.0, got {self.final_confidence}"
            )
        if not isinstance(self.severity, Severity):
            raise ValueError(
                f"severity must be a Severity enum instance, got {type(self.severity)}"
            )
        if self.entity_context is not None and not isinstance(self.entity_context, EntityContext):
            raise ValueError("entity_context must be an EntityContext instance or None.")
        if not isinstance(self.supporting_evidence, tuple):
            raise ValueError("supporting_evidence must be a tuple of FusionEvidence instances.")
        for item in self.supporting_evidence:
            if not isinstance(item, FusionEvidence):
                raise ValueError("supporting_evidence items must be FusionEvidence instances.")
            if item.evidence_type != EvidenceType.SUPPORTING:
                raise ValueError("supporting_evidence items must have evidence_type SUPPORTING.")
        if not isinstance(self.contradictory_evidence, tuple):
            raise ValueError("contradictory_evidence must be a tuple of FusionEvidence instances.")
        for item in self.contradictory_evidence:
            if not isinstance(item, FusionEvidence):
                raise ValueError("contradictory_evidence items must be FusionEvidence instances.")
            if item.evidence_type != EvidenceType.CONTRADICTORY:
                raise ValueError(
                    "contradictory_evidence items must have evidence_type CONTRADICTORY."
                )
        if not isinstance(self.explanation, str):
            raise ValueError("explanation must be a string.")
        if not isinstance(self.investigation_pivots, tuple):
            raise ValueError("investigation_pivots must be a tuple of strings.")
        if any(
            not isinstance(pivot, str) or not pivot.strip() for pivot in self.investigation_pivots
        ):
            raise ValueError("investigation_pivots must contain non-empty strings.")
        if not isinstance(self.assessment_id, UUID):
            raise ValueError("assessment_id must be a UUID.")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware.")
        object.__setattr__(self, "created_at", self.created_at.astimezone(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Serialize ContextualAssessment to a plain dictionary."""
        return {
            "assessment_id": str(self.assessment_id),
            "detection_result": self.detection_result.to_dict(),
            "final_confidence": self.final_confidence,
            "severity": self.severity.name,
            "entity_context": self.entity_context.to_dict() if self.entity_context else None,
            "supporting_evidence": [ev.to_dict() for ev in self.supporting_evidence],
            "contradictory_evidence": [ev.to_dict() for ev in self.contradictory_evidence],
            "explanation": self.explanation,
            "investigation_pivots": list(self.investigation_pivots),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ContextualAssessment":
        """Deserialize ContextualAssessment from dictionary."""
        try:
            entity_ctx_data = data.get("entity_context")
            entity_context = EntityContext.from_dict(entity_ctx_data) if entity_ctx_data else None
            return cls(
                assessment_id=UUID(str(data["assessment_id"])),
                detection_result=DetectionResult.from_dict(dict(data["detection_result"])),
                final_confidence=float(data.get("final_confidence", 0.0)),
                severity=Severity.from_string(str(data["severity"])),
                entity_context=entity_context,
                supporting_evidence=tuple(
                    FusionEvidence.from_dict(dict(ev)) for ev in data.get("supporting_evidence", [])
                ),
                contradictory_evidence=tuple(
                    FusionEvidence.from_dict(dict(ev))
                    for ev in data.get("contradictory_evidence", [])
                ),
                explanation=str(data.get("explanation", "")),
                investigation_pivots=tuple(str(p) for p in data.get("investigation_pivots", [])),
                created_at=datetime.fromisoformat(str(data["created_at"])),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError(f"Invalid ContextualAssessment mapping: {exc}") from exc
