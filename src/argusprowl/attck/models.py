"""ATT&CK domain models.

Immutable, bounded data structures for the ATT&CK knowledge layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class AttckTactic:
    """A MITRE ATT&CK tactic.

    Attributes:
        tactic_id: External ID (e.g. "initial-access").
        name: Human-readable tactic name.
        description: Tactic description.
    """

    tactic_id: str
    name: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class AttckTechnique:
    """A MITRE ATT&CK technique.

    Attributes:
        technique_id: ATT&CK technique ID (e.g. "T1046").
        name: Human-readable technique name.
        description: Technique description.
        tactic: Associated tactic external ID.
        parent_technique_id: Parent sub-technique ID if this is a sub-technique.
    """

    technique_id: str
    name: str
    description: str = ""
    tactic: str | None = None
    parent_technique_id: str | None = None


@dataclass(frozen=True, slots=True)
class AttckTechniqueSummary:
    """Immutable analyst-facing ATT&CK technique summary.

    Aggregates ATT&CK observations from multiple alerts into a bounded,
    provenance-preserving summary for investigation context.

    Attributes:
        technique_id: ATT&CK technique ID (e.g., "T1046").
        mapping_type: One of DIRECT/SUPPORTED/CONTEXTUAL.
        technique_name: Human-readable technique name when available.
        tactic: Associated tactic when available.
        version: ATT&CK version this observation was recorded against.
            Summaries are keyed by (technique_id, mapping_type, version);
            observations recorded against different versions remain separate.
        source_alert_ids: Bounded list of source alert IDs.
        evidence_refs: Bounded list of evidence references.
        rationale: Bounded rationale information where available.
    """

    technique_id: str
    mapping_type: str
    technique_name: str | None = None
    tactic: str | None = None
    version: str = ""
    source_alert_ids: tuple[str, ...] = field(default_factory=tuple)
    evidence_refs: tuple[dict, ...] = field(default_factory=tuple)
    rationale: str | None = None

    @property
    def is_direct(self) -> bool:
        """Whether this technique is directly observed."""
        return self.mapping_type == "DIRECT"

    @property
    def is_supported(self) -> bool:
        """Whether this technique is supporting evidence."""
        return self.mapping_type == "SUPPORTED"

    @property
    def is_contextual(self) -> bool:
        """Whether this technique is contextual only."""
        return self.mapping_type == "CONTEXTUAL"


@dataclass(frozen=True, slots=True)
class AttckSnapshotMetadata:
    """Metadata about an imported ATT&CK snapshot.

    Attributes:
        version: ATT&CK version string (e.g. "14.0").
        imported_at: UTC timestamp of import.
        source: Source identifier (e.g. "mitre-attack-enterprise").
        integrity_hash: SHA-256 hex digest of the imported data.
        technique_count: Number of techniques in the snapshot.
        tactic_count: Number of tactics in the snapshot.
    """

    version: str
    imported_at: datetime
    source: str
    integrity_hash: str
    technique_count: int
    tactic_count: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "version": self.version,
            "imported_at": self.imported_at.isoformat(),
            "source": self.source,
            "integrity_hash": self.integrity_hash,
            "technique_count": self.technique_count,
            "tactic_count": self.tactic_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttckSnapshotMetadata:
        """Deserialize from a JSON-compatible dictionary."""
        return cls(
            version=str(data["version"]),
            imported_at=datetime.fromisoformat(data["imported_at"]),
            source=str(data["source"]),
            integrity_hash=str(data["integrity_hash"]),
            technique_count=int(data["technique_count"]),
            tactic_count=int(data["tactic_count"]),
        )
