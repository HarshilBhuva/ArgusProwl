"""ATT&CK investigation context aggregation service.

Aggregates ATT&CK observations from alerts into bounded, provenance-preserving
technique summaries for analyst investigation context.

Phase 6.5 — ATT&CK Investigation / Incident Integration:
    - Read-only aggregation from existing alert observations
    - No second alert scan, no network access, no enrichment invocation
    - Preserves version, mapping type, and provenance
    - Observations of the same technique/mapping recorded against different
      ATT&CK versions remain separate summaries (no silent version discard)
    - Bounded output: max 128 techniques, 10 alerts, 10 evidence refs
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from argusprowl.attck.models import AttckTechniqueSummary

if TYPE_CHECKING:
    from argusprowl.models.alert import Alert

logger = logging.getLogger(__name__)

# Phase 6.5 bounds
_MAX_TECHNIQUES: int = 128
_MAX_SOURCES_PER_TECHNIQUE: int = 10
_MAX_EVIDENCE_PER_TECHNIQUE: int = 10
_MAX_TECHNIQUE_ID_LENGTH: int = 12
_MAX_TECHNIQUE_NAME_LENGTH: int = 256
_MAX_TACTIC_LENGTH: int = 64
_MAX_VERSION_LENGTH: int = 32
_MAX_RATIONALE_LENGTH: int = 512


class AttckInvestigationContextService:
    """Aggregates ATT&CK observations from alerts into technique summaries.

    This service is read-only and does not modify any source state.
    It derives ATT&CK context solely from observations already present
    on the Alert objects returned by the investigation context.
    """

    def __init__(self) -> None:
        """Initialize ATT&CK investigation context service."""
        pass

    def aggregate(
        self,
        alerts: tuple[Alert, ...],
    ) -> tuple[AttckTechniqueSummary, ...]:
        """Aggregate ATT&CK observations from alerts into technique summaries.

        Args:
            alerts: Tuple of alerts to aggregate ATT&CK observations from.

        Returns:
            Tuple of AttckTechniqueSummary instances, bounded to _MAX_TECHNIQUES.
            Ordered by technique_id, mapping_type, then version for determinism.
        """
        if not alerts:
            return ()

        # Aggregate observations per (technique_id, mapping_type, version).
        # Different ATT&CK versions of the same technique/mapping stay separate
        # so provenance is not silently discarded.
        aggregated: dict[tuple[str, str, str], dict] = {}

        for alert in alerts:
            self._process_alert(alert, aggregated)

        # Build bounded summaries
        summaries: list[AttckTechniqueSummary] = []
        for (technique_id, mapping_type, version), data in sorted(aggregated.items()):
            if len(summaries) >= _MAX_TECHNIQUES:
                logger.debug(
                    "ATT&CK technique summary count bounded at %d",
                    _MAX_TECHNIQUES,
                )
                break

            summary = AttckTechniqueSummary(
                technique_id=technique_id,
                mapping_type=mapping_type,
                technique_name=data.get("technique_name"),
                tactic=data.get("tactic"),
                version=version,
                source_alert_ids=tuple(data["source_alert_ids"][:_MAX_SOURCES_PER_TECHNIQUE]),
                evidence_refs=tuple(data["evidence_refs"][:_MAX_EVIDENCE_PER_TECHNIQUE]),
                rationale=data.get("rationale"),
            )
            summaries.append(summary)

        return tuple(summaries)

    def _process_alert(
        self,
        alert: Alert,
        aggregated: dict[tuple[str, str, str], dict],
    ) -> None:
        """Process a single alert's ATT&CK observations.

        Args:
            alert: The alert to process.
            aggregated: The aggregation dictionary to update.
        """
        observations = alert.metadata.get("attck_observations")
        if not observations or not isinstance(observations, list):
            return

        alert_id_str = str(alert.alert_id)

        for obs in observations:
            if not isinstance(obs, dict):
                # Skip malformed observations safely
                logger.debug("Skipping malformed ATT&CK observation: %r", obs)
                continue

            technique_id = obs.get("technique_id")
            mapping_type = obs.get("mapping_type")

            if not technique_id or not mapping_type:
                continue

            # Validate technique_id format
            if not isinstance(technique_id, str) or len(technique_id) > _MAX_TECHNIQUE_ID_LENGTH:
                continue

            # Validate mapping_type
            if mapping_type not in ("DIRECT", "SUPPORTED", "CONTEXTUAL"):
                continue

            # Preserve the observation's recorded ATT&CK version as part of
            # the aggregation key. Invalid/missing versions stay empty rather
            # than being merged into a different recorded version.
            raw_version = obs.get("version")
            if isinstance(raw_version, str) and 0 < len(raw_version) <= _MAX_VERSION_LENGTH:
                version = raw_version
            else:
                version = ""

            key = (technique_id, mapping_type, version)
            if key not in aggregated:
                aggregated[key] = {
                    "technique_name": None,
                    "tactic": None,
                    "source_alert_ids": [],
                    "evidence_refs": [],
                    "rationale": None,
                }

            entry = aggregated[key]

            # Preserve technique metadata (first non-None wins for name/tactic)
            if entry["technique_name"] is None and obs.get("technique_name"):
                name = obs["technique_name"]
                if isinstance(name, str) and len(name) <= _MAX_TECHNIQUE_NAME_LENGTH:
                    entry["technique_name"] = name

            if entry["tactic"] is None and obs.get("tactic"):
                tactic = obs["tactic"]
                if isinstance(tactic, str) and len(tactic) <= _MAX_TACTIC_LENGTH:
                    entry["tactic"] = tactic

            # Add source alert ID (bounded)
            if (
                alert_id_str not in entry["source_alert_ids"]
                and len(entry["source_alert_ids"]) < _MAX_SOURCES_PER_TECHNIQUE
            ):
                entry["source_alert_ids"].append(alert_id_str)

            # Add evidence references (bounded)
            evidence = obs.get("evidence")
            if evidence:
                if (
                    isinstance(evidence, dict)
                    and len(entry["evidence_refs"]) < _MAX_EVIDENCE_PER_TECHNIQUE
                ):
                    entry["evidence_refs"].append(evidence)
                elif isinstance(evidence, list):
                    for ref in evidence[
                        : _MAX_EVIDENCE_PER_TECHNIQUE - len(entry["evidence_refs"])
                    ]:
                        if isinstance(ref, dict):
                            entry["evidence_refs"].append(ref)

            # Preserve rationale (first non-None wins)
            if entry["rationale"] is None and obs.get("rationale"):
                rationale = obs["rationale"]
                if isinstance(rationale, str) and len(rationale) <= _MAX_RATIONALE_LENGTH:
                    entry["rationale"] = rationale
