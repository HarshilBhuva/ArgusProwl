"""ATT&CK enrichment service.

Provides deterministic ATT&CK enrichment for finalized alerts.
"""

from dataclasses import replace
from typing import Any

from argusprowl.attck.knowledge_service import AttckKnowledgeService, AttckKnowledgeStatus
from argusprowl.attck.mapping_registry import AttckMappingRegistry, MappingType
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.models.alert import Alert


class AttckEnrichmentService:
    """Service for enriching alerts with ATT&CK knowledge."""

    def __init__(
        self,
        knowledge_service: AttckKnowledgeService,
        mapping_registry: AttckMappingRegistry,
        detection_manager: DetectionManager | None = None,
    ) -> None:
        """Initialize enrichment service.

        Args:
            knowledge_service: The ATT&CK knowledge service.
            mapping_registry: The authoritative mapping registry.
            detection_manager: Optional detection manager for condition evaluation.
        """
        self._knowledge_service = knowledge_service
        self._mapping_registry = mapping_registry
        self._detection_manager = detection_manager

    def enrich(self, alert: Alert) -> Alert:
        """Enrich a finalized alert with ATT&CK observations.

        Args:
            alert: The finalized alert to enrich.

        Returns:
            A new Alert instance with ATT&CK enrichment, or the original
            alert if enrichment is disabled, unavailable, or yields no mappings.
        """
        if not self._knowledge_service.is_enabled:
            return alert

        status = self._knowledge_service.get_status()
        if status in (AttckKnowledgeStatus.EMPTY, AttckKnowledgeStatus.UNAVAILABLE):
            return alert

        rule_id = alert.source
        mappings = self._mapping_registry.get_for_rule(rule_id)

        if not mappings:
            return alert

        observations = []
        for mapping in mappings:
            if mapping.mapping_type == MappingType.NONE:
                continue

            # Handle conditional mappings
            if mapping.condition and not self._evaluate_condition(mapping.condition, alert):
                continue

            technique = self._knowledge_service.get_technique(mapping.technique_id)
            if not technique:
                continue

            observation: dict[str, Any] = {
                "technique_id": mapping.technique_id,
                "mapping_type": mapping.mapping_type.value,
                "technique_name": technique.name,
                "version": self._knowledge_service.get_version(),
            }
            if mapping.subtechnique_id:
                observation["subtechnique_id"] = mapping.subtechnique_id
            if technique.tactic:
                observation["tactic"] = technique.tactic
            if mapping.rationale:
                observation["rationale"] = mapping.rationale
            if mapping.condition:
                observation["condition"] = mapping.condition

            observations.append(observation)

        if not observations:
            return alert

        # Create a new alert with the updated metadata
        new_metadata = dict(alert.metadata)
        new_metadata["attck_observations"] = observations

        return replace(alert, metadata=new_metadata)

    def _evaluate_condition(self, condition: str, alert: Alert) -> bool:
        """Evaluate a conditional mapping against an alert.

        Args:
            condition: The condition string to evaluate.
            alert: The alert to evaluate against.

        Returns:
            True if the condition is satisfied, False otherwise.
        """
        if condition == "authentication-context":
            if self._detection_manager is None:
                return False

            detector = self._detection_manager.get_detector(alert.source)
            if detector is None:
                return False

            if type(detector).__name__ == "EventCountCorrelationDetector" and hasattr(
                detector, "get_config"
            ):
                correlation = detector.get_config("correlation", {})
                filter_config = correlation.get("filter", {})
                event_type = filter_config.get("event_type", "")
                if isinstance(event_type, str) and event_type == "authentication_failed":
                    return True

        return False
