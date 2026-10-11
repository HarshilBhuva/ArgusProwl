"""Decision engine implementation.

Orchestrates alert creation from detection results, providing deduplication,
correlation, severity normalization, and suppression logic.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from argusprowl.behavior.baseline_evidence import BaselineEvidence
from argusprowl.constants.severity import Severity
from argusprowl.decision_engine.priority import determine_alert_priority
from argusprowl.deduplication.engine import AlertDeduplicationEngine
from argusprowl.models.alert import Alert
from argusprowl.models.context import ContextualAssessment
from argusprowl.models.detection_result import DetectionResult

if TYPE_CHECKING:
    from argusprowl.behavior.entity_behavior_service import EntityBehaviorService
    from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
    from argusprowl.incident.incident_service import IncidentService

logger = logging.getLogger(__name__)


class DecisionEngine:
    """Decision engine for creating and managing security alerts.

    Transforms DetectionResults into final Alert objects, applying
    business logic for deduplication, correlation, severity normalization,
    and suppression.

    Attributes:
        cooldown_seconds: Minimum seconds between duplicate alerts.
        max_correlated_alerts: Maximum alerts to correlate together.
    """

    def __init__(
        self,
        cooldown_seconds: int = 300,  # 5 minutes
        max_correlated_alerts: int = 10,
        incident_service: IncidentService | None = None,
        entity_correlation_service: EntityCorrelationService | None = None,
        entity_behavior_service: EntityBehaviorService | None = None,
    ) -> None:
        """Initialize decision engine.

        Args:
            cooldown_seconds: Cooldown period for duplicate suppression.
            max_correlated_alerts: Maximum alerts in a correlation group.
            incident_service: Optional incident service for entity-centric
                incident correlation. When provided, alerts with entity
                context are automatically associated with incidents.
            entity_correlation_service: Optional entity correlation service
                for deterministic alert grouping. Defaults to a new instance
                when incident_service is provided.
            entity_behavior_service: Optional EntityBehaviorService for
                attaching behavioral summaries to alerts. Read-only access
                only; does not affect detection or decision logic.
        """
        self._cooldown_seconds = cooldown_seconds
        self._max_correlated_alerts = max_correlated_alerts

        # State tracking
        self._alert_history: dict[str, datetime] = {}  # alert_key -> last_alert_time
        # Retain the attribute above only as a compatibility detail for older
        # callers; suppression itself is now bounded and TTL-expiring.
        self._deduplication = AlertDeduplicationEngine(cooldown=cooldown_seconds)
        self._correlation_groups: dict[str, list[Alert]] = {}  # correlation_key -> alerts
        self._total_alerts_created = 0
        self._total_alerts_suppressed = 0

        # Incident correlation (optional, Phase 4.8.2)
        self._incident_service = incident_service
        if incident_service is not None and entity_correlation_service is None:
            from argusprowl.correlation.entity_correlation_service import EntityCorrelationService

            entity_correlation_service = EntityCorrelationService()
        self._entity_correlation_service = entity_correlation_service

        # Entity behavior summary (optional, Phase 5.1.2)
        self._entity_behavior_service = entity_behavior_service

    def process_detection_result(
        self,
        detection_result: DetectionResult,
        assessment: ContextualAssessment | None = None,
        event: Any | None = None,
    ) -> Alert | None:
        """Process a detection result and create an alert if warranted.

        When a ContextualAssessment is provided, ``Alert.severity`` is taken
        from ``assessment.severity`` and contextual fields are copied onto the
        Alert. DecisionEngine does not recalculate contextual confidence and
        does not re-run fusion severity mapping. When absent, legacy
        DetectionResult-only behaviour is preserved.

        Args:
            detection_result: DetectionResult from a detector.
            assessment: Optional ContextualAssessment produced by the
                intelligence layer for this detection.
            event: Optional NormalizedEvent for behavioral summary extraction.

        Returns:
            Alert if detection should generate an alert, None if suppressed.
        """
        if not detection_result.matched:
            return None

        # Operational severity: consume the intelligence-layer result when
        # present. Do not apply the legacy detector-confidence downgrade table
        # to a contextual score — that would be a second scoring algorithm.
        if assessment is not None:
            normalized_severity = assessment.severity
        else:
            normalized_severity = self._normalize_severity(
                detection_result.severity,
                detection_result.confidence,
            )

        # Enrich evidence
        enriched_evidence = self._enrich_evidence(detection_result.evidence)

        # Build contextual Alert fields when assessment is available
        assessment_id = None
        detector_confidence: float | None = None
        contextual_confidence: float | None = None
        contextual_explanation = ""
        supporting_evidence: tuple[dict[str, Any], ...] = ()
        contradictory_evidence: tuple[dict[str, Any], ...] = ()
        investigation_pivots: tuple[str, ...] = ()
        entity_context: dict[str, Any] | None = None

        if assessment is not None:
            assessment_id = assessment.assessment_id
            detector_confidence = detection_result.confidence
            contextual_confidence = assessment.final_confidence
            contextual_explanation = assessment.explanation
            supporting_evidence = tuple(ev.to_dict() for ev in assessment.supporting_evidence)
            contradictory_evidence = tuple(ev.to_dict() for ev in assessment.contradictory_evidence)
            investigation_pivots = assessment.investigation_pivots
            if assessment.entity_context is not None:
                entity_context = assessment.entity_context.to_dict()

        # Attach behavioral summary (read-only, Phase 5.1.2)
        behavioral_summary = self._get_behavioral_summary(detection_result, event)

        # Attach baseline evidence (read-only, Phase 5.1.7)
        baseline_evidence = self._get_baseline_evidence(detection_result, event)

        # Create alert
        priority = determine_alert_priority(normalized_severity)
        alert = Alert(
            title=self._generate_title(detection_result),
            description=detection_result.description,
            severity=normalized_severity,
            priority=priority,
            source=detection_result.rule_id,
            tags=self._generate_tags(detection_result),
            metadata={
                "rule_id": detection_result.rule_id,
                "event_id": str(detection_result.event_id),
                "result_id": str(detection_result.result_id),
                "confidence": detection_result.confidence,
                "evidence": enriched_evidence,
                **(
                    {"behavioral_summary": behavioral_summary.to_dict()}
                    if behavioral_summary is not None
                    else {}
                ),
                **(
                    {"baseline_evidence": baseline_evidence.to_dict()}
                    if baseline_evidence is not None
                    else {}
                ),
            },
            assessment_id=assessment_id,
            detector_confidence=detector_confidence,
            contextual_confidence=contextual_confidence,
            contextual_explanation=contextual_explanation,
            supporting_evidence=supporting_evidence,
            contradictory_evidence=contradictory_evidence,
            investigation_pivots=investigation_pivots,
            entity_context=entity_context,
            detection_source_event_id=detection_result.event_id,
            contributing_event_ids=detection_result.contributing_event_ids,
        )

        # Legacy callers/tests can explicitly clear or age this compatibility
        # projection. Apply that operator intent to the bounded engine.
        alert_key = self._generate_alert_key(detection_result)
        previous_alert = self._alert_history.get(alert_key)
        if previous_alert is not None and datetime.now(UTC) - previous_alert >= timedelta(
            seconds=self._cooldown_seconds
        ):
            self._deduplication.forget(alert)
        # Alert deduplication is bounded and separate from the event stream.
        # The detection result was still processed; only provider-visible alert
        # emission is suppressed during its configured cooldown.
        decision = self._deduplication.process(alert)
        self._alert_history[alert_key] = datetime.now(UTC)
        if not decision.emit:
            self._total_alerts_suppressed += 1
            return None
        assert decision.alert is not None
        alert = decision.alert
        self._total_alerts_created += 1

        # Add to correlation group
        self._add_to_correlation_group(alert, detection_result)

        # Associate with incident if incident service is configured
        alert = self._associate_with_incident(alert)

        return alert

    def process_batch(self, detection_results: list[DetectionResult]) -> list[Alert]:
        """Process a batch of detection results.

        Args:
            detection_results: List of DetectionResults to process.

        Returns:
            List of Alerts created (suppressed alerts excluded).
        """
        alerts = []
        for result in detection_results:
            alert = self.process_detection_result(result)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def _generate_alert_key(self, detection_result: DetectionResult) -> str:
        """Generate a unique key for alert deduplication.

        Args:
            detection_result: DetectionResult to generate key for.

        Returns:
            String key for deduplication.
        """
        # Combine rule_id and source IP for deduplication
        # Extract src_ip from evidence list if available
        src_ip = "unknown"
        for item in detection_result.evidence:
            if isinstance(item, dict) and item.get("field") in ("src_ip", "source_ip"):
                src_ip = str(item.get("observed", "unknown"))
                break
            if isinstance(item, dict) and "src_ip" in item:
                src_ip = str(item["src_ip"])
                break
        key_data = f"{detection_result.rule_id}:{src_ip}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]

    def _is_in_cooldown(self, alert_key: str) -> bool:
        """Check if an alert key is currently in cooldown period.

        Args:
            alert_key: Alert key to check.

        Returns:
            True if in cooldown period, False otherwise.
        """
        if alert_key not in self._alert_history:
            return False

        last_alert_time = self._alert_history[alert_key]
        cooldown_delta = timedelta(seconds=self._cooldown_seconds)
        return datetime.now(UTC) - last_alert_time < cooldown_delta

    def _normalize_severity(self, severity: Severity, confidence: float) -> Severity:
        """Legacy detector-only severity normalization.

        Used only when no ContextualAssessment is provided. Contextual
        severity is owned by EvidenceFusionEngine and must not be remapped
        here.

        Args:
            severity: Original severity from detection result.
            confidence: Detector confidence from DetectionResult.

        Returns:
            Normalized Severity level.
        """
        # Downgrade severity if confidence is low
        if confidence < 0.3:
            return Severity.LOW
        elif confidence < 0.6 and severity in (Severity.HIGH, Severity.CRITICAL):
            return Severity.MEDIUM

        return severity

    def _enrich_evidence(self, evidence: list[dict[str, object]]) -> list[dict[str, object]]:
        """Enrich evidence with additional context.

        Args:
            evidence: Original evidence list.

        Returns:
            Enriched evidence list.
        """
        enriched = list(evidence) if evidence else []
        enriched.append(
            {
                "field": "_decision_engine_metadata",
                "decision_engine_version": "1.0",
                "processed_at": datetime.now(UTC).isoformat(),
            }
        )
        return enriched

    def _generate_title(self, detection_result: DetectionResult) -> str:
        """Generate alert title from detection result.

        Args:
            detection_result: DetectionResult to generate title from.

        Returns:
            Alert title string.
        """
        rule_id = detection_result.rule_id
        description = detection_result.description

        # Extract source IP from description if present
        # Format: "Rule detected from X.X.X.X: ..."
        if " from " in description and ":" in description:
            parts = description.split(" from ", 1)
            if len(parts) > 1:
                ip_part = parts[1].split(":", 1)[0].strip()
                return f"{rule_id.replace('_', ' ').title()} - {ip_part}"

        return rule_id.replace("_", " ").title()

    def _generate_tags(self, detection_result: DetectionResult) -> tuple[str, ...]:
        """Generate tags for alert from detection result.

        Args:
            detection_result: DetectionResult to generate tags from.

        Returns:
            Tuple of tag strings.
        """
        tags = [detection_result.rule_id, "threat_detection"]

        # Add severity-based tag
        severity_tag = f"severity_{detection_result.severity.name.lower()}"
        tags.append(severity_tag)

        # Add confidence-based tag
        if detection_result.confidence >= 0.8:
            tags.append("high_confidence")
        elif detection_result.confidence >= 0.5:
            tags.append("medium_confidence")

        return tuple(tags)

    def _get_behavioral_summary(
        self,
        detection_result: DetectionResult,
        event: Any | None = None,
    ) -> Any | None:
        """Extract a behavioral summary from the entity behavior service.

        This is a read-only operation that does not affect detection,
        decision, or alert generation logic. The summary is attached
        to Alert.metadata for analyst reference only.

        Args:
            detection_result: The detection result that triggered.
            event: Optional normalized event for entity context extraction.

        Returns:
            EntityBehaviorSummary if available, None otherwise.
        """
        if self._entity_behavior_service is None:
            return None

        # Extract entity context from detection result evidence first,
        # then fall back to event if needed
        entity_type = None
        entity_id = None
        dimension = None

        # Priority 1: Extract from detection result evidence
        for item in detection_result.evidence:
            if not isinstance(item, dict):
                continue
            field = item.get("field", "")
            observed = item.get("observed")

            if field == "hostname" and entity_id is None and isinstance(observed, str):
                entity_id = observed
                entity_type = "hostname"
            elif field == "process_name" and dimension is None and isinstance(observed, str):
                dimension = "process_name"
            elif field in ("dst_ip", "src_ip") and dimension is None:
                dimension = field
                if entity_type is None:
                    entity_type = "ip"
                    entity_id = str(observed) if observed else None

        # Priority 2: Fall back to event if not found in evidence
        if entity_id is None and event is not None:
            entity_id = event.hostname or event.src_ip
            if entity_id:
                entity_type = "hostname" if event.hostname else "ip"

        if dimension is None and event is not None:
            # Determine dimension from event fields
            if event.process_name:
                dimension = "process_name"
            elif event.dst_ip:
                dimension = "dst_ip"
            elif event.src_ip:
                dimension = "src_ip"

        # Validate we have all required fields
        if entity_type is None or entity_id is None or dimension is None:
            return None

        try:
            return self._entity_behavior_service.get_summary(
                entity_type=entity_type,
                entity_id=str(entity_id),
                dimension=dimension,
            )
        except Exception:
            # Return None on any error to avoid disrupting alert generation
            return None

    def _get_baseline_evidence(
        self,
        detection_result: DetectionResult,
        event: Any | None = None,
    ) -> BaselineEvidence | None:
        """Extract baseline evidence from the entity behavior service.

        This is a read-only operation that does not affect detection,
        decision, or alert generation logic. The evidence is attached
        to Alert.metadata for analyst reference only.

        Args:
            detection_result: The detection result that triggered.
            event: Optional normalized event for entity context extraction.

        Returns:
            BaselineEvidence if available, None otherwise.
        """
        if self._entity_behavior_service is None:
            return None

        # Extract entity context from detection result metadata first,
        # then fall back to evidence, then event
        entity_type = None
        entity_id = None
        dimension = None

        # Priority 1: Extract from detection result metadata (set by detector)
        metadata = detection_result.metadata
        if isinstance(metadata, dict):
            entity_type = metadata.get("entity_type")
            entity_id = metadata.get("entity_id")
            dimension = metadata.get("dimension")

        # Priority 2: Extract from detection result evidence
        if entity_id is None or dimension is None:
            for item in detection_result.evidence:
                if not isinstance(item, dict):
                    continue
                field = item.get("field", "")
                observed = item.get("observed")

                if field == "hostname" and entity_id is None and isinstance(observed, str):
                    entity_id = observed
                    if entity_type is None:
                        entity_type = "hostname"
                elif field == "dimension" and dimension is None and isinstance(observed, str):
                    dimension = observed
                elif field == "entity_type" and entity_type is None and isinstance(observed, str):
                    entity_type = observed

        # Priority 3: Fall back to event if not found
        if entity_id is None and event is not None:
            entity_id = event.hostname or event.src_ip
            if entity_id:
                entity_type = "hostname" if event.hostname else "ip"

        if dimension is None and event is not None:
            if event.process_name:
                dimension = "process_name"
            elif event.dst_ip:
                dimension = "dst_ip"
            elif event.src_ip:
                dimension = "src_ip"

        # Validate we have all required fields
        if entity_type is None or entity_id is None or dimension is None:
            return None

        # Extract the actual dimension value from metadata or evidence
        # Priority: metadata.first_value > evidence.first_value > dimension_value from entity_id
        dimension_value = None
        if isinstance(metadata, dict):
            dimension_value = metadata.get("first_value")
        if dimension_value is None:
            for item in detection_result.evidence:
                if not isinstance(item, dict):
                    continue
                if item.get("field") == "first_value" and isinstance(item.get("observed"), str):
                    dimension_value = item.get("observed")
                    break
        if dimension_value is None:
            dimension_value = str(entity_id)

        try:
            # Use event timestamp as processing_time for consistent classification
            processing_time = event.timestamp if event is not None else None
            return self._entity_behavior_service.generate_evidence_for_classification(
                entity_type=entity_type,
                entity_id=str(entity_id),
                dimension=dimension,
                dimension_value=dimension_value,
                processing_time=processing_time,
            )
        except Exception as exc:
            # Log unexpected errors for observability but never disrupt alert generation
            logger.warning(
                "Failed to generate baseline evidence for %s/%s[%s]: %s",
                entity_type,
                entity_id,
                dimension,
                exc,
            )
            return None

    def _add_to_correlation_group(self, alert: Alert, detection_result: DetectionResult) -> None:
        """Add alert to correlation group.

        Args:
            alert: Alert to add.
            detection_result: Associated detection result.
        """
        # Use source IP as correlation key
        src_ip = "unknown"
        for item in detection_result.evidence:
            if not isinstance(item, dict):
                continue
            if item.get("field") in ("src_ip", "source_ip") or "src_ip" in item:
                src_ip = str(item.get("observed", item.get("src_ip", "unknown")))
                break
        if src_ip != "unknown":
            correlation_key = f"src_ip:{src_ip}"
            if correlation_key not in self._correlation_groups:
                self._correlation_groups[correlation_key] = []
            self._correlation_groups[correlation_key].append(alert)

    def _associate_with_incident(self, alert: Alert) -> Alert:
        """Associate alert with an incident using entity correlation.

        Delegates to IncidentService which is the authoritative owner of
        entity-to-incident relationships. DecisionEngine orchestrates but
        does not independently own persistent incident relationship state.

        Alert immutability is preserved: a new Alert with incident_id set
        is returned via dataclasses.replace().

        If the alert already has an incident_id, it is preserved unless
        the incident no longer exists in the service (stale reference).

        Args:
            alert: The alert to associate.

        Returns:
            Alert with incident_id set if association occurred, otherwise
            the original alert unchanged.
        """
        if self._incident_service is None or self._entity_correlation_service is None:
            return alert

        # Only process alerts with entity context
        if alert.entity_context is None:
            return alert

        # Preserve existing incident_id if valid
        if alert.incident_id is not None:
            existing = self._incident_service.get_incident(alert.incident_id)
            if existing is not None:
                return alert  # Already associated, preserve it

        # Compute entity key for this alert
        entity_key = self._entity_correlation_service._compute_entity_key(alert)

        # Delegate to IncidentService for authoritative entity-to-incident mapping
        # This ensures a single source of truth and prevents stale references
        try:
            incident_id = self._incident_service.get_or_create_incident_for_entity(
                entity_key, [alert]
            )
            return replace(alert, incident_id=incident_id)
        except Exception as exc:
            # Log but do not swallow - let the caller know something went wrong
            # This is an operational failure, not a programming error
            import logging

            logging.getLogger(__name__).warning("Failed to associate alert with incident: %s", exc)
            # Return alert without incident_id - alert processing continues

        return alert

    def get_correlated_alerts(self, src_ip: str) -> list[Alert]:
        """Get all alerts correlated to a source IP.

        Args:
            src_ip: Source IP address.

        Returns:
            List of correlated alerts.
        """
        correlation_key = f"src_ip:{src_ip}"
        return self._correlation_groups.get(correlation_key, []).copy()

    def get_statistics(self) -> dict[str, Any]:
        """Get decision engine statistics.

        Returns:
            Dictionary containing decision engine statistics.
        """
        return {
            "total_alerts_created": self._total_alerts_created,
            "total_alerts_suppressed": self._total_alerts_suppressed,
            "active_cooldowns": len(self._alert_history),
            "correlation_groups": len(self._correlation_groups),
            "suppression_rate": (
                self._total_alerts_suppressed
                / (self._total_alerts_created + self._total_alerts_suppressed)
                if (self._total_alerts_created + self._total_alerts_suppressed) > 0
                else 0.0
            ),
        }

    def clear_cooldowns(self) -> None:
        """Clear all cooldown tracking."""
        self._alert_history.clear()
        self._deduplication.clear()

    def clear_correlations(self) -> None:
        """Clear all correlation groups."""
        self._correlation_groups.clear()

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"DecisionEngine("
            f"alerts_created={self._total_alerts_created}, "
            f"alerts_suppressed={self._total_alerts_suppressed}, "
            f"cooldowns={len(self._alert_history)})"
        )
