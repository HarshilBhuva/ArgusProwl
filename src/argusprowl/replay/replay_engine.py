"""Replay engine implementation.

Orchestrates log replay through the production detection pipeline.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detectors.beaconing_detector import BeaconingDetector
from argusprowl.detection.rule_loader import RuleLoader
from argusprowl.feature_engineering.feature_extractor import FeatureExtractor
from argusprowl.intelligence.service import ContextualIntelligenceService
from argusprowl.logging.logger_factory import LoggerFactory
from argusprowl.models.alert import Alert
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.replay.replay_reader import ReplayReader
from argusprowl.temporal.engine import TemporalEngine

if TYPE_CHECKING:
    from argusprowl.behavior.entity_behavior_service import EntityBehaviorService
    from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
    from argusprowl.incident.incident_service import IncidentService


class ReplayEngine:
    """Orchestrates log replay through the detection pipeline.

    Replays historical log files through the production ingestion,
    feature extraction, detection, and alerting pipeline for testing
    and debugging purposes.

    When a TemporalEngine is provided, replay uses the same observe()
    path as live processing. BeaconingDetector is optional and evaluated
    per event after temporal observation.

    When incident_service and entity_correlation_service are provided,
    replay constructs an isolated DecisionEngine wired to those services,
    enabling incident-aware replay with full entity correlation semantics
    while guaranteeing that replay cannot mutate or observe live incident
    state.

    Attributes:
        reader: ReplayReader for log file access.
        feature_extractor: FeatureExtractor for feature engineering.
        detection_manager: DetectionManager for running detectors.
    """

    def __init__(
        self,
        log_path: str | Path,
        feature_extractor: FeatureExtractor | None = None,
        detection_manager: DetectionManager | None = None,
        temporal_engine: TemporalEngine | None = None,
        beaconing_detector: BeaconingDetector | None = None,
        intelligence_service: ContextualIntelligenceService | None = None,
        decision_engine: DecisionEngine | None = None,
        incident_service: IncidentService | None = None,
        entity_correlation_service: EntityCorrelationService | None = None,
        entity_behavior_service: EntityBehaviorService | None = None,
    ) -> None:
        """Initialize replay engine.

        Args:
            log_path: Path to Zeek log file.
            feature_extractor: Optional FeatureExtractor instance.
            detection_manager: Optional DetectionManager instance.
            temporal_engine: Optional TemporalEngine used for the same
                observe() path as live processing.
            beaconing_detector: Optional BeaconingDetector evaluated per event.
            intelligence_service: Optional ContextualIntelligenceService used
                for the same assessment path as live processing.
            decision_engine: Optional DecisionEngine used to synthesize alerts
                from detections and assessments. When not provided but
                incident_service and entity_correlation_service are, an
                isolated DecisionEngine is constructed automatically.
            incident_service: Optional isolated IncidentService for incident
                correlation during replay. When provided with
                entity_correlation_service, enables incident-aware replay.
            entity_correlation_service: Optional isolated EntityCorrelationService
                for deterministic entity grouping during replay.
            entity_behavior_service: Optional EntityBehaviorService for
                behavioral summary attachment during replay.
        """
        self._reader = ReplayReader(log_path)
        self._feature_extractor = feature_extractor or FeatureExtractor()
        self._detection_manager = detection_manager or RuleLoader().build_detection_manager()
        self._temporal_engine = temporal_engine
        self._beaconing_detector = beaconing_detector
        self._intelligence_service = intelligence_service
        self._incident_service = incident_service
        self._entity_correlation_service = entity_correlation_service
        self._entity_behavior_service = entity_behavior_service

        # Construct isolated DecisionEngine if not explicitly provided but
        # incident-aware replay is requested via isolated services.
        if decision_engine is None:
            if incident_service is not None and entity_correlation_service is not None:
                self._decision_engine = DecisionEngine(
                    incident_service=incident_service,
                    entity_correlation_service=entity_correlation_service,
                    entity_behavior_service=entity_behavior_service,
                )
            elif intelligence_service is not None:
                self._decision_engine = DecisionEngine(
                    entity_behavior_service=entity_behavior_service,
                )
            else:
                self._decision_engine = None
        else:
            self._decision_engine = decision_engine

        self._logger = LoggerFactory.get_logger("replay")
        self._events_processed = 0
        # Distinct counters:
        #   _detection_matches  - detector results with matched=True
        #   _alerts_created     - actual Alert objects produced by the decision engine
        #   _alerts_generated   - deprecated alias for _alerts_created (kept for
        #                         backward compatibility with callers and dashboards)
        self._detection_matches = 0
        self._alerts_created = 0
        # Backwards-compatible alias; see property below.
        self._alerts_generated = 0

    def _process_replay_event(
        self,
        event: NormalizedEvent,
        on_feature_vector: Callable[..., Any] | None = None,
    ) -> list[DetectionResult]:
        """Process one replayed event through the production-equivalent path.

        Temporal observation happens before feature extraction, matching
        Application._process_event().
        """
        if self._temporal_engine is not None:
            self._temporal_engine.observe(event)

        detection_results: list[DetectionResult] = []

        feature_vector = self._feature_extractor.extract(event)
        if feature_vector is not None:
            if on_feature_vector:
                on_feature_vector(feature_vector)
            detection_results.extend(self._detection_manager.process_feature_vector(feature_vector))

        # Process event-based detectors loaded by RuleLoader
        detection_results.extend(self._detection_manager.process_event(event))

        if self._beaconing_detector is not None and self._beaconing_detector.is_enabled():
            result = self._beaconing_detector.detect(event)
            if result.matched:
                detection_results.append(result)

        return detection_results

    def _decide_alerts(
        self,
        event: NormalizedEvent,
        detection_results: list[DetectionResult],
        on_alert: Callable[..., Any] | None = None,
    ) -> list[Alert]:
        """Apply the live assessment → decision path to matched detections.

        When intelligence/decision components are not provided, matched
        detections are counted for backward-compatible replay statistics
        without synthesizing Alert objects.
        """
        alerts: list[Alert] = []
        for result in detection_results:
            if not result.matched:
                continue
            self._detection_matches += 1
            if self._intelligence_service is None or self._decision_engine is None:
                continue
            assessment = self._intelligence_service.evaluate(result, event)
            alert = self._decision_engine.process_detection_result(
                result, assessment=assessment, event=event
            )
            if alert is None:
                continue
            self._alerts_created += 1
            alerts.append(alert)
            if on_alert:
                on_alert(alert)
        # Keep the backwards-compat alias in sync with the true alert-creation count.
        self._alerts_generated = self._alerts_created
        return alerts

    def run(self) -> list[Alert]:
        """Run replay through the detection pipeline.

        Returns:
            List of Alerts generated during replay.
        """
        self._logger.info("Starting replay from %s", self._reader._log_path)
        alerts: list[Alert] = []

        for event in self._reader.read_events():
            self._events_processed += 1
            if self._intelligence_service is not None:
                self._intelligence_service.record_event(event)
            if self._entity_behavior_service is not None and event.hostname:
                # Record event for behavioral profiling
                self._entity_behavior_service.record_observation(
                    "hostname",
                    event.hostname,
                    "process_name",
                    event.process_name or "unknown",
                    event.timestamp,
                )
                self._entity_behavior_service.record_observation(
                    "hostname",
                    event.hostname,
                    "dst_ip",
                    event.dst_ip or "unknown",
                    event.timestamp,
                )
            detection_results = self._process_replay_event(event)
            alerts.extend(self._decide_alerts(event, detection_results))

        self._logger.info(
            "Replay complete: %d events processed, %d detections",
            self._events_processed,
            self._alerts_generated,
        )

        return alerts

    def run_with_callbacks(
        self,
        on_event: Any = None,
        on_feature_vector: Any = None,
        on_detection: Any = None,
        on_alert: Any = None,
    ) -> list[Alert]:
        """Run replay with callback hooks for monitoring.

        Args:
            on_event: Callback for each event (event: NormalizedEvent) -> None.
            on_feature_vector: Callback for each feature vector (fv: FeatureVector) -> None.
            on_detection: Callback for each detection (result: DetectionResult) -> None.
            on_alert: Callback for each alert (alert: Alert) -> None.

        Returns:
            List of Alerts generated during replay.
        """
        self._logger.info("Starting replay with callbacks from %s", self._reader._log_path)
        alerts: list[Alert] = []

        for event in self._reader.read_events():
            self._events_processed += 1

            if on_event:
                on_event(event)

            if self._intelligence_service is not None:
                self._intelligence_service.record_event(event)
            if self._entity_behavior_service is not None and event.hostname:
                self._entity_behavior_service.record_observation(
                    "hostname",
                    event.hostname,
                    "process_name",
                    event.process_name or "unknown",
                    event.timestamp,
                )
                self._entity_behavior_service.record_observation(
                    "hostname",
                    event.hostname,
                    "dst_ip",
                    event.dst_ip or "unknown",
                    event.timestamp,
                )

            detection_results = self._process_replay_event(
                event,
                on_feature_vector=on_feature_vector,
            )

            for result in detection_results:
                if on_detection:
                    on_detection(result)

            alerts.extend(self._decide_alerts(event, detection_results, on_alert=on_alert))

        self._logger.info(
            "Replay complete: %d events, %d detections",
            self._events_processed,
            self._alerts_generated,
        )

        return alerts

    def get_statistics(self) -> dict[str, Any]:
        """Get replay statistics.

        Returns:
            Dictionary containing replay statistics.
        """
        return {
            "reader": self._reader.get_statistics(),
            "events_processed": self._events_processed,
            "detection_matches": self._detection_matches,
            "alerts_created": self._alerts_created,
            # Deprecated alias for alerts_created — kept so dashboards / CLI
            # output that reads ``alerts_generated`` do not break.
            "alerts_generated": self._alerts_generated,
            "temporal_enabled": self._temporal_engine is not None,
            "feature_extractor": {
                "window_size_seconds": self._feature_extractor.window_size_seconds,
                "active_windows": self._feature_extractor.active_window_count,
            },
            "detection_manager": self._detection_manager.get_statistics(),
        }

    @property
    def events_processed(self) -> int:
        """Total events processed during replay."""
        return self._events_processed

    @property
    def detection_matches(self) -> int:
        """Total detection matches (result.matched=True) seen during replay."""
        return self._detection_matches

    @property
    def alerts_created(self) -> int:
        """Total Alert objects produced by the decision engine during replay."""
        return self._alerts_created

    @property
    def alerts_generated(self) -> int:
        """Deprecated alias for :attr:`alerts_created`.

        .. deprecated::
            Use :attr:`alerts_created` instead.  This attribute still counts
            only actual :class:`Alert` objects (not raw detection matches).
        """
        return self._alerts_generated

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"ReplayEngine("
            f"events={self._events_processed}, "
            f"detections={self._detection_matches}, "
            f"alerts={self._alerts_created})"
        )
