"""Correlation detector for endpoint ↔ network associations.

Produces DetectionResult objects when the EndpointCorrelator identifies
process-network relationships that meet configurable thresholds.

This detector produces behavioral evidence, not maliciousness verdicts.
Correlation indicates that a process communicated with a destination,
which is context for analysts, not proof of compromise.
"""

from __future__ import annotations

from typing import Any

from argusprowl.correlation.correlator import EndpointCorrelator
from argusprowl.interfaces.detector import Detector
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


class CorrelationDetector(Detector):
    """Detector for endpoint ↔ network correlation evidence.

    Checks the EndpointCorrelator for active correlations and produces
    DetectionResult objects when correlations meet minimum thresholds.

    The detector is evidence-based: it reports that a process was observed
    communicating with a destination, not that the communication is malicious.
    """

    def __init__(
        self,
        correlator: EndpointCorrelator,
        min_observations: int = 2,
        min_confidence: float = 0.5,
        version: int = 1,
    ) -> None:
        """Initialize correlation detector.

        Args:
            correlator: Shared EndpointCorrelator instance.
            min_observations: Minimum observations for correlation evidence.
            min_confidence: Minimum correlation confidence to report.
            version: Rule version.
        """
        self._correlator = correlator
        self._min_observations = min_observations
        self._min_confidence = min_confidence
        self._version = version
        self._detections_count = 0
        self._last_check_key: tuple[str | None, int | None, str | None, int | None] | None = None
        self._last_result: DetectionResult | None = None
        self._last_check_key: tuple[str | None, int | None, str | None, int | None] | None = None
        self._last_result: DetectionResult | None = None

    @property
    def name(self) -> str:
        return "correlation_detector"

    @property
    def description(self) -> str:
        return "Detects endpoint-to-network correlations with process attribution"

    @property
    def rule_id(self) -> str:
        return "TH-CORR-ENDPOINT-001"

    @property
    def version(self) -> int:
        return self._version

    def is_enabled(self) -> bool:
        return True

    def detect(self, event: NormalizedEvent) -> DetectionResult:
        """Evaluate correlation state for the given event's context.

        When the event has process attribution (process_name + pid), this
        detector checks whether the correlator has established a correlation
        involving this process and any destination. If so, it returns a
        DetectionResult with structured evidence.

        Args:
            event: NormalizedEvent to evaluate.

        Returns:
            DetectionResult with correlation evidence if triggered.
        """
        # Only produce correlation results when the event has process attribution
        if event.process_name is None and event.pid is None:
            return self._no_match(event)

        # Check if we already produced a result for this exact process+destination
        # to avoid duplicate detections for the same correlation

        correlations = self._correlator.get_correlations(
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
        )

        # Find correlations matching this process
        matching = [c for c in correlations if c.pid == event.pid and c.hostname == event.hostname]

        if not matching:
            return self._no_match(event)

        # Use the most recent correlation for this process+destination
        best = max(matching, key=lambda c: c.last_seen)

        # Apply thresholds
        if best.observation_count < self._min_observations:
            return self._no_match(event)

        if best.correlation_confidence < self._min_confidence:
            return self._no_match(event)

        self._detections_count += 1

        # Build evidence from correlation
        evidence = best.to_evidence()

        # Add contributing event IDs (all events in the correlation)
        contributing = best.event_ids

        return DetectionResult(
            rule_id=self.rule_id,
            event_id=event.event_id,
            matched=True,
            severity=self._severity_for_confidence(best.correlation_confidence),
            confidence=best.correlation_confidence,
            description=self._description(best),
            explanation=self._explanation(best),
            evidence=evidence,
            version=self._version,
            contributing_event_ids=contributing,
            metadata={
                "correlation_type": "endpoint_network",
                "observation_count": best.observation_count,
                "first_seen": best.first_seen.isoformat(),
                "last_seen": best.last_seen.isoformat(),
                "direction": best.direction.value,
                "source_types": list(best.source_types),
            },
        )

    def _severity_for_confidence(self, confidence: float) -> Any:
        """Map correlation confidence to severity level."""
        from argusprowl.constants.severity import Severity

        if confidence >= 0.8:
            return Severity.HIGH
        if confidence >= 0.6:
            return Severity.MEDIUM
        return Severity.LOW

    def _description(self, correlation: Any) -> str:
        """Generate human-readable description."""
        process = correlation.process_name or "unknown"
        pid = f" (PID {correlation.pid})" if correlation.pid is not None else ""
        dest = f"{correlation.dst_ip}:{correlation.dst_port}"
        proto = f" ({correlation.protocol})" if correlation.protocol else ""
        return (
            f"Process {process}{pid} communicated with {dest}{proto} "
            f"over {correlation.observation_count} observation(s)."
        )

    def _explanation(self, correlation: Any) -> str:
        """Generate structured explanation."""
        return (
            f"Endpoint correlation: {correlation.explanation} "
            f"This is behavioral evidence of process-network association, "
            f"not proof of malicious activity."
        )

    def _no_match(self, event: NormalizedEvent) -> DetectionResult:
        """Return a no-match detection result."""
        return DetectionResult(
            rule_id=self.rule_id,
            event_id=event.event_id,
            matched=False,
        )

    def _increment_detections(self) -> None:
        """Increment detection counter (called by DetectionManager)."""
        self._detections_count += 1

    @property
    def detections_count(self) -> int:
        """Total number of positive detections."""
        return self._detections_count
