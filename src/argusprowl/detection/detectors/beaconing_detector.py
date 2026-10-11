"""Beaconing detector for suspicious periodic network behavior.

Detects potential C2 beaconing by analyzing temporal patterns in
network connections to the same destination.
"""

from __future__ import annotations

from argusprowl.interfaces.detector import Detector
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent
from argusprowl.temporal.engine import TemporalEngine


class BeaconingDetector(Detector):
    """Detector for suspicious periodic network behavior (beaconing).

    Uses temporal analysis to identify destinations with regular
    connection intervals that may indicate C2 communication.

    This detector produces behavioral evidence, not maliciousness.
    A high periodicity score is evidence, not proof of C2.
    """

    def __init__(
        self,
        temporal_engine: TemporalEngine,
        min_observations: int = 10,
        min_duration_seconds: float = 300.0,
        periodicity_threshold: float = 0.7,
        confidence_threshold: float = 0.5,
        version: int = 1,
    ) -> None:
        """Initialize beaconing detector.

        Args:
            temporal_engine: Shared temporal engine for state tracking.
            min_observations: Minimum observations required for analysis.
            min_duration_seconds: Minimum duration for beaconing assessment.
            periodicity_threshold: Minimum periodicity score to flag.
            confidence_threshold: Minimum confidence score for detections.
            version: Rule version.
        """
        self._temporal_engine = temporal_engine
        self._min_observations = min_observations
        self._min_duration_seconds = min_duration_seconds
        self._periodicity_threshold = periodicity_threshold
        self._confidence_threshold = confidence_threshold
        self._version = version
        self._detections_count = 0

    @property
    def name(self) -> str:
        return "beaconing_detector"

    @property
    def description(self) -> str:
        return "Detects suspicious periodic network behavior (beaconing)"

    @property
    def rule_id(self) -> str:
        return "TH-NET-BEACON-001"

    @property
    def version(self) -> int:
        return self._version

    def is_enabled(self) -> bool:
        return True

    def detect(self, event: NormalizedEvent) -> DetectionResult:
        """Evaluate an event for beaconing behavior.

        Args:
            event: NormalizedEvent to evaluate.

        Returns:
            DetectionResult with beaconing evidence if triggered.
        """
        if event.dst_ip is None:
            return self._no_match(event)

        analysis = self._temporal_engine.get_analysis(
            event.dst_ip, event.dst_port, src_ip=event.src_ip
        )

        if analysis is None:
            return self._no_match(event)

        # Check minimum observations
        if analysis["count"] < self._min_observations:
            return self._no_match(event)

        # Check minimum duration
        if analysis["duration_seconds"] < self._min_duration_seconds:
            return self._no_match(event)

        # Check periodicity threshold
        if analysis["periodicity_score"] < self._periodicity_threshold:
            return self._no_match(event)

        # Calculate behavioral confidence score using bounded evidence components:
        # 1. Base periodicity contribution (up to 0.55)
        confidence = analysis["periodicity_score"] * 0.55

        # 2. Observation count contribution (up to 0.15 for 30+ observations)
        count_score = min(analysis["count"] / 30.0, 1.0) * 0.15
        confidence += count_score

        # 3. Endpoint / Process correlation context (up to 0.15)
        if analysis.get("process_name"):
            confidence += 0.15

        # 4. Network context / Direction (up to 0.10)
        if analysis.get("direction") == "outbound":
            confidence += 0.10

        # 5. Negative evidence / Benign service context discount
        dst_port = analysis["key"][1]
        if dst_port == 123:
            # NTP traffic is standard periodic infrastructure protocol
            confidence -= 0.45
        elif dst_port in (80, 443):
            # Web traffic is frequently periodic polling/updating
            confidence -= 0.41

        # Ensure confidence is within [0.0, 1.0]
        confidence = max(0.0, min(1.0, confidence))

        if confidence < self._confidence_threshold:
            return self._no_match(event)

        # Build evidence
        evidence = [
            {"field": "destination", "observed": analysis["key"][0], "condition": "equals"},
            {"field": "destination_port", "observed": analysis["key"][1], "condition": "equals"},
            {
                "field": "observation_count",
                "observed": analysis["count"],
                "condition": "greater_than_or_equal",
            },
            {
                "field": "duration_seconds",
                "observed": analysis["duration_seconds"],
                "condition": "greater_than_or_equal",
            },
            {
                "field": "mean_interval",
                "observed": round(analysis["mean_interval"], 2),
                "condition": "equals",
            },
            {
                "field": "interval_dispersion",
                "observed": analysis["periodicity_classification"],
                "condition": "equals",
            },
            {
                "field": "periodicity_score",
                "observed": round(analysis["periodicity_score"], 3),
                "condition": "greater_than_or_equal",
            },
        ]

        # Add process identity evidence when available
        if analysis.get("process_name"):
            evidence.append(
                {
                    "field": "process_name",
                    "observed": analysis["process_name"],
                    "condition": "equals",
                }
            )
        if analysis.get("pid") is not None:
            evidence.append(
                {"field": "process_id", "observed": analysis["pid"], "condition": "equals"}
            )
        if analysis.get("username"):
            evidence.append(
                {"field": "username", "observed": analysis["username"], "condition": "equals"}
            )
        if analysis.get("hostname"):
            evidence.append(
                {"field": "hostname", "observed": analysis["hostname"], "condition": "equals"}
            )
        if analysis.get("direction"):
            evidence.append(
                {"field": "direction", "observed": analysis["direction"], "condition": "equals"}
            )
        if analysis.get("command_line"):
            evidence.append(
                {
                    "field": "command_line",
                    "observed": analysis["command_line"],
                    "condition": "equals",
                }
            )

        self._detections_count += 1

        # Build explanation with process context when available
        dest = f"{analysis['key'][0]}:{analysis['key'][1]}"
        explanation_parts = []
        if analysis.get("process_name"):
            process_ctx = f"The Process {analysis['process_name']}"
            if analysis.get("pid") is not None:
                process_ctx += f" (PID {analysis['pid']})"
            if analysis.get("username"):
                process_ctx += f", user {analysis['username']}"
            if analysis.get("hostname"):
                process_ctx += f" on {analysis['hostname']}"
            explanation_parts.append(f"{process_ctx} repeatedly communicated with {dest}")
        else:
            explanation_parts.append(f"Repeated communication with {dest} was observed")

        explanation_parts.append(
            f"over the observation window with {analysis['periodicity_classification']} timing."
        )
        explanation_parts.append("\n\nSupporting evidence:")
        explanation_parts.append(f"- {analysis['count']} observations")
        explanation_parts.append(f"- mean interval: {analysis['mean_interval']:.2f} seconds")
        explanation_parts.append(
            f"- periodicity score: {analysis['periodicity_score']:.3f} ({analysis['periodicity_classification']})"
        )
        explanation_parts.append("- destination remained stable")
        if analysis.get("process_name"):
            explanation_parts.append("- process-network correlation present")

        limiting_evidence = []
        if dst_port in (80, 443):
            limiting_evidence.append(
                "destination port is commonly used for benign periodic polling (HTTP/HTTPS)"
            )
        elif dst_port == 123:
            limiting_evidence.append(
                "destination port is used for NTP, which is highly periodic and benign"
            )

        if limiting_evidence:
            explanation_parts.append("\n\nLimiting evidence:")
            for item in limiting_evidence:
                explanation_parts.append(f"- {item}")

        return DetectionResult(
            rule_id=self.rule_id,
            event_id=event.event_id,
            matched=True,
            confidence=confidence,
            description=(
                f"Suspicious periodic behavior detected: {analysis['count']} observations "
                f"to {dest} over {analysis['duration_seconds']:.0f}s with periodicity score "
                f"{analysis['periodicity_score']:.3f} ({analysis['periodicity_classification']})"
            ),
            explanation=" ".join(explanation_parts),
            evidence=evidence,
            version=self._version,
        )

    def _no_match(self, event: NormalizedEvent) -> DetectionResult:
        """Return non-matching detection result."""
        return DetectionResult(
            rule_id=self.rule_id,
            event_id=event.event_id,
            matched=False,
        )

    def _increment_detections(self) -> None:
        """Increment detection counter (used by DetectionManager)."""
        self._detections_count += 1

    @property
    def detections_count(self) -> int:
        return self._detections_count
