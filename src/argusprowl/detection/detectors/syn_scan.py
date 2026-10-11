"""SYN scan detector.

Detects SYN scan attacks characterized by high volumes of SYN packets
without corresponding connection completions.
"""

from typing import Any

from argusprowl.constants.severity import Severity
from argusprowl.detection.base_detector import BaseDetector
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.models.detection_result import DetectionResult


class SynScanDetector(BaseDetector):
    """Detects SYN scanning behavior.

    Identifies SYN scan attacks where an attacker sends SYN packets
    to many ports but rarely completes the TCP handshake, indicated
    by high SYN count and high failed connection ratio.

    Attributes:
        name: Detector identifier.
        min_syn_ratio: Minimum ratio of SYN packets to total connections.
        min_syn_count: Minimum SYN packet count.
    """

    def __init__(
        self,
        min_syn_ratio: float = 0.7,
        min_syn_count: int = 10,
        **kwargs: Any,
    ) -> None:
        """Initialize SYN scan detector.

        Args:
            min_syn_ratio: Minimum SYN/total connection ratio.
            min_syn_count: Minimum SYN packet count.
            **kwargs: Additional configuration passed to BaseDetector.
        """
        super().__init__(
            name="syn_scan",
            description="Detects SYN scanning attacks",
            **kwargs,
        )
        self._min_syn_ratio = min_syn_ratio
        self._min_syn_count = min_syn_count

    def detect(self, feature_vector: FeatureVector) -> DetectionResult:
        """Detect SYN scanning behavior.

        Args:
            feature_vector: FeatureVector to analyze.

        Returns:
            DetectionResult indicating whether SYN scan detected.
        """
        if not self.is_enabled():
            return DetectionResult(
                rule_id=self.name,
                event_id=feature_vector.vector_id,
                matched=False,
                severity=Severity.INFO,
                confidence=0.0,
                description="Detector is disabled",
            )

        syn_count = feature_vector.syn_count
        connection_count = feature_vector.connection_count
        failed_connections = feature_vector.failed_connections

        # Calculate SYN ratio
        syn_ratio = syn_count / connection_count if connection_count > 0 else 0.0

        # Calculate failure ratio
        failure_ratio = failed_connections / connection_count if connection_count > 0 else 0.0

        # Detection logic: high SYN ratio + high failure rate
        matched = (
            syn_count >= self._min_syn_count
            and syn_ratio >= self._min_syn_ratio
            and failure_ratio >= 0.5  # At least 50% failures
        )

        if matched:
            confidence = min(1.0, syn_ratio * failure_ratio * 2.0)
            severity = Severity.HIGH if syn_ratio > 0.9 else Severity.MEDIUM

            description = (
                f"SYN scan detected from {feature_vector.src_ip}: "
                f"{syn_count} SYN packets "
                f"({syn_ratio * 100:.1f}% of connections), "
                f"{failure_ratio * 100:.1f}% failure rate"
            )

            explanation = (
                f"SYN scan detected due to high SYN ratio and failure rate. "
                f"Observed {syn_count} SYN packets ({syn_ratio * 100:.1f}% of connections) "
                f"with {failure_ratio * 100:.1f}% failure rate, exceeding thresholds of "
                f"{self._min_syn_count} SYN packets and {self._min_syn_ratio * 100:.1f}% SYN ratio."
            )

            evidence = [
                {
                    "field": "syn_count",
                    "observed": syn_count,
                    "condition": f">= {self._min_syn_count}",
                    "threshold": self._min_syn_count,
                },
                {
                    "field": "syn_ratio",
                    "observed": syn_ratio,
                    "condition": f">= {self._min_syn_ratio}",
                    "threshold": self._min_syn_ratio,
                },
                {
                    "field": "failure_ratio",
                    "observed": failure_ratio,
                    "condition": ">= 0.5",
                    "threshold": 0.5,
                },
            ]

            self._increment_detections()

            return DetectionResult(
                rule_id=self.name,
                event_id=feature_vector.vector_id,
                matched=True,
                severity=severity,
                confidence=confidence,
                description=description,
                explanation=explanation,
                evidence=evidence,
                version=self.version,
            )

        explanation = (
            f"No SYN scan detected. "
            f"Observed {syn_count} SYN packets ({syn_ratio * 100:.1f}% of connections) "
            f"with {failure_ratio * 100:.1f}% failure rate, below thresholds of "
            f"{self._min_syn_count} SYN packets and {self._min_syn_ratio * 100:.1f}% SYN ratio."
        )

        evidence = [
            {
                "field": "syn_count",
                "observed": syn_count,
                "condition": f"< {self._min_syn_count}",
                "threshold": self._min_syn_count,
            },
            {
                "field": "syn_ratio",
                "observed": syn_ratio,
                "condition": f"< {self._min_syn_ratio}",
                "threshold": self._min_syn_ratio,
            },
        ]

        return DetectionResult(
            rule_id=self.name,
            event_id=feature_vector.vector_id,
            matched=False,
            severity=Severity.INFO,
            confidence=0.0,
            description="No SYN scan detected",
            explanation=explanation,
            evidence=evidence,
            version=self.version,
        )

    def configure(self, config: dict[str, Any]) -> None:
        """Update detector configuration.

        Args:
            config: Configuration dictionary with detector parameters.
        """
        super().configure(config)
        if "min_syn_ratio" in config:
            self._min_syn_ratio = config["min_syn_ratio"]
        if "min_syn_count" in config:
            self._min_syn_count = config["min_syn_count"]
