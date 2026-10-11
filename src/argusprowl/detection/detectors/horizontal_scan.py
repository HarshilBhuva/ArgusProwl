"""Horizontal scan detector.

Detects horizontal scanning where a source IP connects to the same port
across multiple destination IPs.
"""

from typing import Any

from argusprowl.constants.severity import Severity
from argusprowl.detection.base_detector import BaseDetector
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.models.detection_result import DetectionResult


class HorizontalScanDetector(BaseDetector):
    """Detects horizontal port scanning behavior.

    Identifies when a source IP connects to the same destination port
    across multiple unique destination IPs, indicating horizontal
    scanning activity.

    Attributes:
        name: Detector identifier.
        min_unique_dst_ips: Minimum unique destination IPs.
        min_connection_rate: Minimum connections per second.
    """

    def __init__(
        self,
        min_unique_dst_ips: int = 5,
        min_connection_rate: float = 2.0,
        **kwargs: Any,
    ) -> None:
        """Initialize horizontal scan detector.

        Args:
            min_unique_dst_ips: Minimum unique destination IPs.
            min_connection_rate: Minimum connections per second.
            **kwargs: Additional configuration passed to BaseDetector.
        """
        super().__init__(
            name="horizontal_scan",
            description="Detects horizontal scanning across multiple IPs",
            **kwargs,
        )
        self._min_unique_dst_ips = min_unique_dst_ips
        self._min_connection_rate = min_connection_rate

    def detect(self, feature_vector: FeatureVector) -> DetectionResult:
        """Detect horizontal scanning behavior.

        Args:
            feature_vector: FeatureVector to analyze.

        Returns:
            DetectionResult indicating whether horizontal scan detected.
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

        unique_dst_ips = feature_vector.unique_dst_ips
        connection_rate = feature_vector.connection_rate
        is_multi_dst = feature_vector.is_multi_dst

        # Detection logic
        matched = (
            is_multi_dst
            and unique_dst_ips >= self._min_unique_dst_ips
            and connection_rate >= self._min_connection_rate
        )

        if matched:
            confidence = min(1.0, (unique_dst_ips / 10.0) * (connection_rate / 5.0))
            severity = Severity.HIGH if unique_dst_ips > 15 else Severity.MEDIUM

            description = (
                f"Horizontal scan detected from {feature_vector.src_ip}: "
                f"{unique_dst_ips} unique destination IPs, "
                f"{connection_rate:.1f} conn/sec"
            )

            explanation = (
                f"Horizontal scan detected due to multiple destination IPs on the same port. "
                f"Observed {unique_dst_ips} unique destination IPs at "
                f"{connection_rate:.1f} conn/sec, exceeding thresholds of "
                f"{self._min_unique_dst_ips} IPs and {self._min_connection_rate} conn/sec."
            )

            evidence = [
                {
                    "field": "unique_dst_ips",
                    "observed": unique_dst_ips,
                    "condition": f">= {self._min_unique_dst_ips}",
                    "threshold": self._min_unique_dst_ips,
                },
                {
                    "field": "connection_rate",
                    "observed": connection_rate,
                    "condition": f">= {self._min_connection_rate}",
                    "threshold": self._min_connection_rate,
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
            f"No horizontal scan detected. "
            f"Observed {unique_dst_ips} unique destination IPs at "
            f"{connection_rate:.1f} conn/sec, below thresholds of "
            f"{self._min_unique_dst_ips} IPs and {self._min_connection_rate} conn/sec."
        )

        evidence = [
            {
                "field": "unique_dst_ips",
                "observed": unique_dst_ips,
                "condition": f"< {self._min_unique_dst_ips}",
                "threshold": self._min_unique_dst_ips,
            },
        ]

        return DetectionResult(
            rule_id=self.name,
            event_id=feature_vector.vector_id,
            matched=False,
            severity=Severity.INFO,
            confidence=0.0,
            description="No horizontal scan detected",
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
        if "min_unique_dst_ips" in config:
            self._min_unique_dst_ips = config["min_unique_dst_ips"]
        if "min_connection_rate" in config:
            self._min_connection_rate = config["min_connection_rate"]
