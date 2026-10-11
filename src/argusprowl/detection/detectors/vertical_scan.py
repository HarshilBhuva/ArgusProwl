"""Vertical scan detector.

Detects vertical scanning where a source IP connects to multiple ports
on a single destination IP.
"""

from typing import Any

from argusprowl.constants.severity import Severity
from argusprowl.detection.base_detector import BaseDetector
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.models.detection_result import DetectionResult


class VerticalScanDetector(BaseDetector):
    """Detects vertical port scanning behavior.

    Identifies when a source IP connects to multiple ports on a single
    destination IP, indicating vertical scanning activity.

    Attributes:
        name: Detector identifier.
        min_unique_ports: Minimum unique destination ports.
        min_connection_rate: Minimum connections per second.
    """

    def __init__(
        self,
        min_unique_ports: int = 10,
        min_connection_rate: float = 2.0,
        **kwargs: Any,
    ) -> None:
        """Initialize vertical scan detector.

        Args:
            min_unique_ports: Minimum unique destination ports.
            min_connection_rate: Minimum connections per second.
            **kwargs: Additional configuration passed to BaseDetector.
        """
        super().__init__(
            name="vertical_scan",
            description="Detects vertical scanning on single destination",
            **kwargs,
        )
        self._min_unique_ports = min_unique_ports
        self._min_connection_rate = min_connection_rate

    def detect(self, feature_vector: FeatureVector) -> DetectionResult:
        """Detect vertical scanning behavior.

        Args:
            feature_vector: FeatureVector to analyze.

        Returns:
            DetectionResult indicating whether vertical scan detected.
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

        unique_ports = feature_vector.unique_dst_ports
        connection_rate = feature_vector.connection_rate
        is_multi_port = feature_vector.is_multi_port
        unique_dst_ips = feature_vector.unique_dst_ips

        # Vertical scan: multiple ports, single destination
        matched = (
            is_multi_port
            and unique_dst_ips == 1  # Single destination IP
            and unique_ports >= self._min_unique_ports
            and connection_rate >= self._min_connection_rate
        )

        if matched:
            confidence = min(1.0, (unique_ports / 20.0) * (connection_rate / 5.0))
            severity = Severity.HIGH if unique_ports > 20 else Severity.MEDIUM

            description = (
                f"Vertical scan detected from {feature_vector.src_ip} to "
                f"{feature_vector.dst_ip}: {unique_ports} unique ports, "
                f"{connection_rate:.1f} conn/sec"
            )

            explanation = (
                f"Vertical scan detected due to multiple ports on a single destination. "
                f"Observed {unique_ports} unique ports on {feature_vector.dst_ip} at "
                f"{connection_rate:.1f} conn/sec, exceeding thresholds of "
                f"{self._min_unique_ports} ports and {self._min_connection_rate} conn/sec."
            )

            evidence = [
                {
                    "field": "unique_dst_ports",
                    "observed": unique_ports,
                    "condition": f">= {self._min_unique_ports}",
                    "threshold": self._min_unique_ports,
                },
                {
                    "field": "unique_dst_ips",
                    "observed": unique_dst_ips,
                    "condition": "== 1",
                    "threshold": 1,
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
            f"No vertical scan detected. "
            f"Observed {unique_ports} unique ports on {feature_vector.dst_ip} at "
            f"{connection_rate:.1f} conn/sec, below thresholds of "
            f"{self._min_unique_ports} ports and {self._min_connection_rate} conn/sec."
        )

        evidence = [
            {
                "field": "unique_dst_ports",
                "observed": unique_ports,
                "condition": f"< {self._min_unique_ports}",
                "threshold": self._min_unique_ports,
            },
        ]

        return DetectionResult(
            rule_id=self.name,
            event_id=feature_vector.vector_id,
            matched=False,
            severity=Severity.INFO,
            confidence=0.0,
            description="No vertical scan detected",
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
        if "min_unique_ports" in config:
            self._min_unique_ports = config["min_unique_ports"]
        if "min_connection_rate" in config:
            self._min_connection_rate = config["min_connection_rate"]
