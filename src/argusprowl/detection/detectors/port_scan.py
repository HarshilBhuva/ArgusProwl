"""Port scan detector.

Detects port scanning activity by identifying connections to multiple
unique ports from a single source IP within a time window.
"""

from typing import Any

from argusprowl.constants.severity import Severity
from argusprowl.detection.base_detector import BaseDetector
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.models.detection_result import DetectionResult


class PortScanDetector(BaseDetector):
    """Detects general port scanning behavior.

    Identifies when a source IP connects to multiple unique destination
    ports within a configured time window, indicating potential port
    scanning activity.

    Attributes:
        name: Detector identifier.
        min_unique_ports: Minimum unique ports to trigger detection.
        min_connection_rate: Minimum connections per second.
    """

    def __init__(
        self,
        min_unique_ports: int = 10,
        min_connection_rate: float = 1.0,
        **kwargs: Any,
    ) -> None:
        """Initialize port scan detector.

        Args:
            min_unique_ports: Minimum unique destination ports.
            min_connection_rate: Minimum connections per second.
            **kwargs: Additional configuration passed to BaseDetector.
        """
        super().__init__(
            name="port_scan",
            description="Detects port scanning activity",
            **kwargs,
        )
        self._min_unique_ports = min_unique_ports
        self._min_connection_rate = min_connection_rate

    def detect(self, feature_vector: FeatureVector) -> DetectionResult:
        """Detect port scanning behavior.

        Args:
            feature_vector: FeatureVector to analyze.

        Returns:
            DetectionResult indicating whether port scan detected.
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
        connection_count = feature_vector.connection_count
        port_concentration = feature_vector.port_concentration

        # Detection logic
        matched = (
            unique_ports >= self._min_unique_ports
            and connection_rate >= self._min_connection_rate
            and connection_count >= self._min_unique_ports
            and port_concentration < 0.5
        )

        if matched:
            confidence = min(1.0, (unique_ports / 20.0) * (connection_rate / 5.0))
            severity = Severity.HIGH if unique_ports > 20 else Severity.MEDIUM

            description = (
                f"Port scan detected from {feature_vector.src_ip}: "
                f"{unique_ports} unique ports, "
                f"{connection_rate:.1f} conn/sec"
            )

            explanation = (
                f"Port scan detected due to multiple unique ports from a single source. "
                f"Observed {unique_ports} unique ports at {connection_rate:.1f} conn/sec, "
                f"exceeding thresholds of {self._min_unique_ports} ports and "
                f"{self._min_connection_rate} conn/sec."
            )

            evidence = [
                {
                    "field": "unique_dst_ports",
                    "observed": unique_ports,
                    "condition": f">= {self._min_unique_ports}",
                    "threshold": self._min_unique_ports,
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
            f"No port scan detected. "
            f"Observed {unique_ports} unique ports at {connection_rate:.1f} conn/sec, "
            f"below thresholds of {self._min_unique_ports} ports and "
            f"{self._min_connection_rate} conn/sec."
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
            description="No port scan detected",
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
