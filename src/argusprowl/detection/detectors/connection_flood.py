"""Connection flood detector.

Detects connection flooding attacks characterized by high volumes
of connections in a short time period.
"""

from typing import Any

from argusprowl.constants.severity import Severity
from argusprowl.detection.base_detector import BaseDetector
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.models.detection_result import DetectionResult


class ConnectionFloodDetector(BaseDetector):
    """Detects connection flooding behavior.

    Identifies denial-of-service attempts or aggressive scanning
    by detecting abnormally high connection rates.

    Attributes:
        name: Detector identifier.
        min_connection_rate: Minimum connections per second.
        min_connection_count: Minimum total connection count.
    """

    def __init__(
        self,
        min_connection_rate: float = 10.0,
        min_connection_count: int = 20,
        **kwargs: Any,
    ) -> None:
        """Initialize connection flood detector.

        Args:
            min_connection_rate: Minimum connections per second.
            min_connection_count: Minimum total connection count.
            **kwargs: Additional configuration passed to BaseDetector.
        """
        super().__init__(
            name="connection_flood",
            description="Detects connection flooding attacks",
            **kwargs,
        )
        self._min_connection_rate = min_connection_rate
        self._min_connection_count = min_connection_count

    def detect(self, feature_vector: FeatureVector) -> DetectionResult:
        """Detect connection flooding behavior.

        Args:
            feature_vector: FeatureVector to analyze.

        Returns:
            DetectionResult indicating whether connection flood detected.
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

        connection_rate = feature_vector.connection_rate
        connection_count = feature_vector.connection_count

        # Detection logic
        matched = (
            connection_rate >= self._min_connection_rate
            and connection_count >= self._min_connection_count
        )

        if matched:
            confidence = min(1.0, (connection_rate / 50.0) * (connection_count / 100.0))
            severity = Severity.HIGH if connection_rate > 30 else Severity.MEDIUM

            description = (
                f"Connection flood detected from {feature_vector.src_ip}: "
                f"{connection_count} connections, "
                f"{connection_rate:.2f} connections/sec"
            )
        else:
            confidence = 0.0
            severity = Severity.INFO
            description = (
                f"Normal connection activity from {feature_vector.src_ip}: "
                f"{connection_count} connections, "
                f"{connection_rate:.2f} connections/sec"
            )

        return DetectionResult(
            rule_id=self.name,
            event_id=feature_vector.vector_id,
            matched=matched,
            severity=severity,
            confidence=confidence,
            description=description,
        )
