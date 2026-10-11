"""Failed connections detector.

Detects high rates of failed connection attempts indicating potential
brute force or reconnaissance activity.
"""

from typing import Any

from argusprowl.constants.severity import Severity
from argusprowl.detection.base_detector import BaseDetector
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.models.detection_result import DetectionResult


class FailedConnectionsDetector(BaseDetector):
    """Detects high rates of failed connection attempts.

    Identifies potential brute force attacks, reconnaissance, or
    misconfigured clients by monitoring failed connection ratios.

    Attributes:
        name: Detector identifier.
        min_failed_ratio: Minimum failed/total connection ratio.
        min_failed_count: Minimum absolute failed connection count.
    """

    def __init__(
        self,
        min_failed_ratio: float = 0.5,
        min_failed_count: int = 10,
        **kwargs: Any,
    ) -> None:
        """Initialize failed connections detector.

        Args:
            min_failed_ratio: Minimum failed connection ratio (0.0-1.0).
            min_failed_count: Minimum absolute failed connection count.
            **kwargs: Additional configuration passed to BaseDetector.
        """
        super().__init__(
            name="failed_connections",
            description="Detects high rates of failed connections",
            **kwargs,
        )
        self._min_failed_ratio = min_failed_ratio
        self._min_failed_count = min_failed_count

    def detect(self, feature_vector: FeatureVector) -> DetectionResult:
        """Detect high failed connection rate.

        Args:
            feature_vector: FeatureVector to analyze.

        Returns:
            DetectionResult indicating whether failed connection threshold exceeded.
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

        failed_connections = feature_vector.failed_connections
        connection_count = feature_vector.connection_count

        # Calculate failure ratio
        failure_ratio = failed_connections / connection_count if connection_count > 0 else 0.0

        # Detection logic
        matched = (
            failed_connections >= self._min_failed_count and failure_ratio >= self._min_failed_ratio
        )

        if matched:
            confidence = min(1.0, failure_ratio * (failed_connections / 50.0))
            severity = Severity.HIGH if failure_ratio > 0.8 else Severity.MEDIUM

            description = (
                f"High failed connection rate from {feature_vector.src_ip}: "
                f"{failed_connections} failed connections "
                f"({failure_ratio * 100:.1f}% failure rate)"
            )

            explanation = (
                f"High failed connection rate detected. "
                f"Observed {failed_connections} failed connections "
                f"({failure_ratio * 100:.1f}% failure rate), exceeding thresholds of "
                f"{self._min_failed_count} failures and {self._min_failed_ratio * 100:.1f}% failure ratio."
            )

            evidence = [
                {
                    "field": "failed_connections",
                    "observed": failed_connections,
                    "condition": f">= {self._min_failed_count}",
                    "threshold": self._min_failed_count,
                },
                {
                    "field": "failure_ratio",
                    "observed": failure_ratio,
                    "condition": f">= {self._min_failed_ratio}",
                    "threshold": self._min_failed_ratio,
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
            f"No abnormal failed connection rate detected. "
            f"Observed {failed_connections} failed connections "
            f"({failure_ratio * 100:.1f}% failure rate), below thresholds of "
            f"{self._min_failed_count} failures and {self._min_failed_ratio * 100:.1f}% failure ratio."
        )

        evidence = [
            {
                "field": "failed_connections",
                "observed": failed_connections,
                "condition": f"< {self._min_failed_count}",
                "threshold": self._min_failed_count,
            },
        ]

        return DetectionResult(
            rule_id=self.name,
            event_id=feature_vector.vector_id,
            matched=False,
            severity=Severity.INFO,
            confidence=0.0,
            description="No abnormal failed connection rate detected",
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
        if "min_failed_ratio" in config:
            self._min_failed_ratio = config["min_failed_ratio"]
        if "min_failed_count" in config:
            self._min_failed_count = config["min_failed_count"]
