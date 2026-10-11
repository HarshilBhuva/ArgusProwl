"""Long connection detector.

Detects abnormally long-lived connections that may indicate data
exfiltration, command-and-control, or suspicious activity.
"""

from typing import Any

from argusprowl.constants.severity import Severity
from argusprowl.detection.base_detector import BaseDetector
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.models.detection_result import DetectionResult


class LongConnectionDetector(BaseDetector):
    """Detects abnormally long connections.

    Identifies connections that persist for unusually long durations,
    which may indicate data exfiltration, C2 communication, or
    other suspicious long-lived sessions.

    Attributes:
        name: Detector identifier.
        min_duration_seconds: Minimum connection duration to trigger.
        min_bytes_transferred: Minimum bytes transferred.
    """

    def __init__(
        self,
        min_duration_seconds: float = 3600.0,  # 1 hour
        min_bytes_transferred: int = 1024 * 1024,  # 1 MB
        **kwargs: Any,
    ) -> None:
        """Initialize long connection detector.

        Args:
            min_duration_seconds: Minimum connection duration in seconds.
            min_bytes_transferred: Minimum bytes transferred.
            **kwargs: Additional configuration passed to BaseDetector.
        """
        super().__init__(
            name="long_connection",
            description="Detects abnormally long-lived connections",
            **kwargs,
        )
        self._min_duration_seconds = min_duration_seconds
        self._min_bytes_transferred = min_bytes_transferred

    def detect(self, feature_vector: FeatureVector) -> DetectionResult:
        """Detect abnormally long connections.

        Args:
            feature_vector: FeatureVector to analyze.

        Returns:
            DetectionResult indicating whether long connection detected.
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

        avg_duration = feature_vector.avg_duration
        max_duration = feature_vector.max_duration
        total_bytes = feature_vector.total_bytes_sent + feature_vector.total_bytes_received

        # Detection logic: long duration + significant data transfer
        duration_threshold_met = max_duration >= self._min_duration_seconds
        bytes_threshold_met = total_bytes >= self._min_bytes_transferred

        matched = duration_threshold_met and bytes_threshold_met

        if matched:
            # Calculate confidence based on how much thresholds are exceeded
            duration_factor = min(1.0, max_duration / (self._min_duration_seconds * 2))
            bytes_factor = min(1.0, total_bytes / (self._min_bytes_transferred * 2))
            confidence = (duration_factor + bytes_factor) / 2.0

            # Severity based on duration
            if max_duration >= 7200:  # 2+ hours
                severity = Severity.HIGH
            elif max_duration >= 5400:  # 1.5+ hours
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            duration_minutes = max_duration / 60.0
            total_mb = total_bytes / (1024 * 1024)

            description = (
                f"Long connection detected from {feature_vector.src_ip} to "
                f"{feature_vector.dst_ip}: {duration_minutes:.1f} minutes, "
                f"{total_mb:.2f} MB transferred"
            )

            evidence = {
                "max_duration_seconds": max_duration,
                "avg_duration_seconds": avg_duration,
                "total_bytes": total_bytes,
                "duration_minutes": duration_minutes,
                "total_mb": total_mb,
                "threshold_min_duration": self._min_duration_seconds,
                "threshold_min_bytes": self._min_bytes_transferred,
            }

            self._increment_detections()

            explanation = (
                f"Long connection detected due to abnormal duration and data transfer. "
                f"Observed {duration_minutes:.1f} minutes connection duration with "
                f"{total_mb:.2f} MB transferred, exceeding thresholds of "
                f"{self._min_duration_seconds / 60:.1f} minutes and "
                f"{self._min_bytes_transferred / (1024 * 1024):.2f} MB."
            )

            evidence = [
                {
                    "field": "max_duration",
                    "observed": max_duration,
                    "condition": f">= {self._min_duration_seconds}",
                    "threshold": self._min_duration_seconds,
                },
                {
                    "field": "total_bytes",
                    "observed": total_bytes,
                    "condition": f">= {self._min_bytes_transferred}",
                    "threshold": self._min_bytes_transferred,
                },
            ]

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

        return DetectionResult(
            rule_id=self.name,
            event_id=feature_vector.vector_id,
            matched=False,
            severity=Severity.INFO,
            confidence=0.0,
            description="No abnormally long connection detected",
        )

    def configure(self, config: dict[str, Any]) -> None:
        """Update detector configuration.

        Args:
            config: Configuration dictionary with detector parameters.
        """
        super().configure(config)
        if "min_duration_seconds" in config:
            self._min_duration_seconds = config["min_duration_seconds"]
        if "min_bytes_transferred" in config:
            self._min_bytes_transferred = config["min_bytes_transferred"]
