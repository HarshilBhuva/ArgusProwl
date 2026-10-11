"""Base detector implementation.

Provides a concrete base class for detectors with common functionality
like rule loading, configuration management, and metrics tracking.
"""

from abc import abstractmethod
from typing import Any

from argusprowl.interfaces.detector import Detector
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.event import Event


class BaseDetector(Detector):
    """Concrete base class for threat detectors.

    Provides common functionality for all detectors including
    rule configuration, enable/disable state, and metrics.

    Attributes:
        name: Human-readable detector name.
        description: Detailed description of detection logic.
        enabled: Whether detector is active.
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        enabled: bool = True,
        config: dict[str, Any] | None = None,
        confidence: float = 0.0,
        version: int = 1,
    ) -> None:
        """Initialize base detector.

        Args:
            name: Detector name.
            description: Detector description.
            enabled: Initial enabled state.
            config: Optional configuration dictionary.
            confidence: Confidence score in [0.0, 1.0].
            version: Rule version.
        """
        self._name = name
        self._description = description
        self._enabled = enabled
        self._config = config or {}
        self._confidence = confidence
        self._version = version
        self._detections_count = 0

    @abstractmethod
    def detect(self, event: Event) -> DetectionResult:
        """Evaluate an event against detection logic.

        Args:
            event: Event to evaluate.

        Returns:
            DetectionResult describing the outcome.
        """

    @property
    def confidence(self) -> float:
        """Return the detector's confidence score."""
        return self._confidence

    @property
    def version(self) -> int:
        """Return the detector's version."""
        return self._version

    def is_enabled(self) -> bool:
        """Return whether this detector is currently active."""
        return self._enabled

    def enable(self) -> None:
        """Enable this detector."""
        self._enabled = True

    def disable(self) -> None:
        """Disable this detector."""
        self._enabled = False

    def configure(self, config: dict[str, Any]) -> None:
        """Update detector configuration.

        Args:
            config: New configuration dictionary.
        """
        self._config.update(config)

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Args:
            key: Configuration key.
            default: Default value if key not found.

        Returns:
            Configuration value or default.
        """
        return self._config.get(key, default)

    def _increment_detections(self) -> None:
        """Increment internal detection counter."""
        self._detections_count += 1

    @property
    def name(self) -> str:
        """Unique human-readable name of this detector."""
        return self._name

    @property
    def description(self) -> str:
        """Detector description."""
        return self._description

    @property
    def detections_count(self) -> int:
        """Total number of detections made."""
        return self._detections_count

    def __repr__(self) -> str:
        """String representation."""
        status = "enabled" if self._enabled else "disabled"
        return f"{self.__class__.__name__}(name={self._name!r}, status={status})"


# Example query pattern executed by BeaconingDetector against ClickHouse
BEACONING_FEATURE_QUERY = """
SELECT
    source_ip,
    destination_ip,
    count() as connection_count,
    avg(flow_duration) as avg_duration,
    stddevPop(toUnixTimestamp64Milli(timestamp)) as timing_stddev,
    sum(orig_bytes) as total_orig_bytes,
    sum(resp_bytes) as total_resp_bytes
FROM normalized_events
WHERE service = 'TLS'
  AND timestamp >= now() - INTERVAL 1 HOUR
GROUP BY source_ip, destination_ip
HAVING connection_count >= 10
"""
