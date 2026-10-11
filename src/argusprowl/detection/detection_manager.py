"""Detection manager implementation.

Orchestrates the detection pipeline by coordinating feature vector
processing through registered detectors.
"""

from typing import Any

from argusprowl.detection.cross_detector_correlator import CrossDetectorCorrelator
from argusprowl.detection.detector_registry import DetectorRegistry
from argusprowl.feature_engineering.feature_vector import FeatureVector
from argusprowl.interfaces.detector import Detector
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


class DetectionManager:
    """Orchestrates threat detection across multiple detectors.

    Manages the detection pipeline, coordinating feature vector
    processing through registered detectors and collecting results.

    Attributes:
        registry: Detector registry containing all detectors.
    """

    def __init__(self, registry: DetectorRegistry | None = None) -> None:
        """Initialize detection manager.

        Args:
            registry: Optional detector registry. Creates new one if not provided.
        """
        self._registry = registry or DetectorRegistry()
        self._processed_count = 0
        self._detection_count = 0
        self._correlators: list[CrossDetectorCorrelator] = []

    def register_detector(self, detector: Detector) -> None:
        """Register a detector with the manager.

        Args:
            detector: Detector instance to register.
        """
        self._registry.register(detector)

    def register_correlator(self, correlator: CrossDetectorCorrelator) -> None:
        """Register a cross-detector correlator.

        Args:
            correlator: CrossDetectorCorrelator instance to register.
        """
        self._correlators.append(correlator)

    def get_detector(self, name: str) -> Detector | None:
        """Get a registered detector by name.

        Args:
            name: Detector name.

        Returns:
            Detector instance or None if not found.
        """
        try:
            return self._registry.get(name)
        except KeyError:
            return None

    def process_feature_vector(self, feature_vector: FeatureVector) -> list[DetectionResult]:
        """Process a feature vector through all enabled detectors.

        Args:
            feature_vector: FeatureVector to analyze.

        Returns:
            List of DetectionResults from all enabled detectors.
        """
        if not isinstance(feature_vector, FeatureVector):
            raise TypeError(f"Expected FeatureVector, got {type(feature_vector)}")

        results: list[DetectionResult] = []
        enabled_detectors = self._registry.get_enabled()

        for detector_name, detector in enabled_detectors.items():
            # Skip event-based detectors
            if hasattr(detector, "observe"):
                continue

            try:
                result = detector.detect(feature_vector)
                results.append(result)

                if result.matched:
                    self._detection_count += 1
                    if hasattr(detector, "_increment_detections"):
                        detector._increment_detections()

            except Exception as exc:
                # Log error but continue with other detectors
                # In production, this would use proper logging
                print(f"Error in detector '{detector_name}': {exc}")

        self._processed_count += 1
        return results

    def process_event(self, event: NormalizedEvent) -> list[DetectionResult]:
        """Process a normalized event through all enabled event-based detectors.

        Args:
            event: NormalizedEvent to analyze.

        Returns:
            List of DetectionResults from all enabled event-based detectors.
        """
        if not isinstance(event, NormalizedEvent):
            raise TypeError(f"Expected NormalizedEvent, got {type(event)}")

        results: list[DetectionResult] = []
        enabled_detectors = self._registry.get_enabled()

        for detector_name, detector in enabled_detectors.items():
            # Only process detectors that have an observe method (event-based)
            if hasattr(detector, "observe"):
                try:
                    detector.observe(event)
                    result = detector.detect(event)
                    if result and result.matched:
                        results.append(result)
                        self._detection_count += 1
                        if hasattr(detector, "_increment_detections"):
                            detector._increment_detections()
                except Exception as exc:
                    print(f"Error in event detector '{detector_name}': {exc}")

        # Process cross-detector correlation
        for correlator in self._correlators:
            if correlator.is_enabled():
                try:
                    correlation_results = correlator.process(event, results)
                    for result in correlation_results:
                        results.append(result)
                        self._detection_count += 1
                        if hasattr(correlator, "_increment_detections"):
                            correlator._increment_detections()
                except Exception as exc:
                    print(f"Error in correlator '{correlator.name}': {exc}")

        return results

    def process_batch(self, feature_vectors: list[FeatureVector]) -> list[DetectionResult]:
        """Process a batch of feature vectors.

        Args:
            feature_vectors: List of FeatureVectors to process.

        Returns:
            List of all DetectionResults from the batch.
        """
        all_results: list[DetectionResult] = []
        for feature_vector in feature_vectors:
            results = self.process_feature_vector(feature_vector)
            all_results.extend(results)
        return all_results

    def get_registry(self) -> DetectorRegistry:
        """Get the detector registry.

        Returns:
            DetectorRegistry instance.
        """
        return self._registry

    @property
    def processed_count(self) -> int:
        """Total number of feature vectors processed."""
        return self._processed_count

    @property
    def detection_count(self) -> int:
        """Total number of positive detections."""
        return self._detection_count

    @property
    def detector_count(self) -> int:
        """Number of registered detectors."""
        return len(self._registry)

    @property
    def enabled_detector_count(self) -> int:
        """Number of enabled detectors."""
        return len(self._registry.get_enabled())

    def get_statistics(self) -> dict[str, Any]:
        """Get detection manager statistics.

        Returns:
            Dictionary containing processing statistics.
        """
        return {
            "processed_count": self._processed_count,
            "detection_count": self._detection_count,
            "detector_count": self.detector_count,
            "enabled_detector_count": self.enabled_detector_count,
            "detection_rate": (
                self._detection_count / self._processed_count if self._processed_count > 0 else 0.0
            ),
        }

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"DetectionManager("
            f"detectors={self.detector_count}, "
            f"enabled={self.enabled_detector_count}, "
            f"processed={self._processed_count}, "
            f"detections={self._detection_count})"
        )
