"""Detection package.

Provides detector registry, detection management, and concrete
threat detection implementations for network traffic analysis.
"""

from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.detector_registry import DetectorRegistry
from argusprowl.detection.detectors.correlation_detector import CorrelationDetector
from argusprowl.detection.rule_loader import RuleDefinition, RuleLoader

__all__ = [
    "CorrelationDetector",
    "DetectionManager",
    "DetectorRegistry",
    "RuleDefinition",
    "RuleLoader",
]
