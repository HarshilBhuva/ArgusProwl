"""Detector interface.

Defines the contract for components that evaluate events against
detection logic (rules, ML models, heuristics).
"""

from abc import ABC, abstractmethod

from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.event import Event


class Detector(ABC):
    """Abstract threat detector.

    Implementations encapsulate a single detection strategy —
    signature-based, anomaly-based, ML-based, etc.
    """

    @abstractmethod
    def detect(self, event: Event) -> DetectionResult:
        """Evaluate a single event against this detector's logic.

        Args:
            event: The structured event to analyse.

        Returns:
            A :class:`DetectionResult` describing the outcome.

        Raises:
            DetectionError: If evaluation fails.
        """

    @abstractmethod
    def is_enabled(self) -> bool:
        """Return whether this detector is currently active."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique human-readable name of this detector."""
