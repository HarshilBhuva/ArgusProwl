"""Detector registry implementation.

Provides plugin-like registration and management of threat detectors.
"""

from argusprowl.detection.detectors.tls_c2_detector import TLSC2Detector
from argusprowl.interfaces.detector import Detector

# Classes the detection manager is able to construct. RuleLoader.DETECTORS
# is the YAML allow-list that actually instantiates detectors at startup;
# this mapping is the registry-side catalog of the same classes.
BUILTIN_DETECTORS: dict[str, type[Detector]] = {
    "TLSC2Detector": TLSC2Detector,
}


class DetectorRegistry:
    """Registry for managing threat detector plugins.

    Provides centralized registration, discovery, and lifecycle
    management for detector implementations.

    Attributes:
        detectors: Dictionary mapping detector names to instances.
    """

    def __init__(self) -> None:
        """Initialize detector registry."""
        self._detectors: dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        """Register a detector instance.

        Args:
            detector: Detector instance to register.

        Raises:
            ValueError: If detector with same name already registered.
        """
        if not isinstance(detector, Detector):
            raise TypeError(f"Object must implement Detector interface: {type(detector)}")

        name = detector.name
        if name in self._detectors:
            raise ValueError(f"Detector '{name}' is already registered.")

        self._detectors[name] = detector

    def unregister(self, name: str) -> None:
        """Unregister a detector by name.

        Args:
            name: Detector name to unregister.

        Raises:
            KeyError: If detector not found.
        """
        if name not in self._detectors:
            raise KeyError(f"Detector '{name}' not found in registry.")
        del self._detectors[name]

    def get(self, name: str) -> Detector:
        """Get a detector by name.

        Args:
            name: Detector name.

        Returns:
            Detector instance.

        Raises:
            KeyError: If detector not found.
        """
        if name not in self._detectors:
            raise KeyError(f"Detector '{name}' not found in registry.")
        return self._detectors[name]

    def get_all(self) -> dict[str, Detector]:
        """Get all registered detectors.

        Returns:
            Dictionary mapping detector names to instances.
        """
        return self._detectors.copy()

    def get_enabled(self) -> dict[str, Detector]:
        """Get all enabled detectors.

        Returns:
            Dictionary mapping enabled detector names to instances.
        """
        return {name: det for name, det in self._detectors.items() if det.is_enabled()}

    def get_disabled(self) -> dict[str, Detector]:
        """Get all disabled detectors.

        Returns:
            Dictionary mapping disabled detector names to instances.
        """
        return {name: det for name, det in self._detectors.items() if not det.is_enabled()}

    def enable(self, name: str) -> None:
        """Enable a detector by name.

        Args:
            name: Detector name.

        Raises:
            KeyError: If detector not found.
        """
        detector = self.get(name)
        if hasattr(detector, "enable"):
            detector.enable()

    def disable(self, name: str) -> None:
        """Disable a detector by name.

        Args:
            name: Detector name.

        Raises:
            KeyError: If detector not found.
        """
        detector = self.get(name)
        if hasattr(detector, "disable"):
            detector.disable()

    def clear(self) -> None:
        """Remove all registered detectors."""
        self._detectors.clear()

    def __contains__(self, name: str) -> bool:
        """Check if detector is registered."""
        return name in self._detectors

    def __len__(self) -> int:
        """Return number of registered detectors."""
        return len(self._detectors)

    def __repr__(self) -> str:
        """String representation."""
        enabled_count = len(self.get_enabled())
        return f"DetectorRegistry(detectors={len(self._detectors)}, enabled={enabled_count})"
