"""Detector registry implementation.

Provides plugin-like registration and management of threat detectors.
"""

from argusprowl.detection.detectors.tls_c2_detector import TLSC2Detector
from argusprowl.interfaces.detector import Detector

# The catalog is intentionally limited to classes whose window-based API is
# compatible with the application registry. YAML-instantiated event detectors
# remain registered through RuleLoader.
BUILTIN_DETECTORS: dict[str, type[Detector]] = {
    "TLSC2Detector": TLSC2Detector,
}


class DetectorRegistry:
    """Registry for managing threat detector plugins."""

    def __init__(self) -> None:
        self._detectors: dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        if not isinstance(detector, Detector):
            raise TypeError(f"Object must implement Detector interface: {type(detector)}")
        if detector.name in self._detectors:
            raise ValueError(f"Detector '{detector.name}' is already registered.")
        self._detectors[detector.name] = detector

    def unregister(self, name: str) -> None:
        if name not in self._detectors:
            raise KeyError(f"Detector '{name}' not found in registry.")
        del self._detectors[name]

    def get(self, name: str) -> Detector:
        if name not in self._detectors:
            raise KeyError(f"Detector '{name}' not found in registry.")
        return self._detectors[name]

    def get_all(self) -> dict[str, Detector]:
        return self._detectors.copy()

    def get_enabled(self) -> dict[str, Detector]:
        return {name: detector for name, detector in self._detectors.items() if detector.is_enabled()}

    def get_disabled(self) -> dict[str, Detector]:
        return {name: detector for name, detector in self._detectors.items() if not detector.is_enabled()}

    def enable(self, name: str) -> None:
        self.get(name).enable()

    def disable(self, name: str) -> None:
        self.get(name).disable()

    def clear(self) -> None:
        self._detectors.clear()

    def __contains__(self, name: str) -> bool:
        return name in self._detectors

    def __len__(self) -> int:
        return len(self._detectors)

    def __repr__(self) -> str:
        return f"DetectorRegistry(detectors={len(self)}, enabled={len(self.get_enabled())})"
