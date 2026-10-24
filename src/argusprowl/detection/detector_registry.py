"""Registry for optional detector integrations.

Event-driven YAML rule detectors are instantiated by RuleLoader and evaluated
by DetectionManager. The catalog below contains detectors with an explicit
window-analysis API that is invoked by a service outside that event pipeline.
"""

from typing import Any

from argusprowl.detection.detectors.tls_c2_detector import TLSC2Detector


BUILTIN_DETECTORS: dict[str, type[Any]] = {
    "TLSC2Detector": TLSC2Detector,
}


class DetectorRegistry:
    """Registry of event-driven detector instances."""

    def __init__(self) -> None:
        self._detectors: dict[str, Any] = {}

    def register(self, detector: Any) -> None:
        """Register a detector instance by its name."""
        if not hasattr(detector, "name") or not isinstance(detector.name, str):
            raise TypeError("Detector must expose a string name")
        if detector.name in self._detectors:
            raise ValueError(f"Detector '{detector.name}' is already registered.")
        self._detectors[detector.name] = detector

    def unregister(self, name: str) -> None:
        if name not in self._detectors:
            raise KeyError(f"Detector '{name}' not found in registry.")
        del self._detectors[name]

    def get(self, name: str) -> Any:
        if name not in self._detectors:
            raise KeyError(f"Detector '{name}' not found in registry.")
        return self._detectors[name]

    def get_all(self) -> dict[str, Any]:
        return self._detectors.copy()

    def get_enabled(self) -> dict[str, Any]:
        return {name: detector for name, detector in self._detectors.items() if detector.is_enabled()}

    def get_disabled(self) -> dict[str, Any]:
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
