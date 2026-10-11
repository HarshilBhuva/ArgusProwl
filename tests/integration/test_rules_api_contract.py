from argusprowl.behavior.entity_behavior_detector import EntityBehaviorDetector
from argusprowl.detection.detectors.event_count_correlation import EventCountCorrelationDetector


def test_detectors_expose_required_api_attributes():
    """Verify detectors expose attributes required by the Rules API to prevent 500 errors."""
    detectors = [
        EventCountCorrelationDetector(name="test_count"),
        EntityBehaviorDetector(
            name="test_behavior", entity_type="hostname", dimension_field="process_name"
        ),
    ]

    for detector in detectors:
        # These are the attributes accessed in app/api/routes.py
        assert hasattr(detector, "name"), f"{type(detector).__name__} missing 'name'"
        assert hasattr(detector, "description"), f"{type(detector).__name__} missing 'description'"
        assert hasattr(detector, "confidence"), f"{type(detector).__name__} missing 'confidence'"
        assert hasattr(detector, "version"), f"{type(detector).__name__} missing 'version'"
        assert hasattr(detector, "is_enabled"), f"{type(detector).__name__} missing 'is_enabled'"

        # Verify types
        assert isinstance(detector.name, str)
        assert isinstance(detector.description, str)
        assert isinstance(detector.confidence, float)
        assert isinstance(detector.version, int)
        assert callable(detector.is_enabled)
