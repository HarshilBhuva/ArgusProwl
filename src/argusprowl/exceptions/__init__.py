"""Custom exception hierarchy for the argusprowl platform."""

from argusprowl.exceptions.exceptions import (
    AlertError,
    ConfigurationError,
    DetectionError,
    EventError,
    ParserError,
    PluginError,
    StorageError,
    ThreatHunterError,
    ValidationError,
)

__all__ = [
    "AlertError",
    "ConfigurationError",
    "DetectionError",
    "EventError",
    "ParserError",
    "PluginError",
    "StorageError",
    "ThreatHunterError",
    "ValidationError",
]
from argusprowl.exceptions.exceptions import (
    DependencyError,
    LifecycleError,
)

__all__ = [
    "AlertError",
    "ConfigurationError",
    "DependencyError",
    "DetectionError",
    "EventError",
    "LifecycleError",
    "ParserError",
    "PluginError",
    "StorageError",
    "ThreatHunterError",
    "ValidationError",
]
