"""Custom exception hierarchy.

All application-specific exceptions descend from :class:`ThreatHunterError`
so that callers can catch the entire family with a single ``except`` clause
when appropriate.
"""


class ThreatHunterError(Exception):
    """Base exception for all argusprowl errors.

    Attributes:
        message: Human-readable description of the error.
        details: Optional mapping of additional context about the error.
    """

    def __init__(self, message: str, details: dict | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        base = self.message
        if self.details:
            detail_str = ", ".join(f"{k}={v!r}" for k, v in self.details.items())
            return f"{base} ({detail_str})"
        return base


class ConfigurationError(ThreatHunterError):
    """Raised when configuration loading or access fails.

    Examples: missing config file, malformed YAML, unsupported value.
    """


class ValidationError(ThreatHunterError):
    """Raised when data validation fails.

    Examples: invalid field value, missing required field, type mismatch.
    """


class ParserError(ThreatHunterError):
    """Raised when log or data parsing fails.

    Examples: unrecognised log format, corrupt input, encoding error.
    """


class DetectionError(ThreatHunterError):
    """Raised when threat detection processing fails.

    Examples: rule evaluation error, model inference failure.
    """


class PluginError(ThreatHunterError):
    """Raised when plugin loading or execution fails.

    Examples: missing entry point, incompatible API version.
    """


class AlertError(ThreatHunterError):
    """Raised when alert creation or delivery fails.

    Examples: notification channel unreachable, template rendering error.
    """


class StorageError(ThreatHunterError):
    """Raised when data persistence operations fail.

    Examples: database connection lost, write permission denied.
    """


class EventError(ThreatHunterError):
    """Raised when the internal event system encounters a failure.

    Examples: subscriber raised, event queue full.
    """


class DependencyError(ConfigurationError):
    """Raised when a service cannot be registered or resolved."""


class LifecycleError(ThreatHunterError):
    """Raised when application startup or shutdown cannot complete safely."""


class CollectorError(ThreatHunterError):
    """Base exception for all collector framework failures.

    Examples: collector registration conflict, lifecycle transition failure.
    """


class CollectorInitializationError(CollectorError):
    """Raised when a collector's initialize() method fails.

    Examples: missing required configuration key, resource unavailable at startup.
    """


class CollectorStartError(CollectorError):
    """Raised when a collector's start() method fails.

    Examples: network socket bind error, file handle unavailable.
    """


class CollectorStateError(CollectorError):
    """Raised when an invalid lifecycle state transition is attempted.

    Examples: calling pause() on a STOPPED collector, calling start() while RUNNING.
    """
