"""API configuration models.

Defines typed configuration for the HTTP API layer.
"""

from dataclasses import dataclass, field


@dataclass(slots=True)
class ApiConfig:
    """HTTP API subsystem configuration.

    Attributes:
        enabled: Whether the HTTP API server is active.
        host: Bind address. Defaults to localhost for local development.
        port: Bind port. Must be in range 1-65535.
        cors_origins: List of allowed CORS origins. Empty list disables CORS.
        max_alert_limit: Hard server-side maximum for alert search limit.
    """

    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8080
    cors_origins: list[str] = field(default_factory=list)
    max_alert_limit: int = 100
