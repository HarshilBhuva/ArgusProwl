"""Alert provider interface.

Defines the contract for components that deliver alert notifications
to external systems (email, Slack, webhook, etc.).
"""

from abc import ABC, abstractmethod

from argusprowl.models.alert import Alert


class AlertProvider(ABC):
    """Abstract alert delivery provider.

    Implementations handle a specific notification channel.
    """

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Deliver an alert through this provider's channel.

        Args:
            alert: The alert to send.

        Returns:
            ``True`` if delivery succeeded.

        Raises:
            AlertError: If delivery fails.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether this provider's channel is reachable."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique identifier for this provider."""
