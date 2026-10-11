"""Plugin interface.

Defines the contract that all argusprowl plugins must satisfy
to be discovered, loaded, and managed by the plugin subsystem.
"""

from abc import ABC, abstractmethod


class Plugin(ABC):
    """Abstract plugin.

    Plugins extend the platform with additional log sources, detectors,
    alert providers, or other capabilities.
    """

    @abstractmethod
    def initialize(self, config: dict[str, object]) -> None:
        """Initialise the plugin with its configuration section.

        Args:
            config: Plugin-specific configuration dictionary.

        Raises:
            PluginError: If initialisation fails.
        """

    @abstractmethod
    def start(self) -> None:
        """Start the plugin's background activity, if any.

        Raises:
            PluginError: If the plugin cannot start.
        """

    @abstractmethod
    def stop(self) -> None:
        """Gracefully stop the plugin."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name used for registration and logging."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Semantic version string of the plugin."""

    @abstractmethod
    def is_running(self) -> bool:
        """Return whether the plugin is currently active."""
