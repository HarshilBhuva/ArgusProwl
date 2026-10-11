"""Collector registry.

Thread-safe store that maps collector names to :class:`~app.collectors.base_collector.BaseCollector`
instances.  The registry is the single source of truth for which collectors
are known to the platform; it does not drive lifecycle — that is
:class:`~app.collectors.manager.CollectorManager`'s responsibility.
"""

import threading

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.collectors.state import CollectorState
from argusprowl.exceptions.exceptions import CollectorError


class CollectorRegistry:
    """Thread-safe registry mapping collector names to BaseCollector instances.

    Modelled after :class:`~app.detection.detector_registry.DetectorRegistry`.
    """

    def __init__(self) -> None:
        self._collectors: dict[str, BaseCollector] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ mutation

    def register(self, collector: BaseCollector) -> None:
        """Register a collector.

        Args:
            collector: The :class:`BaseCollector` instance to register.

        Raises:
            TypeError: If *collector* is not a :class:`BaseCollector`.
            CollectorError: If a collector with the same name is already registered.
        """
        if not isinstance(collector, BaseCollector):
            raise TypeError(f"Expected BaseCollector, got {type(collector).__name__!r}.")
        with self._lock:
            if collector.name in self._collectors:
                raise CollectorError(
                    f"Collector '{collector.name}' is already registered.",
                    {"collector": collector.name},
                )
            self._collectors[collector.name] = collector

    def unregister(self, name: str) -> None:
        """Remove a collector from the registry.

        Args:
            name: Collector name to remove.

        Raises:
            KeyError: If no collector with that name is registered.
        """
        with self._lock:
            if name not in self._collectors:
                raise KeyError(f"Collector '{name}' not found in registry.")
            del self._collectors[name]

    # ------------------------------------------------------------------ queries

    def get(self, name: str) -> BaseCollector:
        """Return a collector by name.

        Args:
            name: Collector name.

        Returns:
            The registered :class:`BaseCollector` instance.

        Raises:
            KeyError: If no collector with that name is registered.
        """
        with self._lock:
            if name not in self._collectors:
                raise KeyError(f"Collector '{name}' not found in registry.")
            return self._collectors[name]

    def get_all(self) -> dict[str, BaseCollector]:
        """Return a shallow copy of all registered collectors.

        Returns:
            Dict mapping collector names to instances.
        """
        with self._lock:
            return dict(self._collectors)

    def get_by_state(self, state: CollectorState) -> dict[str, BaseCollector]:
        """Return collectors currently in *state*.

        Args:
            state: Target :class:`~app.collectors.state.CollectorState`.

        Returns:
            Dict mapping names to instances whose current state equals *state*.
        """
        with self._lock:
            return {name: c for name, c in self._collectors.items() if c.state == state}

    def names(self) -> list[str]:
        """Return a sorted list of all registered collector names.

        Returns:
            Sorted list of name strings.
        """
        with self._lock:
            return sorted(self._collectors.keys())

    def clear(self) -> None:
        """Remove all collectors from the registry."""
        with self._lock:
            self._collectors.clear()

    # ------------------------------------------------------------------ dunder

    def __contains__(self, name: str) -> bool:
        """Return True if a collector with *name* is registered."""
        with self._lock:
            return name in self._collectors

    def __len__(self) -> int:
        """Return the number of registered collectors."""
        with self._lock:
            return len(self._collectors)

    def __repr__(self) -> str:
        """String representation."""
        with self._lock:
            names = list(self._collectors.keys())
        return f"CollectorRegistry(collectors={names!r})"
