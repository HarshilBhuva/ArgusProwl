"""Collector factory.

Provides two registration styles so both import-time type registration (used
by concrete collector modules) and pre-built instance injection (used by
tests and the DI container) work through the same API.
"""

import queue
from typing import Any

from argusprowl.collectors.base_collector import BaseCollector
from argusprowl.exceptions.exceptions import CollectorError
from argusprowl.models.normalized_event import NormalizedEvent


class CollectorFactory:
    """Factory for creating and initialising :class:`~app.collectors.base_collector.BaseCollector` instances.

    Supports two registration styles:

    **Type-based** (for concrete collector modules)::

        factory.register_type("zeek", ZeekCollector, default_config={...})
        collector = factory.create("zeek", config={...})

    **Instance-based** (for pre-built objects, tests, or DI wiring)::

        factory.register_instance(my_collector)
        collector = factory.get_instance("my_collector_name")
    """

    def __init__(self, event_queue: queue.Queue[NormalizedEvent] | None = None) -> None:
        """Initialise the factory.

        Args:
            event_queue: Optional :class:`queue.Queue` injected
                into every collector created by :meth:`create`.
        """
        self._event_queue = event_queue
        self._types: dict[str, tuple[type[BaseCollector], dict[str, Any]]] = {}
        self._instances: dict[str, BaseCollector] = {}

    # ------------------------------------------------------------------ registration

    def register_type(
        self,
        name: str,
        cls: type[BaseCollector],
        default_config: dict[str, Any] | None = None,
    ) -> None:
        """Register a :class:`BaseCollector` sub-class under *name*.

        Args:
            name: Logical name for this collector type (e.g. ``"zeek"``).
            cls: :class:`BaseCollector` sub-class (not an instance).
            default_config: Default configuration merged under user overrides.

        Raises:
            TypeError: If *cls* is not a sub-class of :class:`BaseCollector`.
            CollectorError: If *name* is already registered as a type.
        """
        if not (isinstance(cls, type) and issubclass(cls, BaseCollector)):
            raise TypeError(f"cls must be a BaseCollector subclass, got {cls!r}.")
        if name in self._types:
            raise CollectorError(
                f"Collector type '{name}' is already registered.",
                {"name": name},
            )
        self._types[name] = (cls, default_config or {})

    def register_instance(self, collector: BaseCollector) -> None:
        """Register a pre-built collector instance.

        Args:
            collector: An already-constructed :class:`BaseCollector`.

        Raises:
            TypeError: If *collector* is not a :class:`BaseCollector`.
            CollectorError: If a collector with the same name is already registered.
        """
        if not isinstance(collector, BaseCollector):
            raise TypeError(f"Expected BaseCollector instance, got {type(collector).__name__!r}.")
        if collector.name in self._instances:
            raise CollectorError(
                f"Collector instance '{collector.name}' is already registered.",
                {"name": collector.name},
            )
        self._instances[collector.name] = collector

    # ------------------------------------------------------------------ creation

    def create(self, name: str, config: dict[str, Any] | None = None) -> BaseCollector:
        """Instantiate and initialize a collector by registered type name.

        Args:
            name: Registered type name (e.g. ``"zeek"``).
            config: Configuration overrides merged on top of *default_config*.

        Returns:
            An initialized (STOPPED) :class:`BaseCollector` instance.

        Raises:
            CollectorError: If *name* is not a registered type.
            CollectorInitializationError: If ``initialize()`` fails.
        """
        if name not in self._types:
            raise CollectorError(
                f"Collector type '{name}' is not registered. Available: {sorted(self._types)}",
                {"name": name},
            )
        cls, default_cfg = self._types[name]
        merged_config = {**default_cfg, **(config or {})}

        collector = cls(event_queue=self._event_queue)
        collector.initialize(merged_config)
        return collector

    def get_instance(self, name: str) -> BaseCollector:
        """Retrieve a pre-registered instance by name.

        Args:
            name: Collector name passed to :meth:`register_instance`.

        Returns:
            The registered :class:`BaseCollector` instance.

        Raises:
            CollectorError: If no instance with *name* is registered.
        """
        if name not in self._instances:
            raise CollectorError(
                f"No collector instance '{name}' registered. Available: {sorted(self._instances)}",
                {"name": name},
            )
        return self._instances[name]

    # ------------------------------------------------------------------ inspection

    def list_types(self) -> list[str]:
        """Return sorted list of registered type names.

        Returns:
            Sorted list of type-name strings.
        """
        return sorted(self._types)

    def list_instances(self) -> list[str]:
        """Return sorted list of registered instance names.

        Returns:
            Sorted list of instance-name strings.
        """
        return sorted(self._instances)

    def is_type_registered(self, name: str) -> bool:
        """Return True if *name* is a registered type."""
        return name in self._types

    def is_instance_registered(self, name: str) -> bool:
        """Return True if *name* is a registered instance."""
        return name in self._instances

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"CollectorFactory("
            f"types={sorted(self._types)!r}, "
            f"instances={sorted(self._instances)!r})"
        )
