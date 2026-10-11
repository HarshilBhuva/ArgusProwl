"""Lightweight dependency injection container.

Supports singleton and transient service registration and resolution.
"""

import threading
from collections.abc import Callable
from typing import Any, TypeVar

from argusprowl.constants.log_names import LogName
from argusprowl.exceptions.exceptions import DependencyError
from argusprowl.logging.logger_factory import LoggerFactory

T = TypeVar("T")


class ServiceRegistration:
    """Internal registration holder for a service in the DI container."""

    def __init__(
        self,
        interface_or_type: type,
        factory: Callable[..., Any],
        is_singleton: bool = True,
    ) -> None:
        self.interface_or_type = interface_or_type
        self.factory = factory
        self.is_singleton = is_singleton
        self.instance: Any = None


class ServiceContainer:
    """Thread-safe dependency injection service container."""

    _instance: "ServiceContainer | None" = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        self._registrations: dict[type, ServiceRegistration] = {}
        self._container_lock = threading.RLock()
        self._logger = LoggerFactory.get_logger(LogName.DI)

    @classmethod
    def get_instance(cls) -> "ServiceContainer":
        """Get global singleton ServiceContainer instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset global container instance (for testing)."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.clear()
            cls._instance = None

    def register_singleton(
        self,
        service_type: type[T],
        factory_or_instance: Callable[..., T] | T,
    ) -> None:
        """Register a singleton service.

        If an already instantiated instance is provided, it will be wrapped in a factory.

        Args:
            service_type: Type/Interface class.
            factory_or_instance: Factory function or pre-built instance.
        """
        with self._container_lock:
            if callable(factory_or_instance) and not isinstance(factory_or_instance, type):
                factory = factory_or_instance
                reg = ServiceRegistration(service_type, factory, is_singleton=True)
            else:
                instance = factory_or_instance
                reg = ServiceRegistration(service_type, lambda: instance, is_singleton=True)
                reg.instance = instance

            self._registrations[service_type] = reg
            self._logger.debug("Registered singleton service: %s", service_type.__name__)

    def register_transient(
        self,
        service_type: type[T],
        factory: Callable[..., T],
    ) -> None:
        """Register a transient service.

        A new instance will be created via factory on every call to resolve().

        Args:
            service_type: Type/Interface class.
            factory: Callable producing an instance.
        """
        with self._container_lock:
            reg = ServiceRegistration(service_type, factory, is_singleton=False)
            self._registrations[service_type] = reg
            self._logger.debug("Registered transient service: %s", service_type.__name__)

    def resolve(self, service_type: type[T]) -> T:
        """Resolve a registered service by type.

        Args:
            service_type: Registered type/Interface class.

        Returns:
            Resolved instance of service_type.

        Raises:
            ConfigurationError: If service_type is not registered.
        """
        with self._container_lock:
            reg = self._registrations.get(service_type)
            if reg is None:
                raise DependencyError(
                    f"Service '{service_type.__name__}' is not registered in DI container.",
                    details={"service_type": service_type.__name__},
                )

            if reg.is_singleton:
                if reg.instance is None:
                    reg.instance = reg.factory()
                return reg.instance
            else:
                return reg.factory()

    def is_registered(self, service_type: type) -> bool:
        """Return True if service_type is registered."""
        with self._container_lock:
            return service_type in self._registrations

    def clear(self) -> None:
        """Close owned singleton resources, then clear registrations.

        ``close`` is deliberately duck-typed so adapters can own database pools,
        queues, or HTTP clients without coupling the container to them.
        """
        with self._container_lock:
            for registration in reversed(list(self._registrations.values())):
                close = getattr(registration.instance, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception as exc:  # shutdown must continue
                        self._logger.warning("Error closing service: %s", exc)
            self._registrations.clear()
