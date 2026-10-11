"""Tests for Dependency Injection Container."""

import pytest

from argusprowl.dependency_injection.container import ServiceContainer
from argusprowl.exceptions.exceptions import ConfigurationError


class ServiceA:
    def __init__(self, value: int = 42) -> None:
        self.value = value


class ServiceB:
    def __init__(self, service_a: ServiceA) -> None:
        self.service_a = service_a


def test_singleton_registration():
    container = ServiceContainer.get_instance()
    container.register_singleton(ServiceA, lambda: ServiceA(100))

    instance1 = container.resolve(ServiceA)
    instance2 = container.resolve(ServiceA)

    assert instance1 is instance2
    assert instance1.value == 100


def test_transient_registration():
    container = ServiceContainer.get_instance()
    container.register_transient(ServiceA, lambda: ServiceA(42))

    instance1 = container.resolve(ServiceA)
    instance2 = container.resolve(ServiceA)

    assert instance1 is not instance2
    assert instance1.value == instance2.value == 42


def test_unregistered_service_throws():
    container = ServiceContainer.get_instance()
    with pytest.raises(ConfigurationError, match="is not registered"):
        container.resolve(ServiceB)
