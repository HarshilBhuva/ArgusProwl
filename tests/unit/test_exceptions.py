"""Tests for exceptions module."""

import pytest

from argusprowl.exceptions.exceptions import (
    ConfigurationError,
    ThreatHunterError,
    ValidationError,
)


def test_base_exception():
    err = ThreatHunterError("Base error", details={"key": "val"})
    assert err.message == "Base error"
    assert err.details == {"key": "val"}
    assert "key='val'" in str(err)


def test_subclass_exception():
    err = ConfigurationError("Config missing")
    assert isinstance(err, ThreatHunterError)
    assert str(err) == "Config missing"


def test_exception_catching():
    with pytest.raises(ThreatHunterError):
        raise ValidationError("Invalid input")
