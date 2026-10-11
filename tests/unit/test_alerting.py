"""Tests for alerting module."""

from pathlib import Path

import pytest

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.alerting.console_provider import ConsoleAlertProvider
from argusprowl.alerting.json_provider import JsonAlertProvider
from argusprowl.constants.severity import Severity
from argusprowl.models.alert import Alert


@pytest.fixture
def alert_manager() -> AlertManager:
    """Create an AlertManager instance for testing."""
    return AlertManager()


@pytest.fixture
def sample_alert() -> Alert:
    """Create a sample Alert for testing."""
    return Alert(
        title="Port Scan Detected - 192.168.1.100",
        description="Port scan detected from 192.168.1.100: 15 unique ports, 2.5 conn/sec",
        severity=Severity.HIGH,
        source="port_scan",
        tags=("port_scan", "threat_detection", "severity_high", "high_confidence"),
        metadata={
            "confidence": 0.8,
            "evidence": {"unique_ports": 15, "connection_rate": 2.5},
        },
    )


@pytest.fixture
def temp_json_path(tmp_path: Path) -> Path:
    """Create a temporary JSON file path for testing."""
    return tmp_path / "test_alerts.jsonl"


class TestAlertManager:
    """Tests for AlertManager class."""

    def test_register_provider(self, alert_manager: AlertManager) -> None:
        """Test provider registration."""
        provider = ConsoleAlertProvider()
        alert_manager.register_provider(provider)

        assert "console" in alert_manager.get_all_providers()
        assert alert_manager.provider_count == 1

    def test_register_duplicate_raises(self, alert_manager: AlertManager) -> None:
        """Test registering duplicate provider raises error."""
        provider1 = ConsoleAlertProvider()
        provider2 = ConsoleAlertProvider()

        alert_manager.register_provider(provider1)
        with pytest.raises(ValueError):
            alert_manager.register_provider(provider2)

    def test_unregister_provider(self, alert_manager: AlertManager) -> None:
        """Test provider unregistration."""
        provider = ConsoleAlertProvider()
        alert_manager.register_provider(provider)
        alert_manager.unregister_provider("console")

        assert "console" not in alert_manager.get_all_providers()
        assert alert_manager.provider_count == 0

    def test_send_alert_to_single_provider(
        self, alert_manager: AlertManager, sample_alert: Alert
    ) -> None:
        """Test sending alert to a single provider."""
        provider = ConsoleAlertProvider()
        alert_manager.register_provider(provider)

        results = alert_manager.send_alert(sample_alert)

        assert "console" in results
        assert results["console"] is True
        assert alert_manager.total_alerts_dispatched == 1

    def test_send_alert_to_multiple_providers(
        self, alert_manager: AlertManager, sample_alert: Alert, temp_json_path: Path
    ) -> None:
        """Test sending alert to multiple providers."""
        console_provider = ConsoleAlertProvider()
        json_provider = JsonAlertProvider(output_path=temp_json_path)

        alert_manager.register_provider(console_provider)
        alert_manager.register_provider(json_provider)

        results = alert_manager.send_alert(sample_alert)

        assert len(results) == 2
        assert all(results.values())  # All should succeed

    def test_unavailable_provider_handling(
        self, alert_manager: AlertManager, sample_alert: Alert
    ) -> None:
        """Test handling of unavailable providers."""
        # Create a mock provider that's not available
        from argusprowl.interfaces.alert_provider import AlertProvider

        class UnavailableProvider(AlertProvider):
            @property
            def provider_name(self) -> str:
                return "unavailable"

            def send(self, alert: Alert) -> bool:
                return False

            def is_available(self) -> bool:
                return False

        provider = UnavailableProvider()
        alert_manager.register_provider(provider)

        results = alert_manager.send_alert(sample_alert)

        assert results["unavailable"] is False
        assert alert_manager.total_delivery_failures == 1

    def test_get_available_providers(self, alert_manager: AlertManager) -> None:
        """Test getting available providers."""
        console_provider = ConsoleAlertProvider()
        alert_manager.register_provider(console_provider)

        available = alert_manager.get_available_providers()
        assert "console" in available

    def test_statistics(self, alert_manager: AlertManager, sample_alert: Alert) -> None:
        """Test alert manager statistics."""
        provider = ConsoleAlertProvider()
        alert_manager.register_provider(provider)

        alert_manager.send_alert(sample_alert)
        stats = alert_manager.get_statistics()

        assert stats["registered_providers"] == 1
        assert stats["total_alerts_dispatched"] == 1
        assert stats["success_rate"] == 1.0


class TestConsoleAlertProvider:
    """Tests for ConsoleAlertProvider."""

    def test_send_alert(self, sample_alert: Alert) -> None:
        """Test sending alert to console."""
        provider = ConsoleAlertProvider(use_colors=False)
        result = provider.send(sample_alert)

        assert result is True

    def test_provider_name(self) -> None:
        """Test provider name."""
        provider = ConsoleAlertProvider()
        assert provider.provider_name == "console"

    def test_is_available(self) -> None:
        """Test availability check."""
        provider = ConsoleAlertProvider()
        assert provider.is_available() is True


class TestJsonAlertProvider:
    """Tests for JsonAlertProvider."""

    def test_send_alert(self, sample_alert: Alert, temp_json_path: Path) -> None:
        """Test writing alert to JSON file."""
        provider = JsonAlertProvider(output_path=temp_json_path)
        result = provider.send(sample_alert)

        assert result is True
        assert temp_json_path.exists()

        # Verify content
        with open(temp_json_path) as f:
            line = f.readline()
            import json

            alert_dict = json.loads(line)
            assert alert_dict["title"] == sample_alert.title
            assert alert_dict["severity"] == "HIGH"

    def test_multiple_alerts(self, sample_alert: Alert, temp_json_path: Path) -> None:
        """Test writing multiple alerts to JSON file."""
        provider = JsonAlertProvider(output_path=temp_json_path)

        alert1 = sample_alert
        alert2 = Alert(
            title="Test Alert 2",
            description="Second test alert",
            severity=Severity.MEDIUM,
            source="test",
        )

        provider.send(alert1)
        provider.send(alert2)

        with open(temp_json_path) as f:
            lines = f.readlines()
            assert len(lines) == 2

    def test_provider_name(self) -> None:
        """Test provider name."""
        provider = JsonAlertProvider()
        assert provider.provider_name == "json"

    def test_is_available(self, temp_json_path: Path) -> None:
        """Test availability check."""
        provider = JsonAlertProvider(output_path=temp_json_path)
        assert provider.is_available() is True

    def test_output_path_property(self, temp_json_path: Path) -> None:
        """Test output path property."""
        provider = JsonAlertProvider(output_path=temp_json_path)
        assert provider.output_path == temp_json_path
