"""Tests for EntityCorrelationService."""

from uuid import uuid4

import pytest

from argusprowl.constants.severity import Severity
from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
from argusprowl.models.alert import Alert


@pytest.fixture
def service() -> EntityCorrelationService:
    return EntityCorrelationService()


def _alert(
    host: str | None = None,
    process_name: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    title: str = "Test Alert",
    **kwargs,
) -> Alert:
    """Create a test alert with optional entity context."""
    entity_context = {}
    if host is not None:
        entity_context["host"] = host
    if process_name is not None:
        entity_context["process_name"] = process_name
    if dst_ip is not None:
        entity_context["dst_ip"] = dst_ip
    if dst_port is not None:
        entity_context["dst_port"] = dst_port

    return Alert(
        title=title,
        description="Test description",
        severity=Severity.HIGH,
        source="test",
        entity_context=entity_context if entity_context else None,
        **kwargs,
    )


class TestGroupAlertsByEntity:
    """Tests for group_alerts_by_entity method."""

    def test_groups_by_host(self, service: EntityCorrelationService) -> None:
        """Alerts with same host and no destination should be grouped together."""
        alerts = [
            _alert(host="host1"),
            _alert(host="host1"),
            _alert(host="host2"),
        ]
        groups = service.group_alerts_by_entity(alerts)
        assert len(groups) == 2
        assert len(groups["host1:*"]) == 2
        assert len(groups["host2:*"]) == 1

    def test_groups_by_host_and_process(self, service: EntityCorrelationService) -> None:
        """Alerts with same host and process should be grouped together."""
        alerts = [
            _alert(host="host1", process_name="svchost.exe"),
            _alert(host="host1", process_name="svchost.exe"),
            _alert(host="host1", process_name="powershell.exe"),
        ]
        groups = service.group_alerts_by_entity(alerts)
        assert len(groups) == 2
        assert len(groups["host1:svchost.exe"]) == 2
        assert len(groups["host1:powershell.exe"]) == 1

    def test_groups_by_host_and_destination(self, service: EntityCorrelationService) -> None:
        """Alerts with same host and destination should be grouped together."""
        alerts = [
            _alert(host="host1", dst_ip="10.0.0.1"),
            _alert(host="host1", dst_ip="10.0.0.1"),
            _alert(host="host1", dst_ip="10.0.0.2"),
        ]
        groups = service.group_alerts_by_entity(alerts)
        assert len(groups) == 2
        assert len(groups["host1:10.0.0.1"]) == 2
        assert len(groups["host1:10.0.0.2"]) == 1

    def test_process_precedence_over_destination(self, service: EntityCorrelationService) -> None:
        """When both process and destination exist, process takes precedence."""
        alerts = [
            _alert(host="host1", process_name="svchost.exe", dst_ip="10.0.0.1"),
            _alert(host="host1", process_name="svchost.exe", dst_ip="10.0.0.2"),
        ]
        groups = service.group_alerts_by_entity(alerts)
        # Both should be grouped by host+process, not host+destination
        assert len(groups) == 1
        assert "host1:svchost.exe" in groups

    def test_empty_input(self, service: EntityCorrelationService) -> None:
        """Empty input should return empty dict."""
        groups = service.group_alerts_by_entity([])
        assert groups == {}

    def test_single_alert(self, service: EntityCorrelationService) -> None:
        """Single alert should form its own group."""
        alert = _alert(host="host1", dst_ip="10.0.0.1")
        groups = service.group_alerts_by_entity([alert])
        assert len(groups) == 1
        assert len(groups["host1:10.0.0.1"]) == 1

    def test_deterministic_grouping(self, service: EntityCorrelationService) -> None:
        """Same alerts should produce same groups regardless of input order."""
        # Create alerts once
        alert1 = _alert(host="host1", dst_ip="10.0.0.1")
        alert2 = _alert(host="host2", dst_ip="10.0.0.2")
        alert3 = _alert(host="host1", dst_ip="10.0.0.3")

        alerts1 = [alert1, alert2, alert3]
        alerts2 = [alert2, alert3, alert1]
        groups1 = service.group_alerts_by_entity(alerts1)
        groups2 = service.group_alerts_by_entity(alerts2)
        assert set(groups1.keys()) == set(groups2.keys())
        for key in groups1:
            assert {str(a.alert_id) for a in groups1[key]} == {
                str(a.alert_id) for a in groups2[key]
            }

    def test_alerts_without_entity_context(self, service: EntityCorrelationService) -> None:
        """Alerts without entity context should use fallback key."""
        alerts = [
            _alert(),
            _alert(),
            _alert(host="host1"),
        ]
        groups = service.group_alerts_by_entity(alerts)
        # Alerts without entity context should be in separate groups (fallback includes alert_id)
        assert len(groups) == 3

    def test_dst_ip_only(self, service: EntityCorrelationService) -> None:
        """Alerts with only dst_ip should be grouped by destination."""
        alerts = [
            _alert(dst_ip="10.0.0.1"),
            _alert(dst_ip="10.0.0.1"),
            _alert(dst_ip="10.0.0.2"),
        ]
        groups = service.group_alerts_by_entity(alerts)
        assert len(groups) == 2
        assert len(groups["*:10.0.0.1"]) == 2
        assert len(groups["*:10.0.0.2"]) == 1

    def test_sorted_within_groups(self, service: EntityCorrelationService) -> None:
        """Alerts within groups should be sorted by alert_id."""
        alert1 = _alert(host="host1", alert_id=uuid4())
        alert2 = _alert(host="host1", alert_id=uuid4())
        alert3 = _alert(host="host1", alert_id=uuid4())
        # Ensure different alert_ids
        ids = [alert1.alert_id, alert2.alert_id, alert3.alert_id]
        assert len(set(ids)) == 3

        groups = service.group_alerts_by_entity([alert1, alert2, alert3])
        group = groups["host1:*"]
        assert group == sorted(group, key=lambda a: str(a.alert_id))


class TestEntityKeyComputation:
    """Tests for entity key computation."""

    def test_host_only(self, service: EntityCorrelationService) -> None:
        """Host-only alerts should use host key."""
        alert = _alert(host="host1")
        key = service._compute_entity_key(alert)
        assert key == "host1:*"

    def test_host_and_process(self, service: EntityCorrelationService) -> None:
        """Host+process alerts should use host:process key."""
        alert = _alert(host="host1", process_name="svchost.exe")
        key = service._compute_entity_key(alert)
        assert key == "host1:svchost.exe"

    def test_host_and_destination(self, service: EntityCorrelationService) -> None:
        """Host+destination alerts should use host:dst_ip key."""
        alert = _alert(host="host1", dst_ip="10.0.0.1")
        key = service._compute_entity_key(alert)
        assert key == "host1:10.0.0.1"

    def test_process_precedence_over_destination(self, service: EntityCorrelationService) -> None:
        """When both process and destination exist, process takes precedence."""
        alert = _alert(host="host1", process_name="svchost.exe", dst_ip="10.0.0.1")
        key = service._compute_entity_key(alert)
        assert key == "host1:svchost.exe"

    def test_dst_ip_only(self, service: EntityCorrelationService) -> None:
        """Alerts with only dst_ip should use *:dst_ip key."""
        alert = _alert(dst_ip="10.0.0.1")
        key = service._compute_entity_key(alert)
        assert key == "*:10.0.0.1"

    def test_no_entity_context(self, service: EntityCorrelationService) -> None:
        """Alerts without entity context should use fallback key."""
        alert = _alert()
        key = service._compute_entity_key(alert)
        assert key.startswith("unknown:")
