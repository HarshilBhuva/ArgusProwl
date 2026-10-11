"""Focused Phase 6.4 tests for ATT&CK-aware unified alert search."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from argusprowl.alerting.alert_manager import AlertManager
from argusprowl.alerting.alert_persistence import AlertPersistence
from argusprowl.constants.priority import AlertPriority
from argusprowl.constants.severity import Severity
from argusprowl.correlation.entity_correlation_service import EntityCorrelationService
from argusprowl.models.alert import Alert
from argusprowl.services.alert_search_service import AlertSearchService, AlertSearchStatus


def make_alert(
    *, observations=None, source="port_scan", alert_id=None, host="host-a", created_at=None
) -> Alert:
    kwargs = dict(
        alert_id=alert_id or uuid4(),
        title="Test alert",
        description="Test description",
        severity=Severity.HIGH,
        priority=AlertPriority.HIGH,
        source=source,
        metadata={"attck_observations": observations} if observations is not None else {},
        entity_context={"host": host},
    )
    if created_at is not None:
        kwargs["created_at"] = created_at
    return Alert(**kwargs)


def obs(technique="T1046", mapping="DIRECT", tactic="Discovery", subtechnique=None):
    value = {"technique_id": technique, "mapping_type": mapping, "tactic": tactic}
    if subtechnique is not None:
        value["subtechnique_id"] = subtechnique
    return value


@pytest.fixture
def service() -> AlertSearchService:
    return AlertSearchService(None, None, EntityCorrelationService())


class TestAttckFilters:
    def test_exact_technique_match(self, service):
        alert = make_alert(observations=[obs()])
        service._queue = _Queue([alert])
        assert service.search(limit=10, technique_id="T1046").alerts == (alert,)

    def test_non_matching_and_similar_technique_do_not_match(self, service):
        alert = make_alert(observations=[obs("T1046")])
        service._queue = _Queue([alert])
        assert service.search(limit=10, technique_id="T1059").alerts == ()
        assert service.search(limit=10, technique_id="1046").alerts == ()

    def test_multiple_observations_match(self, service):
        alert = make_alert(observations=[obs("T1059"), obs("T1046")])
        service._queue = _Queue([alert])
        assert service.search(limit=10, technique_id="T1046").alerts == (alert,)

    @pytest.mark.parametrize("mapping", ["DIRECT", "SUPPORTED", "CONTEXTUAL"])
    def test_mapping_type(self, service, mapping):
        alert = make_alert(observations=[obs(mapping=mapping)])
        service._queue = _Queue([alert])
        assert service.search(limit=10, mapping_type=mapping).alerts == (alert,)

    def test_invalid_and_unobservable_mapping_type_rejected(self, service):
        with pytest.raises(ValueError):
            service.search(limit=10, mapping_type="UNKNOWN")
        with pytest.raises(ValueError):
            service.search(limit=10, mapping_type="NONE")

    def test_exact_tactic_only(self, service):
        alert = make_alert(observations=[obs(tactic="Discovery")])
        service._queue = _Queue([alert])
        assert service.search(limit=10, tactic="Discovery").alerts == (alert,)
        assert service.search(limit=10, tactic="Discover").alerts == ()
        assert service.search(limit=10, tactic="discovery").alerts == ()

    def test_combined_filters_are_and_with_or_within_dimension(self, service):
        match = make_alert(observations=[obs("T1046", "SUPPORTED", "Discovery")])
        wrong_type = make_alert(observations=[obs("T1046", "DIRECT", "Discovery")])
        wrong_tactic = make_alert(observations=[obs("T1046", "SUPPORTED", "Execution")])
        ordinary_mismatch = make_alert(
            observations=[obs("T1046", "SUPPORTED", "Discovery")], host="host-b"
        )
        service._queue = _Queue([match, wrong_type, wrong_tactic, ordinary_mismatch])
        result = service.search(
            limit=10,
            technique_id=("T1046",),
            mapping_type="SUPPORTED",
            tactic="Discovery",
            host="host-a",
        )
        assert result.alerts == (match,)

    def test_multiple_values_within_dimension_are_or(self, service):
        first = make_alert(observations=[obs("T1046")])
        second = make_alert(observations=[obs("T1059")])
        service._queue = _Queue([first, second])
        result = service.search(limit=10, technique_id=("T1046", "T1059"))
        assert len(result.alerts) == 2
        assert {a.alert_id for a in result.alerts} == {first.alert_id, second.alert_id}

    def test_subtechnique_filter_is_exact(self, service):
        alert = make_alert(observations=[obs(subtechnique="T1046.001")])
        service._queue = _Queue([alert])
        assert service.search(limit=10, subtechnique_id="T1046.001").alerts == (alert,)
        assert service.search(limit=10, subtechnique_id="T1046.002").alerts == ()

    def test_bounds_and_invalid_inputs(self, service):
        service._queue = _Queue([make_alert(observations=[obs()])])
        with pytest.raises(ValueError):
            service.search(limit=0)
        with pytest.raises(ValueError):
            service.search(limit=10, technique_id=())
        with pytest.raises(ValueError):
            service.search(limit=10, tactic=("x",) * 33)

    def test_malformed_observations_are_ignored_and_bounded(self, service):
        malformed = ["bad", None, {"technique_id": "T1059"}] * 100
        malformed.append({"technique_id": "T1046", "mapping_type": "DIRECT"})
        alert = make_alert(observations=malformed)
        service._queue = _Queue([alert])
        assert service.search(limit=10, technique_id="T1046").alerts == ()


class _Queue:
    def __init__(self, alerts):
        self._alerts = list(alerts)

    def list(self, **_kwargs):
        return list(self._alerts)


def test_queue_and_persistence_are_both_searched(tmp_path: Path):
    queue_alert = make_alert(observations=[obs()])
    persistent_alert = make_alert(observations=[obs("T1059")])
    persistence = AlertPersistence(tmp_path / "alerts.db", max_alerts=10)
    persistence.initialize()
    persistence.save_alert(persistent_alert)
    service = AlertSearchService(_Queue([queue_alert]), persistence, EntityCorrelationService())
    result = service.search(limit=10, technique_id="T1046")
    assert result.alerts == (queue_alert,)
    persistence.close()


def test_same_alert_deduplicates_and_queue_copy_is_authoritative(tmp_path: Path):
    alert_id = uuid4()
    created_at = datetime.now(UTC)
    persistent = make_alert(
        alert_id=alert_id, observations=[obs()], host="host-a", created_at=created_at
    )
    queue = make_alert(
        alert_id=alert_id, observations=[obs()], host="host-a", created_at=created_at
    )
    persistence = AlertPersistence(tmp_path / "alerts.db", max_alerts=10)
    persistence.initialize()
    persistence.save_alert(persistent)
    service = AlertSearchService(_Queue([queue]), persistence, EntityCorrelationService())
    result = service.search(limit=10, technique_id="T1046")
    assert result.status == AlertSearchStatus.AVAILABLE
    assert len(result.alerts) == 1
    assert result.alerts[0] == queue
    persistence.close()


def test_immutable_conflict_behavior_remains_degraded(tmp_path: Path):
    alert_id = uuid4()
    persistent = make_alert(alert_id=alert_id, observations=[obs()], host="host-a")
    queue = make_alert(alert_id=alert_id, observations=[obs("T1059")], host="host-a")
    persistence = AlertPersistence(tmp_path / "alerts.db", max_alerts=10)
    persistence.initialize()
    persistence.save_alert(persistent)
    service = AlertSearchService(_Queue([queue]), persistence, EntityCorrelationService())
    result = service.search(limit=10)
    assert result.status == AlertSearchStatus.DEGRADED
    assert result.reason == "payload_conflict"
    persistence.close()


def test_alert_manager_forwards_attck_filters():
    alert = make_alert(observations=[obs()])
    manager = AlertManager(alert_queue=_Queue([alert]))
    result = manager.search_alerts(limit=10, technique_id="T1046")
    assert result.alerts == (alert,)


def test_search_does_not_mutate_alert_security_or_attck_state(service):
    alert = make_alert(observations=[obs()])
    service._queue = _Queue([alert])
    before = alert.to_dict()
    result = service.search(limit=10, technique_id="T1046")
    assert result.alerts == (alert,)
    assert alert.to_dict() == before
