from datetime import UTC, datetime, timedelta
from threading import Thread

from argusprowl.constants.severity import Severity
from argusprowl.deduplication import AlertDeduplicationEngine, AlertFingerprint, FingerprintConfig
from argusprowl.models.alert import Alert


def _alert(src_ip: str = "10.0.0.1") -> Alert:
    return Alert(
        "Scan",
        "desc",
        Severity.HIGH,
        "port_scan",
        metadata={"evidence": {"src_ip": src_ip, "dst_ip": "10.0.0.2", "dst_port": 443}},
    )


def test_fingerprint_is_deterministic_versioned_and_normalized() -> None:
    fingerprint = AlertFingerprint(FingerprintConfig(("detector", "source", "src_ip"), version=2))
    one = _alert()
    two = _alert()
    assert fingerprint.create(one) == fingerprint.create(two)
    assert fingerprint.create(one).startswith("v2:")


def test_duplicate_is_suppressed_but_occurrence_is_retained() -> None:
    engine = AlertDeduplicationEngine(cooldown=60)
    first = engine.process(_alert())
    second = engine.process(_alert())
    assert first.emit and first.alert.metadata["occurrence_count"] == 1
    assert second.suppressed and second.state.occurrence_count == 2
    assert second.state.first_seen == first.state.first_seen
    assert engine.duplicate_occurrences.get_value() == 1


def test_cooldown_and_ttl_expiration() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    engine = AlertDeduplicationEngine(cooldown=10, state_ttl=20, clock=lambda: now)
    first = engine.process(_alert())
    now += timedelta(seconds=11)
    later = engine.process(_alert())
    assert later.emit and later.state.occurrence_count == 2
    now += timedelta(seconds=21)
    assert engine.expire() == 1
    assert engine.active_fingerprints.get_value() == 0
    assert first.state.alert_id != engine.process(_alert()).state.alert_id


def test_deduplication_check_update_is_atomic_across_threads() -> None:
    engine = AlertDeduplicationEngine(cooldown=60)
    results = []
    threads = [Thread(target=lambda: results.append(engine.process(_alert()))) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(result.emit for result in results) == 1
    assert max(result.state.occurrence_count for result in results) == 20


def test_deduplication_ignores_contextual_score() -> None:
    """Contextual score must NOT accidentally become part of alert identity."""
    engine = AlertDeduplicationEngine(cooldown=60)

    # First alert with no contextual score
    alert1 = Alert(
        title="Scan",
        description="desc",
        severity=Severity.HIGH,
        source="port_scan",
        metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
    )

    # Second alert with contextual score
    alert2 = Alert(
        title="Scan",
        description="desc",
        severity=Severity.CRITICAL,
        source="port_scan",
        contextual_confidence=0.95,
        metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
    )

    first = engine.process(alert1)
    second = engine.process(alert2)

    assert first.emit is True
    assert second.suppressed is True
    assert second.state.occurrence_count == 2


def test_deduplication_different_entities() -> None:
    """Different entities must not be deduplicated together."""
    engine = AlertDeduplicationEngine(cooldown=60)

    alert1 = Alert(
        title="Scan",
        description="desc",
        severity=Severity.HIGH,
        source="port_scan",
        metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.1"}]},
    )

    alert2 = Alert(
        title="Scan",
        description="desc",
        severity=Severity.HIGH,
        source="port_scan",
        metadata={"evidence": [{"field": "src_ip", "observed": "10.0.0.2"}]},
    )

    first = engine.process(alert1)
    second = engine.process(alert2)

    assert first.emit is True
    assert second.emit is True
