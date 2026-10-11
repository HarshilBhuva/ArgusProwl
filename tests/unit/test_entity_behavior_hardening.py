"""Phase 5.0.3 hardening tests for EntityBehavior first-seen detection."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest
import yaml

from argusprowl.behavior.bounded_value_set import BoundedValueSet
from argusprowl.behavior.entity_behavior_detector import EntityBehaviorDetector
from argusprowl.behavior.entity_behavior_profile import ProfileMaturity
from argusprowl.behavior.entity_behavior_service import EntityBehaviorService
from argusprowl.constants.severity import Severity
from argusprowl.decision_engine.decision_engine import DecisionEngine
from argusprowl.detection.detection_manager import DetectionManager
from argusprowl.detection.rule_loader import RuleLoader
from argusprowl.exceptions.exceptions import DetectionError
from argusprowl.models.detection_result import DetectionResult
from argusprowl.models.normalized_event import NormalizedEvent


def make_event(hostname, process_name=None, dst_ip=None, src_ip=None, timestamp=None, suffix=""):
    return NormalizedEvent(
        source_type="test",
        event_type="test",
        timestamp=timestamp or datetime.now(UTC),
        hostname=hostname,
        src_ip=src_ip,
        dst_ip=dst_ip,
        process_name=process_name,
        metadata={"suffix": suffix} if suffix else {},
    )


def make_detector(
    name="test_rule",
    entity_type="hostname",
    dimension_field="process_name",
    behavior_service=None,
    enabled=True,
    confidence=1.0,
):
    return EntityBehaviorDetector(
        name=name,
        entity_type=entity_type,
        dimension_field=dimension_field,
        enabled=enabled,
        confidence=confidence,
        behavior_service=behavior_service or EntityBehaviorService(),
    )


class TestPipelineAudit:
    def test_detection_reaches_decision_engine(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_p1", behavior_service=service)
        event = make_event(hostname="host_p1", process_name="malware.exe", suffix="p1")
        result = detector.detect(event)
        assert result.matched is True
        assert result.rule_id == "test_p1"
        assert result.severity == Severity.INFO
        assert result.confidence == 1.0

    def test_decision_engine_processes_behavior_detection(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_p2", behavior_service=service)
        event = make_event(hostname="host_p2", process_name="malware.exe", suffix="p2")
        result = detector.detect(event)
        assert result.matched is True
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None
        assert alert.source == "test_p2"

    def test_no_duplicate_detection_for_repeated_value(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_p3", behavior_service=service)
        event = make_event(hostname="host_p3", process_name="malware.exe", suffix="p3")
        result1 = detector.detect(event)
        result2 = detector.detect(event)
        assert result1.matched is True
        assert result2.matched is False

    def test_rule_id_survives_pipeline(self):
        service = EntityBehaviorService()
        detector = make_detector(name="first_seen_host_process", behavior_service=service)
        event = make_event(hostname="host_p4", process_name="malware.exe", suffix="p4")
        result = detector.detect(event)
        engine = DecisionEngine(cooldown_seconds=0)
        alert = engine.process_detection_result(result)
        assert alert is not None
        assert alert.source == "first_seen_host_process"

    def test_behavior_state_independent(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_p5", behavior_service=service)
        event = make_event(hostname="host_p5", process_name="malware.exe", suffix="p5")
        result = detector.detect(event)
        assert result.matched is True
        fresh_service = EntityBehaviorService()
        fresh_detector = make_detector(name="test_p5_fresh", behavior_service=fresh_service)
        fresh_result = fresh_detector.detect(event)
        assert fresh_result.matched is True

    def test_detection_manager_processes_behavior_detector(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_p6", behavior_service=service)
        manager = DetectionManager()
        manager.register_detector(detector)
        event = make_event(hostname="host_p6", process_name="malware.exe", suffix="p6")
        results = manager.process_event(event)
        assert len(results) == 1
        assert results[0].matched is True
        results2 = manager.process_event(event)
        assert len(results2) == 0


class TestConcurrencyHardening:
    def test_concurrent_first_observation_same_entity_value(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_c1", behavior_service=service)
        event = make_event(hostname="host_c1", process_name="malware.exe", suffix="c1")
        results = []
        lock = threading.Lock()

        def detect_once():
            result = detector.detect(event)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=detect_once) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        matched = [r for r in results if r.matched]
        assert len(matched) == 1, f"Expected 1 match, got {len(matched)}"

    def test_concurrent_different_values_same_entity(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_c2", behavior_service=service)
        results = []
        lock = threading.Lock()
        hostname = "host_c2"

        def detect_value(value):
            event = make_event(hostname=hostname, process_name=value, suffix=f"c2_{value}")
            result = detector.detect(event)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=detect_value, args=(f"proc{i}",)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        matched = [r for r in results if r.matched]
        assert len(matched) == 20

    def test_concurrent_different_entities(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_c3", behavior_service=service)
        results = []
        lock = threading.Lock()

        def detect_entity(entity):
            event = make_event(hostname=entity, process_name="malware.exe", suffix=f"c3_{entity}")
            result = detector.detect(event)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=detect_entity, args=(f"host_{i}",)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        matched = [r for r in results if r.matched]
        assert len(matched) == 20

    def test_concurrent_profile_creation(self):
        service = EntityBehaviorService(max_profiles=100)

        def create_profile(i):
            service.record_observation(
                entity_type="hostname",
                entity_id=f"host_{i}",
                dimension="process_name",
                dimension_value="proc1",
                timestamp=datetime.now(UTC),
            )

        threads = [threading.Thread(target=create_profile, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert service.profile_count == 50

    def test_concurrent_profile_eviction(self):
        service = EntityBehaviorService(max_profiles=10)

        def create_profile(i):
            service.record_observation(
                entity_type="hostname",
                entity_id=f"host_{i}",
                dimension="process_name",
                dimension_value="proc1",
                timestamp=datetime.now(UTC),
            )

        threads = [threading.Thread(target=create_profile, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert service.profile_count <= 10


class TestEvictionChurn:
    def test_profile_eviction_beyond_max_profiles(self):
        service = EntityBehaviorService(max_profiles=5)
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        for i in range(10):
            service.record_observation(
                entity_type="hostname",
                entity_id=f"host_{i}",
                dimension="process_name",
                dimension_value="proc1",
                timestamp=timestamp,
            )
        assert service.profile_count == 5
        assert service.get_profile("hostname", "host_0", "process_name") is None
        assert service.get_profile("hostname", "host_1", "process_name") is None
        assert service.get_profile("hostname", "host_2", "process_name") is None
        assert service.get_profile("hostname", "host_3", "process_name") is None
        assert service.get_profile("hostname", "host_4", "process_name") is None
        assert service.get_profile("hostname", "host_5", "process_name") is not None
        assert service.get_profile("hostname", "host_9", "process_name") is not None

    def test_value_eviction_beyond_max_per_profile(self):
        service = EntityBehaviorService(max_values_per_profile=5)
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        for i in range(10):
            service.record_observation(
                entity_type="hostname",
                entity_id="host1",
                dimension="dst_ip",
                dimension_value=f"10.0.0.{i}",
                timestamp=timestamp,
            )
        profile = service.get_profile("hostname", "host1", "dst_ip")
        assert profile is not None
        assert profile.observation_count == 10
        assert not service.has_value("hostname", "host1", "dst_ip", "10.0.0.0")
        assert service.has_value("hostname", "host1", "dst_ip", "10.0.0.5")
        assert service.has_value("hostname", "host1", "dst_ip", "10.0.0.9")

    def test_deterministic_lru_behavior(self):
        service = EntityBehaviorService(max_profiles=3)
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        for i in range(3):
            service.record_observation(
                entity_type="hostname",
                entity_id=f"host_{i}",
                dimension="process_name",
                dimension_value="proc1",
                timestamp=timestamp,
            )
        service.get_profile("hostname", "host_1", "process_name")
        service.record_observation(
            entity_type="hostname",
            entity_id="host_3",
            dimension="process_name",
            dimension_value="proc1",
            timestamp=timestamp,
        )
        assert service.get_profile("hostname", "host_0", "process_name") is None
        assert service.get_profile("hostname", "host_1", "process_name") is not None
        assert service.get_profile("hostname", "host_2", "process_name") is not None
        assert service.get_profile("hostname", "host_3", "process_name") is not None

    def test_evicted_profile_allows_new_first_seen(self):
        service = EntityBehaviorService(max_profiles=2)
        detector = make_detector(name="test_evict", behavior_service=service)
        detector.detect(make_event(hostname="host_evict0", process_name="proc1", suffix="evict0"))
        detector.detect(make_event(hostname="host_evict1", process_name="proc1", suffix="evict1"))
        detector.detect(make_event(hostname="host_evict2", process_name="proc1", suffix="evict2"))
        assert service.get_profile("hostname", "host_evict0", "process_name") is None
        result = detector.detect(
            make_event(hostname="host_evict0", process_name="proc2", suffix="evict3")
        )
        assert result.matched is True

    def test_unrelated_profiles_not_corrupted(self):
        service = EntityBehaviorService(max_profiles=3)
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        for i in range(3):
            service.record_observation(
                entity_type="hostname",
                entity_id=f"host_{i}",
                dimension="process_name",
                dimension_value=f"proc{i}",
                timestamp=timestamp,
            )
        service.record_observation(
            entity_type="hostname",
            entity_id="host_3",
            dimension="process_name",
            dimension_value="proc3",
            timestamp=timestamp,
        )
        assert service.has_value("hostname", "host_1", "process_name", "proc1")
        assert service.has_value("hostname", "host_2", "process_name", "proc2")
        assert service.has_value("hostname", "host_3", "process_name", "proc3")

    def test_value_set_lru_deterministic(self):
        bvs = BoundedValueSet(max_values=3)
        bvs.add("value1")
        bvs.add("value2")
        bvs.add("value3")
        _ = "value2" in bvs
        is_new, _ = bvs.add("value4")
        assert is_new is True
        assert "value1" not in bvs
        assert "value2" in bvs
        assert "value3" in bvs
        assert "value4" in bvs


class TestEventTimeSemantics:
    def test_monotonically_increasing_timestamps(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_mono", behavior_service=service)
        base_time = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        events = [
            make_event(
                hostname="host_mono", process_name="proc1", timestamp=base_time, suffix="m1"
            ),
            make_event(
                hostname="host_mono",
                process_name="proc2",
                timestamp=base_time + timedelta(seconds=1),
                suffix="m2",
            ),
            make_event(
                hostname="host_mono",
                process_name="proc3",
                timestamp=base_time + timedelta(seconds=2),
                suffix="m3",
            ),
        ]
        results = [detector.detect(e) for e in events]
        assert all(r.matched for r in results)
        profile = service.get_profile("hostname", "host_mono", "process_name")
        assert profile.first_seen == base_time
        assert profile.last_seen == base_time + timedelta(seconds=2)
        assert profile.observation_count >= 3

    def test_equal_timestamps(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_equal", behavior_service=service)
        timestamp = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        event1 = make_event(
            hostname="host_equal", process_name="proc1", timestamp=timestamp, suffix="e1"
        )
        event2 = make_event(
            hostname="host_equal", process_name="proc2", timestamp=timestamp, suffix="e2"
        )
        result1 = detector.detect(event1)
        result2 = detector.detect(event2)
        assert result1.matched is True
        assert result2.matched is True
        profile = service.get_profile("hostname", "host_equal", "process_name")
        assert profile.first_seen == timestamp
        assert profile.last_seen == timestamp
        assert profile.observation_count >= 2

    def test_out_of_order_timestamps(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_ooo", behavior_service=service)
        event_late = make_event(
            hostname="host_ooo",
            process_name="proc2",
            timestamp=datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC),
            suffix="o1",
        )
        event_early = make_event(
            hostname="host_ooo",
            process_name="proc1",
            timestamp=datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC),
            suffix="o2",
        )
        result_late = detector.detect(event_late)
        result_early = detector.detect(event_early)
        assert result_late.matched is True
        assert result_early.matched is True
        profile = service.get_profile("hostname", "host_ooo", "process_name")
        assert profile.first_seen == datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        assert profile.last_seen == datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC)

    def test_very_old_events(self):
        service = EntityBehaviorService(stale_timeout=timedelta(hours=1))
        detector = make_detector(name="test_old", behavior_service=service)
        old_time = datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)
        event = make_event(
            hostname="host_old", process_name="proc1", timestamp=old_time, suffix="old"
        )
        result = detector.detect(event)
        assert result.matched is True
        profile = service.get_profile("hostname", "host_old", "process_name")
        assert profile.first_seen == old_time
        assert (
            service.get_profile_maturity("hostname", "host_old", "process_name")
            == ProfileMaturity.STALE
        )

    def test_future_dated_events(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_future", behavior_service=service)
        future_time = datetime(2030, 1, 1, 0, 0, 0, tzinfo=UTC)
        event = make_event(
            hostname="host_future", process_name="proc1", timestamp=future_time, suffix="fut"
        )
        result = detector.detect(event)
        assert result.matched is True
        profile = service.get_profile("hostname", "host_future", "process_name")
        assert profile.first_seen == future_time
        assert profile.last_seen == future_time

    def test_stale_profile_followed_by_new_observation(self):
        service = EntityBehaviorService(stale_timeout=timedelta(hours=1))
        detector = make_detector(name="test_stale", behavior_service=service)
        old_time = datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)
        event1 = make_event(
            hostname="host_stale", process_name="proc1", timestamp=old_time, suffix="s1"
        )
        detector.detect(event1)
        assert (
            service.get_profile_maturity("hostname", "host_stale", "process_name")
            == ProfileMaturity.STALE
        )
        new_time = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        event2 = make_event(
            hostname="host_stale", process_name="proc2", timestamp=new_time, suffix="s2"
        )
        result2 = detector.detect(event2)
        assert result2.matched is True
        profile = service.get_profile("hostname", "host_stale", "process_name")
        assert profile.last_seen == new_time
        assert profile.observation_count >= 2

    def test_first_seen_last_seen_consistency(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_consist", behavior_service=service)
        timestamps = [
            datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC),
            datetime(2026, 9, 3, 9, 0, 0, tzinfo=UTC),
            datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC),
        ]
        for i, ts in enumerate(timestamps):
            detector.detect(
                make_event(
                    hostname="host_consist", process_name=f"proc{i}", timestamp=ts, suffix=f"c{i}"
                )
            )
        profile = service.get_profile("hostname", "host_consist", "process_name")
        assert profile.first_seen == datetime(2026, 9, 3, 9, 0, 0, tzinfo=UTC)
        assert profile.last_seen == datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC)
        assert profile.observation_count >= 3

    def test_maturity_state_consistency(self):
        service = EntityBehaviorService(stale_timeout=timedelta(hours=24))
        detector = make_detector(name="test_maturity", behavior_service=service)
        detector.detect(make_event(hostname="host_maturity", process_name="proc1", suffix="mat"))
        profile = service.get_profile("hostname", "host_maturity", "process_name")
        assert profile.maturity == ProfileMaturity.WARMING


class TestReplayLiveEquivalence:
    def test_live_and_replay_same_event_sequence(self):
        events = [
            make_event(hostname="host1", process_name="proc1", suffix="r1"),
            make_event(hostname="host1", process_name="proc2", suffix="r2"),
            make_event(hostname="host2", process_name="proc1", suffix="r3"),
            make_event(hostname="host1", process_name="proc1", suffix="r4"),
        ]
        live_service = EntityBehaviorService()
        live_detector = make_detector(name="test_live", behavior_service=live_service)
        live_results = [live_detector.detect(e) for e in events]
        replay_service = EntityBehaviorService()
        replay_detector = make_detector(name="test_replay", behavior_service=replay_service)
        replay_results = [replay_detector.detect(e) for e in events]
        assert [r.matched for r in live_results] == [r.matched for r in replay_results]

    def test_no_live_state_leaks_to_replay(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_leak", behavior_service=service)
        event = make_event(hostname="host1", process_name="proc1", suffix="leak")
        detector.detect(event)
        replay_service = EntityBehaviorService()
        replay_detector = make_detector(name="test_replay_leak", behavior_service=replay_service)
        replay_result = replay_detector.detect(event)
        assert replay_result.matched is True

    def test_event_timestamps_drive_behavioral_ordering(self):
        timestamp1 = datetime(2026, 9, 3, 10, 0, 0, tzinfo=UTC)
        timestamp2 = datetime(2026, 9, 3, 11, 0, 0, tzinfo=UTC)
        events = [
            make_event(hostname="host1", process_name="proc1", timestamp=timestamp2, suffix="ord1"),
            make_event(hostname="host1", process_name="proc1", timestamp=timestamp1, suffix="ord2"),
        ]
        service = EntityBehaviorService()
        detector = make_detector(name="test_order", behavior_service=service)
        results = [detector.detect(e) for e in events]
        assert results[0].matched is True
        assert results[1].matched is False
        profile = service.get_profile("hostname", "host1", "process_name")
        assert profile.first_seen == timestamp1
        assert profile.last_seen == timestamp2


class TestConfigurationValidation:
    def test_valid_entity_types(self, tmp_path):
        valid_types = ["hostname", "src_ip", "dst_ip", "username", "process_name", "pid"]
        for entity_type in valid_types:
            rule_data = {
                "rule_id": f"test_{entity_type}",
                "detector": "EntityBehaviorDetector",
                "enabled": True,
                "version": 1,
                "confidence_threshold": 1.0,
                "parameters": {
                    "entity": {"type": entity_type},
                    "dimension": {"field": "process_name"},
                },
            }
            (tmp_path / f"test_{entity_type}.yaml").write_text(yaml.dump(rule_data))
        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()
        for rule in rules:
            detector = loader.create_detector(rule)
            assert detector.entity_type == rule.parameters["entity"]["type"]

    def test_invalid_entity_type_rejected(self, tmp_path):
        rule_data = {
            "rule_id": "invalid_entity",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {
                "entity": {"type": "invalid_type"},
                "dimension": {"field": "process_name"},
            },
        }
        (tmp_path / "invalid.yaml").write_text(yaml.dump(rule_data))
        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()
        with pytest.raises(DetectionError, match=r"Invalid entity\.type"):
            loader.create_detector(rules[0])

    def test_invalid_dimension_field_rejected(self, tmp_path):
        rule_data = {
            "rule_id": "invalid_dim",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {"entity": {"type": "hostname"}, "dimension": {"field": "invalid_field"}},
        }
        (tmp_path / "invalid.yaml").write_text(yaml.dump(rule_data))
        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()
        with pytest.raises(DetectionError, match=r"Invalid dimension\.field"):
            loader.create_detector(rules[0])

    def test_missing_entity_type_rejected(self, tmp_path):
        rule_data = {
            "rule_id": "missing_entity",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {"entity": {}, "dimension": {"field": "process_name"}},
        }
        (tmp_path / "invalid.yaml").write_text(yaml.dump(rule_data))
        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()
        with pytest.raises(DetectionError, match=r"entity\.type must be a non-empty string"):
            loader.create_detector(rules[0])

    def test_missing_dimension_field_rejected(self, tmp_path):
        rule_data = {
            "rule_id": "missing_dim",
            "detector": "EntityBehaviorDetector",
            "enabled": True,
            "version": 1,
            "confidence_threshold": 1.0,
            "parameters": {"entity": {"type": "hostname"}, "dimension": {}},
        }
        (tmp_path / "invalid.yaml").write_text(yaml.dump(rule_data))
        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()
        with pytest.raises(DetectionError, match=r"dimension\.field must be a non-empty string"):
            loader.create_detector(rules[0])

    def test_zero_max_profiles_rejected(self):
        with pytest.raises(ValueError, match="max_profiles must be positive"):
            EntityBehaviorService(max_profiles=0)

    def test_negative_max_profiles_rejected(self):
        with pytest.raises(ValueError, match="max_profiles must be positive"):
            EntityBehaviorService(max_profiles=-1)

    def test_zero_max_values_per_profile_rejected(self):
        with pytest.raises(ValueError, match="max_values_per_profile must be positive"):
            EntityBehaviorService(max_values_per_profile=0)

    def test_zero_max_value_length_rejected(self):
        with pytest.raises(ValueError, match="max_value_length must be positive"):
            EntityBehaviorService(max_value_length=0)

    def test_invalid_confidence_rejected(self):
        with pytest.raises(ValueError, match="Confidence must be between"):
            EntityBehaviorDetector(
                name="test", entity_type="hostname", dimension_field="process_name", confidence=1.5
            )
        with pytest.raises(ValueError, match="Confidence must be between"):
            EntityBehaviorDetector(
                name="test", entity_type="hostname", dimension_field="process_name", confidence=-0.1
            )

    def test_all_valid_entity_dimension_combinations(self, tmp_path):
        valid_combinations = [
            ("hostname", "process_name"),
            ("hostname", "dst_ip"),
            ("hostname", "dst_port"),
            ("hostname", "protocol"),
            ("hostname", "username"),
            ("hostname", "event_type"),
            ("hostname", "source_type"),
            ("hostname", "command_line"),
            ("hostname", "hostname"),
            ("hostname", "src_ip"),
            ("src_ip", "process_name"),
            ("src_ip", "dst_ip"),
            ("src_ip", "dst_port"),
            ("src_ip", "protocol"),
            ("src_ip", "username"),
            ("src_ip", "event_type"),
            ("src_ip", "source_type"),
            ("src_ip", "command_line"),
            ("src_ip", "hostname"),
            ("src_ip", "src_ip"),
            ("dst_ip", "process_name"),
            ("dst_ip", "dst_ip"),
            ("dst_ip", "dst_port"),
            ("dst_ip", "protocol"),
            ("dst_ip", "username"),
            ("dst_ip", "event_type"),
            ("dst_ip", "source_type"),
            ("dst_ip", "command_line"),
            ("dst_ip", "hostname"),
            ("dst_ip", "src_ip"),
            ("username", "process_name"),
            ("username", "dst_ip"),
            ("username", "dst_port"),
            ("username", "protocol"),
            ("username", "username"),
            ("username", "event_type"),
            ("username", "source_type"),
            ("username", "command_line"),
            ("username", "hostname"),
            ("username", "src_ip"),
            ("process_name", "process_name"),
            ("process_name", "dst_ip"),
            ("process_name", "dst_port"),
            ("process_name", "protocol"),
            ("process_name", "username"),
            ("process_name", "event_type"),
            ("process_name", "source_type"),
            ("process_name", "command_line"),
            ("process_name", "hostname"),
            ("process_name", "src_ip"),
            ("pid", "process_name"),
            ("pid", "dst_ip"),
            ("pid", "dst_port"),
            ("pid", "protocol"),
            ("pid", "username"),
            ("pid", "event_type"),
            ("pid", "source_type"),
            ("pid", "command_line"),
            ("pid", "hostname"),
            ("pid", "src_ip"),
        ]
        for entity_type, dimension_field in valid_combinations:
            rule_data = {
                "rule_id": f"test_{entity_type}_{dimension_field}",
                "detector": "EntityBehaviorDetector",
                "enabled": True,
                "version": 1,
                "confidence_threshold": 1.0,
                "parameters": {
                    "entity": {"type": entity_type},
                    "dimension": {"field": dimension_field},
                },
            }
            (tmp_path / f"test_{entity_type}_{dimension_field}.yaml").write_text(
                yaml.dump(rule_data)
            )
        loader = RuleLoader(rules_dir=tmp_path)
        rules = loader.load_rules()
        for rule in rules:
            detector = loader.create_detector(rule)
            assert detector.entity_type == rule.parameters["entity"]["type"]
            assert detector.dimension_field == rule.parameters["dimension"]["field"]


class TestSecurityAudit:
    def test_entity_explosion_mitigated(self):
        service = EntityBehaviorService(max_profiles=100)
        for i in range(1000):
            service.record_observation(
                entity_type="hostname",
                entity_id=f"host_{i}",
                dimension="process_name",
                dimension_value="proc1",
                timestamp=datetime.now(UTC),
            )
        assert service.profile_count <= 100

    def test_value_explosion_mitigated(self):
        service = EntityBehaviorService(max_values_per_profile=100)
        for i in range(1000):
            service.record_observation(
                entity_type="hostname",
                entity_id="host1",
                dimension="dst_ip",
                dimension_value=f"10.0.0.{i}",
                timestamp=datetime.now(UTC),
            )
        profile = service.get_profile("hostname", "host1", "dst_ip")
        assert profile is not None
        assert profile.observation_count == 1000

    def test_oversized_input_handled(self):
        service = EntityBehaviorService(max_value_length=10)
        oversized = "x" * 1000
        service.record_observation(
            entity_type="hostname",
            entity_id="host_oversized",
            dimension="process_name",
            dimension_value=oversized,
            timestamp=datetime.now(UTC),
        )
        profile = service.get_profile("hostname", "host_oversized", "process_name")
        assert profile is not None
        assert profile.observation_count >= 1
        service.record_observation(
            entity_type="hostname",
            entity_id="host_oversized",
            dimension="process_name",
            dimension_value=oversized,
            timestamp=datetime.now(UTC),
        )
        assert profile.observation_count >= 1

    def test_baseline_poisoning_not_claimed(self):
        pass

    def test_profile_churn_acceptable(self):
        service = EntityBehaviorService(max_profiles=2)
        detector = make_detector(name="test_churn", behavior_service=service)
        detector.detect(make_event(hostname="host_churn0", process_name="proc1", suffix="ch1"))
        detector.detect(make_event(hostname="host_churn1", process_name="proc1", suffix="ch2"))
        detector.detect(make_event(hostname="host_churn2", process_name="proc1", suffix="ch3"))
        assert service.get_profile("hostname", "host_churn0", "process_name") is None
        result = detector.detect(
            make_event(hostname="host_churn0", process_name="proc2", suffix="ch4")
        )
        assert result.matched is True

    def test_malformed_attacker_controlled_strings(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_malformed", behavior_service=service)
        malformed_values = [
            "",
            "\x00",
            "\n\r\t",
            "a" * 10000,
            "🔥🚀💀",
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
        ]
        for value in malformed_values:
            result = detector.detect(
                make_event(hostname="host_mal", process_name=value, suffix=f"mal_{len(value)}")
            )
            assert isinstance(result, DetectionResult)

    def test_excessive_evidence_metadata_bounded(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_bounded", behavior_service=service)
        result = detector.detect(
            make_event(hostname="host_bound", process_name="proc1", suffix="bound")
        )
        assert result.matched is True
        assert len(result.evidence) < 20
        assert len(result.metadata) < 20

    def test_no_raw_event_retention(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_no_raw", behavior_service=service)
        result = detector.detect(
            make_event(hostname="host_noraw", process_name="proc1", suffix="sensitive_data_here")
        )
        assert result.matched is True
        evidence_text = str(result.evidence)
        metadata_text = str(result.metadata)
        assert "sensitive_data_here" not in evidence_text
        assert "sensitive_data_here" not in metadata_text


class TestEdgeCases:
    def test_missing_entity_field_no_profile(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_missing_entity", behavior_service=service)
        result = detector.detect(make_event(hostname=None, process_name="proc1", suffix="me"))
        assert result.matched is False
        assert service.profile_count == 0

    def test_missing_dimension_field_no_detection(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_missing_dim", behavior_service=service)
        result = detector.detect(make_event(hostname="host1", process_name=None, suffix="md"))
        assert result.matched is False

    def test_disabled_detector_no_detection(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_disabled", behavior_service=service, enabled=False)
        result = detector.detect(make_event(hostname="host1", process_name="proc1", suffix="dis"))
        assert result.matched is False

    def test_detector_enable_disable(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_enable", behavior_service=service)
        event = make_event(hostname="host_enable", process_name="proc1", suffix="en")
        assert detector.is_enabled() is True
        result1 = detector.detect(event)
        assert result1.matched is True
        detector.disable()
        assert detector.is_enabled() is False
        result2 = detector.detect(event)
        assert result2.matched is False
        detector.enable()
        assert detector.is_enabled() is True
        result3 = detector.detect(event)
        assert result3.matched is False

    def test_confidence_bounds(self):
        detector_low = make_detector(name="test_low", confidence=0.0)
        assert detector_low._confidence == 0.0
        detector_high = make_detector(name="test_high", confidence=1.0)
        assert detector_high._confidence == 1.0
        with pytest.raises(ValueError):
            make_detector(name="test_invalid_high", confidence=1.1)
        with pytest.raises(ValueError):
            make_detector(name="test_invalid_low", confidence=-0.1)

    def test_version_tracking(self):
        detector = EntityBehaviorDetector(
            name="test_version", entity_type="hostname", dimension_field="process_name", version=5
        )
        assert detector._version == 5

    def test_stats_tracking(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_stats", behavior_service=service)
        detector.detect(make_event(hostname="host_stats", process_name="proc1", suffix="stats"))
        stats = detector.get_stats()
        assert stats["name"] == "test_stats"
        assert stats["entity_type"] == "hostname"
        assert stats["dimension_field"] == "process_name"
        assert stats["enabled"] is True
        assert stats["detections_count"] == 1
        assert stats["profile_count"] == 1


class TestDetectionManagerIntegration:
    def test_behavior_detector_in_detection_manager(self):
        service = EntityBehaviorService()
        detector = make_detector(name="test_dm1", behavior_service=service)
        manager = DetectionManager()
        manager.register_detector(detector)
        results = manager.process_event(
            make_event(hostname="host_dm1", process_name="proc1", suffix="dm1")
        )
        assert len(results) == 1
        assert results[0].matched is True

    def test_multiple_behavior_detectors(self):
        service1 = EntityBehaviorService()
        service2 = EntityBehaviorService()
        detector1 = make_detector(
            name="rule1",
            entity_type="hostname",
            dimension_field="process_name",
            behavior_service=service1,
        )
        detector2 = make_detector(
            name="rule2", entity_type="src_ip", dimension_field="dst_ip", behavior_service=service2
        )
        manager = DetectionManager()
        manager.register_detector(detector1)
        manager.register_detector(detector2)
        results = manager.process_event(
            make_event(
                hostname="host_multi",
                src_ip="10.0.0.1",
                dst_ip="192.168.1.1",
                process_name="proc1",
                suffix="multi",
            )
        )
        assert len(results) == 2
        assert all(r.matched for r in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
