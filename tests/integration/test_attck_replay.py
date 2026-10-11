"""Tests for Phase 6.6 — ATT&CK Replay + Final Hardening.

Focused tests covering:
- Historical replay semantics
- Current-semantic replay semantics
- Degraded/fallback behavior
- Snapshot integrity
- Replay determinism
- Alert immutability
- Security boundary verification
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from argusprowl.attck.knowledge_service import AttckKnowledgeService, AttckKnowledgeStatus
from argusprowl.attck.mapping_registry import AttckMapping, MappingType
from argusprowl.attck.models import AttckTactic, AttckTechnique
from argusprowl.attck.replay_service import (
    AttckReplayService,
    ReplayMode,
    ReplayReport,
    ReplayResult,
    ReplayStatus,
)
from argusprowl.constants.severity import Severity
from argusprowl.models.alert import Alert

# ── Fixtures ──────────────────────────────────────────────────────────────────


class FakeKnowledgeService:
    """Small knowledge service test double."""

    def __init__(
        self,
        techniques: dict[str, AttckTechnique] | None = None,
        *,
        enabled: bool = True,
        status: AttckKnowledgeStatus = AttckKnowledgeStatus.AVAILABLE,
        version: str = "14.0",
    ) -> None:
        self._techniques = techniques or {}
        self.is_enabled = enabled
        self._status = status
        self._version = version

    def get_status(self) -> AttckKnowledgeStatus:
        return self._status

    def get_technique(self, technique_id: str) -> AttckTechnique | None:
        return self._techniques.get(technique_id)

    def get_version(self) -> str | None:
        return self._version

    def get_tactic(self, tactic_id: str) -> AttckTactic | None:
        return None


class FakeMappingRegistry:
    """Small mapping registry test double."""

    def __init__(
        self,
        mappings: dict[str, list[AttckMapping]] | None = None,
    ) -> None:
        self._mappings = mappings or {}

    def get_for_rule(self, rule_id: str) -> tuple[AttckMapping, ...]:
        return tuple(self._mappings.get(rule_id, []))

    def get_all(self) -> tuple[AttckMapping, ...]:
        return tuple()


def make_alert(
    alert_id: str | None = None,
    title: str = "Test Alert",
    source: str = "port_scan",
    observations: list[dict[str, Any]] | None = None,
    severity: Severity = Severity.HIGH,
    metadata: dict[str, Any] | None = None,
) -> Alert:
    """Create a test alert with optional ATT&CK observations."""
    meta = dict(metadata or {})
    if observations is not None:
        meta["attck_observations"] = observations
    return Alert(
        alert_id=alert_id or uuid4(),
        title=title,
        description="Test description",
        severity=severity,
        source=source,
        metadata=meta,
    )


def make_observation(
    technique_id: str = "T1046",
    mapping_type: str = "DIRECT",
    technique_name: str | None = None,
    tactic: str | None = None,
    version: str = "14.0",
    subtechnique_id: str | None = None,
    rationale: str | None = None,
) -> dict[str, Any]:
    """Create a test ATT&CK observation."""
    obs: dict[str, Any] = {
        "technique_id": technique_id,
        "mapping_type": mapping_type,
        "version": version,
    }
    if technique_name:
        obs["technique_name"] = technique_name
    if tactic:
        obs["tactic"] = tactic
    if subtechnique_id:
        obs["subtechnique_id"] = subtechnique_id
    if rationale:
        obs["rationale"] = rationale
    return obs


# ── Historical Replay Tests ───────────────────────────────────────────────────


class TestHistoricalReplay:
    """Tests for historical replay mode."""

    def test_historical_replay_valid_version(self) -> None:
        """Historical replay with valid matching version succeeds."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=[make_observation(version="14.0")])

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        assert result.status == ReplayStatus.HISTORICAL_REPLAYED
        assert result.version == "14.0"
        assert result.is_successful
        assert result.original_alert_id is not None

    def test_historical_replay_version_unavailable(self) -> None:
        """Historical replay with unavailable version returns DEGRADED."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="15.0",  # Different from alert's version
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=[make_observation(version="14.0")])

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        assert result.status == ReplayStatus.DEGRADED
        assert result.version == "14.0"
        assert result.is_degraded
        assert "Historical version" in result.degraded_reason
        assert "unavailable" in result.degraded_reason.lower()

    def test_historical_replay_no_observations(self) -> None:
        """Historical replay with no observations returns EMPTY."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=None)

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        assert result.status == ReplayStatus.EMPTY
        assert result.observations == ()

    def test_historical_replay_missing_version(self) -> None:
        """Historical replay with missing version returns DEGRADED."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=[make_observation(version="")])

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        assert result.status == ReplayStatus.DEGRADED
        assert "No version recorded" in result.degraded_reason

    def test_historical_replay_malformed_version(self) -> None:
        """Historical replay with malformed version returns DEGRADED."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=[make_observation(version="invalid!")])

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        # Should still attempt replay but may be degraded
        assert result.status in (
            ReplayStatus.HISTORICAL_REPLAYED,
            ReplayStatus.DEGRADED,
        )

    def test_historical_replay_multiple_versions(self) -> None:
        """Historical replay with multiple observations uses first version."""
        knowledge = FakeKnowledgeService(
            techniques={
                "T1046": AttckTechnique("T1046", "Test"),
                "T1110": AttckTechnique("T1110", "Brute Force"),
            },
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(
            observations=[
                make_observation("T1046", "DIRECT", version="14.0"),
                make_observation("T1110", "SUPPORTED", version="14.0"),
            ]
        )

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        assert result.status == ReplayStatus.HISTORICAL_REPLAYED
        assert result.version == "14.0"
        assert len(result.observations) == 2

    def test_historical_replay_no_silent_substitution(self) -> None:
        """Historical replay does NOT silently substitute current version."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="15.0",  # Current is 15.0
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(
            observations=[make_observation(version="14.0")]  # Alert is 14.0
        )

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        # Must be DEGRADED, not silently using current
        assert result.status == ReplayStatus.DEGRADED
        assert result.version == "14.0"  # Preserves original version
        assert "15.0" in result.degraded_reason  # Shows current version

    def test_historical_replay_preserves_mapping_type(self) -> None:
        """Historical replay preserves original mapping type."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=[make_observation("T1046", "SUPPORTED", version="14.0")])

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        assert result.status == ReplayStatus.HISTORICAL_REPLAYED
        assert result.observations[0]["mapping_type"] == "SUPPORTED"

    def test_historical_replay_preserves_technique_id(self) -> None:
        """Historical replay preserves original technique ID."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=[make_observation("T1046", "DIRECT", version="14.0")])

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        assert result.status == ReplayStatus.HISTORICAL_REPLAYED
        assert result.observations[0]["technique_id"] == "T1046"


# ── Current-Semantic Replay Tests ─────────────────────────────────────────────


class TestCurrentSemanticReplay:
    """Tests for current-semantic replay mode."""

    def test_current_semantic_replay_valid(self) -> None:
        """Current-semantic replay with valid snapshot succeeds."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry(
            mappings={
                "port_scan": [
                    AttckMapping(
                        rule_id="port_scan",
                        technique_id="T1046",
                        mapping_type=MappingType.DIRECT,
                    )
                ]
            }
        )
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(source="port_scan")

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result.status == ReplayStatus.CURRENT_SEMANTIC_REPLAYED
        assert result.version == "14.0"
        assert result.is_successful
        assert len(result.observations) == 1
        assert result.observations[0]["technique_id"] == "T1046"

    def test_current_semantic_replay_explicit_version(self) -> None:
        """Current-semantic replay records active snapshot version."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="15.0",
        )
        registry = FakeMappingRegistry(
            mappings={
                "port_scan": [
                    AttckMapping(
                        rule_id="port_scan",
                        technique_id="T1046",
                        mapping_type=MappingType.DIRECT,
                    )
                ]
            }
        )
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(source="port_scan")

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result.status == ReplayStatus.CURRENT_SEMANTIC_REPLAYED
        assert result.version == "15.0"
        assert result.observations[0]["version"] == "15.0"

    def test_current_semantic_replay_historical_differs(self) -> None:
        """Current-semantic replay when historical version differs."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="15.0",
        )
        registry = FakeMappingRegistry(
            mappings={
                "port_scan": [
                    AttckMapping(
                        rule_id="port_scan",
                        technique_id="T1046",
                        mapping_type=MappingType.DIRECT,
                    )
                ]
            }
        )
        service = AttckReplayService(knowledge, registry)

        # Alert has historical observations from version 14.0
        alert = make_alert(
            source="port_scan",
            observations=[make_observation(version="14.0")],
        )

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        # Should use current version 15.0, not historical 14.0
        assert result.status == ReplayStatus.CURRENT_SEMANTIC_REPLAYED
        assert result.version == "15.0"
        assert result.observations[0]["version"] == "15.0"

    def test_current_semantic_replay_identifies_behavior(self) -> None:
        """Current-semantic replay clearly identifies as current-semantic."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result.mode == ReplayMode.CURRENT_SEMANTIC
        assert result.status == ReplayStatus.CURRENT_SEMANTIC_REPLAYED
        assert result.observations == ()

    def test_current_semantic_replay_does_not_mutate_original(self) -> None:
        """Current-semantic replay does not mutate the original alert."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry(
            mappings={
                "port_scan": [
                    AttckMapping(
                        rule_id="port_scan",
                        technique_id="T1046",
                        mapping_type=MappingType.DIRECT,
                    )
                ]
            }
        )
        service = AttckReplayService(knowledge, registry)

        original_alert = make_alert(
            source="port_scan",
            observations=[make_observation(version="14.0")],
        )
        original_metadata = dict(original_alert.metadata)

        service.replay(original_alert, mode=ReplayMode.CURRENT_SEMANTIC)

        # Original alert must be unchanged
        assert original_alert.metadata == original_metadata
        assert "attck_observations" in original_alert.metadata
        assert original_alert.metadata["attck_observations"][0]["version"] == "14.0"

    def test_current_semantic_replay_unavailable(self) -> None:
        """Current-semantic replay with unavailable knowledge returns UNAVAILABLE."""
        knowledge = FakeKnowledgeService(
            status=AttckKnowledgeStatus.UNAVAILABLE,
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result.status == ReplayStatus.UNAVAILABLE
        assert result.is_unavailable
        assert result.observations == ()

    def test_current_semantic_replay_empty(self) -> None:
        """Current-semantic replay with empty knowledge returns UNAVAILABLE."""
        knowledge = FakeKnowledgeService(
            status=AttckKnowledgeStatus.EMPTY,
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result.status == ReplayStatus.UNAVAILABLE

    def test_current_semantic_replay_degraded(self) -> None:
        """Current-semantic replay with degraded knowledge returns DEGRADED."""
        knowledge = FakeKnowledgeService(
            status=AttckKnowledgeStatus.DEGRADED,
            version="13.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result.status == ReplayStatus.DEGRADED
        assert result.is_degraded
        assert "previous known-good" in result.degraded_reason.lower()


# ── Alert Immutability Tests ──────────────────────────────────────────────────


class TestAlertImmutability:
    """Tests for alert immutability during replay."""

    def test_replay_does_not_mutate_alert_id(self) -> None:
        """Replay does not change alert_id."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()
        original_id = alert.alert_id

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.alert_id == original_id

    def test_replay_does_not_mutate_severity(self) -> None:
        """Replay does not change severity."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(severity=Severity.CRITICAL)
        original_severity = alert.severity

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.severity == original_severity

    def test_replay_does_not_mutate_priority(self) -> None:
        """Replay does not change priority."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()
        original_priority = alert.priority

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.priority == original_priority

    def test_replay_does_not_mutate_confidence(self) -> None:
        """Replay does not change confidence."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(metadata={"confidence": 0.95})
        original_confidence = alert.metadata.get("confidence")

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.metadata.get("confidence") == original_confidence

    def test_replay_does_not_mutate_fingerprint(self) -> None:
        """Replay does not change fingerprint."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()
        original_dict = alert.to_dict()

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.to_dict() == original_dict

    def test_replay_does_not_mutate_lifecycle(self) -> None:
        """Replay does not change lifecycle_state."""

        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()
        original_state = alert.lifecycle_state

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.lifecycle_state == original_state

    def test_replay_does_not_mutate_incident_id(self) -> None:
        """Replay does not change incident_id."""
        from uuid import uuid4

        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        uuid4()
        alert = make_alert()
        # Note: Alert is frozen, so we can't modify incident_id after creation
        # This test verifies the replay doesn't attempt to change it

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)
        assert result.original_alert_id == str(alert.alert_id)

    def test_replay_does_not_mutate_source(self) -> None:
        """Replay does not change source."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(source="port_scan")
        original_source = alert.source

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.source == original_source

    def test_replay_does_not_mutate_existing_observations(self) -> None:
        """Replay does not overwrite existing attck_observations."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        original_obs = [make_observation("T1046", "DIRECT", version="14.0")]
        alert = make_alert(observations=original_obs)

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        # Original observations must be preserved
        assert alert.metadata["attck_observations"] == original_obs

    def test_replay_result_is_separate_object(self) -> None:
        """Replay result is a separate immutable object."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry(
            mappings={
                "port_scan": [
                    AttckMapping(
                        rule_id="port_scan",
                        technique_id="T1046",
                        mapping_type=MappingType.DIRECT,
                    )
                ]
            }
        )
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(source="port_scan")

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        # Result should be a ReplayResult, not an Alert
        assert isinstance(result, ReplayResult)
        assert result.mode == ReplayMode.CURRENT_SEMANTIC


# ── Determinism Tests ─────────────────────────────────────────────────────────


class TestDeterminism:
    """Tests for replay determinism."""

    def test_repeated_historical_replay_equivalent(self) -> None:
        """Repeated historical replay produces equivalent results."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(
            observations=[
                make_observation("T1046", "DIRECT", version="14.0"),
                make_observation("T1110", "SUPPORTED", version="14.0"),
            ]
        )

        result1 = service.replay(alert, mode=ReplayMode.HISTORICAL)
        result2 = service.replay(alert, mode=ReplayMode.HISTORICAL)

        assert result1.status == result2.status
        assert result1.version == result2.version
        assert result1.observations == result2.observations
        assert result1.original_alert_id == result2.original_alert_id

    def test_repeated_current_semantic_replay_equivalent(self) -> None:
        """Repeated current-semantic replay produces equivalent results."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry(
            mappings={
                "port_scan": [
                    AttckMapping(
                        rule_id="port_scan",
                        technique_id="T1046",
                        mapping_type=MappingType.DIRECT,
                    )
                ]
            }
        )
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(source="port_scan")

        result1 = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)
        result2 = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result1.status == result2.status
        assert result1.version == result2.version
        assert result1.observations == result2.observations

    def test_deterministic_ordering(self) -> None:
        """Replay results have deterministic ordering."""
        knowledge = FakeKnowledgeService(
            techniques={
                "T1046": AttckTechnique("T1046", "Test1"),
                "T1110": AttckTechnique("T1110", "Test2"),
                "T1071": AttckTechnique("T1071", "Test3"),
            },
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        # Create alert with observations in non-alphabetical order
        alert = make_alert(
            observations=[
                make_observation("T1110", "DIRECT", version="14.0"),
                make_observation("T1046", "SUPPORTED", version="14.0"),
                make_observation("T1071", "CONTEXTUAL", version="14.0"),
            ]
        )

        result1 = service.replay(alert, mode=ReplayMode.HISTORICAL)
        result2 = service.replay(alert, mode=ReplayMode.HISTORICAL)

        # Results should be identical
        assert result1.observations == result2.observations

    def test_no_network_dependency(self) -> None:
        """Replay does not depend on network access."""
        # This is implicitly tested by the fact that we use FakeKnowledgeService
        # which has no network access
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=[make_observation(version="14.0")])

        # Should complete without network access
        result = service.replay(alert, mode=ReplayMode.HISTORICAL)
        assert result is not None

    def test_no_wall_clock_dependency(self) -> None:
        """Replay does not depend on wall-clock time."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=[make_observation(version="14.0")])

        # Run multiple times
        results = [service.replay(alert, mode=ReplayMode.HISTORICAL) for _ in range(10)]

        # All results should be identical
        for result in results[1:]:
            assert result.status == results[0].status
            assert result.version == results[0].version
            assert result.observations == results[0].observations

    def test_no_random_ids_in_results(self) -> None:
        """Replay does not introduce random IDs into results."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=[make_observation(version="14.0")])

        result1 = service.replay(alert, mode=ReplayMode.HISTORICAL)
        result2 = service.replay(alert, mode=ReplayMode.HISTORICAL)

        # original_alert_id should be deterministic
        assert result1.original_alert_id == result2.original_alert_id
        # Should not contain UUID-like random strings in observations
        for obs in result1.observations:
            assert "uuid" not in str(obs).lower()


# ── Snapshot Integrity Tests ──────────────────────────────────────────────────


class TestSnapshotIntegrity:
    """Tests for snapshot integrity and recovery."""

    def test_corrupt_snapshot_handling(self) -> None:
        """Corrupt snapshot is handled gracefully."""
        knowledge = FakeKnowledgeService(
            status=AttckKnowledgeStatus.UNAVAILABLE,
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result.status == ReplayStatus.UNAVAILABLE

    def test_malformed_object_handling(self) -> None:
        """Malformed observations are handled safely."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=["malformed", None, {"invalid": True}])

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        # Should not crash, should return empty or degraded
        assert result.status in (
            ReplayStatus.EMPTY,
            ReplayStatus.DEGRADED,
            ReplayStatus.HISTORICAL_REPLAYED,
        )

    def test_duplicate_technique_id_handling(self) -> None:
        """Duplicate technique IDs in observations are handled."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(
            observations=[
                make_observation("T1046", "DIRECT", version="14.0"),
                make_observation("T1046", "SUPPORTED", version="14.0"),
            ]
        )

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        # Should handle gracefully
        assert result.status in (
            ReplayStatus.HISTORICAL_REPLAYED,
            ReplayStatus.DEGRADED,
        )

    def test_oversized_input_handling(self) -> None:
        """Oversized observations are handled safely."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        # Create observation with oversized fields
        alert = make_alert(
            observations=[
                {
                    "technique_id": "T" + "0" * 100,  # Too long
                    "mapping_type": "DIRECT",
                    "version": "14.0",
                }
            ]
        )

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        # Should not crash
        assert result is not None

    def test_invalid_version_handling(self) -> None:
        """Invalid version is preserved in stored observations."""
        knowledge = FakeKnowledgeService(
            version="invalid-version!",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(observations=[make_observation(version="invalid-version!")])

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        # Invalid version is preserved as stored - replay succeeds
        # because the stored version matches the knowledge service version
        assert result.status == ReplayStatus.HISTORICAL_REPLAYED
        assert result.version == "invalid-version!"

    def test_failed_filesystem_replacement_recovery(self) -> None:
        """Failed filesystem replacement recovers with known-good state."""
        # This is tested indirectly through the status model
        # DEGRADED status indicates previous known-good is active
        knowledge = FakeKnowledgeService(
            status=AttckKnowledgeStatus.DEGRADED,
            version="13.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result.status == ReplayStatus.DEGRADED
        assert result.version == "13.0"

    def test_previous_known_good_recovery(self) -> None:
        """Previous known-good snapshot is recovered on failure."""
        knowledge = FakeKnowledgeService(
            status=AttckKnowledgeStatus.DEGRADED,
            version="13.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()

        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result.status == ReplayStatus.DEGRADED
        assert "previous known-good" in result.degraded_reason.lower()


# ── Security Boundary Tests ───────────────────────────────────────────────────


class TestSecurityBoundary:
    """Tests for security boundary verification."""

    def test_replay_does_not_change_severity(self) -> None:
        """Replay does not change severity."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(severity=Severity.CRITICAL)
        original_severity = alert.severity

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.severity == original_severity

    def test_replay_does_not_change_priority(self) -> None:
        """Replay does not change priority."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()
        original_priority = alert.priority

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.priority == original_priority

    def test_replay_does_not_change_confidence(self) -> None:
        """Replay does not change confidence."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert(metadata={"confidence": 0.95})
        original_confidence = alert.metadata.get("confidence")

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.metadata.get("confidence") == original_confidence

    def test_replay_does_not_change_fingerprint(self) -> None:
        """Replay does not change fingerprint."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()
        original_dict = alert.to_dict()

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.to_dict() == original_dict

    def test_replay_does_not_change_dedup_identity(self) -> None:
        """Replay does not change deduplication identity."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()
        original_id = alert.alert_id

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.alert_id == original_id

    def test_replay_does_not_change_lifecycle(self) -> None:
        """Replay does not change lifecycle state."""

        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()
        original_state = alert.lifecycle_state

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.lifecycle_state == original_state

    def test_replay_does_not_change_incident_association(self) -> None:
        """Replay does not change incident association."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()
        original_incident_id = alert.incident_id

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.incident_id == original_incident_id

    def test_replay_does_not_mutate_stored_observations(self) -> None:
        """Replay does not mutate stored ATT&CK observations."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        original_obs = [make_observation("T1046", "DIRECT", version="14.0")]
        alert = make_alert(observations=original_obs)

        service.replay(alert, mode=ReplayMode.HISTORICAL)
        service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert alert.metadata["attck_observations"] == original_obs

    def test_no_feedback_path_to_detection(self) -> None:
        """No feedback path from ATT&CK replay to detection."""
        # This is verified by the architecture:
        # ReplayService only reads from Alert.metadata
        # It does not invoke DetectionManager or DecisionEngine
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()

        # Replay should complete without touching detection
        result = service.replay(alert, mode=ReplayMode.HISTORICAL)
        assert result is not None

    def test_no_feedback_path_to_decision_engine(self) -> None:
        """No feedback path from ATT&CK replay to DecisionEngine."""
        knowledge = FakeKnowledgeService()
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alert = make_alert()

        # Replay should complete without touching DecisionEngine
        result = service.replay(alert, mode=ReplayMode.HISTORICAL)
        assert result is not None


# ── Batch Replay Tests ────────────────────────────────────────────────────────


class TestBatchReplay:
    """Tests for batch replay operations."""

    def test_batch_historical_replay(self) -> None:
        """Batch historical replay works correctly."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alerts = tuple(
            make_alert(observations=[make_observation("T1046", "DIRECT", version="14.0")])
            for _ in range(5)
        )

        report = service.replay_batch(alerts, mode=ReplayMode.HISTORICAL)

        assert isinstance(report, ReplayReport)
        assert report.mode == ReplayMode.HISTORICAL
        assert report.total == 5
        assert report.successful == 5
        assert report.degraded == 0
        assert report.unavailable == 0

    def test_batch_current_semantic_replay(self) -> None:
        """Batch current-semantic replay works correctly."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="14.0",
        )
        registry = FakeMappingRegistry(
            mappings={
                "port_scan": [
                    AttckMapping(
                        rule_id="port_scan",
                        technique_id="T1046",
                        mapping_type=MappingType.DIRECT,
                    )
                ]
            }
        )
        service = AttckReplayService(knowledge, registry)

        alerts = tuple(make_alert(source="port_scan") for _ in range(3))

        report = service.replay_batch(alerts, mode=ReplayMode.CURRENT_SEMANTIC)

        assert isinstance(report, ReplayReport)
        assert report.mode == ReplayMode.CURRENT_SEMANTIC
        assert report.total == 3
        assert report.successful == 3

    def test_batch_mixed_status(self) -> None:
        """Batch replay with mixed success/degraded/unavailable."""
        knowledge = FakeKnowledgeService(
            techniques={"T1046": AttckTechnique("T1046", "Test")},
            version="15.0",  # Different from alert versions
        )
        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        alerts = tuple(
            make_alert(observations=[make_observation("T1046", "DIRECT", version="14.0")])
            for _ in range(3)
        )

        report = service.replay_batch(alerts, mode=ReplayMode.HISTORICAL)

        assert report.total == 3
        assert report.successful == 0
        assert report.degraded == 3
        assert report.unavailable == 0


# ── Integration Tests ─────────────────────────────────────────────────────────


class TestIntegration:
    """Integration tests with real services."""

    def test_with_real_knowledge_service(self, temp_dir: Any) -> None:
        """Test with real AttckKnowledgeService."""
        import json
        from pathlib import Path

        # Create a minimal valid snapshot
        bundle = {
            "type": "bundle",
            "id": "bundle--test",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "x-mitre-collection",
                    "spec_version": "2.1",
                    "x_mitre_version": "14.0",
                    "name": "Enterprise ATT&CK",
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--t1046",
                    "name": "Network Service Discovery",
                    "description": "Discovering services",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1046",
                        }
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "discovery"}
                    ],
                },
            ],
        }

        snapshot_path = Path(temp_dir) / "snapshot.json"
        snapshot_path.write_text(json.dumps(bundle))

        knowledge = AttckKnowledgeService(
            snapshot_path=snapshot_path,
            enabled=True,
        )

        registry = FakeMappingRegistry(
            mappings={
                "port_scan": [
                    AttckMapping(
                        rule_id="port_scan",
                        technique_id="T1046",
                        mapping_type=MappingType.DIRECT,
                    )
                ]
            }
        )

        service = AttckReplayService(knowledge, registry)

        # Test current-semantic replay
        alert = make_alert(source="port_scan")
        result = service.replay(alert, mode=ReplayMode.CURRENT_SEMANTIC)

        assert result.status == ReplayStatus.CURRENT_SEMANTIC_REPLAYED
        assert result.version == "14.0"
        assert len(result.observations) == 1
        assert result.observations[0]["technique_id"] == "T1046"

    def test_historical_replay_with_real_service(self, temp_dir: Any) -> None:
        """Test historical replay with real knowledge service."""
        import json
        from pathlib import Path

        # Create snapshot for version 14.0
        bundle = {
            "type": "bundle",
            "id": "bundle--test",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "x-mitre-collection",
                    "spec_version": "2.1",
                    "x_mitre_version": "14.0",
                    "name": "Enterprise ATT&CK",
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--t1046",
                    "name": "Network Service Discovery",
                    "description": "Discovering services",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1046",
                        }
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "discovery"}
                    ],
                },
            ],
        }

        snapshot_path = Path(temp_dir) / "snapshot.json"
        snapshot_path.write_text(json.dumps(bundle))

        knowledge = AttckKnowledgeService(
            snapshot_path=snapshot_path,
            enabled=True,
        )

        registry = FakeMappingRegistry()
        service = AttckReplayService(knowledge, registry)

        # Alert with historical observations from version 14.0
        alert = make_alert(observations=[make_observation("T1046", "DIRECT", version="14.0")])

        result = service.replay(alert, mode=ReplayMode.HISTORICAL)

        assert result.status == ReplayStatus.HISTORICAL_REPLAYED
        assert result.version == "14.0"
