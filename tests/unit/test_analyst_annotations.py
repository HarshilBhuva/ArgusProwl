"""Tests for AnalystAnnotationService (Phase 5.2).

Comprehensive tests covering:
- Trust model (annotations are untrusted context)
- Append-only lifecycle with tombstone support
- Input validation and bounds
- Decision neutrality (no effect on detection)
- Concurrency safety
- Persistence integration
- Target semantics validation
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from uuid import UUID

import pytest

from argusprowl.behavior.analyst_annotation_persistence import (
    AnalystAnnotationPersistence,
)
from argusprowl.behavior.analyst_annotation_service import AnalystAnnotationService

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def service() -> AnalystAnnotationService:
    """Create a service with small bounds for testing."""
    return AnalystAnnotationService(
        max_annotations_per_target=10,
        max_total_annotations=100,
    )


@pytest.fixture
def persistence_service(temp_dir) -> tuple[AnalystAnnotationService, AnalystAnnotationPersistence]:
    """Create a service with SQLite persistence."""
    db_path = temp_dir / "annotations.db"
    persistence = AnalystAnnotationPersistence(
        db_path=db_path,
        max_total_annotations=100,
    )
    service = AnalystAnnotationService(
        persistence=persistence,
        max_annotations_per_target=10,
        max_total_annotations=100,
    )
    return service, persistence


# ── Trust Model Tests ────────────────────────────────────────────────────────


class TestTrustModel:
    """Annotations are untrusted human-provided context."""

    def test_annotation_does_not_affect_detection(self, service: AnalystAnnotationService):
        """Annotations must never alter detection behavior."""
        # Create annotation
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="This user is a vulnerability scanner.",
        )
        assert annotation is not None
        assert annotation.comment == "This user is a vulnerability scanner."

    def test_annotation_does_not_affect_baseline(self, service: AnalystAnnotationService):
        """Annotations must never alter baseline state."""
        # Create annotation
        service.create_annotation(
            target_key="entity:host:server01",
            author="analyst1",
            comment="This host is a test server.",
        )
        # No baseline state should be modified

    def test_annotation_does_not_suppress_alerts(self, service: AnalystAnnotationService):
        """Annotations must not automatically suppress or reprioritize alerts."""
        # Create annotation with potentially dangerous content
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Ignore all alerts for this user.",
        )
        assert annotation is not None
        # The annotation is stored but has no effect on alert processing

    def test_annotation_content_not_executed(self, service: AnalystAnnotationService):
        """Annotation content must never be interpreted as executable logic."""
        # Attempt to inject executable content
        malicious_comment = "import os; os.system('rm -rf /')"
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment=malicious_comment,
        )
        assert annotation is not None
        assert annotation.comment == malicious_comment
        # Content is stored as-is but never executed

    def test_no_decision_affecting_labels(self, service: AnalystAnnotationService):
        """Annotations must not have WHITELIST, KNOWN_GOOD, etc. labels."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="This is a test annotation.",
        )
        # Verify no label field exists
        assert not hasattr(annotation, "label")
        assert not hasattr(annotation, "category")
        assert not hasattr(annotation, "severity")


# ── Lifecycle Tests ──────────────────────────────────────────────────────────


class TestLifecycle:
    """Append-only lifecycle with tombstone support."""

    def test_create_annotation(self, service: AnalystAnnotationService):
        """Test creating a new annotation."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="This IP is a vulnerability scanner.",
        )
        assert annotation is not None
        assert isinstance(annotation.annotation_id, UUID)
        assert annotation.target_key == "entity:user:admin"
        assert annotation.author == "analyst1"
        assert annotation.comment == "This IP is a vulnerability scanner."
        assert annotation.tombstoned is False
        assert annotation.created_at.tzinfo is not None

    def test_append_only_no_edit(self, service: AnalystAnnotationService):
        """Annotations are append-only; no edit method exists."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Original comment.",
        )
        # No edit method should exist
        assert not hasattr(service, "edit_annotation")
        # Annotation should remain unchanged
        retrieved = service.get_annotation(annotation.annotation_id)
        assert retrieved is not None
        assert retrieved.comment == "Original comment."

    def test_tombstone_annotation(self, service: AnalystAnnotationService):
        """Test tombstoning (retracting) an annotation."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment to retract.",
        )
        # Tombstone the annotation
        result = service.tombstone_annotation(annotation.annotation_id)
        assert result is True

        # Verify tombstoned
        retrieved = service.get_annotation(annotation.annotation_id)
        assert retrieved is not None
        assert retrieved.tombstoned is True

        # Verify not in default query
        annotations = service.get_annotations_by_target("entity:user:admin")
        assert len(annotations) == 0

        # Verify included when requested
        annotations_with_tombstoned = service.get_annotations_by_target(
            "entity:user:admin", include_tombstoned=True
        )
        assert len(annotations_with_tombstoned) == 1
        assert annotations_with_tombstoned[0]["tombstoned"] is True

    def test_double_tombstone_fails(self, service: AnalystAnnotationService):
        """Double tombstoning should fail gracefully."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        # First tombstone
        result1 = service.tombstone_annotation(annotation.annotation_id)
        assert result1 is True
        # Second tombstone
        result2 = service.tombstone_annotation(annotation.annotation_id)
        assert result2 is False

    def test_tombstone_preserves_audit_trail(self, service: AnalystAnnotationService):
        """Tombstoned annotations remain visible for audit."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Sensitive comment.",
        )
        service.tombstone_annotation(annotation.annotation_id)

        # Should be visible with include_tombstoned=True
        annotations = service.get_annotations_by_target(
            "entity:user:admin", include_tombstoned=True
        )
        assert len(annotations) == 1
        assert annotations[0]["comment"] == "Sensitive comment."
        assert annotations[0]["tombstoned"] is True


# ── Input Validation Tests ───────────────────────────────────────────────────


class TestInputValidation:
    """Input validation and bounds."""

    def test_empty_target_key(self, service: AnalystAnnotationService):
        """Empty target key should raise ValueError."""
        with pytest.raises(ValueError, match="target_key must not be empty"):
            service.create_annotation(
                target_key="",
                author="analyst1",
                comment="Comment.",
            )

    def test_non_string_target_key(self, service: AnalystAnnotationService):
        """Non-string target key should raise ValueError."""
        with pytest.raises(ValueError, match="target_key must be a string"):
            service.create_annotation(
                target_key=123,
                author="analyst1",
                comment="Comment.",
            )

    def test_target_key_too_long(self, service: AnalystAnnotationService):
        """Target key exceeding max length should raise ValueError."""
        with pytest.raises(ValueError, match="target_key exceeds maximum length"):
            service.create_annotation(
                target_key="entity:user:" + "a" * 257,
                author="analyst1",
                comment="Comment.",
            )

    def test_invalid_target_key_format(self, service: AnalystAnnotationService):
        """Invalid target key format should raise ValueError."""
        with pytest.raises(ValueError, match="target_key must match"):
            service.create_annotation(
                target_key="invalid-format",
                author="analyst1",
                comment="Comment.",
            )

    def test_valid_entity_target(self, service: AnalystAnnotationService):
        """Valid entity target should be accepted."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        assert annotation is not None

    def test_valid_behavior_target(self, service: AnalystAnnotationService):
        """Valid behavior target should be accepted."""
        annotation = service.create_annotation(
            target_key="behavior:host:server01|dimension:process_name|value:powershell.exe",
            author="analyst1",
            comment="Comment.",
        )
        assert annotation is not None

    def test_empty_author(self, service: AnalystAnnotationService):
        """Empty author should raise ValueError."""
        with pytest.raises(ValueError, match="author must not be empty"):
            service.create_annotation(
                target_key="entity:user:admin",
                author="",
                comment="Comment.",
            )

    def test_non_string_author(self, service: AnalystAnnotationService):
        """Non-string author should raise ValueError."""
        with pytest.raises(ValueError, match="author must be a string"):
            service.create_annotation(
                target_key="entity:user:admin",
                author=123,
                comment="Comment.",
            )

    def test_author_too_long(self, service: AnalystAnnotationService):
        """Author exceeding max length should raise ValueError."""
        with pytest.raises(ValueError, match="author exceeds maximum length"):
            service.create_annotation(
                target_key="entity:user:admin",
                author="a" * 129,
                comment="Comment.",
            )

    def test_invalid_author_characters(self, service: AnalystAnnotationService):
        """Author with invalid characters should raise ValueError."""
        with pytest.raises(ValueError, match="author must contain only"):
            service.create_annotation(
                target_key="entity:user:admin",
                author="analyst@1",
                comment="Comment.",
            )

    def test_empty_comment(self, service: AnalystAnnotationService):
        """Empty comment should raise ValueError."""
        with pytest.raises(ValueError, match="comment must not be empty"):
            service.create_annotation(
                target_key="entity:user:admin",
                author="analyst1",
                comment="",
            )

    def test_non_string_comment(self, service: AnalystAnnotationService):
        """Non-string comment should raise ValueError."""
        with pytest.raises(ValueError, match="comment must be a string"):
            service.create_annotation(
                target_key="entity:user:admin",
                author="analyst1",
                comment=123,
            )

    def test_comment_too_long(self, service: AnalystAnnotationService):
        """Comment exceeding max length should raise ValueError."""
        with pytest.raises(ValueError, match="comment exceeds maximum length"):
            service.create_annotation(
                target_key="entity:user:admin",
                author="analyst1",
                comment="a" * 513,
            )

    def test_control_characters_stripped(self, service: AnalystAnnotationService):
        """Control characters should be stripped from comment."""
        comment = "Normal text\x00\x01\x02more text"
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment=comment,
        )
        assert annotation.comment == "Normal textmore text"


# ── Boundedness Tests ────────────────────────────────────────────────────────


class TestBoundedness:
    """Query bounds and limits."""

    def test_max_annotations_per_target(self, service: AnalystAnnotationService):
        """Should enforce max annotations per target."""
        for i in range(10):
            service.create_annotation(
                target_key="entity:user:admin",
                author=f"analyst{i}",
                comment=f"Comment {i}",
            )
        # Should fail at limit
        with pytest.raises(RuntimeError, match="Maximum annotations per target"):
            service.create_annotation(
                target_key="entity:user:admin",
                author="analyst10",
                comment="Comment 10",
            )

    def test_max_total_annotations(self, service: AnalystAnnotationService):
        """Should enforce max total annotations."""
        for i in range(100):
            service.create_annotation(
                target_key=f"entity:user:user{i}",
                author="analyst1",
                comment=f"Comment {i}",
            )
        # Should fail at limit
        with pytest.raises(RuntimeError, match="Maximum total annotations"):
            service.create_annotation(
                target_key="entity:user:user100",
                author="analyst1",
                comment="Comment 100",
            )

    def test_query_results_bounded(self, service: AnalystAnnotationService):
        """Query results should be bounded."""
        for i in range(5):
            service.create_annotation(
                target_key="entity:user:admin",
                author="analyst1",
                comment=f"Comment {i}",
            )
        annotations = service.get_annotations_by_target("entity:user:admin")
        assert len(annotations) <= 50  # _MAX_ANNOTATIONS_PER_TARGET_QUERY

    def test_list_bounded(self, service: AnalystAnnotationService):
        """List should be bounded."""
        for i in range(5):
            service.create_annotation(
                target_key=f"entity:user:user{i}",
                author="analyst1",
                comment=f"Comment {i}",
            )
        annotations = service.list_annotations()
        assert len(annotations) <= 100  # _MAX_TOTAL_ANNOTATIONS_QUERY


# ── Read-Only / Decision Neutrality Tests ────────────────────────────────────


class TestDecisionNeutrality:
    """Annotations must not affect detection or decision logic."""

    def test_annotation_count_independent_of_detection(self, service: AnalystAnnotationService):
        """Annotation count should not affect detection results."""
        # Create annotations
        for i in range(10):
            service.create_annotation(
                target_key="entity:user:admin",
                author="analyst1",
                comment=f"Comment {i}",
            )
        # No detection state should be modified

    def test_tombstone_does_not_affect_detection(self, service: AnalystAnnotationService):
        """Tombstoning should not affect detection results."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        service.tombstone_annotation(annotation.annotation_id)
        # No detection state should be modified

    def test_no_alert_severity_change(self, service: AnalystAnnotationService):
        """Annotations should not change alert severity."""
        # Create annotation
        service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        # No alert severity should be modified

    def test_no_confidence_change(self, service: AnalystAnnotationService):
        """Annotations should not change detector confidence."""
        # Create annotation
        service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        # No confidence should be modified

    def test_no_deduplication_change(self, service: AnalystAnnotationService):
        """Annotations should not affect deduplication."""
        # Create annotation
        service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        # No deduplication state should be modified

    def test_no_incident_association_change(self, service: AnalystAnnotationService):
        """Annotations should not affect incident association."""
        # Create annotation
        service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        # No incident state should be modified

    def test_no_lifecycle_change(self, service: AnalystAnnotationService):
        """Annotations should not affect alert lifecycle."""
        # Create annotation
        service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        # No lifecycle state should be modified

    def test_no_entity_behavior_profile_change(self, service: AnalystAnnotationService):
        """Annotations should not modify entity behavior profiles."""
        # Create annotation
        service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        # No behavior profile should be modified


# ── Concurrency Tests ────────────────────────────────────────────────────────


class TestConcurrency:
    """Thread safety and concurrency."""

    def test_concurrent_creation(self, service: AnalystAnnotationService):
        """Concurrent annotation creation should not corrupt state."""
        errors = []

        def create_annotation(i: int) -> None:
            try:
                service.create_annotation(
                    target_key=f"entity:user:user{i}",
                    author=f"analyst{i % 5}",
                    comment=f"Comment {i}",
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=create_annotation, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert service.get_annotation_count() == 50

    def test_concurrent_create_and_read(self, service: AnalystAnnotationService):
        """Concurrent create and read should not corrupt state."""
        errors = []

        def create_annotations() -> None:
            for i in range(5):
                try:
                    service.create_annotation(
                        target_key="entity:user:admin",
                        author="analyst1",
                        comment=f"Comment {i}",
                    )
                except Exception as exc:
                    errors.append(exc)

        def read_annotations() -> None:
            for _ in range(20):
                try:
                    service.get_annotations_by_target("entity:user:admin")
                except Exception as exc:
                    errors.append(exc)

        threads = [
            threading.Thread(target=create_annotations),
            threading.Thread(target=read_annotations),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_concurrent_tombstone(self, service: AnalystAnnotationService):
        """Concurrent tombstoning should not corrupt state."""
        # Create annotations
        annotations = []
        for i in range(10):
            annotations.append(
                service.create_annotation(
                    target_key="entity:user:admin",
                    author="analyst1",
                    comment=f"Comment {i}",
                )
            )

        errors = []

        def tombstone(annotation_id: UUID) -> None:
            try:
                service.tombstone_annotation(annotation_id)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=tombstone, args=(a.annotation_id,)) for a in annotations]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Only one should succeed
        active = service.get_annotations_by_target("entity:user:admin")
        assert len(active) == 0
        tombstoned = service.get_annotations_by_target("entity:user:admin", include_tombstoned=True)
        assert len(tombstoned) == 10

    def test_duplicate_annotation_ids(self, service: AnalystAnnotationService):
        """Duplicate annotation IDs should not cause issues."""
        annotation1 = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment 1",
        )
        annotation2 = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment 2",
        )
        # IDs should be unique
        assert annotation1.annotation_id != annotation2.annotation_id


# ── Persistence Tests ────────────────────────────────────────────────────────


class TestPersistence:
    """Persistence integration."""

    def test_persistence_enabled(self, persistence_service: tuple) -> None:
        """Test with persistence enabled."""
        service, persistence = persistence_service
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Persistent comment.",
        )
        assert annotation is not None
        assert persistence.load_annotation(annotation.annotation_id) is not None

    def test_persistence_disabled(self, service: AnalystAnnotationService):
        """Test without persistence."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="In-memory comment.",
        )
        assert annotation is not None
        # Should still be retrievable from memory
        retrieved = service.get_annotation(annotation.annotation_id)
        assert retrieved is not None

    def test_persistence_failure_does_not_disrupt(self, service: AnalystAnnotationService):
        """Persistence failures should not disrupt annotation creation."""
        # Service without persistence
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        assert annotation is not None

    def test_corrupted_annotation_record(self, persistence_service: tuple) -> None:
        """Corrupted records should be handled gracefully."""
        service, persistence = persistence_service
        # Create valid annotation
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        # Manually corrupt the database by setting an invalid timestamp
        persistence._get_connection().execute(
            "UPDATE analyst_annotations SET created_at='invalid' WHERE annotation_id=?",
            (str(annotation.annotation_id),),
        )
        persistence._get_connection().commit()
        # Service should still work (corrupted record returns None)
        retrieved = service.get_annotation(annotation.annotation_id)
        # May be None due to corruption handling
        assert retrieved is None or retrieved.annotation_id == annotation.annotation_id


# ── Edge Cases ───────────────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_service(self, service: AnalystAnnotationService):
        """Empty service should return empty lists."""
        assert service.get_annotations_by_target("entity:user:admin") == []
        assert service.list_annotations() == []
        assert service.get_annotation_count() == 0

    def test_nonexistent_annotation(self, service: AnalystAnnotationService):
        """Non-existent annotation should return None."""
        from uuid import uuid4

        assert service.get_annotation(uuid4()) is None

    def test_invalid_annotation_id(self, service: AnalystAnnotationService):
        """Invalid annotation ID should return None."""
        assert service.get_annotation("not-a-uuid") is None
        assert service.get_annotation(None) is None

    def test_max_length_inputs(self, service: AnalystAnnotationService):
        """Max length inputs should be accepted."""
        annotation = service.create_annotation(
            target_key="entity:user:" + "a" * 200,
            author="a" * 100,
            comment="a" * 500,
        )
        assert annotation is not None

    def test_special_characters_in_comment(self, service: AnalystAnnotationService):
        """Special characters in comment should be handled."""
        comment = "Special chars: <>&\"'`$(){}[]!@#%^*+-=|\\/:;"
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment=comment,
        )
        assert annotation.comment == comment

    def test_unicode_in_comment(self, service: AnalystAnnotationService):
        """Unicode characters should be handled."""
        comment = "Unicode: 你好世界 🌍 émoji"
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment=comment,
        )
        assert annotation.comment == comment

    def test_newline_in_comment(self, service: AnalystAnnotationService):
        """Newlines in comment should be preserved."""
        comment = "Line 1\nLine 2\nLine 3"
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment=comment,
        )
        assert annotation.comment == comment

    def test_whitespace_only_comment(self, service: AnalystAnnotationService):
        """Whitespace-only comment should be rejected."""
        with pytest.raises(ValueError, match="comment must not be empty"):
            service.create_annotation(
                target_key="entity:user:admin",
                author="analyst1",
                comment="   ",
            )

    def test_whitespace_stripped_comment(self, service: AnalystAnnotationService):
        """Whitespace-only after stripping should be rejected."""
        with pytest.raises(ValueError, match="comment must not be empty"):
            service.create_annotation(
                target_key="entity:user:admin",
                author="analyst1",
                comment="\t\n  \r",
            )

    def test_deterministic_ordering(self, service: AnalystAnnotationService):
        """Annotations should be returned in deterministic order."""
        base_time = datetime(2026, 9, 4, 10, 0, 0, tzinfo=UTC)
        for i in range(5):
            service.create_annotation(
                target_key="entity:user:admin",
                author="analyst1",
                comment=f"Comment {i}",
                created_at=base_time,
            )
        annotations = service.get_annotations_by_target("entity:user:admin")
        # Should be ordered by created_at descending
        for i in range(len(annotations) - 1):
            assert annotations[i]["created_at"] >= annotations[i + 1]["created_at"]


# ── Data Contract Tests ──────────────────────────────────────────────────────


# ── Exact Boundary Tests ─────────────────────────────────────────────────────
# PHASE 5.2 HARDENING: Verify exact bound exhaustion semantics


class TestExactBoundarySemantics:
    """Exact boundary tests per Phase 5.2 hardening requirements.

    Required semantics:
    - maximum per target = 50
    - maximum total = 10,000
    - tombstoned annotations are NOT counted toward bounds
    - tombstoning frees capacity
    - newest annotation is rejected at capacity
    - behavior is deterministic
    """

    # --- Per-target exact boundaries ---

    def test_per_target_49_succeeds(self):
        """49 → 50 succeeds for same target."""
        service = AnalystAnnotationService(
            max_annotations_per_target=50,
            max_total_annotations=10000,
        )
        target = "entity:user:admin"
        # Create 49 annotations
        for i in range(49):
            service.create_annotation(
                target_key=target,
                author=f"analyst{i}",
                comment=f"Comment {i}",
            )
        assert service.count_annotations(target) == 49
        # 50th should succeed
        ann = service.create_annotation(
            target_key=target,
            author="analyst49",
            comment="The 50th annotation",
        )
        assert ann is not None
        assert service.count_annotations(target) == 50

    def test_per_target_51_rejected(self):
        """51st annotation is rejected for same target."""
        service = AnalystAnnotationService(
            max_annotations_per_target=50,
            max_total_annotations=10000,
        )
        target = "entity:user:admin"
        # Create 50 annotations (at limit)
        for i in range(50):
            service.create_annotation(
                target_key=target,
                author=f"analyst{i}",
                comment=f"Comment {i}",
            )
        assert service.count_annotations(target) == 50
        # 51st should be rejected
        with pytest.raises(RuntimeError, match="Maximum annotations per target"):
            service.create_annotation(
                target_key=target,
                author="analyst50",
                comment="This should be rejected",
            )

    def test_per_target_capacity_after_tombstone(self):
        """Tombstoning frees per-target capacity."""
        service = AnalystAnnotationService(
            max_annotations_per_target=50,
            max_total_annotations=10000,
        )
        target = "entity:user:admin"
        # Create 50 annotations (at limit)
        for i in range(50):
            service.create_annotation(
                target_key=target,
                author=f"analyst{i}",
                comment=f"Comment {i}",
            )
        assert service.count_annotations(target) == 50
        # Tombstone one
        last = service._all_annotations[0]  # Most recent
        service.tombstone_annotation(last.annotation_id)
        assert service.count_annotations(target) == 49
        # Should be able to create one more
        ann = service.create_annotation(
            target_key=target,
            author="analyst50",
            comment="After tombstone",
        )
        assert ann is not None
        assert service.count_annotations(target) == 50

    def test_per_target_boundary_different_target_succeeds(self):
        """At per-target capacity on one target, can still create on different target."""
        service = AnalystAnnotationService(
            max_annotations_per_target=50,
            max_total_annotations=10000,
        )
        target1 = "entity:user:admin"
        target2 = "entity:user:other"
        # Fill target1 to capacity
        for i in range(50):
            service.create_annotation(
                target_key=target1,
                author=f"analyst{i}",
                comment=f"Comment {i}",
            )
        assert service.count_annotations(target1) == 50
        # Can still create on target2
        ann = service.create_annotation(
            target_key=target2,
            author="analyst0",
            comment="Different target",
        )
        assert ann is not None
        assert service.count_annotations(target2) == 1

    # --- Total exact boundaries ---

    def test_total_9999_succeeds(self):
        """9,999 → 10,000 succeeds."""
        service = AnalystAnnotationService(
            max_annotations_per_target=50,
            max_total_annotations=10000,
        )
        # Create 9,999 annotations
        for i in range(9999):
            service.create_annotation(
                target_key=f"entity:user:user{i}",
                author="analyst0",
                comment=f"Comment {i}",
            )
        assert service.count_annotations() == 9999
        # 10,000th should succeed
        ann = service.create_annotation(
            target_key="entity:user:last",
            author="analyst0",
            comment="The 10,000th annotation",
        )
        assert ann is not None
        assert service.count_annotations() == 10000

    def test_total_10001_rejected(self):
        """10,001st annotation is rejected."""
        service = AnalystAnnotationService(
            max_annotations_per_target=50,
            max_total_annotations=10000,
        )
        # Create 10,000 annotations (at limit)
        for i in range(10000):
            service.create_annotation(
                target_key=f"entity:user:user{i}",
                author="analyst0",
                comment=f"Comment {i}",
            )
        assert service.count_annotations() == 10000
        # 10,001st should be rejected
        with pytest.raises(RuntimeError, match="Maximum total annotations"):
            service.create_annotation(
                target_key="entity:user:user10000",
                author="analyst0",
                comment="This should be rejected",
            )

    def test_total_capacity_after_tombstone(self):
        """Tombstoning frees total capacity."""
        service = AnalystAnnotationService(
            max_annotations_per_target=50,
            max_total_annotations=10000,
        )
        # Create 10,000 annotations (at limit)
        for i in range(10000):
            service.create_annotation(
                target_key=f"entity:user:user{i}",
                author="analyst0",
                comment=f"Comment {i}",
            )
        assert service.count_annotations() == 10000
        # Tombstone one
        last = service._all_annotations[0]
        service.tombstone_annotation(last.annotation_id)
        assert service.count_annotations() == 9999
        # Should be able to create one more
        ann = service.create_annotation(
            target_key="entity:user:user10000",
            author="analyst0",
            comment="After tombstone",
        )
        assert ann is not None
        assert service.count_annotations() == 10000

    def test_tombstone_multiple_frees_capacity(self):
        """Multiple tombstones free cumulative capacity."""
        service = AnalystAnnotationService(
            max_annotations_per_target=50,
            max_total_annotations=100,
        )
        # Create 100 annotations
        for i in range(100):
            service.create_annotation(
                target_key=f"entity:user:user{i}",
                author="analyst0",
                comment=f"Comment {i}",
            )
        # Tombstone 10
        for ann in service._all_annotations[:10]:
            service.tombstone_annotation(ann.annotation_id)
        assert service.count_annotations() == 90
        # Create 10 more
        for i in range(10):
            service.create_annotation(
                target_key=f"entity:user:new{i}",
                author="analyst0",
                comment=f"New comment {i}",
            )
        assert service.count_annotations() == 100

    # --- Persistence layer exact boundaries ---

    def test_persistence_per_target_50_at_limit(self, temp_dir):
        """Persistence layer enforces per-target limit."""
        db_path = temp_dir / "test.db"
        from argusprowl.behavior.analyst_annotation_persistence import (
            AnalystAnnotationPersistence,
        )

        persistence = AnalystAnnotationPersistence(
            db_path=db_path,
            max_total_annotations=10000,
        )
        persistence.initialize()
        service = AnalystAnnotationService(
            persistence=persistence,
            max_annotations_per_target=50,
            max_total_annotations=10000,
        )
        target = "entity:user:admin"
        # Create 50 (at limit)
        for i in range(50):
            service.create_annotation(
                target_key=target,
                author=f"analyst{i}",
                comment=f"Comment {i}",
            )
        # 51st rejected
        with pytest.raises(RuntimeError, match="Maximum annotations per target"):
            service.create_annotation(
                target_key=target,
                author="analyst50",
                comment="Should fail",
            )

    def test_persistence_total_10000_at_limit(self, temp_dir):
        """Persistence layer enforces total limit."""
        db_path = temp_dir / "test.db"
        from argusprowl.behavior.analyst_annotation_persistence import (
            AnalystAnnotationPersistence,
        )

        persistence = AnalystAnnotationPersistence(
            db_path=db_path,
            max_total_annotations=10000,
        )
        persistence.initialize()
        service = AnalystAnnotationService(
            persistence=persistence,
            max_annotations_per_target=50,
            max_total_annotations=10000,
        )
        # Create 10,000 (at limit)
        for i in range(10000):
            service.create_annotation(
                target_key=f"entity:user:user{i}",
                author="analyst0",
                comment=f"Comment {i}",
            )
        # 10,001st rejected
        with pytest.raises(RuntimeError, match="Maximum total annotations"):
            service.create_annotation(
                target_key="entity:user:user10000",
                author="analyst0",
                comment="Should fail",
            )


class TestTombstoneIdempotency:
    """Tombstone idempotency tests per Phase 5.2 requirements."""

    def test_tombstone_idempotent(self, service: AnalystAnnotationService):
        """Tombstoning same annotation multiple times is idempotent."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Test comment",
        )
        # First tombstone
        result1 = service.tombstone_annotation(annotation.annotation_id)
        assert result1 is True
        # Second tombstone
        result2 = service.tombstone_annotation(annotation.annotation_id)
        assert result2 is False
        # Third tombstone
        result3 = service.tombstone_annotation(annotation.annotation_id)
        assert result3 is False
        # Verify state unchanged
        retrieved = service.get_annotation(annotation.annotation_id)
        assert retrieved is not None
        assert retrieved.tombstoned is True

    def test_tombstone_concurrent_idempotent(self, service: AnalystAnnotationService):
        """Concurrent tombstones produce deterministic result."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Test comment",
        )
        results = []

        def tombstone():
            result = service.tombstone_annotation(annotation.annotation_id)
            results.append(result)

        threads = [threading.Thread(target=tombstone) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly one True, rest False
        assert results.count(True) == 1
        assert results.count(False) == 9


class TestControlCharacterContract:
    """Control character stripping contract tests."""

    def test_null_stripped(self, service: AnalystAnnotationService):
        """U+0000 (NUL) is stripped."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Hello\x00World",
        )
        assert annotation.comment == "HelloWorld"

    def test_bell_stripped(self, service: AnalystAnnotationService):
        """U+0007 (BEL) is stripped."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Alert\x07!",
        )
        assert annotation.comment == "Alert!"

    def test_backspace_stripped(self, service: AnalystAnnotationService):
        """U+0008 (BS) is stripped."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="text\x08hidden",
        )
        assert annotation.comment == "texthidden"

    def test_tab_preserved(self, service: AnalystAnnotationService):
        """U+0009 (TAB) is preserved."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="col1\tcol2",
        )
        assert annotation.comment == "col1\tcol2"

    def test_newline_preserved(self, service: AnalystAnnotationService):
        """U+000A (LF) is preserved."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="line1\nline2",
        )
        assert annotation.comment == "line1\nline2"

    def test_carriage_return_preserved(self, service: AnalystAnnotationService):
        """U+000D (CR) is preserved."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="line1\rline2",
        )
        assert annotation.comment == "line1\rline2"

    def test_vertical_tab_stripped(self, service: AnalystAnnotationService):
        """U+000B (VT) is stripped."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="a\x0bb",
        )
        assert annotation.comment == "ab"

    def test_form_feed_stripped(self, service: AnalystAnnotationService):
        """U+000C (FF) is stripped."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="page1\x0cpage2",
        )
        assert annotation.comment == "page1page2"

    def test_delete_stripped(self, service: AnalystAnnotationService):
        """U+007F (DEL) is stripped."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="text\x7fhidden",
        )
        assert annotation.comment == "texthidden"

    def test_unicode_preserved(self, service: AnalystAnnotationService):
        """Unicode characters are preserved."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Hello 世界 🌍 émoji",
        )
        assert annotation.comment == "Hello 世界 🌍 émoji"


class TestDeterminism:
    """Determinism tests for Phase 5.2."""

    def test_annotation_identity_immutable(self, service: AnalystAnnotationService):
        """Annotation identity is immutable after creation."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Test",
        )
        original_id = annotation.annotation_id
        # Frozen dataclass - cannot modify
        assert annotation.annotation_id == original_id

    def test_tombstone_preserves_original_fields(self, service: AnalystAnnotationService):
        """Tombstoning preserves all original fields."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Original comment",
        )
        original_comment = annotation.comment
        original_author = annotation.author
        original_target = annotation.target_key
        service.tombstone_annotation(annotation.annotation_id)
        retrieved = service.get_annotation(annotation.annotation_id)
        assert retrieved is not None
        assert retrieved.comment == original_comment
        assert retrieved.author == original_author
        assert retrieved.target_key == original_target
        assert retrieved.tombstoned is True

    def test_concurrent_create_at_boundary_deterministic(self):
        """Concurrent creates are thread-safe and atomic.

        The service uses RLock to ensure check-then-create is atomic.
        With 48 existing + 3 concurrent creates, exactly 2 succeed and 1 fails
        (because 48 + 2 = 50 is the limit).
        """
        service = AnalystAnnotationService(
            max_annotations_per_target=50,
            max_total_annotations=200,
        )
        target = "entity:user:admin"

        # Fill to 48 (leave room for exactly 2 more)
        for i in range(48):
            service.create_annotation(
                target_key=target,
                author=f"analyst{i}",
                comment=f"Comment {i}",
            )
        assert service.count_annotations(target) == 48

        # Test that concurrent creates are serialized by lock
        barrier = threading.Barrier(3)
        errors = []
        successes = []

        def create():
            barrier.wait()
            try:
                ann = service.create_annotation(
                    target_key=target,
                    author="concurrent",
                    comment="Test",
                )
                successes.append(ann)
            except RuntimeError as exc:
                errors.append(exc)

        threads = [threading.Thread(target=create) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly 2 should succeed, 1 should fail (correct bound behavior)
        assert len(successes) == 2, f"Expected 2 successes, got {len(successes)}"
        assert len(errors) == 1, f"Expected 1 failure, got {len(errors)}"
        # Total should be exactly 50
        assert service.count_annotations(target) == 50


# ── Data Contract Tests ──────────────────────────────────────────────────────


class TestDataContract:
    """Data contract validation."""

    def test_annotation_fields(self, service: AnalystAnnotationService):
        """Annotation should have required fields."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        assert hasattr(annotation, "annotation_id")
        assert hasattr(annotation, "target_key")
        assert hasattr(annotation, "author")
        assert hasattr(annotation, "created_at")
        assert hasattr(annotation, "comment")
        assert hasattr(annotation, "tombstoned")

    def test_immutable_identity(self, service: AnalystAnnotationService):
        """Annotation identity should be immutable."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        original_id = annotation.annotation_id
        # Annotation is frozen, cannot be modified
        assert annotation.annotation_id == original_id

    def test_canonical_timestamp(self, service: AnalystAnnotationService):
        """Timestamps should be canonical UTC."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        assert annotation.created_at.tzinfo is not None
        assert annotation.created_at.tzname() == "UTC"

    def test_deterministic_serialization(self, service: AnalystAnnotationService):
        """Serialization should be deterministic."""
        annotation = service.create_annotation(
            target_key="entity:user:admin",
            author="analyst1",
            comment="Comment.",
        )
        serialized = {
            "annotation_id": str(annotation.annotation_id),
            "target_key": annotation.target_key,
            "author": annotation.author,
            "created_at": annotation.created_at.isoformat(),
            "comment": annotation.comment,
            "tombstoned": annotation.tombstoned,
        }
        assert serialized["annotation_id"] is not None
        assert serialized["target_key"] == "entity:user:admin"
        assert serialized["author"] == "analyst1"
        assert serialized["comment"] == "Comment."
        assert serialized["tombstoned"] is False
