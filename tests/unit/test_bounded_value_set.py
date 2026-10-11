"""Tests for BoundedValueSet."""

import pytest

from argusprowl.behavior.bounded_value_set import BoundedValueSet


class TestBoundedValueSetCreation:
    """Tests for BoundedValueSet creation."""

    def test_creation_default(self) -> None:
        """Test creation with defaults."""
        bvs = BoundedValueSet()
        assert bvs.max_values == 1000
        assert bvs.max_value_length == 256
        assert len(bvs) == 0

    def test_creation_custom(self) -> None:
        """Test creation with custom values."""
        bvs = BoundedValueSet(max_values=100, max_value_length=128)
        assert bvs.max_values == 100
        assert bvs.max_value_length == 128

    def test_creation_invalid_max_values(self) -> None:
        """Test creation with invalid max_values raises."""
        with pytest.raises(ValueError, match="max_values must be positive"):
            BoundedValueSet(max_values=0)

    def test_creation_invalid_max_value_length(self) -> None:
        """Test creation with invalid max_value_length raises."""
        with pytest.raises(ValueError, match="max_value_length must be positive"):
            BoundedValueSet(max_value_length=0)


class TestBoundedValueSetAdd:
    """Tests for BoundedValueSet.add()."""

    def test_add_single_value(self) -> None:
        """Test adding a single value."""
        bvs = BoundedValueSet()
        is_new, representation = bvs.add("value1")

        assert is_new is True
        assert representation == "value1"
        assert len(bvs) == 1
        assert "value1" in bvs

    def test_add_duplicate_value(self) -> None:
        """Test adding a duplicate value."""
        bvs = BoundedValueSet()
        bvs.add("value1")
        is_new, representation = bvs.add("value1")

        assert is_new is False
        assert representation == "value1"
        assert len(bvs) == 1  # Still only one value

    def test_add_multiple_different_values(self) -> None:
        """Test adding multiple distinct values."""
        bvs = BoundedValueSet()
        bvs.add("value1")
        bvs.add("value2")
        bvs.add("value3")

        assert len(bvs) == 3
        assert "value1" in bvs
        assert "value2" in bvs
        assert "value3" in bvs

    def test_add_oversized_value(self) -> None:
        """Test adding a value exceeding max_value_length uses hash representation."""
        bvs = BoundedValueSet(max_value_length=10)
        oversized = "x" * 100

        is_new, representation = bvs.add(oversized)

        assert is_new is True
        assert representation != oversized  # Should be a hash
        assert len(representation) == 64  # SHA-256 hex digest

        # The representation (hash) is returned, and the value is stored
        # We can verify by checking count
        assert bvs.count() == 1

        # Adding the same oversized value again should return is_new=False
        is_new2, rep2 = bvs.add(oversized)
        assert is_new2 is False
        assert rep2 == representation

    def test_add_duplicate_oversized_values(self) -> None:
        """Test adding duplicate oversized values uses same hash."""
        bvs = BoundedValueSet(max_value_length=10)
        oversized = "x" * 100

        bvs.add(oversized)
        is_new, representation = bvs.add(oversized)

        assert is_new is False
        assert len(representation) == 64

    def test_add_similar_oversized_values_different(self) -> None:
        """Test that similar oversized values produce different hashes."""
        bvs = BoundedValueSet(max_value_length=10)

        _, rep1 = bvs.add("x" * 100)
        _, rep2 = bvs.add("y" * 100)

        assert rep1 != rep2
        assert len(bvs) == 2


class TestBoundedValueSetEviction:
    """Tests for BoundedValueSet eviction."""

    def test_lru_eviction(self) -> None:
        """Test LRU eviction when at capacity."""
        bvs = BoundedValueSet(max_values=3)
        bvs.add("value1")
        bvs.add("value2")
        bvs.add("value3")

        # value1 should still be present
        assert "value1" in bvs
        assert "value2" in bvs
        assert "value3" in bvs

        # Re-add value3 to make it most recently used (value1 becomes LRU)
        bvs.add("value3")

        # Add new value - should evict value1 (LRU)
        bvs.add("value4")

        assert "value1" not in bvs  # Evicted (LRU)
        assert "value2" in bvs
        assert "value3" in bvs  # Most recently used
        assert "value4" in bvs

    def test_eviction_updates_on_access(self) -> None:
        """Test that access updates LRU order."""
        bvs = BoundedValueSet(max_values=3)
        bvs.add("value1")
        bvs.add("value2")
        bvs.add("value3")

        # Re-add value1 to make it most recently used
        bvs.add("value1")

        # Add value4 - should evict value2 (now LRU)
        bvs.add("value4")

        assert "value2" not in bvs  # Evicted
        assert "value1" in bvs  # Most recently used
        assert "value3" in bvs
        assert "value4" in bvs
        assert len(bvs) == 3

    def test_duplicate_add_updates_lru(self) -> None:
        """Test that adding a value updates its LRU position."""
        bvs = BoundedValueSet(max_values=3)
        bvs.add("value1")
        bvs.add("value2")
        bvs.add("value3")

        # Re-add value1 (making it MRU)
        bvs.add("value1")

        # Add value4 - should evict value2 (now LRU)
        bvs.add("value4")

        assert "value1" in bvs  # Most recently used
        assert "value2" not in bvs  # Evicted
        assert "value3" in bvs
        assert "value4" in bvs


class TestBoundedValueSetCollisionResistance:
    """Tests for collision resistance of oversized value handling."""

    def test_same_oversized_value_produces_same_hash(self) -> None:
        """Test same value produces same hash (deterministic)."""
        bvs = BoundedValueSet(max_value_length=10)
        value = "test_value"

        _, rep1 = bvs.add(value)
        _, rep2 = bvs.add(value)

        assert rep1 == rep2
        assert bvs.count() == 1

    def test_different_oversized_values_produce_different_hashes(self) -> None:
        """Test different values produce different hashes."""
        bvs = BoundedValueSet(max_value_length=10)
        values = ["value_a", "value_b", "value_c"]

        reps = []
        for v in values:
            _, rep = bvs.add(v)
            reps.append(rep)

        assert len(set(reps)) == 3
        assert bvs.count() == 3

    def test_hash_deterministic_across_instances(self) -> None:
        """Test hash is deterministic across BoundedValueSet instances."""
        bvs1 = BoundedValueSet(max_value_length=10)
        bvs2 = BoundedValueSet(max_value_length=10)
        value = "long_value_that_exceeds_limit"

        _, rep1 = bvs1.add(value)
        _, rep2 = bvs2.add(value)

        assert rep1 == rep2  # Same hash


class TestBoundedValueSetConcurrency:
    """Tests for BoundedValueSet thread safety."""

    def test_concurrent_add(self) -> None:
        """Test concurrent adds don't corrupt state."""
        import threading

        bvs = BoundedValueSet(max_values=100)
        errors: list[Exception] = []

        def add_values(start: int, count: int) -> None:
            try:
                for i in range(start, start + count):
                    bvs.add(f"value{i}")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=add_values, args=(0, 50)),
            threading.Thread(target=add_values, args=(50, 50)),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert bvs.count() <= 100  # May be less due to LRU

    def test_concurrent_contains(self) -> None:
        """Test concurrent contains don't corrupt state."""
        import threading

        bvs = BoundedValueSet(max_values=100)
        for i in range(100):
            bvs.add(f"value{i}")

        errors: list[Exception] = []
        results: list[bool] = []

        def check_values(start: int, count: int) -> None:
            try:
                for _i in range(start, start + count):
                    results.append("value50" in bvs)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=check_values, args=(0, 50)),
            threading.Thread(target=check_values, args=(50, 50)),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # All results should be True (value50 exists)
        assert all(results)


class TestBoundedValueSetIteration:
    """Tests for BoundedValueSet iteration."""

    def test_iteration(self) -> None:
        """Test iteration returns all values."""
        bvs = BoundedValueSet()
        bvs.add("value1")
        bvs.add("value2")
        bvs.add("value3")

        values = list(bvs)
        assert len(values) == 3
        assert set(values) == {"value1", "value2", "value3"}

    def test_get_all(self) -> None:
        """Test get_all returns list."""
        bvs = BoundedValueSet()
        bvs.add("value1")
        bvs.add("value2")

        values = bvs.get_all()
        assert len(values) == 2
        assert "value1" in values
        assert "value2" in values


class TestBoundedValueSetClear:
    """Tests for BoundedValueSet.clear()."""

    def test_clear(self) -> None:
        """Test clear removes all values."""
        bvs = BoundedValueSet()
        bvs.add("value1")
        bvs.add("value2")
        bvs.add("value3")

        assert len(bvs) == 3
        bvs.clear()
        assert len(bvs) == 0
        assert "value1" not in bvs


class TestBoundedValueSetBounds:
    """Tests for BoundedValueSet memory bounds."""

    def test_oversized_values_memory_bounded(self) -> None:
        """Test that oversized values are bounded by max_values, not value size."""
        bvs = BoundedValueSet(max_values=3, max_value_length=10)

        # Add oversized values
        bvs.add("x" * 1000)
        bvs.add("y" * 1000)
        bvs.add("z" * 1000)

        assert len(bvs) == 3

        # Add one more - should evict
        bvs.add("a" * 1000)
        assert len(bvs) == 3

    def test_small_max_values(self) -> None:
        """Test small max_values with many adds."""
        bvs = BoundedValueSet(max_values=2)
        bvs.add("value1")
        bvs.add("value2")
        bvs.add("value3")
        bvs.add("value4")

        assert len(bvs) == 2

    def test_attacker_cannot_exceed_bounds(self) -> None:
        """Test attacker cannot exceed max_values through many distinct values."""
        bvs = BoundedValueSet(max_values=10)

        # Add 20 distinct values
        for i in range(20):
            bvs.add(f"malicious_value_{i}")

        assert len(bvs) == 10  # Capped at max_values
