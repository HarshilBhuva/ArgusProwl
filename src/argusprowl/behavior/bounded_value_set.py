"""Bounded value storage with deterministic LRU eviction.

Provides thread-safe storage for distinct values with hard limits on both
the number of distinct values and the length of individual values.

Oversized-value semantics: Values exceeding max_value_length are represented
by their SHA-256 hash (hex digest, 64 characters). This provides:
1. Deterministic, collision-resistant representation (no practical SHA-256 collisions)
2. Fixed-length storage regardless of input size
3. O(1) membership lookup via hash key
4. Memory bounded by max_values * 64 bytes for the hash representation

Values that hash to the same digest are considered identical for the purpose
of first-seen detection. This is a deliberate trade-off: we accept the
theoretical collision risk (2^256) in exchange for bounded memory and
deterministic behavior. For Phase 5.0.2 first-seen detection, this is
acceptable because:
- SHA-256 collisions are computationally infeasible to find
- The alternative (unbounded storage or lossy truncation) is worse
- Even if a collision occurred, both values would be treated as the same
  first-seen event, which is no worse than accepting either individually
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator
from hashlib import sha256
from threading import Lock


class BoundedValueSet:
    """Thread-safe bounded set with deterministic LRU eviction.

    Stores distinct string values with a hard limit on both the number of
    values and the length of each value. When at capacity, the least recently
    used (LRU) value is evicted to make room for a new value.

    Thread-safe for concurrent access.

    Attributes:
        max_values: Maximum number of distinct values to store.
        max_value_length: Maximum length of value strings. Values exceeding
            this are represented by their SHA-256 hash.
    """

    def __init__(
        self,
        max_values: int = 1000,
        max_value_length: int = 256,
    ) -> None:
        """Initialize bounded value set.

        Args:
            max_values: Maximum distinct values to store. Must be positive.
            max_value_length: Maximum length of value strings. Must be positive.

        Raises:
            ValueError: If max_values or max_value_length is not positive.
        """
        if max_values <= 0:
            raise ValueError(f"max_values must be positive, got {max_values}")
        if max_value_length <= 0:
            raise ValueError(f"max_value_length must be positive, got {max_value_length}")

        self._max_values = max_values
        self._max_value_length = max_value_length
        # OrderedDict provides O(1) lookup and O(1) move_to_end for LRU
        # Keys are either the original value or SHA-256 hash for oversized values
        self._values: OrderedDict[str, None] = OrderedDict()
        self._lock = Lock()

    @property
    def max_values(self) -> int:
        """Return the maximum number of distinct values."""
        return self._max_values

    @property
    def max_value_length(self) -> int:
        """Return the maximum length of value strings."""
        return self._max_value_length

    def __len__(self) -> int:
        """Return the number of distinct values stored."""
        with self._lock:
            return len(self._values)

    def __contains__(self, value: str) -> bool:
        """Check if a value is in the set.

        Args:
            value: The value to check.

        Returns:
            True if the value is stored, False otherwise.
        """
        with self._lock:
            key = self._to_key(value)
            return key in self._values

    def __iter__(self) -> Iterator[str]:
        """Iterate over stored values (in LRU order, oldest first)."""
        with self._lock:
            return iter(list(self._values.keys()))

    def _to_key(self, value: str) -> str:
        """Convert a value to its storage key.

        Values exceeding max_value_length are represented by their SHA-256 hash.
        This ensures memory bounds are respected while maintaining deterministic
        behavior.

        Args:
            value: The value to convert.

        Returns:
            The storage key (original value or hash for oversized values).
        """
        if len(value) > self._max_value_length:
            return sha256(value.encode("utf-8")).hexdigest()
        return value

    def _is_hash_key(self, key: str) -> bool:
        """Check if a key is a hash representation.

        SHA-256 hex digests are always exactly 64 characters.

        Args:
            key: The key to check.

        Returns:
            True if the key is a hash representation.
        """
        return len(key) == 64 and all(c in "0123456789abcdef" for c in key)

    def add(self, value: str) -> tuple[bool, str]:
        """Add a value to the set.

        If the set is at capacity, the least recently used (LRU) value is
        evicted to make room. If the value is already present, it is moved
        to the end (most recently used) but no new slot is consumed.

        Args:
            value: The value to add.

        Returns:
            Tuple of (is_new, representation) where is_new indicates whether
            this was a first-time addition and representation is either the
            original value or its SHA-256 hash if it was oversized.
        """
        key = self._to_key(value)
        representation = key if self._is_hash_key(key) else value

        with self._lock:
            is_new = key not in self._values

            if is_new:
                if len(self._values) >= self._max_values:
                    # LRU eviction: remove least recently used (first item)
                    self._values.popitem(last=False)

                self._values[key] = None

            # Move to end to mark as most recently used
            self._values.move_to_end(key)

            return is_new, representation

    def clear(self) -> None:
        """Remove all values from the set."""
        with self._lock:
            self._values.clear()

    def get_all(self) -> list[str]:
        """Return all stored values as a list.

        Returns:
            List of all values in LRU order (oldest first).
        """
        with self._lock:
            return list(self._values.keys())

    def count(self) -> int:
        """Return the number of distinct values.

        Returns:
            Number of values in the set.
        """
        with self._lock:
            return len(self._values)
