"""JSON serialisation helper functions.

Extends the standard library's :mod:`json` module with support for
common Python types that are not natively serialisable (datetimes,
UUIDs, dataclasses, enums, Paths).
"""

import dataclasses
import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID


def make_serializable(obj: Any) -> Any:
    """Convert *obj* to a JSON-compatible Python primitive.

    Recursively handles dataclasses, datetimes, UUIDs, enums, Paths,
    sets, and byte strings.

    Args:
        obj: The object to convert.

    Returns:
        A JSON-safe primitive (str, int, float, bool, None, list, dict).
    """
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: make_serializable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [make_serializable(item) for item in obj]
    return str(obj)


class _ExtendedEncoder(json.JSONEncoder):
    """JSON encoder that delegates unknown types to :func:`make_serializable`."""

    def default(self, o: Any) -> Any:
        result = make_serializable(o)
        if isinstance(result, str):
            return result
        return super().default(o)


def json_dumps(obj: Any, *, indent: int | None = 2, sort_keys: bool = False) -> str:
    """Serialise *obj* to a JSON string with extended type support.

    Args:
        obj: The object to serialise.
        indent: Indentation level (``None`` for compact output).
        sort_keys: Whether to sort dictionary keys.

    Returns:
        A JSON-formatted string.
    """
    serializable = make_serializable(obj)
    return json.dumps(serializable, indent=indent, sort_keys=sort_keys, ensure_ascii=False)


def json_loads(text: str) -> Any:
    """Deserialise a JSON string.

    Args:
        text: The JSON string to parse.

    Returns:
        The parsed Python object.

    Raises:
        json.JSONDecodeError: If *text* is not valid JSON.
    """
    return json.loads(text)
