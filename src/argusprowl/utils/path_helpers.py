"""Filesystem path helper functions.

Provides safe path resolution, directory creation, and path
traversal checks.
"""

from pathlib import Path


def resolve_path(path: str | Path, base: Path | None = None) -> Path:
    """Resolve *path* to an absolute :class:`Path`.

    If *path* is relative and *base* is provided, it is resolved
    relative to *base*; otherwise relative to the current directory.

    Args:
        path: The path to resolve.
        base: Optional base directory for relative paths.

    Returns:
        An absolute, resolved :class:`Path`.
    """
    p = Path(path)
    if not p.is_absolute() and base is not None:
        p = base / p
    return p.resolve()


def ensure_directory(path: str | Path) -> Path:
    """Create a directory (and parents) if it does not exist.

    Args:
        path: The directory path to ensure.

    Returns:
        The resolved :class:`Path` of the directory.
    """
    resolved = Path(path).resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def is_safe_path(path: str | Path, allowed_root: str | Path) -> bool:
    """Check that *path* resolves to a location within *allowed_root*.

    Prevents path traversal attacks (e.g. ``../../etc/passwd``).

    Args:
        path: The path to validate.
        allowed_root: The root directory that *path* must stay within.

    Returns:
        ``True`` if the resolved *path* is within *allowed_root*.
    """
    resolved = Path(path).resolve()
    root = Path(allowed_root).resolve()
    return resolved == root or str(resolved).startswith(str(root) + "/")
