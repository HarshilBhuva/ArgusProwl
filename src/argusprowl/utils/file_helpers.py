"""File I/O helper functions.

Provides safe, encoding-aware read/write operations and
atomic file writes to prevent partial writes on failure.
"""

import os
import tempfile
from pathlib import Path


def read_text_file(path: str | Path, encoding: str = "utf-8") -> str:
    """Read the entire contents of a text file.

    Args:
        path: Filesystem path to read.
        encoding: Text encoding (default UTF-8).

    Returns:
        The file contents as a string.

    Raises:
        FileNotFoundError: If *path* does not exist.
        OSError: If the file cannot be read.
    """
    return Path(path).read_text(encoding=encoding)


def write_text_file(
    path: str | Path,
    content: str,
    encoding: str = "utf-8",
    make_parents: bool = True,
) -> Path:
    """Write text content to a file, creating parent directories if needed.

    Args:
        path: Target file path.
        content: Text to write.
        encoding: Text encoding (default UTF-8).
        make_parents: Whether to create missing parent directories.

    Returns:
        The resolved :class:`Path` of the written file.
    """
    resolved = Path(path).resolve()
    if make_parents:
        resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(content, encoding=encoding)
    return resolved


def atomic_write(
    path: str | Path,
    content: str,
    encoding: str = "utf-8",
) -> Path:
    """Write content atomically by writing to a temp file then renaming.

    This prevents partial writes if the process is interrupted.

    Args:
        path: Target file path.
        content: Text to write.
        encoding: Text encoding.

    Returns:
        The resolved :class:`Path` of the written file.
    """
    resolved = Path(path).resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        dir=str(resolved.parent),
        prefix=f".{resolved.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(content)
        os.replace(tmp_path, str(resolved))
    except BaseException:
        # Clean up the temp file on any failure
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    return resolved


# Required for atomic_write cleanup
import contextlib  # noqa: E402
