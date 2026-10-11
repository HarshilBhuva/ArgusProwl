"""Zeek Collector Tailer and File Watcher."""

import os
import time
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path

from argusprowl.collectors.zeek.offset import ZeekOffsetStore
from argusprowl.constants.log_names import LogName
from argusprowl.logging.logger_factory import LoggerFactory


class ZeekFileWatcher:
    """Watches a file for creation, rotation, or truncation."""

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._last_inode = -1

    def check_rotation(self) -> bool:
        """Check if the file has been rotated.

        Returns:
            True if rotated (or newly created), False otherwise.
        """
        if not self._log_path.exists():
            return False

        try:
            stat_info = self._log_path.stat()
            current_inode = stat_info.st_ino

            if self._last_inode == -1:
                self._last_inode = current_inode
                return True

            if current_inode != self._last_inode:
                self._last_inode = current_inode
                return True

        except OSError:
            pass

        return False

    def has_replaced_or_truncated(self, offset: int) -> bool:
        """Return whether the active path no longer matches the open stream."""
        try:
            stat_info = self._log_path.stat()
        except OSError:
            return False
        return self._last_inode != -1 and (
            stat_info.st_ino != self._last_inode or stat_info.st_size < offset
        )

    @property
    def current_inode(self) -> int:
        return self._last_inode


class ZeekTailReader:
    """Continuously reads from a file, handling rotation and offsets."""

    def __init__(
        self,
        log_path: Path,
        offset_store: ZeekOffsetStore,
        poll_interval: float = 0.1,
    ) -> None:
        self._log_path = log_path
        self._offset_store = offset_store
        self._poll_interval = poll_interval
        self._watcher = ZeekFileWatcher(log_path)
        self._file = None
        self._logger = LoggerFactory.get_logger(LogName.COLLECTOR)
        # Standalone tailers are useful in diagnostics/tests; collectors call
        # start() explicitly as part of their managed lifecycle.
        self._running = True
        self._paused = False

    def start(self) -> None:
        """Make this reader available for a new collection lifecycle."""
        self._running = True
        self._paused = False

    def pause(self) -> None:
        """Temporarily suspend reads without discarding the current offset."""
        self._paused = True

    def resume(self) -> None:
        """Resume a paused reader."""
        self._paused = False

    def _open_file(self) -> bool:
        """Open the file and seek to the correct offset."""
        try:
            if not self._log_path.exists():
                return False

            # This handle intentionally stays open while following the file.
            self._file = open(self._log_path, "rb")  # noqa: SIM115

            # Re-read the inode using stat to ensure consistency
            stat_info = os.fstat(self._file.fileno())
            inode = stat_info.st_ino

            # Get saved offset
            saved_offset = self._offset_store.get_offset(inode)

            if saved_offset > stat_info.st_size:
                # File was truncated
                self._logger.warning(
                    f"File {self._log_path} was truncated, reading from beginning."
                )
                saved_offset = 0

            self._file.seek(saved_offset)

            # Initialize watcher with this inode
            self._watcher._last_inode = inode
            return True
        except OSError as e:
            self._logger.warning(f"Failed to open {self._log_path}: {e}")
            self._close_file()
            return False

    def _close_file(self) -> None:
        """Safely close the file."""
        if self._file:
            with suppress(OSError):
                self._file.close()
            self._file = None

    def _save_current_offset(self) -> None:
        """Save the current file read offset."""
        if self._file and self._watcher.current_inode != -1:
            try:
                current_offset = self._file.tell()
                self._offset_store.save_offset(self._watcher.current_inode, current_offset)
            except OSError:
                pass

    def stop(self) -> None:
        """Stop tailing."""
        self._running = False
        self._paused = False
        self._save_current_offset()
        self._close_file()

    def tail(self) -> Iterator[str]:
        """Generator that continuously yields lines from the file."""
        while self._running:
            if self._paused:
                time.sleep(self._poll_interval)
                continue
            if self._file is None and not self._open_file():
                time.sleep(self._poll_interval)
                continue

            # Read available lines
            while self._running:
                try:
                    line_start = self._file.tell()
                    line = self._file.readline()
                except OSError as e:
                    self._logger.error(f"Error reading file: {e}")
                    self._close_file()
                    break

                if not line:
                    # EOF reached
                    if self._watcher.has_replaced_or_truncated(self._file.tell()):
                        self._logger.info("File rotation detected.")
                        self._close_file()
                        break
                    else:
                        time.sleep(self._poll_interval)
                        continue

                # Do not advance the durable offset over a line which is still
                # being written.  It will be read again once a newline arrives.
                if not line.endswith(b"\n"):
                    self._file.seek(line_start)
                    time.sleep(self._poll_interval)
                    continue

                # We successfully read a complete line.
                self._save_current_offset()
                yield line.decode("utf-8", errors="replace")

        # Final save when stopped
        self._save_current_offset()
        self._close_file()
