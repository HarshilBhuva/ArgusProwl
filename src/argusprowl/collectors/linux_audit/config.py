"""Validated settings for Linux audit/auditd collection."""

import math
from dataclasses import dataclass
from pathlib import Path

SUPPORTED_RECORD_TYPES = frozenset(
    {
        "SYSCALL",
        "EXECVE",
        "USER_LOGIN",
        "USER_START",
        "USER_ACCT",
        "USER_CMD",
        "USER_ROLE_CHANGE",
        "USER_CHAUTHTOK",
        "CRED_ACQ",
        "CRED_REFR",
        "CRED_DISP",
        "USER_END",
    }
)


@dataclass(frozen=True, slots=True)
class LinuxAuditCollectorConfig:
    path: Path = Path("/var/log/audit/audit.log")
    bookmark_path: Path = Path("data/linux-audit-bookmark.json")
    batch_size: int = 100
    polling_interval: float = 1.0
    grouping_timeout: float = 1.0
    max_pending_groups: int = 1000
    supported_record_types: tuple[str, ...] = tuple(sorted(SUPPORTED_RECORD_TYPES))

    def validate(self) -> None:
        if (
            not isinstance(self.path, Path)
            or not str(self.path)
            or not isinstance(self.bookmark_path, Path)
            or not str(self.bookmark_path)
        ):
            raise ValueError("path and bookmark_path must be provided")
        if (
            not isinstance(self.batch_size, int)
            or isinstance(self.batch_size, bool)
            or self.batch_size <= 0
        ):
            raise ValueError("batch_size must be positive")
        for value, name in (
            (self.polling_interval, "polling_interval"),
            (self.grouping_timeout, "grouping_timeout"),
        ):
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be positive")
        if (
            not isinstance(self.max_pending_groups, int)
            or isinstance(self.max_pending_groups, bool)
            or self.max_pending_groups <= 0
        ):
            raise ValueError("max_pending_groups must be positive")
        if not self.supported_record_types or any(
            value not in SUPPORTED_RECORD_TYPES for value in self.supported_record_types
        ):
            raise ValueError("supported_record_types contains unsupported values")
